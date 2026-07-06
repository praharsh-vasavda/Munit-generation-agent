"""
MUnit Generation Agent - Web Application
Flask-based web interface for MUnit test generation.

Unified implementation with:
- Security sanitization (removes sensitive data before LLM)
- Token tracking (monitors usage and provides suggestions)
- Enhanced prompt building (with ruleset integration)
"""

import os
import json
import re
import tempfile
import logging
import hashlib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
import threading
import time
from datetime import datetime

# Import file utilities
from utils.file_utils import file_reader
from utils.security import SecuritySanitizer
from utils.token_tracker import TokenBudget, TokenEstimator

# Import existing core modules
from config import Config
from core import (
    XMLAnalyzer,
    DocumentParser,
    PromptBuilder,
    RulesetLoader,
    BlueprintPipeline,
    DeterministicMUnitBuilder,
    MUnitSemanticValidator,
)
from inputs import GitHubFetcher, LocalReader, ConfluenceReader
from llm import LLMRouter
from munitWriter import MUnitWriter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'munit-generation-agent-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Mule project ZIPs are often larger than 16MB

# Global variables for job tracking
active_jobs = {}
job_results = {}
analysis_cache = {}

class WebMUnitGenerator:
    """
    Web-based MUnit generator with:
    - Security sanitization (removes sensitive data before LLM)
    - Token tracking (monitors usage)
    - Job tracking for async generation
    """

    DEFAULT_MUNIT_VERSION = "3.6.0"

    # MUnit 3.x requires Mule 4.5+.  Mule 4.1–4.4 must use MUnit 2.x.
    # Sources: MuleSoft release notes for MUnit 2.x and 3.x.
    MULE_RUNTIME_MUNIT_VERSIONS = {
        "4.1": "2.1.5",   # MUnit 2.1.x — last patch for Mule 4.1
        "4.2": "2.2.5",   # MUnit 2.2.x — last patch for Mule 4.2
        "4.3": "2.3.15",  # MUnit 2.3.x — latest 2.x; MUnit 3 NOT compatible with 4.3
        "4.4": "2.3.15",  # MUnit 2.3.x is supported on 4.4; 3.x requires 4.5+
        "4.5": "3.3.0",   # MUnit 3.x introduced with Mule 4.5 support
        "4.6": "3.6.0",   # Latest MUnit 3.x stable as of 2024
        "4.7": "3.6.0",
        "4.8": "3.6.0",
    }

    # Matching munit-maven-plugin versions per MUnit series
    # Plugin major version tracks MUnit major version.
    MUNIT_PLUGIN_VERSIONS = {
        "2.1": "2.1.5",
        "2.2": "2.2.5",
        "2.3": "2.3.15",
        "3.0": "3.3.0",
        "3.1": "3.3.0",
        "3.2": "3.3.0",
        "3.3": "3.3.0",
        "3.4": "3.6.0",
        "3.5": "3.6.0",
        "3.6": "3.6.0",
    }
    
    def __init__(self, token_budget: int = 50000):
        self.config = Config()
        self.xml_analyzer = XMLAnalyzer()
        self.doc_parser = DocumentParser()
        self.prompt_builder = PromptBuilder(max_tokens=self.config.max_prompt_tokens)
        self.ruleset_loader = RulesetLoader()
        self.llm_router = LLMRouter(timeout=self.config.llm_timeout)
        self.munit_writer = MUnitWriter(output_dir=self.config.output_path)
        
        # Security and token tracking
        self.security_sanitizer = SecuritySanitizer()
        self.token_budget = TokenBudget(total_budget=token_budget)
        self._project_dwl_files = {}
        
        # Load ruleset once
        self.ruleset = self.ruleset_loader.load_ruleset()

        # Blueprint pipeline (Steps 3-8) — wired to the same LLM router
        self.blueprint_pipeline = BlueprintPipeline(
            llm_caller=lambda prompt: self.llm_router.generate_raw(prompt),
            output_dir=self.config.output_path,
        )
        self.deterministic_builder = DeterministicMUnitBuilder(output_dir=self.config.output_path)
        self.semantic_validator = MUnitSemanticValidator()
        
        logger.info(f"WebMUnitGenerator initialized with token budget: {token_budget}")

    def _configure_output_for_job(self, job_id: str, params: dict) -> str:
        """Resolve and apply a per-job output directory outside the app by default."""
        requested = (params.get("output_path") or "").strip()
        in_app_defaults = {"", "./output", "./output/", "output", "output/"}
        if requested in in_app_defaults:
            output_path = os.path.join(tempfile.gettempdir(), "munit-generation-agent-output", job_id)
        elif os.path.isabs(os.path.expanduser(requested)) or requested.startswith("~"):
            output_path = os.path.abspath(os.path.expanduser(requested))
        else:
            output_path = os.path.abspath(
                os.path.join(tempfile.gettempdir(), "munit-generation-agent-output", requested)
            )

        params["output_path"] = output_path
        self.config.output_path = output_path
        self.munit_writer = MUnitWriter(output_dir=output_path)
        self.deterministic_builder = DeterministicMUnitBuilder(output_dir=output_path)
        self.blueprint_pipeline.output_dir = Path(output_path)
        if hasattr(self.blueprint_pipeline, "_mock_payload_dir"):
            self.blueprint_pipeline._mock_payload_dir = (
                Path(output_path) / "src" / "test" / "resources" / "mock_payloads"
            )
            self.blueprint_pipeline._mock_payload_dir.mkdir(parents=True, exist_ok=True)
        return output_path
    
    def generate_munit_web(self, job_id: str, params: dict) -> dict:
        """
        Generate MUnit with web interface parameters.
        
        Args:
            job_id: Unique job identifier
            params: Dictionary with generation parameters
            
        Returns:
            Dictionary with generation results
        """
        try:
            # Update job status
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': 'Starting generation...'}
            output_path = self._configure_output_for_job(job_id, params)
            
            # Step 1: Fetch Mule XML
            active_jobs[job_id].update({'progress': 10, 'message': 'Fetching Mule XML...'})
            xml_content = self._fetch_xml_content(params)
            self._project_dwl_files = params.get('project_dwl_files', {}) or {}
            
            # Step 2: Validate and analyze XML
            active_jobs[job_id].update({'progress': 20, 'message': 'Analyzing Mule XML...'})
            
            # Debug: Show XML content preview
            xml_preview = xml_content[:200] + "..." if len(xml_content) > 200 else xml_content
            print(f"DEBUG: XML content preview: {xml_preview}")
            
            print("DEBUG: Analyzing Mule project content using project-aware XML analyzer")
            flow_summary = self.xml_analyzer.analyze_mule_project(xml_content)
            selected_flows = params.get('selected_flows') or []
            if isinstance(selected_flows, str):
                try:
                    selected_flows = json.loads(selected_flows)
                except Exception:
                    selected_flows = [selected_flows]
            flow_summary = self.apply_selected_flows(flow_summary, selected_flows)
            flow_summary = self._apply_user_dynamic_flow_targets(flow_summary, params)
            flow_summary = self._apply_external_flow_links(flow_summary, params)
            
            # Step 3: Fetch business use case
            active_jobs[job_id].update({'progress': 30, 'message': 'Fetching business use case...'})
            usecase_content = self._fetch_usecase_content(params)
            
            # Step 4: Parse business use case
            active_jobs[job_id].update({'progress': 40, 'message': 'Parsing business use case...'})
            scenarios = self.doc_parser.parse_document(usecase_content, flow_summary["job_type"])
            scenario_map = (
                self.doc_parser.map_scenarios_to_flows(scenarios["scenarios"], flow_summary)
                if usecase_content and usecase_content.strip()
                else {}
            )
            
            # Step 5-7: Build targeted prompts, generate, and write per-flow MUnits
            active_jobs[job_id].update({'progress': 50, 'message': 'Generating per-flow MUnit suites...'})
            target_munit_version = (params.get("target_munit_version") or "").strip() or None
            if not target_munit_version:
                target_munit_version = (params.get("build_validation", {}) or {}).get("munit_version")
            sample_payloads = self._build_sample_payloads_dict(params)
            connector_samples = self._build_connector_samples_dict(params)
            clarification_requests = self._collect_generation_clarification_requests(
                flow_summary,
                scenario_map,
                scenarios,
                sample_payloads=sample_payloads,
                connector_samples=connector_samples,
                generation_mode=params.get("generation_mode"),
            )
            if clarification_requests and not self._allow_synthetic_defaults(params):
                return self._needs_user_input_result(
                    job_id,
                    flow_summary,
                    clarification_requests,
                    output_path=output_path,
                )
            generation_outputs = self._generate_targeted_munits(
                flow_summary,
                scenario_map,
                scenarios,
                sample_payloads=sample_payloads,
                connector_samples=connector_samples,
                target_munit_version=target_munit_version,
                generation_mode=params.get("generation_mode"),
            )
            output_files = []
            for item in generation_outputs:
                output_files.append(item["output_file"])
                output_files.extend(item.get("extra_files", []))
            output_files = self._collect_generated_output_files(output_path, output_files)
            output_file = output_files[0] if output_files else None
            
            # Step 8: Complete
            active_jobs[job_id].update({'status': 'complete', 'progress': 100, 'message': 'Generation complete!'})
            
            # Prepare results with token usage
            token_usage = self.token_budget.get_usage_summary()
            results = {
                'success': True,
                'output_file': output_file,
                'output_files': output_files,
                'output_path': output_path,
                'flow_outputs': generation_outputs,
                'flow_summary': flow_summary,
                'build_validation': params.get('build_validation', {}),
                'scenarios_count': len(scenarios["scenarios"]),
                'metadata': generation_outputs[0]["metadata"] if generation_outputs else {},
                'generation_mode': (generation_outputs[0]["metadata"].get("generation_mode") if generation_outputs else "deterministic"),
                'semantic_validation': (generation_outputs[0]["metadata"].get("semantic_validation") if generation_outputs else {}),
                'generation_time': sum(item["metadata"].get('generation_time', 0) for item in generation_outputs),
                'token_usage': token_usage,
                'security': {'sanitized': True, 'warnings': []}
            }
            
            job_results[job_id] = results
            active_jobs[job_id]['result'] = results
            return results
            
        except Exception as e:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Error: {str(e)}'}
            job_results[job_id] = {'success': False, 'error': str(e)}
            return {'success': False, 'error': str(e)}
    
    def _fetch_xml_content(self, params: dict) -> str:
        """Fetch XML content based on source type."""
        xml_source = params.get('xml_source')
        
        # First check if content is already processed (from ZIP extraction)
        if 'xml_file' in params and params['xml_file']:
            print(f"DEBUG: Using pre-processed XML content (length: {len(params['xml_file'])})")
            return params['xml_file']
        
        # If not processed, handle based on source type
        if xml_source == 'local':
            raise Exception("No XML content found in processed files")
        
        elif xml_source == 'folder':
            raise Exception("No XML content found in processed ZIP file")
        
        elif xml_source == 'github':
            github_fetcher = GitHubFetcher(token=params.get('github_token'))
            return github_fetcher.fetch_file(
                params['github_repo'],
                params['github_branch'],
                params['github_file_path']
            )
        
        else:
            # No content available
            raise Exception("No XML content available for processing")
    
    def _fetch_usecase_content(self, params: dict) -> str:
        """Fetch use case content based on source type (optional)."""
        usecase_source = (params.get('usecase_source') or '').strip().lower()
        confluence_url = (params.get('confluence_url') or '').strip()
        if not usecase_source and confluence_url:
            usecase_source = 'confluence'
        
        # First check if content is already processed (from ZIP extraction)
        if 'usecase_file' in params and params['usecase_file']:
            print(f"DEBUG: Using pre-processed use case content (length: {len(params['usecase_file'])})")
            return params['usecase_file']
        
        # If no use case source provided, return empty string (will use default scenarios)
        if not usecase_source:
            return ""
        
        if usecase_source == 'local':
            return ""  # No processed content found, use default scenarios
        
        elif usecase_source == 'confluence':
            if not confluence_url:
                raise Exception("Confluence use case source selected, but no Confluence URL was provided.")
            if not params.get('confluence_token') or not params.get('confluence_email'):
                raise Exception("Confluence URL was provided, but Confluence email/token is missing.")
            confluence_reader = ConfluenceReader(
                url=confluence_url.split("/wiki")[0] + "/wiki",
                token=params['confluence_token'],
                email=params['confluence_email']
            )
            content = confluence_reader.fetch_page_content(confluence_url)
            if not content or not content.strip():
                raise Exception("Confluence page was fetched, but no business use case content was found.")
            return content
        
        else:
            return ""  # Invalid source, use default scenarios
    
    def generate_munit_enhanced_web(self, job_id: str, params: dict) -> dict:
        """
        Generate MUnit with enhanced web interface parameters
        
        Args:
            job_id: Unique job identifier
            params: Dictionary with generation parameters
            
        Returns:
            Dictionary with generation results
        """
        try:
            # Update job status
            active_jobs[job_id] = {'status': 'processing', 'progress': 0, 'message': 'Starting enhanced generation...'}
            
            # Check if enhanced mode is enabled
            enhanced_mode = params.get('enhanced_mode', True)
            
            if enhanced_mode:
                return self._generate_enhanced_mode(job_id, params)
            else:
                return self._generate_legacy_mode(job_id, params)
                
        except Exception as e:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Error: {str(e)}'}
            job_results[job_id] = {'success': False, 'error': str(e)}
            return {'success': False, 'error': str(e)}
    
    def _generate_enhanced_mode(self, job_id: str, params: dict) -> dict:
        """Generate using enhanced mode"""
        try:
            # Step 1: Validate XML content is available
            active_jobs[job_id].update({'progress': 10, 'message': 'Validating XML content...'})
            
            if 'xml_file' not in params or not params['xml_file']:
                raise Exception("No XML content available for processing")
            
            xml_content = params['xml_file']
            self._project_dwl_files = params.get('project_dwl_files', {}) or {}
            print(f"DEBUG: Using pre-processed XML content (length: {len(xml_content)})")
            
            # Step 2: Validate use case content (optional)
            active_jobs[job_id].update({'progress': 20, 'message': 'Validating documentation...'})
            
            usecase_content = self._fetch_usecase_content(params)
            if usecase_content:
                print(f"DEBUG: Documentation available for enhanced generation (length: {len(usecase_content)})")
                params['usecase_file'] = usecase_content
            
            # Step 3: Generate with enhanced features
            active_jobs[job_id].update({'progress': 30, 'message': 'Running enhanced generation...'})
            
            # Use the legacy generation with enhanced features
            return self._generate_legacy_mode(job_id, params, enhanced=True)
                
        except Exception as e:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Enhanced generation error: {str(e)}'}
            job_results[job_id] = {'success': False, 'error': str(e)}
            return {'success': False, 'error': str(e)}
    
    def _generate_legacy_mode(self, job_id: str, params: dict, enhanced: bool = False) -> dict:
        """Generate using legacy mode"""
        try:
            output_path = self._configure_output_for_job(job_id, params)
            # Step 1: Validate and get Mule XML content
            active_jobs[job_id].update({'progress': 10, 'message': 'Validating Mule XML...'})
            
            if 'xml_file' not in params or not params['xml_file']:
                raise Exception("No XML content available for processing")
            
            xml_content = params['xml_file']
            print(f"DEBUG: Using pre-processed XML content (length: {len(xml_content)})")
            
            # Step 2: Validate and analyze XML
            active_jobs[job_id].update({'progress': 20, 'message': 'Analyzing Mule XML...'})
            
            # Debug: Show XML content preview
            xml_preview = xml_content[:200] + "..." if len(xml_content) > 200 else xml_content
            print(f"DEBUG: XML content preview: {xml_preview}")
            print(f"DEBUG: XML content length: {len(xml_content)} characters")
            print(f"DEBUG: XML content starts with: {repr(xml_content[:100])}")
            
            cached_flow_summary = params.get("_cached_flow_summary")
            if cached_flow_summary:
                print("DEBUG: Using cached flow analysis for generation")
                flow_summary = cached_flow_summary
            else:
                print("DEBUG: Analyzing Mule project content using project-aware XML analyzer")
                flow_summary = self.xml_analyzer.analyze_mule_project(xml_content)
            selected_flows = params.get('selected_flows') or []
            if isinstance(selected_flows, str):
                try:
                    selected_flows = json.loads(selected_flows)
                except Exception:
                    selected_flows = [selected_flows]
            flow_summary = self.apply_selected_flows(flow_summary, selected_flows)
            flow_summary = self._apply_user_dynamic_flow_targets(flow_summary, params)
            flow_summary = self._apply_external_flow_links(flow_summary, params)
            
            # Step 3: Get business use case content
            active_jobs[job_id].update({'progress': 30, 'message': 'Processing documentation...'})
            
            usecase_content = self._fetch_usecase_content(params)
            if usecase_content:
                print(f"DEBUG: Using business use case content (length: {len(usecase_content)})")
            else:
                print(f"DEBUG: No documentation provided, using default scenarios")
            
            # Step 4: Parse business use case
            active_jobs[job_id].update({'progress': 40, 'message': 'Parsing business use case...'})
            scenarios = self.doc_parser.parse_document(usecase_content, flow_summary["job_type"])
            scenario_map = (
                self.doc_parser.map_scenarios_to_flows(scenarios["scenarios"], flow_summary)
                if usecase_content and usecase_content.strip()
                else {}
            )
            
            # Step 5-7: Build targeted prompts, generate, and write per-flow MUnits
            active_jobs[job_id].update({'progress': 50, 'message': 'Generating per-flow MUnit suites...'})
            target_munit_version = (params.get("target_munit_version") or "").strip() or None
            if not target_munit_version:
                target_munit_version = (params.get("build_validation", {}) or {}).get("munit_version")
            sample_payloads = self._build_sample_payloads_dict(params)
            connector_samples = self._build_connector_samples_dict(params)
            clarification_requests = self._collect_generation_clarification_requests(
                flow_summary,
                scenario_map,
                scenarios,
                sample_payloads=sample_payloads,
                connector_samples=connector_samples,
                generation_mode=params.get("generation_mode"),
            )
            if clarification_requests and not self._allow_synthetic_defaults(params):
                return self._needs_user_input_result(
                    job_id,
                    flow_summary,
                    clarification_requests,
                    output_path=output_path,
                    mode='enhanced' if enhanced else 'legacy',
                )
            generation_outputs = self._generate_targeted_munits(
                flow_summary,
                scenario_map,
                scenarios,
                sample_payloads=sample_payloads,
                connector_samples=connector_samples,
                target_munit_version=target_munit_version,
                generation_mode=params.get("generation_mode"),
            )
            output_files = []
            for item in generation_outputs:
                output_files.append(item["output_file"])
                output_files.extend(item.get("extra_files", []))
            output_files = self._collect_generated_output_files(output_path, output_files)
            output_file = output_files[0] if output_files else None
            
            # Step 8: Complete
            active_jobs[job_id].update({'status': 'complete', 'progress': 100, 'message': 'Generation complete!'})
            
            # Prepare results with token usage
            token_usage = self.token_budget.get_usage_summary()
            results = {
                'success': True,
                'mode': 'enhanced' if enhanced else 'legacy',
                'output_file': output_file,
                'output_files': output_files,
                'output_path': output_path,
                'flow_outputs': generation_outputs,
                'flow_summary': flow_summary,
                'build_validation': params.get('build_validation', {}),
                'scenarios_count': len(scenarios["scenarios"]),
                'metadata': generation_outputs[0]["metadata"] if generation_outputs else {},
                'generation_mode': (generation_outputs[0]["metadata"].get("generation_mode") if generation_outputs else "deterministic"),
                'semantic_validation': (generation_outputs[0]["metadata"].get("semantic_validation") if generation_outputs else {}),
                'generation_time': sum(item["metadata"].get('generation_time', 0) for item in generation_outputs),
                'token_usage': token_usage,
                'security': {'sanitized': True, 'warnings': []}
            }
            
            # Add enhanced metadata if available
            if enhanced:
                results['enhanced_features'] = {
                    'token_budget': params.get('token_budget', '50000'),
                    'optimization_level': params.get('optimization_level', 'balanced'),
                    'security_focus': params.get('security_focus', 'high')
                }
            
            job_results[job_id] = results
            active_jobs[job_id]['result'] = results
            return results
            
        except Exception as e:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Error: {str(e)}'}
            job_results[job_id] = {'success': False, 'error': str(e)}
            return {'success': False, 'error': str(e)}
    
    def _fetch_xml_content_enhanced(self, params: dict) -> str:
        """Fetch XML content with enhanced folder support"""
        # Use the existing XML fetching logic
        return self._fetch_xml_content(params)
    
    def _fetch_usecase_content_enhanced(self, params: dict) -> str:
        """Fetch use case content with enhanced folder support"""
        # Use the existing use case fetching logic
        return self._fetch_usecase_content(params)
    
    def _fetch_xml_content_legacy(self, params: dict) -> str:
        """Fetch XML content using legacy method"""
        return self._fetch_xml_content(params)
    
    def _fetch_usecase_content_legacy(self, params: dict) -> str:
        """Fetch use case content using legacy method"""
        return self._fetch_usecase_content(params)

    def _read_file_content(self, file):
        """
        Read file content with robust encoding detection.
        
        Args:
            file: FileStorage object
            
        Returns:
            str: File content as string
        """
        try:
            # Use robust file reader
            content = file_reader.read_uploaded_file(file, max_size_mb=10)
            
            # Clean content if it's XML
            if file.filename.lower().endswith(('.xml', '.mule')):
                content = file_reader.clean_xml_content(content)
            
            return content
                
        except Exception as e:
            return f"[Error reading file {file.filename}: {str(e)}]"

    def _read_uploaded_usecase_file(self, file) -> str:
        """Read uploaded business use-case files, including PDF/DOCX and archives."""
        if not file or not hasattr(file, 'filename') or not file.filename:
            return ""

        filename = file.filename
        lower_name = filename.lower()

        try:
            if lower_name.endswith(('.zip', '.jar')):
                return self._read_usecase_archive(file)
            if lower_name.endswith(('.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.csv')):
                return self._read_file_content(file)
            if lower_name.endswith(('.pdf', '.docx', '.doc')):
                return self._read_uploaded_document_via_tempfile(file)
            return self._read_file_content(file)
        except Exception as exc:
            return f"[Error reading use case file {filename}: {str(exc)}]"

    def _read_uploaded_document_via_tempfile(self, file) -> str:
        """Persist an uploaded document briefly so LocalReader can parse it."""
        suffix = Path(file.filename).suffix or ".txt"
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                file.seek(0)
                temp_file.write(file.read())
                temp_path = temp_file.name
            return LocalReader().read_document(temp_path)
        finally:
            try:
                file.seek(0)
            except Exception:
                pass
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _read_usecase_archive(self, file) -> str:
        """Read supported business-use-case documents from an uploaded ZIP/JAR."""
        import zipfile
        import shutil

        temp_dir = tempfile.mkdtemp(prefix='usecase_docs_')
        archive_path = os.path.join(temp_dir, 'usecase.zip')
        supported_suffixes = {'.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.csv', '.pdf', '.docx', '.doc'}
        parts = []

        try:
            file.seek(0)
            file.save(archive_path)
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if d.lower() not in {'__macosx', '.git', '__pycache__'}]
                for file_name in sorted(files):
                    if file_name == 'usecase.zip' or file_name.startswith('._'):
                        continue
                    path = Path(root) / file_name
                    suffix = path.suffix.lower()
                    if suffix not in supported_suffixes:
                        continue
                    try:
                        if suffix in {'.pdf', '.docx', '.doc'}:
                            content = LocalReader().read_document(str(path))
                        else:
                            content = path.read_text(encoding='utf-8', errors='replace')
                    except Exception as exc:
                        content = f"[Error reading archived use case file {file_name}: {str(exc)}]"
                    if content.strip():
                        rel_name = os.path.relpath(path, temp_dir).replace("\\", "/")
                        parts.append(f"\n\n--- Content from {rel_name} ---\n{content}\n")
        finally:
            try:
                file.seek(0)
            except Exception:
                pass
            shutil.rmtree(temp_dir, ignore_errors=True)

        return "".join(parts)

    def _resolve_generation_mode(
        self,
        generation_mode: Optional[str],
        sample_payloads: dict,
    ) -> str:
        """
        Resolve generation strategy for the web app.

        The web UI no longer exposes generation modes. Uploaded Mule apps are
        generated through the backend recorder-style path so output is
        Studio-like and consistent without user selection.
        """
        return "recorder"

    def _generate_targeted_munits(
        self,
        flow_summary: dict,
        scenario_map: dict,
        document_context: dict = None,
        sample_payloads: dict = None,
        connector_samples: dict = None,
        target_munit_version: Optional[str] = None,
        generation_mode: Optional[str] = None,
    ) -> list:
        """
        Generate one MUnit suite per target flow using focused context.

        Includes:
        - Security sanitization of flow content
        - Token usage tracking
        - Per-flow metadata
        - Sample payload injection (recorder-style real data)

        Args:
            sample_payloads: Optional dict of {flow_name: payload_text}.
                             Use key '_all' to apply one payload to every flow.
        """
        outputs = []
        test_targets = self._dedupe_preserve_order(
            flow_summary.get("test_targets") or flow_summary.get("flows") or ["main-flow"]
        )
        flow_contexts = flow_summary.get("flow_contexts", {})
        sample_payloads = sample_payloads or {}
        connector_samples = connector_samples or {}
        resolved_mode = self._resolve_generation_mode(generation_mode, sample_payloads)
        business_context_applied = bool(
            document_context and (
                document_context.get("raw_content_length", 0) > 0
                or any(item.get("source") != "default" for item in document_context.get("scenarios", []) or [])
                or document_context.get("business_rules")
                or document_context.get("inputs_outputs")
            )
        )

        # Reset token tracking for this generation session
        self.token_budget.reset()

        for target_flow in test_targets:
            flow_context = dict(flow_contexts.get(target_flow, {"target_flow": target_flow}))
            target_scenarios = scenario_map.get(target_flow) or []
            flow_context["scenarios"] = target_scenarios

            sample_payload = (
                sample_payloads.get(target_flow)
                or sample_payloads.get("_all")
                or None
            )
            if sample_payload:
                logger.info(f"Using sample payload for '{target_flow}' ({len(sample_payload)} chars)")

            mode = resolved_mode

            if mode in {"deterministic", "recorder"}:
                munit_xml, build_metadata = self.deterministic_builder.build_suite(
                    flow_context,
                    generation_mode=mode,
                    sample_payload=sample_payload,
                    connector_samples=self._connector_samples_for_flow(connector_samples, target_flow),
                    scenarios=target_scenarios,
                    target_munit_version=target_munit_version,
                )
                validation = self.semantic_validator.validate(munit_xml, flow_context)
                maven_paths = self.deterministic_builder.write_maven_layout(munit_xml, build_metadata)

                metadata = {
                    "model_used": "deterministic-builder",
                    "template_based": False,
                    "generation_mode": mode,
                    "target_flow": target_flow,
                    "source_file": flow_context.get("source_file", "unknown.xml"),
                    "scenario_count": build_metadata.get("test_count", 1),
                    "related_flows": flow_context.get("related_flows", []),
                    "semantic_validation": validation,
                    "maven_layout_paths": maven_paths,
                    "resource_files": build_metadata.get("resource_files", {}),
                    "scenario_plan": build_metadata.get("scenario_plan", []),
                    "preflight_validation": build_metadata.get("preflight_validation", {}),
                    "target_munit_version": build_metadata.get("target_munit_version"),
                    "business_context_applied": business_context_applied,
                    "business_context_length": (document_context or {}).get("raw_content_length", 0),
                    "generation_time": 0.0,
                    "failures": validation.get("errors", []),
                }
                output_file = maven_paths.get("suite_file") or str(
                    Path(self.config.output_path) / f"{target_flow}-munit-test.xml"
                )
                Path(output_file).write_text(munit_xml, encoding="utf-8")
                extra_files = self._resource_paths_from_maven_layout(maven_paths)
            else:
                dwl_content = self._select_dwl_context(flow_context)
                sanitized_flow_summary = self._sanitize_flow_summary(flow_summary)
                prompt = self.prompt_builder.build_prompt(
                    sanitized_flow_summary,
                    target_scenarios,
                    self.ruleset,
                    flow_context=flow_context,
                    document_context=document_context,
                    dwl_content=dwl_content,
                    sample_payload=sample_payload,
                    munit_version=target_munit_version,
                )
                estimated_tokens = TokenEstimator.estimate_tokens(prompt)
                logger.info(
                    f"Generating MUnit for '{target_flow}' via LLM - estimated prompt tokens: {estimated_tokens}"
                )
                munit_xml, llm_metadata = self.llm_router.generate_munit(prompt)
                if "input_tokens" in llm_metadata and "output_tokens" in llm_metadata:
                    self.token_budget.record_llm_usage(
                        operation=f"generate_{target_flow}",
                        input_tokens=llm_metadata.get("input_tokens", estimated_tokens),
                        output_tokens=llm_metadata.get("output_tokens", 0),
                    )
                else:
                    self.token_budget.use_tokens(estimated_tokens, f"generate_{target_flow}")

                validation = self.semantic_validator.validate(munit_xml, flow_context)
                metadata = {
                    **llm_metadata,
                    "generation_mode": "llm_suite",
                    "target_flow": target_flow,
                    "source_file": flow_context.get("source_file", "unknown.xml"),
                    "scenario_count": len(target_scenarios),
                    "related_flows": flow_context.get("related_flows", []),
                    "security_sanitized": True,
                    "estimated_tokens": estimated_tokens,
                    "semantic_validation": validation,
                    "template_based": llm_metadata.get("template_based", False),
                    "business_context_applied": business_context_applied,
                    "business_context_length": (document_context or {}).get("raw_content_length", 0),
                }
                output_file = self.munit_writer.write_munit_file(munit_xml, target_flow, metadata)
                extra_files = metadata.get("mock_asset_files", []) or []

            outputs.append({
                "target_flow": target_flow,
                "output_file": output_file,
                "extra_files": extra_files,
                "munit_xml": munit_xml,
                "scenarios": target_scenarios,
                "metadata": metadata
            })
        
        # Log token usage summary
        usage_summary = self.token_budget.get_usage_summary()
        logger.info(f"Token usage: {usage_summary['used_tokens']} / {usage_summary['total_budget']} ({usage_summary['usage_percentage']}%)")
        for suggestion in usage_summary['suggestions']:
            logger.info(f"  {suggestion}")

        return outputs

    def _collect_generation_clarification_requests(
        self,
        flow_summary: dict,
        scenario_map: dict,
        document_context: dict = None,
        *,
        sample_payloads: Optional[dict] = None,
        connector_samples: Optional[dict] = None,
        generation_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Collect user input needed before writing weak synthetic MUnit assets."""
        sample_payloads = sample_payloads or {}
        connector_samples = connector_samples or {}
        resolved_mode = self._resolve_generation_mode(generation_mode, sample_payloads)
        requests: List[Dict[str, Any]] = []
        seen = set()
        test_targets = self._dedupe_preserve_order(
            flow_summary.get("test_targets") or flow_summary.get("flows") or ["main-flow"]
        )
        flow_contexts = flow_summary.get("flow_contexts", {}) or {}

        for target_flow in test_targets:
            flow_context = dict(flow_contexts.get(target_flow, {"target_flow": target_flow}))
            target_scenarios = scenario_map.get(target_flow) or []
            flow_context["scenarios"] = target_scenarios
            sample_payload = sample_payloads.get(target_flow) or sample_payloads.get("_all") or None
            scenarios = self.deterministic_builder._build_scenario_plan(
                flow_context,
                scenarios=target_scenarios or None,
                generation_mode=resolved_mode,
            )
            plan = self.deterministic_builder._build_munit_plan(
                flow_context,
                scenarios,
                generation_mode=resolved_mode,
                sample_payload=sample_payload,
                connector_samples=self._connector_samples_for_flow(connector_samples, target_flow),
            )
            for request_item in plan.get("clarificationRequests", []) or []:
                if request_item.get("type") == "dynamic_flow_ref_resolution":
                    # Dynamic routing belongs to selected-flow tracing (Step 5),
                    # never to the final sample-data dialog.
                    continue
                item = dict(request_item)
                item.setdefault("flow", target_flow)
                key = json.dumps(item, sort_keys=True, default=str)
                if key in seen:
                    continue
                seen.add(key)
                requests.append(item)

        return requests

    @staticmethod
    def _connector_samples_for_flow(connector_samples: dict, target_flow: str) -> dict:
        """Merge shared samples with flow-specific samples for builder lookup."""
        merged = dict((connector_samples or {}).get("_all", {}) or {})
        merged.update((connector_samples or {}).get(target_flow, {}) or {})
        return merged

    def _needs_user_input_result(
        self,
        job_id: str,
        flow_summary: dict,
        clarification_requests: List[Dict[str, Any]],
        *,
        output_path: str,
        mode: Optional[str] = None,
    ) -> dict:
        """Return a paused generation response with safe sample-data prompts."""
        active_jobs[job_id] = {
            'status': 'needs_user_input',
            'progress': 45,
            'message': 'Additional synthetic sample values are required before MUnit generation.',
        }
        result = {
            'success': False,
            'needs_user_input': True,
            'message': 'Provide synthetic or masked values for the requested fields, then rerun generation.',
            'clarification_requests': clarification_requests,
            'flow_summary': flow_summary,
            'selection': self.build_flow_selection_payload(flow_summary),
            'output_path': output_path,
            'security': {
                'sanitized': True,
                'warnings': [
                    'Use only synthetic or masked test data.',
                    'Do not provide production PII, credentials, access tokens, or secrets.',
                ],
            },
        }
        if mode:
            result['mode'] = mode
        job_results[job_id] = result
        active_jobs[job_id]['result'] = result
        return result

    @staticmethod
    def _allow_synthetic_defaults(params: dict) -> bool:
        """Return true only when the caller explicitly accepts placeholder defaults."""
        for key in (
            "allow_synthetic_defaults",
            "use_synthetic_defaults",
            "confirm_synthetic_defaults",
            "skip_clarification_gate",
        ):
            value = params.get(key)
            if isinstance(value, bool):
                if value:
                    return True
            elif isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "y", "on"}:
                return True
        return False

    @staticmethod
    def _dedupe_preserve_order(values: list) -> list:
        """Return unique non-empty values in their first-seen order."""
        seen = set()
        deduped = []
        for value in values or []:
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _resource_paths_from_maven_layout(self, maven_paths: dict) -> list:
        """Return generated companion resource files without repeating suite XML."""
        return self._dedupe_preserve_order(
            [
                path
                for key, path in (maven_paths or {}).items()
                if key not in {"suite_file", "suite_file_maven"}
            ]
        )

    def _collect_generated_output_files(self, output_path: str, known_files: list) -> list:
        """Include every generated Maven-layout file in results and downloads."""
        files = list(known_files or [])
        root = Path(output_path) if output_path else None
        if root and root.is_dir():
            files.extend(
                str(path)
                for path in sorted(root.rglob("*"))
                if path.is_file()
            )
        return self._dedupe_preserve_order(files)

    def _select_dwl_context(self, flow_context: dict) -> dict:
        """Return only DWL files that are relevant to the current target flow."""
        project_dwl = getattr(self, "_project_dwl_files", {}) or {}
        if not project_dwl:
            return {}

        requested_files = flow_context.get("dwl_files", []) or []
        selected = {}

        for dwl_ref in requested_files:
            normalized_ref = self._normalize_project_relative_path(dwl_ref)
            for project_path, content in project_dwl.items():
                normalized_project_path = self._normalize_project_relative_path(project_path)
                if (
                    normalized_ref == normalized_project_path
                    or normalized_project_path.endswith(normalized_ref)
                    or normalized_ref.endswith(normalized_project_path)
                ):
                    selected[project_path] = content

        if selected:
            return selected

        # Fallback to a very small sample rather than sending the entire DWL set.
        limited_items = list(project_dwl.items())[:3]
        return dict(limited_items)

    def _normalize_project_relative_path(self, path_value: str) -> str:
        """Normalize resource paths to improve matching across Mule XML and ZIP layout."""
        cleaned = (path_value or "").replace("\\", "/").strip().lstrip("/")
        if cleaned.startswith("classpath:/"):
            cleaned = cleaned[len("classpath:/"):]
        elif cleaned.startswith("classpath:"):
            cleaned = cleaned[len("classpath:"):]
        return cleaned

    def _collect_project_files(self, temp_dir: str, include_dwl: bool = True) -> dict:
        """Collect Mule XML and optionally DWL files from an extracted Mule project."""
        mule_files = []
        dwl_files = {}
        src_main_dir = None
        pom_path = None
        scan_details = {
            "scan_root": "",
            "scan_roots": [],
            "used_src_main": False,
            "xml_candidates": [],
            "mule_files": [],
            "skipped_xml": [],
            "nested_archives": [],
        }

        self._extract_nested_archives(temp_dir, scan_details)

        # Walk to find src/main, but skip junk folders injected by macOS Finder
        # (__MACOSX) or other tools so they never shadow the real project root.
        _JUNK_ROOTS = {'__macosx', '.ds_store', '__pycache__', '.git', 'node_modules'}

        # Collect ALL valid src/main candidates first, then pick the best one.
        candidates = []  # list of (src_main_path, pom_path_or_None)
        for root, dirs, files in os.walk(temp_dir):
            # Prune junk dirs in-place so os.walk never descends into them
            dirs[:] = sorted(d for d in dirs if d.lower() not in _JUNK_ROOTS)
            if 'src' in dirs and os.path.exists(os.path.join(root, 'src', 'main')):
                candidate = os.path.join(root, 'src', 'main')
                pom = os.path.join(root, 'pom.xml')
                candidates.append((candidate, pom if os.path.isfile(pom) else None))

        scan_roots = []
        if candidates:
            src_main_dir, pom_path = candidates[0]
            if len(candidates) > 1:
                logger.info("Multiple src/main candidates found; scanning all %s candidates", len(candidates))
            for candidate, candidate_pom in candidates:
                if candidate not in scan_roots:
                    scan_roots.append(candidate)
                if pom_path is None and candidate_pom:
                    pom_path = candidate_pom
        else:
            logger.info(
                "src/main folder not found in ZIP archive; scanning extracted archive for Mule XML files"
            )

        if temp_dir not in scan_roots:
            scan_roots.append(temp_dir)

        scan_details["scan_root"] = os.path.relpath(scan_roots[0], temp_dir).replace("\\", "/")
        scan_details["scan_roots"] = [
            os.path.relpath(root, temp_dir).replace("\\", "/") for root in scan_roots
        ]
        scan_details["used_src_main"] = bool(candidates)
        if candidates:
            logger.info("Scanning Mule project roots: %s", ", ".join(scan_details["scan_roots"]))

        skip_xml_names = {'pom.xml', 'log4j2.xml', 'log4j.xml', 'application-types.xml'}
        skip_path_markers = (
            '/munit/', '/target/', '/.mule/', '/__macosx/',
            '/src/test/', '/test/munit/',
        )

        seen_files = set()
        for scan_root in scan_roots:
            for root, dirs, files in os.walk(scan_root):
                dirs[:] = sorted(d for d in dirs if d.lower() not in _JUNK_ROOTS)
                for file_name in files:
                    full_path = os.path.abspath(os.path.join(root, file_name))
                    if full_path in seen_files:
                        continue
                    seen_files.add(full_path)
                    normalized_path = full_path.replace("\\", "/").lower()
                    relative_to_scan_root = os.path.relpath(full_path, scan_root).replace("\\", "/")
                    relative_to_archive = os.path.relpath(full_path, temp_dir).replace("\\", "/")
                    normalized_relative = f"/{relative_to_archive.lower()}"

                    if (
                        any(marker in normalized_path for marker in skip_path_markers)
                        or any(marker in normalized_relative for marker in skip_path_markers)
                    ):
                        continue

                    lower_name = file_name.lower()
                    if lower_name.endswith(('.xml', '.mule')):
                        scan_details["xml_candidates"].append(relative_to_archive)
                        if lower_name in skip_xml_names:
                            scan_details["skipped_xml"].append({
                                "path": relative_to_archive,
                                "reason": "ignored infrastructure XML",
                            })
                            continue
                        looks_like_mule, reason = self._classify_mule_xml_file(full_path)
                        if not looks_like_mule:
                            scan_details["skipped_xml"].append({
                                "path": relative_to_archive,
                                "reason": reason,
                            })
                            continue
                        mule_files.append(full_path)
                        scan_details["mule_files"].append(relative_to_archive)
                    elif include_dwl and lower_name.endswith('.dwl'):
                        relative_path = relative_to_archive
                        try:
                            dwl_files[relative_path] = Path(full_path).read_text(encoding='utf-8')
                        except UnicodeDecodeError:
                            dwl_files[relative_path] = Path(full_path).read_text(encoding='utf-8', errors='replace')

        if not mule_files:
            raise Exception(
                "No Mule XML files found in ZIP archive. Upload a Mule project ZIP or XML files containing a <mule> root."
            )

        combined_content = ""
        for xml_file_path in sorted(mule_files):
            # Read bytes first so we can handle any encoding correctly, then
            # sanitize (BOM, control chars, missing xmlns declarations) before
            # adding to the combined payload that analyze_mule_project will parse.
            try:
                raw = Path(xml_file_path).read_bytes()
            except Exception as read_err:
                logger.warning("Could not read %s: %s — skipping", xml_file_path, read_err)
                continue

            for enc in ('utf-8-sig', 'utf-8', 'latin-1'):
                try:
                    content = raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            else:
                content = raw.decode('utf-8', errors='replace')

            content = XMLAnalyzer._sanitize_xml_string(content)
            relative_name = os.path.relpath(xml_file_path, temp_dir).replace("\\", "/")
            combined_content += f"\n\n--- Content from {relative_name} ---\n{content}\n"

        build_validation = self._inspect_project_build(pom_path)

        return {
            "combined_xml": combined_content,
            "dwl_files": dwl_files,
            "xml_count": len(mule_files),
            "dwl_count": len(dwl_files),
            "build_validation": build_validation,
            "scan_details": scan_details,
        }

    def _looks_like_mule_xml_file(self, file_path: str) -> bool:
        """Return True when an XML file appears to be a Mule configuration file."""
        return self._classify_mule_xml_file(file_path)[0]

    def _classify_mule_xml_file(self, file_path: str) -> tuple:
        """Return (is_mule_config, reason) for an XML file."""
        try:
            raw = Path(file_path).read_bytes()
        except Exception:
            return False, "could not read file"

        # Decode with best-effort fallback
        for enc in ('utf-8-sig', 'utf-8', 'latin-1'):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = raw.decode('utf-8', errors='replace')

        if "<mule" not in text:
            return False, "does not contain a Mule root"

        # Sanitize: strip BOM, illegal control chars, inject missing xmlns
        # declarations (e.g. xmlns:doc) before attempting to parse.
        sanitized = XMLAnalyzer._sanitize_xml_string(text.strip())
        try:
            root = ET.fromstring(sanitized)
        except Exception as exc:
            return False, f"XML parse error: {exc}"
        local_name = root.tag.split("}", 1)[-1] if "}" in root.tag else root.tag
        if local_name != "mule":
            return False, f"root element is <{local_name}>, not <mule>"
        return True, "mule config"

    def _extract_nested_archives(self, temp_dir: str, scan_details: dict) -> None:
        """Extract ZIPs nested inside the uploaded archive, common in exported code bundles."""
        import zipfile

        extracted_root = os.path.join(temp_dir, "_nested_archives")
        archive_paths = []
        for root, _dirs, files in os.walk(temp_dir):
            if os.path.basename(root) == "_nested_archives":
                continue
            for file_name in files:
                if root == temp_dir and file_name == "project.zip":
                    continue
                if file_name.lower().endswith((".zip", ".jar")):
                    archive_paths.append(os.path.join(root, file_name))

        for index, archive_path in enumerate(archive_paths[:5], start=1):
            try:
                target_dir = os.path.join(extracted_root, f"archive_{index}")
                os.makedirs(target_dir, exist_ok=True)
                with zipfile.ZipFile(archive_path, "r") as nested_zip:
                    nested_zip.extractall(target_dir)
                scan_details["nested_archives"].append({
                    "path": os.path.relpath(archive_path, temp_dir).replace("\\", "/"),
                    "extracted_to": os.path.relpath(target_dir, temp_dir).replace("\\", "/"),
                })
            except Exception as exc:
                scan_details["nested_archives"].append({
                    "path": os.path.relpath(archive_path, temp_dir).replace("\\", "/"),
                    "error": str(exc),
                })

    def _inspect_project_build(self, pom_path: Optional[str]) -> dict:
        """Check whether the project appears ready to run generated MUnit tests."""
        result = {
            "has_pom": False,
            "status": "unknown",
            "munit_plugin_present": False,
            "munit_runner_dependency_present": False,
            "munit_tools_dependency_present": False,
            "munit_dependency_present": False,
            "munit_version": None,
            "munit_plugin_version": None,
            "mule_runtime_version": None,
            "recommended_munit_version": None,
            "latest_munit_version": None,
            "latest_munit_plugin_version": None,
            "latest_lookup_status": "not_attempted",
            "missing_dependencies": [],
            "missing_plugins": [],
            "recommended_snippets": [],
            "runtime_dependencies": [],
            "warnings": [],
            "errors": []
        }

        if not pom_path or not os.path.exists(pom_path):
            result["status"] = "warning"
            result["warnings"].append("pom.xml not found, so MUnit dependency/plugin readiness could not be checked.")
            return result

        result["has_pom"] = True
        try:
            pom_content = Path(pom_path).read_text(encoding='utf-8', errors='replace')
            root = ET.fromstring(pom_content)
        except Exception as exc:
            result["status"] = "warning"
            result["warnings"].append("pom.xml was found but could not be read for MUnit validation.")
            result["errors"].append(str(exc))
            return result

        properties = self._extract_pom_properties(root)
        dependencies = self._extract_pom_artifacts(root, "dependencies/dependency")
        plugins = self._extract_pom_artifacts(root, "build/plugins/plugin")
        result["runtime_dependencies"] = self._runtime_dependency_hints(dependencies, properties)

        runner = self._find_artifact(dependencies, "org.mule.munit", "munit-runner")
        tools = self._find_artifact(dependencies, "org.mule.munit", "munit-tools")
        plugin = self._find_artifact(plugins, "org.mule.tools.maven", "munit-maven-plugin")

        result["munit_runner_dependency_present"] = bool(runner)
        result["munit_tools_dependency_present"] = bool(tools)
        result["munit_dependency_present"] = bool(runner and tools)
        result["munit_plugin_present"] = bool(plugin)

        result["munit_version"] = (
            self._resolve_pom_version(runner.get("version") if runner else None, properties)
            or self._resolve_pom_version(tools.get("version") if tools else None, properties)
            or self._resolve_pom_version(properties.get("munit.version"), properties)
        )
        result["munit_plugin_version"] = self._resolve_pom_version(
            plugin.get("version") if plugin else None,
            properties
        ) if plugin else None

        result["mule_runtime_version"] = self._extract_mule_runtime_version(properties)
        result["recommended_munit_version"] = self._resolve_recommended_munit_version(
            result["mule_runtime_version"]
        )

        latest_versions = self._lookup_latest_munit_versions(root)
        result["latest_munit_version"] = latest_versions.get("munit")
        result["latest_munit_plugin_version"] = latest_versions.get("plugin")
        result["latest_lookup_status"] = latest_versions.get("status", "unavailable")
        if latest_versions.get("warning"):
            result["warnings"].append(latest_versions["warning"])

        if not result["munit_version"]:
            result["munit_version"] = result["recommended_munit_version"]
        if not result["munit_plugin_version"]:
            result["munit_plugin_version"] = result["recommended_munit_version"]

        if not runner:
            result["missing_dependencies"].append("org.mule.munit:munit-runner")
            result["warnings"].append("MUnit runner dependency is missing from pom.xml.")
        elif runner.get("scope") and runner.get("scope") != "test":
            result["warnings"].append("munit-runner dependency should normally use <scope>test</scope>.")

        if not tools:
            result["missing_dependencies"].append("org.mule.munit:munit-tools")
            result["warnings"].append("MUnit tools dependency is missing from pom.xml.")
        elif tools.get("scope") and tools.get("scope") != "test":
            result["warnings"].append("munit-tools dependency should normally use <scope>test</scope>.")

        if not plugin:
            result["missing_plugins"].append("org.mule.tools.maven:munit-maven-plugin")
            result["warnings"].append("munit-maven-plugin was not detected in pom.xml.")

        if result["missing_dependencies"] or result["missing_plugins"]:
            result["recommended_snippets"] = self._build_munit_pom_recommendations(result)

        if result["warnings"]:
            result["status"] = "warning"
        else:
            result["status"] = "ready"

        return result

    def _extract_pom_properties(self, root: ET.Element) -> dict:
        """Extract Maven properties from pom.xml without depending on XML prefixes."""
        properties = {}
        properties_node = self._find_direct_child(root, "properties")
        if properties_node is None:
            return properties

        for child in list(properties_node):
            properties[self._xml_local_name(child.tag)] = (child.text or "").strip()
        return properties

    def _extract_pom_artifacts(self, root: ET.Element, path: str) -> list:
        """Extract Maven artifact coordinates from a simple slash-separated path."""
        nodes = [root]
        for part in path.split("/"):
            next_nodes = []
            for node in nodes:
                next_nodes.extend(self._find_direct_children(node, part))
            nodes = next_nodes

        artifacts = []
        for node in nodes:
            artifacts.append({
                "groupId": self._child_text(node, "groupId"),
                "artifactId": self._child_text(node, "artifactId"),
                "version": self._child_text(node, "version"),
                "scope": self._child_text(node, "scope"),
                "type": self._child_text(node, "type"),
                "classifier": self._child_text(node, "classifier"),
            })
        return artifacts

    def _runtime_dependency_hints(self, dependencies: list, properties: dict) -> list:
        """Return non-test Maven dependencies that may contribute Mule runtime flows."""
        hints = []
        ignored_groups = {
            "org.mule.munit",
            "com.mulesoft.munit",
            "junit",
            "org.junit.jupiter",
            "org.mockito",
        }
        ignored_artifacts = {"munit-runner", "munit-tools"}
        for dep in dependencies or []:
            group_id = (dep.get("groupId") or "").strip()
            artifact_id = (dep.get("artifactId") or "").strip()
            scope = (dep.get("scope") or "").strip()
            if not group_id or not artifact_id:
                continue
            if scope == "test" or group_id in ignored_groups or artifact_id in ignored_artifacts:
                continue
            version = self._resolve_pom_version(dep.get("version"), properties) or ""
            packaging = (dep.get("type") or dep.get("classifier") or "jar").strip() or "jar"
            extension = "jar"
            if "mule-application" in packaging or "mule-plugin" in packaging:
                extension = "jar"
            local_path = self._maven_local_repo_path(group_id, artifact_id, version, extension)
            hints.append({
                "groupId": group_id,
                "artifactId": artifact_id,
                "version": version,
                "scope": scope or "compile",
                "type": packaging,
                "coordinates": f"{group_id}:{artifact_id}:{version or '?'}",
                "local_maven_path": local_path,
            })
        return hints[:20]

    def _maven_local_repo_path(self, group_id: str, artifact_id: str, version: str, extension: str = "jar") -> str:
        group_path = "/".join(part for part in group_id.split(".") if part)
        file_version = version or "<version>"
        return (
            f"~/.m2/repository/{group_path}/{artifact_id}/{file_version}/"
            f"{artifact_id}-{file_version}.{extension}"
        )

    def _find_artifact(self, artifacts: list, group_id: str, artifact_id: str) -> Optional[dict]:
        """Find a dependency/plugin by exact Maven coordinates."""
        for artifact in artifacts:
            if artifact.get("groupId") == group_id and artifact.get("artifactId") == artifact_id:
                return artifact
        return None

    def _resolve_pom_version(self, version: Optional[str], properties: dict) -> Optional[str]:
        """Resolve simple ${property.name} Maven version expressions."""
        if not version:
            return None
        version = version.strip()
        if version.startswith("${") and version.endswith("}"):
            return properties.get(version[2:-1], version)
        return version

    def _extract_mule_runtime_version(self, properties: dict) -> Optional[str]:
        """Extract Mule runtime version from common pom.xml properties."""
        for key in ("app.runtime", "mule.version", "mule.runtime.version", "mule.runtime", "runtimeVersion"):
            value = self._resolve_pom_version(properties.get(key), properties)
            if value and not value.startswith("${"):
                return value
        return None

    def _resolve_recommended_munit_version(self, mule_runtime: Optional[str]) -> str:
        """Map Mule runtime version to a compatible MUnit dependency version.

        MUnit 3.x is only compatible with Mule 4.5+.
        Mule 4.1–4.4 must use MUnit 2.x.
        """
        if not mule_runtime:
            return self.DEFAULT_MUNIT_VERSION

        parts = mule_runtime.strip().split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            runtime_key = f"{parts[0]}.{parts[1]}"
            return self.MULE_RUNTIME_MUNIT_VERSIONS.get(runtime_key, self.DEFAULT_MUNIT_VERSION)
        return self.DEFAULT_MUNIT_VERSION

    def _resolve_recommended_plugin_version(self, munit_version: str) -> str:
        """Return the munit-maven-plugin version that matches the given MUnit version."""
        if not munit_version:
            return self.DEFAULT_MUNIT_VERSION
        # Derive series from first two components e.g. "2.3.15" → "2.3", "3.6.0" → "3.6"
        parts = munit_version.strip().split(".")
        if len(parts) >= 2:
            series = f"{parts[0]}.{parts[1]}"
            if series in self.MUNIT_PLUGIN_VERSIONS:
                return self.MUNIT_PLUGIN_VERSIONS[series]
        return munit_version  # fall back to same version

    def _build_munit_pom_recommendations(self, validation: dict) -> list:
        """Return copy-ready POM snippets for missing MUnit build pieces.

        Snippet versions are derived from the recommended MUnit version which
        is already correctly mapped from the Mule runtime version in pom.xml
        (or from the user's manual selection).
        """
        munit_version = (
            validation.get("recommended_munit_version")
            or validation.get("munit_version")
            or self.DEFAULT_MUNIT_VERSION
        )
        # Derive correct plugin version from the MUnit dependency version
        plugin_version = self._resolve_recommended_plugin_version(munit_version)
        snippets = []

        missing_deps = set(validation.get("missing_dependencies", []))
        if missing_deps:
            dependency_lines = []
            if "org.mule.munit:munit-runner" in missing_deps:
                dependency_lines.append(f"""<dependency>
    <groupId>org.mule.munit</groupId>
    <artifactId>munit-runner</artifactId>
    <version>{munit_version}</version>
    <classifier>mule-plugin</classifier>
    <scope>test</scope>
</dependency>""")
            if "org.mule.munit:munit-tools" in missing_deps:
                dependency_lines.append(f"""<dependency>
    <groupId>org.mule.munit</groupId>
    <artifactId>munit-tools</artifactId>
    <version>{munit_version}</version>
    <classifier>mule-plugin</classifier>
    <scope>test</scope>
</dependency>""")
            snippets.append({
                "title": f"Add these inside <dependencies>  (MUnit {munit_version} — matched to your Mule runtime)",
                "xml": "\n".join(dependency_lines)
            })

        if "org.mule.tools.maven:munit-maven-plugin" in validation.get("missing_plugins", []):
            snippets.append({
                "title": f"Add this inside <build><plugins>  (plugin {plugin_version})",
                "xml": f"""<plugin>
    <groupId>org.mule.tools.maven</groupId>
    <artifactId>munit-maven-plugin</artifactId>
    <version>{plugin_version}</version>
    <executions>
        <execution>
            <id>test</id>
            <phase>test</phase>
            <goals>
                <goal>test</goal>
                <goal>coverage-report</goal>
            </goals>
        </execution>
    </executions>
</plugin>"""
            })

        return snippets

    def _lookup_latest_munit_versions(self, pom_root: ET.Element) -> dict:
        """Best-effort latest version lookup from Maven metadata."""
        repositories = self._extract_pom_repositories(pom_root)
        repositories.extend([
            "https://repository.mulesoft.org/nexus/content/repositories/releases/",
            "https://repo1.maven.org/maven2/",
        ])

        result = {
            "munit": None,
            "plugin": None,
            "status": "unavailable",
            "warning": None,
        }

        munit_version = self._fetch_latest_maven_version(
            "org.mule.munit",
            "munit-runner",
            repositories,
        )
        plugin_version = self._fetch_latest_maven_version(
            "org.mule.tools.maven",
            "munit-maven-plugin",
            repositories,
        )

        result["munit"] = munit_version
        result["plugin"] = plugin_version

        if munit_version or plugin_version:
            result["status"] = "resolved"
        else:
            result["warning"] = (
                "Could not resolve latest MUnit versions from Maven metadata; "
                "recommendations use versions already present in pom.xml or the built-in fallback."
            )

        return result

    def _extract_pom_repositories(self, root: ET.Element) -> list:
        """Extract repository and pluginRepository URLs from pom.xml."""
        urls = []
        for path in ("repositories/repository", "pluginRepositories/pluginRepository"):
            nodes = [root]
            for part in path.split("/"):
                next_nodes = []
                for node in nodes:
                    next_nodes.extend(self._find_direct_children(node, part))
                nodes = next_nodes
            for repository in nodes:
                url = self._child_text(repository, "url")
                if url and url not in urls:
                    urls.append(url)
        return urls

    def _fetch_latest_maven_version(self, group_id: str, artifact_id: str, repositories: list) -> Optional[str]:
        """Fetch latest/release version from maven-metadata.xml using configured repositories."""
        artifact_path = "/".join(group_id.split(".") + [artifact_id, "maven-metadata.xml"])

        for repository in repositories:
            base_url = (repository or "").rstrip("/")
            if not base_url.startswith(("http://", "https://")):
                continue

            metadata_url = f"{base_url}/{artifact_path}"
            try:
                with urllib.request.urlopen(metadata_url, timeout=3) as response:
                    metadata_xml = response.read().decode("utf-8", errors="replace")
                return self._parse_latest_maven_version(metadata_xml)
            except (urllib.error.URLError, TimeoutError, ET.ParseError, ValueError, OSError) as exc:
                logger.debug("Maven metadata lookup failed for %s: %s", metadata_url, exc)

        return None

    def _parse_latest_maven_version(self, metadata_xml: str) -> Optional[str]:
        """Parse latest stable version from maven-metadata.xml."""
        root = ET.fromstring(metadata_xml)
        versioning = self._find_direct_child(root, "versioning")
        if versioning is None:
            return None

        for field_name in ("release", "latest"):
            value = self._child_text(versioning, field_name)
            if value and not self._is_unstable_maven_version(value):
                return value

        versions_node = self._find_direct_child(versioning, "versions")
        if versions_node is None:
            return None

        versions = [
            (version_node.text or "").strip()
            for version_node in self._find_direct_children(versions_node, "version")
            if (version_node.text or "").strip()
        ]
        stable_versions = [version for version in versions if not self._is_unstable_maven_version(version)]
        return stable_versions[-1] if stable_versions else None

    def _is_unstable_maven_version(self, version: str) -> bool:
        """Return True for non-release Maven versions (snapshots, RC, milestones, alpha/beta)."""
        normalized = (version or "").lower()
        if "snapshot" in normalized:
            return True
        for marker in ("-rc", "-m", "-alpha", "-beta"):
            if marker in normalized:
                return True
        return False

    def _find_direct_child(self, node: ET.Element, local_name: str) -> Optional[ET.Element]:
        """Find the first direct child with the requested local tag name."""
        matches = self._find_direct_children(node, local_name)
        return matches[0] if matches else None

    def _find_direct_children(self, node: ET.Element, local_name: str) -> list:
        """Find direct children with the requested local tag name."""
        return [child for child in list(node) if self._xml_local_name(child.tag) == local_name]

    def _child_text(self, node: ET.Element, local_name: str) -> str:
        """Return stripped text from a direct child."""
        child = self._find_direct_child(node, local_name)
        return (child.text or "").strip() if child is not None else ""

    def _xml_local_name(self, tag: str) -> str:
        """Return XML local name without namespace."""
        return tag.split("}", 1)[-1] if "}" in tag else tag

    def _set_project_context(self, project_files: dict):
        """Store extracted project context for targeted prompt construction."""
        self._project_dwl_files = project_files.get("dwl_files", {}) or {}
    
    def _sanitize_flow_summary(self, flow_summary: dict) -> dict:
        """
        Sanitize flow summary to remove sensitive data before LLM processing.
        
        Args:
            flow_summary: Original flow summary from XML analyzer
            
        Returns:
            Sanitized flow summary with sensitive data redacted
        """
        sanitized = flow_summary.copy()
        
        # Sanitize raw XML content if present
        if 'raw_xml' in sanitized:
            analysis = self.security_sanitizer.analyze_and_sanitize(sanitized['raw_xml'])
            sanitized['raw_xml'] = analysis.sanitized_content
            if not analysis.is_safe:
                logger.warning(f"Sensitive data detected and redacted: {analysis.sensitive_data_detected}")
        
        # Sanitize flow contexts
        if 'flow_contexts' in sanitized:
            for flow_name, context in sanitized['flow_contexts'].items():
                if 'flow_xml' in context:
                    analysis = self.security_sanitizer.analyze_and_sanitize(context['flow_xml'])
                    context['flow_xml'] = analysis.sanitized_content
        
        # Sanitize connector configurations
        if 'connectors' in sanitized:
            for connector in sanitized.get('connectors', []):
                if isinstance(connector, dict) and 'config' in connector:
                    analysis = self.security_sanitizer.analyze_and_sanitize(str(connector['config']))
                    connector['config'] = analysis.sanitized_content
        
        return sanitized

    def apply_selected_flows(self, flow_summary: dict, selected_flows: list) -> dict:
        """Restrict generation to user-selected parent flows while keeping child context."""
        if not selected_flows:
            return flow_summary

        flow_graph = flow_summary.get("flow_graph", {}) or {}
        existing_contexts = flow_summary.get("flow_contexts", {}) or {}
        selected = self._dedupe_preserve_order(
            [
                flow for flow in selected_flows
                if flow in flow_graph or flow in existing_contexts
            ]
        )
        if not selected:
            return flow_summary
        selected = selected[:1]

        filtered_summary = dict(flow_summary)
        filtered_summary["test_targets"] = selected
        filtered_summary["selected_flows"] = selected
        if flow_graph:
            rebuilt_contexts = self.xml_analyzer._build_flow_contexts(selected, flow_graph)
            merged_contexts = dict(existing_contexts)
            merged_contexts.update(rebuilt_contexts)
            filtered_summary["flow_contexts"] = merged_contexts
        return filtered_summary

    def _apply_user_dynamic_flow_targets(self, flow_summary: dict, params: dict) -> dict:
        """Apply user-supplied targets for unresolved dynamic flow-ref expressions."""
        targets = self._build_dynamic_flow_targets_dict(params)
        if not targets:
            return flow_summary

        flow_graph = flow_summary.get("flow_graph", {}) or {}
        if not flow_graph:
            return flow_summary

        selected = flow_summary.get("test_targets") or flow_summary.get("selected_flows") or []
        if not selected:
            selected = flow_summary.get("flows") or []

        known_flows = set(flow_graph.keys())
        changed = False

        def targets_for(unresolved: dict) -> List[str]:
            keys = [
                unresolved.get("expression", ""),
                unresolved.get("doc_name", ""),
                unresolved.get("flow", ""),
                "_all",
            ]
            merged: List[str] = []
            for key in keys:
                for name in targets.get(key, []) or []:
                    if name in known_flows and name not in merged:
                        merged.append(name)
            return merged

        for target_flow in selected:
            context = (flow_summary.get("flow_contexts") or {}).get(target_flow, {}) or {}
            for unresolved in context.get("unresolved_flow_refs", []) or []:
                resolved_targets = targets_for(unresolved)
                if not resolved_targets:
                    continue
                source_flow = unresolved.get("flow") or target_flow
                expression = unresolved.get("expression", "")
                doc_name = unresolved.get("doc_name", "")
                node = flow_graph.get(source_flow)
                if not node:
                    continue
                for processor in node.get("processor_chain", []) or []:
                    if processor.get("type") != "flow-ref":
                        continue
                    proc_expr = processor.get("name") or processor.get("ref") or processor.get("target") or ""
                    proc_doc = processor.get("doc_name", "")
                    if expression and proc_expr != expression:
                        continue
                    if doc_name and proc_doc != doc_name:
                        continue
                    existing = list(processor.get("dynamic_flow_candidates", []) or [])
                    merged = self._dedupe_preserve_order(existing + resolved_targets)
                    processor["dynamic_flow_candidates"] = merged
                    processor["dynamic"] = True
                    processor["dynamic_unresolved"] = False
                    for child in resolved_targets:
                        if child not in node.get("children", []):
                            node.setdefault("children", []).append(child)
                        child_node = flow_graph.get(child)
                        if child_node is not None and source_flow not in child_node.get("parents", []):
                            child_node.setdefault("parents", []).append(source_flow)
                    changed = True

        if not changed:
            return flow_summary

        updated_summary = dict(flow_summary)
        updated_summary["flow_graph"] = flow_graph
        if selected:
            rebuilt_contexts = self.xml_analyzer._build_flow_contexts(selected, flow_graph)
            merged_contexts = dict(flow_summary.get("flow_contexts", {}) or {})
            merged_contexts.update(rebuilt_contexts)
            updated_summary["flow_contexts"] = merged_contexts
        return updated_summary

    def _apply_external_flow_links(self, flow_summary: dict, params: dict) -> dict:
        """
        Link a missing dependency flow back to local flows when the user knows
        that the dependency app calls them at runtime.

        Example accepted input:
        [{"externalFlow":"validate-shared-flow","linkedLocalFlows":["current-app-flow"]}]
        """
        links = self._build_external_flow_links_dict(params)
        if not links:
            return flow_summary

        flow_graph = flow_summary.get("flow_graph", {}) or {}
        if not flow_graph:
            return flow_summary

        selected = flow_summary.get("test_targets") or flow_summary.get("selected_flows") or []
        if not selected:
            selected = flow_summary.get("flows") or []

        changed = False
        for external_flow, local_flows in links.items():
            external_node = flow_graph.get(external_flow)
            if not external_node or not external_node.get("external_dependency"):
                continue

            valid_local_flows = [
                name for name in self._dedupe_preserve_order(local_flows)
                if name in flow_graph and not flow_graph.get(name, {}).get("external_dependency")
            ]
            if not valid_local_flows:
                continue

            external_node.setdefault("children", [])
            external_node.setdefault("processor_chain", [])
            external_node["external_linked_local_flows"] = self._dedupe_preserve_order(
                list(external_node.get("external_linked_local_flows", []) or []) + valid_local_flows
            )

            existing_linked_refs = {
                item.get("name") or item.get("ref") or item.get("target")
                for item in external_node.get("processor_chain", []) or []
                if item.get("type") == "flow-ref" and item.get("external_bridge")
            }
            for local_flow in valid_local_flows:
                if local_flow not in external_node["children"]:
                    external_node["children"].append(local_flow)
                local_node = flow_graph.get(local_flow)
                if local_node is not None and external_flow not in local_node.get("parents", []):
                    local_node.setdefault("parents", []).append(external_flow)
                if local_flow not in existing_linked_refs:
                    external_node["processor_chain"].append({
                        "index": len(external_node.get("processor_chain", [])) + 1,
                        "type": "flow-ref",
                        "doc_name": f"Linked local flow {local_flow}",
                        "name": local_flow,
                        "flow": external_flow,
                        "external_bridge": True,
                    })
                    existing_linked_refs.add(local_flow)
                changed = True

        if not changed:
            return flow_summary

        updated_summary = dict(flow_summary)
        updated_summary["flow_graph"] = flow_graph
        if selected:
            rebuilt_contexts = self.xml_analyzer._build_flow_contexts(selected, flow_graph)
            merged_contexts = dict(flow_summary.get("flow_contexts", {}) or {})
            merged_contexts.update(rebuilt_contexts)
            updated_summary["flow_contexts"] = merged_contexts
        return updated_summary

    def _build_external_flow_links_dict(self, params: dict) -> Dict[str, List[str]]:
        raw_values = []
        ftd = self._build_flow_test_data_dict(params)
        if ftd.get("externalFlowLinks"):
            raw_values.append(ftd.get("externalFlowLinks"))
        for key in ("external_flow_links", "externalFlowLinks"):
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                raw_values.append(value.strip())

        links: Dict[str, List[str]] = {}
        for raw in raw_values:
            for external_flow, local_flows in self._parse_external_flow_links(raw).items():
                links.setdefault(external_flow, [])
                links[external_flow] = self._dedupe_preserve_order(links[external_flow] + local_flows)
        return links

    def _parse_external_flow_links(self, raw: Any) -> Dict[str, List[str]]:
        if raw is None:
            return {}

        def clean(value: Any) -> str:
            return str(value or "").strip().strip("'\"")

        text = ""
        if isinstance(raw, (list, dict)):
            parsed = raw
        else:
            text = str(raw or "").strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None

        result: Dict[str, List[str]] = {}
        if isinstance(parsed, list):
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                external_flow = clean(
                    item.get("externalFlow")
                    or item.get("external_flow")
                    or item.get("dependencyFlow")
                    or item.get("flow")
                )
                local_values = (
                    item.get("linkedLocalFlows")
                    or item.get("linked_local_flows")
                    or item.get("internalFlows")
                    or item.get("localFlows")
                    or item.get("calls")
                    or []
                )
                if isinstance(local_values, str):
                    local_values = re.split(r"[\n,]+", local_values)
                if external_flow:
                    result.setdefault(external_flow, [])
                    result[external_flow].extend(clean(value) for value in local_values if clean(value))
        elif isinstance(parsed, dict):
            for external_flow, value in parsed.items():
                local_values = value if isinstance(value, list) else [value]
                external_key = clean(external_flow)
                if external_key:
                    result.setdefault(external_key, [])
                    result[external_key].extend(clean(item) for item in local_values if clean(item))
        else:
            # Compact text form: externalFlow -> localA, localB
            for line in text.splitlines():
                if "->" not in line:
                    continue
                left, right = line.split("->", 1)
                external_flow = clean(left)
                if not external_flow:
                    continue
                result.setdefault(external_flow, [])
                result[external_flow].extend(
                    clean(part) for part in re.split(r"[,]+", right) if clean(part)
                )

        return {
            external_flow: self._dedupe_preserve_order([name for name in local_flows if name])
            for external_flow, local_flows in result.items()
            if external_flow and local_flows
        }

    def _build_dynamic_flow_targets_dict(self, params: dict) -> Dict[str, List[str]]:
        """Parse user answers for unresolved dynamic flow-ref targets."""
        raw_values = []
        ftd = self._build_flow_test_data_dict(params)
        if ftd.get("dynamicFlowTargets"):
            raw_values.append(ftd.get("dynamicFlowTargets"))
        for key in ("dynamic_flow_targets", "dynamicFlowTargets", "flow_ref_targets"):
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                raw_values.append(value.strip())

        targets: Dict[str, List[str]] = {}
        for raw in raw_values:
            for key, names in self._parse_dynamic_flow_targets(raw).items():
                targets.setdefault(key, [])
                targets[key] = self._dedupe_preserve_order(targets[key] + names)
        return targets

    def _parse_dynamic_flow_targets(self, raw: str) -> Dict[str, List[str]]:
        text = (raw or "").strip()
        if not text:
            return {}

        def clean_name(value: Any) -> str:
            return str(value or "").strip().strip("'\"")

        result: Dict[str, List[str]] = {"_all": []}
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    name = clean_name(
                        item.get("targetFlow")
                        or item.get("target_flow")
                        or item.get("flow")
                        or item.get("name")
                    )
                    key = clean_name(item.get("expression") or item.get("doc_name") or item.get("sourceFlow") or "_all") or "_all"
                else:
                    name = clean_name(item)
                    key = "_all"
                if name:
                    result.setdefault(key, []).append(name)
        elif isinstance(parsed, dict):
            for key, value in parsed.items():
                names = value if isinstance(value, list) else [value]
                for name_value in names:
                    name = clean_name(
                        (name_value or {}).get("targetFlow")
                        if isinstance(name_value, dict)
                        else name_value
                    )
                    if name:
                        result.setdefault(clean_name(key) or "_all", []).append(name)
        else:
            for part in re.split(r"[\n,]+", text):
                name = clean_name(part)
                if name:
                    result["_all"].append(name)

        return {
            key: self._dedupe_preserve_order([name for name in names if name])
            for key, names in result.items()
            if names
        }

    def build_flow_selection_payload(self, flow_summary: dict) -> dict:
        """Build UI-friendly flow selection metadata."""
        contexts = flow_summary.get("flow_contexts", {}) or {}
        flow_graph = flow_summary.get("flow_graph", {}) or {}
        recommended = flow_summary.get("test_targets", []) or []
        flows_payload = []

        for flow_name, context in contexts.items():
            if context.get("direct_munit_excluded"):
                continue
            is_recommended = flow_name in recommended
            trigger = (context.get("trigger", {}) or {}).get("type", "")
            trigger_name = (context.get("trigger", {}) or {}).get("doc_name", "")
            munit_plan_preview = self._build_munit_plan_preview(context)
            flows_payload.append({
                "name": flow_name,
                "display_name": self._build_flow_display_name(flow_name, trigger, trigger_name),
                "type": context.get("target_type", "flow"),
                "source_file": context.get("source_file", "unknown.xml"),
                "trigger": trigger or "internal",
                "has_source_listener": bool(context.get("has_source_listener")),
                "is_parent_flow": bool(context.get("is_parent_flow")),
                "connectors": context.get("connectors", []),
                "mock_connectors": self._build_mock_connector_payload(flow_name, context),
                "mock_connector_count": len([
                    item for item in (context.get("mock_plan", []) or [])
                    if item.get("action") == "mock-when"
                ]),
                "munit_plan_preview": munit_plan_preview,
                "clarification_requests": munit_plan_preview.get("clarificationRequests", []),
                "planned_scenarios": self._build_flow_scenario_preview(context),
                "assertion_strategy": self._describe_assertion_strategy(context),
                "branch_points": context.get("branch_points", []),
                "variable_writes": context.get("variable_writes", []),
                "error_handlers": context.get("error_handlers", []),
                "child_flows": context.get("child_flows", []),
                "parent_flows": context.get("parent_flows", []),
                "related_flows": context.get("related_flows", []),
                "execution_flows": context.get("execution_flows", []),
                "unresolved_flow_refs": context.get("unresolved_flow_refs", []),
                "dynamic_flow_sources": context.get("dynamic_flow_sources", []),
                "external_flow_refs": context.get("external_flow_refs", []),
                "external_flow_names": context.get("external_flow_names", []),
                "external_assisted_flow_names": context.get("external_assisted_flow_names", []),
                "munit_enable_flow_sources": context.get("munit_enable_flow_sources", []),
                "recommended": is_recommended,
                "selection_reason": self._describe_flow_selection_reason(context, is_recommended)
            })

        # ── Group flows into three UI categories ─────────────────────────────
        # Use final flow_context/flow_graph data, not raw flow_details, because
        # dynamic flow-ref resolution can add parents after initial extraction.
        categories = {
            "entry_point": [],
            "api_resource": [],
            "external": [],
            "unreachable": [],
            "internal": [],
        }
        for flow in flows_payload:
            name = flow["name"]
            has_source = flow.get("is_parent_flow") or flow.get("has_source_listener")
            has_parent = bool(flow.get("parent_flows"))
            is_external = flow.get("type") == "external-dependency-flow" or bool(
                (flow_graph.get(name, {}) or {}).get("external_dependency")
            )
            if is_external:
                categories["external"].append(name)
            elif has_source:
                categories["entry_point"].append(name)
            elif self._is_apikit_resource_name(name):
                categories["api_resource"].append(name)
            elif has_parent:
                categories["internal"].append(name)
            else:
                categories["unreachable"].append(name)

        payload_by_name = {f["name"]: f for f in flows_payload}

        def _group(names):
            out = []
            for n in names:
                if n in payload_by_name:
                    out.append(payload_by_name[n])
            return sorted(out, key=lambda x: x["name"].lower())

        entry_point_flows  = _group(categories["entry_point"])
        api_resource_flows = _group(categories["api_resource"])
        external_flows     = _group(categories["external"])
        internal_flows     = _group(categories["internal"])
        unreachable_flows  = _group(categories["unreachable"])

        # Add flow_category field to every flow so the UI can group them
        for f in entry_point_flows:
            f["flow_category"] = "entry_point"
        for f in api_resource_flows:
            f["flow_category"] = "api_resource"
        for f in external_flows:
            f["flow_category"] = "external"
            f["selection_reason"] = (
                "Called by this app but XML is not present in the uploaded ZIP; "
                "treat as a parent/dependency Mule app flow."
            )
        for f in internal_flows:
            f["flow_category"] = "internal"
        for f in unreachable_flows:
            f["flow_category"] = "unreachable"

        recommended_flows = [f for f in flows_payload if f["recommended"]]
        all_flows = sorted(flows_payload, key=lambda item: (not item["recommended"], item["name"].lower()))

        return {
            "job_type":           flow_summary.get("job_type", "Generic Mule Flow"),
            "entry_point_flows":  entry_point_flows,
            "api_resource_flows": api_resource_flows,
            "external_flows":     external_flows,
            "internal_flows":     internal_flows,
            "unreachable_flows":  unreachable_flows,
            # Keep legacy keys so other parts of the app still work
            "recommended_flows":  recommended_flows,
            "parent_flows":       entry_point_flows,
            "listener_flows":     entry_point_flows,
            "all_flows":          all_flows,
        }

    def _is_apikit_resource_name(self, flow_name: str) -> bool:
        import re
        n = (flow_name or "").lower()
        return bool(re.match(r'^(get|post|put|patch|delete|head|options)[:\\\\\/]', n))

    def _build_mock_connector_payload(self, flow_name: str, context: dict) -> list:
        """
        Return UI-friendly connector sample prompts for a flow and ALL its
        descendant flows (full call chain: A→B→C→D→E/F).

        Uses traversal_connectors (from _traverse_flow_graph) which walks the
        complete call tree. Falls back to mock_plan (single-flow) if traversal
        data is not available.
        """
        connectors = []
        seen_keys = set()

        # ── Primary: use traversal connectors (deep, covers all child flows) ──
        traversal = context.get("traversal_connectors") or []
        if traversal:
            for item in traversal:
                processor = item.get("connector", "")
                if not processor or processor == "flow-ref":
                    continue
                action = self._classify_mock_action(processor)
                if action not in ("mock-when", "spy"):
                    continue
                source_flow = item.get("flow", flow_name)
                doc_name    = item.get("doc_name") or item.get("operation") or processor
                key = f"{processor}::{source_flow}::{doc_name}"
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                connectors.append({
                    "id":              self._connector_sample_key(flow_name, {
                                           "processor": processor,
                                           "match_value": doc_name,
                                       }),
                    "flow":            source_flow,
                    "source_flow":     source_flow,
                    "depth":           item.get("level", 0),
                    "processor":       processor,
                    "doc_name":        doc_name,
                    "match_attribute": "doc:name",
                    "match_value":     doc_name,
                    "media_type":      item.get("media_type", "application/json"),
                    "result_shape":    "object",
                    "display_name":    f"{doc_name} ({processor})" + (
                                           f" — in {source_flow}" if source_flow != flow_name else ""
                                       ),
                    "action":          action,
                    "position":        len(connectors) + 1,
                })
        # ── Merge mock_plan so external flow-ref mocks are not hidden by traversal data ──
        for index, item in enumerate(context.get("mock_plan", []) or [], start=1):
            if item.get("action") not in ("mock-when", "spy"):
                continue
            processor = item.get("processor", "connector")
            doc_name  = item.get("doc_name") or item.get("match_value") or processor
            source_flow = item.get("flow") or item.get("source_flow") or flow_name
            key = f"{processor}::{source_flow}::{doc_name}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            connectors.append({
                "id":              self._connector_sample_key(flow_name, item),
                "flow":            source_flow,
                "source_flow":     source_flow,
                "depth":           0,
                "processor":       processor,
                "doc_name":        doc_name,
                "match_attribute": item.get("match_attribute", "doc:name"),
                "match_value":     item.get("match_value") or doc_name,
                "media_type":      item.get("media_type", "application/json"),
                "result_shape":    item.get("result_shape", "object"),
                "display_name":    (
                    f"{doc_name} ({processor})"
                    + (f" — external {item.get('external_flow')}" if item.get("external_flow") else "")
                ),
                "action":          item.get("action", "mock-when"),
                "position":        index,
                "external_dependency": bool(item.get("external_dependency")),
                "external_flow":   item.get("external_flow", ""),
                "reason":          item.get("reason", ""),
            })
        return connectors

    MOCK_PROCESSORS = {
        "http:request","wsc:consume",
        "db:select","db:insert","db:update","db:delete","db:stored-procedure",
        "salesforce:query","salesforce:create","salesforce:update","salesforce:delete",
        "salesforce:upsert","salesforce:retrieve",
        "sap:synchronous-remote-function-call","sap:send",
        "sftp:read","ftp:read","file:read",
        "jms:publish-consume","vm:publish-consume",
        "objectstore:retrieve","objectstore:contains",
        "servicenow:invoke","workday:invoke","redis:get",
    }
    SPY_PROCESSORS = {
        "anypoint-mq:publish","kafka:publish","amqp:publish","rabbitmq:publish",
        "jms:publish","vm:publish","email:send",
        "sftp:write","ftp:write","file:write",
        "objectstore:store","objectstore:remove",
    }

    def _classify_mock_action(self, processor_type: str) -> str:
        p = (processor_type or "").lower().strip()
        if p in self.MOCK_PROCESSORS:
            return "mock-when"
        if p in self.SPY_PROCESSORS:
            return "spy"
        # Heuristic fallback
        if any(x in p for x in ("request","query","select","retrieve","read","get","invoke","consume")):
            return "mock-when"
        if any(x in p for x in ("publish","write","send","store","push","emit","produce")):
            return "spy"
        return "none"

    def _build_flow_scenario_preview(self, context: dict) -> list:
        """Return the backend scenario plan shown before generation."""
        scenarios = self.deterministic_builder._build_scenario_plan(
            context,
            scenarios=context.get("scenarios") or None,
            generation_mode="recorder",
        )
        return [
            {
                "name": item.get("name"),
                "type": item.get("type"),
                "description": item.get("description"),
                "assertion_strategy": item.get("assertion_strategy", "payload_equals_expected"),
                "expected_error_type": item.get("expected_error_type"),
                "failed_processor": item.get("failed_processor"),
                "empty_result_shape": item.get("empty_result_shape"),
                "branch_condition": item.get("branch_condition"),
            }
            for item in scenarios
        ]

    def build_selected_flow_trace_payload(
        self,
        flow_summary: dict,
        selected_flows: list,
        build_validation: Optional[dict] = None,
    ) -> dict:
        """Build the UI payload for selected-flow trace review and external stops."""
        contexts = flow_summary.get("flow_contexts", {}) or {}
        flow_graph = flow_summary.get("flow_graph", {}) or {}
        selected = (
            flow_summary.get("selected_flows")
            or selected_flows
            or flow_summary.get("test_targets")
            or []
        )
        local_flows = sorted(
            [
                name for name, node in flow_graph.items()
                if not (node or {}).get("external_dependency")
            ],
            key=str.lower,
        )
        dependency_hints = (build_validation or {}).get("runtime_dependencies", []) or []

        traces = []
        external_stops = []
        seen_stops = set()
        for flow_name in selected:
            context = contexts.get(flow_name, {}) or {}
            execution_flows = context.get("execution_flows", []) or [flow_name]
            trace_nodes = []
            for name in execution_flows:
                node = flow_graph.get(name, {}) or {}
                is_external = bool(node.get("external_dependency"))
                trace_nodes.append({
                    "name": name,
                    "type": node.get("type") or context.get("target_type") or "flow",
                    "source_file": node.get("source_file", "unknown.xml"),
                    "external": is_external,
                    "linked_local_flows": node.get("external_linked_local_flows", []) or [],
                })
                if is_external and name not in seen_stops:
                    seen_stops.add(name)
                    external_stops.append({
                        "flow": name,
                        "called_from": node.get("parents", []) or context.get("parent_flows", []),
                        "dependency_hint": dependency_hints[0] if dependency_hints else {},
                        "dependency_hints": dependency_hints[:5],
                        "message": (
                            f"Flow {name} is from a runtime dependency or shared Mule module. "
                            "Its XML is not present in the uploaded app, so I cannot automatically trace inside it."
                        ),
                    })
            traces.append({
                "flow": flow_name,
                "execution_flows": execution_flows,
                "nodes": trace_nodes,
                "external_flow_refs": context.get("external_flow_refs", []) or [],
                "unresolved_flow_refs": context.get("unresolved_flow_refs", []) or [],
                "munit_enable_flow_sources": context.get("munit_enable_flow_sources", []) or [],
            })

        return {
            "traces": traces,
            "external_stops": external_stops,
            "local_flow_candidates": local_flows,
            "dependency_hints": dependency_hints[:10],
        }

    def _build_munit_plan_preview(self, context: dict) -> dict:
        """Return a compact Behavior / Execution / Validation preview for the UI."""
        scenarios = self.deterministic_builder._build_scenario_plan(
            context,
            scenarios=context.get("scenarios") or None,
            generation_mode="recorder",
        )
        plan = self.deterministic_builder._build_munit_plan(
            context,
            scenarios,
            generation_mode="recorder",
        )
        return {
            "execution": plan.get("execution", {}),
            "behavior": {
                "mock_count": len((plan.get("behavior") or {}).get("mockWhen", [])),
                "spy_count": len((plan.get("behavior") or {}).get("spy", [])),
                "verify_later_count": len((plan.get("behavior") or {}).get("verifyLater", [])),
            },
            "validation": [
                {
                    "scenario": item.get("scenario"),
                    "type": item.get("type"),
                    "assertions": item.get("assertions", []),
                    "verifications": item.get("verifications", []),
                    "expectedErrorType": item.get("expectedErrorType"),
                }
                for item in (plan.get("validation") or [])[:8]
            ],
            "clarificationRequests": (plan.get("clarificationRequests") or [])[:8],
            "warnings": (plan.get("warnings") or [])[:8],
        }

    def _describe_assertion_strategy(self, context: dict) -> str:
        """Describe how the deterministic builder will validate the final response."""
        final_processor = context.get("final_processor", {}) or {}
        if final_processor.get("dwl_excerpt"):
            return "Final DataWeave response equality"
        if context.get("mock_plan"):
            return "Passthrough connector response equality"
        if context.get("output_fields"):
            return "Derived output field equality"
        return "Fallback response equality"

    def _connector_sample_key(self, flow_name: str, mock_item: dict) -> str:
        """Stable key used by UI and builder to attach samples to connectors."""
        raw = "|".join([
            flow_name or "",
            mock_item.get("processor", ""),
            mock_item.get("match_value") or mock_item.get("doc_name") or "",
        ])
        return re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw).strip("_")

    def _build_flow_display_name(self, flow_name: str, trigger_type: str, trigger_name: str) -> str:
        """Build a friendlier flow label for the UI."""
        parts = [flow_name]
        if trigger_name:
            parts.append(trigger_name)
        elif trigger_type and trigger_type != "internal":
            parts.append(trigger_type)
        return " - ".join(parts)

    def _describe_flow_selection_reason(self, context: dict, is_recommended: bool) -> str:
        """Return a short reason shown in the UI."""
        if is_recommended:
            trigger = (context.get("trigger", {}) or {}).get("type", "")
            if trigger:
                return f"Recommended because it is an entry flow triggered by {trigger}."
            return "Recommended because it is a top-level business flow."
        if context.get("parent_flows"):
            return "Hidden by default because it is invoked by another parent flow and will be covered there."
        return "Available in advanced mode for explicit testing."

    def generate_blueprint_web(self, job_id: str, params: dict) -> dict:
        """
        Blueprint-compliant generation (Steps 3-8).

        Runs the full multi-step pipeline for each selected flow:
          Step 3 — Isolated flow context extraction
          Step 4 — Deterministic mock blueprint
          Step 5 — Multi-pass DWL + test XML generation
          Step 6 — Three structured scenarios (happy / error / edge)
          Step 7 — Backend template assembly + XML sanity check
          Step 8 — Optional Maven self-healing loop

        Args:
            job_id: Unique job identifier for async tracking.
            params:  Dictionary containing at minimum:
                       xml_file (str)           — combined project XML
                       selected_flows (list)    — flow names to generate tests for
                       run_maven (bool)         — whether to invoke Step 8 (default False)
                       project_root (str|None)  — path to Maven project root for Step 8

        Returns:
            Result dict with keys: success, flow_results, output_files, error.
        """
        try:
            active_jobs[job_id] = {
                'status': 'processing',
                'progress': 0,
                'message': 'Blueprint pipeline starting...',
            }
            output_path = self._configure_output_for_job(job_id, params)

            # Validate XML content
            if not params.get('xml_file'):
                raise Exception("No XML content available for processing")

            combined_xml = params['xml_file']
            self._project_dwl_files = params.get('project_dwl_files', {}) or {}

            # Resolve selected flows
            selected_flows = params.get('selected_flows') or []
            if isinstance(selected_flows, str):
                try:
                    selected_flows = json.loads(selected_flows)
                except Exception:
                    selected_flows = [selected_flows]

            # If no flows explicitly selected, derive from XML analysis
            if not selected_flows:
                active_jobs[job_id].update({'progress': 10, 'message': 'Analysing project flows...'})
                flow_summary = self.xml_analyzer.analyze_mule_project(combined_xml)
                selected_flows = flow_summary.get('test_targets') or flow_summary.get('flows') or []

            total_flows = len(selected_flows) or 1
            run_maven = str(params.get('run_maven', 'false')).lower() == 'true'
            project_root = params.get('project_root') or None

            flow_results = []
            all_output_files = []

            for idx, flow_name in enumerate(selected_flows):
                progress = int(20 + (idx / total_flows) * 75)
                active_jobs[job_id].update({
                    'progress': progress,
                    'message': f'Processing flow {idx + 1}/{total_flows}: {flow_name}',
                })

                flow_result = self.blueprint_pipeline.run(
                    flow_name=flow_name,
                    combined_xml=combined_xml,
                    run_maven=run_maven,
                    project_root=project_root,
                )
                flow_results.append(flow_result)

                if flow_result.get('output_file'):
                    all_output_files.append(flow_result['output_file'])
                all_output_files.extend(flow_result.get('dwl_files', {}).values())

            active_jobs[job_id].update({'progress': 100, 'message': 'Blueprint generation complete!'})

            results = {
                'success': all(r['success'] for r in flow_results),
                'flow_results': flow_results,
                'output_files': all_output_files,
                'output_file': all_output_files[0] if all_output_files else None,
                'flows_processed': len(flow_results),
                'build_validation': params.get('build_validation', {}),
                'output_path': output_path,
                'pipeline': 'blueprint',
            }
            job_results[job_id] = results
            return results

        except Exception as exc:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Error: {str(exc)}'}
            job_results[job_id] = {'success': False, 'error': str(exc)}
            return {'success': False, 'error': str(exc)}


    def _build_sample_payloads_dict(self, params: dict) -> dict:
        """
        Build a {flow_name: payload_text} dict from request params.
        Now also reads flow_test_data posted from the modal in Step 7.
        """
        samples = self._build_explicit_sample_payloads(params)

        # ── New: flow_test_data from the flow-data modal ──────────────────
        ftd = self._build_flow_test_data_dict(params)
        if ftd:
            payload_text = ftd.get("payload", "")
            expected_text = ftd.get("expectedResponse", "")
            combined = {}
            if payload_text:
                try:
                    combined["request"] = json.loads(payload_text)
                except Exception:
                    combined["request"] = payload_text
            if expected_text:
                try:
                    combined["response"] = json.loads(expected_text)
                except Exception:
                    combined["response"] = expected_text
            if ftd.get("statusCode"):
                combined["statusCode"] = str(ftd["statusCode"])
            if ftd.get("queryParams"):
                combined["queryParams"] = ftd["queryParams"]
            if ftd.get("uriParams"):
                combined["uriParams"] = ftd["uriParams"]
            if ftd.get("headers"):
                combined["headers"] = ftd["headers"]
            if combined:
                samples["_all"] = json.dumps(combined, indent=2)

        raw = self._first_non_empty_param(
            params,
            "sample_payload",
            "request_payload",
            "input_payload",
            "payload_sample",
            "request_sample",
        )
        if raw and "_all" not in samples:
            samples["_all"] = self._normalize_recorder_sample_payload(raw)
        field_samples = self._build_field_value_sample_payloads(params)
        for flow, sample in field_samples.items():
            samples.setdefault(flow, sample)
        if not raw and len(field_samples) == 1 and "_all" not in samples:
            samples["_all"] = next(iter(field_samples.values()))
        return samples

    def _build_explicit_sample_payloads(self, params: dict) -> dict:
        """Build flow-specific recorder samples posted by the clarification UI."""
        raw = (params.get("sample_payloads") or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}

        samples: Dict[str, str] = {}
        items = parsed if isinstance(parsed, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            flow = (item.get("flow") or "_all").strip() or "_all"
            sample = item.get("sample") or item.get("sample_payload")
            if sample is None and any(key in item for key in ("request", "payload", "response", "expectedResponse", "output")):
                request_value = item.get("request")
                payload_value = item.get("payload")
                if request_value is None and "payload" in item:
                    if isinstance(payload_value, dict) and any(
                        key in payload_value for key in ("request", "input", "response", "output", "expectedResponse", "expected")
                    ):
                        sample = payload_value
                    else:
                        request_value = {"payload": payload_value}
                if sample is None:
                    sample = {
                        "request": request_value or {},
                        "response": item.get("response") or item.get("expectedResponse") or item.get("output") or {},
                    }
            if isinstance(sample, (dict, list)):
                sample_text = json.dumps(sample)
            else:
                sample_text = str(sample or "").strip()
            if not sample_text:
                continue
            samples[flow] = self._normalize_recorder_sample_payload(sample_text)

        return samples

    @staticmethod
    def _first_non_empty_param(params: dict, *keys: str) -> str:
        for key in keys:
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _normalize_recorder_sample_payload(self, raw: str) -> str:
        """
        Normalize user-provided request/response samples to the recorder shape.

        The clarification UI asks for a recorder-style JSON object, but users
        often paste only the request body. Treat a plain object/list/string as
        request.payload so set-event payload DWLs do not come out empty.
        """
        text = (raw or "").strip()
        if not text:
            return text

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return text

        normalized = self._replace_dynamic_sample_placeholders(parsed)
        if not isinstance(normalized, dict):
            return json.dumps({"request": {"payload": normalized}}, indent=2)

        recorder_keys = {
            "request",
            "input",
            "response",
            "output",
            "payload",
            "body",
            "attributes",
            "headers",
            "queryParams",
            "uriParams",
            "method",
            "requestPath",
            "path",
        }
        if any(key in normalized for key in recorder_keys):
            return json.dumps(normalized, indent=2)

        return json.dumps({"request": {"payload": normalized}}, indent=2)

    def _replace_dynamic_sample_placeholders(self, value: Any) -> Any:
        """Replace supported safe placeholders inside pasted JSON samples."""
        if isinstance(value, dict):
            return {key: self._replace_dynamic_sample_placeholders(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._replace_dynamic_sample_placeholders(item) for item in value]
        if isinstance(value, str):
            return self._coerce_user_field_value(value)
        return value

    def _build_field_value_sample_payloads(self, params: dict) -> dict:
        """Build recorder-style request samples from user-entered field answers."""
        raw = (params.get("field_values") or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, list):
            return {}

        by_flow: Dict[str, Dict[str, Any]] = {}
        for item in parsed:
            if not isinstance(item, dict):
                continue
            flow = (item.get("flow") or "_all").strip() or "_all"
            location = (item.get("location") or "payload").strip()
            field = (item.get("field") or "").strip()
            if not field:
                continue
            value = self._coerce_user_field_value(item.get("value"), item.get("expected_type"), field)
            request = by_flow.setdefault(flow, {"request": {"payload": {}, "headers": {}, "queryParams": {}, "uriParams": {}}})
            request_obj = request["request"]
            if location == "headers":
                request_obj.setdefault("headers", {})[field] = value
            elif location == "queryParams":
                request_obj.setdefault("queryParams", {})[field] = value
            elif location == "uriParams":
                request_obj.setdefault("uriParams", {})[field] = value
            else:
                request_obj.setdefault("payload", {})[field] = value

        return {
            flow: self._normalize_recorder_sample_payload(json.dumps(value))
            for flow, value in by_flow.items()
        }

    def _coerce_user_field_value(self, value: Any, expected_type: str = "", field: str = "") -> Any:
        """Convert inline user answers into safe JSON test values."""
        if value is None:
            value = ""
        if not isinstance(value, str):
            return value
        text = value.strip()
        lowered = text.lower()
        if lowered in {"{{uuid}}", "${uuid}", "uuid()", "#[uuid()]"}:
            return "11111111-1111-4111-8111-111111111111"
        if lowered in {"{{now}}", "{{datetime}}", "${now}", "now()", "#[now()]"}:
            return "2026-01-01T00:00:00Z"
        if lowered in {"{{date}}", "${date}", "currentdate()", "#[currentDate()]"}:
            return "2026-01-01"
        if lowered in {"{{time}}", "${time}", "currenttime()", "#[currentTime()]"}:
            return "00:00:00"
        if lowered in {"{{correlationid}}", "{{correlation_id}}", "${correlationid}"}:
            return "test-correlation-id"
        if lowered in {"true", "false"}:
            return lowered == "true"
        if lowered in {"null", "{{null}}"}:
            return None
        expected = (expected_type or "").lower()
        if expected == "number":
            try:
                return float(text) if "." in text else int(text)
            except ValueError:
                return 1
        if expected == "boolean":
            return lowered in {"1", "yes", "y", "true", "on"}
        if expected in {"object", "array"}:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {} if expected == "object" else []
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def _build_connector_samples_dict(self, params: dict) -> dict:
        """
        Build {flow: {connector_key: sample}} from connector_samples JSON.

        Accepts two formats:
          1. New UI format (dict keyed by 'connectorType__index'):
             { "http:request__0": { "input": "...", "output": "..." }, ... }
          2. Legacy list format:
             [{ "flow": "...", "id": "...", "request": "...", "response": "..." }, ...]
        """
        raw = (params.get("connector_samples") or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}

        samples = {}

        # ── New dict format from Step 6 UI ───────────────────────────────
        if isinstance(parsed, dict):
            for key, val in parsed.items():
                if not isinstance(val, dict):
                    continue
                sample_key = (val.get("id") or key).strip()
                flow = (val.get("flow") or val.get("flowName") or "_all").strip() or "_all"
                inp = (val.get("input")  or "").strip()
                out = (val.get("output") or "").strip()
                variables = (val.get("variables") or "").strip()
                return_attributes = (val.get("returnAttributes") or val.get("return_attributes") or "").strip()
                error_type = (val.get("errorType") or val.get("error_type") or "").strip()
                return_types = val.get("returnTypes") or val.get("return_types") or []
                if isinstance(return_types, str):
                    return_types = [item.strip() for item in return_types.split(",") if item.strip()]
                return_types = [
                    str(item).strip()
                    for item in return_types
                    if str(item).strip() in {"payload", "variables", "attributes", "error", "nothing"}
                ]
                inferred_return_types = []
                if out:
                    inferred_return_types.append("payload")
                if variables:
                    inferred_return_types.append("variables")
                if return_attributes:
                    inferred_return_types.append("attributes")
                if error_type:
                    inferred_return_types.append("error")
                if error_type:
                    return_types = ["error"]
                elif inferred_return_types:
                    return_types = [item for item in return_types if item not in {"nothing", "error"}]
                    for item in inferred_return_types:
                        if item not in return_types:
                            return_types.append(item)
                if not (inp or out or variables or return_attributes or error_type or return_types):
                    continue
                samples.setdefault(flow, {})[sample_key] = {
                    "request":    inp,
                    "response":   out,
                    "media_type": _detect_media_type(out or inp),
                    "return_types": return_types,
                    "variables": variables,
                    "return_attributes": return_attributes,
                    "error_type": error_type,
                    "external_dependency": bool(val.get("external_dependency")),
                    "external_flow": (val.get("external_flow") or "").strip(),
                }
            return samples

        # ── Legacy list format ────────────────────────────────────────────
        if not isinstance(parsed, list):
            return samples

        for item in parsed:
            if not isinstance(item, dict):
                continue
            flow          = (item.get("flow") or "").strip()
            key           = (item.get("id")   or "").strip()
            request_text  = (item.get("request")  or "").strip()
            response_text = (item.get("response") or "").strip()
            if not flow or not key or not (request_text or response_text):
                continue
            samples.setdefault(flow, {})[key] = {
                "request":    request_text,
                "response":   response_text,
                "media_type": item.get("media_type") or "application/json",
            }
        return samples

    def _build_flow_test_data_dict(self, params: dict) -> dict:
        """
        Parse flow_test_data from the modal (Step 7 additional data).

        Format: {
            "payload": "...",
            "expectedResponse": "...",
            "statusCode": "200",
            "queryParams": { "key": "value" },
            "uriParams":   { "key": "value" },
            "headers":     { "Authorization": "Bearer ..." },
        }
        """
        raw = (params.get("flow_test_data") or "").strip()
        if not raw:
            return {}
        try:
            return json.loads(raw) or {}
        except json.JSONDecodeError:
            return {}


# Initialize generator
generator = WebMUnitGenerator()


def _detect_media_type(text: str) -> str:
    """Guess media type from sample text."""
    t = (text or "").strip()
    if not t:
        return "application/json"
    if t.startswith("<"):
        return "application/xml"
    if t.startswith("{") or t.startswith("["):
        return "application/json"
    return "application/json"

def _extract_project_request_payload(params: dict, files: dict, include_dwl: bool = True, include_usecase: bool = True) -> dict:
    """Read uploaded Mule project inputs into params for analysis or generation."""
    xml_files = None
    possible_keys = ['xml_file', 'project_folder']
    for key in possible_keys:
        if key in files and files[key]:
            xml_files = files[key]
            break

    if not xml_files:
        raise Exception('No XML file provided. Please upload a Mule project (.xml or .zip file).')

    if isinstance(xml_files, list):
        zip_files = []
        xml_file_list = []
        for file in xml_files:
            if file and hasattr(file, 'filename') and file.filename:
                if file.filename.lower().endswith(('.zip', '.jar', '.rar', '.7z')):
                    zip_files.append(file)
                elif file.filename.lower().endswith(('.xml', '.mule')):
                    xml_file_list.append(file)

        if zip_files:
            import zipfile
            temp_dir = tempfile.mkdtemp(prefix='mule_project_')
            zip_path = os.path.join(temp_dir, 'project.zip')
            zip_files[0].save(zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            project_files = generator._collect_project_files(temp_dir, include_dwl=include_dwl)
            params['xml_file'] = project_files["combined_xml"]
            params['project_dwl_files'] = project_files["dwl_files"]
            params['build_validation'] = project_files.get("build_validation", {})
            params['project_scan'] = project_files.get("scan_details", {})
            generator._set_project_context(project_files)
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        elif xml_file_list:
            combined_content = ""
            for file in xml_file_list:
                content = generator._read_file_content(file)
                if content.strip():
                    combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
            if not combined_content.strip():
                raise Exception("No valid XML files found in upload")
            params['xml_file'] = combined_content
            params['project_dwl_files'] = {}
            params['build_validation'] = {}
            params['project_scan'] = {
                "mule_files": [file.filename for file in xml_file_list],
                "xml_candidates": [file.filename for file in xml_file_list],
            }
            generator._set_project_context({"dwl_files": {}})
        else:
            raise Exception("No valid XML or ZIP files found in upload")
    else:
        if not (xml_files and hasattr(xml_files, 'filename') and xml_files.filename):
            raise Exception("Invalid file upload")
        filename = xml_files.filename.lower()
        if filename.endswith(('.zip', '.jar', '.rar', '.7z')):
            import zipfile
            temp_dir = tempfile.mkdtemp(prefix='mule_project_')
            zip_path = os.path.join(temp_dir, 'project.zip')
            xml_files.save(zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            project_files = generator._collect_project_files(temp_dir, include_dwl=include_dwl)
            params['xml_file'] = project_files["combined_xml"]
            params['project_dwl_files'] = project_files["dwl_files"]
            params['build_validation'] = project_files.get("build_validation", {})
            params['project_scan'] = project_files.get("scan_details", {})
            generator._set_project_context(project_files)
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        elif filename.endswith(('.xml', '.mule')):
            xml_content = generator._read_file_content(xml_files)
            if not xml_content.strip():
                raise Exception(f"File {xml_files.filename} content doesn't appear to be valid XML")
            params['xml_file'] = xml_content
            params['project_dwl_files'] = {}
            params['build_validation'] = {}
            params['project_scan'] = {
                "mule_files": [xml_files.filename],
                "xml_candidates": [xml_files.filename],
            }
            generator._set_project_context({"dwl_files": {}})
        else:
            raise Exception(f"File {xml_files.filename} is not supported. Please upload .xml or .zip files.")

    if include_usecase and 'usecase_file' in files and files['usecase_file']:
        usecase_files = files['usecase_file']
        if isinstance(usecase_files, list):
            combined_content = ""
            for file in usecase_files:
                if file and hasattr(file, 'filename') and file.filename:
                    combined_content += f"\n\n--- Content from {file.filename} ---\n{generator._read_uploaded_usecase_file(file)}\n"
            params['usecase_file'] = combined_content
        else:
            if usecase_files and hasattr(usecase_files, 'filename') and usecase_files.filename:
                params['usecase_file'] = generator._read_uploaded_usecase_file(usecase_files)

    return params

def _prune_analysis_cache(max_entries: int = 12, ttl_seconds: int = 3600) -> None:
    """Keep short-lived analyzed project context for resume generation."""
    now = time.time()
    expired = [
        key for key, value in analysis_cache.items()
        if now - float(value.get('created_at', now)) > ttl_seconds
    ]
    for key in expired:
        analysis_cache.pop(key, None)
    if len(analysis_cache) <= max_entries:
        return
    for key, _value in sorted(
        analysis_cache.items(),
        key=lambda item: float(item[1].get('created_at', 0)),
    )[:len(analysis_cache) - max_entries]:
        analysis_cache.pop(key, None)

def _read_dependency_artifact(file) -> dict:
    """Read a dependency artifact upload as Mule XML content."""
    if not file or not getattr(file, "filename", ""):
        return {"combined_xml": "", "xml_count": 0, "scan_details": {}}

    filename = file.filename.lower()
    if filename.endswith((".zip", ".jar")):
        import shutil
        import zipfile
        temp_dir = tempfile.mkdtemp(prefix="mule_dependency_")
        try:
            archive_path = os.path.join(temp_dir, secure_filename(file.filename) or "dependency.jar")
            file.save(archive_path)
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            return generator._collect_project_files(temp_dir, include_dwl=False)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if filename.endswith((".xml", ".mule")):
        content = generator._read_file_content(file)
        return {
            "combined_xml": f"\n\n--- Content from {file.filename} ---\n{content}\n",
            "xml_count": 1 if content.strip() else 0,
            "scan_details": {"mule_files": [file.filename]},
        }

    raise Exception("Dependency artifact must be a .jar, .zip, .xml, or .mule file.")


def _as_combined_xml_documents(xml_content: str, fallback_name: str) -> str:
    """Convert standalone Mule XML to the same multi-document envelope used for project ZIPs."""
    content = (xml_content or "").strip()
    if not content:
        return ""
    if re.search(r"\n?--- Content from .+? ---\n", content):
        return content
    safe_name = secure_filename(fallback_name) or "uploaded.xml"
    return f"--- Content from {safe_name} ---\n{content}\n"


def _analysis_fingerprint(params: dict) -> str:
    """Stable fingerprint for analyzed Mule project content used by resume cache."""
    digest = hashlib.sha256()
    digest.update((params.get('xml_file') or '').encode('utf-8', errors='replace'))
    project_dwl = params.get('project_dwl_files') or {}
    for path, content in sorted(project_dwl.items()):
        digest.update(str(path).encode('utf-8', errors='replace'))
        digest.update(str(content).encode('utf-8', errors='replace'))
    return digest.hexdigest()

@app.route('/')
def index():
    """Main application page."""
    return render_template('enhanced_index.html')

@app.route('/api/enhanced/generate', methods=['POST'])
def generate_enhanced_munit():
    """Enhanced MUnit test suite generation endpoint."""
    try:
        print("DEBUG: Enhanced endpoint called")
        
        # Validate content type
        if not request.is_json and not request.files and not request.form:
            print("DEBUG: No files in request")
            return jsonify({
                'success': False,
                'error': 'No file data received'
            }), 400
        
        # Get form data and files
        params = request.form.to_dict()
        files = request.files.to_dict()
        
        print(f"DEBUG: Form data keys: {list(params.keys())}")
        print(f"DEBUG: Files keys: {list(files.keys())}")
        print(f"DEBUG: xml_source from form: {params.get('xml_source')}")
        
        # Extract enhanced parameters
        params['enhanced_mode'] = params.get('enhanced_mode', 'true').lower() == 'true'
        params['token_budget'] = 50000
        params['optimization_level'] = 'balanced'
        params['security_focus'] = 'high'
        params["target_mule_runtime"] = (params.get("target_mule_runtime") or "").strip()
        params["target_munit_series"] = (params.get("target_munit_series") or "").strip()
        params["target_munit_custom"] = (params.get("target_munit_custom") or "").strip()
        if params["target_munit_custom"]:
            params["target_munit_version"] = params["target_munit_custom"]
        elif params["target_munit_series"] and params["target_munit_series"] != "custom":
            params["target_munit_version"] = params["target_munit_series"]
        elif not (params.get("target_munit_version") or "").strip():
            params["target_munit_version"] = ""

        analysis_id = (params.get("analysis_id") or "").strip()
        cached_analysis = analysis_cache.get(analysis_id) if analysis_id else None
        use_cached_analysis = (params.get("use_cached_analysis") or "").lower() == "true"
        if use_cached_analysis and not cached_analysis:
            return jsonify({
                'success': False,
                'error': 'Cached flow analysis is no longer available. Please upload or analyze the latest ZIP again.'
            }), 409
        if cached_analysis and use_cached_analysis:
            requested_fingerprint = (params.get("analysis_fingerprint") or "").strip()
            cached_fingerprint = cached_analysis.get("fingerprint") or ""
            if requested_fingerprint and requested_fingerprint != cached_fingerprint:
                return jsonify({
                    'success': False,
                    'error': 'Cached flow analysis does not match the current Mule project. Please upload or analyze the latest ZIP again.'
                }), 409
            params['xml_file'] = cached_analysis.get('xml_file', '')
            params['project_dwl_files'] = cached_analysis.get('project_dwl_files', {}) or {}
            params['build_validation'] = cached_analysis.get('build_validation', {}) or {}
            params['project_scan'] = cached_analysis.get('project_scan', {}) or {}
            params['_cached_flow_summary'] = cached_analysis.get('flow_summary')
            generator._set_project_context({"dwl_files": params['project_dwl_files']})
            if 'usecase_file' in files and files['usecase_file']:
                usecase_files = files['usecase_file']
                if isinstance(usecase_files, list):
                    combined_content = ""
                    for file in usecase_files:
                        if file and hasattr(file, 'filename') and file.filename:
                            content = generator._read_uploaded_usecase_file(file)
                            combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
                    params['usecase_file'] = combined_content
                else:
                    if usecase_files and hasattr(usecase_files, 'filename') and usecase_files.filename:
                        params['usecase_file'] = generator._read_uploaded_usecase_file(usecase_files)

            job_id = f"enhanced_job_{int(time.time())}_{len(active_jobs)}"

            def run_cached_generation():
                generator.generate_munit_enhanced_web(job_id, params)

            thread = threading.Thread(target=run_cached_generation)
            thread.daemon = True
            thread.start()

            return jsonify({
                'success': True,
                'job_id': job_id,
                'message': 'Enhanced generation resumed from cached analysis'
            })
        
        # Handle XML files or ZIP folder
        xml_files = None
        
        # Check different possible file keys
        possible_keys = ['xml_file', 'project_folder']
        for key in possible_keys:
            if key in files and files[key]:
                xml_files = files[key]
                print(f"DEBUG: Found files with key '{key}': {type(xml_files)}")
                break
        
        if not xml_files:
            print(f"DEBUG: No files found with keys {possible_keys}")
            print(f"DEBUG: Available files: {files}")
            return jsonify({
                'success': False,
                'error': 'No XML file provided. Please upload a Mule project (.xml or .zip file).'
            }), 400
        
        print(f"DEBUG: Processing files: {type(xml_files)}")
        
        if hasattr(xml_files, 'filename'):
            print(f"DEBUG: Single file: {xml_files.filename}")
        elif isinstance(xml_files, list):
            print(f"DEBUG: Multiple files: {len(xml_files)} files")
            for i, f in enumerate(xml_files):
                if hasattr(f, 'filename'):
                    print(f"DEBUG: File {i}: {f.filename}")
        
        # Process the files
        if isinstance(xml_files, list):
            # Multiple files - check if any are ZIP files
            zip_files = []
            xml_file_list = []
            
            for file in xml_files:
                if file and hasattr(file, 'filename') and file.filename:
                    if file.filename.lower().endswith(('.zip', '.jar', '.rar', '.7z')):
                        zip_files.append(file)
                    elif file.filename.lower().endswith(('.xml', '.mule')):
                        xml_file_list.append(file)
                    else:
                        print(f"WARNING: Skipping unsupported file: {file.filename}")
            
            # Handle ZIP files first (project folders)
            if zip_files:
                print(f"DEBUG: enhanced endpoint - Processing {len(zip_files)} ZIP files as project folders")
                if len(zip_files) > 1:
                    print(f"WARNING: Multiple ZIP files found, using first one: {zip_files[0].filename}")
                
                zip_file = zip_files[0]
                try:
                    # Extract and process ZIP file
                    import tempfile
                    import zipfile
                    
                    # Create temporary directory
                    temp_dir = tempfile.mkdtemp(prefix='mule_project_')
                    
                    # Save ZIP file
                    zip_path = os.path.join(temp_dir, 'project.zip')
                    zip_file.save(zip_path)
                    
                    # Extract ZIP file
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                    
                    project_files = generator._collect_project_files(temp_dir)
                    generator._set_project_context(project_files)
                    params['project_dwl_files'] = project_files['dwl_files']
                    params['build_validation'] = project_files.get('build_validation', {})

                    if project_files["combined_xml"].strip():
                        params['xml_file'] = project_files["combined_xml"]
                        print(
                            "DEBUG: ZIP processing complete - "
                            f"{project_files['xml_count']} XML files and {project_files['dwl_count']} DWL files processed"
                        )
                    else:
                        raise Exception("No valid files found in src/main folder of ZIP archive")
                    
                    # Clean up temp directory
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                        
                except Exception as e:
                    raise Exception(f"Error processing ZIP file: {str(e)}")
            
            # Handle individual XML files
            elif xml_file_list:
                print(f"DEBUG: enhanced endpoint - Processing {len(xml_file_list)} XML files")
                combined_content = ""
                for i, file in enumerate(xml_file_list):
                    print(f"DEBUG: enhanced endpoint - Processing XML file {i}: {file.filename}")
                    
                    # Skip pom.xml files explicitly
                    if file.filename.lower() == 'pom.xml':
                        print(f"DEBUG: Skipping pom.xml file: {file.filename}")
                        continue
                    
                    # Skip log4j and application-types files
                    if file.filename.lower() in ['log4j2.xml', 'log4j.xml', 'application-types.xml']:
                        print(f"DEBUG: Skipping log4j/application-types file: {file.filename}")
                        continue
                    
                    content = generator._read_file_content(file)
                    
                    # Validate content looks like XML
                    if not content.strip().startswith('<?xml') and '<' not in content[:100]:
                        print(f"WARNING: File {file.filename} content doesn't look like XML")
                        print(f"DEBUG: Content preview: {content[:100]}")
                        continue
                    
                    combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
                    print(f"DEBUG: enhanced endpoint - Successfully processed {file.filename}")
                
                if not combined_content.strip():
                    raise Exception("No valid XML files found in upload")
                
                params['xml_file'] = combined_content
                params['project_dwl_files'] = {}
                params['build_validation'] = {}
                generator._set_project_context({"dwl_files": {}})
                print(f"DEBUG: enhanced endpoint - Combined content length: {len(combined_content)} characters")
            
            else:
                raise Exception("No valid XML or ZIP files found in upload")
        
        else:
            # Single file - check if it's ZIP or XML
                if xml_files and hasattr(xml_files, 'filename') and xml_files.filename:
                    filename = xml_files.filename.lower()
                    
                    if filename.endswith(('.zip', '.jar', '.rar', '.7z')):
                        # Handle ZIP file
                        print(f"DEBUG: enhanced endpoint - Processing ZIP file: {xml_files.filename}")
                        try:
                            import tempfile
                            import zipfile
                            
                            # Create temporary directory
                            temp_dir = tempfile.mkdtemp(prefix='mule_project_')
                            
                            # Save ZIP file
                            zip_path = os.path.join(temp_dir, 'project.zip')
                            xml_files.save(zip_path)
                            
                            # Extract ZIP file
                            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                                zip_ref.extractall(temp_dir)
                            
                            project_files = generator._collect_project_files(temp_dir)
                            generator._set_project_context(project_files)
                            params['project_dwl_files'] = project_files['dwl_files']
                            params['build_validation'] = project_files.get('build_validation', {})
                            
                            # Clean up temp directory
                            import shutil
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            
                            if project_files["combined_xml"].strip():
                                params['xml_file'] = project_files["combined_xml"]
                                print(
                                    "DEBUG: enhanced endpoint - ZIP extraction complete - "
                                    f"{project_files['xml_count']} XML files and {project_files['dwl_count']} DWL files found"
                                )
                            else:
                                raise Exception("No XML files found in ZIP archive")
                                
                        except Exception as e:
                            raise Exception(f"Error processing ZIP file: {str(e)}")
                    
                    elif filename.endswith(('.xml', '.mule')):
                        # Handle XML file - directly pass to LLM without strict validation
                        print(f"DEBUG: enhanced endpoint - Processing single XML file")
                        
                        # Skip pom.xml, log4j and application-types files
                        if xml_files.filename.lower() in ['pom.xml', 'log4j2.xml', 'log4j.xml', 'application-types.xml']:
                            print(f"DEBUG: Skipping pom.xml/log4j/application-types file: {xml_files.filename}")
                            return jsonify({
                                'success': False,
                                'error': f'File {xml_files.filename} is not supported for MUnit generation. Please upload Mule configuration XML files only.'
                            }), 400
                        
                        xml_content = generator._read_file_content(xml_files)
                        params['xml_file'] = xml_content
                        params['project_dwl_files'] = {}
                        params['build_validation'] = {}
                        generator._set_project_context({"dwl_files": {}})
                        print(f"DEBUG: enhanced endpoint - XML content length: {len(xml_content)} characters")
                        print(f"DEBUG: XML content preview: {xml_content[:200]}...")
                    
                    else:
                        raise Exception(f"File {xml_files.filename} is not supported. Please upload .xml or .zip files.")
                else:
                    print(f"DEBUG: enhanced endpoint - Invalid single file object: {xml_files}")
                    raise Exception("Invalid file upload")
        
        # Handle use case files
        if 'usecase_file' in files and files['usecase_file']:
            usecase_files = files['usecase_file']
            if isinstance(usecase_files, list):
                combined_content = ""
                for file in usecase_files:
                    if file and hasattr(file, 'filename') and file.filename:
                        content = generator._read_uploaded_usecase_file(file)
                        combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
                params['usecase_file'] = combined_content
            else:
                if usecase_files and hasattr(usecase_files, 'filename') and usecase_files.filename:
                    content = generator._read_uploaded_usecase_file(usecase_files)
                    params['usecase_file'] = content
        
        # Generate unique job ID
        job_id = f"enhanced_job_{int(time.time())}_{len(active_jobs)}"
        
        # Start generation in background thread
        def run_generation():
            generator.generate_munit_enhanced_web(job_id, params)
        
        thread = threading.Thread(target=run_generation)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Enhanced generation started'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/enhanced/analyze-flows', methods=['POST'])
def analyze_enhanced_flows():
    """Analyze uploaded Mule app and return recommended/selectable flows."""
    try:
        params = request.form.to_dict()
        files = request.files.to_dict(flat=False)
        normalized_files = {key: value if len(value) > 1 else value[0] for key, value in files.items()}
        params = _extract_project_request_payload(
            params,
            normalized_files,
            include_dwl=False,
            include_usecase=False
        )

        flow_summary = generator.xml_analyzer.analyze_mule_project(params['xml_file'])
        selection_payload = generator.build_flow_selection_payload(flow_summary)
        analysis_id = uuid.uuid4().hex
        analysis_fingerprint = _analysis_fingerprint(params)
        analysis_cache[analysis_id] = {
            'xml_file': params.get('xml_file', ''),
            'base_xml_file': params.get('xml_file', ''),
            'project_dwl_files': params.get('project_dwl_files', {}) or {},
            'build_validation': params.get('build_validation', {}) or {},
            'project_scan': params.get('project_scan', {}) or {},
            'base_project_scan': params.get('project_scan', {}) or {},
            'flow_summary': flow_summary,
            'fingerprint': analysis_fingerprint,
            'created_at': time.time(),
        }
        _prune_analysis_cache()

        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'analysis_fingerprint': analysis_fingerprint,
            'flow_summary': {
                'job_type': flow_summary.get('job_type'),
                'flows_count': len(flow_summary.get('flows', [])),
                'recommended_count': len(selection_payload.get('recommended_flows', []))
            },
            'selection': selection_payload,
            'build_validation': params.get('build_validation', {}),
            'project_scan': params.get('project_scan', {})
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/enhanced/resolve-selected-flow', methods=['POST'])
def resolve_selected_flow_context():
    """Trace selected flows and optionally resolve external stops using an uploaded artifact or manual links."""
    try:
        params = request.form.to_dict()
        files = request.files.to_dict()
        analysis_id = (params.get("analysis_id") or "").strip()
        cached = analysis_cache.get(analysis_id) if analysis_id else None
        if not cached:
            return jsonify({
                "success": False,
                "error": "Cached flow analysis is no longer available. Please analyze the app again."
            }), 409

        selected_flows = params.get("selected_flows") or []
        if isinstance(selected_flows, str):
            try:
                selected_flows = json.loads(selected_flows)
            except Exception:
                selected_flows = [item.strip() for item in selected_flows.split(",") if item.strip()]

        xml_file = cached.get("xml_file", "")
        base_xml_file = cached.get("base_xml_file") or xml_file
        resolution_mode = (params.get("dependency_resolution_mode") or "").strip().lower()
        build_validation = cached.get("build_validation", {}) or {}
        project_scan = dict(cached.get("base_project_scan") or cached.get("project_scan", {}) or {})

        dependency_file = files.get("dependency_artifact")
        external_links = generator._build_external_flow_links_dict(params)
        if dependency_file and external_links:
            return jsonify({
                "success": False,
                "error": "Choose either dependency artifact upload or manual flow declaration, not both."
            }), 400
        if resolution_mode == "upload" and not (
            dependency_file and getattr(dependency_file, "filename", "")
        ):
            return jsonify({"success": False, "error": "Select a JAR, ZIP, XML, or Mule file first."}), 400
        if resolution_mode == "manual" and not external_links:
            return jsonify({"success": False, "error": "Select at least one local callback flow."}), 400

        xml_file = base_xml_file
        if resolution_mode == "upload" and dependency_file and getattr(dependency_file, "filename", ""):
            dep_project = _read_dependency_artifact(dependency_file)
            if dep_project.get("combined_xml", "").strip():
                xml_file = (
                    _as_combined_xml_documents(base_xml_file, "uploaded-application.xml")
                    + "\n\n"
                    + _as_combined_xml_documents(
                        dep_project["combined_xml"],
                        dependency_file.filename,
                    )
                )
                project_scan = dict(project_scan)
                project_scan.setdefault("dependency_artifacts", []).append({
                    "filename": dependency_file.filename,
                    "xml_count": dep_project.get("xml_count", 0),
                    "mule_files": (dep_project.get("scan_details") or {}).get("mule_files", []),
                })

        flow_summary = generator.xml_analyzer.analyze_mule_project(xml_file)
        flow_summary = generator.apply_selected_flows(flow_summary, selected_flows)
        flow_summary = generator._apply_user_dynamic_flow_targets(flow_summary, params)
        if resolution_mode == "manual":
            flow_summary = generator._apply_external_flow_links(flow_summary, params)

        cached.update({
            "xml_file": xml_file,
            "flow_summary": flow_summary,
            "build_validation": build_validation,
            "project_scan": project_scan,
            "created_at": time.time(),
        })
        selection_payload = generator.build_flow_selection_payload(flow_summary)
        return jsonify({
            "success": True,
            "selection": selection_payload,
            "selected_flow_trace": generator.build_selected_flow_trace_payload(
                flow_summary,
                selected_flows,
                build_validation,
            ),
            "build_validation": build_validation,
            "project_scan": project_scan,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/generate', methods=['POST'])
def generate_munit():
    """Generate MUnit test suite."""
    try:
        # Validate content type
        if not request.is_json and not request.files:
            return jsonify({
                'success': False,
                'error': 'No file data received'
            }), 400
        
        # Get form data
        params = request.form.to_dict()
        files = request.files.to_dict()
        
        # Debug logging
        print(f"DEBUG: Request method: {request.method}")
        print(f"DEBUG: Content type: {request.content_type}")
        print(f"DEBUG: Form params: {list(params.keys())}")
        print(f"DEBUG: Files received: {list(files.keys())}")
        print(f"DEBUG: Files dict type: {type(files)}")
        
        # Validate required fields
        if 'xml_source' not in params:
            return jsonify({
                'success': False,
                'error': 'XML source is required'
            }), 400
        
        # Generate unique job ID
        job_id = f"job_{int(time.time())}_{len(active_jobs)}"
        print(f"DEBUG: Generated job_id: {job_id}")
        
        # Handle file uploads
        xml_content = None
        usecase_content = None
        
        # Handle XML files or ZIP folder
        if 'xml_file' in files and files['xml_file']:
            xml_files = files['xml_file']
            print(f"DEBUG: xml_files type: {type(xml_files)}")
            
            if isinstance(xml_files, list):
                # Multiple files - check if any are ZIP files
                zip_files = []
                xml_file_list = []
                
                for file in xml_files:
                    if file and hasattr(file, 'filename') and file.filename:
                        if file.filename.lower().endswith(('.zip', '.jar', '.rar', '.7z')):
                            zip_files.append(file)
                        elif file.filename.lower().endswith(('.xml', '.mule')):
                            xml_file_list.append(file)
                        else:
                            print(f"WARNING: Skipping unsupported file: {file.filename}")
                
                # Handle ZIP files first (project folders)
                if zip_files:
                    print(f"DEBUG: Processing {len(zip_files)} ZIP files as project folders")
                    if len(zip_files) > 1:
                        print(f"WARNING: Multiple ZIP files found, using first one: {zip_files[0].filename}")
                    
                    zip_file = zip_files[0]
                    try:
                        # Extract and process ZIP file
                        import tempfile
                        import zipfile
                        
                        # Create temporary directory
                        temp_dir = tempfile.mkdtemp(prefix='mule_project_')
                        
                        # Save ZIP file
                        zip_path = os.path.join(temp_dir, 'project.zip')
                        zip_file.save(zip_path)
                        
                        # Extract ZIP file
                        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir)
                        
                        project_files = generator._collect_project_files(temp_dir)
                        generator._set_project_context(project_files)
                        params['project_dwl_files'] = project_files['dwl_files']
                        combined_content = project_files["combined_xml"]
                        
                        # Clean up temp directory
                        import shutil
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        
                        if combined_content.strip():
                            params['xml_file'] = combined_content
                            print(
                                "DEBUG: ZIP extraction complete - "
                                f"{project_files['xml_count']} XML files and {project_files['dwl_count']} DWL files found"
                            )
                        else:
                            raise Exception("No XML files found in ZIP archive")
                            
                    except Exception as e:
                        raise Exception(f"Error processing ZIP file: {str(e)}")
                
                # Handle individual XML files
                elif xml_file_list:
                    print(f"DEBUG: Processing {len(xml_file_list)} XML files")
                    combined_content = ""
                    for i, file in enumerate(xml_file_list):
                        print(f"DEBUG: Processing XML file {i}: {file.filename}")
                        
                        print(f"DEBUG: File {file.filename} size: {file.content_length if hasattr(file, 'content_length') else 'Unknown'}")
                        content = generator._read_file_content(file)
                        
                        # Validate content looks like XML
                        if not content.strip().startswith('<?xml') and '<' not in content[:100]:
                            print(f"WARNING: File {file.filename} content doesn't look like XML")
                            print(f"DEBUG: Content preview: {content[:100]}")
                            continue
                        
                        combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
                        print(f"DEBUG: Successfully processed {file.filename}")
                    
                    if not combined_content.strip():
                        raise Exception("No valid XML files found in upload")
                    
                    params['xml_file'] = combined_content
                    params['project_dwl_files'] = {}
                    generator._set_project_context({"dwl_files": {}})
                    print(f"DEBUG: Combined content length: {len(combined_content)} characters")
                
                else:
                    raise Exception("No valid XML or ZIP files found in upload")
                    
            else:
                # Single file - check if it's ZIP or XML
                if xml_files and hasattr(xml_files, 'filename') and xml_files.filename:
                    filename = xml_files.filename.lower()
                    
                    if filename.endswith(('.zip', '.jar', '.rar', '.7z')):
                        # Handle ZIP file
                        print(f"DEBUG: Processing ZIP file: {xml_files.filename}")
                        try:
                            import tempfile
                            import zipfile
                            
                            # Create temporary directory
                            temp_dir = tempfile.mkdtemp(prefix='mule_project_')
                            
                            # Save ZIP file
                            zip_path = os.path.join(temp_dir, 'project.zip')
                            xml_files.save(zip_path)
                            
                            # Extract ZIP file
                            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                                zip_ref.extractall(temp_dir)
                            
                            project_files = generator._collect_project_files(temp_dir)
                            generator._set_project_context(project_files)
                            params['project_dwl_files'] = project_files['dwl_files']
                            combined_content = project_files["combined_xml"]
                            
                            # Clean up temp directory
                            import shutil
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            
                            if combined_content.strip():
                                params['xml_file'] = combined_content
                                print(
                                    "DEBUG: ZIP extraction complete - "
                                    f"{project_files['xml_count']} XML files and {project_files['dwl_count']} DWL files found"
                                )
                            else:
                                raise Exception("No XML files found in ZIP archive")
                                
                        except Exception as e:
                            raise Exception(f"Error processing ZIP file: {str(e)}")
                    
                    elif filename.endswith(('.xml', '.mule')):
                        # Handle XML file
                        print(f"DEBUG: Processing single XML file")
                        print(f"DEBUG: File {xml_files.filename} size: {xml_files.content_length if hasattr(xml_files, 'content_length') else 'Unknown'}")
                        
                        # Skip pom.xml, log4j and application-types files
                        if xml_files.filename.lower() in ['pom.xml', 'log4j2.xml', 'log4j.xml', 'application-types.xml']:
                            print(f"DEBUG: Skipping pom.xml/log4j/application-types file: {xml_files.filename}")
                            return jsonify({
                                'success': False,
                                'error': f'File {xml_files.filename} is not supported for MUnit generation. Please upload Mule configuration XML files only.'
                            }), 400
                        
                        xml_content = generator._read_file_content(xml_files)
                        
                        # Validate content looks like XML
                        if not xml_content.strip().startswith('<?xml') and '<' not in xml_content[:100]:
                            print(f"ERROR: File content doesn't look like XML")
                            print(f"DEBUG: Content preview: {xml_content[:100]}")
                            raise Exception(f"File {xml_files.filename} content doesn't appear to be valid XML")
                        
                        params['xml_file'] = xml_content
                        params['project_dwl_files'] = {}
                        generator._set_project_context({"dwl_files": {}})
                        print(f"DEBUG: XML content length: {len(xml_content)} characters")
                    
                    else:
                        raise Exception(f"File {xml_files.filename} is not supported. Please upload .xml or .zip files.")
                else:
                    print(f"DEBUG: Invalid single file object: {xml_files}")
                    raise Exception("Invalid file upload")
        
        # Handle multiple use case files
        if 'usecase_file' in files and files['usecase_file']:
            usecase_files = files['usecase_file']
            if isinstance(usecase_files, list):
                # Multiple files
                combined_content = ""
                for file in usecase_files:
                    if file and hasattr(file, 'filename') and file.filename:
                        content = generator._read_uploaded_usecase_file(file)
                        combined_content += f"\n\n--- Content from {file.filename} ---\n{content}\n"
                params['usecase_file'] = combined_content
            else:
                # Single file
                if usecase_files and hasattr(usecase_files, 'filename') and usecase_files.filename:
                    usecase_content = generator._read_uploaded_usecase_file(usecase_files)
                    params['usecase_file'] = usecase_content
        
        # Start generation in background thread
        def run_generation():
            generator.generate_munit_web(job_id, params)
        
        thread = threading.Thread(target=run_generation)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Generation started'
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"ERROR: Exception in generate_munit: {str(e)}")
        print(f"TRACEBACK: {error_details}")
        
        return jsonify({
            'success': False,
            'error': str(e),
            'debug_info': error_details if app.debug else None
        }), 500

@app.route('/api/job-status/<job_id>')
def job_status(job_id):
    """Get job status."""
    if job_id in active_jobs:
        return jsonify(active_jobs[job_id])
    else:
        return jsonify({'error': 'Job not found'}), 404

@app.route('/api/job-result/<job_id>')
def job_result(job_id):
    """Get job result."""
    if job_id in job_results:
        return jsonify(job_results[job_id])
    else:
        return jsonify({'error': 'Result not found'}), 404

@app.route('/api/download/<job_id>')
def download_file(job_id):
    """Download generated MUnit files."""
    if job_id in job_results and job_results[job_id]['success']:
        result = job_results[job_id]
        output_root = Path(result.get('output_path') or '').resolve() if result.get('output_path') else None
        download_files = list(result.get('output_files') or [])
        if output_root and output_root.is_dir():
            download_files.extend(
                str(path)
                for path in sorted(output_root.rglob("*"))
                if path.is_file()
            )
        download_files = list(dict.fromkeys(download_files))
        
        # If multiple files were generated, create a ZIP
        if len(download_files) > 1:
            import zipfile
            import io
            
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                used_names = set()
                for output_file in download_files:
                    if os.path.exists(output_file):
                        file_path = Path(output_file).resolve()
                        try:
                            filename = str(file_path.relative_to(output_root)).replace(os.sep, "/") if output_root else file_path.name
                        except ValueError:
                            filename = file_path.name
                        if filename in used_names:
                            stem = Path(filename).stem
                            suffix = Path(filename).suffix
                            parent = Path(filename).parent
                            counter = 2
                            candidate = str(parent / f"{stem}_{counter}{suffix}").replace(os.sep, "/")
                            while candidate in used_names:
                                counter += 1
                                candidate = str(parent / f"{stem}_{counter}{suffix}").replace(os.sep, "/")
                            filename = candidate
                        used_names.add(filename)
                        zip_file.write(file_path, filename)
            
            zip_buffer.seek(0)
            return send_file(
                io.BytesIO(zip_buffer.read()),
                mimetype='application/zip',
                as_attachment=True,
                download_name=f'munit_tests_{job_id}.zip'
            )
        else:
            # Single file download
            output_file = download_files[0] if download_files else result.get('output_file')
            if output_file and os.path.exists(output_file):
                return send_file(output_file, as_attachment=True)
    
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/config')
def get_config():
    """Get current configuration."""
    return jsonify({
        'llm_models': generator.config.validate_llm_config(),
        'github_config': generator.config.validate_github_config(),
        'confluence_config': generator.config.validate_confluence_config(),
        'output_config': generator.config.validate_output_config()
    })

@app.route('/api/enhanced/capabilities')
def get_enhanced_capabilities():
    """Get enhanced capabilities information."""
    try:
        capabilities = {
            'security_features': {
                'input_sanitization': True,
                'sensitive_data_redaction': True,
                'compliance_validation': True,
                'security_scanning': True
            },
            'token_optimization': {
                'smart_file_selection': True,
                'content_reduction': True,
                'progressive_analysis': True,
                'budget_management': True
            },
            'business_context': {
                'use_case_analysis': True,
                'api_spec_analysis': True,
                'business_rule_extraction': True,
                'scenario_generation': True
            },
            'test_generation': {
                'api_integration_tests': True,
                'unit_tests': True,
                'business_scenario_tests': True,
                'fault_tolerance_tests': True,
                'security_tests': True
            }
        }
        return jsonify(capabilities)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/enhanced/validate')
def validate_enhanced_setup():
    """Validate enhanced setup and dependencies."""
    try:
        validation = {
            'valid': True,
            'enhanced_features_available': True,
            'issues': [],
            'recommendations': [
                'Configure LLM API key for best results',
                'Consider using enhanced mode for better test coverage',
                'ZIP file upload is supported for project folders'
            ]
        }
        return jsonify(validation)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_jobs': len(active_jobs),
        'enhanced_mode': True
    })

@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Test endpoint for debugging."""
    if request.method == 'GET':
        return jsonify({
            'message': 'Test endpoint working',
            'method': 'GET',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'message': 'Test endpoint working',
            'method': 'POST',
            'form_keys': list(request.form.keys()),
            'file_keys': list(request.files.keys()),
            'timestamp': datetime.now().isoformat()
        })

@app.route('/api/debug/xml', methods=['POST'])
def debug_xml_validation():
    """Debug endpoint for XML validation"""
    try:
        if 'xml_file' not in request.files:
            return jsonify({'error': 'No XML file provided'}), 400
        
        file = request.files['xml_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        content = generator._read_file_content(file)
        
        # Debug info
        debug_info = {
            'filename': file.filename,
            'file_size': len(content),
            'content_preview': content[:200] + "..." if len(content) > 200 else content,
            'encoding_issues': 'Error reading file' if content.startswith('[Error') else 'None'
        }
        
        # Validate XML
        is_valid = generator.xml_analyzer.validate_mule_xml(content)
        debug_info['validation_result'] = is_valid
        
        if is_valid:
            try:
                analysis = generator.xml_analyzer.analyze_mule_xml(content)
                debug_info['analysis'] = {
                    'job_type': analysis.get('job_type'),
                    'flows_count': len(analysis.get('flows', [])),
                    'connectors_count': len(analysis.get('connectors', []))
                }
            except Exception as e:
                debug_info['analysis_error'] = str(e)
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blueprint/generate', methods=['POST'])
def generate_blueprint_munit():
    """
    Blueprint-compliant MUnit generation endpoint (Steps 3-8).

    Accepts the same multipart/form-data payload as the enhanced endpoint
    but routes through the full multi-step pipeline:
      - Step 3: Isolated flow context
      - Step 4: Deterministic mock blueprint
      - Step 5: Multi-pass DWL + test XML generation
      - Step 6: Three structured scenarios per flow
      - Step 7: Backend template assembly + XML sanity check
      - Step 8: Optional Maven self-healing (set run_maven=true in form)

    Form fields:
      xml_file / project_folder  — Mule project ZIP or XML file(s)
      selected_flows             — JSON array of flow names (optional)
      run_maven                  — 'true' to enable Step 8 (default: false)
      project_root               — Path to Maven project root (optional, for Step 8)
    """
    try:
        params = request.form.to_dict()
        files = request.files.to_dict(flat=False)
        normalized_files = {k: v if len(v) > 1 else v[0] for k, v in files.items()}

        # Reuse existing file extraction helper
        params = _extract_project_request_payload(
            params,
            normalized_files,
            include_dwl=True,
            include_usecase=False,
        )

        job_id = f"blueprint_job_{int(time.time())}_{len(active_jobs)}"

        def run_generation():
            generator.generate_blueprint_web(job_id, params)

        thread = threading.Thread(target=run_generation, daemon=True)
        thread.start()

        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Blueprint pipeline started',
            'pipeline': 'blueprint',
        })

    except Exception as exc:
        import traceback
        return jsonify({
            'success': False,
            'error': str(exc),
            'debug_info': traceback.format_exc() if app.debug else None,
        }), 500



# ─── Version compatibility API ────────────────────────────────────────────────

@app.route('/api/munit-versions', methods=['GET'])
def get_all_munit_versions():
    """Return the full Runtime → MUnit compatibility matrix used by the UI dropdowns."""
    try:
        from core.version_config import get_full_version_map, RUNTIME_VERSIONS
        return jsonify({
            'success': True,
            'runtime_versions': RUNTIME_VERSIONS,
            'compatibility': get_full_version_map(),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/munit-versions/<runtime_version>', methods=['GET'])
def get_munit_versions_for_runtime(runtime_version):
    try:
        from core.version_config import (
            get_munit_versions_for_runtime as _get_versions,
            get_recommended_munit_version, get_munit_series, get_pom_snippet,
        )
        versions = _get_versions(runtime_version)
        if not versions:
            return jsonify({'success': False, 'error': f'Unknown runtime: {runtime_version}'}), 404
        recommended = get_recommended_munit_version(runtime_version)
        return jsonify({
            'success': True,
            'runtime': runtime_version,
            'series': get_munit_series(runtime_version),
            'versions': versions,
            'recommended': recommended,
            'pom_snippet': get_pom_snippet(recommended or versions[-1], runtime_version),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pom-snippet', methods=['POST'])
def get_pom_snippet_api():
    try:
        from core.version_config import get_pom_snippet
        data = request.get_json() or {}
        munit_version = data.get('munit_version', '').strip()
        runtime_version = data.get('runtime_version', '').strip()
        if not munit_version:
            return jsonify({'success': False, 'error': 'munit_version is required'}), 400
        return jsonify({'success': True, 'pom_snippet': get_pom_snippet(munit_version, runtime_version)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/check-pom', methods=['POST'])
def check_pom_endpoint():
    import xml.etree.ElementTree as _ET
    pom_content = None
    selected_munit_version = ''
    if 'pom_file' in request.files:
        pom_content = request.files['pom_file'].read().decode('utf-8-sig')
        selected_munit_version = request.form.get('munit_version', '')
    elif request.is_json:
        body = request.get_json() or {}
        pom_content = body.get('pom_content', '')
        selected_munit_version = body.get('munit_version', '')
    if not pom_content:
        return jsonify({'success': False, 'error': 'No POM content provided'}), 400
    return jsonify({'success': True, 'pom_analysis': _analyze_pom_content(pom_content, selected_munit_version)})


def _analyze_pom_content(pom_content: str, munit_version: str = '') -> dict:
    import xml.etree.ElementTree as ET, re
    NS = "http://maven.apache.org/POM/4.0.0"
    result = {'has_pom': True, 'has_runner': False, 'has_tools': False, 'has_plugin': False,
              'runner_version': None, 'tools_version': None, 'plugin_version': None,
              'mule_runtime': None, 'missing': [], 'warnings': [], 'pom_snippet': ''}
    def _strip(tag): return re.sub(r"\{[^}]+\}", "", tag)
    def _text(node, local):
        el = node.find(f"{{{NS}}}{local}") or node.find(local)
        return (el.text or "").strip() if el is not None else ""
    try:
        root = ET.fromstring(pom_content.lstrip("\ufeff"))
    except ET.ParseError as e:
        result['parse_error'] = str(e); return result
    props = root.find(f"{{{NS}}}properties") or root.find("properties")
    if props is not None:
        for child in props:
            if "mule" in _strip(child.tag).lower() and "version" in _strip(child.tag).lower():
                result['mule_runtime'] = (child.text or "").strip(); break
    for dep in root.iter():
        if _strip(dep.tag) != "dependency": continue
        gid, aid, ver = _text(dep,"groupId"), _text(dep,"artifactId"), _text(dep,"version")
        if gid == "com.mulesoft.munit":
            if aid == "munit-runner": result['has_runner'] = True; result['runner_version'] = ver
            elif aid == "munit-tools": result['has_tools'] = True; result['tools_version'] = ver
    for plugin in root.iter():
        if _strip(plugin.tag) != "plugin": continue
        if _text(plugin,"groupId") == "com.mulesoft.munit.tools" and _text(plugin,"artifactId") == "munit-maven-plugin":
            result['has_plugin'] = True; result['plugin_version'] = _text(plugin,"version")
    detected = result['runner_version'] or result['tools_version']
    if detected and munit_version and detected != munit_version:
        result['warnings'].append(f"POM has MUnit {detected} but you selected {munit_version}")
    if not result['has_runner']: result['missing'].append('munit-runner dependency')
    if not result['has_tools']: result['missing'].append('munit-tools dependency')
    if not result['has_plugin']: result['missing'].append('munit-maven-plugin')
    if result['missing']:
        try:
            from core.version_config import get_pom_snippet
            result['pom_snippet'] = get_pom_snippet(munit_version or detected or '2.3.15', result.get('mule_runtime',''))
        except Exception: pass
    return result


@app.route('/api/job-status/<job_id>', methods=['GET'])
def get_job_status_endpoint(job_id):
    if job_id in active_jobs:
        j = active_jobs[job_id]
        return jsonify(j)
    if job_id in job_results:
        r = job_results[job_id]
        status = 'complete' if r.get('success') else r.get('status', 'error')
        return jsonify({'status': status, 'success': r.get('success', False), 'result': r})
    return jsonify({'status': 'not_found', 'error': f'Job {job_id} not found'}), 404



if __name__ == '__main__':
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
