#!/usr/bin/env python3
"""
Simple MUnit Generation Agent
Clean, focused application for generating MUnit tests from Mule projects
"""

import os
import sys
import time
import tempfile
import zipfile
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import core modules
from core.xml_analyzer import XMLAnalyzer
from core.document_parser import DocumentParser
from core.prompt_builder import PromptBuilder
from core.ruleset_loader import RulesetLoader
from llm.llm_router import LLMRouter
from munitWriter import MUnitWriter
from utils.file_utils import FileReader
from config import Config

app = Flask(__name__)

# Global storage for jobs
active_jobs = {}
job_results = {}

class SimpleMUnitGenerator:
    """Simple MUnit Generation Agent"""
    
    def __init__(self):
        """Initialize the generator"""
        self.config = Config()
        self.xml_analyzer = XMLAnalyzer()
        self.doc_parser = DocumentParser()
        self.prompt_builder = PromptBuilder()
        self.ruleset_loader = RulesetLoader()
        self.llm_router = LLMRouter(self.config)
        self.munit_writer = MUnitWriter(self.config)
        self.file_reader = FileReader()
        self.ruleset = self.ruleset_loader.load_ruleset()
    
    def generate_munit_tests(self, job_id: str, mule_zip_path: str, doc_zip_path: str = None) -> dict:
        """
        Generate MUnit tests for Mule application
        
        Args:
            job_id: Unique job identifier
            mule_zip_path: Path to Mule project ZIP file
            doc_zip_path: Optional path to documentation ZIP file
            
        Returns:
            Dictionary with generation results
        """
        try:
            # Step 1: Extract and analyze Mule project
            active_jobs[job_id].update({'progress': 10, 'message': 'Extracting Mule project...'})
            mule_content = self._extract_mule_project(mule_zip_path)
            
            # Step 2: Analyze Mule XML structure
            active_jobs[job_id].update({'progress': 20, 'message': 'Analyzing Mule application structure...'})
            if not self.xml_analyzer.validate_mule_xml(mule_content):
                raise Exception("Invalid Mule XML files found in the project")
            
            flow_summary = self.xml_analyzer.analyze_mule_xml(mule_content)
            
            # Step 3: Process documentation if provided
            usecase_content = ""
            if doc_zip_path:
                active_jobs[job_id].update({'progress': 30, 'message': 'Processing documentation...'})
                usecase_content = self._extract_documentation(doc_zip_path)
                active_jobs[job_id].update({'progress': 40, 'message': 'Analyzing business requirements...'})
            else:
                active_jobs[job_id].update({'progress': 40, 'message': 'Using default test scenarios...'})
            
            # Step 4: Parse business scenarios
            active_jobs[job_id].update({'progress': 50, 'message': 'Extracting test scenarios...'})
            scenarios = self.doc_parser.parse_document(usecase_content, flow_summary["job_type"])
            
            # Step 5: Build comprehensive prompt
            active_jobs[job_id].update({'progress': 60, 'message': 'Preparing generation prompt...'})
            prompt = self.prompt_builder.build_prompt(
                flow_summary,
                scenarios["scenarios"],
                self.ruleset,
                document_context=scenarios
            )
            
            # Step 6: Generate MUnit tests
            active_jobs[job_id].update({'progress': 70, 'message': 'Generating MUnit tests...'})
            munit_xml, metadata = self.llm_router.generate_munit(prompt)
            
            # Step 7: Create output files
            active_jobs[job_id].update({'progress': 80, 'message': 'Creating test files...'})
            output_files = self._create_munit_files(munit_xml, flow_summary, metadata)
            
            # Step 8: Complete
            active_jobs[job_id].update({'progress': 100, 'message': 'Generation complete!'})
            
            results = {
                'success': True,
                'output_files': output_files,
                'flow_summary': flow_summary,
                'scenarios_count': len(scenarios["scenarios"]),
                'metadata': metadata,
                'generation_time': metadata['generation_time']
            }
            
            job_results[job_id] = results
            return results
            
        except Exception as e:
            active_jobs[job_id] = {'status': 'error', 'progress': 0, 'message': f'Error: {str(e)}'}
            job_results[job_id] = {'success': False, 'error': str(e)}
            return {'success': False, 'error': str(e)}
    
    def _extract_mule_project(self, zip_path: str) -> str:
        """Extract and read Mule project files"""
        temp_dir = tempfile.mkdtemp(prefix='mule_project_')
        
        try:
            # Extract ZIP file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find all XML files
            xml_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.lower().endswith('.xml'):
                        xml_files.append(os.path.join(root, file))
            
            if not xml_files:
                raise Exception("No XML files found in the Mule project")
            
            # Read and combine XML files
            combined_content = ""
            for xml_file_path in xml_files:
                try:
                    with open(xml_file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    combined_content += f"\n\n--- Content from {os.path.basename(xml_file_path)} ---\n{content}\n"
                except Exception as e:
                    print(f"Warning: Could not read {xml_file_path}: {e}")
                    continue
            
            return combined_content
            
        finally:
            # Clean up temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _extract_documentation(self, zip_path: str) -> str:
        """Extract and read documentation files"""
        temp_dir = tempfile.mkdtemp(prefix='docs_')
        
        try:
            # Extract ZIP file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find all readable files
            doc_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.lower().endswith(('.txt', '.md', '.docx', '.pdf', '.doc')):
                        doc_files.append(os.path.join(root, file))
            
            # Read and combine documentation
            combined_content = ""
            for doc_file_path in doc_files:
                try:
                    if doc_file_path.lower().endswith(('.txt', '.md')):
                        with open(doc_file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        combined_content += f"\n\n--- Content from {os.path.basename(doc_file_path)} ---\n{content}\n"
                    else:
                        # Use file reader for other formats
                        with open(doc_file_path, 'rb') as f:
                            content_bytes = f.read()
                        content = self.file_reader.read_file_with_encoding_detection(content_bytes, doc_file_path)
                        combined_content += f"\n\n--- Content from {os.path.basename(doc_file_path)} ---\n{content}\n"
                except Exception as e:
                    print(f"Warning: Could not read {doc_file_path}: {e}")
                    continue
            
            return combined_content
            
        finally:
            # Clean up temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _create_munit_files(self, munit_xml: str, flow_summary: dict, metadata: dict) -> list:
        """Create MUnit test files"""
        output_files = []
        
        # Create output directory
        output_dir = os.path.join(self.config.output_path, 'munit_tests')
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate individual test files for each flow
        flows = flow_summary.get("flows", [])
        if not flows:
            # Create a single test file if no specific flows
            main_flow = "main-flow"
            metadata = {
                **metadata,
                "target_flow": main_flow,
                "source_file": flow_summary.get("source_file", "unknown.xml")
            }
            output_file = self.munit_writer.write_munit_file(munit_xml, main_flow, metadata)
            output_files.append(output_file)
        else:
            # Create separate test files for each flow
            for i, flow in enumerate(flows):
                flow_name = flow.replace(" ", "-").lower()
                metadata = {
                    **metadata,
                    "target_flow": flow_name,
                    "source_file": flow_summary.get("source_file", "unknown.xml")
                }
                output_file = self.munit_writer.write_munit_file(munit_xml, flow_name, metadata)
                output_files.append(output_file)
        
        return output_files

# Initialize generator
generator = SimpleMUnitGenerator()

@app.route('/')
def index():
    """Main application page."""
    return render_template('simple_index.html')

@app.route('/api/generate', methods=['POST'])
def generate_tests():
    """Generate MUnit tests endpoint."""
    try:
        # Get uploaded files
        mule_zip = request.files.get('mule_zip')
        doc_zip = request.files.get('doc_zip')
        
        if not mule_zip:
            return jsonify({
                'success': False,
                'error': 'Mule project ZIP file is required'
            }), 400
        
        # Validate file types
        if not mule_zip.filename.lower().endswith('.zip'):
            return jsonify({
                'success': False,
                'error': 'Mule project must be a ZIP file'
            }), 400
        
        if doc_zip and not doc_zip.filename.lower().endswith('.zip'):
            return jsonify({
                'success': False,
                'error': 'Documentation must be a ZIP file'
            }), 400
        
        # Save files temporarily
        temp_dir = tempfile.mkdtemp(prefix='upload_')
        mule_zip_path = os.path.join(temp_dir, secure_filename(mule_zip.filename))
        mule_zip.save(mule_zip_path)
        
        doc_zip_path = None
        if doc_zip:
            doc_zip_path = os.path.join(temp_dir, secure_filename(doc_zip.filename))
            doc_zip.save(doc_zip_path)
        
        # Generate unique job ID
        job_id = f"job_{int(time.time())}_{len(active_jobs)}"
        
        # Initialize job status
        active_jobs[job_id] = {
            'status': 'processing',
            'progress': 0,
            'message': 'Starting generation...',
            'start_time': datetime.now().isoformat()
        }
        
        # Start generation in background thread
        def run_generation():
            try:
                generator.generate_munit_tests(job_id, mule_zip_path, doc_zip_path)
            finally:
                # Clean up temporary files
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        thread = threading.Thread(target=run_generation)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Generation started'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/status/<job_id>')
def get_job_status(job_id):
    """Get job status."""
    if job_id not in active_jobs:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    
    job = active_jobs[job_id]
    response = {
        'success': True,
        'status': job['status'],
        'progress': job['progress'],
        'message': job['message'],
        'start_time': job.get('start_time')
    }
    
    if job['status'] == 'completed' and job_id in job_results:
        response['results'] = job_results[job_id]
    elif job['status'] == 'error' and job_id in job_results:
        response['error'] = job_results[job_id].get('error', 'Unknown error')
    
    return jsonify(response)

@app.route('/api/download/<job_id>')
def download_results(job_id):
    """Download generated test files."""
    if job_id not in job_results or not job_results[job_id]['success']:
        return jsonify({'success': False, 'error': 'Results not available'}), 404
    
    results = job_results[job_id]
    output_files = results.get('output_files', [])
    
    if not output_files:
        return jsonify({'success': False, 'error': 'No files to download'}), 404
    
    # Create a ZIP file with all test files
    temp_dir = tempfile.mkdtemp(prefix='download_')
    zip_path = os.path.join(temp_dir, f'munit_tests_{job_id}.zip')
    
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        for output_file in output_files:
            if os.path.exists(output_file):
                zip_file.write(output_file, os.path.basename(output_file))
    
    def cleanup():
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return send_file(
        zip_path,
        as_attachment=True,
        download_name=f'munit_tests_{job_id}.zip',
        mimetype='application/zip'
    )

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_jobs': len(active_jobs)
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
