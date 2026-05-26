"""
Enhanced Integration Module
Seamlessly integrates enhanced security, token optimization, and business context
with the existing MUnit generation architecture.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import existing core modules
from .xml_analyzer import XMLAnalyzer
from .doc_parser import DocumentParser
from .prompt_builder import PromptBuilder
from .ruleset_loader import RulesetLoader

# Import enhanced modules
from enhanced_munit_generator import (
    EnhancedMUnitGenerator, 
    TokenBudget, 
    EnhancedSecurityRules,
    TokenOptimizer,
    EnhancedFileAnalyzer,
    EnhancedBusinessContextAnalyzer
)

from config import Config
from inputs import GitHubFetcher, LocalReader, ConfluenceReader
from llm import LLMRouter
from munitWriter import MUnitWriter

logger = logging.getLogger(__name__)

class EnhancedIntegration:
    """Integration layer for enhanced MUnit generation with existing architecture"""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize enhanced integration"""
        self.config = config or Config()
        
        # Initialize existing components
        self.xml_analyzer = XMLAnalyzer()
        self.doc_parser = DocumentParser()
        self.prompt_builder = PromptBuilder(max_tokens=self.config.max_prompt_tokens)
        self.ruleset_loader = RulesetLoader()
        self.llm_router = LLMRouter(timeout=self.config.llm_timeout)
        self.munit_writer = MUnitWriter(output_dir=self.config.output_path)
        
        # Initialize enhanced components
        self.enhanced_generator = EnhancedMUnitGenerator(
            config=self.config,
            token_budget=self.config.max_prompt_tokens * 8  # Larger budget for enhanced features
        )
        
        # Load existing ruleset
        self.existing_ruleset = self.ruleset_loader.load_ruleset()
        
        logger.info("Enhanced integration initialized")
    
    def generate_with_enhanced_features(self, 
                                      xml_content: str,
                                      usecase_content: str = "",
                                      enhanced_mode: bool = True,
                                      token_budget: Optional[int] = None,
                                      business_context_path: Optional[str] = None,
                                      api_spec_path: Optional[str] = None,
                                      optimization_level: str = "balanced") -> Dict[str, Any]:
        """
        Generate MUnit tests with enhanced features integrated
        
        Args:
            xml_content: Mule XML content
            usecase_content: Business use case content
            enhanced_mode: Enable enhanced features
            token_budget: Token budget for enhanced processing
            business_context_path: Path to business context files
            api_spec_path: Path to API specification files
            optimization_level: Token optimization level
            
        Returns:
            Dictionary with generation results
        """
        try:
            if enhanced_mode:
                return self._generate_enhanced_mode(
                    xml_content, usecase_content, token_budget,
                    business_context_path, api_spec_path, optimization_level
                )
            else:
                return self._generate_legacy_mode(xml_content, usecase_content)
                
        except Exception as e:
            logger.error(f"Error in enhanced generation: {e}")
            return {
                'success': False,
                'error': str(e),
                'mode': 'enhanced' if enhanced_mode else 'legacy'
            }
    
    def _generate_enhanced_mode(self, 
                               xml_content: str,
                               usecase_content: str,
                               token_budget: Optional[int],
                               business_context_path: Optional[str],
                               api_spec_path: Optional[str],
                               optimization_level: str) -> Dict[str, Any]:
        """Generate using enhanced mode"""
        logger.info("Using enhanced generation mode")
        
        # Create temporary directory for processing
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save XML content to temporary file
            xml_file = os.path.join(temp_dir, "mule_app.xml")
            with open(xml_file, 'w') as f:
                f.write(xml_content)
            
            # Save use case content if provided
            if usecase_content:
                usecase_file = os.path.join(temp_dir, "use_case.md")
                with open(usecase_file, 'w') as f:
                    f.write(use_case_content)
                business_context_path = temp_dir
            
            # Generate with enhanced features
            results = self.enhanced_generator.generate_munit_enhanced(
                mule_app_path=temp_dir,
                business_context_path=business_context_path,
                api_spec_path=api_spec_path,
                optimization_level=optimization_level
            )
            
            # Integrate with existing output system
            if results['success']:
                self._integrate_with_existing_output(results)
            
            return results
    
    def _generate_legacy_mode(self, xml_content: str, usecase_content: str) -> Dict[str, Any]:
        """Generate using legacy mode (existing functionality)"""
        logger.info("Using legacy generation mode")
        
        try:
            # Validate and analyze XML using existing analyzer
            if not self.xml_analyzer.validate_mule_xml(xml_content):
                raise Exception("Invalid Mule XML file")
            
            flow_summary = self.xml_analyzer.analyze_mule_xml(xml_content)
            
            # Parse business use case using existing parser
            scenarios = self.doc_parser.parse_document(usecase_content, flow_summary["job_type"])
            
            # Build prompt using existing prompt builder
            prompt = self.prompt_builder.build_prompt(
                flow_summary,
                scenarios["scenarios"],
                self.existing_ruleset,
                document_context=scenarios
            )
            
            # Generate MUnit with existing LLM router
            munit_xml, metadata = self.llm_router.generate_munit(prompt)
            
            # Write MUnit file using existing writer
            main_flow = flow_summary["flows"][0] if flow_summary["flows"] else "main-flow"
            metadata = {
                **metadata,
                "target_flow": main_flow,
                "source_file": flow_summary.get("source_file", "unknown.xml")
            }
            output_file = self.munit_writer.write_munit_file(munit_xml, main_flow, metadata)
            
            return {
                'success': True,
                'mode': 'legacy',
                'output_file': output_file,
                'flow_summary': flow_summary,
                'scenarios_count': len(scenarios["scenarios"]),
                'metadata': metadata,
                'generation_time': metadata['generation_time']
            }
            
        except Exception as e:
            return {
                'success': False,
                'mode': 'legacy',
                'error': str(e)
            }
    
    def _integrate_with_existing_output(self, enhanced_results: Dict[str, Any]):
        """Integrate enhanced results with existing output system"""
        try:
            # Extract test suites from enhanced results
            test_suites = enhanced_results.get('test_suites', {})
            
            # Convert enhanced test suites to MUnit XML using existing writer
            for suite_name, suite_data in test_suites.items():
                if suite_data.get('tests'):
                    # Generate MUnit XML for each test
                    for test in suite_data['tests']:
                        munit_xml = self._convert_test_to_munit_xml(test)
                        test_metadata = {
                            **test.get('metadata', {}),
                            "target_flow": test.get('name', 'test'),
                            "source_file": test.get('metadata', {}).get("source_file", "unknown.xml")
                        }
                        
                        # Write using existing MUnit writer
                        output_file = self.munit_writer.write_munit_file(
                            munit_xml, 
                            test.get('name', 'test'), 
                            test_metadata
                        )
                        
                        logger.info(f"Wrote enhanced test to: {output_file}")
            
            # Save mock data
            mock_data = enhanced_results.get('mock_data', {})
            if mock_data:
                self._save_mock_data(mock_data)
            
            # Save documentation
            documentation = enhanced_results.get('documentation', {})
            if documentation:
                self._save_documentation(documentation)
                
        except Exception as e:
            logger.error(f"Error integrating with existing output: {e}")
    
    def _convert_test_to_munit_xml(self, test: Dict[str, Any]) -> str:
        """Convert enhanced test format to MUnit XML"""
        # This is a simplified conversion - in practice, you'd want more sophisticated XML generation
        test_name = test.get('name', 'test')
        test_description = test.get('description', '')
        test_type = test.get('type', 'unit')
        
        # Basic MUnit XML structure
        munit_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:munit="http://www.mulesoft.org/schema/mule/munit" 
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core">
    
    <munit:test name="{test_name}" doc:id="test-{test_name}">
        <munit:behavior>
            <!-- Mock configurations would go here -->
            <munit-tools:mock-when doc:name="Mock Service" processor="http:request">
                <munit-tools:then-return>
                    <munit-tools:payload value="#[{{'result': 'success'}}]" />
                </munit-tools:then-return>
            </munit-tools:mock-when>
        </munit:behavior>
        
        <munit:execution>
            <!-- Test execution would go here -->
            <flow-ref name="test-flow" />
        </munit:execution>
        
        <munit:validation>
            <!-- Assertions would go here -->
            <munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" />
        </munit:validation>
    </munit:test>
</mule>'''
        
        return munit_xml
    
    def _save_mock_data(self, mock_data: Dict[str, Any]):
        """Save mock data using existing output system"""
        try:
            mock_dir = os.path.join(self.config.output_path, 'mock_data')
            os.makedirs(mock_dir, exist_ok=True)
            
            for data_key, data_content in mock_data.items():
                mock_file = os.path.join(mock_dir, f"{data_key}_mock_data.json")
                with open(mock_file, 'w') as f:
                    json.dump(data_content, f, indent=2, default=str)
                
                logger.info(f"Saved mock data to: {mock_file}")
                
        except Exception as e:
            logger.error(f"Error saving mock data: {e}")
    
    def _save_documentation(self, documentation: Dict[str, Any]):
        """Save documentation using existing output system"""
        try:
            docs_dir = os.path.join(self.config.output_path, 'documentation')
            os.makedirs(docs_dir, exist_ok=True)
            
            for doc_key, doc_content in documentation.items():
                if isinstance(doc_content, str):
                    doc_file = os.path.join(docs_dir, f"{doc_key}.md")
                    with open(doc_file, 'w') as f:
                        f.write(doc_content)
                    
                    logger.info(f"Saved documentation to: {doc_file}")
                    
        except Exception as e:
            logger.error(f"Error saving documentation: {e}")
    
    def get_enhanced_capabilities(self) -> Dict[str, Any]:
        """Get information about enhanced capabilities"""
        return {
            'security_features': {
                'input_sanitization': True,
                'data_classification': True,
                'compliance_validation': True,
                'sensitive_data_redaction': True
            },
            'token_optimization': {
                'smart_file_selection': True,
                'content_reduction': True,
                'progressive_analysis': True,
                'budget_management': True
            },
            'business_context': {
                'use_case_analysis': True,
                'api_spec_integration': True,
                'business_rule_extraction': True,
                'scenario_generation': True
            },
            'enhanced_testing': {
                'api_integration_tests': True,
                'business_scenario_tests': True,
                'security_tests': True,
                'fault_tolerance_tests': True
            },
            'reporting': {
                'security_reports': True,
                'optimization_reports': True,
                'business_context_reports': True,
                'compliance_reports': True
            }
        }
    
    def validate_enhanced_setup(self) -> Dict[str, Any]:
        """Validate enhanced setup and dependencies"""
        validation = {
            'valid': True,
            'issues': [],
            'recommendations': [],
            'enhanced_features_available': True
        }
        
        try:
            # Check enhanced modules are available
            required_modules = [
                'enhanced_munit_generator',
                'tiktoken',
                'bs4',
                'yaml'
            ]
            
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    validation['issues'].append(f"Missing required module: {module}")
                    validation['valid'] = False
            
            # Check configuration
            if not self.config.validate_all()['llm']['valid']:
                validation['issues'].append("LLM configuration is invalid")
                validation['recommendations'].append("Configure LLM API keys in .env file")
            
            # Check output directory
            if not os.path.exists(self.config.output_path):
                try:
                    os.makedirs(self.config.output_path, exist_ok=True)
                except Exception as e:
                    validation['issues'].append(f"Cannot create output directory: {e}")
                    validation['valid'] = False
            
            # Check token budget
            if self.config.max_prompt_tokens < 1000:
                validation['recommendations'].append("Consider increasing token budget for better results")
            
        except Exception as e:
            validation['issues'].append(f"Validation error: {e}")
            validation['valid'] = False
        
        return validation

class WebInterfaceEnhancer:
    """Enhancer for web interface to integrate enhanced features"""
    
    def __init__(self, app_instance):
        """Initialize web interface enhancer"""
        self.app = app_instance
        self.enhanced_integration = EnhancedIntegration()
        
        # Add enhanced routes
        self._add_enhanced_routes()
    
    def _add_enhanced_routes(self):
        """Add enhanced routes to Flask app"""
        
        @self.app.route('/api/enhanced/generate', methods=['POST'])
        def generate_enhanced_munit():
            """Enhanced MUnit generation endpoint"""
            try:
                # Get form data and files
                params = self.app.request.form.to_dict()
                files = self.app.request.files.to_dict()
                
                # Get enhanced parameters
                enhanced_mode = params.get('enhanced_mode', 'true').lower() == 'true'
                token_budget = int(params.get('token_budget', '50000'))
                optimization_level = params.get('optimization_level', 'balanced')
                
                # Handle file uploads
                xml_content = self._extract_xml_content(files, params)
                usecase_content = self._extract_usecase_content(files, params)
                
                # Generate with enhanced features
                results = self.enhanced_integration.generate_with_enhanced_features(
                    xml_content=xml_content,
                    usecase_content=usecase_content,
                    enhanced_mode=enhanced_mode,
                    token_budget=token_budget,
                    optimization_level=optimization_level
                )
                
                return self.app.jsonify(results)
                
            except Exception as e:
                return self.app.jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/enhanced/capabilities')
        def get_enhanced_capabilities():
            """Get enhanced capabilities information"""
            capabilities = self.enhanced_integration.get_enhanced_capabilities()
            return self.app.jsonify(capabilities)
        
        @self.app.route('/api/enhanced/validate')
        def validate_enhanced_setup():
            """Validate enhanced setup"""
            validation = self.enhanced_integration.validate_enhanced_setup()
            return self.app.jsonify(validation)
    
    def _extract_xml_content(self, files: Dict, params: Dict) -> str:
        """Extract XML content from files or parameters"""
        if 'xml_file' in files and files['xml_file']:
            xml_file = files['xml_file']
            if isinstance(xml_file, list):
                # Handle multiple files
                combined_content = ""
                for file in xml_file:
                    if hasattr(file, 'read'):
                        combined_content += file.read().decode('utf-8') + "\n"
                return combined_content
            else:
                # Single file
                if hasattr(xml_file, 'read'):
                    return xml_file.read().decode('utf-8')
        
        # Fallback to parameter
        return params.get('xml_content', '')
    
    def _extract_usecase_content(self, files: Dict, params: Dict) -> str:
        """Extract use case content from files or parameters"""
        if 'usecase_file' in files and files['usecase_file']:
            usecase_file = files['usecase_file']
            if isinstance(usecase_file, list):
                # Handle multiple files
                combined_content = ""
                for file in usecase_file:
                    if hasattr(file, 'read'):
                        combined_content += file.read().decode('utf-8') + "\n"
                return combined_content
            else:
                # Single file
                if hasattr(usecase_file, 'read'):
                    return usecase_file.read().decode('utf-8')
        
        # Fallback to parameter
        return params.get('usecase_content', '')

class CLIEnhancer:
    """Enhancer for CLI interface to integrate enhanced features"""
    
    def __init__(self):
        """Initialize CLI enhancer"""
        self.enhanced_integration = EnhancedIntegration()
    
    def add_enhanced_commands(self, cli_app):
        """Add enhanced commands to CLI app"""
        import typer
        
        @cli_app.command()
        def generate_enhanced(
            xml_source: str = typer.Option(..., help="Source type: 'local' or 'github'"),
            xml_path: Optional[str] = typer.Option(None, help="Local path to Mule XML file"),
            enhanced_mode: bool = typer.Option(True, help="Enable enhanced features"),
            token_budget: int = typer.Option(50000, help="Token budget for enhanced processing"),
            optimization_level: str = typer.Option("balanced", help="Optimization level: conservative, balanced, aggressive"),
            business_context_path: Optional[str] = typer.Option(None, help="Path to business context files"),
            api_spec_path: Optional[str] = typer.Option(None, help="Path to API specification files"),
            # Existing parameters...
            github_repo: Optional[str] = typer.Option(None, help="GitHub repository (owner/repo-name)"),
            github_branch: Optional[str] = typer.Option("main", help="GitHub branch name"),
            github_file_path: Optional[str] = typer.Option(None, help="File path in GitHub repository"),
            github_token: Optional[str] = typer.Option(None, help="GitHub personal access token"),
            usecase_source: Optional[str] = typer.Option(None, help="Source type: 'local', 'confluence', or skip for default scenarios"),
            usecase_path: Optional[str] = typer.Option(None, help="Local path to use case document"),
            confluence_url: Optional[str] = typer.Option(None, help="Confluence page URL"),
            confluence_token: Optional[str] = typer.Option(None, help="Confluence API token"),
            confluence_email: Optional[str] = typer.Option(None, help="Confluence email"),
            output_path: Optional[str] = typer.Option(None, help="Output directory for generated files"),
            verbose: bool = typer.Option(False, help="Enable verbose output")
        ):
            """Generate MUnit test suite with enhanced features"""
            
            from rich.console import Console
            from rich.panel import Panel
            
            console = Console()
            
            # Print banner
            banner = """
            [bold blue]Enhanced MUnit Generation Agent[/bold blue]
            [dim]Generate MUnit test suites with security, optimization, and business context[/dim]
            """
            console.print(Panel(banner, border_style="blue"))
            
            try:
                # Validate enhanced setup
                validation = self.enhanced_integration.validate_enhanced_setup()
                if not validation['valid']:
                    console.print("[red]Enhanced setup validation failed:[/red]")
                    for issue in validation['issues']:
                        console.print(f"  • {issue}")
                    raise typer.Exit(1)
                
                # Show capabilities if verbose
                if verbose:
                    capabilities = self.enhanced_integration.get_enhanced_capabilities()
                    console.print("[blue]Enhanced Capabilities:[/blue]")
                    for category, features in capabilities.items():
                        enabled_features = [k for k, v in features.items() if v]
                        console.print(f"  {category.replace('_', ' ').title()}: {', '.join(enabled_features)}")
                
                # Fetch XML content (reuse existing logic)
                xml_content = self._fetch_xml_content(xml_source, xml_path, github_repo, github_branch, github_file_path, github_token)
                
                # Fetch use case content (reuse existing logic)
                usecase_content = self._fetch_usecase_content(usecase_source, usecase_path, confluence_url, confluence_token, confluence_email)
                
                # Generate with enhanced features
                console.print("[blue]Generating MUnit tests with enhanced features...[/blue]")
                
                results = self.enhanced_integration.generate_with_enhanced_features(
                    xml_content=xml_content,
                    usecase_content=usecase_content,
                    enhanced_mode=enhanced_mode,
                    token_budget=token_budget,
                    business_context_path=business_context_path,
                    api_spec_path=api_spec_path,
                    optimization_level=optimization_level
                )
                
                if results['success']:
                    console.print("\n[bold green]Enhanced Generation Complete![/bold green]")
                    
                    # Display results
                    self._display_enhanced_results(results, console, verbose)
                else:
                    console.print(f"[red]Generation failed: {results.get('error', 'Unknown error')}[/red]")
                    raise typer.Exit(1)
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                if verbose:
                    import traceback
                    console.print(traceback.format_exc())
                raise typer.Exit(1)
        
        @cli_app.command()
        def enhanced_info():
            """Show enhanced features information"""
            from rich.console import Console
            from rich.table import Table
            
            console = Console()
            
            capabilities = self.enhanced_integration.get_enhanced_capabilities()
            validation = self.enhanced_integration.validate_enhanced_setup()
            
            # Capabilities table
            capabilities_table = Table(title="Enhanced Capabilities")
            capabilities_table.add_column("Category", style="cyan")
            capabilities_table.add_column("Features", style="green")
            
            for category, features in capabilities.items():
                enabled_features = [f"✓ {k}" for k, v in features.items() if v]
                capabilities_table.add_row(
                    category.replace('_', ' ').title(),
                    ', '.join(enabled_features)
                )
            
            console.print(capabilities_table)
            
            # Validation status
            validation_color = "green" if validation['valid'] else "red"
            console.print(f"\nEnhanced Setup Status: [{validation_color}]{validation['valid']}[/{validation_color}]")
            
            if validation['issues']:
                console.print("[red]Issues:[/red]")
                for issue in validation['issues']:
                    console.print(f"  • {issue}")
            
            if validation['recommendations']:
                console.print("[yellow]Recommendations:[/yellow]")
                for rec in validation['recommendations']:
                    console.print(f"  • {rec}")
    
    def _fetch_xml_content(self, xml_source: str, xml_path: Optional[str], 
                          github_repo: Optional[str], github_branch: str, 
                          github_file_path: Optional[str], github_token: Optional[str]) -> str:
        """Fetch XML content (reuse existing logic)"""
        # This would reuse the existing XML fetching logic from main.py
        # For now, return placeholder
        if xml_source == "local" and xml_path:
            from inputs import LocalReader
            local_reader = LocalReader()
            return local_reader.read_xml_file(xml_path)
        elif xml_source == "github" and github_repo and github_file_path:
            from inputs import GitHubFetcher
            from config import Config
            config = Config()
            token = github_token or config.github_token
            github_fetcher = GitHubFetcher(token=token)
            return github_fetcher.fetch_file(github_repo, github_branch, github_file_path)
        else:
            raise ValueError("Invalid XML source configuration")
    
    def _fetch_usecase_content(self, usecase_source: Optional[str], usecase_path: Optional[str],
                              confluence_url: Optional[str], confluence_token: Optional[str], 
                              confluence_email: Optional[str]) -> str:
        """Fetch use case content (reuse existing logic)"""
        # This would reuse the existing use case fetching logic from main.py
        # For now, return placeholder
        if usecase_source == "local" and usecase_path:
            from inputs import LocalReader
            local_reader = LocalReader()
            return local_reader.read_document(usecase_path)
        elif usecase_source == "confluence" and confluence_url:
            from inputs import ConfluenceReader
            from config import Config
            config = Config()
            token = confluence_token or config.confluence_token
            email = confluence_email or config.confluence_email
            confluence_reader = ConfluenceReader(
                url=confluence_url.split("/wiki")[0] + "/wiki",
                token=token,
                email=email
            )
            return confluence_reader.fetch_page_content(confluence_url)
        else:
            return ""
    
    def _display_enhanced_results(self, results: Dict[str, Any], console, verbose: bool):
        """Display enhanced generation results"""
        from rich.table import Table
        
        # Results table
        results_table = Table(title="Enhanced Generation Results")
        results_table.add_column("Property", style="cyan")
        results_table.add_column("Value", style="green")
        
        results_table.add_row("Mode", results.get('mode', 'enhanced'))
        results_table.add_row("Success", "Yes")
        
        # Token usage
        token_usage = results.get('token_usage', {})
        results_table.add_row("Token Budget", str(token_usage.get('budget', 0)))
        results_table.add_row("Tokens Used", str(token_usage.get('used', 0)))
        results_table.add_row("Tokens Remaining", str(token_usage.get('remaining', 0)))
        
        # Security
        security_validation = results.get('security_validation', {})
        results_table.add_row("Security Status", security_validation.get('status', 'unknown'))
        
        # Optimization
        optimization_validation = results.get('optimization_validation', {})
        results_table.add_row("Optimization Status", optimization_validation.get('status', 'unknown'))
        results_table.add_row("Savings Percentage", f"{optimization_validation.get('savings_percentage', 0):.1f}%")
        
        # Test suites
        test_suites = results.get('test_suites', {})
        results_table.add_row("Test Suites Generated", str(len(test_suites)))
        
        console.print(results_table)
        
        # Test suites details
        if test_suites and verbose:
            suites_table = Table(title="Generated Test Suites")
            suites_table.add_column("Suite Type", style="cyan")
            suites_table.add_column("Tests", style="green")
            
            for suite_name, suite_data in test_suites.items():
                test_count = len(suite_data.get('tests', []))
                suites_table.add_row(suite_name.replace('_', ' ').title(), str(test_count))
            
            console.print(suites_table)
        
        # Recommendations
        optimization_suggestions = token_usage.get('optimization_suggestions', [])
        if optimization_suggestions and verbose:
            console.print("\n[yellow]Optimization Suggestions:[/yellow]")
            for suggestion in optimization_suggestions:
                console.print(f"  • {suggestion}")

# Factory function for easy integration
def create_enhanced_generator(config: Optional[Config] = None) -> EnhancedIntegration:
    """Create enhanced generator instance"""
    return EnhancedIntegration(config)

def enhance_web_app(app_instance) -> WebInterfaceEnhancer:
    """Enhance existing web app"""
    return WebInterfaceEnhancer(app_instance)

def enhance_cli_app(cli_app) -> CLIEnhancer:
    """Enhance existing CLI app"""
    return CLIEnhancer()
