
"""
MUnit Generation Agent - Main CLI Application
"""

import typer
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import Config
from core import XMLAnalyzer, DocumentParser, PromptBuilder, RulesetLoader
from inputs import GitHubFetcher, LocalReader, ConfluenceReader
from llm import LLMRouter
from munitWriter import MUnitWriter


app = typer.Typer(
    name="munit-agent",
    help="MuleSoft MUnit Generation Agent - Generate MUnit test suites from Mule XML and business use cases",
    add_completion=False
)

console = Console()


def print_banner():
    """Print application banner."""
    banner = """
    [bold blue]MUnit Generation Agent[/bold blue]
    [dim]Generate MUnit test suites from Mule XML and business use cases[/dim]
    """
    console.print(Panel(banner, border_style="blue"))


@app.command()
def generate(
    xml_source: str = typer.Option(..., help="Source type: 'local' or 'github'"),
    xml_path: Optional[str] = typer.Option(None, help="Local path to Mule XML file"),
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
    """Generate MUnit test suite from Mule XML and business use case."""
    
    print_banner()
    
    try:
        # Load configuration
        config = Config()
        
        if verbose:
            config.print_config_summary()
        
        # Validate configuration
        validation = config.validate_all()
        
        if not validation["llm"]["valid"]:
            console.print("[red]Error: No LLM API keys configured. Please set up API keys in .env file.[/red]")
            console.print("Missing keys: " + ", ".join(validation["llm"]["missing_keys"]))
            raise typer.Exit(1)
        
        # Override config with CLI arguments
        if output_path:
            config.output_path = output_path
        
        # Initialize components
        xml_analyzer = XMLAnalyzer()
        doc_parser = DocumentParser()
        prompt_builder = PromptBuilder(max_tokens=config.max_prompt_tokens)
        ruleset_loader = RulesetLoader()
        llm_router = LLMRouter(timeout=config.llm_timeout)
        munit_writer = MUnitWriter(output_dir=config.output_path)
        
        # Load ruleset
        console.print("[blue]Loading ruleset...[/blue]")
        ruleset = ruleset_loader.load_ruleset()
        
        if not ruleset_loader.validate_ruleset_structure(ruleset):
            console.print("[red]Error: Invalid ruleset structure[/red]")
            raise typer.Exit(1)
        
        # Fetch Mule XML
        console.print("[blue]Fetching Mule XML...[/blue]")
        if xml_source == "local":
            if not xml_path:
                console.print("[red]Error: --xml-path required for local source[/red]")
                raise typer.Exit(1)
            
            local_reader = LocalReader()
            xml_content = local_reader.read_xml_file(xml_path)
            
        elif xml_source == "github":
            if not all([github_repo, github_file_path]):
                console.print("[red]Error: --github-repo and --github-file-path required for GitHub source[/red]")
                raise typer.Exit(1)
            
            token = github_token or config.github_token
            github_fetcher = GitHubFetcher(token=token)
            xml_content = github_fetcher.fetch_file(github_repo, github_branch, github_file_path)
            
        else:
            console.print(f"[red]Error: Invalid xml_source: {xml_source}[/red]")
            raise typer.Exit(1)
        
        # Validate Mule XML
        if not xml_analyzer.validate_mule_xml(xml_content):
            console.print("[red]Error: Invalid Mule XML file[/red]")
            raise typer.Exit(1)
        
        # Analyze Mule XML
        console.print("[blue]Analyzing Mule XML...[/blue]")
        flow_summary = xml_analyzer.analyze_mule_project(xml_content)
        
        # Fetch business use case (optional)
        console.print("[blue]Fetching business use case...[/blue]")
        usecase_content = ""
        
        if usecase_source == "local":
            if not usecase_path:
                console.print("[yellow]Warning: No use case path provided, using default scenarios[/yellow]")
            else:
                local_reader = LocalReader()
                usecase_content = local_reader.read_document(usecase_path)
            
        elif usecase_source == "confluence":
            if not confluence_url:
                console.print("[yellow]Warning: No Confluence URL provided, using default scenarios[/yellow]")
            else:
                token = confluence_token or config.confluence_token
                email = confluence_email or config.confluence_email
                
                if not token or not email:
                    console.print("[yellow]Warning: Confluence token and email required, using default scenarios[/yellow]")
                else:
                    confluence_reader = ConfluenceReader(
                        url=confluence_url.split("/wiki")[0] + "/wiki",
                        token=token,
                        email=email
                    )
                    usecase_content = confluence_reader.fetch_page_content(confluence_url)
            
        elif usecase_source is None:
            console.print("[blue]No business use case specified, using default scenarios[/blue]")
            
        else:
            console.print(f"[yellow]Warning: Invalid usecase_source: {usecase_source}, using default scenarios[/yellow]")
        
        # Validate use case content
        if not doc_parser.validate_document_content(usecase_content):
            console.print("[yellow]Warning: Use case document appears to have minimal content[/yellow]")
        
        # Parse business use case
        console.print("[blue]Parsing business use case...[/blue]")
        scenarios = doc_parser.parse_document(usecase_content, flow_summary["job_type"])
        
        scenario_map = doc_parser.map_scenarios_to_flows(scenarios["scenarios"], flow_summary)

        # Build targeted prompts, generate, and write per-flow MUnits
        console.print("[blue]Generating per-flow MUnit suites...[/blue]")
        generation_outputs = []
        for target_flow in flow_summary.get("test_targets") or flow_summary.get("flows") or ["main-flow"]:
            flow_context = flow_summary.get("flow_contexts", {}).get(target_flow, {"target_flow": target_flow})
            prompt = prompt_builder.build_prompt(
                flow_summary,
                scenario_map.get(target_flow, []),
                ruleset,
                flow_context=flow_context,
                document_context=scenarios
            )

            if not prompt_builder.validate_prompt_structure(prompt):
                console.print(f"[red]Error: Invalid prompt structure for target flow {target_flow}[/red]")
                raise typer.Exit(1)

            munit_xml, metadata = llm_router.generate_munit(prompt)
            metadata = {
                **metadata,
                "target_flow": target_flow,
                "source_file": flow_context.get("source_file", "unknown.xml"),
                "scenario_count": len(scenario_map.get(target_flow, [])),
                "related_flows": flow_context.get("related_flows", [])
            }
            output_file = munit_writer.write_munit_file(munit_xml, target_flow, metadata)
            generation_outputs.append({
                "target_flow": target_flow,
                "output_file": output_file,
                "metadata": metadata
            })
        
        # Validate generated MUnit
        primary_output = generation_outputs[0]["output_file"] if generation_outputs else ""
        file_info = munit_writer.get_file_info(primary_output) if primary_output else {}
        
        # Print results
        console.print("\n[bold green]Generation Complete![/bold green]")
        
        results_table = Table(title="Generation Results")
        results_table.add_column("Property", style="cyan")
        results_table.add_column("Value", style="green")
        
        results_table.add_row("Primary Output File", primary_output or "None")
        results_table.add_row("Output Files Generated", str(len(generation_outputs)))
        results_table.add_row("Job Type", flow_summary["job_type"])
        results_table.add_row("Main Flow", flow_summary["flows"][0] if flow_summary["flows"] else "main-flow")
        results_table.add_row("Target Flows", str(len(flow_summary.get("test_targets", []))))
        results_table.add_row("Scenarios Generated", str(len(scenarios["scenarios"])))
        results_table.add_row("Tests Generated", str(file_info.get("test_count", "Unknown")))
        results_table.add_row("LLM Model", generation_outputs[0]["metadata"]["model_used"] if generation_outputs else "Unknown")
        results_table.add_row("Generation Time", f"{sum(item['metadata']['generation_time'] for item in generation_outputs):.2f}s")
        results_table.add_row("XML Valid", "Yes" if file_info.get("valid_xml") else "No")
        
        console.print(results_table)
        
        if verbose:
            console.print("\n[bold]Detailed Metadata:[/bold]")
            for item in generation_outputs:
                console.print(f"  {item['target_flow']}: {item['output_file']}")
        
        console.print(f"\n[green]Generated {len(generation_outputs)} MUnit suite(s). Primary file: {primary_output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)


@app.command()
def config(
    show: bool = typer.Option(False, help="Show current configuration"),
    create_env: bool = typer.Option(False, help="Create .env file template"),
    validate: bool = typer.Option(False, help="Validate configuration")
):
    """Manage configuration."""
    
    print_banner()
    
    config_manager = Config()
    
    if create_env:
        config_manager.create_env_file()
        console.print("[green]Created .env file template[/green]")
        console.print("Please edit .env file with your API keys and configuration.")
        return
    
    if show:
        config_manager.print_config_summary()
        return
    
    if validate:
        validation = config_manager.validate_all()
        
        console.print("[bold]Configuration Validation:[/bold]")
        
        # LLM validation
        llm_val = validation["llm"]
        console.print(f"\n[blue]LLM Configuration:[/blue]")
        console.print(f"  Valid: {'Yes' if llm_val['valid'] else 'No'}")
        console.print(f"  Available Models: {', '.join(llm_val['available_models'])}")
        if llm_val['missing_keys']:
            console.print(f"  Missing Keys: {', '.join(llm_val['missing_keys'])}")
        
        # GitHub validation
        github_val = validation["github"]
        console.print(f"\n[blue]GitHub Configuration:[/blue]")
        console.print(f"  Token Set: {'Yes' if github_val['has_token'] else 'No'}")
        
        # Confluence validation
        confluence_val = validation["confluence"]
        console.print(f"\n[blue]Confluence Configuration:[/blue]")
        console.print(f"  Valid: {'Yes' if confluence_val['valid'] else 'No'}")
        console.print(f"  Token Set: {'Yes' if confluence_val['has_token'] else 'No'}")
        console.print(f"  Email Set: {'Yes' if confluence_val['has_email'] else 'No'}")
        
        # Output validation
        output_val = validation["output"]
        console.print(f"\n[blue]Output Configuration:[/blue]")
        console.print(f"  Path: {output_val['output_path']}")
        console.print(f"  Directory Exists: {'Yes' if output_val['dir_exists'] else 'No'}")
        console.print(f"  Directory Writable: {'Yes' if output_val['dir_writable'] else 'No'}")
        
        return
    
    # Default: show help
    console.print("Use --show, --create-env, or --validate to manage configuration.")


@app.command()
def version():
    """Show version information."""
    console.print("[bold]MUnit Generation Agent v1.0.0[/bold]")
    console.print("[dim]A Python-based AI agent for generating MUnit test suites[/dim]")


if __name__ == "__main__":
    import sys
    
    # If no arguments provided, launch web app
    if len(sys.argv) == 1:
        print("Launching MUnit Generation Agent Web Application...")
        print("Opening browser in 3 seconds...")
        print("Press Ctrl+C to stop the server")
        print("-" * 50)
        
        import webbrowser
        import time
        import threading
        
        # Start Flask app in a separate thread
        def start_flask():
            from app import app as flask_app
            flask_app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
        
        flask_thread = threading.Thread(target=start_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Wait a moment for server to start
        time.sleep(2)
        
        # Open browser
        webbrowser.open('http://localhost:5000')
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down web server...")
            sys.exit(0)
    else:
        # Run CLI mode with arguments
        app()
