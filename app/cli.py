#!/usr/bin/env python3
"""
R.A.I.D CLI Interface
Command-line interface for the R.A.I.D security scanner
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from app.core.engine import ScanEngine
from app.utils.logger import setup_logger
from app.utils.http_client import HTTPClient

app = typer.Typer(
    name="raid",
    help="R.A.I.D (Reconnaissance and Automated Intrusion Detector)",
    no_args_is_help=True
)

console = Console()

ASCII_LOGO = """


████████████████████████████████████████
████████████████████████████████████████
██████████████─────────────█████████████
███████████───────────────────██████████
█████████───────────────────────████████
███████─────██─────────────██─────██████
██████─────████───────────████─────█████
█████─────██████─────────█████──────████
████──────██████────────███████──────███
███──────██████████████████████──────███
███──────███─────███████─────███──────██
██───────█─────█───███───█─────█──────██
██──────██─────█────█────█─────██─────██
██──────█──────█────█────█─────██─────██
███─────██─────█────█────█─────██─────██
███─▄▄▄▄███────█───███───█────███▄▄▄▄─██
████─▄▄▄▄████────███████────████▄▄▄▄─███
████─▄▄▄▄▄▄███████████████████▄▄▄▄▄▄─███
█████─────────█████████████─────────████
██████─────────────███─────────────█████
███████────────────███────────────██████
█████████──────────███──────────████████
███████████───────█████───────██████████
██████████████────█████────█████████████
████████████████████████████████████████




            KADEZ-406  |  R.A.I.D  — Recon & Automated Intrusion Detector
"""

ETHICAL_WARNING = """
⚠️  IMPORTANT ETHICAL NOTICE ⚠️

This tool is designed for AUTHORIZED security testing only.
- Only use on systems you own or have explicit written permission to test
- Unauthorized scanning is illegal and unethical
- Always follow responsible disclosure practices
- Respect system resources and don't cause damage

By using this tool, you agree to use it responsibly and legally.
"""


def validate_attestation(mode: str, target: str) -> bool:
    """Validate attestation file for audit mode."""
    if mode != "audit":
        return True
    
    attestation_file = Path("attestation.txt")
    if not attestation_file.exists():
        console.print("[red]ERROR: attestation.txt required for audit mode[/red]")
        console.print("Create attestation.txt with: 'I confirm I have authorization to scan {target}'")
        return False
    
    try:
        content = attestation_file.read_text().strip()
        expected_content = f"I confirm I have authorization to scan {target}"
        if content != expected_content:
            console.print("[red]ERROR: Invalid attestation content[/red]")
            console.print(f"Expected: {expected_content}")
            console.print(f"Found: {content}")
            return False
        return True
    except Exception as e:
        console.print(f"[red]ERROR reading attestation file: {e}[/red]")
        return False


def validate_target(target: str) -> bool:
    """Validate target URL format and safety."""
    if not target.startswith(('http://', 'https://')):
        console.print("[red]ERROR: Target must start with http:// or https://[/red]")
        return False
    
    # Check for localhost/private IPs in safe mode
    import urllib.parse
    parsed = urllib.parse.urlparse(target)
    hostname = parsed.hostname
    
    if hostname in ['localhost', '127.0.0.1', '::1']:
        return True  # Allow localhost
    
    # Allow private networks (common in lab environments)
    import ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private:
            return True
    except (ipaddress.AddressValueError, ValueError):
        pass  # Not an IP address
    
    return True


@app.command()
def scan(
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Target URL to scan (e.g., https://example.com)"
    ),
    scope_file: Optional[str] = typer.Option(
        None, "--scope-file", "-s",
        help="File containing list of URLs to scan"
    ),
    mode: str = typer.Option(
        "safe", "--mode", "-m",
        help="Scan mode: safe (default), lab, or audit"
    ),
    concurrency: int = typer.Option(
        5, "--concurrency", "-c",
        help="Number of concurrent requests"
    ),
    output_dir: str = typer.Option(
        "./reports", "--output-dir", "-o",
        help="Output directory for reports"
    ),
    plugins: Optional[str] = typer.Option(
        None, "--plugins", "-p",
        help="Comma-separated list of plugins to run (default: all)"
    ),
    timeout: int = typer.Option(
        30, "--timeout",
        help="Request timeout in seconds"
    ),
    user_agent: str = typer.Option(
        "R.A.I.D-Scanner/1.0", "--user-agent", "-ua",
        help="Custom User-Agent string"
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy",
        help="Proxy URL (http://proxy:port)"
    ),
    verbose: int = typer.Option(
        1, "--verbose", "-v",
        help="Verbosity level: 0=minimal, 1=standard, 2=debug"
    ),
    log_payloads: bool = typer.Option(
        False, "--log-payloads",
        help="Save all used payloads to payloads_used.txt"
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Ignore robots.txt and rate limits"
    ),
    no_subdomain_discovery: bool = typer.Option(
        False, "--no-subdomain-discovery",
        help="Disable subdomain discovery"
    ),
    crawl_depth: int = typer.Option(
        3, "--crawl-depth",
        help="Maximum crawling depth for parameter discovery"
    ),
    max_subdomains: int = typer.Option(
        50, "--max-subdomains",
        help="Maximum number of subdomains to discover"
    ),
    max_param_checks: int = typer.Option(
        0, "--max-param-checks",
        help="Limit number of parameterized endpoint checks per plugin (0 = no limit)"
    )
):
    """Run a security scan against the specified target(s)."""
    
    # Display logo and warning
    console.print(Text(ASCII_LOGO, style="cyan"))
    console.print(Panel(ETHICAL_WARNING, title="⚠️  ETHICAL NOTICE", border_style="red"))
    
    # Validate mode
    if mode not in ["safe", "lab", "audit"]:
        console.print("[red]ERROR: Mode must be 'safe', 'lab', or 'audit'[/red]")
        raise typer.Exit(1)
    
    # Validate target
    if not validate_target(target):
        raise typer.Exit(1)
    
    # Validate attestation for audit mode
    if not validate_attestation(mode, target):
        raise typer.Exit(1)
    
    # Setup logging
    logger = setup_logger(verbose)
    
    # Parse targets
    targets = [target]
    if scope_file:
        try:
            with open(scope_file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        except FileNotFoundError:
            console.print(f"[red]ERROR: Scope file {scope_file} not found[/red]")
            raise typer.Exit(1)
    
    # Parse plugins
    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(',')]
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Run scan
    try:
        # Initialize progress manager
        from app.utils.progress_manager import ProgressManager
        progress_manager = ProgressManager(console, output_dir, verbosity=verbose)
        
        # Initialize scan engine
        engine = ScanEngine(
            mode=mode,
            concurrency=concurrency,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            force=force,
            output_dir=output_dir,
            logger=logger,
            progress_manager=progress_manager,
            max_param_checks=max_param_checks
        )
        
        # Configure discovery options
        engine.enable_subdomain_discovery = not no_subdomain_discovery
        engine.crawl_depth = crawl_depth
        
        # Display discovery configuration
        if engine.enable_subdomain_discovery:
            progress_manager.log_message("INFO", f"Enhanced Discovery: Enabled (depth: {crawl_depth}, max subdomains: {max_subdomains})")
        else:
            progress_manager.log_message("INFO", "Enhanced Discovery: Parameter crawling only")
        
        # Log worker configuration
        progress_manager.log_worker_info(concurrency)
        
        # Run the scan
        asyncio.run(engine.run_scan(targets, plugin_list, log_payloads))
        
        # Show completion message
        progress_manager.log_message("SUCCESS", "Scan completed successfully!")
        progress_manager.log_message("INFO", f"Reports saved to: {output_dir}")
        
    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)


@app.command()
def generate_plugin(
    name: str = typer.Argument(..., help="Plugin name"),
    category: str = typer.Option("custom", "--category", "-c", help="Plugin category"),
    mode: str = typer.Option("safe", "--mode", "-m", help="Required mode (safe/lab/both)")
):
    """Generate a new plugin template."""
    from app.plugins.plugin_generator import generate_plugin_template
    
    try:
        plugin_path = generate_plugin_template(name, category, mode)
        console.print(f"[green]Plugin template created: {plugin_path}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to generate plugin: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list_checks():
    """List all available security checks."""
    from app.data.checks_manifest import load_checks_manifest
    
    try:
        checks = load_checks_manifest()
        
        console.print("[cyan]Available Security Checks:[/cyan]\n")
        
        for category, check_list in checks.items():
            console.print(f"[yellow]{category.upper()}[/yellow]")
            for check in check_list:
                status = "✓" if check.get("implemented", False) else "○"
                mode = check.get("required_mode", "safe")
                console.print(f"  {status} {check['id']} - {check['name']} [{mode}]")
            console.print()
            
    except Exception as e:
        console.print(f"[red]Failed to load checks: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def discover(
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Target URL for discovery (e.g., https://example.com)"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file for discovery results"
    ),
    crawl_depth: int = typer.Option(
        3, "--crawl-depth",
        help="Maximum crawling depth for parameter discovery"
    ),
    max_subdomains: int = typer.Option(
        50, "--max-subdomains",
        help="Maximum number of subdomains to discover"
    ),
    no_subdomain_discovery: bool = typer.Option(
        False, "--no-subdomain-discovery",
        help="Disable subdomain discovery"
    ),
    timeout: int = typer.Option(
        30, "--timeout",
        help="Request timeout in seconds"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose output"
    )
):
    """Run comprehensive target discovery without security scanning."""
    
    # Display logo
    console.print(Text(ASCII_LOGO, style="cyan"))
    console.print(Panel("🔍 R.A.I.D Discovery Mode", title="Discovery", border_style="cyan"))
    
    # Validate target
    if not validate_target(target):
        console.print("[red]ERROR: Invalid target format[/red]")
        raise typer.Exit(1)
    
    # Setup logging
    logger = setup_logger(verbose)
    
    try:
        console.print(f"[green]Starting comprehensive discovery for {target}...[/green]")
        console.print(f"Crawl depth: {crawl_depth}")
        console.print(f"Subdomain discovery: {'Enabled' if not no_subdomain_discovery else 'Disabled'}")
        
        async def run_discovery():
            async with HTTPClient(timeout=timeout) as session:
                # Initialize discovery components
                from app.utils.crawler import EnhancedDiscovery
                # Get the httpx session from HTTPClient
                httpx_session = await session._ensure_session()
                discovery = EnhancedDiscovery(httpx_session, logger)
                
                # Run comprehensive discovery
                results = await discovery.comprehensive_discovery(
                    target,
                    include_subdomains=not no_subdomain_discovery,
                    max_depth=crawl_depth
                )
                
                # Save results
                if not output_file:
                    from urllib.parse import urlparse
                    domain = urlparse(target).netloc.replace('.', '_')
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = f"reports/discovery_{domain}_{timestamp}.json"
                else:
                    output_path = output_file
                
                saved_file = discovery.save_discovery_results(results, output_path)
                
                # Display summary
                console.print("\n[bold green]Discovery Results:[/bold green]")
                console.print(f"Total Endpoints: {results['total_endpoints']}")
                console.print(f"Total Parameters: {results['total_parameters']}")
                console.print(f"Subdomains Found: {results['total_subdomains']}")
                console.print(f"Results saved to: {saved_file}")
                
                # Display top findings
                if results.get('endpoints_with_parameters'):
                    console.print("\n[bold cyan]Top Endpoints with Parameters:[/bold cyan]")
                    count = 0
                    for endpoint, params in results['endpoints_with_parameters'].items():
                        if count >= 10:  # Limit display
                            break
                        console.print(f"  {endpoint} -> {len(params)} parameters")
                        count += 1
                
                if results.get('subdomains'):
                    console.print("\n[bold cyan]Discovered Subdomains:[/bold cyan]")
                    for subdomain in results['subdomains'][:10]:  # Limit display
                        console.print(f"  {subdomain}")
                    
                    if len(results['subdomains']) > 10:
                        console.print(f"  ... and {len(results['subdomains']) - 10} more")
        
        # Run discovery
        asyncio.run(run_discovery())
        
        console.print("[green]Discovery completed successfully![/green]")
        
    except KeyboardInterrupt:
        console.print("[yellow]Discovery interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from app import __version__, __author__
    console.print(f"R.A.I.D Scanner v{__version__}")
    console.print(f"By {__author__}")


if __name__ == "__main__":
    app() 