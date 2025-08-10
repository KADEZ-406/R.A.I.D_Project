"""
Progress Manager for R.A.I.D Scanner
Handles real-time progress output, colored logging, and progress tracking
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns


class ProgressManager:
    """Manages real-time progress output for R.A.I.D scanner."""
    
    def __init__(self, console: Console, output_dir: str = "./reports", verbosity: int = 1):
        self.console = console
        self.output_dir = Path(output_dir)
        self.verbosity = verbosity
        self.start_time = None
        self.total_checks = 0
        self.completed_checks = 0
        self.current_plugin = ""
        self.current_endpoint = ""
        self.current_payload = ""
        self.current_check_number = 0
        
        # Statistics tracking
        self.vulnerabilities: Dict[str, List[Dict]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        # Payload logging
        self.payloads_used: List[Dict] = []
        self.log_payloads = False
        
        # Progress bar
        self.progress = None
        self.progress_task = None
        
        # Scan statistics
        self.scan_stats = {
            "targets": [],
            "plugins_loaded": 0,
            "endpoints_discovered": 0,
            "parameters_found": 0,
            "requests_made": 0
        }
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def start_scan(self, total_checks: int, log_payloads: bool = False, mode: str = "safe", target: str = ""):
        """Start a new scan with progress tracking."""
        self.start_time = datetime.now()
        self.total_checks = total_checks
        self.completed_checks = 0
        self.log_payloads = log_payloads
        self.current_check_number = 0
        
        # Display scan start information
        if self.verbosity >= 1:
            self.console.print(f"[{self._get_timestamp()}] [INFO] Starting R.A.I.D scan in {mode} mode...")
            if target:
                self.console.print(f"[{self._get_timestamp()}] [INFO] Target: {target}")
        
        # Initialize progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console
        )
        
        self.progress.start()
        self.progress_task = self.progress.add_task(
            f"Scanning... ({total_checks} checks)", 
            total=total_checks
        )

    def set_total_checks(self, total_checks: int):
        """Set absolute total checks for the progress bar."""
        self.total_checks = max(0, int(total_checks))
        if self.progress and self.progress_task is not None:
            # Update task total
            self.progress.update(self.progress_task, total=self.total_checks)

    def add_checks(self, additional_checks: int):
        """Increase total checks dynamically during the scan."""
        if additional_checks <= 0:
            return
        new_total = self.total_checks + int(additional_checks)
        self.set_total_checks(new_total)
    
    def update_progress(self, plugin_name: str, endpoint: str, payload: str = "", check_number: int = None):
        """Update current progress information."""
        self.current_plugin = plugin_name
        self.current_endpoint = endpoint
        self.current_payload = payload
        
        if check_number:
            self.current_check_number = check_number
        
        if self.progress and self.progress_task:
            self.progress.update(self.progress_task, advance=1)
            self.completed_checks += 1
    
    def log_message(self, level: str, message: str):
        """Log a message with timestamp and color coding."""
        timestamp = self._get_timestamp()
        
        # Color mapping for different log levels
        colors = {
            "INFO": "cyan",
            "PAYLOAD": "yellow",
            "VULNERABLE": "red bold",
            "SUCCESS": "green bold",
            "WARNING": "yellow",
            "ERROR": "red"
        }
        
        color = colors.get(level, "white")
        if self.verbosity >= 1 or level in ("VULNERABLE", "ERROR"):
            self.console.print(f"[{timestamp}] [{level}] {message}", style=color)
    
    def log_plugin_start(self, plugin_name: str, check_number: int = None):
        """Log when a plugin starts running."""
        if self.verbosity >= 1:
            if check_number:
                self.log_message("INFO", f"Running check: {plugin_name} [{check_number}/{self.total_checks}]")
            else:
                self.log_message("INFO", f"Running check: {plugin_name}")
    
    def log_payload(self, method: str, url: str, payload: str):
        """Log a payload being tested."""
        if self.verbosity >= 2:
            self.log_message("PAYLOAD", f"{method} {url}")
        
        # Store payload for logging if enabled
        if self.log_payloads:
            self.payloads_used.append({
                "timestamp": self._get_timestamp(),
                "method": method,
                "url": url,
                "payload": payload
            })
    
    def log_vulnerability(self, plugin_name: str, severity: str, description: str, url: str):
        """Log a vulnerability finding."""
        self.log_message("VULNERABLE", f"{plugin_name} found at {url}")
        
        # Store vulnerability
        if severity in self.vulnerabilities:
            self.vulnerabilities[severity].append({
                "plugin": plugin_name,
                "description": description,
                "url": url,
                "timestamp": self._get_timestamp()
            })
    
    def log_discovery_info(self, endpoints_count: int, parameters_count: int, subdomains_count: int = 0):
        """Log discovery information."""
        self.scan_stats["endpoints_discovered"] = endpoints_count
        self.scan_stats["parameters_found"] = parameters_count
        
        if self.verbosity >= 1:
            self.log_message("INFO", f"Discovered {endpoints_count} endpoints with {parameters_count} parameters")
            if subdomains_count > 0:
                self.log_message("INFO", f"Found {subdomains_count} subdomains")
    
    def log_worker_info(self, concurrency: int):
        """Log worker configuration."""
        if self.verbosity >= 1:
            self.log_message("INFO", f"Using {concurrency} concurrent workers")
    
    def log_scan_progress(self, current_check: int, total_checks: int, plugin_name: str, endpoint: str):
        """Log detailed scan progress."""
        percentage = (current_check / total_checks) * 100 if total_checks > 0 else 0
        self.log_message("INFO", f"Progress: {current_check}/{total_checks} ({percentage:.1f}%) - {plugin_name} at {endpoint}")
    
    def complete_scan(self):
        """Complete the scan and show summary."""
        if self.progress:
            self.progress.stop()
        
        self.console.print()
        
        # Calculate scan duration
        duration = self._calculate_duration()
        duration_str = self._format_duration(duration)
        
        self.log_message("SUCCESS", f"Scan completed in {duration_str}")
        
        # Show vulnerability summary
        self.show_vulnerability_summary()
        
        # Save payloads log if enabled
        if self.log_payloads and self.payloads_used:
            self.save_payloads_log()
    
    def show_vulnerability_summary(self):
        """Display vulnerability summary table similar to sqlmap."""
        total_vulnerabilities = sum(len(vulns) for vulns in self.vulnerabilities.values())
        
        if total_vulnerabilities == 0:
            self.console.print("[green]No vulnerabilities found![/green]")
            return
        
        # Create summary table
        table = Table(title="Vulnerability Summary", show_header=True, header_style="bold magenta")
        table.add_column("Vulnerability Type", style="cyan", no_wrap=True)
        table.add_column("Severity", style="yellow", justify="center")
        table.add_column("Affected URLs", style="green", justify="right")
        
        # Add rows for each severity level
        for severity, vulns in self.vulnerabilities.items():
            if vulns:
                # Group by plugin type
                plugin_counts = {}
                for vuln in vulns:
                    plugin_name = vuln["plugin"]
                    plugin_counts[plugin_name] = plugin_counts.get(plugin_name, 0) + 1
                
                for plugin_name, count in plugin_counts.items():
                    severity_color = {
                        "critical": "red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue",
                        "info": "cyan"
                    }.get(severity, "white")
                    
                    table.add_row(
                        plugin_name,
                        f"[{severity_color}]{severity.upper()}[/{severity_color}]",
                        str(count)
                    )
        
        self.console.print(table)
        
        # Show total summary
        duration = self._calculate_duration()
        self.console.print(f"\n[bold]Total: {self.total_checks} checks, {total_vulnerabilities} vulnerabilities found in {self._format_duration(duration)}[/bold]")
        
        # Show breakdown by severity
        severity_breakdown = []
        for severity, vulns in self.vulnerabilities.items():
            if vulns:
                severity_breakdown.append(f"{len(vulns)} {severity.title()}")
        
        if severity_breakdown:
            self.console.print(f"[{self._get_timestamp()}] [SUMMARY] {' | '.join(severity_breakdown)}")
    
    def save_payloads_log(self):
        """Save all used payloads to a file."""
        try:
            payloads_file = self.output_dir / "payloads_used.txt"
            
            with open(payloads_file, 'w', encoding='utf-8') as f:
                f.write("R.A.I.D Scanner - Payloads Used\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Payloads: {len(self.payloads_used)}\n\n")
                
                for entry in self.payloads_used:
                    f.write(f"[{entry['timestamp']}] {entry['method']} {entry['url']}\n")
                    f.write(f"  Payload: {entry['payload']}\n")
                    f.write("-" * 30 + "\n")
            
            self.console.print(f"[{self._get_timestamp()}] [INFO] Payloads log saved to: {payloads_file}")
            
        except Exception as e:
            self.console.print(f"[{self._get_timestamp()}] [ERROR] Failed to save payloads log: {e}")
    
    def get_scan_stats(self) -> Dict[str, any]:
        """Get scan statistics."""
        duration = self._calculate_duration()
        
        return {
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "duration_seconds": duration,
            "total_checks": self.total_checks,
            "completed_checks": self.completed_checks,
            "vulnerabilities": {k: len(v) for k, v in self.vulnerabilities.items()},
            "scan_stats": self.scan_stats
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in HH:MM:SS format."""
        return datetime.now().strftime("%H:%M:%S")
    
    def _calculate_duration(self) -> float:
        """Calculate scan duration in seconds."""
        if not self.start_time:
            return 0.0
        return (datetime.now() - self.start_time).total_seconds()
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            remaining_seconds = seconds % 60
            return f"{minutes}m{remaining_seconds:.0f}s"
        else:
            hours = int(seconds // 3600)
            remaining_minutes = int((seconds % 3600) // 60)
            return f"{hours}h{remaining_minutes}m"
