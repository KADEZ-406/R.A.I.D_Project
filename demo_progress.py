#!/usr/bin/env python3
"""
Demo script for R.A.I.D Scanner Progress Manager
Shows the enhanced real-time progress output features
"""

import asyncio
import time
from rich.console import Console
from app.utils.progress_manager import ProgressManager

async def demo_progress_manager():
    """Demonstrate the enhanced progress manager features."""
    console = Console()
    
    # Initialize progress manager
    progress_manager = ProgressManager(console, "./demo_output")
    
    # Simulate scan start
    console.print("[bold cyan]R.A.I.D Scanner Progress Demo[/bold cyan]")
    console.print("=" * 50)
    
    # Start scan
    progress_manager.start_scan(
        total_checks=265,
        log_payloads=True,
        mode="lab",
        target="https://testsite.com"
    )
    
    # Simulate worker configuration
    progress_manager.log_worker_info(5)
    
    # Simulate discovery
    await asyncio.sleep(1)
    progress_manager.log_discovery_info(45, 128, 12)
    
    # Simulate plugin execution
    plugins = [
        ("SQL Injection", "sqli_heuristic"),
        ("XSS Detection", "xss_heuristic"),
        ("File Exposure", "exposed_files"),
        ("Health Check", "health_header_check"),
        ("Banner Grab", "banner_grab")
    ]
    
    check_number = 1
    for plugin_name, plugin_id in plugins:
        progress_manager.log_plugin_start(plugin_name, check_number)
        
        # Simulate some payloads
        for i in range(3):
            await asyncio.sleep(0.5)
            progress_manager.log_payload(
                "GET",
                f"/test.php?id=1'",
                f"1' OR 1=1--"
            )
            progress_manager.update_progress(plugin_name, f"/test.php?id=1", "", check_number)
            check_number += 1
        
        # Simulate vulnerability found
        if plugin_id == "sqli_heuristic":
            progress_manager.log_vulnerability(
                plugin_name,
                "high",
                "SQL injection vulnerability detected",
                "/test.php?id=1"
            )
        
        await asyncio.sleep(0.5)
    
    # Complete scan
    progress_manager.complete_scan()
    
    # Show final stats
    stats = progress_manager.get_scan_stats()
    console.print(f"\n[bold green]Demo completed![/bold green]")
    console.print(f"Final stats: {stats}")

if __name__ == "__main__":
    asyncio.run(demo_progress_manager())
