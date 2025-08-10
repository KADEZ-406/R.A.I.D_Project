"""
Report Generation Utilities for R.A.I.D Scanner
Additional report formats and utilities
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from tabulate import tabulate


class ReportGenerator:
    """Generate various report formats from scan findings."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def generate_csv_report(self, findings: List[Dict[str, Any]], 
                          filename: Optional[str] = None) -> str:
        """Generate CSV report from findings."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        # Define CSV columns
        columns = [
            'ID', 'Name', 'Plugin', 'Target', 'Endpoint', 'Parameter',
            'Severity', 'Confidence', 'Timestamp', 'Mode', 'Description',
            'Indicators', 'Evidence_Summary'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(columns)
            
            for finding in findings:
                # Extract evidence summary
                evidence = finding.get('evidence', {})
                evidence_summary = '; '.join([f"{k}:{v}" for k, v in evidence.items() if isinstance(v, (str, int, float))])
                
                row = [
                    finding.get('id', ''),
                    finding.get('name', ''),
                    finding.get('plugin', ''),
                    finding.get('target', ''),
                    finding.get('endpoint', ''),
                    finding.get('param', ''),
                    finding.get('severity', ''),
                    finding.get('confidence', 0),
                    finding.get('timestamp', ''),
                    finding.get('proof_mode', ''),
                    finding.get('description', ''),
                    '; '.join(finding.get('indicators', [])),
                    evidence_summary
                ]
                writer.writerow(row)
        
        self.logger.info(f"CSV report generated: {filepath}")
        return str(filepath)
    
    def generate_summary_report(self, findings: List[Dict[str, Any]], 
                              scan_stats: Dict[str, Any],
                              filename: Optional[str] = None) -> str:
        """Generate executive summary report."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"summary_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        # Calculate summary statistics
        total_findings = len(findings)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        plugin_counts = {}
        target_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            plugin = finding.get('plugin', 'unknown')
            plugin_counts[plugin] = plugin_counts.get(plugin, 0) + 1
            
            target = finding.get('target', 'unknown')
            target_counts[target] = target_counts.get(target, 0) + 1
        
        # Generate summary content
        content = []
        content.append("=" * 70)
        content.append("R.A.I.D SECURITY SCAN SUMMARY REPORT")
        content.append("=" * 70)
        content.append("")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Scan Mode: {scan_stats.get('mode', 'unknown')}")
        content.append(f"Duration: {scan_stats.get('duration_seconds', 0):.1f} seconds")
        content.append("")
        
        content.append("SCAN OVERVIEW")
        content.append("-" * 20)
        content.append(f"Total Findings: {total_findings}")
        content.append(f"Unique Targets: {len(target_counts)}")
        content.append(f"Plugins Used: {len(plugin_counts)}")
        content.append("")
        
        content.append("FINDINGS BY SEVERITY")
        content.append("-" * 25)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            content.append(f"{severity.capitalize():>8}: {count}")
        content.append("")
        
        if plugin_counts:
            content.append("FINDINGS BY PLUGIN")
            content.append("-" * 20)
            sorted_plugins = sorted(plugin_counts.items(), key=lambda x: x[1], reverse=True)
            for plugin, count in sorted_plugins[:10]:  # Top 10
                content.append(f"{plugin:>20}: {count}")
            content.append("")
        
        if target_counts:
            content.append("FINDINGS BY TARGET")
            content.append("-" * 20)
            sorted_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)
            for target, count in sorted_targets[:5]:  # Top 5
                content.append(f"{target:>30}: {count}")
            content.append("")
        
        # High-priority findings
        high_priority = [f for f in findings if f.get('severity') in ['critical', 'high']]
        if high_priority:
            content.append("HIGH PRIORITY FINDINGS")
            content.append("-" * 25)
            for finding in high_priority[:10]:  # Top 10
                content.append(f"• {finding.get('name', 'Unknown')} [{finding.get('severity', 'unknown')}]")
                content.append(f"  Target: {finding.get('target', 'unknown')}")
                content.append(f"  Confidence: {finding.get('confidence', 0)}%")
                content.append("")
        
        content.append("RECOMMENDATIONS")
        content.append("-" * 15)
        content.append("1. Review all CRITICAL and HIGH severity findings immediately")
        content.append("2. Validate findings in a controlled lab environment")
        content.append("3. Apply security patches for confirmed vulnerabilities")
        content.append("4. Implement additional security controls as needed")
        content.append("5. Re-scan after remediation to verify fixes")
        content.append("")
        
        content.append("LEGAL NOTICE")
        content.append("-" * 12)
        content.append("This report contains security findings from an authorized assessment.")
        content.append("Use this information only for remediation purposes on systems you")
        content.append("own or have explicit permission to test. Unauthorized use is illegal.")
        content.append("")
        content.append("=" * 70)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        self.logger.info(f"Summary report generated: {filepath}")
        return str(filepath)
    
    def generate_console_summary(self, findings: List[Dict[str, Any]], 
                               scan_stats: Dict[str, Any]) -> str:
        """Generate console-friendly summary."""
        total_findings = len(findings)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Create summary table
        severity_data = []
        severity_colors = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
            'low': '🟢', 'info': 'ℹ️'
        }
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            icon = severity_colors.get(severity, '')
            severity_data.append([f"{icon} {severity.capitalize()}", count])
        
        summary_table = tabulate(
            severity_data,
            headers=['Severity', 'Count'],
            tablefmt='grid'
        )
        
        duration = scan_stats.get('duration_seconds', 0)
        mode = scan_stats.get('mode', 'unknown')
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                           R.A.I.D SCAN RESULTS                      ║
╚══════════════════════════════════════════════════════════════════════╝

📊 Scan Summary:
   • Total Findings: {total_findings}
   • Scan Mode: {mode}
   • Duration: {duration:.1f} seconds

{summary_table}

💡 Next Steps:
   1. Review detailed HTML/JSON reports
   2. Prioritize CRITICAL and HIGH findings
   3. Test fixes in lab environment
   4. Re-scan after remediation
"""
        return summary
    
    def generate_plugin_performance_report(self, scan_stats: Dict[str, Any],
                                         filename: Optional[str] = None) -> str:
        """Generate plugin performance and statistics report."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"plugin_stats_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        plugin_stats = scan_stats.get('plugin_stats', {})
        
        content = []
        content.append("R.A.I.D PLUGIN PERFORMANCE REPORT")
        content.append("=" * 40)
        content.append("")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        content.append("PLUGIN OVERVIEW")
        content.append("-" * 15)
        content.append(f"Total Plugins: {plugin_stats.get('total_plugins', 0)}")
        content.append("")
        
        # Plugins by mode
        by_mode = plugin_stats.get('by_mode', {})
        if by_mode:
            content.append("PLUGINS BY MODE")
            content.append("-" * 15)
            for mode, count in by_mode.items():
                content.append(f"{mode:>8}: {count}")
            content.append("")
        
        # Plugins by category
        by_category = plugin_stats.get('by_category', {})
        if by_category:
            content.append("PLUGINS BY CATEGORY")
            content.append("-" * 20)
            sorted_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
            for category, count in sorted_categories:
                content.append(f"{category:>15}: {count}")
            content.append("")
        
        # Plugins by severity
        by_severity = plugin_stats.get('by_severity', {})
        if by_severity:
            content.append("PLUGINS BY SEVERITY")
            content.append("-" * 19)
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = by_severity.get(severity, 0)
                content.append(f"{severity:>8}: {count}")
            content.append("")
        
        content.append("PERFORMANCE NOTES")
        content.append("-" * 17)
        content.append("• Plugin execution times not tracked in this version")
        content.append("• Consider implementing timing metrics for optimization")
        content.append("• Monitor plugin error rates and success rates")
        content.append("")
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        self.logger.info(f"Plugin performance report generated: {filepath}")
        return str(filepath)
    
    def generate_finding_details_report(self, findings: List[Dict[str, Any]],
                                      filename: Optional[str] = None) -> str:
        """Generate detailed findings report in text format."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_detailed_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        content = []
        content.append("R.A.I.D DETAILED FINDINGS REPORT")
        content.append("=" * 40)
        content.append("")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append(f"Total Findings: {len(findings)}")
        content.append("")
        
        # Sort findings by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: (severity_order.get(x.get('severity', 'info'), 4), 
                          -x.get('confidence', 0))
        )
        
        for i, finding in enumerate(sorted_findings, 1):
            content.append(f"FINDING #{i:03d}")
            content.append("-" * 15)
            content.append(f"Name: {finding.get('name', 'Unknown')}")
            content.append(f"Severity: {finding.get('severity', 'unknown').upper()}")
            content.append(f"Confidence: {finding.get('confidence', 0)}%")
            content.append(f"Plugin: {finding.get('plugin', 'unknown')}")
            content.append(f"Target: {finding.get('target', 'unknown')}")
            content.append(f"Endpoint: {finding.get('endpoint', 'unknown')}")
            
            if finding.get('param'):
                content.append(f"Parameter: {finding.get('param')}")
            
            content.append(f"Timestamp: {finding.get('timestamp', 'unknown')}")
            content.append(f"Mode: {finding.get('proof_mode', 'unknown')}")
            content.append("")
            
            if finding.get('description'):
                content.append("Description:")
                content.append(finding.get('description'))
                content.append("")
            
            indicators = finding.get('indicators', [])
            if indicators:
                content.append(f"Indicators: {', '.join(indicators)}")
                content.append("")
            
            evidence = finding.get('evidence', {})
            if evidence:
                content.append("Evidence:")
                for key, value in evidence.items():
                    if isinstance(value, (str, int, float)):
                        content.append(f"  {key}: {value}")
                    else:
                        content.append(f"  {key}: {str(value)[:100]}...")
                content.append("")
            
            if finding.get('recommendation'):
                content.append("Recommendation:")
                content.append(finding.get('recommendation'))
                content.append("")
            
            content.append("Lab Reproduction:")
            content.append("1. Start lab environment: docker-compose -f docker/docker-compose.lab.yml up -d")
            content.append(f"2. Run plugin: python -m app.cli scan --target <lab-target> --mode lab --plugins {finding.get('plugin', 'unknown')}")
            content.append("3. Review results in controlled environment")
            content.append("")
            content.append("=" * 70)
            content.append("")
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        self.logger.info(f"Detailed findings report generated: {filepath}")
        return str(filepath)
    
    def export_for_external_tools(self, findings: List[Dict[str, Any]],
                                 tool_format: str = "burp") -> str:
        """Export findings in format compatible with external tools."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if tool_format.lower() == "burp":
            # Burp Suite compatible format
            filename = f"burp_export_{timestamp}.xml"
            filepath = self.output_dir / filename
            
            # Simple XML format for Burp
            xml_content = ['<?xml version="1.0" encoding="UTF-8"?>']
            xml_content.append('<issues>')
            
            for finding in findings:
                xml_content.append('  <issue>')
                xml_content.append(f'    <name>{finding.get("name", "")}</name>')
                xml_content.append(f'    <host>{finding.get("target", "")}</host>')
                xml_content.append(f'    <path>{finding.get("endpoint", "")}</path>')
                xml_content.append(f'    <severity>{finding.get("severity", "").upper()}</severity>')
                xml_content.append(f'    <confidence>{finding.get("confidence", 0)}</confidence>')
                xml_content.append(f'    <description>{finding.get("description", "")}</description>')
                xml_content.append('  </issue>')
            
            xml_content.append('</issues>')
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(xml_content))
        
        elif tool_format.lower() == "nessus":
            # Nessus-like format
            filename = f"nessus_export_{timestamp}.json"
            filepath = self.output_dir / filename
            
            nessus_format = {
                "scan": {
                    "uuid": f"raid-{timestamp}",
                    "name": "R.A.I.D Security Scan",
                    "creation_date": datetime.now().isoformat(),
                    "vulnerabilities": []
                }
            }
            
            for finding in findings:
                vuln = {
                    "plugin_id": finding.get('id', ''),
                    "plugin_name": finding.get('name', ''),
                    "severity": finding.get('severity', ''),
                    "description": finding.get('description', ''),
                    "solution": finding.get('recommendation', ''),
                    "hosts": [finding.get('target', '')]
                }
                nessus_format["scan"]["vulnerabilities"].append(vuln)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(nessus_format, f, indent=2)
        
        else:
            # Default JSON format
            filename = f"generic_export_{timestamp}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, default=str)
        
        self.logger.info(f"External tool export generated: {filepath}")
        return str(filepath) 