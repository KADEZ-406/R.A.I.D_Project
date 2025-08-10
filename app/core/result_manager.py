"""
Result Manager for R.A.I.D Scanner
Handles storage, processing, and reporting of scan findings
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template

from .model import Finding


class ResultManager:
    """Manages scan results, findings storage, and report generation."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        # Create subdirectories
        (self.output_dir / "json").mkdir(exist_ok=True)
        (self.output_dir / "html").mkdir(exist_ok=True)
        (self.output_dir / "raw").mkdir(exist_ok=True)
    
    async def save_findings(self, findings: List[Finding]) -> str:
        """Save findings to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"findings_{timestamp}.json"
        filepath = self.output_dir / "json" / filename
        
        # Convert findings to serializable format
        findings_data = []
        for finding in findings:
            finding_dict = {
                "id": finding.id,
                "name": finding.name,
                "plugin": finding.plugin,
                "target": finding.target,
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
                "evidence": finding.evidence,
                "indicators": finding.indicators,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "timestamp": finding.timestamp,
                "proof_mode": finding.proof_mode,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "references": finding.references,
            }
            findings_data.append(finding_dict)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "total_findings": len(findings),
                    "tool": "R.A.I.D Scanner v1.0"
                },
                "findings": findings_data
            }, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Findings saved to: {filepath}")
        return str(filepath)
    
    async def save_raw_response(self, 
                              response_data: Dict[str, Any], 
                              identifier: str) -> str:
        """Save raw HTTP response data."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"response_{identifier}_{timestamp}.json"
        filepath = self.output_dir / "raw" / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def get_findings_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary statistics for findings."""
        summary = {
            "total": len(findings),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_plugin": {},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
            "unique_targets": set(),
            "unique_endpoints": set()
        }
        
        for finding in findings:
            # Count by severity
            summary["by_severity"][finding.severity] += 1
            
            # Count by plugin
            plugin = finding.plugin
            summary["by_plugin"][plugin] = summary["by_plugin"].get(plugin, 0) + 1
            
            # Count by confidence level
            if finding.confidence >= 70:
                summary["by_confidence"]["high"] += 1
            elif finding.confidence >= 40:
                summary["by_confidence"]["medium"] += 1
            else:
                summary["by_confidence"]["low"] += 1
            
            # Track unique targets and endpoints
            summary["unique_targets"].add(finding.target)
            summary["unique_endpoints"].add(finding.endpoint)
        
        # Convert sets to counts
        summary["unique_targets"] = len(summary["unique_targets"])
        summary["unique_endpoints"] = len(summary["unique_endpoints"])
        
        return summary
    
    async def generate_html_report(self, 
                                 findings: List[Finding], 
                                 scan_stats: Dict[str, Any]) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        filepath = self.output_dir / "html" / filename
        
        # Get summary
        summary = self.get_findings_summary(findings)
        
        # HTML template
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>R.A.I.D Security Scan Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .ascii-logo { font-family: monospace; font-size: 10px; white-space: pre; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .finding { background: white; margin: 10px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #ccc; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .info { border-left-color: #1976d2; }
        .severity-badge { padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; }
        .confidence { font-weight: bold; }
        .evidence { background: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; font-size: 12px; }
        .recommendation { background: #e8f5e8; padding: 10px; border-radius: 4px; margin-top: 10px; }
        .disclaimer { background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #ffeaa7; }
        .lab-notice { background: #d4edda; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="header">
        <div class="ascii-logo">


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

            KADEZ-406  |  R.A.I.D  — Security Scan Report
        </div>
        <h1>Security Assessment Report</h1>
        <p>Generated on {{ scan_date }} | Mode: {{ scan_mode }}</p>
    </div>

    <div class="disclaimer">
        <h3>⚠️ Important Notice</h3>
        <p>This report contains security findings from an authorized assessment. These findings should only be used for remediation purposes on systems you own or have explicit permission to test. Unauthorized use of this information is illegal and unethical.</p>
    </div>

    {% if scan_mode == 'lab' %}
    <div class="lab-notice">
        <h3>🧪 Lab Mode Report</h3>
        <p>This scan was performed in lab mode against containerized vulnerable applications. Findings may include techniques that should only be tested in controlled environments.</p>
    </div>
    {% endif %}

    <div class="summary">
        <div class="card">
            <h3>Scan Summary</h3>
            <p><strong>Total Findings:</strong> {{ summary.total }}</p>
            <p><strong>Unique Targets:</strong> {{ summary.unique_targets }}</p>
            <p><strong>Unique Endpoints:</strong> {{ summary.unique_endpoints }}</p>
            <p><strong>Duration:</strong> {{ scan_duration }}</p>
        </div>
        
        <div class="card">
            <h3>Findings by Severity</h3>
            <p>🔴 Critical: {{ summary.by_severity.critical }}</p>
            <p>🟠 High: {{ summary.by_severity.high }}</p>
            <p>🟡 Medium: {{ summary.by_severity.medium }}</p>
            <p>🟢 Low: {{ summary.by_severity.low }}</p>
            <p>ℹ️ Info: {{ summary.by_severity.info }}</p>
        </div>
        
        <div class="card">
            <h3>Confidence Distribution</h3>
            <p><strong>High (70-100%):</strong> {{ summary.by_confidence.high }}</p>
            <p><strong>Medium (40-69%):</strong> {{ summary.by_confidence.medium }}</p>
            <p><strong>Low (0-39%):</strong> {{ summary.by_confidence.low }}</p>
        </div>
    </div>

    <h2>Detailed Findings</h2>
    
    {% for finding in findings %}
    <div class="finding {{ finding.severity }}">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h3>{{ finding.name }}</h3>
            <span class="severity-badge" style="background-color: {% if finding.severity == 'critical' %}#d32f2f{% elif finding.severity == 'high' %}#f57c00{% elif finding.severity == 'medium' %}#fbc02d{% elif finding.severity == 'low' %}#388e3c{% else %}#1976d2{% endif %};">
                {{ finding.severity.upper() }}
            </span>
        </div>
        
        <p><strong>Target:</strong> {{ finding.target }}</p>
        <p><strong>Endpoint:</strong> {{ finding.endpoint }}</p>
        {% if finding.param %}<p><strong>Parameter:</strong> {{ finding.param }}</p>{% endif %}
        <p><strong>Plugin:</strong> {{ finding.plugin }}</p>
        <p><strong>Confidence:</strong> <span class="confidence">{{ finding.confidence }}%</span></p>
        <p><strong>Found:</strong> {{ finding.timestamp }}</p>
        
        {% if finding.description %}
        <h4>Description</h4>
        <p>{{ finding.description }}</p>
        {% endif %}
        
        <h4>Indicators</h4>
        <p>{{ finding.indicators | join(', ') }}</p>
        
        {% if finding.evidence %}
        <h4>Evidence</h4>
        <div class="evidence">{{ finding.evidence | tojson | safe }}</div>
        {% endif %}
        
        {% if finding.recommendation %}
        <div class="recommendation">
            <h4>Recommendation</h4>
            <p>{{ finding.recommendation }}</p>
        </div>
        {% endif %}
        
        <div class="lab-notice" style="margin-top: 15px; font-size: 12px;">
            <strong>How to reproduce safely in lab:</strong><br>
            1. Set up the Docker lab environment using docker-compose.lab.yml<br>
            2. Configure R.A.I.D in lab mode: <code>python -m app.cli scan --target &lt;lab-target&gt; --mode lab</code><br>
            3. Enable detailed verification with appropriate payload templates<br>
            4. Review findings in a controlled environment before applying to production systems
        </div>
    </div>
    {% endfor %}

    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center;">
        <p><strong>R.A.I.D Scanner v1.0</strong> | KADEZ-406 Team</p>
        <p>This report is for authorized security testing only. Use responsibly and legally.</p>
    </div>
</body>
</html>
        """
        
        # Render template
        template = Template(html_template)
        
        # Format duration
        duration = "Unknown"
        if scan_stats.get("duration_seconds"):
            duration = f"{scan_stats['duration_seconds']:.1f} seconds"
        
        html_content = template.render(
            findings=findings,
            summary=summary,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_mode=scan_stats.get("mode", "unknown"),
            scan_duration=duration
        )
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    async def generate_json_report(self, 
                                 findings: List[Finding], 
                                 scan_stats: Dict[str, Any]) -> str:
        """Generate structured JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.json"
        filepath = self.output_dir / "json" / filename
        
        # Get summary
        summary = self.get_findings_summary(findings)
        
        # Create report structure
        report = {
            "metadata": {
                "tool": "R.A.I.D Scanner",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "scan_mode": scan_stats.get("mode", "unknown"),
                "scan_stats": scan_stats
            },
            "summary": summary,
            "findings": []
        }
        
        # Add findings
        for finding in findings:
            finding_data = {
                "id": finding.id,
                "name": finding.name,
                "plugin": finding.plugin,
                "target": finding.target,
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "timestamp": finding.timestamp,
                "proof_mode": finding.proof_mode,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "indicators": finding.indicators,
                "evidence": finding.evidence,
                "references": finding.references,
                "lab_reproduction": {
                    "docker_command": "docker-compose -f docker/docker-compose.lab.yml up -d",
                    "scan_command": f"python -m app.cli scan --target <lab-target> --mode lab --plugins {finding.plugin}",
                    "note": "Reproduce this finding safely in the provided lab environment"
                }
            }
            report["findings"].append(finding_data)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    async def generate_reports(self, 
                             findings: List[Finding], 
                             scan_stats: Dict[str, Any]) -> Dict[str, str]:
        """Generate all report formats."""
        reports = {}
        
        try:
            # Generate JSON report
            json_report = await self.generate_json_report(findings, scan_stats)
            reports["json"] = json_report
            
            # Generate HTML report
            html_report = await self.generate_html_report(findings, scan_stats)
            reports["html"] = html_report
            
            self.logger.info(f"Generated {len(reports)} reports")
            
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")
        
        return reports
    
    def load_findings(self, filepath: str) -> List[Finding]:
        """Load findings from a JSON file."""
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings_data = data.get("findings", [])
            for finding_dict in findings_data:
                finding = Finding(
                    id=finding_dict["id"],
                    name=finding_dict["name"],
                    plugin=finding_dict["plugin"],
                    target=finding_dict["target"],
                    endpoint=finding_dict["endpoint"],
                    parameter=finding_dict.get("parameter"),
                    evidence=finding_dict.get("evidence", {}),
                    indicators=finding_dict.get("indicators", []),
                    severity=finding_dict.get("severity", "info"),
                    confidence=float(finding_dict.get("confidence", 0.0)),
                    timestamp=finding_dict.get("timestamp"),
                    proof_mode=finding_dict.get("proof_mode", "safe"),
                    description=finding_dict.get("description", ""),
                    recommendation=finding_dict.get("recommendation", ""),
                    references=finding_dict.get("references", []),
                )
                findings.append(finding)
            
            self.logger.info(f"Loaded {len(findings)} findings from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error loading findings from {filepath}: {e}")
        
        return findings 