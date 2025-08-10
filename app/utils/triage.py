"""
False Positive Triage and Human-in-the-Loop Management
Provides CLI and programmatic interface for finding review and classification
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.core.plugin_loader import Finding
from app.utils.logger import security_logger


class TriageStatus:
    """Constants for triage status values."""
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class FindingTriageManager:
    """Manages finding triage, review status, and human feedback."""
    
    def __init__(self, triage_db_path: str = "reports/triage_db.json"):
        self.triage_db_path = Path(triage_db_path)
        self.triage_db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.triage_data = self.load_triage_data()
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Audit log for all triage actions
        self.audit_log_path = Path("logs/triage_audit.log")
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    
    def load_triage_data(self) -> Dict:
        """Load existing triage data from disk."""
        if not self.triage_db_path.exists():
            return {"findings": {}, "metadata": {"version": "1.0", "created": datetime.now().isoformat()}}
        
        try:
            with open(self.triage_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load triage data: {e}")
            return {"findings": {}, "metadata": {"version": "1.0", "created": datetime.now().isoformat()}}
    
    def save_triage_data(self):
        """Save triage data to disk."""
        try:
            self.triage_data["metadata"]["last_updated"] = datetime.now().isoformat()
            with open(self.triage_db_path, 'w') as f:
                json.dump(self.triage_data, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save triage data: {e}")
    
    def log_audit_event(self, action: str, finding_id: str, details: Dict = None):
        """Log triage actions for audit trail."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "finding_id": finding_id,
            "details": details or {},
            "user": "system"  # Could be extended to track actual users
        }
        
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(audit_entry) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
        
        # Also log to security logger
        security_logger.log_security_event(
            event_type="finding_triage",
            action=action,
            finding_id=finding_id,
            details=details
        )
    
    def update_finding_status(self, finding_id: str, status: str, reason: str = "", 
                            confidence_override: Optional[int] = None) -> bool:
        """Update the triage status of a finding."""
        
        if status not in [TriageStatus.NEEDS_REVIEW, TriageStatus.CONFIRMED, 
                         TriageStatus.FALSE_POSITIVE, TriageStatus.INVESTIGATING, 
                         TriageStatus.RESOLVED]:
            raise ValueError(f"Invalid status: {status}")
        
        # Get existing triage data for this finding
        existing_data = self.triage_data["findings"].get(finding_id, {})
        
        # Update triage record
        triage_record = {
            "finding_id": finding_id,
            "status": status,
            "reason": reason,
            "updated_at": datetime.now().isoformat(),
            "confidence_override": confidence_override,
            "review_history": existing_data.get("review_history", [])
        }
        
        # Add this update to history
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "old_status": existing_data.get("status", "unknown"),
            "new_status": status,
            "reason": reason,
            "confidence_override": confidence_override
        }
        triage_record["review_history"].append(history_entry)
        
        # Save to database
        self.triage_data["findings"][finding_id] = triage_record
        self.save_triage_data()
        
        # Log audit event
        self.log_audit_event(
            action="status_update",
            finding_id=finding_id,
            details={
                "new_status": status,
                "reason": reason,
                "confidence_override": confidence_override
            }
        )
        
        self.logger.info(f"Updated finding {finding_id} status to {status}")
        return True
    
    def get_finding_status(self, finding_id: str) -> Optional[Dict]:
        """Get triage status for a finding."""
        return self.triage_data["findings"].get(finding_id)
    
    def auto_triage_finding(self, finding: Finding, ai_classification: str, 
                          ai_confidence: float) -> str:
        """Automatically triage finding based on AI classification and rules."""
        
        # Auto-triage rules
        if ai_classification == "LIKELY" and ai_confidence >= 0.8 and finding.confidence >= 80:
            status = TriageStatus.CONFIRMED
            reason = f"Auto-confirmed: High AI confidence ({ai_confidence:.2f}) and scanner confidence ({finding.confidence})"
        
        elif ai_classification == "UNLIKELY" and ai_confidence <= 0.3 and finding.confidence <= 40:
            status = TriageStatus.FALSE_POSITIVE
            reason = f"Auto-rejected: Low AI confidence ({ai_confidence:.2f}) and scanner confidence ({finding.confidence})"
        
        else:
            status = TriageStatus.NEEDS_REVIEW
            reason = f"Requires manual review: AI={ai_classification} ({ai_confidence:.2f}), Scanner={finding.confidence}"
        
        # Update status
        self.update_finding_status(finding.id, status, reason)
        
        return status
    
    def get_findings_for_review(self, status: str = TriageStatus.NEEDS_REVIEW) -> List[Dict]:
        """Get findings that need manual review."""
        findings_for_review = []
        
        for finding_id, triage_data in self.triage_data["findings"].items():
            if triage_data.get("status") == status:
                findings_for_review.append({
                    "finding_id": finding_id,
                    "triage_data": triage_data
                })
        
        # Sort by update time (oldest first)
        findings_for_review.sort(
            key=lambda x: x["triage_data"].get("updated_at", "")
        )
        
        return findings_for_review
    
    def display_finding_for_review(self, finding: Finding, ai_analysis: Dict = None):
        """Display finding information for manual review."""
        
        # Create finding summary panel
        finding_info = f"""
[bold]Finding ID:[/bold] {finding.id}
[bold]Name:[/bold] {finding.name}
[bold]Plugin:[/bold] {finding.plugin}
[bold]Severity:[/bold] {finding.severity}
[bold]Confidence:[/bold] {finding.confidence}%
[bold]Target:[/bold] {finding.target}
[bold]Endpoint:[/bold] {finding.endpoint}
[bold]Parameter:[/bold] {finding.param or 'N/A'}
[bold]Indicators:[/bold] {', '.join(finding.indicators)}
"""
        
        self.console.print(Panel(finding_info, title="Finding Details", border_style="blue"))
        
        # Display AI analysis if available
        if ai_analysis:
            ai_info = f"""
[bold]Classification:[/bold] {ai_analysis['ai_triage']['classification']}
[bold]AI Confidence:[/bold] {ai_analysis['ai_triage']['confidence']:.3f}
[bold]Reasoning:[/bold] {ai_analysis['ai_triage']['reasoning']}
"""
            self.console.print(Panel(ai_info, title="AI Analysis", border_style="green"))
        
        # Display evidence
        if finding.evidence:
            evidence_table = Table(title="Evidence")
            evidence_table.add_column("Key", style="cyan")
            evidence_table.add_column("Value", style="white")
            
            for key, value in finding.evidence.items():
                if isinstance(value, (dict, list)):
                    value_str = json.dumps(value, indent=2)[:200] + "..." if len(str(value)) > 200 else json.dumps(value, indent=2)
                else:
                    value_str = str(value)[:200] + "..." if len(str(value)) > 200 else str(value)
                
                evidence_table.add_row(key, value_str)
            
            self.console.print(evidence_table)
        
        # Display current triage status
        current_status = self.get_finding_status(finding.id)
        if current_status:
            status_info = f"""
[bold]Current Status:[/bold] {current_status.get('status', 'Unknown')}
[bold]Last Updated:[/bold] {current_status.get('updated_at', 'Unknown')}
[bold]Reason:[/bold] {current_status.get('reason', 'No reason provided')}
"""
            self.console.print(Panel(status_info, title="Triage Status", border_style="yellow"))
    
    def interactive_review(self, finding: Finding, ai_analysis: Dict = None) -> str:
        """Interactive review interface for a finding."""
        
        self.display_finding_for_review(finding, ai_analysis)
        
        # Review options
        self.console.print("\n[bold]Review Options:[/bold]")
        self.console.print("1. [green]CONFIRM[/green] - True positive, valid security issue")
        self.console.print("2. [red]FALSE_POSITIVE[/red] - False positive, not a real issue")
        self.console.print("3. [yellow]INVESTIGATING[/yellow] - Needs further investigation")
        self.console.print("4. [blue]SKIP[/blue] - Skip for now")
        
        while True:
            choice = self.console.input("\nEnter your choice (1-4): ").strip()
            
            if choice == "1":
                reason = self.console.input("Reason for confirmation (optional): ").strip()
                confidence_override = self.console.input("Override confidence (0-100, optional): ").strip()
                
                confidence_val = None
                if confidence_override:
                    try:
                        confidence_val = int(confidence_override)
                        if not 0 <= confidence_val <= 100:
                            self.console.print("[red]Invalid confidence value. Must be 0-100.[/red]")
                            continue
                    except ValueError:
                        self.console.print("[red]Invalid confidence value. Must be a number.[/red]")
                        continue
                
                self.update_finding_status(finding.id, TriageStatus.CONFIRMED, reason, confidence_val)
                self.console.print("[green]✓ Finding confirmed as true positive[/green]")
                return TriageStatus.CONFIRMED
            
            elif choice == "2":
                reason = self.console.input("Reason for false positive classification: ").strip()
                if not reason:
                    self.console.print("[red]Reason is required for false positive classification.[/red]")
                    continue
                
                self.update_finding_status(finding.id, TriageStatus.FALSE_POSITIVE, reason)
                self.console.print("[red]✓ Finding marked as false positive[/red]")
                return TriageStatus.FALSE_POSITIVE
            
            elif choice == "3":
                reason = self.console.input("Investigation notes: ").strip()
                self.update_finding_status(finding.id, TriageStatus.INVESTIGATING, reason)
                self.console.print("[yellow]✓ Finding marked for investigation[/yellow]")
                return TriageStatus.INVESTIGATING
            
            elif choice == "4":
                self.console.print("[blue]Skipped review[/blue]")
                return "SKIPPED"
            
            else:
                self.console.print("[red]Invalid choice. Please enter 1-4.[/red]")
    
    def batch_review_session(self, max_findings: int = 10) -> Dict:
        """Run a batch review session for findings needing review."""
        findings_to_review = self.get_findings_for_review()
        
        if not findings_to_review:
            self.console.print("[green]No findings need review at this time.[/green]")
            return {"reviewed": 0, "total": 0}
        
        self.console.print(f"[blue]Found {len(findings_to_review)} findings needing review[/blue]")
        
        reviewed_count = 0
        results = {
            "reviewed": 0,
            "confirmed": 0,
            "false_positives": 0,
            "investigating": 0,
            "skipped": 0
        }
        
        for finding_data in findings_to_review[:max_findings]:
            finding_id = finding_data["finding_id"]
            
            # Load finding details (would need to be passed in or loaded from report)
            self.console.print(f"\n{'='*70}")
            self.console.print(f"[bold]Reviewing Finding {reviewed_count + 1}/{min(len(findings_to_review), max_findings)}[/bold]")
            self.console.print(f"[bold]Finding ID:[/bold] {finding_id}")
            
            # For now, just show the basic info we have
            triage_data = finding_data["triage_data"]
            self.console.print(f"[bold]Current Status:[/bold] {triage_data.get('status')}")
            self.console.print(f"[bold]Updated:[/bold] {triage_data.get('updated_at')}")
            
            # Ask for action
            self.console.print("\n[bold]Quick Actions:[/bold]")
            self.console.print("1. Mark as [green]CONFIRMED[/green]")
            self.console.print("2. Mark as [red]FALSE_POSITIVE[/red]")
            self.console.print("3. Mark as [yellow]INVESTIGATING[/yellow]")
            self.console.print("4. Skip")
            self.console.print("5. Stop review session")
            
            choice = self.console.input("Enter choice (1-5): ").strip()
            
            if choice == "1":
                reason = self.console.input("Confirmation reason: ").strip()
                self.update_finding_status(finding_id, TriageStatus.CONFIRMED, reason)
                results["confirmed"] += 1
            elif choice == "2":
                reason = self.console.input("False positive reason: ").strip()
                self.update_finding_status(finding_id, TriageStatus.FALSE_POSITIVE, reason)
                results["false_positives"] += 1
            elif choice == "3":
                reason = self.console.input("Investigation notes: ").strip()
                self.update_finding_status(finding_id, TriageStatus.INVESTIGATING, reason)
                results["investigating"] += 1
            elif choice == "4":
                results["skipped"] += 1
                continue
            elif choice == "5":
                break
            else:
                self.console.print("[red]Invalid choice, skipping.[/red]")
                results["skipped"] += 1
                continue
            
            reviewed_count += 1
            results["reviewed"] += 1
        
        # Summary
        self.console.print(f"\n[bold]Review Session Complete![/bold]")
        self.console.print(f"Reviewed: {results['reviewed']}")
        self.console.print(f"Confirmed: {results['confirmed']}")
        self.console.print(f"False Positives: {results['false_positives']}")
        self.console.print(f"Investigating: {results['investigating']}")
        self.console.print(f"Skipped: {results['skipped']}")
        
        return results
    
    def get_triage_statistics(self) -> Dict:
        """Get statistics about triage status across all findings."""
        stats = {
            "total_findings": len(self.triage_data["findings"]),
            "by_status": {},
            "confidence_override_count": 0,
            "review_queue_size": 0
        }
        
        for finding_data in self.triage_data["findings"].values():
            status = finding_data.get("status", "unknown")
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            
            if finding_data.get("confidence_override") is not None:
                stats["confidence_override_count"] += 1
            
            if status == TriageStatus.NEEDS_REVIEW:
                stats["review_queue_size"] += 1
        
        return stats
    
    def export_triage_report(self, output_file: str = None) -> str:
        """Export triage data to a comprehensive report."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/triage_report_{timestamp}.json"
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate comprehensive report
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(self.triage_data["findings"]),
                "database_version": self.triage_data["metadata"].get("version"),
                "database_created": self.triage_data["metadata"].get("created")
            },
            "statistics": self.get_triage_statistics(),
            "findings": self.triage_data["findings"],
            "analysis": {
                "false_positive_rate": self._calculate_false_positive_rate(),
                "confirmation_rate": self._calculate_confirmation_rate(),
                "common_false_positive_reasons": self._get_common_fp_reasons(),
                "confidence_override_impact": self._analyze_confidence_overrides()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Triage report exported to {output_path}")
        return str(output_path)
    
    def _calculate_false_positive_rate(self) -> float:
        """Calculate false positive rate."""
        total_reviewed = 0
        false_positives = 0
        
        for finding_data in self.triage_data["findings"].values():
            status = finding_data.get("status")
            if status in [TriageStatus.CONFIRMED, TriageStatus.FALSE_POSITIVE]:
                total_reviewed += 1
                if status == TriageStatus.FALSE_POSITIVE:
                    false_positives += 1
        
        return false_positives / total_reviewed if total_reviewed > 0 else 0.0
    
    def _calculate_confirmation_rate(self) -> float:
        """Calculate confirmation rate."""
        total_reviewed = 0
        confirmed = 0
        
        for finding_data in self.triage_data["findings"].values():
            status = finding_data.get("status")
            if status in [TriageStatus.CONFIRMED, TriageStatus.FALSE_POSITIVE]:
                total_reviewed += 1
                if status == TriageStatus.CONFIRMED:
                    confirmed += 1
        
        return confirmed / total_reviewed if total_reviewed > 0 else 0.0
    
    def _get_common_fp_reasons(self) -> List[Dict]:
        """Get most common false positive reasons."""
        fp_reasons = {}
        
        for finding_data in self.triage_data["findings"].values():
            if finding_data.get("status") == TriageStatus.FALSE_POSITIVE:
                reason = finding_data.get("reason", "No reason provided")
                fp_reasons[reason] = fp_reasons.get(reason, 0) + 1
        
        # Sort by frequency
        common_reasons = [
            {"reason": reason, "count": count}
            for reason, count in sorted(fp_reasons.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return common_reasons[:10]  # Top 10
    
    def _analyze_confidence_overrides(self) -> Dict:
        """Analyze the impact of confidence overrides."""
        overrides = []
        
        for finding_data in self.triage_data["findings"].values():
            if finding_data.get("confidence_override") is not None:
                overrides.append({
                    "override_value": finding_data["confidence_override"],
                    "status": finding_data.get("status"),
                    "reason": finding_data.get("reason", "")
                })
        
        analysis = {
            "total_overrides": len(overrides),
            "override_distribution": {},
            "impact_on_classification": {}
        }
        
        # Analyze override values
        for override_data in overrides:
            value_range = self._get_confidence_range(override_data["override_value"])
            analysis["override_distribution"][value_range] = analysis["override_distribution"].get(value_range, 0) + 1
            
            status = override_data["status"]
            analysis["impact_on_classification"][status] = analysis["impact_on_classification"].get(status, 0) + 1
        
        return analysis
    
    def _get_confidence_range(self, confidence: int) -> str:
        """Get confidence range bucket."""
        if confidence >= 80:
            return "high (80-100)"
        elif confidence >= 60:
            return "medium (60-79)"
        elif confidence >= 40:
            return "low (40-59)"
        else:
            return "very_low (0-39)"


# CLI Commands for triage management
@click.group()
def triage():
    """Manage finding triage and false positive handling."""
    pass


@triage.command()
@click.argument('finding_id')
@click.option('--status', type=click.Choice([
    TriageStatus.CONFIRMED, 
    TriageStatus.FALSE_POSITIVE, 
    TriageStatus.INVESTIGATING,
    TriageStatus.RESOLVED
]), required=True, help='New triage status')
@click.option('--reason', required=True, help='Reason for status change')
@click.option('--confidence', type=int, help='Override confidence score (0-100)')
def update(finding_id, status, reason, confidence):
    """Update the triage status of a finding."""
    manager = FindingTriageManager()
    
    try:
        manager.update_finding_status(finding_id, status, reason, confidence)
        click.echo(f"✓ Updated finding {finding_id} to {status}")
    except Exception as e:
        click.echo(f"✗ Error updating finding: {e}", err=True)


@triage.command()
@click.option('--max-findings', default=10, help='Maximum findings to review')
def review(max_findings):
    """Start interactive review session."""
    manager = FindingTriageManager()
    results = manager.batch_review_session(max_findings)
    click.echo(f"Review session completed. Reviewed {results['reviewed']} findings.")


@triage.command()
def stats():
    """Show triage statistics."""
    manager = FindingTriageManager()
    stats = manager.get_triage_statistics()
    
    click.echo("Triage Statistics:")
    click.echo(f"Total Findings: {stats['total_findings']}")
    click.echo(f"Review Queue: {stats['review_queue_size']}")
    click.echo("\nBy Status:")
    for status, count in stats['by_status'].items():
        click.echo(f"  {status}: {count}")


@triage.command()
@click.option('--output', help='Output file path')
def export(output):
    """Export triage report."""
    manager = FindingTriageManager()
    report_path = manager.export_triage_report(output)
    click.echo(f"✓ Triage report exported to {report_path}")


if __name__ == '__main__':
    triage() 