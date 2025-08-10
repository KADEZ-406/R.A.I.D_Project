#!/usr/bin/env python3
"""
R.A.I.D Detection Evaluation Harness
Automated evaluation of detection accuracy against synthetic lab tests
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import click
import requests
import yaml
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from tabulate import tabulate

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.engine import ScanEngine
from app.utils.logger import setup_logger


class EvaluationHarness:
    """Evaluation harness for measuring detection accuracy."""
    
    def __init__(self, config_file: str = "docker/lab_tests/expected_results.yaml"):
        self.config_file = Path(config_file)
        self.config = None
        self.results = {}
        self.logger = setup_logger(verbose=True, logger_name="evaluation")
        
    def load_config(self):
        """Load expected results configuration."""
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            self.logger.info(f"Loaded evaluation config from {self.config_file}")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise
    
    async def check_lab_environment(self) -> bool:
        """Check if lab environment is running and accessible."""
        self.logger.info("Checking lab environment health...")
        
        if not self.config:
            self.load_config()
        
        health_checks = self.config.get("environment_requirements", {}).get("health_checks", [])
        
        for check in health_checks:
            url = check["url"]
            expected_status = check["expected_status"]
            
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == expected_status:
                    self.logger.info(f"✓ Health check passed: {url}")
                else:
                    self.logger.error(f"✗ Health check failed: {url} (status: {response.status_code})")
                    return False
            except Exception as e:
                self.logger.error(f"✗ Health check failed: {url} ({e})")
                return False
        
        return True
    
    async def run_evaluation(self, plugins: List[str] = None) -> Dict:
        """Run complete evaluation against lab tests."""
        if not await self.check_lab_environment():
            raise RuntimeError("Lab environment is not available")
        
        self.logger.info("Starting R.A.I.D detection evaluation...")
        start_time = time.time()
        
        # Initialize scan engine
        engine = ScanEngine(
            mode="lab",
            concurrency=self.config["test_config"]["concurrency"],
            timeout=self.config["test_config"]["timeout"],
            output_dir="./reports/evaluation"
        )
        
        # Run tests for each vulnerability type
        all_results = {}
        
        for vuln_type, test_cases in self.config["lab_tests"].items():
            if vuln_type == "safe_endpoints":
                continue  # Handle separately
                
            self.logger.info(f"Testing {vuln_type} detection...")
            
            # Filter plugins if specified
            test_plugins = plugins if plugins else None
            if vuln_type == "sqli_error" and test_plugins:
                test_plugins = [p for p in test_plugins if "sqli" in p.lower()]
            elif vuln_type == "xss_reflected" and test_plugins:
                test_plugins = [p for p in test_plugins if "xss" in p.lower()]
            
            vuln_results = await self.test_vulnerability_type(
                vuln_type, test_cases, engine, test_plugins
            )
            all_results[vuln_type] = vuln_results
        
        # Test negative cases
        if "safe_endpoints" in self.config["lab_tests"]:
            self.logger.info("Testing negative cases (safe endpoints)...")
            safe_results = await self.test_vulnerability_type(
                "safe_endpoints", 
                self.config["lab_tests"]["safe_endpoints"], 
                engine, 
                plugins
            )
            all_results["safe_endpoints"] = safe_results
        
        # Calculate overall metrics
        evaluation_time = time.time() - start_time
        metrics = self.calculate_metrics(all_results)
        
        # Generate evaluation report
        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "evaluation_time_seconds": evaluation_time,
                "scanner_version": "2.0.0",
                "config_file": str(self.config_file),
                "plugins_tested": plugins or "all"
            },
            "results": all_results,
            "metrics": metrics,
            "accuracy_analysis": self.analyze_accuracy(metrics),
            "recommendations": self.generate_recommendations(metrics, all_results)
        }
        
        return report
    
    async def test_vulnerability_type(self, vuln_type: str, test_cases: List[Dict], 
                                    engine: ScanEngine, plugins: List[str] = None) -> Dict:
        """Test detection for a specific vulnerability type."""
        results = {
            "test_cases": [],
            "summary": {
                "total_tests": len(test_cases),
                "detected": 0,
                "missed": 0,
                "false_positives": 0,
                "true_positives": 0,
                "true_negatives": 0,
                "false_negatives": 0
            }
        }
        
        for test_case in test_cases:
            endpoint = test_case["endpoint"]
            parameter = test_case.get("parameter", "")
            expected_detection = test_case["expected_detection"]
            
            self.logger.info(f"Testing {endpoint} (param: {parameter})")
            
            try:
                # Run scan against specific endpoint
                scan_result = await engine.run_scan([endpoint], plugins)
                
                # Analyze results
                detected = self.analyze_scan_result(
                    scan_result, test_case, parameter
                )
                
                test_result = {
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "expected_detection": expected_detection,
                    "actual_detection": detected["found"],
                    "confidence": detected["confidence"],
                    "indicators": detected["indicators"],
                    "finding_details": detected["finding"],
                    "test_passed": detected["found"] == expected_detection,
                    "notes": test_case.get("notes", "")
                }
                
                results["test_cases"].append(test_result)
                
                # Update summary counters
                if expected_detection and detected["found"]:
                    results["summary"]["true_positives"] += 1
                    results["summary"]["detected"] += 1
                elif expected_detection and not detected["found"]:
                    results["summary"]["false_negatives"] += 1
                    results["summary"]["missed"] += 1
                elif not expected_detection and detected["found"]:
                    results["summary"]["false_positives"] += 1
                    results["summary"]["detected"] += 1
                else:  # not expected_detection and not detected["found"]
                    results["summary"]["true_negatives"] += 1
                
            except Exception as e:
                self.logger.error(f"Error testing {endpoint}: {e}")
                test_result = {
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "expected_detection": expected_detection,
                    "actual_detection": False,
                    "confidence": 0,
                    "indicators": [],
                    "finding_details": None,
                    "test_passed": False,
                    "error": str(e),
                    "notes": test_case.get("notes", "")
                }
                results["test_cases"].append(test_result)
                results["summary"]["missed"] += 1
        
        return results
    
    def analyze_scan_result(self, scan_result: Dict, test_case: Dict, parameter: str) -> Dict:
        """Analyze scan result to determine if vulnerability was detected."""
        findings = scan_result.get("findings", [])
        
        # Look for findings matching the test case
        matching_findings = []
        for finding in findings:
            if (finding.param == parameter or 
                finding.endpoint == test_case["endpoint"] or
                any(indicator in finding.indicators for indicator in test_case.get("expected_indicators", []))):
                matching_findings.append(finding)
        
        if not matching_findings:
            return {
                "found": False,
                "confidence": 0,
                "indicators": [],
                "finding": None
            }
        
        # Use the highest confidence finding
        best_finding = max(matching_findings, key=lambda f: f.confidence)
        
        # Check if confidence meets minimum threshold
        min_confidence = test_case.get("min_confidence", 50)
        detection_confirmed = best_finding.confidence >= min_confidence
        
        return {
            "found": detection_confirmed,
            "confidence": best_finding.confidence,
            "indicators": best_finding.indicators,
            "finding": {
                "id": best_finding.id,
                "name": best_finding.name,
                "severity": best_finding.severity,
                "plugin": best_finding.plugin,
                "evidence_keys": list(best_finding.evidence.keys()) if best_finding.evidence else []
            }
        }
    
    def calculate_metrics(self, all_results: Dict) -> Dict:
        """Calculate precision, recall, F1, and other metrics."""
        # Aggregate true/false positives and negatives
        total_tp = sum(r["summary"]["true_positives"] for r in all_results.values())
        total_fp = sum(r["summary"]["false_positives"] for r in all_results.values())
        total_tn = sum(r["summary"]["true_negatives"] for r in all_results.values())
        total_fn = sum(r["summary"]["false_negatives"] for r in all_results.values())
        
        # Calculate overall metrics
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (total_tp + total_tn) / (total_tp + total_fp + total_tn + total_fn) if (total_tp + total_fp + total_tn + total_fn) > 0 else 0
        
        # Per-vulnerability-type metrics
        per_type_metrics = {}
        for vuln_type, results in all_results.items():
            if vuln_type == "safe_endpoints":
                continue
                
            tp = results["summary"]["true_positives"]
            fp = results["summary"]["false_positives"]
            tn = results["summary"]["true_negatives"]
            fn = results["summary"]["false_negatives"]
            
            type_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            type_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            type_f1 = 2 * (type_precision * type_recall) / (type_precision + type_recall) if (type_precision + type_recall) > 0 else 0
            
            per_type_metrics[vuln_type] = {
                "precision": round(type_precision, 3),
                "recall": round(type_recall, 3),
                "f1_score": round(type_f1, 3),
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn
            }
        
        return {
            "overall": {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "accuracy": round(accuracy, 3),
                "true_positives": total_tp,
                "false_positives": total_fp,
                "true_negatives": total_tn,
                "false_negatives": total_fn
            },
            "by_vulnerability_type": per_type_metrics,
            "confusion_matrix": {
                "true_positives": total_tp,
                "false_positives": total_fp,
                "true_negatives": total_tn,
                "false_negatives": total_fn
            }
        }
    
    def analyze_accuracy(self, metrics: Dict) -> Dict:
        """Analyze accuracy against targets and provide insights."""
        overall = metrics["overall"]
        targets = self.config["test_config"]["accuracy_targets"]
        
        analysis = {
            "target_achievement": {
                "precision": {
                    "target": targets["overall_precision"],
                    "actual": overall["precision"],
                    "achieved": overall["precision"] >= targets["overall_precision"]
                },
                "recall": {
                    "target": targets["overall_recall"],
                    "actual": overall["recall"],
                    "achieved": overall["recall"] >= targets["overall_recall"]
                }
            },
            "performance_analysis": [],
            "improvement_areas": []
        }
        
        # Performance analysis
        if overall["precision"] >= targets["overall_precision"]:
            analysis["performance_analysis"].append("✓ Precision target achieved")
        else:
            gap = targets["overall_precision"] - overall["precision"]
            analysis["performance_analysis"].append(f"✗ Precision gap: {gap:.3f}")
            analysis["improvement_areas"].append("Reduce false positive rate")
        
        if overall["recall"] >= targets["overall_recall"]:
            analysis["performance_analysis"].append("✓ Recall target achieved")
        else:
            gap = targets["overall_recall"] - overall["recall"]
            analysis["performance_analysis"].append(f"✗ Recall gap: {gap:.3f}")
            analysis["improvement_areas"].append("Improve detection sensitivity")
        
        # Per-type analysis
        by_type_targets = targets.get("by_vulnerability_type", {})
        for vuln_type, type_metrics in metrics["by_vulnerability_type"].items():
            if vuln_type in by_type_targets:
                type_targets = by_type_targets[vuln_type]
                
                if type_metrics["precision"] < type_targets["precision"]:
                    analysis["improvement_areas"].append(f"Improve {vuln_type} precision")
                
                if type_metrics["recall"] < type_targets["recall"]:
                    analysis["improvement_areas"].append(f"Improve {vuln_type} recall")
        
        return analysis
    
    def generate_recommendations(self, metrics: Dict, results: Dict) -> List[str]:
        """Generate recommendations based on evaluation results."""
        recommendations = []
        overall = metrics["overall"]
        
        # Precision recommendations
        if overall["precision"] < 0.9:
            recommendations.append(
                "Consider increasing confidence thresholds to reduce false positives"
            )
            recommendations.append(
                "Improve response normalization to handle dynamic content better"
            )
        
        # Recall recommendations
        if overall["recall"] < 0.85:
            recommendations.append(
                "Review detection signatures and add more comprehensive patterns"
            )
            recommendations.append(
                "Consider lowering confidence thresholds for initial detection"
            )
        
        # False positive analysis
        false_positives = []
        for vuln_type, vuln_results in results.items():
            for test_case in vuln_results["test_cases"]:
                if test_case["actual_detection"] and not test_case["expected_detection"]:
                    false_positives.append(test_case)
        
        if false_positives:
            recommendations.append(
                f"Investigate {len(false_positives)} false positive cases for pattern improvement"
            )
        
        # False negative analysis
        false_negatives = []
        for vuln_type, vuln_results in results.items():
            for test_case in vuln_results["test_cases"]:
                if not test_case["actual_detection"] and test_case["expected_detection"]:
                    false_negatives.append(test_case)
        
        if false_negatives:
            recommendations.append(
                f"Investigate {len(false_negatives)} false negative cases for detection gaps"
            )
        
        return recommendations
    
    def save_report(self, report: Dict, output_file: str):
        """Save evaluation report to file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Evaluation report saved to {output_path}")
    
    def print_summary(self, report: Dict):
        """Print evaluation summary to console."""
        metrics = report["metrics"]["overall"]
        
        print("\n" + "="*70)
        print("R.A.I.D DETECTION EVALUATION SUMMARY")
        print("="*70)
        
        # Overall metrics table
        overall_data = [
            ["Precision", f"{metrics['precision']:.3f}", "≥ 0.900"],
            ["Recall", f"{metrics['recall']:.3f}", "≥ 0.850"],
            ["F1 Score", f"{metrics['f1_score']:.3f}", ""],
            ["Accuracy", f"{metrics['accuracy']:.3f}", ""]
        ]
        
        print("\nOverall Performance:")
        print(tabulate(overall_data, headers=["Metric", "Actual", "Target"], tablefmt="grid"))
        
        # Confusion matrix
        cm = report["metrics"]["confusion_matrix"]
        confusion_data = [
            ["True Positives", cm["true_positives"]],
            ["False Positives", cm["false_positives"]],
            ["True Negatives", cm["true_negatives"]],
            ["False Negatives", cm["false_negatives"]]
        ]
        
        print("\nConfusion Matrix:")
        print(tabulate(confusion_data, headers=["Category", "Count"], tablefmt="grid"))
        
        # Per-type metrics
        if report["metrics"]["by_vulnerability_type"]:
            print("\nBy Vulnerability Type:")
            type_data = []
            for vuln_type, type_metrics in report["metrics"]["by_vulnerability_type"].items():
                type_data.append([
                    vuln_type,
                    f"{type_metrics['precision']:.3f}",
                    f"{type_metrics['recall']:.3f}",
                    f"{type_metrics['f1_score']:.3f}"
                ])
            
            print(tabulate(type_data, headers=["Type", "Precision", "Recall", "F1"], tablefmt="grid"))
        
        # Recommendations
        if report["recommendations"]:
            print("\nRecommendations:")
            for i, rec in enumerate(report["recommendations"], 1):
                print(f"{i}. {rec}")
        
        print("\n" + "="*70)


class HTTPClient:
    def __init__(self):
        import requests
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
    
    def get(self, url, **kwargs):
        return self.session.get(url, **kwargs)
    
    def post(self, url, **kwargs):
        return self.session.post(url, **kwargs)
    
    def close(self):
        self.session.close()


@click.command()
@click.option('--config', default='docker/lab_tests/expected_results.yaml',
              help='Path to expected results configuration file')
@click.option('--output', default=None,
              help='Output file for evaluation report (default: reports/evaluation-YYYYMMDD.json)')
@click.option('--plugins', default=None,
              help='Comma-separated list of plugins to test (default: all)')
@click.option('--run-lab', is_flag=True,
              help='Run complete lab evaluation')
@click.option('--check-env', is_flag=True,
              help='Only check lab environment health')
def main(config, output, plugins, run_lab, check_env):
    """R.A.I.D Detection Evaluation Harness."""
    
    # Setup output file
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"reports/evaluation-{timestamp}.json"
    
    # Parse plugins list
    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(',')]
    
    # Initialize harness
    harness = EvaluationHarness(config)
    harness.load_config()
    
    if check_env:
        # Only check environment
        async def check_only():
            healthy = await harness.check_lab_environment()
            if healthy:
                print("✓ Lab environment is healthy and ready for testing")
                return 0
            else:
                print("✗ Lab environment is not ready")
                return 1
        
        return asyncio.run(check_only())
    
    if run_lab:
        # Run complete evaluation
        async def run_evaluation():
            try:
                report = await harness.run_evaluation(plugin_list)
                harness.save_report(report, output)
                harness.print_summary(report)
                
                # Check if accuracy targets were met
                overall = report["metrics"]["overall"]
                targets = harness.config["test_config"]["accuracy_targets"]
                
                if (overall["precision"] >= targets["overall_precision"] and 
                    overall["recall"] >= targets["overall_recall"]):
                    print("\n🎉 All accuracy targets achieved!")
                    return 0
                else:
                    print("\n⚠️  Some accuracy targets not met. See recommendations above.")
                    return 1
                    
            except Exception as e:
                print(f"Evaluation failed: {e}")
                harness.logger.error(f"Evaluation error: {e}")
                return 1
        
        return asyncio.run(run_evaluation())
    
    else:
        print("Use --run-lab to run evaluation or --check-env to check environment")
        return 0


if __name__ == '__main__':
    sys.exit(main())