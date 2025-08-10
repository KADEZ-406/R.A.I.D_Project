"""
AI-Assisted Triage and Suggestion System for R.A.I.D Scanner
Provides intelligent analysis, recommendations, and command templates
"""

import json
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from app.core.model import Finding


class AITriageClassifier:
    """Machine learning classifier for finding triage."""
    
    def __init__(self, model_path: str = "models/triage.pkl"):
        self.model_path = Path(model_path)
        self.classifier = None
        self.scaler = None
        self.is_trained = False
        self.logger = logging.getLogger(__name__)
        
        # Load existing model if available
        self.load_model()
    
    def extract_features(self, finding: Finding, context: Dict = None) -> np.ndarray:
        """Extract features from finding for ML classification."""
        evidence = finding.evidence or {}
        
        # Basic features
        features = [
            finding.confidence / 100.0,  # Normalized confidence
            len(finding.indicators),  # Number of indicators
            1.0 if finding.severity == "critical" else 0.0,
            1.0 if finding.severity == "high" else 0.0,
            1.0 if finding.severity == "medium" else 0.0,
        ]
        
        # Response comparison features
        compare_metrics = evidence.get("compare_metrics", {})
        features.extend([
            compare_metrics.get("avg_body_similarity", 0.5),
            compare_metrics.get("avg_timing_delta", 0.0) / 10.0,  # Normalize
            compare_metrics.get("status_changes", 0) / 5.0,  # Normalize
        ])
        
        # Indicator-based features
        indicator_features = [
            1.0 if "error_signature" in finding.indicators else 0.0,
            1.0 if "status_changed" in finding.indicators else 0.0,
            1.0 if "body_diff" in finding.indicators else 0.0,
            1.0 if "timing_anomaly" in finding.indicators else 0.0,
            1.0 if "xss_reflection" in finding.indicators else 0.0,
            1.0 if "script_execution" in finding.indicators else 0.0,
        ]
        features.extend(indicator_features)
        
        # Evidence quality features
        evidence_features = [
            1.0 if "sql_error_patterns" in evidence else 0.0,
            1.0 if "xss_reflections" in evidence else 0.0,
            1.0 if "headless_verification" in evidence else 0.0,
            len(evidence.get("request_test", {}).get("values", [])) / 5.0,  # Normalize
        ]
        features.extend(evidence_features)
        
        # Parameter entropy (simple measure)
        param = finding.param or ""
        param_entropy = len(set(param.lower())) / max(len(param), 1) if param else 0.0
        features.append(param_entropy)
        
        return np.array(features)
    
    def train_on_synthetic_data(self, training_data: List[Tuple[Finding, bool]]):
        """Train classifier on synthetic lab data."""
        if len(training_data) < 10:
            self.logger.warning("Insufficient training data for ML classifier")
            return False
        
        # Extract features and labels
        X = []
        y = []
        
        for finding, is_true_positive in training_data:
            features = self.extract_features(finding)
            X.append(features)
            y.append(1 if is_true_positive else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train classifier
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.classifier.fit(X_scaled, y)
        self.is_trained = True
        
        # Save model
        self.save_model()
        
        self.logger.info(f"Trained ML classifier on {len(training_data)} samples")
        return True
    
    def predict(self, finding: Finding, context: Dict = None) -> Tuple[str, float]:
        """Predict if finding is likely to be a true positive."""
        if not self.is_trained:
            # Fall back to rule-based prediction
            return self.rule_based_prediction(finding)
        
        try:
            features = self.extract_features(finding, context)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Get probability prediction
            probabilities = self.classifier.predict_proba(features_scaled)[0]
            true_positive_prob = probabilities[1] if len(probabilities) > 1 else 0.5
            
            # Classify based on threshold
            if true_positive_prob >= 0.7:
                classification = "LIKELY"
            elif true_positive_prob >= 0.3:
                classification = "UNCERTAIN"
            else:
                classification = "UNLIKELY"
            
            return classification, true_positive_prob
        
        except Exception as e:
            self.logger.error(f"ML prediction failed: {e}")
            return self.rule_based_prediction(finding)
    
    def rule_based_prediction(self, finding: Finding) -> Tuple[str, float]:
        """Rule-based fallback prediction."""
        confidence = finding.confidence / 100.0
        indicator_count = len(finding.indicators)
        
        # Rule-based scoring
        score = confidence * 0.6  # Base confidence
        score += min(indicator_count / 3.0, 1.0) * 0.3  # Indicator count
        
        # Boost for high-value indicators
        if "error_signature" in finding.indicators:
            score += 0.2
        if "script_execution" in finding.indicators:
            score += 0.2
        if "timing_anomaly" in finding.indicators:
            score += 0.1
        
        score = min(score, 1.0)
        
        if score >= 0.7:
            return "LIKELY", score
        elif score >= 0.4:
            return "UNCERTAIN", score
        else:
            return "UNLIKELY", score
    
    def save_model(self):
        """Save trained model to disk."""
        if not self.is_trained:
            return
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            "classifier": self.classifier,
            "scaler": self.scaler,
            "trained_at": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        self.logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load trained model from disk."""
        if not self.model_path.exists():
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.classifier = model_data["classifier"]
            self.scaler = model_data["scaler"]
            self.is_trained = True
            
            self.logger.info(f"Model loaded from {self.model_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False


class SecuritySuggester:
    """AI-powered security analysis and suggestion system."""
    
    def __init__(self):
        self.triage_classifier = AITriageClassifier()
        self.logger = logging.getLogger(__name__)
        self.refusal_log = Path("refusal.log")
        
        # Load recommendation templates
        self.templates = self.load_templates()
    
    def load_templates(self) -> Dict:
        """Load recommendation and command templates."""
        return {
            "remediation": {
                "sql_injection": {
                    "description": "SQL injection vulnerabilities allow attackers to manipulate database queries",
                    "remediation_steps": [
                        "Implement parameterized queries/prepared statements",
                        "Use stored procedures with proper input validation",
                        "Apply input validation and sanitization",
                        "Implement least privilege database access",
                        "Consider using an ORM framework",
                        "Enable database query logging and monitoring"
                    ],
                    "prevention": [
                        "Never concatenate user input directly into SQL queries",
                        "Validate all input on both client and server side",
                        "Use whitelisting for input validation",
                        "Implement proper error handling to avoid information disclosure"
                    ]
                },
                "xss": {
                    "description": "Cross-site scripting allows injection of malicious scripts into web pages",
                    "remediation_steps": [
                        "Implement proper output encoding based on context",
                        "Use Content Security Policy (CSP) headers",
                        "Validate and sanitize all user input",
                        "Apply context-aware encoding (HTML, JavaScript, CSS, URL)",
                        "Use secure templating engines with auto-escaping",
                        "Implement input validation with whitelisting"
                    ],
                    "prevention": [
                        "Never trust user input - validate everything",
                        "Use framework-provided XSS protection features",
                        "Implement strict CSP with nonce or hash-based policies",
                        "Regularly scan for XSS vulnerabilities"
                    ]
                }
            },
            "command_templates": {
                "sql_injection": {
                    "sqlmap": {
                        "description": "Automated SQL injection testing tool",
                        "template": [
                            "sqlmap",
                            "--url", "<TARGET_URL>",
                            "--data", "<POST_DATA>",
                            "--level", "<LEVEL>",
                            "--risk", "<RISK>",
                            "--batch",
                            "--tamper", "<TAMPER_SCRIPTS>"
                        ],
                        "example_params": {
                            "LEVEL": "1-5 (depth of testing)",
                            "RISK": "1-3 (risk level)",
                            "TAMPER_SCRIPTS": "space2comment,randomcase"
                        }
                    },
                    "manual_verification": {
                        "description": "Manual SQL injection verification steps",
                        "template": [
                            "curl",
                            "-X", "<METHOD>",
                            "-d", "<DATA>",
                            "-H", "Content-Type: application/x-www-form-urlencoded",
                            "<TARGET_URL>"
                        ]
                    }
                },
                "xss": {
                    "xsser": {
                        "description": "Cross Site 'Scripter' testing tool",
                        "template": [
                            "xsser",
                            "--url", "<TARGET_URL>",
                            "--auto",
                            "--cookie", "<COOKIE>",
                            "--payload", "<PAYLOAD_LIST>"
                        ]
                    },
                    "manual_verification": {
                        "description": "Manual XSS verification in browser",
                        "template": [
                            "# Navigate to:",
                            "<TARGET_URL>?<PARAM>=<TEST_PAYLOAD>",
                            "# Check browser console for script execution",
                            "# Verify DOM modifications"
                        ]
                    }
                }
            }
        }
    
    def analyze_finding(self, finding: Finding, waf_profile: Dict = None, 
                       tech_fingerprint: Dict = None) -> Dict:
        """Comprehensive finding analysis with AI assistance."""
        
        # Get ML triage prediction
        triage_result, confidence = self.triage_classifier.predict(finding)
        
        # Determine vulnerability type
        vuln_type = self.classify_vulnerability_type(finding)
        
        # Generate remediation guidance
        remediation = self.generate_remediation_guidance(finding, vuln_type)
        
        # Generate reproduction steps (safe templates only)
        repro_steps = self.generate_reproduction_steps(finding, vuln_type)
        
        # Generate command templates (placeholders only)
        command_templates = self.generate_command_templates(finding, vuln_type)
        
        # WAF-aware recommendations
        waf_recommendations = self.generate_waf_recommendations(finding, waf_profile)
        
        # Technology-specific advice
        tech_recommendations = self.generate_tech_recommendations(finding, tech_fingerprint)
        
        analysis = {
            "finding_id": finding.id,
            "ai_triage": {
                "classification": triage_result,
                "confidence": round(confidence, 3),
                "reasoning": self.explain_triage_decision(finding, triage_result, confidence)
            },
            "vulnerability_analysis": {
                "type": vuln_type,
                "severity_assessment": finding.severity,
                "confidence_factors": self.analyze_confidence_factors(finding),
                "exploitability": self.assess_exploitability(finding, waf_profile)
            },
            "remediation_guidance": remediation,
            "reproduction_steps_lab": repro_steps,
            "command_templates": command_templates,
            "waf_considerations": waf_recommendations,
            "technology_specific": tech_recommendations,
            "next_steps": self.recommend_next_steps(finding, triage_result)
        }
        
        return analysis
    
    def classify_vulnerability_type(self, finding: Finding) -> str:
        """Classify the vulnerability type based on finding characteristics."""
        plugin = finding.plugin.lower()
        indicators = [ind.lower() for ind in finding.indicators]
        
        if "sqli" in plugin or "sql" in plugin:
            return "sql_injection"
        elif "xss" in plugin:
            return "xss"
        elif "lfi" in plugin or "file" in plugin:
            return "lfi"
        elif "command" in plugin:
            return "command_injection"
        elif "idor" in plugin:
            return "idor"
        elif "header" in plugin:
            return "security_misconfiguration"
        elif "file" in plugin and "exposure" in plugin:
            return "sensitive_data_exposure"
        else:
            return "unknown"
    
    def generate_remediation_guidance(self, finding: Finding, vuln_type: str) -> Dict:
        """Generate comprehensive remediation guidance."""
        template = self.templates["remediation"].get(vuln_type, {})
        
        guidance = {
            "description": template.get("description", "Security vulnerability detected"),
            "remediation_steps": template.get("remediation_steps", [
                "Validate and sanitize all user input",
                "Implement proper security controls",
                "Follow secure coding practices",
                "Conduct security testing"
            ]),
            "prevention_measures": template.get("prevention", [
                "Regular security assessments",
                "Developer security training",
                "Code review processes"
            ]),
            "priority": self.calculate_remediation_priority(finding),
            "estimated_effort": self.estimate_remediation_effort(finding, vuln_type),
            "testing_recommendations": [
                "Test fix in lab environment first",
                "Verify remediation with automated scanning",
                "Perform manual verification",
                "Monitor for regression"
            ]
        }
        
        return guidance
    
    def generate_reproduction_steps(self, finding: Finding, vuln_type: str) -> Dict:
        """Generate safe reproduction steps for lab environment."""
        steps = {
            "lab_setup": [
                "Start R.A.I.D lab environment: docker-compose -f docker/docker-compose.lab.yml up -d",
                "Verify lab services are running: docker-compose ps",
                "Access lab dashboard: http://localhost:8000"
            ],
            "reproduction_steps": [],
            "verification": [
                "Check scanner output for detection confirmation",
                "Review finding evidence and indicators",
                "Validate confidence score meets threshold"
            ],
            "safety_notice": "These steps only work in the controlled lab environment. "
                           "Do not attempt on production systems without authorization."
        }
        
        # Add vulnerability-specific steps
        if vuln_type == "sql_injection":
            steps["reproduction_steps"] = [
                f"Navigate to vulnerable endpoint: {finding.endpoint}",
                f"Test parameter: {finding.param}",
                "Use R.A.I.D lab mode: python -m app.cli scan --target <LAB_URL> --mode lab",
                "Observe SQL error messages in response",
                "Check for database error signatures in findings"
            ]
        elif vuln_type == "xss":
            steps["reproduction_steps"] = [
                f"Navigate to vulnerable endpoint: {finding.endpoint}",
                f"Test parameter: {finding.param}",
                "Use R.A.I.D lab mode with headless verification",
                "Observe script reflection in response",
                "Check browser console for execution (if headless enabled)"
            ]
        else:
            steps["reproduction_steps"] = [
                f"Navigate to endpoint: {finding.endpoint}",
                f"Test parameter: {finding.param}" if finding.param else "Test identified vulnerability",
                "Follow R.A.I.D detection methodology",
                "Review evidence and indicators"
            ]
        
        return steps
    
    def generate_command_templates(self, finding: Finding, vuln_type: str) -> Dict:
        """Generate command templates with placeholders (NO real payloads)."""
        templates = self.templates["command_templates"].get(vuln_type, {})
        
        command_templates = {}
        
        for tool_name, tool_config in templates.items():
            command_templates[tool_name] = {
                "description": tool_config["description"],
                "command_template": tool_config["template"],
                "parameter_examples": tool_config.get("example_params", {}),
                "usage_note": "Replace <PLACEHOLDERS> with appropriate values for your test environment",
                "safety_warning": "Only use against systems you own or have explicit authorization to test"
            }
        
        # Add finding-specific placeholders
        if finding.endpoint:
            for tool in command_templates.values():
                if "<TARGET_URL>" in str(tool["command_template"]):
                    tool["suggested_url"] = "<LAB_EQUIVALENT_URL>"
        
        if finding.param:
            for tool in command_templates.values():
                tool["target_parameter"] = finding.param
        
        return command_templates
    
    def refuse_exploit_request(self, request_type: str, context: str = "") -> str:
        """Refuse requests for actual exploit payloads and log refusal."""
        refusal_message = (
            f"REFUSAL: Cannot provide actual {request_type} payloads for public targets. "
            "This violates ethical usage guidelines. Use lab mode with containerized "
            "vulnerable applications for safe testing. See docker/docker-compose.lab.yml "
            "for the appropriate testing environment."
        )
        
        # Log refusal
        self.log_refusal(request_type, context)
        
        return refusal_message
    
    def log_refusal(self, request_type: str, context: str):
        """Log payload refusal for monitoring."""
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "request_type": request_type,
                "context": context,
                "action": "refused"
            }
            
            with open(self.refusal_log, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        
        except Exception as e:
            self.logger.error(f"Failed to log refusal: {e}")
    
    def generate_waf_recommendations(self, finding: Finding, waf_profile: Dict = None) -> Dict:
        """Generate WAF-aware recommendations."""
        if not waf_profile:
            return {"message": "No WAF detected - standard remediation applies"}
        
        waf_name = waf_profile.get("name", "unknown")
        waf_version = waf_profile.get("version", "unknown")
        
        recommendations = {
            "waf_detected": waf_name,
            "waf_version": waf_version,
            "implications": [
                f"Vulnerability detected despite {waf_name} protection",
                "WAF rules may need updating or tuning",
                "Consider defense-in-depth approach"
            ],
            "recommendations": [
                "Review WAF rule configuration",
                "Update WAF signatures if available",
                "Implement application-level controls",
                "Consider additional security layers"
            ],
            "testing_notes": [
                "Use conservative testing approach",
                "WAF may interfere with automated tools",
                "Manual verification may be required"
            ]
        }
        
        return recommendations
    
    def generate_tech_recommendations(self, finding: Finding, tech_fingerprint: Dict = None) -> Dict:
        """Generate technology-specific recommendations."""
        if not tech_fingerprint:
            return {"message": "No specific technology fingerprint available"}
        
        technologies = tech_fingerprint.get("technologies", [])
        
        recommendations = {
            "detected_technologies": technologies,
            "technology_specific_advice": []
        }
        
        # Technology-specific guidance
        for tech in technologies:
            tech_lower = tech.lower()
            
            if "php" in tech_lower:
                recommendations["technology_specific_advice"].extend([
                    "Review PHP configuration for security settings",
                    "Ensure error reporting is disabled in production",
                    "Use PHP's prepared statements for database queries"
                ])
            elif "node" in tech_lower or "express" in tech_lower:
                recommendations["technology_specific_advice"].extend([
                    "Review Express.js middleware for security",
                    "Use helmet.js for security headers",
                    "Validate input with express-validator"
                ])
            elif "wordpress" in tech_lower:
                recommendations["technology_specific_advice"].extend([
                    "Update WordPress core and plugins",
                    "Review plugin security configurations",
                    "Use WordPress security plugins"
                ])
        
        return recommendations
    
    def explain_triage_decision(self, finding: Finding, classification: str, confidence: float) -> str:
        """Explain the AI triage decision."""
        explanations = []
        
        if classification == "LIKELY":
            explanations.append(f"High confidence ({confidence:.1%}) based on multiple indicators")
        elif classification == "UNCERTAIN":
            explanations.append(f"Moderate confidence ({confidence:.1%}) - requires manual review")
        else:
            explanations.append(f"Low confidence ({confidence:.1%}) - likely false positive")
        
        # Add specific reasoning
        if "error_signature" in finding.indicators:
            explanations.append("Database/application error signatures detected")
        
        if "script_execution" in finding.indicators:
            explanations.append("Script execution verified with headless browser")
        
        if finding.confidence >= 80:
            explanations.append("High scanner confidence score")
        elif finding.confidence <= 40:
            explanations.append("Low scanner confidence score")
        
        return "; ".join(explanations)
    
    def analyze_confidence_factors(self, finding: Finding) -> Dict:
        """Analyze factors contributing to confidence score."""
        factors = {
            "positive_factors": [],
            "negative_factors": [],
            "neutral_factors": []
        }
        
        # Analyze indicators
        for indicator in finding.indicators:
            if indicator in ["error_signature", "script_execution"]:
                factors["positive_factors"].append(f"Strong indicator: {indicator}")
            elif indicator in ["body_diff", "status_changed"]:
                factors["positive_factors"].append(f"Supporting indicator: {indicator}")
            elif indicator in ["plugin_error"]:
                factors["negative_factors"].append(f"Scan error: {indicator}")
        
        # Analyze evidence
        evidence = finding.evidence or {}
        if "sql_error_patterns" in evidence:
            factors["positive_factors"].append("SQL error patterns found")
        
        if "headless_verification" in evidence:
            factors["positive_factors"].append("Headless browser verification")
        
        # Confidence score analysis
        if finding.confidence >= 80:
            factors["positive_factors"].append("High confidence score")
        elif finding.confidence <= 40:
            factors["negative_factors"].append("Low confidence score")
        else:
            factors["neutral_factors"].append("Moderate confidence score")
        
        return factors
    
    def assess_exploitability(self, finding: Finding, waf_profile: Dict = None) -> Dict:
        """Assess exploitability of the finding."""
        exploitability = {
            "level": "unknown",
            "factors": [],
            "barriers": [],
            "recommendations": []
        }
        
        # Base exploitability on finding characteristics
        if finding.severity == "critical":
            exploitability["level"] = "high"
        elif finding.severity == "high":
            exploitability["level"] = "medium"
        else:
            exploitability["level"] = "low"
        
        # Factors increasing exploitability
        if "error_signature" in finding.indicators:
            exploitability["factors"].append("Error messages provide information")
        
        if "script_execution" in finding.indicators:
            exploitability["factors"].append("Script execution confirmed")
        
        # Barriers to exploitation
        if waf_profile:
            exploitability["barriers"].append(f"WAF protection: {waf_profile.get('name', 'unknown')}")
        
        if finding.confidence < 60:
            exploitability["barriers"].append("Low confidence in detection")
        
        return exploitability
    
    def calculate_remediation_priority(self, finding: Finding) -> str:
        """Calculate remediation priority."""
        if finding.severity == "critical":
            return "immediate"
        elif finding.severity == "high":
            return "urgent"
        elif finding.severity == "medium":
            return "normal"
        else:
            return "low"
    
    def estimate_remediation_effort(self, finding: Finding, vuln_type: str) -> str:
        """Estimate remediation effort."""
        effort_map = {
            "sql_injection": "medium",
            "xss": "low",
            "lfi": "medium",
            "command_injection": "high",
            "security_misconfiguration": "low"
        }
        
        return effort_map.get(vuln_type, "medium")
    
    def recommend_next_steps(self, finding: Finding, triage_result: str) -> List[str]:
        """Recommend next steps based on triage result."""
        if triage_result == "LIKELY":
            return [
                "Prioritize this finding for immediate investigation",
                "Verify in lab environment before production testing",
                "Develop and test remediation approach",
                "Plan for urgent deployment of fix"
            ]
        elif triage_result == "UNCERTAIN":
            return [
                "Conduct manual verification of this finding",
                "Review evidence and indicators carefully",
                "Test reproduction in lab environment",
                "Seek security expert review if needed"
            ]
        else:  # UNLIKELY
            return [
                "Mark for manual review to confirm false positive",
                "Consider adjusting detection parameters",
                "Document reason for false positive",
                "Update detection rules if necessary"
            ] 