"""
Security Headers Check Plugin for R.A.I.D Scanner
Analyzes HTTP security headers for security misconfigurations
"""

from datetime import datetime
from typing import Dict, List, Tuple

from app.core.model import Finding


METADATA = {
    "id": "health_header_check",
    "name": "Security Headers Check",
    "category": "configuration",
    "severity_hint": "Medium",
    "required_mode": "safe",
    "implemented": True,
}


# Security headers configuration
SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "required": True,
        "good_values": ["max-age="],
        "bad_values": ["max-age=0"]
    },
    "x-frame-options": {
        "description": "Clickjacking protection",
        "severity": "medium", 
        "required": True,
        "good_values": ["deny", "sameorigin"],
        "bad_values": ["allowall"]
    },
    "x-content-type-options": {
        "description": "MIME type sniffing protection",
        "severity": "low",
        "required": True,
        "good_values": ["nosniff"],
        "bad_values": []
    },
    "x-xss-protection": {
        "description": "XSS filtering (legacy)",
        "severity": "low",
        "required": False,
        "good_values": ["1; mode=block"],
        "bad_values": ["0"]
    },
    "content-security-policy": {
        "description": "Content Security Policy",
        "severity": "high",
        "required": True,
        "good_values": ["default-src"],
        "bad_values": ["unsafe-inline", "unsafe-eval", "*"]
    },
    "referrer-policy": {
        "description": "Referrer information control",
        "severity": "low",
        "required": False,
        "good_values": ["strict-origin-when-cross-origin", "no-referrer"],
        "bad_values": ["unsafe-url"]
    },
    "permissions-policy": {
        "description": "Feature policy control",
        "severity": "low", 
        "required": False,
        "good_values": ["geolocation=()"],
        "bad_values": []
    }
}


async def run(target: str, session, context) -> List[Finding]:
    """
    Run security headers analysis.
    
    Args:
        target: Target URL
        session: HTTP session object  
        context: Scan context
        
    Returns:
        List of findings
    """
    findings = []
    
    try:
        # Make request to analyze headers
        response = await session.get(target)
        
        # Analyze security headers
        headers_analysis = analyze_security_headers(response.headers)
        
        # Generate findings based on analysis
        findings.extend(generate_header_findings(headers_analysis, target, response.url))
        
        # Check for additional security indicators
        findings.extend(check_additional_security_indicators(response, target))
        
    except Exception as e:
        error_finding = Finding(
            id="headers_check_error",
            name="Security Headers Check Error", 
            plugin="health_header_check",
            target=target,
            endpoint=target,
            parameter=None,
            evidence={"error": str(e)},
            indicators=["plugin_error"],
            severity="info",
            confidence=0.0,
            timestamp=datetime.now().isoformat(),
            proof_mode=context.mode,
            description=f"Error during security headers check: {e}"
        )
        findings.append(error_finding)
    
    return findings


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, any]:
    """Analyze security headers and return assessment."""
    # Convert to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    analysis = {
        "missing_headers": [],
        "misconfigured_headers": [],
        "good_headers": [],
        "deprecated_headers": [],
        "all_headers": dict(headers)
    }
    
    for header_name, config in SECURITY_HEADERS.items():
        header_value = lower_headers.get(header_name.lower())
        
        if header_value is None:
            if config["required"]:
                analysis["missing_headers"].append({
                    "header": header_name,
                    "description": config["description"],
                    "severity": config["severity"]
                })
        else:
            # Header is present, check configuration
            is_good = False
            is_bad = False
            
            # Check for good values
            for good_value in config["good_values"]:
                if good_value.lower() in header_value.lower():
                    is_good = True
                    break
            
            # Check for bad values
            for bad_value in config["bad_values"]:
                if bad_value.lower() in header_value.lower():
                    is_bad = True
                    break
            
            if is_bad:
                analysis["misconfigured_headers"].append({
                    "header": header_name,
                    "value": header_value,
                    "description": config["description"],
                    "severity": config["severity"],
                    "issue": "Contains insecure directive"
                })
            elif is_good:
                analysis["good_headers"].append({
                    "header": header_name,
                    "value": header_value,
                    "description": config["description"]
                })
            else:
                # Present but not clearly good or bad
                analysis["misconfigured_headers"].append({
                    "header": header_name,
                    "value": header_value,
                    "description": config["description"],
                    "severity": config["severity"],
                    "issue": "Unusual or potentially weak configuration"
                })
    
    # Check for deprecated headers
    deprecated_headers = ["x-xss-protection", "x-webkit-csp"]
    for dep_header in deprecated_headers:
        if dep_header in lower_headers:
            analysis["deprecated_headers"].append({
                "header": dep_header,
                "value": lower_headers[dep_header],
                "reason": "Header is deprecated and should be replaced with modern alternatives"
            })
    
    return analysis


def generate_header_findings(analysis: Dict, target: str, endpoint: str) -> List[Finding]:
    """Generate findings based on headers analysis."""
    findings = []
    
    # Missing headers finding
    if analysis["missing_headers"]:
        severity_map = {"high": 3, "medium": 2, "low": 1}
        max_severity = max(analysis["missing_headers"], 
                          key=lambda x: severity_map.get(x["severity"], 0))["severity"]
        
        finding = Finding(
            id="missing_security_headers",
            name="Missing Security Headers",
            plugin="health_header_check",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "missing_headers": analysis["missing_headers"],
                "count": len(analysis["missing_headers"])
            },
            indicators=["missing_security_headers"],
            severity=max_severity,
            confidence=95.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Missing {len(analysis['missing_headers'])} important security headers",
            recommendation="Implement missing security headers to improve application security posture"
        )
        findings.append(finding)
    
    # Misconfigured headers findings
    for misc_header in analysis["misconfigured_headers"]:
        finding = Finding(
            id=f"misconfigured_{misc_header['header'].replace('-', '_')}",
            name=f"Misconfigured {misc_header['header']} Header",
            plugin="health_header_check",
            target=target,
            endpoint=endpoint,
            parameter=misc_header['header'],
            evidence={
                "header_name": misc_header['header'],
                "header_value": misc_header['value'],
                "issue": misc_header['issue'],
                "description": misc_header['description']
            },
            indicators=["misconfigured_header"],
            severity=misc_header['severity'],
            confidence=90.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"{misc_header['header']} header is misconfigured: {misc_header['issue']}",
            recommendation=f"Review and fix {misc_header['header']} header configuration"
        )
        findings.append(finding)
    
    # Deprecated headers finding
    if analysis["deprecated_headers"]:
        finding = Finding(
            id="deprecated_security_headers",
            name="Deprecated Security Headers",
            plugin="health_header_check",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "deprecated_headers": analysis["deprecated_headers"],
                "count": len(analysis["deprecated_headers"])
            },
            indicators=["deprecated_headers"],
            severity="info",
            confidence=100.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Using {len(analysis['deprecated_headers'])} deprecated security headers",
            recommendation="Replace deprecated headers with modern security header equivalents"
        )
        findings.append(finding)
    
    # Good configuration finding (informational)
    if analysis["good_headers"] and not analysis["missing_headers"] and not analysis["misconfigured_headers"]:
        finding = Finding(
            id="good_security_headers",
            name="Good Security Headers Configuration",
            plugin="health_header_check",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "good_headers": analysis["good_headers"],
                "count": len(analysis["good_headers"])
            },
            indicators=["good_security_config"],
            severity="info",
            confidence=95.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Good security headers configuration with {len(analysis['good_headers'])} properly configured headers",
            recommendation="Maintain current security headers configuration"
        )
        findings.append(finding)
    
    return findings


def check_additional_security_indicators(response, target: str) -> List[Finding]:
    """Check for additional security indicators beyond standard headers."""
    findings = []
    
    # Check for HTTPS enforcement
    if not target.startswith('https://'):
        finding = Finding(
            id="http_not_https",
            name="HTTP Instead of HTTPS",
            plugin="health_header_check",
            target=target,
            endpoint=response.url,
            parameter=None,
            evidence={
                "protocol": "http",
                "recommendation": "Use HTTPS for secure communication"
            },
            indicators=["insecure_protocol"],
            severity="medium",
            confidence=100.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description="Site accessible over insecure HTTP protocol",
            recommendation="Implement HTTPS and redirect HTTP traffic to HTTPS"
        )
        findings.append(finding)
    
    # Check for server information disclosure
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    
    disclosure_headers = {
        "server": "Server software information",
        "x-powered-by": "Technology stack information",
        "x-aspnet-version": "ASP.NET version information",
        "x-generator": "Generator software information"
    }
    
    disclosed_info = []
    for header, description in disclosure_headers.items():
        if header in headers_lower:
            disclosed_info.append({
                "header": header,
                "value": headers_lower[header],
                "description": description
            })
    
    if disclosed_info:
        finding = Finding(
            id="information_disclosure_headers",
            name="Information Disclosure via Headers",
            plugin="health_header_check",
            target=target,
            endpoint=response.url,
            parameter=None,
            evidence={
                "disclosed_headers": disclosed_info,
                "count": len(disclosed_info)
            },
            indicators=["information_disclosure"],
            severity="low",
            confidence=85.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Headers disclose {len(disclosed_info)} pieces of system information",
            recommendation="Remove or obscure headers that disclose system information"
        )
        findings.append(finding)
    
    return findings 