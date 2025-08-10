"""
Banner Grabbing Plugin for R.A.I.D Scanner
Identifies services, versions, and technologies from HTTP headers and responses
"""

import re
from datetime import datetime
from typing import List

from app.core.model import Finding


METADATA = {
    "id": "banner_grab",
    "name": "Banner Grabbing",
    "category": "reconnaissance",
    "severity_hint": "Info",
    "required_mode": "safe",
    "implemented": True,
}


# Technology fingerprints
TECHNOLOGY_PATTERNS = {
    # Web servers
    "apache": [
        r"apache[/\s](\d+\.[\d\.]*)",
        r"server:\s*apache",
    ],
    "nginx": [
        r"nginx[/\s](\d+\.[\d\.]*)",
        r"server:\s*nginx",
    ],
    "iis": [
        r"microsoft-iis[/\s](\d+\.[\d\.]*)",
        r"server:\s*microsoft-iis",
    ],
    "lighttpd": [
        r"lighttpd[/\s](\d+\.[\d\.]*)",
    ],
    
    # Frameworks
    "express": [
        r"x-powered-by:\s*express",
        r"express[/\s](\d+\.[\d\.]*)",
    ],
    "django": [
        r"django[/\s](\d+\.[\d\.]*)",
        r"csrftoken",
        r"sessionid",
    ],
    "flask": [
        r"werkzeug[/\s](\d+\.[\d\.]*)",
        r"flask",
    ],
    "rails": [
        r"x-powered-by:\s*phusion\s+passenger",
        r"ruby\s+on\s+rails",
    ],
    "laravel": [
        r"laravel_session",
        r"x-powered-by:\s*php",
    ],
    "spring": [
        r"spring\s+framework",
        r"jsessionid",
    ],
    
    # Programming languages
    "php": [
        r"x-powered-by:\s*php[/\s](\d+\.[\d\.]*)",
        r"phpsessid",
        r"set-cookie:.*php",
    ],
    "asp.net": [
        r"x-powered-by:\s*asp\.net",
        r"x-aspnet-version:\s*(\d+\.[\d\.]*)",
        r"asp\.net_sessionid",
    ],
    "nodejs": [
        r"x-powered-by:\s*express",
        r"connect\.sid",
    ],
    
    # CMS
    "wordpress": [
        r"wp-content",
        r"wp-includes",
        r"wp-admin",
        r"/wp-json/",
    ],
    "drupal": [
        r"drupal",
        r"x-drupal-cache",
        r"/sites/default/",
    ],
    "joomla": [
        r"joomla",
        r"/administrator/",
        r"mosConfig_",
    ],
    
    # CDN/Proxy
    "cloudflare": [
        r"cf-ray:",
        r"cloudflare",
        r"cf-cache-status:",
    ],
    "akamai": [
        r"akamai",
        r"x-akamai-",
    ],
    "fastly": [
        r"fastly",
        r"x-served-by:.*fastly",
    ],
    
    # Security products
    "waf": [
        r"x-sucuri-id:",
        r"x-protected-by:",
        r"x-security-",
    ]
}


async def run(target: str, session, context) -> List[Finding]:
    """
    Run banner grabbing analysis.
    
    Args:
        target: Target URL
        session: HTTP session object
        context: Scan context
        
    Returns:
        List of findings
    """
    findings = []
    
    try:
        # Make initial request to gather headers
        response = await session.get(target)
        
        # Analyze headers
        header_findings = analyze_headers(response.headers, target, response.url)
        findings.extend(header_findings)
        
        # Analyze response body for technology indicators
        if response.status_code == 200:
            body_findings = analyze_response_body(response.text, target, response.url)
            findings.extend(body_findings)
        
        # Try additional endpoints for more information
        additional_endpoints = [
            "/robots.txt",
            "/sitemap.xml", 
            "/.well-known/security.txt",
            "/server-info",
            "/server-status"
        ]
        
        for endpoint in additional_endpoints:
            try:
                endpoint_url = target.rstrip('/') + endpoint
                endpoint_response = await session.get(endpoint_url)
                
                if endpoint_response.status_code == 200:
                    endpoint_findings = analyze_endpoint_response(
                        endpoint, endpoint_response, target, endpoint_url
                    )
                    findings.extend(endpoint_findings)
                    
            except Exception:
                continue  # Skip failed endpoints
        
    except Exception as e:
        # Create error finding
        error_finding = Finding(
            id="banner_grab_error",
            name="Banner Grabbing Error",
            plugin="banner_grab",
            target=target,
            endpoint=target,
            parameter=None,
            evidence={"error": str(e)},
            indicators=["plugin_error"],
            severity="info",
            confidence=0.0,
            timestamp=datetime.now().isoformat(),
            proof_mode=context.mode,
            description=f"Error during banner grabbing: {e}"
        )
        findings.append(error_finding)
    
    return findings


def analyze_headers(headers: dict, target: str, endpoint: str) -> List[Finding]:
    """Analyze HTTP headers for technology indicators."""
    findings = []
    
    # Convert headers to lowercase for case-insensitive matching
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    # Server header analysis
    server_header = lower_headers.get('server', '')
    if server_header:
        finding = Finding(
            id="server_banner",
            name="Server Banner Disclosure",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "server_header": server_header,
                "full_headers": dict(headers)
            },
            indicators=["server_disclosure"],
            severity="info",
            confidence=90.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Server banner reveals: {server_header}",
            recommendation="Consider hiding server version information to reduce information disclosure"
        )
        findings.append(finding)
    
    # Technology-specific header analysis
    technologies_found = []
    
    for tech_name, patterns in TECHNOLOGY_PATTERNS.items():
        for pattern in patterns:
            # Check headers
            for header_name, header_value in lower_headers.items():
                header_line = f"{header_name}: {header_value}"
                if re.search(pattern, header_line, re.IGNORECASE):
                    technologies_found.append(tech_name)
                    break
    
    # Remove duplicates
    technologies_found = list(set(technologies_found))
    
    if technologies_found:
        finding = Finding(
            id="technology_fingerprint",
            name="Technology Stack Fingerprinting",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "technologies": technologies_found,
                "detection_method": "http_headers",
                "headers_analyzed": dict(lower_headers)
            },
            indicators=["technology_disclosure"],
            severity="info",
            confidence=80.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Detected technologies: {', '.join(technologies_found)}",
            recommendation="Review technology disclosure for security implications"
        )
        findings.append(finding)
    
    # Security headers analysis
    security_headers = {
        'x-frame-options': 'Clickjacking protection',
        'x-content-type-options': 'MIME type sniffing protection',
        'x-xss-protection': 'XSS filtering',
        'strict-transport-security': 'HTTPS enforcement',
        'content-security-policy': 'Content injection protection',
        'referrer-policy': 'Referrer information control'
    }
    
    missing_security_headers = []
    for header, description in security_headers.items():
        if header not in lower_headers:
            missing_security_headers.append(f"{header} ({description})")
    
    if missing_security_headers:
        finding = Finding(
            id="missing_security_headers",
            name="Missing Security Headers",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "missing_headers": missing_security_headers,
                "present_headers": [h for h in security_headers.keys() if h in lower_headers]
            },
            indicators=["missing_security_headers"],
            severity="low",
            confidence=95.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Missing {len(missing_security_headers)} security headers",
            recommendation="Implement missing security headers to improve application security posture"
        )
        findings.append(finding)
    
    return findings


def analyze_response_body(response_body: str, target: str, endpoint: str) -> List[Finding]:
    """Analyze response body for technology indicators."""
    findings = []
    
    # Look for technology patterns in response body
    technologies_found = []
    
    for tech_name, patterns in TECHNOLOGY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                technologies_found.append(tech_name)
                break
    
    # Additional body-specific patterns
    body_patterns = {
        "jquery": r"jquery[/\s](\d+\.[\d\.]*)",
        "bootstrap": r"bootstrap[/\s](\d+\.[\d\.]*)",
        "angular": r"angular[/\s](\d+\.[\d\.]*)",
        "react": r"react[/\s](\d+\.[\d\.]*)",
        "vue": r"vue[/\s](\d+\.[\d\.]*)",
    }
    
    for tech_name, pattern in body_patterns.items():
        if re.search(pattern, response_body, re.IGNORECASE):
            technologies_found.append(tech_name)
    
    # Remove duplicates
    technologies_found = list(set(technologies_found))
    
    if technologies_found:
        finding = Finding(
            id="body_technology_fingerprint",
            name="Technology Detection in Response Body",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint,
            parameter=None,
            evidence={
                "technologies": technologies_found,
                "detection_method": "response_body",
                "response_length": len(response_body)
            },
            indicators=["technology_disclosure"],
            severity="info",
            confidence=70.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Response body reveals technologies: {', '.join(technologies_found)}",
            recommendation="Consider minimizing technology disclosure in response content"
        )
        findings.append(finding)
    
    # Look for error messages that reveal information
    error_patterns = [
        (r"mysql.*error", "MySQL database error"),
        (r"postgresql.*error", "PostgreSQL database error"),
        (r"oracle.*error", "Oracle database error"),
        (r"microsoft.*oledb", "Microsoft database error"),
        (r"php\s+(warning|error|notice)", "PHP error message"),
        (r"asp\.net.*error", "ASP.NET error message"),
        (r"java\.lang\.", "Java stack trace"),
        (r"python.*traceback", "Python traceback"),
    ]
    
    for pattern, description in error_patterns:
        if re.search(pattern, response_body, re.IGNORECASE):
            finding = Finding(
                id="error_disclosure",
                name="Error Message Disclosure",
                plugin="banner_grab",
                target=target,
                endpoint=endpoint,
                parameter=None,
                evidence={
                    "error_type": description,
                    "pattern_matched": pattern,
                    "response_snippet": response_body[:500]
                },
                indicators=["error_disclosure"],
                severity="low",
                confidence=85.0,
                timestamp=datetime.now().isoformat(),
                proof_mode="safe",
                description=f"Response contains error disclosure: {description}",
                recommendation="Configure error handling to avoid revealing sensitive system information"
            )
            findings.append(finding)
            break  # Only report first error pattern found
    
    return findings


def analyze_endpoint_response(endpoint: str, response, target: str, endpoint_url: str) -> List[Finding]:
    """Analyze specific endpoint responses for information disclosure."""
    findings = []
    
    if endpoint == "/robots.txt":
        # Analyze robots.txt for interesting paths
        disallowed_paths = re.findall(r'disallow:\s*([^\s]+)', response.text, re.IGNORECASE)
        interesting_paths = [path for path in disallowed_paths 
                           if any(keyword in path.lower() for keyword in 
                                ['admin', 'private', 'secret', 'backup', 'config', 'test'])]
        
    if interesting_paths:
        finding = Finding(
                id="robots_disclosure",
                name="Sensitive Paths in robots.txt",
                plugin="banner_grab",
                target=target,
                endpoint=endpoint_url,
            parameter=None,
                evidence={
                    "interesting_paths": interesting_paths,
                    "all_disallowed": disallowed_paths
                },
                indicators=["path_disclosure"],
                severity="info",
            confidence=75.0,
            timestamp=datetime.now().isoformat(),
                proof_mode="safe",
                description=f"robots.txt reveals {len(interesting_paths)} potentially sensitive paths",
                recommendation="Review robots.txt to ensure it doesn't disclose sensitive application paths"
            )
            findings.append(finding)
    
    elif endpoint == "/.well-known/security.txt":
        # Security contact information found
        finding = Finding(
            id="security_txt_found",
            name="Security Contact Information Available",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint_url,
            parameter=None,
            evidence={
                "security_txt_content": response.text[:500]
            },
            indicators=["security_contact"],
            severity="info",
            confidence=100.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description="Security contact information is available",
            recommendation="Good practice - security.txt file found for vulnerability reporting"
        )
        findings.append(finding)
    
    elif endpoint in ["/server-info", "/server-status"]:
        # Apache server information disclosure
        finding = Finding(
            id="server_info_disclosure",
            name="Server Information Disclosure",
            plugin="banner_grab",
            target=target,
            endpoint=endpoint_url,
            parameter=None,
            evidence={
                "endpoint": endpoint,
                "response_length": len(response.text),
                "status_code": response.status_code
            },
            indicators=["server_info_disclosure"],
            severity="medium",
            confidence=90.0,
            timestamp=datetime.now().isoformat(),
            proof_mode="safe",
            description=f"Server information accessible at {endpoint}",
            recommendation="Disable or restrict access to server information endpoints"
        )
        findings.append(finding)
    
    return findings 