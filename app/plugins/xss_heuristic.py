"""
XSS Heuristic Detection Plugin for R.A.I.D Scanner
Multi-layer verification with headless browser validation in lab mode
"""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional

from app.core.model import Finding
from app.utils.compare import ResponseComparator


METADATA = {
    "id": "xss_heuristic",
    "name": "XSS — heuristic",
    "category": "input-validation",
    "severity_hint": "High",
    "required_mode": "both",
    "implemented": True,
}

# Configuration
CONFIG = {
    "body_diff_threshold": 0.2,
    "confidence_threshold": 60,
    "mutation_count": 4,
    "delay_between_requests": 0.3,
    "headless_verification": True  # Only in lab mode
}

# Indicator weights
INDICATOR_WEIGHTS = {
    "status_changed": 0.20,
    "xss_reflection": 0.35,
    "script_execution": 0.30,  # Playwright verification
    "body_diff": 0.15
}

# XSS reflection patterns
XSS_REFLECTION_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:.*?["\']',
    r'on\w+\s*=\s*["\'].*?["\']',
    r'<img[^>]*onerror\s*=',
    r'<svg[^>]*onload\s*=',
    r'<iframe[^>]*src\s*=\s*["\']javascript:',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'document\.cookie',
    r'alert\s*\(',
    r'confirm\s*\(',
    r'prompt\s*\('
]


async def run(target: str, session, context) -> List[Finding]:
    """Main XSS detection function with multi-layer verification."""
    findings = []
    comparator = ResponseComparator()
    
    try:
        # A) Discovery
        parameterized_endpoints = await discover_xss_parameters(context)
        
        if not parameterized_endpoints:
            context.logger.info("No parameterized endpoints found for XSS testing")
            return findings
        
        context.logger.info(f"Testing {len(parameterized_endpoints)} endpoints for XSS")
        
        # Process each endpoint
    for idx, endpoint_data in enumerate(parameterized_endpoints, start=1):
        # Update progress per endpoint
        if context.progress_manager:
            context.progress_manager.update_progress("xss_heuristic", endpoint_data["url"], check_number=idx)

        endpoint_findings = await test_endpoint_for_xss(
            endpoint_data, session, context, comparator
        )
        findings.extend(endpoint_findings)
        
        await asyncio.sleep(CONFIG["delay_between_requests"])
    
    except Exception as e:
        error_finding = Finding(
            id="xss_heuristic_error",
            name="XSS Detection Error",
            plugin="xss_heuristic",
            target=target,
            endpoint=target,
            parameter=None,
            evidence={"error": str(e)},
            indicators=["plugin_error"],
            severity="info",
            confidence=0.0,
            timestamp=datetime.now().isoformat(),
            proof_mode=context.mode,
            description=f"Error during XSS detection: {e}"
        )
        findings.append(error_finding)
    
    return findings


async def discover_xss_parameters(context) -> List[Dict]:
    """Discover endpoints suitable for XSS testing."""
    parameterized_endpoints = []
    
    for endpoint, params in context.parameters.items():
        for param in params:
            # Skip CSRF tokens and obvious non-XSS parameters
            if param.lower() in ['csrf_token', 'token', '_token', 'authenticity_token']:
                continue
            
            # Focus on parameters likely to be reflected
            if any(keyword in param.lower() for keyword in ['search', 'q', 'query', 'name', 'message', 'comment', 'text']):
                priority = "high"
            else:
                priority = "normal"
            
            endpoint_data = {
                "url": endpoint,
                "parameter": param,
                "method": "GET",
                "content_type": "application/x-www-form-urlencoded",
                "priority": priority
            }
            parameterized_endpoints.append(endpoint_data)
    
    # Sort by priority
    parameterized_endpoints.sort(key=lambda x: 0 if x["priority"] == "high" else 1)
    
    return parameterized_endpoints


async def test_endpoint_for_xss(endpoint_data: Dict, session, context, comparator) -> List[Finding]:
    """Test endpoint for XSS vulnerabilities using multi-layer verification."""
    findings = []
    
    try:
        # B) Control request
        control_response = await send_control_request(endpoint_data, session)
        if not control_response:
            return findings
        
        # C) Mutation requests
        mutation_results = await send_xss_mutations(endpoint_data, session, context)
        if not mutation_results:
            return findings
        
        # D & E) Normalize responses
        normalized_control = normalize_xss_response(control_response)
        normalized_mutations = [normalize_xss_response(mut["response"]) for mut in mutation_results]
        
        # F, G, H) Analysis
        analysis_results = []
        for i, mutation_result in enumerate(mutation_results):
            analysis = await analyze_xss_response(
                normalized_control,
                normalized_mutations[i], 
                mutation_result,
                comparator,
                context
            )
            analysis_results.append(analysis)
        
        # Headless verification in lab mode
        if context.mode == "lab" and CONFIG["headless_verification"]:
            for i, mutation_result in enumerate(mutation_results):
                if any(ind in analysis_results[i]["indicators"] for ind in ["xss_reflection"]):
                    headless_result = await verify_xss_with_playwright(
                        mutation_result, context
                    )
                    if headless_result:
                        analysis_results[i]["indicators"].append("script_execution")
                        analysis_results[i]["evidence"]["headless_verification"] = headless_result
        
        # I, J) Decision
        finding = await make_xss_detection_decision(
            endpoint_data, control_response, mutation_results, 
            analysis_results, context
        )
        
        if finding:
            findings.append(finding)
    
    except Exception as e:
        context.logger.error(f"Error testing XSS on {endpoint_data['url']}: {e}")
    
    return findings


async def send_control_request(endpoint_data: Dict, session) -> Optional[Dict]:
    """Send control request with safe value."""
    try:
        url = endpoint_data["url"]
        param = endpoint_data["parameter"]
        safe_value = "safe_xss_control_value_123"
        
        if endpoint_data["method"].upper() == "GET":
            params = {param: safe_value}
            response = await session.get(url, params=params)
        else:
            data = {param: safe_value}
            response = await session.post(url, data=data)
        
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text,
            "elapsed": response.elapsed,
            "request_data": {param: safe_value}
        }
    
    except Exception:
        return None


async def send_xss_mutations(endpoint_data: Dict, session, context) -> List[Dict]:
    """Send XSS mutation requests."""
    mutations = []
    mutation_patterns = get_xss_mutation_patterns(context.mode)
    
    try:
        for pattern_id, pattern_info in mutation_patterns.items():
            # Use safe placeholder in non-lab modes
            if context.mode != "lab":
                test_value = pattern_info.get("safe_replacement", "XSS_TEST_MARKER")
            else:
                # In lab mode, get actual payload
                test_value = context.payload_manager.render_payload(
                    pattern_id, {"value": "test"}, context.mode
                ) or pattern_info.get("safe_replacement", "XSS_TEST_MARKER")
            
            url = endpoint_data["url"]
            param = endpoint_data["parameter"]
            
            if endpoint_data["method"].upper() == "GET":
                params = {param: test_value}
                response = await session.get(url, params=params)
            else:
                data = {param: test_value}
                response = await session.post(url, data=data)
            
            mutation_result = {
                "pattern_id": pattern_id,
                "pattern_type": pattern_info["type"],
                "test_value": test_value if context.mode == "lab" else "<XSS_MUTATION_PLACEHOLDER>",
                "response": {
                    "url": response.url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "text": response.text,
                    "elapsed": response.elapsed
                },
                "request_data": {param: test_value if context.mode == "lab" else "<XSS_MUTATION_PLACEHOLDER>"}
            }
            mutations.append(mutation_result)
            
            await asyncio.sleep(0.1)
    
    except Exception as e:
        context.logger.error(f"Error sending XSS mutations: {e}")
    
    return mutations


def get_xss_mutation_patterns(mode: str) -> Dict:
    """Get XSS test patterns based on scan mode."""
    patterns = {
        "xss_script_basic": {
            "type": "script_injection",
            "safe_replacement": "XSS_SCRIPT_TEST_MARKER",
            "description": "Basic script tag injection"
        },
        "xss_img_onerror": {
            "type": "event_handler",
            "safe_replacement": "XSS_IMG_TEST_MARKER",
            "description": "Image onerror event handler"
        },
        "xss_svg_onload": {
            "type": "event_handler", 
            "safe_replacement": "XSS_SVG_TEST_MARKER",
            "description": "SVG onload event handler"
        },
        "xss_javascript_url": {
            "type": "javascript_url",
            "safe_replacement": "XSS_JAVASCRIPT_TEST_MARKER",
            "description": "JavaScript URL scheme"
        }
    }
    
    return patterns


def normalize_xss_response(response: Dict) -> Dict:
    """Normalize response for XSS analysis."""
    normalized = response.copy()
    
    if "text" in normalized:
        text = normalized["text"]
        
        # Remove timestamps and dynamic content
        text = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', text)
        text = re.sub(r'sessionid=[a-zA-Z0-9]+', 'sessionid=SESSIONID', text)
        text = re.sub(r'csrf_token=[a-zA-Z0-9]+', 'csrf_token=CSRFTOKEN', text)
        
        # Normalize whitespace in HTML
        text = re.sub(r'\s+', ' ', text)
        
        normalized["text"] = text
    
    return normalized


async def analyze_xss_response(control: Dict, mutation: Dict, mutation_result: Dict,
                             comparator, context) -> Dict:
    """Analyze mutation response for XSS indicators."""
    analysis = {
        "indicators": [],
        "metrics": {},
        "evidence": {}
    }
    
    control_response = control
    test_response = mutation
    
    # Calculate similarity metrics
    body_similarity = comparator.calculate_text_similarity(
        control_response.get("text", ""),
        test_response.get("text", "")
    )
    
    analysis["metrics"] = {
        "body_similarity": body_similarity,
        "status_delta": abs(
            test_response.get("status_code", 200) - control_response.get("status_code", 200)
        )
    }
    
    # Check for XSS reflection
    test_body = test_response.get("text", "")
    test_value = mutation_result.get("test_value", "")
    
    # Look for reflection patterns
    reflections_found = []
    if context.mode == "lab" and "<" in test_value:
        # In lab mode, check for actual reflection
        for pattern in XSS_REFLECTION_PATTERNS:
            if re.search(pattern, test_body, re.IGNORECASE):
                reflections_found.append(pattern)
    
    # Check for test value reflection (even in safe mode)
    # Only treat reflection as significant if value appears in HTML context (between tags)
    if test_value and isinstance(test_value, str):
        # Avoid counting reflection in attributes like URLs without angle brackets unless explicit pattern matched
        appears = test_value in test_body
        appears_in_html = bool(re.search(r">[^<]*" + re.escape(test_value) + r"[^<]*<", test_body))
        if appears_in_html or (context.mode == "lab" and appears):
            reflections_found.append("test_value_reflected")
    
    # Indicators
    indicators = []
    
    # Status changed
    if control_response.get("status_code") != test_response.get("status_code"):
        indicators.append("status_changed")
    
    # XSS reflection detected
    if reflections_found:
        indicators.append("xss_reflection")
        analysis["evidence"]["reflections"] = reflections_found
    
    # Body difference
    if body_similarity < (1 - CONFIG["body_diff_threshold"]):
        indicators.append("body_diff")
    
    analysis["indicators"] = indicators
    
    return analysis


async def verify_xss_with_playwright(mutation_result: Dict, context) -> Optional[Dict]:
    """Verify XSS execution using Playwright headless browser (lab mode only)."""
    if context.mode != "lab":
        return None
    
    try:
        # Import Playwright only when needed
        from playwright.async_api import async_playwright
        
        verification_result = {
            "browser_used": "chromium",
            "execution_detected": False,
            "console_logs": [],
            "screenshot_path": None,
            "error": None
        }
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Set up console logging
            page.on("console", lambda msg: verification_result["console_logs"].append({
                "type": msg.type,
                "text": msg.text
            }))
            
            # Navigate to the page with XSS payload
            url = mutation_result["response"]["url"]
            
            try:
                await page.goto(url, timeout=10000)
                
                # Wait a bit for any JavaScript to execute
                await page.wait_for_timeout(2000)
                
                # Check for alert dialogs (common XSS test)
                page.on("dialog", lambda dialog: dialog.accept())
                
                # Look for XSS indicators in console logs
                for log in verification_result["console_logs"]:
                    if any(xss_indicator in log["text"].lower() for xss_indicator in 
                           ["xss", "alert", "script", "eval", "error"]):
                        verification_result["execution_detected"] = True
                        break
                
                # Take screenshot as evidence (in lab mode)
                screenshot_path = f"/tmp/xss_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                await page.screenshot(path=screenshot_path)
                verification_result["screenshot_path"] = screenshot_path
                
            except Exception as e:
                verification_result["error"] = str(e)
            
            await browser.close()
        
        return verification_result
    
    except ImportError:
        context.logger.warning("Playwright not available for headless XSS verification")
        return None
    except Exception as e:
        context.logger.error(f"Error in headless XSS verification: {e}")
        return {"error": str(e), "execution_detected": False}


async def make_xss_detection_decision(endpoint_data: Dict, control_response: Dict,
                                    mutation_results: List[Dict], analysis_results: List[Dict],
                                    context) -> Optional[Finding]:
    """Make XSS detection decision based on analysis."""
    
    # Aggregate results
    all_indicators = []
    positive_mutations = 0
    headless_verified = False
    
    for analysis in analysis_results:
        all_indicators.extend(analysis["indicators"])
        
        # Check if mutation is positive
        mutation_confidence = calculate_xss_confidence(analysis["indicators"])
        if mutation_confidence >= CONFIG["confidence_threshold"] or len(analysis["indicators"]) >= 2:
            positive_mutations += 1
        
        # Check for headless verification
        if "script_execution" in analysis["indicators"]:
            headless_verified = True
    
    # Decision criteria
    if positive_mutations < 1:
        return None
    
    # Calculate confidence
    unique_indicators = list(set(all_indicators))
    overall_confidence = calculate_xss_confidence(unique_indicators)
    
    # Boost confidence if headless verified
    if headless_verified:
        overall_confidence = min(100, overall_confidence + 15)
    
    # Create evidence
    evidence = {
        "request_control": {
            "url": control_response["url"],
            "method": endpoint_data["method"],
            "parameter": endpoint_data["parameter"],
            "value": control_response["request_data"][endpoint_data["parameter"]]
        },
        "request_test": {
            "url": endpoint_data["url"],
            "method": endpoint_data["method"],
            "parameter": endpoint_data["parameter"],
            "mutations_count": len(mutation_results),
            "values": ["<XSS_MUTATION_PLACEHOLDER>" if context.mode != "lab" else mr["test_value"] 
                      for mr in mutation_results]
        },
        "response_control": {
            "status_code": control_response["status_code"],
            "headers": dict(control_response["headers"]),
            "body_snippet": control_response["text"][:500]
        },
        "response_test": [
            {
                "status_code": mr["response"]["status_code"],
                "headers": dict(mr["response"]["headers"]),
                "body_snippet": mr["response"]["text"][:500],
                "pattern_type": mr["pattern_type"]
            }
            for mr in mutation_results
        ],
        "indicators": unique_indicators,
        "confidence_calculation": {
            "base_score": 50,
            "indicator_weights": INDICATOR_WEIGHTS,
            "headless_bonus": 15 if headless_verified else 0,
            "final_score": overall_confidence
        },
        "positive_mutations": positive_mutations,
        "total_mutations": len(mutation_results),
        "headless_verified": headless_verified
    }
    
    # Add reflection evidence
    reflections = []
    for analysis in analysis_results:
        if "reflections" in analysis.get("evidence", {}):
            reflections.extend(analysis["evidence"]["reflections"])
    
    if reflections:
        evidence["xss_reflections"] = list(set(reflections))
    
    # Add headless verification evidence
    for analysis in analysis_results:
        if "headless_verification" in analysis.get("evidence", {}):
            evidence["headless_verification"] = analysis["evidence"]["headless_verification"]
            break
    
    finding = Finding(
        id=f"xss_heuristic_{endpoint_data['parameter']}",
        name=f"Cross-Site Scripting (XSS) - {endpoint_data['parameter']}",
        plugin="xss_heuristic",
        target=context.target,
        endpoint=endpoint_data["url"],
        parameter=endpoint_data["parameter"],
        evidence=evidence,
        indicators=unique_indicators,
        severity="high",
        confidence=float(overall_confidence),
        timestamp=datetime.now().isoformat(),
        proof_mode=context.mode,
        description=(
            f"XSS vulnerability detected in parameter '{endpoint_data['parameter']}'. "
            f"{'Execution verified with headless browser. ' if headless_verified else ''}"
            f"{positive_mutations}/{len(mutation_results)} mutations were positive."
        ),
        recommendation=(
            "Implement proper input validation and output encoding. Use Content Security Policy (CSP). "
            "Sanitize user input and encode output based on context (HTML, JavaScript, CSS, URL)."
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html"
        ],
    )
    
    return finding


def calculate_xss_confidence(indicators: List[str]) -> int:
    """Calculate XSS confidence score."""
    base_confidence = 50
    confidence_boost = 0
    
    for indicator in indicators:
        weight = INDICATOR_WEIGHTS.get(indicator, 0)
        confidence_boost += weight * 100
    
    # Multiple indicators bonus
    if len(indicators) > 2:
        confidence_boost += 10
    elif len(indicators) > 1:
        confidence_boost += 5
    
    final_confidence = min(100, base_confidence + confidence_boost)
    return max(0, int(final_confidence)) 