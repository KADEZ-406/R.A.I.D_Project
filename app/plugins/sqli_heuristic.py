"""
SQL Injection Heuristic Detection Plugin for R.A.I.D Scanner
Multi-layer verification with comprehensive evidence collection
"""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Tuple

from app.core.model import Finding
from app.utils.compare import ResponseComparator


METADATA = {
    "id": "sqli_heuristic",
    "name": "SQL Injection — heuristic",
    "category": "input-validation",
    "severity_hint": "High",
    "required_mode": "both",
    "implemented": True,
}

# Configuration thresholds
CONFIG = {
    "body_diff_threshold": 0.3,
    "timing_threshold_ms": 2000,
    "confidence_threshold": 65,
    "mutation_count": 5,
    "delay_between_requests": 0.5
}

# Indicator weights for confidence calculation
INDICATOR_WEIGHTS = {
    "status_changed": 0.25,
    "error_signature": 0.40,
    "body_diff": 0.25,
    "timing_anomaly": 0.10
}

# SQL error patterns for signature matching
SQL_ERROR_PATTERNS = [
    r"mysql_fetch_array\(\)",
    r"ORA-\d{5}",
    r"Microsoft.*ODBC.*Driver",
    r"PostgreSQL query failed",
    r"Warning: mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"Warning: pg_",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"OleDbException",
    r"System\.Data\.SqlClient\.SqlException",
    r"Unclosed quotation mark",
    r"Microsoft OLE DB Provider",
    r"Incorrect syntax near"
]


async def run(target: str, session, context) -> List[Finding]:
    """
    Main SQL injection detection function using multi-layer verification.
    
    Args:
        target: Target URL
        session: HTTP session object
        context: Scan context with endpoints and parameters
        
    Returns:
        List of findings with comprehensive evidence
    """
    findings = []
    comparator = ResponseComparator()
    
    try:
        # A) Discovery - find parameterized endpoints
        parameterized_endpoints = await discover_sql_parameters(context)
        
        if not parameterized_endpoints:
            context.logger.info("No parameterized endpoints found for SQL injection testing")
            return findings
        
        context.logger.info(f"Testing {len(parameterized_endpoints)} parameterized endpoints")
        
        # Apply max parameter checks limit if provided via context
        limit = getattr(context, "max_param_checks", 0)
        if limit and limit > 0:
            parameterized_endpoints = parameterized_endpoints[:limit]

        # Process each endpoint with parameters
        for idx, endpoint_data in enumerate(parameterized_endpoints, start=1):
            # Update progress per endpoint
            if context.progress_manager:
                context.progress_manager.update_progress("sqli_heuristic", endpoint_data["url"], check_number=idx)

            endpoint_findings = await test_endpoint_for_sqli(
                endpoint_data, session, context, comparator
            )
            findings.extend(endpoint_findings)
            
            # Rate limiting
            await asyncio.sleep(CONFIG["delay_between_requests"])
    
    except Exception as e:
        error_finding = Finding(
            id="sqli_heuristic_error",
            name="SQL Injection Detection Error",
            plugin="sqli_heuristic",
            target=target,
            endpoint=target,
            parameter=None,
            evidence={"error": str(e)},
            indicators=["plugin_error"],
            severity="info",
            confidence=0.0,
            timestamp=datetime.now().isoformat(),
            proof_mode=context.mode,
            description=f"Error during SQL injection detection: {e}"
        )
        findings.append(error_finding)
    
    return findings


async def discover_sql_parameters(context) -> List[Dict]:
    """Discover endpoints with parameters suitable for SQL injection testing."""
    parameterized_endpoints = []
    
    for endpoint, params in context.parameters.items():
        for param in params:
            # Skip parameters that are unlikely to be SQL injectable
            if param.lower() in ['csrf_token', 'token', '_token', 'authenticity_token']:
                continue
            
            endpoint_data = {
                "url": endpoint,
                "parameter": param,
                "method": "GET",  # Default to GET, could be enhanced to detect POST
                "content_type": "application/x-www-form-urlencoded"
            }
            parameterized_endpoints.append(endpoint_data)
    
    return parameterized_endpoints


async def test_endpoint_for_sqli(endpoint_data: Dict, session, context, comparator) -> List[Finding]:
    """Test a specific endpoint parameter for SQL injection vulnerabilities."""
    findings = []
    
    try:
        # B) Control request - baseline with safe value
        control_response = await send_control_request(endpoint_data, session, context)
        if not control_response:
            return findings
        
        # C) Mutated requests - test with various SQL injection patterns
        mutation_results = await send_mutation_requests(endpoint_data, session, context)
        
        if not mutation_results:
            return findings
        
        # D & E) Capture and normalize responses
        normalized_control = normalize_response(control_response)
        normalized_mutations = [normalize_response(mut["response"]) for mut in mutation_results]
        
        # F, G, H) Analysis - compare responses and detect indicators
        analysis_results = []
        for i, mutation_result in enumerate(mutation_results):
            analysis = await analyze_mutation_response(
                normalized_control,
                normalized_mutations[i],
                mutation_result,
                comparator,
                context
            )
            analysis_results.append(analysis)
        
        # I, J) Decision and aggregation
        finding = await make_detection_decision(
            endpoint_data, control_response, mutation_results, 
            analysis_results, context
        )
        
        if finding:
            findings.append(finding)
    
    except Exception as e:
        context.logger.error(f"Error testing endpoint {endpoint_data['url']}: {e}")
    
    return findings


async def send_control_request(endpoint_data: Dict, session, context) -> Dict:
    """Send control request with safe baseline value."""
    try:
        url = endpoint_data["url"]
        param = endpoint_data["parameter"]
        
        # Safe baseline value
        safe_value = "safe_test_value_123"
        
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
    
    except Exception as e:
        context.logger.error(f"Error sending control request: {e}")
        return None


async def send_mutation_requests(endpoint_data: Dict, session, context) -> List[Dict]:
    """Send mutated requests with SQL injection test patterns."""
    mutations = []
    
    # Get mutation patterns based on scan mode
    mutation_patterns = get_mutation_patterns(context.mode)
    
    try:
        for pattern_id, pattern_info in mutation_patterns.items():
            # Use safe placeholder in non-lab modes
            if context.mode != "lab":
                test_value = pattern_info.get("safe_replacement", "SQL_TEST_MARKER")
            else:
                # In lab mode, get actual test payload from payload manager
                test_value = context.payload_manager.render_payload(
                    pattern_id, {"value": "test"}, context.mode
                ) or pattern_info.get("safe_replacement", "SQL_TEST_MARKER")
            
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
                "test_value": test_value if context.mode == "lab" else "<MUTATION_PLACEHOLDER>",
                "response": {
                    "url": response.url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "text": response.text,
                    "elapsed": response.elapsed
                },
                "request_data": {param: test_value if context.mode == "lab" else "<MUTATION_PLACEHOLDER>"}
            }
            mutations.append(mutation_result)
            
            # Rate limiting between mutations
            await asyncio.sleep(0.2)
    
    except Exception as e:
        context.logger.error(f"Error sending mutation requests: {e}")
    
    return mutations


def get_mutation_patterns(mode: str) -> Dict:
    """Get SQL injection test patterns based on scan mode."""
    patterns = {
        "sql_error_quote": {
            "type": "error_based",
            "safe_replacement": "'",
            "description": "Single quote to trigger SQL error"
        },
        "sql_error_double_quote": {
            "type": "error_based", 
            "safe_replacement": '"',
            "description": "Double quote to trigger SQL error"
        },
        "sql_boolean_or": {
            "type": "boolean_based",
            "safe_replacement": "' OR '1'='1",
            "description": "Boolean OR condition test"
        },
        "sql_boolean_and": {
            "type": "boolean_based",
            "safe_replacement": "' AND '1'='1",
            "description": "Boolean AND condition test"
        },
        "sql_union_select": {
            "type": "union_based",
            "safe_replacement": "' UNION SELECT NULL--",
            "description": "UNION SELECT test"
        },
        "sql_comment": {
            "type": "comment_based",
            "safe_replacement": "'--",
            "description": "SQL comment test"
        },
        "sql_semicolon": {
            "type": "statement_based",
            "safe_replacement": "';",
            "description": "Statement termination test"
        }
    }
    
    return patterns


def normalize_response(response: Dict) -> Dict:
    """Normalize response by removing volatile content."""
    normalized = response.copy()
    
    # Normalize response body
    if "text" in normalized:
        text = normalized["text"]
        
        # Remove timestamps
        text = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', text)
        
        # Remove session IDs
        text = re.sub(r'sessionid=[a-zA-Z0-9]+', 'sessionid=SESSIONID', text)
        text = re.sub(r'PHPSESSID=[a-zA-Z0-9]+', 'PHPSESSID=SESSIONID', text)
        
        # Remove CSRF tokens
        text = re.sub(r'csrf_token=[a-zA-Z0-9]+', 'csrf_token=CSRFTOKEN', text)
        text = re.sub(r'_token=[a-zA-Z0-9]+', '_token=CSRFTOKEN', text)
        
        # Remove UUIDs
        text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', text)
        
        normalized["text"] = text
    
    return normalized


async def analyze_mutation_response(control: Dict, mutation: Dict, mutation_result: Dict, 
                                  comparator, context) -> Dict:
    """Analyze mutation response against control to detect SQL injection indicators."""
    analysis = {
        "indicators": [],
        "metrics": {},
        "evidence": {}
    }
    
    # F) Comparison metrics
    control_response = control
    test_response = mutation
    
    # Calculate similarity metrics
    body_similarity = comparator.calculate_text_similarity(
        control_response.get("text", ""), 
        test_response.get("text", "")
    )
    
    header_similarity = comparator.calculate_header_similarity(
        control_response.get("headers", {}),
        test_response.get("headers", {})
    )
    
    timing_delta = abs(
        test_response.get("elapsed", 0) - control_response.get("elapsed", 0)
    )
    
    analysis["metrics"] = {
        "body_similarity": body_similarity,
        "header_similarity": header_similarity,
        "timing_delta": timing_delta,
        "status_delta": abs(
            test_response.get("status_code", 200) - control_response.get("status_code", 200)
        )
    }
    
    # G) Signature check - look for SQL error patterns
    test_body = test_response.get("text", "")
    control_body = control_response.get("text", "")
    
    sql_errors_found = []
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, test_body, re.IGNORECASE):
            # Check if error wasn't present in control
            if not re.search(pattern, control_body, re.IGNORECASE):
                sql_errors_found.append(pattern)
    
    # H) Indicator rules
    indicators = []
    
    # Status changed
    if control_response.get("status_code") != test_response.get("status_code"):
        indicators.append("status_changed")
    
    # Error signature detected
    if sql_errors_found:
        indicators.append("error_signature")
        analysis["evidence"]["sql_errors"] = sql_errors_found
    
    # Body difference significant
    if body_similarity < (1 - CONFIG["body_diff_threshold"]):
        indicators.append("body_diff")
    
    # Timing anomaly (only in lab mode or explicitly enabled)
    if (context.mode == "lab" or getattr(context, "enable_timing", False)):
        if timing_delta > CONFIG["timing_threshold_ms"] / 1000.0:
            indicators.append("timing_anomaly")
    
    analysis["indicators"] = indicators
    
    return analysis


async def make_detection_decision(endpoint_data: Dict, control_response: Dict,
                                mutation_results: List[Dict], analysis_results: List[Dict],
                                context) -> Finding:
    """Make final detection decision based on aggregated analysis."""
    
    # Aggregate indicators across all mutations
    all_indicators = []
    all_metrics = []
    positive_mutations = 0
    
    for analysis in analysis_results:
        all_indicators.extend(analysis["indicators"])
        all_metrics.append(analysis["metrics"])
        
        # Count as positive if confidence threshold met or multiple indicators
        mutation_confidence = calculate_confidence(analysis["indicators"])
        if mutation_confidence >= CONFIG["confidence_threshold"] or len(analysis["indicators"]) >= 2:
            positive_mutations += 1
    
    # Majority voting - require at least 2 positive mutations out of 5
    if positive_mutations < 2:
        return None
    
    # Calculate overall confidence
    unique_indicators = list(set(all_indicators))
    overall_confidence = calculate_confidence(unique_indicators)
    
    # Create comprehensive evidence
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
             "values": ["<MUTATION_PLACEHOLDER>" if context.mode != "lab" else mr["test_value"] 
                      for mr in mutation_results]
        },
        "response_control": {
            "status_code": control_response["status_code"],
            "headers": dict(control_response["headers"]),
            "body_snippet": control_response["text"][:500],
             "elapsed_ms": control_response["elapsed"] * 1000
        },
        "response_test": [
            {
                "status_code": mr["response"]["status_code"],
                "headers": dict(mr["response"]["headers"]),
                "body_snippet": mr["response"]["text"][:500],
                 "elapsed_ms": mr["response"]["elapsed"] * 1000,
                "pattern_type": mr["pattern_type"]
            }
            for mr in mutation_results
        ],
        "compare_metrics": {
            "avg_body_similarity": sum(m["body_similarity"] for m in all_metrics) / len(all_metrics),
            "avg_timing_delta": sum(m["timing_delta"] for m in all_metrics) / len(all_metrics),
            "status_changes": sum(1 for m in all_metrics if m["status_delta"] > 0),
            "timing_anomalies": sum(1 for a in analysis_results if "timing_anomaly" in a["indicators"])
        },
        "indicators": unique_indicators,
        "confidence_calculation": {
            "base_score": 50,
            "indicator_weights": INDICATOR_WEIGHTS,
            "applied_weights": {ind: INDICATOR_WEIGHTS.get(ind, 0) for ind in unique_indicators},
            "final_score": overall_confidence
        },
        "positive_mutations": positive_mutations,
        "total_mutations": len(mutation_results)
    }
    
    # Add SQL error evidence if found
    sql_errors = []
    for analysis in analysis_results:
        if "sql_errors" in analysis.get("evidence", {}):
            sql_errors.extend(analysis["evidence"]["sql_errors"])
    
    if sql_errors:
        evidence["sql_error_patterns"] = list(set(sql_errors))
    
    # Create finding
    finding = Finding(
        id=f"sqli_heuristic_{endpoint_data['parameter']}",
        name=f"SQL Injection Vulnerability - {endpoint_data['parameter']}",
        plugin="sqli_heuristic",
        target=context.target,
        endpoint=endpoint_data["url"],
        parameter=endpoint_data["parameter"],
        evidence=evidence,
        indicators=unique_indicators,
        severity="high",
        confidence=float(overall_confidence),
        timestamp=datetime.now().isoformat(),
        proof_mode=context.mode,
        description=f"SQL injection vulnerability detected in parameter '{endpoint_data['parameter']}' "
                   f"with {positive_mutations}/{len(mutation_results)} positive mutations",
        recommendation="Implement parameterized queries/prepared statements to prevent SQL injection. "
                      "Validate and sanitize all user input. Consider using an ORM framework.",
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    )
    
    return finding


def calculate_confidence(indicators: List[str]) -> int:
    """Calculate confidence score based on detected indicators."""
    base_confidence = 50
    confidence_boost = 0
    
    for indicator in indicators:
        weight = INDICATOR_WEIGHTS.get(indicator, 0)
        confidence_boost += weight * 100
    
    # Multiple indicators increase confidence
    if len(indicators) > 2:
        confidence_boost += 10
    elif len(indicators) > 1:
        confidence_boost += 5
    
    final_confidence = min(100, base_confidence + confidence_boost)
    return max(0, int(final_confidence)) 