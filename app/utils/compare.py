"""
Response Comparison Utilities for R.A.I.D Scanner
Functions to compute similarity metrics and detect anomalies
"""

import difflib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# import pandas as pd  # Temporarily commented out due to Python 3.13 compatibility
# from Levenshtein import distance as levenshtein_distance  # Temporarily commented out


class ResponseComparator:
    """Compare HTTP responses to detect anomalies and injection points."""
    
    def __init__(self):
        self.ignored_headers = {
            'date', 'expires', 'last-modified', 'etag', 'set-cookie',
            'cache-control', 'x-request-id', 'x-trace-id', 'cf-ray'
        }
        
        # Patterns to normalize before comparison
        self.normalization_patterns = [
            # Timestamps
            (r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', 'TIMESTAMP'),
            # Session IDs
            (r'sessionid=[a-zA-Z0-9]+', 'sessionid=SESSIONID'),
            (r'PHPSESSID=[a-zA-Z0-9]+', 'PHPSESSID=SESSIONID'),
            # CSRF tokens
            (r'csrf_token=[a-zA-Z0-9]+', 'csrf_token=CSRFTOKEN'),
            (r'_token=[a-zA-Z0-9]+', '_token=CSRFTOKEN'),
            # UUIDs
            (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID'),
            # Request IDs
            (r'request_id=[a-zA-Z0-9\-]+', 'request_id=REQUESTID'),
        ]
    
    def normalize_response(self, response_text: str) -> str:
        """Normalize response text by removing dynamic content."""
        normalized = response_text
        
        for pattern, replacement in self.normalization_patterns:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
        
        return normalized
    
    def normalize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize headers by removing dynamic and ignored headers."""
        normalized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            # Skip ignored headers
            if key_lower in self.ignored_headers:
                continue
            
            # Normalize specific header values
            if key_lower == 'content-length':
                # Keep content-length as is for comparison
                normalized[key] = value
            elif key_lower == 'server':
                # Normalize server version info
                normalized[key] = re.sub(r'/[\d\.]+', '/VERSION', value)
            else:
                normalized[key] = value
        
        return normalized
    
    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text responses using multiple metrics."""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        # Normalize texts
        norm_text1 = self.normalize_response(text1)
        norm_text2 = self.normalize_response(text2)
        
        # Calculate different similarity metrics
        
        # 1. Simple token-aware similarity proxy for Levenshtein
        # Use difflib.SequenceMatcher ratio on characters as proxy
        levenshtein_sim = difflib.SequenceMatcher(None, norm_text1, norm_text2).ratio()
        
        # 2. Sequence matcher (SequenceMatcher from difflib)
        seq_matcher = difflib.SequenceMatcher(None, norm_text1, norm_text2)
        sequence_sim = seq_matcher.ratio()
        
        # 3. Word overlap similarity
        words1 = set(norm_text1.split())
        words2 = set(norm_text2.split())
        if len(words1) == 0 and len(words2) == 0:
            word_sim = 1.0
        elif len(words1) == 0 or len(words2) == 0:
            word_sim = 0.0
        else:
            common_words = words1.intersection(words2)
            total_words = words1.union(words2)
            word_sim = len(common_words) / len(total_words)
        
        # 4. Line-by-line similarity
        lines1 = norm_text1.splitlines()
        lines2 = norm_text2.splitlines()
        line_matcher = difflib.SequenceMatcher(None, lines1, lines2)
        line_sim = line_matcher.ratio()
        
        # Weighted average of similarity metrics
        similarity = (
            levenshtein_sim * 0.3 +
            sequence_sim * 0.3 +
            word_sim * 0.2 +
            line_sim * 0.2
        )
        
        return min(1.0, max(0.0, similarity))
    
    def calculate_header_similarity(self, headers1: Dict[str, str], 
                                  headers2: Dict[str, str]) -> float:
        """Calculate similarity between response headers."""
        norm_headers1 = self.normalize_headers(headers1)
        norm_headers2 = self.normalize_headers(headers2)
        
        if not norm_headers1 and not norm_headers2:
            return 1.0
        
        all_keys = set(norm_headers1.keys()).union(set(norm_headers2.keys()))
        if not all_keys:
            return 1.0
        
        matching_headers = 0
        for key in all_keys:
            val1 = norm_headers1.get(key, '')
            val2 = norm_headers2.get(key, '')
            if val1 == val2:
                matching_headers += 1
        
        return matching_headers / len(all_keys)
    
    def calculate_timing_delta(self, time1: float, time2: float) -> float:
        """Calculate timing difference between responses."""
        return abs(time2 - time1)
    
    def find_error_signatures(self, response_text: str, 
                            signatures: Dict[str, List[str]]) -> List[str]:
        """Find error signatures in response text."""
        found_signatures = []
        response_lower = response_text.lower()
        
        for category, patterns in signatures.items():
            for pattern in patterns:
                if isinstance(pattern, str):
                    if pattern.lower() in response_lower:
                        found_signatures.append(f"{category}:{pattern}")
                else:
                    # Regex pattern
                    if re.search(pattern, response_text, re.IGNORECASE):
                        found_signatures.append(f"{category}:{pattern}")
        
        return found_signatures
    
    def detect_content_changes(self, baseline_response: str, 
                             test_response: str) -> Dict[str, Any]:
        """Detect specific types of content changes."""
        changes = {
            'length_change': 0,
            'lines_added': 0,
            'lines_removed': 0,
            'significant_changes': [],
            'html_structure_changed': False,
            'json_structure_changed': False
        }
        
        # Length change
        changes['length_change'] = len(test_response) - len(baseline_response)
        
        # Line-by-line differences
        baseline_lines = baseline_response.splitlines()
        test_lines = test_response.splitlines()
        
        diff = list(difflib.unified_diff(baseline_lines, test_lines, lineterm=''))
        
        for line in diff:
            if line.startswith('+') and not line.startswith('+++'):
                changes['lines_added'] += 1
            elif line.startswith('-') and not line.startswith('---'):
                changes['lines_removed'] += 1
        
        # Check for HTML structure changes
        if '<html' in baseline_response.lower() or '<html' in test_response.lower():
            # Basic HTML structure comparison
            baseline_tags = re.findall(r'<(\w+)', baseline_response, re.IGNORECASE)
            test_tags = re.findall(r'<(\w+)', test_response, re.IGNORECASE)
            
            if set(baseline_tags) != set(test_tags):
                changes['html_structure_changed'] = True
        
        # Check for JSON structure changes
        try:
            baseline_json = json.loads(baseline_response)
            test_json = json.loads(test_response)
            
            if self._get_json_structure(baseline_json) != self._get_json_structure(test_json):
                changes['json_structure_changed'] = True
                
        except (json.JSONDecodeError, TypeError):
            pass  # Not JSON or invalid JSON
        
        return changes
    
    def _get_json_structure(self, obj: Any, max_depth: int = 3) -> Any:
        """Get JSON structure for comparison (types and keys only)."""
        if max_depth <= 0:
            return type(obj).__name__
        
        if isinstance(obj, dict):
            return {key: self._get_json_structure(value, max_depth - 1) 
                   for key, value in obj.items()}
        elif isinstance(obj, list):
            if obj:
                return [self._get_json_structure(obj[0], max_depth - 1)]
            else:
                return []
        else:
            return type(obj).__name__
    
    def compare_responses(self, baseline_response: Dict[str, Any], 
                         test_response: Dict[str, Any],
                         error_signatures: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        """Comprehensive response comparison."""
        comparison = {
            'text_similarity': 0.0,
            'header_similarity': 0.0,
            'status_code_change': False,
            'timing_delta': 0.0,
            'content_changes': {},
            'error_signatures': [],
            'indicators': [],
            'confidence_factors': {}
        }
        
        # Extract response data
        baseline_text = baseline_response.get('text', '')
        test_text = test_response.get('text', '')
        baseline_headers = baseline_response.get('headers', {})
        test_headers = test_response.get('headers', {})
        baseline_status = baseline_response.get('status_code', 0)
        test_status = test_response.get('status_code', 0)
        baseline_time = baseline_response.get('elapsed', 0.0)
        test_time = test_response.get('elapsed', 0.0)
        
        # Calculate similarities
        comparison['text_similarity'] = self.calculate_text_similarity(baseline_text, test_text)
        comparison['header_similarity'] = self.calculate_header_similarity(baseline_headers, test_headers)
        
        # Status code change
        if baseline_status != test_status:
            comparison['status_code_change'] = True
            comparison['indicators'].append('status_changed')
        
        # Timing delta
        comparison['timing_delta'] = self.calculate_timing_delta(baseline_time, test_time)
        
        # Content changes
        comparison['content_changes'] = self.detect_content_changes(baseline_text, test_text)
        
        # Error signatures
        if error_signatures:
            test_signatures = self.find_error_signatures(test_text, error_signatures)
            baseline_signatures = self.find_error_signatures(baseline_text, error_signatures)
            
            # New error signatures in test response
            new_signatures = [sig for sig in test_signatures if sig not in baseline_signatures]
            comparison['error_signatures'] = new_signatures
            
            if new_signatures:
                comparison['indicators'].append('error_signature')
        
        # Detect significant body differences
        if comparison['text_similarity'] < 0.8:
            comparison['indicators'].append('body_diff')
        
        # Detect timing anomalies (threshold: 2+ seconds)
        if comparison['timing_delta'] > 2.0:
            comparison['indicators'].append('timing_anomaly')
        
        # Detect header changes
        if comparison['header_similarity'] < 0.9:
            comparison['indicators'].append('header_change')
        
        # Calculate confidence factors
        comparison['confidence_factors'] = {
            'low_similarity': comparison['text_similarity'] < 0.7,
            'status_change': comparison['status_code_change'],
            'timing_delay': comparison['timing_delta'] > 1.0,
            'error_signatures_found': len(comparison['error_signatures']) > 0,
            'structural_changes': (
                comparison['content_changes'].get('html_structure_changed', False) or
                comparison['content_changes'].get('json_structure_changed', False)
            )
        }
        
        return comparison
    
    def analyze_response_patterns(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns across multiple responses."""
        if len(responses) < 2:
            return {'error': 'Need at least 2 responses for pattern analysis'}
        
        analysis = {
            'total_responses': len(responses),
            'status_codes': {},
            'timing_stats': {},
            'length_stats': {},
            'similarity_matrix': [],
            'outliers': []
        }
        
        # Collect stats
        status_codes = [r.get('status_code', 0) for r in responses]
        timings = [r.get('elapsed', 0.0) for r in responses]
        lengths = [len(r.get('text', '')) for r in responses]
        
        # Status code distribution
        for code in status_codes:
            analysis['status_codes'][code] = analysis['status_codes'].get(code, 0) + 1
        
        # Timing statistics
        if timings:
            mean_timing = sum(timings) / len(timings)
            variance_timing = sum((x - mean_timing) ** 2 for x in timings) / len(timings)
            std_timing = variance_timing ** 0.5 if len(timings) > 1 else 0.0
            
            analysis['timing_stats'] = {
                'mean': mean_timing,
                'min': min(timings),
                'max': max(timings),
                'std': std_timing
            }
        
        # Length statistics
        if lengths:
            mean_length = sum(lengths) / len(lengths)
            variance_length = sum((x - mean_length) ** 2 for x in lengths) / len(lengths)
            std_length = variance_length ** 0.5 if len(lengths) > 1 else 0.0
            
            analysis['length_stats'] = {
                'mean': mean_length,
                'min': min(lengths),
                'max': max(lengths),
                'std': std_length
            }
        
        # Similarity matrix (for first 10 responses to avoid performance issues)
        sample_responses = responses[:10]
        for i, resp1 in enumerate(sample_responses):
            row = []
            for j, resp2 in enumerate(sample_responses):
                if i == j:
                    row.append(1.0)
                else:
                    similarity = self.calculate_text_similarity(
                        resp1.get('text', ''), resp2.get('text', '')
                    )
                    row.append(similarity)
            analysis['similarity_matrix'].append(row)
        
        # Detect outliers (responses significantly different from others)
        if len(responses) >= 3:
            avg_similarities = []
            for i, resp in enumerate(responses[:10]):  # Limit for performance
                similarities = []
                for j, other_resp in enumerate(responses[:10]):
                    if i != j:
                        sim = self.calculate_text_similarity(
                            resp.get('text', ''), other_resp.get('text', '')
                        )
                        similarities.append(sim)
                
                if similarities:
                    avg_sim = sum(similarities) / len(similarities)
                    avg_similarities.append((i, avg_sim))
            
            # Find outliers (responses with low average similarity to others)
            if avg_similarities:
                mean_avg_sim = sum(sim for _, sim in avg_similarities) / len(avg_similarities)
                threshold = mean_avg_sim - 0.2  # Outlier threshold
                
                for idx, avg_sim in avg_similarities:
                    if avg_sim < threshold:
                        analysis['outliers'].append({
                            'response_index': idx,
                            'average_similarity': avg_sim,
                            'reason': 'Low similarity to other responses'
                        })
        
        return analysis 