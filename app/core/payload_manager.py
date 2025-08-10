"""
Payload Manager for R.A.I.D Scanner
Handles parameterized payload templates and safe payload generation
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template
from datetime import datetime


class PayloadManager:
    """Manages payload templates and safe payload generation."""
    
    def __init__(self, templates_file: str = "app/data/payload_templates.json"):
        self.templates_file = Path(templates_file)
        self.templates: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
        # Refusal log for tracking bypass attempts
        self.refusal_log = Path("refusal.log")
    
    async def load_templates(self) -> bool:
        """Load payload templates from JSON file."""
        try:
            if not self.templates_file.exists():
                self.logger.warning(f"Payload templates file not found: {self.templates_file}")
                # Create default templates
                await self._create_default_templates()
                return False
            
            with open(self.templates_file, 'r', encoding='utf-8') as f:
                self.templates = json.load(f)
            
            self.logger.info(f"Loaded {len(self.templates)} payload templates")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading payload templates: {e}")
            return False
    
    async def _create_default_templates(self):
        """Create default payload templates with safe placeholders."""
        default_templates = {
            "sql_basic_test": {
                "template": "<SQL_TEST_MARKER>",
                "mode": "lab",
                "category": "sql_injection",
                "description": "Basic SQL injection test marker",
                "parameters": ["value"],
                "safe_replacement": "test_value_123"
            },
            "xss_basic_test": {
                "template": "<XSS_TEST_MARKER>",
                "mode": "lab", 
                "category": "xss",
                "description": "Basic XSS test marker",
                "parameters": ["value"],
                "safe_replacement": "test_script_tag"
            },
            "lfi_basic_test": {
                "template": "<LFI_TEST_MARKER>",
                "mode": "lab",
                "category": "lfi",
                "description": "Basic LFI test marker",
                "parameters": ["file"],
                "safe_replacement": "test_file_path"
            },
            "time_based_test": {
                "template": "<TIME_TEST_MARKER>",
                "mode": "lab",
                "category": "timing",
                "description": "Time-based injection test marker",
                "parameters": ["delay"],
                "safe_replacement": "test_delay_marker"
            },
            "command_test": {
                "template": "<COMMAND_TEST_MARKER>",
                "mode": "lab",
                "category": "command_injection",
                "description": "Command injection test marker",
                "parameters": ["command"],
                "safe_replacement": "test_command_marker"
            }
        }
        
        # Ensure directory exists
        self.templates_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save default templates
        with open(self.templates_file, 'w', encoding='utf-8') as f:
            json.dump(default_templates, f, indent=2)
        
        self.templates = default_templates
        self.logger.info("Created default payload templates")
    
    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific payload template."""
        return self.templates.get(template_id)
    
    def get_templates_by_category(self, category: str) -> Dict[str, Any]:
        """Get all templates for a specific category."""
        return {
            tid: template for tid, template in self.templates.items()
            if template.get("category") == category
        }
    
    def get_templates_by_mode(self, mode: str) -> Dict[str, Any]:
        """Get templates compatible with the specified mode."""
        compatible_templates = {}
        
        for template_id, template in self.templates.items():
            template_mode = template.get("mode", "safe")
            
            # Check mode compatibility
            if template_mode == "both" or template_mode == mode:
                compatible_templates[template_id] = template
            elif mode == "audit" and template_mode in ["safe", "lab"]:
                compatible_templates[template_id] = template
            elif mode == "lab" and template_mode == "safe":
                compatible_templates[template_id] = template
        
        return compatible_templates
    
    def render_payload(self, 
                      template_id: str, 
                      parameters: Dict[str, Any], 
                      mode: str = "safe") -> Optional[str]:
        """Render a payload from template with parameters."""
        template_data = self.get_template(template_id)
        if not template_data:
            self.logger.error(f"Template not found: {template_id}")
            return None
        
        # Check mode compatibility
        template_mode = template_data.get("mode", "safe")
        if not self._is_mode_compatible(template_mode, mode):
            self.logger.warning(f"Template {template_id} not compatible with mode {mode}")
            return None
        
        try:
            # In safe mode, use safe replacements and never return dangerous strings
            if mode == "safe":
                return template_data.get("safe_replacement", "SAFE_TEST_VALUE")
            
            # In lab/audit mode, still use placeholders but allow more realistic tests
            template_str = template_data["template"]
            
            # Use Jinja2 for template rendering if needed
            if "{{" in template_str and "}}" in template_str:
                template = Template(template_str)
                return template.render(**parameters)
            
            # Simple placeholder replacement
            rendered = template_str
            for param, value in parameters.items():
                placeholder = f"<{param.upper()}>"
                if placeholder in rendered:
                    rendered = rendered.replace(placeholder, str(value))
            
            # Validate safety for current mode
            if not self.validate_payload_safety(rendered, mode):
                self.log_refusal(
                    reason="Rendered payload deemed unsafe for current mode",
                    requested_payload=rendered,
                    user_context=f"template={template_id}, mode={mode}"
                )
                return template_data.get("safe_replacement", "SAFE_TEST_VALUE")
            return rendered
            
        except Exception as e:
            self.logger.error(f"Error rendering template {template_id}: {e}")
            return None
    
    def _is_mode_compatible(self, template_mode: str, current_mode: str) -> bool:
        """Check if template mode is compatible with current scan mode."""
        if template_mode == "both":
            return True
        if template_mode == current_mode:
            return True
        if current_mode == "audit" and template_mode in ["safe", "lab"]:
            return True
        if current_mode == "lab" and template_mode == "safe":
            return True
        return False
    
    def generate_safe_variants(self, base_value: str, test_type: str) -> List[str]:
        """Generate safe test variants for input validation testing."""
        variants = []
        
        if test_type == "sql":
            # Safe SQL test markers
            variants = [
                base_value + "SQLTEST",
                base_value + "'SQLTEST",
                base_value + "\"SQLTEST",
                base_value + "/*SQLTEST*/",
                base_value + ";SQLTEST--"
            ]
        
        elif test_type == "xss":
            # Safe XSS test markers
            variants = [
                base_value + "<XSSTEST>",
                base_value + "javascript:XSSTEST",
                base_value + "onload=XSSTEST",
                base_value + "\"><XSSTEST>",
                base_value + "'><XSSTEST>"
            ]
        
        elif test_type == "lfi":
            # Safe LFI test markers
            variants = [
                base_value + "../LFITEST",
                base_value + "..\\LFITEST",
                base_value + "/etc/LFITEST",
                base_value + "C:\\LFITEST",
                base_value + "file://LFITEST"
            ]
        
        elif test_type == "command":
            # Safe command injection markers
            variants = [
                base_value + ";CMDTEST",
                base_value + "|CMDTEST",
                base_value + "&CMDTEST",
                base_value + "&&CMDTEST",
                base_value + "`CMDTEST`"
            ]
        
        else:
            # Generic test variants
            variants = [
                base_value + "TEST",
                base_value + "'TEST",
                base_value + "\"TEST",
                base_value + "<TEST>",
                base_value + ";TEST"
            ]
        
        return variants
    
    def log_refusal(self, reason: str, requested_payload: str, user_context: str = ""):
        """Log payload refusal for security monitoring."""
        try:
            with open(self.refusal_log, 'a', encoding='utf-8') as f:
                log_entry = {
                    "timestamp": str(datetime.now()),
                    "reason": reason,
                    "requested_payload": requested_payload,
                    "user_context": user_context
                }
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            self.logger.error(f"Error logging refusal: {e}")
    
    def refuse_exploit_request(self, requested_payload: str, context: str = ""):
        """Refuse to provide exploit payloads and log the refusal."""
        refusal_message = (
            "REFUSAL: Cannot provide actual exploit payloads for public targets. "
            "Use lab mode with containerized vulnerable applications for testing. "
            "See docker/docker-compose.lab.yml for safe testing environment."
        )
        
        self.log_refusal(
            reason="Exploit payload requested for public target",
            requested_payload=requested_payload,
            user_context=context
        )
        
        self.logger.warning(f"Refused exploit request: {requested_payload}")
        return refusal_message
    
    def get_lab_payload_examples(self, category: str) -> Dict[str, str]:
        """Get example payloads for lab environment only."""
        # These are only provided for lab/educational purposes
        lab_examples = {
            "sql": {
                "basic_test": "' OR '1'='1",
                "union_test": "' UNION SELECT NULL--",
                "time_test": "'; WAITFOR DELAY '00:00:05'--",
                "error_test": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            },
            "xss": {
                "basic_test": "<script>alert('XSS')</script>",
                "img_test": "<img src=x onerror=alert('XSS')>",
                "svg_test": "<svg onload=alert('XSS')>",
                "event_test": "javascript:alert('XSS')"
            },
            "lfi": {
                "linux_test": "../../../../etc/passwd",
                "windows_test": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "php_filter": "php://filter/convert.base64-encode/resource=index.php",
                "null_byte": "../../../../etc/passwd%00"
            },
            "command": {
                "linux_test": "; id",
                "windows_test": "& dir",
                "pipe_test": "| whoami",
                "background_test": "; sleep 5 &"
            }
        }
        
        return lab_examples.get(category, {})
    
    def validate_payload_safety(self, payload: str, mode: str) -> bool:
        """Validate that payload is safe for the current mode."""
        if mode == "safe":
            # In safe mode, only allow test markers
            dangerous_patterns = [
                "<script", "javascript:", "onerror=", "onload=",
                "union select", "waitfor delay", "sleep(",
                "../", "..\\", "/etc/", "C:\\",
                "|", "&&", ";", "`",
            ]
            
            payload_lower = payload.lower()
            for pattern in dangerous_patterns:
                if pattern in payload_lower:
                    return False
        
        return True
    
    def get_template_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded templates."""
        stats = {
            "total_templates": len(self.templates),
            "by_category": {},
            "by_mode": {}
        }
        
        for template_id, template in self.templates.items():
            # Count by category
            category = template.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # Count by mode
            mode = template.get("mode", "safe")
            stats["by_mode"][mode] = stats["by_mode"].get(mode, 0) + 1
        
        return stats 