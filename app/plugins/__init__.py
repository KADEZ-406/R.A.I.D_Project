"""
R.A.I.D Security Plugins
Collection of security testing plugins for various vulnerability categories
"""

# Import available plugins
from . import (
    banner_grab,
    exposed_files,
    health_header_check,
    sqli_heuristic,
    xss_heuristic,
    plugin_generator
)

__all__ = [
    "banner_grab",
    "exposed_files", 
    "health_header_check",
    "sqli_heuristic",
    "xss_heuristic",
    "plugin_generator"
]

# Plugin metadata for discovery
AVAILABLE_PLUGINS = {
    "banner_grab": "Service banner and version detection",
    "exposed_files": "Detection of exposed sensitive files",
    "health_header_check": "Security headers analysis",
    "sqli_heuristic": "SQL injection vulnerability detection",
    "xss_heuristic": "Cross-site scripting vulnerability detection"
} 