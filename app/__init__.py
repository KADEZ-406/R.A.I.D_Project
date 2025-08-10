"""
R.A.I.D (Reconnaissance and Automated Intrusion Detector)
KADEZ-406 | Security Scanner Framework

A comprehensive security testing framework designed for authorized penetration testing
and vulnerability assessment in controlled environments.

Copyright (c) 2024 KADEZ-406 Team
Licensed under MIT License
"""

__version__ = "1.0.0"
__author__ = "KADEZ-406 Team"
__description__ = "Reconnaissance and Automated Intrusion Detector"

# Ethical usage reminder
ETHICAL_NOTICE = """
⚠️  ETHICAL USAGE ONLY ⚠️
This tool is designed for authorized security testing only.
Unauthorized scanning or testing is illegal and unethical.
Always obtain proper authorization before testing any system.
"""

import logging

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.info("R.A.I.D Scanner Framework Initialized")
logger.warning(ETHICAL_NOTICE) 