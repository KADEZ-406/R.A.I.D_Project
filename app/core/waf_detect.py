"""
WAF Detection module.

Provides simple fingerprinting based on headers and body tokens.
"""

from __future__ import annotations

import re
from typing import Dict


WAF_SIGNATURES = [
    {
        "name": "Cloudflare",
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "body": [r"Attention Required!|Cloudflare"],
    },
    {
        "name": "Akamai",
        "headers": ["akamai-ghost"],
        "body": [r"Reference#[0-9a-f]{8}"],
    },
    {
        "name": "Sucuri",
        "headers": ["x-sucuri-id"],
        "body": [r"Sucuri WebSite Firewall"],
    },
]


def detect_waf(headers: Dict[str, str], body_text: str) -> Dict:
    headers_lower = {k.lower(): v.lower() for k, v in (headers or {}).items()}
    text = body_text or ""

    best = {"waf_name": None, "confidence": 0.0, "advice": "standard"}

    for sig in WAF_SIGNATURES:
        score = 0
        for h in sig["headers"]:
            key = h.split(":")[0]
            if key in headers_lower and (":" not in h or h.split(":", 1)[1].strip() in headers_lower.get(key, "")):
                score += 1
        for pattern in sig["body"]:
            if re.search(pattern, text, re.I):
                score += 1

        if score >= 2 and score > best["confidence"] * 3:
            best = {
                "waf_name": sig["name"],
                "confidence": min(1.0, score / 3.0),
                "advice": "conservative",
            }

    return best


