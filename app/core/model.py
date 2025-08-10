"""
Core models for R.A.I.D

Defines central dataclasses and types shared across the engine and plugins.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Finding:
    """Standard Finding object used across plugins and core engine.

    Note: `timestamp` is an ISO8601 string to ease serialization and report generation.
    """

    id: str
    name: str
    plugin: str
    target: str
    endpoint: str
    parameter: Optional[str]
    proof_mode: str  # "safe" or "lab" ("audit" treated as permissive superset internally)
    indicators: List[str]
    evidence: Dict[str, dict]
    severity: str  # Low|Medium|High|Critical (case-insensitive accepted by UI)
    confidence: float  # 0.0 - 100.0
    timestamp: str  # ISO8601 string

    # Optional narrative fields
    description: str = ""
    recommendation: str = ""
    references: List[str] = None

    def __post_init__(self) -> None:
        # Normalize severity capitalization
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "information": "info",
        }
        sev = (self.severity or "").lower()
        self.severity = severity_map.get(sev, sev or "info")

        # Ensure lists/dicts are at least empty structures
        if self.indicators is None:
            self.indicators = []
        if self.evidence is None:
            self.evidence = {}
        if self.references is None:
            self.references = []

        # Clamp confidence
        try:
            self.confidence = max(0.0, min(100.0, float(self.confidence)))
        except Exception:
            self.confidence = 0.0


