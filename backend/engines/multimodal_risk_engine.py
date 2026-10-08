"""
CYBERGUARD Multimodal Risk Engine

Calculates risk score (0-100) and severity rating from multimodal forensic indicators.
"""

from typing import List, Dict, Any, Tuple


def calculate_multimodal_risk(indicators: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes heuristic risk score and severity based on forensic indicators.
    """
    if not indicators:
        return 0, "SAFE"

    raw_score = 0
    for ind in indicators:
        weight = ind.get("weight", 0)
        raw_score += weight

    clamped_score = max(0, min(100, raw_score))

    if clamped_score >= 80:
        severity = "CRITICAL"
    elif clamped_score >= 60:
        severity = "HIGH"
    elif clamped_score >= 35:
        severity = "MEDIUM"
    elif clamped_score >= 15:
        severity = "LOW"
    else:
        severity = "SAFE"

    return clamped_score, severity
