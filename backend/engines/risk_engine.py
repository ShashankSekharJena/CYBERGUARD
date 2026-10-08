"""
CYBERGUARD Risk Scoring Engine

Calculates a normalized, transparent risk score (0-100) and severity classification
based on detected heuristic indicators.

SCORING METHODOLOGY & DESIGN PRINCIPLES:
1. Category-Capped Aggregation:
   Indicators belong to specific threat categories (e.g. urgency, threat,
   credential_request, otp_request, call_to_action, account_verification,
   url_ip, url_obfuscation, url_structure, lookalike_domain, domain_mismatch,
   url_scheme, url_length, url_tld).
   Each category has a maximum contribution cap to prevent repetitive patterns
   from artificially inflating the score.

2. Single Keyword Safeguard:
   No single keyword or indicator alone can push the severity into CRITICAL or HIGH.
   HIGH (70+) and CRITICAL (90+) ratings require multi-vector evidence (e.g.
   credential/OTP harvesting combined with deceptive lookalike URLs or domain mismatches).

3. Transparent Severity Ranges:
   - 0  to 19  -> SAFE
   - 20 to 39  -> LOW
   - 40 to 69  -> MEDIUM
   - 70 to 89  -> HIGH
   - 90 to 100 -> CRITICAL

4. Heuristic Disclosure:
   The risk score is a heuristic risk indicator derived from observable telemetry patterns,
   NOT a mathematically verified probability of maliciousness.
"""

from typing import Dict, List, Tuple, Any

# Maximum points allowed per category to prevent score inflation
CATEGORY_CAPS: Dict[str, int] = {
    "urgency": 15,
    "threat": 18,
    "credential_request": 25,
    "otp_request": 30,
    "call_to_action": 12,
    "account_verification": 15,
    "url_ip": 25,
    "url_obfuscation": 25,
    "url_scheme": 35,
    "url_length": 12,
    "url_structure": 18,
    "url_tld": 10,
    "lookalike_domain": 30,
    "domain_mismatch": 35,
}

SEVERITY_LEVELS: List[Tuple[int, int, str]] = [
    (0, 19, "SAFE"),
    (20, 39, "LOW"),
    (40, 69, "MEDIUM"),
    (70, 89, "HIGH"),
    (90, 100, "CRITICAL"),
]


def calculate_risk_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes a clamped risk score (0-100) and severity rating from detected indicators.
    Deduplicates indicators and applies category caps and multi-vector scaling.
    """
    if not indicators:
        return 0, "SAFE"

    category_scores: Dict[str, int] = {}
    seen_indicators = set()

    for item in indicators:
        indicator_name = item.get("indicator", "")
        # Prevent exact duplicate indicator inflation
        if indicator_name in seen_indicators:
            continue
        seen_indicators.add(indicator_name)

        category = item.get("category", "generic")
        weight = int(item.get("weight", 10))
        cap = CATEGORY_CAPS.get(category, 25)

        current_val = category_scores.get(category, 0)
        # Cap the category contribution
        category_scores[category] = min(cap, current_val + weight)

    raw_sum = sum(category_scores.values())

    # Multi-indicator synergy bonus (if both deceptive link + credential/OTP request are present)
    has_cred_or_otp = "credential_request" in category_scores or "otp_request" in category_scores
    has_bad_url = (
        "domain_mismatch" in category_scores or
        "lookalike_domain" in category_scores or
        "url_ip" in category_scores or
        "url_scheme" in category_scores
    )

    if has_cred_or_otp and has_bad_url:
        raw_sum += 10  # Synergistic high risk when credential lure pairs with suspicious link

    # Strict clamping between 0 and 100
    final_score = max(0, min(100, raw_sum))

    # Determine severity based on documented ranges
    severity = "SAFE"
    for min_val, max_val, label in SEVERITY_LEVELS:
        if min_val <= final_score <= max_val:
            severity = label
            break

    return final_score, severity
