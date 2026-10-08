"""
CYBERGUARD Account Security Risk Scoring Engine

Calculates a normalized, transparent risk score (0-100) and risk level classification
(SAFE, LOW, MEDIUM, HIGH, CRITICAL) for account takeover and authentication anomaly
indicators using category-capped aggregation and multi-vector synergy bonuses.

SCORING METHODOLOGY & PRINCIPLES:
1. Category-Capped Aggregation:
   - Prevents score inflation from repeated triggers in the same category.
   - Categories: brute_force, unusual_location, unknown_device, password_reset,
     mfa_manipulation, session_anomaly, impossible_travel, privilege_escalation.
2. Multi-Vector Synergy:
   - High (70+) and Critical (90+) ratings require multiple independent categories.
   - Synergy bonuses when brute-force + location anomaly, or MFA + privilege escalation co-occur.
3. Risk Levels:
   - SAFE: 0 to 19
   - LOW: 20 to 39
   - MEDIUM: 40 to 69
   - HIGH: 70 to 89
   - CRITICAL: 90 to 100
4. Heuristic Transparency:
   - All scores are derived from observable telemetry patterns.
   - This is an advisory heuristic, not a confirmed breach determination.
"""

from typing import Dict, List, Tuple, Any

ACCOUNT_SECURITY_CATEGORY_CAPS: Dict[str, int] = {
    "brute_force": 40,
    "unusual_location": 30,
    "unknown_device": 25,
    "password_reset": 30,
    "mfa_manipulation": 35,
    "session_anomaly": 35,
    "impossible_travel": 35,
    "privilege_escalation": 30,
}

ACCOUNT_SECURITY_RISK_LEVELS: List[Tuple[int, int, str]] = [
    (0, 19, "SAFE"),
    (20, 39, "LOW"),
    (40, 69, "MEDIUM"),
    (70, 89, "HIGH"),
    (90, 100, "CRITICAL"),
]


def calculate_account_security_risk_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes a clamped risk score (0-100) and risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
    from detected account security indicators with category capping and multi-vector synergy.
    """
    if not indicators:
        return 0, "SAFE"

    category_scores: Dict[str, int] = {}
    seen_indicators = set()

    for item in indicators:
        indicator_name = item.get("indicator", "")
        if indicator_name in seen_indicators:
            continue
        seen_indicators.add(indicator_name)

        category = item.get("category", "generic")
        weight = int(item.get("weight", 10))
        cap = ACCOUNT_SECURITY_CATEGORY_CAPS.get(category, 25)

        current_val = category_scores.get(category, 0)
        category_scores[category] = min(cap, current_val + weight)

    raw_sum = sum(category_scores.values())

    # Multi-Vector Synergy Bonuses:

    # 1. Brute-force + Unusual location / Impossible travel
    has_brute_force = "brute_force" in category_scores
    has_location_anomaly = (
        "unusual_location" in category_scores or
        "impossible_travel" in category_scores
    )
    if has_brute_force and has_location_anomaly:
        raw_sum += 10

    # 2. MFA manipulation + Session anomaly (ATO in progress)
    has_mfa_issue = "mfa_manipulation" in category_scores
    has_session_issue = "session_anomaly" in category_scores
    if has_mfa_issue and has_session_issue:
        raw_sum += 10

    # 3. Password reset + MFA manipulation (recovery chain attack)
    has_password_reset = "password_reset" in category_scores
    if has_password_reset and has_mfa_issue:
        raw_sum += 10

    # 4. Privilege escalation combined with any credential compromise vector
    has_priv_esc = "privilege_escalation" in category_scores
    if has_priv_esc and (has_brute_force or has_mfa_issue or has_session_issue):
        raw_sum += 5

    # 5. Unknown device + Unusual location (foreign access)
    has_unknown_device = "unknown_device" in category_scores
    if has_unknown_device and has_location_anomaly:
        raw_sum += 5

    # Strict clamping between 0 and 100
    final_score = max(0, min(100, raw_sum))

    # Determine risk level
    risk_level = "SAFE"
    for min_val, max_val, label in ACCOUNT_SECURITY_RISK_LEVELS:
        if min_val <= final_score <= max_val:
            risk_level = label
            break

    return final_score, risk_level
