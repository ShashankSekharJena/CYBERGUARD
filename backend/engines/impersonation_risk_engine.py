"""
CYBERGUARD Impersonation Risk Scoring Engine

Calculates a normalized, transparent risk score (0-100) and severity classification
(SAFE, LOW, MEDIUM, HIGH, CRITICAL) for digital impersonation attempts based on
detected heuristic indicators.

SCORING METHODOLOGY & PRINCIPLES:
1. Category-Capped Aggregation:
   - Prevents score inflation from repeated trigger phrases.
   - Categories: authority_impersonation, executive_impersonation, fake_support,
     brand_mention, sender_mismatch, sender_identity, financial_solicitation,
     data_solicitation, coercive_urgency, lookalike_domain.
2. Single-Keyword Safeguard:
   - High (70+) and Critical (90+) ratings require multi-vector indicators
     (e.g., impersonated authority/brand + credential/financial solicitation + sender mismatch).
3. Risk Levels:
   - SAFE: 0 to 19
   - LOW: 20 to 39
   - MEDIUM: 40 to 69
   - HIGH: 70 to 89
   - CRITICAL: 90 to 100
4. Heuristic Transparency:
   - Outputs heuristic metrics derived from observable telemetry patterns,
     clarifying that this is an advisory heuristic indicator and not guaranteed identity verification.
"""

from typing import Dict, List, Tuple, Any

IMPERSONATION_CATEGORY_CAPS: Dict[str, int] = {
    "authority_impersonation": 30,
    "executive_impersonation": 25,
    "fake_support": 20,
    "brand_mention": 15,
    "sender_mismatch": 35,
    "sender_identity": 15,
    "financial_solicitation": 30,
    "data_solicitation": 30,
    "coercive_urgency": 25,
    "lookalike_domain": 35,
}

IMPERSONATION_RISK_LEVELS: List[Tuple[int, int, str]] = [
    (0, 19, "SAFE"),
    (20, 39, "LOW"),
    (40, 69, "MEDIUM"),
    (70, 89, "HIGH"),
    (90, 100, "CRITICAL"),
]


def calculate_impersonation_risk_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes a clamped risk score (0-100) and risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
    from detected impersonation indicators with category capping and multi-vector synergy.
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
        cap = IMPERSONATION_CATEGORY_CAPS.get(category, 25)

        current_val = category_scores.get(category, 0)
        category_scores[category] = min(cap, current_val + weight)

    raw_sum = sum(category_scores.values())

    # Multi-Vector Synergy Bonuses:
    # 1. Official/Executive Persona + Sender Mismatch
    has_identity_claim = (
        "authority_impersonation" in category_scores or
        "executive_impersonation" in category_scores or
        "brand_mention" in category_scores or
        "fake_support" in category_scores
    )
    has_sender_anomaly = (
        "sender_mismatch" in category_scores or
        "lookalike_domain" in category_scores
    )
    if has_identity_claim and has_sender_anomaly:
        raw_sum += 10

    # 2. Impersonation + Direct Asset/Credential Solicitation (OTP, password, wire, gift card)
    has_solicitation = (
        "financial_solicitation" in category_scores or
        "data_solicitation" in category_scores
    )
    if has_identity_claim and has_solicitation:
        raw_sum += 10

    # 3. Urgency / Coercive threat combined with solicitation
    if "coercive_urgency" in category_scores and has_solicitation:
        raw_sum += 5

    # Strict clamping between 0 and 100
    final_score = max(0, min(100, raw_sum))

    # Determine risk level based on standard ranges
    risk_level = "SAFE"
    for min_val, max_val, label in IMPERSONATION_RISK_LEVELS:
        if min_val <= final_score <= max_val:
            risk_level = label
            break

    return final_score, risk_level
