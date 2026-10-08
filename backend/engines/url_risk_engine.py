"""
CYBERGUARD URL, Domain & IP Risk Scoring Engine

Calculates a normalized, transparent risk score (0-100) and risk level classification
for analyzed URLs, domains, and IP addresses based on detected heuristic threat patterns.

SCORING METHODOLOGY:
1. Category-Capped Aggregation:
   Threat categories have hard contribution caps to prevent repetitive patterns
   from causing unbounded score inflation.
2. Multi-Vector Synergy Bonus:
   When high-risk vectors coincide (e.g. IP host, brand lookalike, or punycode combined with
   credential keywords or HTTP transport), a synergistic weighting bonus is applied.
3. Transparent Risk Levels:
   - 0  to 19  -> SAFE
   - 20 to 39  -> LOW
   - 40 to 69  -> MEDIUM
   - 70 to 89  -> HIGH
   - 90 to 100 -> CRITICAL
4. Heuristic Boundary Disclosure:
   The calculated risk score represents observable heuristic indicators and anomalous structures,
   NOT a definitive verdict or proof that an entity is malicious without external reputation context.
"""

from typing import Dict, List, Tuple, Any

URL_CATEGORY_CAPS: Dict[str, int] = {
    "scheme": 35,
    "ip_host": 30,
    "shortener": 20,
    "subdomains": 20,
    "suspicious_keywords": 25,
    "url_structure": 30,
    "suspicious_tld": 15,
    "url_length": 15,
    "encoding_obfuscation": 15,
    "lookalike_domain": 30,
    "punycode": 25,
    "domain_structure": 20,
    "ip_address": 10,
    "validation_error": 0,
}

URL_RISK_LEVELS: List[Tuple[int, int, str]] = [
    (0, 19, "SAFE"),
    (20, 39, "LOW"),
    (40, 69, "MEDIUM"),
    (70, 89, "HIGH"),
    (90, 100, "CRITICAL"),
]


def calculate_url_risk_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Computes a clamped risk score (0-100) and risk level from URL/Domain/IP indicators.
    Applies category caps and synergy rules.
    """
    if not indicators:
        return 0, "SAFE"

    category_scores: Dict[str, int] = {}
    seen_indicators = set()

    for item in indicators:
        name = item.get("indicator", "")
        if name in seen_indicators:
            continue
        seen_indicators.add(name)

        category = item.get("category", "generic")
        weight = int(item.get("weight", 10))
        cap = URL_CATEGORY_CAPS.get(category, 25)

        current = category_scores.get(category, 0)
        category_scores[category] = min(cap, current + weight)

    raw_sum = sum(category_scores.values())

    # Multi-vector synergy: suspicious keywords combined with suspicious host, lookalike, punycode, or deceptive syntax
    has_keywords = "suspicious_keywords" in category_scores
    has_suspicious_host = (
        "ip_host" in category_scores or
        "lookalike_domain" in category_scores or
        "url_structure" in category_scores or
        "suspicious_tld" in category_scores or
        "punycode" in category_scores or
        "domain_structure" in category_scores
    )

    if has_keywords and has_suspicious_host:
        raw_sum += 10

    # Clamping between 0 and 100
    final_score = max(0, min(100, raw_sum))

    # Determine risk level
    risk_level = "SAFE"
    for min_val, max_val, label in URL_RISK_LEVELS:
        if min_val <= final_score <= max_val:
            risk_level = label
            break

    return final_score, risk_level
