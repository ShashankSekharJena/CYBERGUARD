"""
CYBERGUARD Explanation Engine

Generates transparent, contextual, human-readable explanations of detection findings,
highlighting why specific indicators matter, incorporating ML classification context,
and clarifying heuristic limitations.
"""

from typing import Dict, List, Any, Optional

# Contextual explanations for why each indicator represents a threat vector
INDICATOR_EXPLANATIONS: Dict[str, str] = {
    "Urgent language": "Attackers fabricate artificial deadlines or panic to prevent recipients from critically reviewing the request.",
    "Threatening language": "Coercive threats of account lockout or legal penalties are classic social engineering tactics to force compliance.",
    "Credential request": "Legitimate organizations rarely request passwords or security PINs via unsolicited messages or direct links.",
    "OTP/password request": "One-time passwords (2FA/MFA) bypass multi-factor authentication if relayed to an attacker.",
    "Suspicious call to action": "Unsolicited prompts to click links or claim unexpected rewards frequently lead to credential harvesting or malware.",
    "Account verification request": "Generic account re-verification requests often mimic legitimate security notices to capture credentials.",
    "IP address in URL": "Using an IP address directly in a link bypasses DNS reputation filters and conceals domain ownership.",
    "@ symbol in URL": "The '@' character instructs browsers to treat preceding text as authentication credentials, disguising the true destination host.",
    "Suspicious URL scheme": "Non-standard or scripting URI schemes (e.g. javascript:) can trigger malicious client-side execution.",
    "Excessively long URL": "Unusually long URLs are frequently engineered to hide malicious destination parameters beyond typical display bounds.",
    "Suspicious URL structure": "Excessive sub-domain nesting or excessive hyphenation is commonly used to construct deceptive lookalike web addresses.",
    "Suspicious domain hyphenation": "Multiple hyphens in domain names are frequently used to assemble fake security portal names.",
    "Suspicious top-level domain": "High-abuse generic top-level domains are favored in disposable phishing campaigns due to low acquisition costs.",
    "Possible look-alike domain": "Domain utilizes typosquatting or homoglyph character substitutions to impersonate a reputable brand.",
    "Organization domain mismatch": "The message claims to originate from a known organization, but the destination URL points to an unrelated, unauthorized domain.",
    "Malformed URL": "The URL structure is syntactically invalid or formatted deceptively.",
}


def explain_indicator(indicator_name: str) -> str:
    """Returns why a specific indicator matters from a security standpoint."""
    return INDICATOR_EXPLANATIONS.get(
        indicator_name,
        "This heuristic telemetry pattern is commonly associated with deceptive or unsolicited communications."
    )


def generate_explanation(
    indicators: List[Dict[str, Any]],
    risk_score: int,
    severity: str,
    ml_result: Optional[Dict[str, Any]] = None
) -> str:
    """
    Synthesizes a coherent, honest human-readable explanation of findings,
    reflecting severity, specific indicators, ML text analysis, and heuristic boundaries.
    """
    ml_note = ""
    if ml_result and ml_result.get("available"):
        conf = ml_result.get("confidence", 0.0)
        conf_pct = round(conf * 100, 1) if conf <= 1.0 else round(conf, 1)
        if ml_result.get("is_phishing") or ml_result.get("prediction") == "phishing":
            ml_note = f"ML classifier identifies phishing-like language ({conf_pct}% confidence)."
        elif ml_result.get("prediction") == "legitimate":
            ml_note = f"ML classifier evaluated content as legitimate ({conf_pct}% confidence)."

    if not indicators or risk_score == 0:
        base_msg = (
            "No overt phishing indicators or deceptive patterns were identified in the submitted telemetry. "
            "However, heuristic pattern matching cannot guarantee safety against novel or highly targeted social engineering attacks."
        )
        if ml_note:
            return f"{base_msg} {ml_note}"
        return base_msg

    indicator_names = [item.get("indicator", "Suspicious pattern") for item in indicators]
    joined_names = ", ".join(indicator_names)

    if len(indicators) == 1:
        name = indicator_names[0]
        context = explain_indicator(name)
        base_exp = (
            f"A suspicious indicator was detected: {name} ({context}). "
            f"Overall risk is classified as {severity} ({risk_score}/100). Exercise caution and verify sender identity."
        )
        if ml_note:
            return f"{ml_note} {base_exp}"
        return base_exp

    if severity in ["HIGH", "CRITICAL"]:
        base_exp = (
            f"Multiple high-risk indicators were detected ({joined_names}). "
            f"The combination of coercive language or credential solicitation alongside suspicious destination routing "
            f"strongly indicates a phishing attempt. Heuristic risk score: {risk_score}/100 ({severity})."
        )
    elif severity == "MEDIUM":
        base_exp = (
            f"Multiple suspicious indicators were identified ({joined_names}). "
            f"While not definitively malicious, these patterns match common social engineering vectors. "
            f"Heuristic risk score: {risk_score}/100 ({severity})."
        )
    else:  # LOW
        base_exp = (
            f"Minor suspicious indicators were noted ({joined_names}). "
            f"Calculated risk is {severity} ({risk_score}/100). Review the context before interacting with links or providing details."
        )

    if ml_note:
        return f"{ml_note} {base_exp}"
    return base_exp
