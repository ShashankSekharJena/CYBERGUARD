"""
CYBERGUARD URL, Domain & IP Response Engine

Generates actionable, evidence-based safety recommendations based on detected
indicators, input type, and calculated risk level.
"""

from typing import Dict, List, Any


def generate_url_recommended_actions(
    indicators: List[Dict[str, Any]],
    risk_level: str,
    input_type: str = "url"
) -> List[str]:
    """
    Generates actionable safety precautions based on detected telemetry patterns.
    """
    actions: List[str] = []
    categories = {item.get("category", "") for item in indicators}
    indicator_names = {item.get("indicator", "") for item in indicators}

    # Validation errors
    if "validation_error" in categories:
        return [
            f"Verify the formatting of the submitted {input_type} string.",
            "Ensure the domain name includes a valid top-level domain (e.g., .com, .org) or valid IPv4/IPv6 syntax.",
            "Check for illegal punctuation, typographical errors, or trailing delimiters."
        ]

    # Safe / No indicators
    if risk_level == "SAFE" or not indicators:
        return [
            f"Target {input_type} appears structurally standard based on observable characteristics.",
            "Always verify domain spelling directly through official sources before submitting credentials.",
            "Ensure browser displays a valid HTTPS padlock when entering sensitive information.",
            "Exercise standard vigilance when following links from unsolicited messages."
        ]

    # Primary precautions for elevated risk
    if risk_level in ["HIGH", "CRITICAL"]:
        actions.append("Do not submit credentials, OTPs, or financial information to this destination.")
        actions.append("Verify the domain through an official source before proceeding.")
        actions.append("Investigate if received through an unsolicited message or phishing lure.")
        actions.append("Block or filter the indicator at your security gateway / firewall if authorized.")
    elif risk_level in ["MEDIUM", "LOW"]:
        actions.append("Proceed with caution. Verify the legitimacy of the destination before proceeding.")

    # Punycode / IDN specific recommendation
    if "punycode" in categories or "Punycode / IDN Domain" in indicator_names:
        actions.append("Inspect decoded Unicode representation to verify that characters are not homoglyphs mimicking a legitimate brand.")

    # URL Shortener specific recommendation
    if "shortener" in categories or "URL Shortener Service" in indicator_names:
        actions.append("Use a dedicated URL expansion tool to preview the unshortened destination before visiting.")

    # IP address / Lookalike / Structure specific recommendation
    if categories.intersection({"ip_host", "lookalike_domain", "subdomains", "url_structure", "domain_structure"}):
        actions.append("Navigate to the intended service via trusted bookmarks or official corporate search rather than direct links.")

    # Suspicious Keywords / Credential lure recommendation
    if "suspicious_keywords" in categories or "Suspicious Security Keywords" in indicator_names:
        actions.append("Never enter passwords or personal data on pages reached via unexpected links or unauthorized domains.")

    # Insecure Protocol recommendation
    if "scheme" in categories:
        actions.append("Do not transmit credentials or sensitive telemetry over unencrypted HTTP connections.")

    # SOC Reporting
    if risk_level in ["HIGH", "CRITICAL", "MEDIUM"]:
        actions.append("Report this indicator to your organization's security operations center (SOC).")

    # Deduplicate while preserving order
    deduped: List[str] = []
    seen = set()
    for act in actions:
        if act not in seen:
            seen.add(act)
            deduped.append(act)

    return deduped
