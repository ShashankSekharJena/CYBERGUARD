"""
CYBERGUARD Response Engine

Generates actionable, threat-specific security recommendations based on detected
indicators and severity level.

DESIGN PRINCIPLES:
- Recommendations provide practical defense guidance for end-users and security teams.
- Honest scope: Recommendations must NOT claim that the system has already blocked
  a URL or quarantined a message automatically.
"""

from typing import Dict, List, Any


def generate_recommended_actions(
    indicators: List[Dict[str, Any]],
    severity: str
) -> List[str]:
    """
    Generates tailored, actionable mitigation steps based on specific detected indicators
    and computed threat severity.
    """
    actions: List[str] = []
    indicator_names = {item.get("indicator", "") for item in indicators}
    categories = {item.get("category", "") for item in indicators}

    if severity == "SAFE" or not indicators:
        return [
            "No immediate action required. Maintain standard security awareness.",
            "Always inspect URLs carefully before entering login credentials.",
            "Verify unexpected requests through official internal communication channels."
        ]

    # Universal primary warning for suspicious findings
    if severity in ["HIGH", "CRITICAL"]:
        actions.append("Do not click any embedded links or open unexpected attachments.")
    elif severity in ["MEDIUM", "LOW"]:
        actions.append("Treat the message with caution and avoid following unsolicited links.")

    # Specific advice for Credential solicitation
    if "credential_request" in categories or "Credential request" in indicator_names:
        actions.append("Never enter passwords, PINs, or confidential credentials on untrusted pages.")
        actions.append("If you have already submitted credentials, reset your password immediately on the official website.")

    # Specific advice for OTP / MFA solicitation
    if "otp_request" in categories or "OTP/password request" in indicator_names:
        actions.append("Do not share One-Time Passwords (OTPs) or MFA verification codes with anyone.")

    # Specific advice for Domain Mismatch / Lookalikes / Suspicious URLs
    url_threat_categories = {"domain_mismatch", "lookalike_domain", "url_ip", "url_obfuscation", "url_scheme"}
    if categories.intersection(url_threat_categories):
        actions.append("Verify the sender and destination URL independently via bookmarks or official channels.")

    # Specific advice for Urgent / Threatening pressure
    if "urgency" in categories or "threat" in categories:
        actions.append("Do not succumb to artificial urgency; confirm requests with the purported organization directly.")

    # Administrative and reporting guidance
    if severity in ["HIGH", "CRITICAL", "MEDIUM"]:
        actions.append("Report this message to your IT security team or security administrator.")
        actions.append("Quarantine or flag the message if your organization's email client controls permit.")

    # Deduplicate actions while preserving logical order
    deduped_actions: List[str] = []
    seen = set()
    for act in actions:
        if act not in seen:
            seen.add(act)
            deduped_actions.append(act)

    return deduped_actions
