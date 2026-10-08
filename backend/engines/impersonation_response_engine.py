"""
CYBERGUARD Impersonation Response Engine

Generates tailored, actionable safety precautions and response protocols
based on detected impersonation categories and severity levels.
"""

from typing import Dict, List, Any


def generate_impersonation_recommended_actions(
    indicators: List[Dict[str, Any]],
    risk_level: str
) -> List[str]:
    """
    Generates tailored, actionable response recommendations based on detected categories
    and computed risk level.
    """
    actions: List[str] = []
    categories = {item.get("category") for item in indicators}

    if risk_level in ["HIGH", "CRITICAL"]:
        actions.append("DO NOT comply with requested payments, transfers, gift cards, or password resets.")
        actions.append("Do NOT share One-Time Passwords (OTPs), PINs, 2FA codes, or identity documents under any circumstance.")

    if "sender_mismatch" in categories:
        actions.append("Verify sender identity out-of-band using official public directories or confirmed company communication channels.")

    if "authority_impersonation" in categories:
        actions.append("Contact the claimed agency or department directly via their official .gov or verified hotline (never use phone numbers in the message).")

    if "executive_impersonation" in categories:
        actions.append("Execute corporate BEC (Business Email Compromise) verification protocol before initiating any wire transfer, gift card purchase, or data disclosure.")

    if "fake_support" in categories:
        actions.append("Do not grant remote desktop access or provide diagnostic account tokens. Access the organization's official support portal directly.")

    if "lookalike_domain" in categories:
        actions.append("Inspect the exact top-level domain and URL structure for homoglyphs or typosquatting. Do not click links.")

    if "financial_solicitation" in categories:
        actions.append("Flag message for enterprise fraud/compliance review and freeze any pending unverified financial transactions.")

    if not actions:
        if risk_level == "SAFE":
            actions.append("No immediate impersonation indicators detected. Follow standard organizational security protocols.")
            actions.append("Remain cautious when receiving unexpected requests for account updates or confidential files.")
        else:
            actions.append("Exercise caution and independently verify the communication before responding or clicking links.")

    # Deduplicate while preserving order
    unique_actions = []
    for act in actions:
        if act not in unique_actions:
            unique_actions.append(act)

    return unique_actions
