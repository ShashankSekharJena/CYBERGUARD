"""
CYBERGUARD Account Security Response Engine

Generates tailored, actionable security recommendations and response protocols
based on detected account security categories and severity levels.

IMPORTANT: Recommendations are advisory only. This engine does NOT perform
actual account locking, password resets, or MFA changes.
"""

from typing import Dict, List, Any


def generate_account_security_recommended_actions(
    indicators: List[Dict[str, Any]],
    risk_level: str
) -> List[str]:
    """
    Generates tailored, actionable response recommendations based on detected
    account security categories and computed risk level.
    """
    actions: List[str] = []
    categories = {item.get("category") for item in indicators}

    # Critical / High severity — immediate defensive posture
    if risk_level in ["HIGH", "CRITICAL"]:
        actions.append(
            "IMMEDIATE: Review all active sessions and terminate any unrecognized sessions through your account security dashboard."
        )
        actions.append(
            "Reset your password immediately through official channels only. Do NOT use links from unsolicited messages."
        )
        if risk_level == "CRITICAL":
            actions.append(
                "Consider temporarily locking the account through your organization's security administrator until forensic review is completed."
            )

    # Category-specific recommendations
    if "brute_force" in categories:
        actions.append(
            "Implement account lockout policies or progressive CAPTCHA challenges after repeated failed login attempts."
        )
        actions.append(
            "Check if the account credentials have been exposed in known data breaches using authorized breach monitoring services."
        )

    if "unusual_location" in categories:
        actions.append(
            "Verify whether the reported login location matches expected user geography. Investigate any unexpected foreign login origins."
        )

    if "impossible_travel" in categories:
        actions.append(
            "Investigate the login timeline for impossible travel — concurrent logins from geographically distant locations require immediate credential revocation."
        )

    if "unknown_device" in categories:
        actions.append(
            "Review registered devices for the account and remove any unrecognized device enrollments."
        )

    if "password_reset" in categories:
        actions.append(
            "Confirm that any password reset requests were initiated by the legitimate account holder. Review recovery email and phone number for unauthorized changes."
        )

    if "mfa_manipulation" in categories:
        actions.append(
            "Enable or re-enable multi-factor authentication (MFA) using a hardware security key or TOTP authenticator app. Avoid SMS-based MFA where possible."
        )
        actions.append(
            "Investigate any MFA disabling events or SIM swap indicators with your telecom provider."
        )

    if "session_anomaly" in categories:
        actions.append(
            "Invalidate all existing session tokens and force re-authentication across all devices."
        )
        actions.append(
            "Review access logs for session replay or cookie theft indicators and rotate session secrets."
        )

    if "privilege_escalation" in categories:
        actions.append(
            "Contact the security administrator to audit recent privilege changes and verify authorization through change management records."
        )
        actions.append(
            "Review administrative audit logs for unauthorized role assignments or permission grants."
        )

    # General recommendations for moderate risk without specific high-severity categories
    if not actions:
        if risk_level == "SAFE":
            actions.append(
                "No immediate account security threats detected. Continue following organizational security protocols."
            )
            actions.append(
                "Ensure multi-factor authentication (MFA) is enabled and recovery contact information is current."
            )
        else:
            actions.append(
                "Review recent account login history and verify all sessions are legitimate."
            )
            actions.append(
                "Enable multi-factor authentication (MFA) if not already active."
            )

    # Always include as final recommendation for non-SAFE
    if risk_level != "SAFE":
        actions.append(
            "Report suspicious activity to your organization's IT security team or security administrator for further investigation."
        )

    # Deduplicate while preserving order
    unique_actions: List[str] = []
    for act in actions:
        if act not in unique_actions:
            unique_actions.append(act)

    return unique_actions
