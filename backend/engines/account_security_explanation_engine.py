"""
CYBERGUARD Account Security Explanation Engine

Generates transparent, contextual, human-readable explanations of account security
and authentication anomaly findings, highlighting why specific indicators matter
and clarifying heuristic limitations.
"""

from typing import Dict, List, Any

ACCOUNT_SECURITY_INDICATOR_EXPLANATIONS: Dict[str, str] = {
    "Critical Brute-Force / Credential Stuffing":
        "Ten or more consecutive failed login attempts strongly indicate automated credential stuffing or brute-force password attacks against this account.",
    "Elevated Failed Login Attempts":
        "Five or more consecutive failed logins exceed normal user error patterns and may indicate targeted credential guessing or dictionary attacks.",
    "Multiple Failed Login Attempts":
        "Several failed login attempts were recorded. While occasional login failures are common, repeated failures within a short window warrant monitoring.",
    "High-Risk Geographic Login Origin":
        "The login originated from a geographic region associated with elevated threat actor activity or sanctioned jurisdictions.",
    "Anonymized / Proxied Login Origin":
        "The login source indicates anonymization infrastructure (Tor, VPN, proxy), which conceals the true origin and is commonly used to mask malicious activity.",
    "Anonymized IP Address Detected":
        "The originating IP address shows characteristics of anonymization or proxy services, obscuring the attacker's true network location.",
    "Suspicious / Unknown Device Fingerprint":
        "The device fingerprint exhibits characteristics of automated tools, emulators, or previously unregistered hardware, which is atypical for legitimate account holders.",
    "Password Reset Request Detected":
        "Password recovery or reset events, when unsolicited, may indicate an attacker attempting to seize control of an account via the recovery flow.",
    "Rapid Password Reset Flooding":
        "Multiple rapid password reset requests suggest automated abuse of the recovery mechanism, potentially to overwhelm notification systems or timing-based OTP validation.",
    "Recovery Method Modification":
        "Changes to backup email, recovery phone, or security questions are a common preparatory step before completing an account takeover.",
    "MFA/OTP Bypass Attempt":
        "Attempts to circumvent multi-factor authentication indicate a sophisticated attacker aware of MFA controls and actively seeking evasion.",
    "MFA Interception / SIM Swap Indicator":
        "Patterns consistent with SIM swap attacks or MFA push-bombing, techniques used to intercept one-time codes or fatigue victims into approving malicious authentication requests.",
    "OTP Brute-Force / Token Replay":
        "Rapid OTP submission or token reuse attempts aim to guess or replay valid authentication codes before they expire.",
    "MFA Disabled or Authenticator Removed":
        "Disabling or removing an authenticator weakens account security and is a common post-compromise action to maintain persistent unauthorized access.",
    "Session Hijacking / Cookie Theft Indicator":
        "Session replay, cookie theft, or session fixation allows attackers to impersonate an authenticated user without knowing their credentials.",
    "Concurrent Session Anomaly":
        "Multiple simultaneous active sessions from different geographic locations or devices indicate possible credential sharing or account compromise.",
    "Abnormal Session Termination":
        "Unexpected session invalidation or forced logouts may indicate an attacker forcibly displacing the legitimate user from their active session.",
    "Impossible Travel Detected":
        "Login attempts from geographically distant locations within an impossibly short timeframe indicate credential use from multiple distinct threat actors or infrastructure.",
    "Geographic Location Discrepancy":
        "Rapid transitions between distant geographic regions for the same account are physically implausible and suggest compromised credentials.",
    "Suspicious Privilege Escalation":
        "Unauthorized elevation of account privileges or granting of administrative roles is a critical post-compromise action enabling lateral movement and data exfiltration.",
    "Unauthorized Role Modification":
        "Role or permission changes outside standard administrative workflows may indicate an attacker consolidating control over the compromised account.",
}


def explain_account_security_indicator(name: str) -> str:
    """Returns why a specific account security indicator represents a threat vector."""
    return ACCOUNT_SECURITY_INDICATOR_EXPLANATIONS.get(
        name,
        "This heuristic authentication pattern is commonly observed in account takeover and credential compromise attack chains."
    )


def generate_account_security_explanation(
    indicators: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str,
    username: str = ""
) -> str:
    """
    Synthesizes a coherent, honest human-readable explanation of account security findings.
    """
    account_label = f" for account '{username}'" if username and username != "unknown_user" else ""

    if not indicators or risk_score == 0:
        return (
            f"No suspicious account security anomalies were identified{account_label}. "
            f"However, heuristic analysis evaluates observable telemetry patterns only and cannot guarantee "
            f"the absence of sophisticated credential compromise. Continue to follow organizational "
            f"authentication security best practices. "
            f"[Transparency Notice: This assessment is a heuristic indicator, not a verified security audit.]"
        )

    indicator_names = [item.get("indicator", "Suspicious pattern") for item in indicators]

    if len(indicators) == 1:
        name = indicator_names[0]
        context = explain_account_security_indicator(name)
        return (
            f"An account security indicator was detected{account_label}: {name}. {context} "
            f"Calculated heuristic risk level: {risk_level} ({risk_score}/100). "
            f"Exercise caution and review recent account activity through official security dashboards. "
            f"[Transparency Notice: This is a heuristic risk indicator derived from observable patterns, "
            f"not a confirmed security breach determination.]"
        )

    joined_names = ", ".join(indicator_names)
    if risk_level in ["HIGH", "CRITICAL"]:
        return (
            f"Multiple high-severity account security indicators were detected{account_label} ({joined_names}). "
            f"The convergence of these indicators across multiple attack categories strongly suggests "
            f"an active or imminent account takeover attempt. "
            f"Heuristic risk score: {risk_score}/100 ({risk_level}). "
            f"Immediate security review and response actions are recommended. "
            f"[Transparency Notice: This is a heuristic risk assessment based on observable telemetry patterns. "
            f"It does not constitute a confirmed breach determination.]"
        )
    elif risk_level == "MEDIUM":
        return (
            f"Multiple suspicious authentication patterns were identified{account_label} ({joined_names}). "
            f"While individual indicators may occasionally occur in normal operations, "
            f"their combination elevates the risk profile. "
            f"Heuristic risk score: {risk_score}/100 ({risk_level}). "
            f"[Transparency Notice: Heuristic indicator — verify through official security channels.]"
        )
    else:  # LOW
        return (
            f"Minor account activity anomalies were identified{account_label} ({joined_names}). "
            f"Calculated heuristic risk: {risk_level} ({risk_score}/100). "
            f"Review recent login history and ensure multi-factor authentication is active. "
            f"[Transparency Notice: Heuristic assessment based on observable patterns.]"
        )
