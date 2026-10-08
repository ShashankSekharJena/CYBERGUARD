"""
CYBERGUARD Digital Impersonation Explanation Engine

Generates transparent, contextual, human-readable explanations of impersonation findings,
highlighting why specific indicators matter and clarifying heuristic limitations.
"""

from typing import Dict, List, Any

IMPERSONATION_INDICATOR_EXPLANATIONS: Dict[str, str] = {
    "Free Webmail Sender Mismatch": "Legitimate institutions and corporate executives conduct official operations via domain-authenticated email infrastructure rather than free public webmail.",
    "Authority Impersonation (Government Tax Authority)": "Government and federal tax bodies do not demand immediate money transfers, gift cards, or credentials through unsolicited electronic messages.",
    "Authority Impersonation (Law Enforcement / Legal Authority)": "Fraudulent threats of imminent arrest or police dispatch are common coercion tactics engineered to induce compliance.",
    "Authority Impersonation (Government Agency Persona)": "Impersonation of immigration, border, or regulatory agencies is frequently utilized to extort compliance under pressure.",
    "Executive / C-Suite Persona": "Business Email Compromise (BEC) schemes routinely impersonate C-level executives to initiate unauthorized wire payments.",
    "Corporate Recruiter / HR Persona": "Recruitment scams lure job seekers into purchasing equipment or disclosing sensitive identity documentation under false pretenses.",
    "Fake Support / Helpdesk Pretext": "Unsolicited IT helpdesk notices frequently aim to obtain remote access credentials or MFA session tokens.",
    "Recognized Brand Reference": "Referencing recognizable brands builds false trust and exploits consumer familiarity.",
    "Untraceable Payment Solicitation": "Demands for gift cards, cryptocurrency, or wire transfers are irreversible payment channels favored in financial fraud.",
    "Financial Transaction Request": "Direct requests to expedite funds transfer or bypass standard approval procedures represent high financial risk.",
    "OTP / 2FA Token Solicitation": "Requests for authentication codes aim to compromise multi-factor protection mechanisms.",
    "Password / Credential Request": "Direct solicitation of account passwords or PINs is a primary indicator of unauthorized access attempts.",
    "Sensitive Identity / KYC Data Request": "Collection of SSNs, passport copies, or government IDs facilitates identity theft and synthetic identity fraud.",
    "Urgent Time Pressure": "Artificial urgency prevents recipients from consulting standard organizational directories or peers.",
    "Coercive Consequence Threat": "Coercive threats of account termination or legal action are designed to provoke panic-driven compliance.",
    "Impersonating Lookalike Domain": "Typosquatted domain names mimic legitimate brands to disguise the true origin of communications.",
    "Free Webmail Sender": "Communication originates from public webmail infrastructure without custom organizational domain verification.",
}


def explain_impersonation_indicator(name: str) -> str:
    """Returns why a specific impersonation indicator represents a threat vector."""
    return IMPERSONATION_INDICATOR_EXPLANATIONS.get(
        name,
        "This heuristic communication pattern is frequently observed in social engineering and brand impersonation attacks."
    )


def generate_impersonation_explanation(
    indicators: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str,
    claimed_identity: str = "",
    sender: str = ""
) -> str:
    """
    Synthesizes a coherent, honest human-readable explanation of impersonation threat findings.
    """
    if not indicators or risk_score == 0:
        return (
            "No deceptive impersonation markers or suspicious patterns were identified in the submitted communication. "
            "However, heuristic analysis cannot guarantee legitimate identity without verified cryptographic or out-of-band domain signatures. "
            "[Transparency Notice: This assessment is a heuristic indicator, not a definitive legal identity verification.]"
        )

    indicator_names = [item.get("indicator", "Suspicious pattern") for item in indicators]

    if len(indicators) == 1:
        name = indicator_names[0]
        context = explain_impersonation_indicator(name)
        return (
            f"An impersonation indicator was detected: {name} ({context}). "
            f"Calculated heuristic risk level: {risk_level} ({risk_score}/100). Exercise caution and verify sender identity through official channels. "
            f"[Transparency Notice: This is a heuristic risk indicator, not a definitive legal identity verification.]"
        )

    joined_names = ", ".join(indicator_names)
    if risk_level in ["HIGH", "CRITICAL"]:
        return (
            f"Multiple high-confidence impersonation indicators were detected ({joined_names}). "
            f"The combination of claimed authority, sender anomalies, and solicitation strongly suggests a digital impersonation or BEC attempt. "
            f"Heuristic risk score: {risk_score}/100 ({risk_level}). "
            f"[Transparency Notice: This is a heuristic risk indicator, not a definitive legal verification.]"
        )
    elif risk_level == "MEDIUM":
        return (
            f"Multiple suspicious impersonation patterns were identified ({joined_names}). "
            f"While these patterns may occasionally occur in informal communications, they represent elevated risk. "
            f"Heuristic risk score: {risk_score}/100 ({risk_level}). "
            f"[Transparency Notice: Heuristic indicator — verify through official channels.]"
        )
    else:  # LOW
        return (
            f"Minor communication anomalies were identified ({joined_names}). "
            f"Calculated heuristic risk: {risk_level} ({risk_score}/100). Review the sender's authentic contact information. "
            f"[Transparency Notice: Heuristic assessment based on observable patterns.]"
        )
