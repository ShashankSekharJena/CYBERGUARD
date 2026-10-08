"""
CYBERGUARD Defensive Incident Response Playbook Engine

Provides standardized, advisory security response playbooks for SOC analysts and end-users across:
1. Phishing email lures & credential harvesting
2. Malicious and deceptive URLs
3. Digital & Multimedia Impersonation
4. Account Takeover & Behavioural Anomalies
5. Correlated multi-stage attack chains

NOTE: All generated recommendations and playbooks are strictly ADVISORY.
They do NOT execute active network disruption, account deletions, or automated external blocking.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class PlaybookStep(BaseModel):
    step_number: int
    phase: str = Field(..., description="Playbook phase: Triage, Containment, Remediation, Hardening, Escalation")
    title: str = Field(..., description="Action step title")
    description: str = Field(..., description="Detailed step-by-step guidance")
    target_audience: str = Field(default="Analyst & End-User", description="Target recipient: End-User, SOC Analyst, System Administrator")


class IncidentResponsePlaybook(BaseModel):
    playbook_id: str
    threat_category: str
    severity_level: str
    summary: str
    steps: List[PlaybookStep]
    disclaimer: str = Field(
        default="ADVISORY NOTICE: This playbook contains recommended defensive procedures. Execute actions through approved organizational change management workflows.",
        description="Defensive safety notice"
    )


PLAYBOOK_TEMPLATES: Dict[str, List[Dict[str, str]]] = {
    "Phishing": [
        {"phase": "Containment", "title": "Do Not Open or Forward Links", "desc": "Refrain from opening links, downloading attachments, or replying to the message.", "aud": "End-User"},
        {"phase": "Triage", "title": "Extract and Preserve Headers", "desc": "Export complete RFC 822 / MIME email headers (Authentication-Results, SPF, DKIM, Received-From) for SOC triage.", "aud": "SOC Analyst"},
        {"phase": "Remediation", "title": "Reset Credentials Out-of-Band", "desc": "If credentials or OTPs were submitted, immediately reset passwords via official, known-clean bookmarks.", "aud": "End-User"},
        {"phase": "Hardening", "title": "Email Gateway Filter Rule Advisory", "desc": "Recommend adding identified sender envelope domains and look-alike strings to inbound mail filters.", "aud": "System Administrator"},
        {"phase": "Escalation", "title": "Log Security Ticket & Notify SOC", "desc": "Forward the original message as an attachment to security-abuse@organization.local for threat intelligence logging.", "aud": "End-User"}
    ],
    "URL Threat": [
        {"phase": "Containment", "title": "Avoid Accessing Target Endpoint", "desc": "Do not navigate to the suspicious URL or bypass browser safety warnings.", "aud": "End-User"},
        {"phase": "Triage", "title": "Domain & IP Reputation Inspection", "desc": "Query internal proxy logs and defensive DNS threat feeds to assess whether other internal hosts contacted this endpoint.", "aud": "SOC Analyst"},
        {"phase": "Remediation", "title": "Purge Browser Session Data", "desc": "If visited, clear browser cookies, active sessions, and local storage cache for that origin.", "aud": "End-User"},
        {"phase": "Hardening", "title": "Egress Proxy & DNS Sinkhole Advisory", "desc": "Consider appending the destination host or raw IP to egress web proxy inspection blocks.", "aud": "System Administrator"},
        {"phase": "Escalation", "title": "Report Deceptive Domain to Registrar/Host", "desc": "Submit domain abuse report to the corresponding registrar and web host abuse contact.", "aud": "SOC Analyst"}
    ],
    "Digital Impersonation": [
        {"phase": "Triage", "title": "Out-of-Band Identity Verification", "desc": "Verify request authenticity via a secondary, established communication channel (corporate voice, Slack, in-person).", "aud": "End-User"},
        {"phase": "Containment", "title": "Halt Financial or Data Requests", "desc": "Immediately pause gift card purchases, wire transfers, or sensitive document disclosures until identity is verified.", "aud": "End-User"},
        {"phase": "Remediation", "title": "Brand Impersonation Advisory", "desc": "Issue an internal security bulletin alerting employees to active brand or executive impersonation attempts.", "aud": "SOC Analyst"},
        {"phase": "Hardening", "title": "Review Social Profiles & Executive Footprint", "desc": "Audit public directory visibility and implement DMARC reject policies for corporate domains.", "aud": "System Administrator"},
        {"phase": "Escalation", "title": "Takedown Notification", "desc": "File impersonation takedown notices with social platforms or hosting providers where deceptive profiles reside.", "aud": "SOC Analyst"}
    ],
    "Multimedia Impersonation": [
        {"phase": "Triage", "title": "Examine Forensic & Metadata Markers", "desc": "Review EXIF tags, software modification history, and reverse search results for authentic source context.", "aud": "SOC Analyst"},
        {"phase": "Containment", "title": "Do Not Disseminate Unverified Media", "desc": "Avoid sharing or publishing media until authenticity and provenance are verified.", "aud": "End-User"},
        {"phase": "Remediation", "title": "Request Cryptographic or Live Verification", "desc": "Request cryptographic C2PA signature or schedule live synchronous video confirmation with known colleagues.", "aud": "End-User"},
        {"phase": "Hardening", "title": "Adopt Provenance Standards (C2PA)", "desc": "Implement signed Content Credentials across corporate media release channels.", "aud": "System Administrator"},
        {"phase": "Escalation", "title": "Document Findings in Incident Record", "desc": "Catalog forensic indicators and file hashes in incident ticket for forensic recordkeeping.", "aud": "SOC Analyst"}
    ],
    "Account Security": [
        {"phase": "Containment", "title": "Terminate Active Sessions", "desc": "Revoke all concurrent web sessions, mobile tokens, and OAuth authorization grants.", "aud": "End-User & Administrator"},
        {"phase": "Remediation", "title": "Mandatory Password & Recovery Reset", "desc": "Perform an urgent password reset through the official portal and verify recovery email/phone integrity.", "aud": "End-User"},
        {"phase": "Hardening", "title": "Enforce Hardware-Backed MFA (FIDO2/WebAuthn)", "desc": "Require phishing-resistant MFA tokens or authenticator apps; disable SMS-based 2FA fallback where feasible.", "aud": "System Administrator"},
        {"phase": "Triage", "title": "Audit Authentication & Access Logs", "desc": "Inspect audit logs for unauthorized privilege escalation, API key generation, or mail forwarding rule creation.", "aud": "SOC Analyst"},
        {"phase": "Escalation", "title": "Initiate Account Takeover (ATO) Incident Protocol", "desc": "Assign incident priority and monitor account activity for secondary lateral movement indicators.", "aud": "SOC Analyst"}
    ]
}


def generate_playbook(
    threat_category: str,
    severity: str = "MEDIUM",
    indicators: Optional[List[Any]] = None
) -> IncidentResponsePlaybook:
    """
    Generates a structured, defensive advisory incident response playbook.
    """
    category_key = threat_category
    if "phish" in threat_category.lower():
        category_key = "Phishing"
    elif "url" in threat_category.lower():
        category_key = "URL Threat"
    elif "multimedia" in threat_category.lower():
        category_key = "Multimedia Impersonation"
    elif "impersonation" in threat_category.lower():
        category_key = "Digital Impersonation"
    elif "account" in threat_category.lower():
        category_key = "Account Security"
    else:
        category_key = "Phishing"

    raw_steps = PLAYBOOK_TEMPLATES.get(category_key, PLAYBOOK_TEMPLATES["Phishing"])
    steps = [
        PlaybookStep(
            step_number=idx,
            phase=item["phase"],
            title=item["title"],
            description=item["desc"],
            target_audience=item["aud"]
        )
        for idx, item in enumerate(raw_steps, start=1)
    ]

    summary = (
        f"Standard defensive incident response playbook for {category_key} at {severity} severity rating. "
        "Follow advisory phases in sequential order."
    )

    return IncidentResponsePlaybook(
        playbook_id=f"PB-{category_key.upper().replace(' ', '_')}-{severity}",
        threat_category=category_key,
        severity_level=severity,
        summary=summary,
        steps=steps
    )
