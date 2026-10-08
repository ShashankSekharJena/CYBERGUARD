"""
CYBERGUARD MITRE ATT&CK Mapping Engine

Maps detected threat indicators and behavioral patterns to official MITRE ATT&CK Enterprise techniques
strictly when evidence supports the attribution.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class MitreTechniqueMapping(BaseModel):
    technique_id: str = Field(..., description="Official MITRE ATT&CK Technique ID (e.g., T1566.002)")
    technique_name: str = Field(..., description="Technique Title")
    tactic: str = Field(..., description="Primary MITRE ATT&CK Tactic category")
    evidence_summary: str = Field(..., description="Observed indicator or telemetry triggering the mapping")
    mapping_rationale: str = Field(..., description="Technical justification linking the indicator to the technique")
    confidence: str = Field(default="HIGH", description="Mapping confidence: HIGH or MEDIUM")


MITRE_RULES = [
    {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "keywords": ["domain mismatch", "urgent credential", "credential harvesting", "verify your identity", "urgent language"],
        "rationale": "Adversary delivers deceptive links in messages to trick users into providing credentials or visiting hostile sites."
    },
    {
        "technique_id": "T1204.001",
        "technique_name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "keywords": ["raw ip address", "embedded userinfo", "hex-encoded", "punycode", "shortened url", "look-alike"],
        "rationale": "Adversary crafts deceptive URLs to induce user execution and circumvent security gateways."
    },
    {
        "technique_id": "T1656",
        "technique_name": "Impersonation",
        "tactic": "Defense Evasion / Social Engineering",
        "keywords": ["brand impersonation", "executive impersonation", "ceo urgent", "claimed organization", "lookalike brand"],
        "rationale": "Adversary assumes the identity of a known organization or trusted persona to facilitate fraud or exploitation."
    },
    {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "keywords": ["multiple failed login", "failed login attempts", "credential guessing", "brute-force"],
        "rationale": "Adversary systematically submits candidate passwords against target accounts."
    },
    {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "keywords": ["credential stuffing", "rapid authentication burst", "burst frequency"],
        "rationale": "Adversary utilizes high-frequency authentication attempts across credentials to evade lockout policies."
    },
    {
        "technique_id": "T1621",
        "technique_name": "Multi-Factor Authentication Request Generation",
        "tactic": "Credential Access / Defense Evasion",
        "keywords": ["mfa fatigue", "push bombing", "otp bypass", "consecutive mfa", "mfa manipulation"],
        "rationale": "Adversary spams MFA authorization push notifications to induce user fatigue and gain unauthorized entry."
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "keywords": ["impossible travel", "concurrent session", "high-risk geographic", "anonymized / proxied"],
        "rationale": "Adversary leverages legitimate account credentials from anomalous geographic origins or concurrent sessions."
    },
    {
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "keywords": ["session hijack", "cookie theft", "cookie replay", "session fixation"],
        "rationale": "Adversary captures or replays active session cookies to bypass standard authentication workflows."
    },
    {
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "keywords": ["homoglyph", "typosquatting", "look-alike domain", "deceptive domain"],
        "rationale": "Adversary modifies names or domain structures to mimic trusted services and deceive recipients."
    }
]


def map_mitre_techniques(
    threat_type: str,
    evidence_items: List[Any],
    source_data: Optional[Dict[str, Any]] = None
) -> List[MitreTechniqueMapping]:
    """
    Evaluates evidence indicators and context against MITRE ATT&CK techniques.
    Only produces mappings when concrete evidence keywords are satisfied.
    """
    mappings: List[MitreTechniqueMapping] = []
    seen_technique_ids = set()

    # Normalize evidence text
    evidence_strings = []
    for item in evidence_items:
        if isinstance(item, dict):
            evidence_strings.append(f"{item.get('indicator', '')} {item.get('details', '')}".lower())
        elif hasattr(item, "indicator") and hasattr(item, "details"):
            evidence_strings.append(f"{item.indicator} {item.details}".lower())
        elif isinstance(item, str):
            evidence_strings.append(item.lower())

    combined_evidence = " ".join(evidence_strings)
    if source_data:
        combined_evidence += " " + str(source_data).lower()

    for rule in MITRE_RULES:
        tid = rule["technique_id"]
        if tid in seen_technique_ids:
            continue

        matching_keywords = [kw for kw in rule["keywords"] if kw in combined_evidence]
        if matching_keywords:
            seen_technique_ids.add(tid)
            mappings.append(MitreTechniqueMapping(
                technique_id=tid,
                technique_name=rule["technique_name"],
                tactic=rule["tactic"],
                evidence_summary=f"Matched indicators: {', '.join(matching_keywords[:3])}",
                mapping_rationale=rule["rationale"],
                confidence="HIGH" if len(matching_keywords) >= 2 else "MEDIUM"
            ))

    return mappings
