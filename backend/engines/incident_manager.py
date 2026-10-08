"""
CYBERGUARD Incident Management Engine

Provides thread-safe in-memory incident storage, querying, filtering,
metrics aggregation, and automatic ingestion from all threat detectors:
- Phishing Detection
- URL Threat Analysis
- Digital Impersonation Detection
- Account Security & Takeover Detection
- Multimedia Impersonation Detection
"""

import threading
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

try:
    from backend.models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentCorrelationInfo,
        IncidentListResponse
    )
    from backend.services.incident_correlation import find_related_incidents
except ImportError:
    from models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentCorrelationInfo,
        IncidentListResponse
    )
    from services.incident_correlation import find_related_incidents


class IncidentManager:
    """
    Thread-safe in-memory store and manager for CYBERGUARD security incidents.
    """

    def __init__(self, seed: bool = True):
        self._lock = threading.Lock()
        self._incidents: List[Incident] = []
        self._counter: int = 1000
        self._total_analyzed: int = 0
        if seed:
            self._seed_initial_incidents()
            self._total_analyzed = len(self._incidents)

    def _generate_incident_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"INC-2026-{self._counter:04d}"

    def _correlate_and_store(self, incident: Incident) -> Incident:
        """Computes correlation against existing incidents, attaches correlation metadata, and stores the incident."""
        with self._lock:
            corr_res = find_related_incidents(incident, self._incidents)
            corr_info = IncidentCorrelationInfo(
                related=corr_res["related"],
                correlation_score=corr_res["correlation_score"],
                matched_signals=corr_res["matched_signals"],
                related_incident_ids=corr_res["related_incident_ids"],
                reason=corr_res["reason"],
                relationships=corr_res.get("relationships")
            )
            incident_with_corr = incident.model_copy(update={"correlation": corr_info})
            self._incidents.insert(0, incident_with_corr)
            return incident_with_corr

    def _seed_initial_incidents(self):
        """Pre-populates the store with realistic baseline incidents across all threat domains."""
        seed_data = [
            Incident(
                incident_id="INC-2026-0001",
                threat_type="Phishing",
                classification="Brand Impersonation & Urgent Credential Lure",
                risk_score=92,
                risk_level="CRITICAL",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="High Urgency Keyword",
                        details="Message contains urgent coercive wording: 'URGENT: Your account access has been restricted'."
                    ),
                    IncidentEvidenceItem(
                        indicator="Credential Harvesting Trigger",
                        details="Message urges victim to verify password and OTP immediately to avoid account suspension."
                    ),
                    IncidentEvidenceItem(
                        indicator="Deceptive Domain Mismatch",
                        details="Claimed sender 'security@paypal-notice.com' routes to unverified host 'http://paypa1-secure-verify.net'."
                    )
                ],
                explanation="Critical phishing lure identified imitating PayPal. High urgency coercion coupled with deceptive credential harvesting endpoint.",
                recommended_actions=[
                    "Do not click the provided link or input credentials.",
                    "Verify sender identity via verified out-of-band channels.",
                    "Block the sender domain at the email gateway.",
                    "Forward sample to the Security Operations Center (SOC)."
                ],
                timestamp="2026-09-17T08:15:22Z",
                status=IncidentStatus.NEW,
                source_data={
                    "sender": "security@paypal-notice.com",
                    "url": "http://paypa1-secure-verify.net/signin",
                    "subject": "URGENT: Your account access has been restricted"
                }
            ),
            Incident(
                incident_id="INC-2026-0002",
                threat_type="URL Threat",
                classification="Deceptive Raw IP Host & Embedded Credentials",
                risk_score=85,
                risk_level="HIGH",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="Raw IP Address Host",
                        details="URL utilizes raw public IP host (192.168.1.100) instead of a registered domain name."
                    ),
                    IncidentEvidenceItem(
                        indicator="Embedded Userinfo '@' Syntax",
                        details="URL uses '@' symbol to obscure the true destination server (admin@secure-portal.xyz)."
                    ),
                    IncidentEvidenceItem(
                        indicator="Non-Standard Port Target",
                        details="Connection directed to uncommon port 8443 without standard SSL verification."
                    )
                ],
                explanation="High-risk malicious URL pattern utilizing raw IP host syntax and embedded credential delimiters to bypass security filters.",
                recommended_actions=[
                    "Avoid accessing or forwarding the target link.",
                    "Add destination IP to network egress blocklists.",
                    "Inspect web proxy logs for related outbound telemetry.",
                    "Submit URL to threat intelligence feed."
                ],
                timestamp="2026-09-17T09:42:10Z",
                status=IncidentStatus.INVESTIGATING,
                source_data={
                    "target_url": "http://192.168.1.100:8443/admin@secure-portal.xyz/login.php",
                    "ip_address": "192.168.1.100"
                }
            ),
            Incident(
                incident_id="INC-2026-0003",
                threat_type="Digital Impersonation",
                classification="Executive Impersonation & Wire Transfer Solicit",
                risk_score=88,
                risk_level="CRITICAL",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="Executive Title Impersonation",
                        details="Sender claims to be 'Chief Executive Officer' requesting urgent discrete task."
                    ),
                    IncidentEvidenceItem(
                        indicator="Lookalike Domain Spoofing",
                        details="Sender address 'ceo@company-corp.xyz' mimics official domain 'company.corp'."
                    ),
                    IncidentEvidenceItem(
                        indicator="Urgent Wire / Gift Card Solicitation",
                        details="Request directs finance personnel to execute immediate confidential wire transfer."
                    )
                ],
                explanation="Critical Business Email Compromise (BEC) pattern detected simulating executive authority to initiate unauthorized financial transaction.",
                recommended_actions=[
                    "Verify request directly with executive using verified internal phone/Slack.",
                    "Do not transfer funds or share financial credentials.",
                    "Alert finance department lead and SOC team.",
                    "Tag external lookalike domain in mail server rules."
                ],
                timestamp="2026-09-17T11:20:45Z",
                status=IncidentStatus.NEW,
                source_data={
                    "claimed_identity": "Chief Executive Officer",
                    "sender": "ceo@company-corp.xyz",
                    "channel": "Email"
                }
            ),
            Incident(
                incident_id="INC-2026-0004",
                threat_type="Account Security",
                classification="Brute-Force Attack & Impossible Travel",
                risk_score=95,
                risk_level="CRITICAL",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="Rapid Failed Authentication Spike",
                        details="15 consecutive failed login attempts recorded within 60 seconds."
                    ),
                    IncidentEvidenceItem(
                        indicator="Impossible Geographic Velocity",
                        details="Account authenticated in New York and Tokyo within 8 minutes."
                    ),
                    IncidentEvidenceItem(
                        indicator="Automated Bot User-Agent",
                        details="Client identified as headless python-requests script targeting admin endpoints."
                    )
                ],
                explanation="Critical account takeover indicators detected including rapid brute-force password spraying and impossible travel anomalies across distinct continents.",
                recommended_actions=[
                    "Prompt user for credential reset through official account portal.",
                    "Require Multi-Factor Authentication (MFA) step-up verification.",
                    "Review concurrent active sessions in identity provider.",
                    "Audit privileged action logs for unauthorized modifications."
                ],
                timestamp="2026-09-17T13:05:18Z",
                status=IncidentStatus.INVESTIGATING,
                source_data={
                    "username": "admin@cyberguard-ops.internal",
                    "location": "Kyiv, Ukraine / Tokyo, Japan",
                    "ip_address": "198.51.100.42",
                    "failed_login_count": 15
                }
            ),
            Incident(
                incident_id="INC-2026-0005",
                threat_type="Account Security",
                classification="Password Reset Abuse & MFA Disablement",
                risk_score=78,
                risk_level="HIGH",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="Multiple Password Reset Requests",
                        details="4 password reset links generated in rapid succession."
                    ),
                    IncidentEvidenceItem(
                        indicator="MFA Authenticator Device Removed",
                        details="Hardware security key detached from account profile."
                    )
                ],
                explanation="High-risk authentication telemetry indicates targeted attempt to disable MFA defenses and intercept password reset token.",
                recommended_actions=[
                    "Contact account holder directly via phone.",
                    "Re-enable mandatory hardware token MFA requirement.",
                    "Invalidate existing active sessions and tokens.",
                    "Review account recovery audit trail."
                ],
                timestamp="2026-09-17T14:18:30Z",
                status=IncidentStatus.RESOLVED,
                source_data={
                    "username": "finance.lead@enterprise.com",
                    "location": "London, UK",
                    "ip_address": "203.0.113.77"
                }
            ),
            Incident(
                incident_id="INC-2026-0006",
                threat_type="URL Threat",
                classification="Shortened Link Masking Unknown Redirect",
                risk_score=55,
                risk_level="MEDIUM",
                evidence=[
                    IncidentEvidenceItem(
                        indicator="URL Shortener Detected",
                        details="Link utilizes bit.ly redirection service masking the final landing page destination."
                    )
                ],
                explanation="Medium-risk URL utilizing shortening service to obscure final endpoint destination.",
                recommended_actions=[
                    "Expand shortened link in a sandbox before visiting.",
                    "Avoid entering credentials on redirected page.",
                    "Verify target destination legitimacy."
                ],
                timestamp="2026-09-17T15:40:12Z",
                status=IncidentStatus.FALSE_POSITIVE,
                source_data={
                    "target_url": "https://bit.ly/marketing-quarterly-update"
                }
            )
        ]
        
        # Populate initial correlations across seed items
        enriched_seed = []
        for inc in seed_data:
            corr_res = find_related_incidents(inc, seed_data)
            corr_info = IncidentCorrelationInfo(
                related=corr_res["related"],
                correlation_score=corr_res["correlation_score"],
                matched_signals=corr_res["matched_signals"],
                related_incident_ids=corr_res["related_incident_ids"],
                reason=corr_res["reason"],
                relationships=corr_res.get("relationships")
            )
            enriched_seed.append(inc.model_copy(update={"correlation": corr_info}))
            
        self._incidents.extend(enriched_seed)

    def get_all_incidents(
        self,
        threat_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "timestamp",
        order: str = "desc",
        limit: Optional[int] = None
    ) -> IncidentListResponse:
        """
        Retrieves filtered incidents with aggregated risk, status, and similarity metrics.
        """
        with self._lock:
            critical_count = sum(1 for inc in self._incidents if inc.risk_level.upper() == "CRITICAL")
            high_count = sum(1 for inc in self._incidents if inc.risk_level.upper() == "HIGH")
            medium_count = sum(1 for inc in self._incidents if inc.risk_level.upper() == "MEDIUM")
            low_count = sum(1 for inc in self._incidents if inc.risk_level.upper() == "LOW")
            safe_count = sum(1 for inc in self._incidents if inc.risk_level.upper() == "SAFE")
            resolved_count = sum(1 for inc in self._incidents if inc.status == IncidentStatus.RESOLVED)
            new_count = sum(1 for inc in self._incidents if inc.status == IncidentStatus.NEW)
            investigating_count = sum(1 for inc in self._incidents if inc.status == IncidentStatus.INVESTIGATING)
            false_positive_count = sum(1 for inc in self._incidents if inc.status == IncidentStatus.FALSE_POSITIVE)

            phishing_count = sum(1 for inc in self._incidents if "phishing" in inc.threat_type.lower())
            url_threat_count = sum(1 for inc in self._incidents if "url" in inc.threat_type.lower())
            impersonation_count = sum(1 for inc in self._incidents if "impersonation" in inc.threat_type.lower())
            account_security_count = sum(1 for inc in self._incidents if "account" in inc.threat_type.lower())
            linked_count = sum(1 for inc in self._incidents if inc.correlation and inc.correlation.related)

            # Filter items
            filtered = list(self._incidents)

            if threat_type and threat_type.strip() and threat_type.upper() != "ALL":
                tt_clean = threat_type.strip().lower()
                filtered = [
                    inc for inc in filtered 
                    if tt_clean in inc.threat_type.lower() or inc.threat_type.lower() in tt_clean
                ]

            if risk_level and risk_level.strip() and risk_level.upper() != "ALL":
                rl_clean = risk_level.strip().upper()
                filtered = [inc for inc in filtered if inc.risk_level.upper() == rl_clean]

            if status and status.strip() and status.upper() != "ALL":
                st_clean = status.strip().upper()
                filtered = [inc for inc in filtered if inc.status.value.upper() == st_clean]

            if search and search.strip():
                query = search.strip().lower()
                filtered = [
                    inc for inc in filtered
                    if query in inc.incident_id.lower()
                    or query in inc.threat_type.lower()
                    or query in inc.classification.lower()
                    or query in inc.explanation.lower()
                    or any(query in ev.indicator.lower() or query in ev.details.lower() for ev in inc.evidence)
                    or (inc.source_data and any(query in str(v).lower() for v in inc.source_data.values()))
                ]

            # Sorting
            reverse = (order.lower() == "desc")
            if sort_by == "risk_score":
                filtered.sort(key=lambda x: x.risk_score, reverse=reverse)
            elif sort_by == "incident_id":
                filtered.sort(key=lambda x: x.incident_id, reverse=reverse)
            else:
                filtered.sort(key=lambda x: x.timestamp, reverse=reverse)

            if limit is not None and limit > 0:
                filtered = filtered[:limit]

            return IncidentListResponse(
                total=len(filtered),
                incidents=filtered,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                safe_count=safe_count,
                resolved_count=resolved_count,
                new_count=new_count,
                investigating_count=investigating_count,
                false_positive_count=false_positive_count,
                phishing_count=phishing_count,
                url_threat_count=url_threat_count,
                impersonation_count=impersonation_count,
                account_security_count=account_security_count,
                linked_count=linked_count,
                total_analyzed_count=max(self._total_analyzed, len(self._incidents))
            )

    def get_incident_by_id(self, incident_id: str) -> Optional[Incident]:
        """Fetches a single incident by its unique ID, dynamically populating correlation if missing."""
        with self._lock:
            for idx, inc in enumerate(self._incidents):
                if inc.incident_id.upper() == incident_id.strip().upper():
                    if inc.correlation is None:
                        corr_res = find_related_incidents(inc, self._incidents)
                        corr_info = IncidentCorrelationInfo(
                            related=corr_res["related"],
                            correlation_score=corr_res["correlation_score"],
                            matched_signals=corr_res["matched_signals"],
                            related_incident_ids=corr_res["related_incident_ids"],
                            reason=corr_res["reason"],
                            relationships=corr_res.get("relationships")
                        )
                        updated = inc.model_copy(update={"correlation": corr_info})
                        self._incidents[idx] = updated
                        return updated
                    return inc
            return None

    def update_incident_status(self, incident_id: str, new_status: IncidentStatus) -> Optional[Incident]:
        """Updates the triage status of an incident."""
        with self._lock:
            for idx, inc in enumerate(self._incidents):
                if inc.incident_id.upper() == incident_id.strip().upper():
                    updated = inc.model_copy(update={"status": new_status})
                    self._incidents[idx] = updated
                    return updated
            return None

    def record_phishing_analysis(
        self,
        risk_score: int,
        severity: str,
        explanation: str,
        evidence_items: List[Dict[str, str]],
        recommended_actions: List[str],
        source_data: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Creates and stores an incident record from a phishing detection outcome."""
        incident_id = self._generate_incident_id()
        
        if severity.upper() in ["CRITICAL", "HIGH"]:
            classification = "Suspected Credential Harvesting & Phishing Lure"
        elif severity.upper() == "MEDIUM":
            classification = "Suspicious Communication & Potential Phishing Pattern"
        elif severity.upper() == "LOW":
            classification = "Low-Risk Message with Minor Anomalies"
        else:
            classification = "Verified Benign Communication"

        if evidence_items and len(evidence_items) > 0:
            top_indicator = evidence_items[0].get("indicator", "")
            if top_indicator:
                classification = f"Phishing: {top_indicator}"

        incident_evidence = [
            IncidentEvidenceItem(
                indicator=item.get("indicator", "Indicator"),
                details=item.get("details", "")
            )
            for item in evidence_items
        ]

        incident = Incident(
            incident_id=incident_id,
            threat_type="Phishing",
            classification=classification,
            risk_score=risk_score,
            risk_level=severity.upper(),
            evidence=incident_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=IncidentStatus.NEW,
            source_data=source_data
        )

        return self._correlate_and_store(incident)

    def record_url_analysis(
        self,
        target_url: str,
        risk_score: int,
        risk_level: str,
        explanation: str,
        evidence_items: List[Dict[str, str]],
        recommended_actions: List[str],
        source_data: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Creates and stores an incident record from a URL threat analysis outcome."""
        incident_id = self._generate_incident_id()

        if risk_level.upper() in ["CRITICAL", "HIGH"]:
            classification = "High-Risk Deceptive URL Structure"
        elif risk_level.upper() == "MEDIUM":
            classification = "Suspicious Domain / URL Redirect Pattern"
        elif risk_level.upper() == "LOW":
            classification = "Low-Risk Target URL"
        else:
            classification = "Standard Safe URL Host"

        if evidence_items and len(evidence_items) > 0:
            top_indicator = evidence_items[0].get("indicator", "")
            if top_indicator:
                classification = f"URL Threat: {top_indicator}"

        incident_evidence = [
            IncidentEvidenceItem(
                indicator=item.get("indicator", "Pattern"),
                details=item.get("details", "")
            )
            for item in evidence_items
        ]

        merged_source = {"target_url": target_url}
        if source_data:
            merged_source.update(source_data)

        incident = Incident(
            incident_id=incident_id,
            threat_type="URL Threat",
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level.upper(),
            evidence=incident_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=IncidentStatus.NEW,
            source_data=merged_source
        )

        return self._correlate_and_store(incident)

    def record_impersonation_analysis(
        self,
        risk_score: int,
        risk_level: str,
        explanation: str,
        evidence_items: List[Dict[str, str]],
        recommended_actions: List[str],
        claimed_identity: Optional[str] = None,
        sender: Optional[str] = None,
        source_data: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Creates and stores an incident record from a digital impersonation analysis outcome."""
        incident_id = self._generate_incident_id()

        if risk_level.upper() in ["CRITICAL", "HIGH"]:
            classification = f"Brand & Identity Impersonation ({claimed_identity or 'Entity'})"
        elif risk_level.upper() == "MEDIUM":
            classification = f"Suspicious Sender Mismatch ({claimed_identity or 'Profile'})"
        elif risk_level.upper() == "LOW":
            classification = "Low-Risk Identity Verification"
        else:
            classification = "Legitimate Verified Identity"

        if evidence_items and len(evidence_items) > 0:
            top_indicator = evidence_items[0].get("indicator", "")
            if top_indicator:
                classification = f"Impersonation: {top_indicator}"

        incident_evidence = [
            IncidentEvidenceItem(
                indicator=item.get("indicator", "Indicator"),
                details=item.get("details", "")
            )
            for item in evidence_items
        ]

        merged_source = {
            "claimed_identity": claimed_identity,
            "sender": sender
        }
        if source_data:
            merged_source.update(source_data)

        incident = Incident(
            incident_id=incident_id,
            threat_type="Digital Impersonation",
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level.upper(),
            evidence=incident_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=IncidentStatus.NEW,
            source_data=merged_source
        )

        return self._correlate_and_store(incident)

    def record_account_security_analysis(
        self,
        username: Optional[str],
        risk_score: int,
        risk_level: str,
        explanation: str,
        evidence_items: List[Dict[str, str]],
        recommended_actions: List[str],
        source_data: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Creates and stores an incident record from an account security telemetry analysis outcome."""
        incident_id = self._generate_incident_id()

        if risk_level.upper() in ["CRITICAL", "HIGH"]:
            classification = f"Account Takeover & Authentication Anomaly ({username or 'Unknown'})"
        elif risk_level.upper() == "MEDIUM":
            classification = f"Elevated Login Anomaly ({username or 'Account'})"
        elif risk_level.upper() == "LOW":
            classification = "Minor Authentication Discrepancy"
        else:
            classification = "Normal Verified Authentication"

        if evidence_items and len(evidence_items) > 0:
            top_indicator = evidence_items[0].get("indicator", "")
            if top_indicator:
                classification = f"Account Security: {top_indicator}"

        incident_evidence = [
            IncidentEvidenceItem(
                indicator=item.get("indicator", "Anomaly"),
                details=item.get("details", "")
            )
            for item in evidence_items
        ]

        merged_source = {"username": username}
        if source_data:
            merged_source.update(source_data)

        incident = Incident(
            incident_id=incident_id,
            threat_type="Account Security",
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level.upper(),
            evidence=incident_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=IncidentStatus.NEW,
            source_data=merged_source
        )

        return self._correlate_and_store(incident)

    def record_multimodal_analysis(
        self,
        file_name: str,
        risk_score: int,
        risk_level: str,
        explanation: str,
        evidence_items: List[Dict[str, str]],
        recommended_actions: List[str],
        source_data: Optional[Dict[str, Any]] = None
    ) -> Incident:
        """Creates and stores an incident record from a multimodal forensic analysis outcome."""
        incident_id = self._generate_incident_id()

        if risk_level.upper() in ["CRITICAL", "HIGH"]:
            classification = f"Multimedia Forensics & Impersonation Alert ({file_name})"
        elif risk_level.upper() == "MEDIUM":
            classification = f"Suspicious Media Header / Tool Marker ({file_name})"
        elif risk_level.upper() == "LOW":
            classification = f"Low-Risk Media ({file_name})"
        else:
            classification = f"Verified Standard Media ({file_name})"

        incident_evidence = [
            IncidentEvidenceItem(
                indicator=item.get("indicator", "Forensic Indicator"),
                details=item.get("details", "")
            )
            for item in evidence_items
        ]

        merged_source = {"file_name": file_name}
        if source_data:
            merged_source.update(source_data)

        incident = Incident(
            incident_id=incident_id,
            threat_type="Multimedia Impersonation",
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level.upper(),
            evidence=incident_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=IncidentStatus.NEW,
            source_data=merged_source
        )

        return self._correlate_and_store(incident)

    def reset_store(self, seed: bool = True):
        """Clears all stored incidents and resets counter, optionally re-seeding default data."""
        with self._lock:
            self._incidents.clear()
            self._counter = 1000
            self._total_analyzed = 0
            if seed:
                self._seed_initial_incidents()
                self._total_analyzed = len(self._incidents)


# Global Singleton Instance for FastAPI app
incident_manager = IncidentManager(seed=True)
