"""
Unit Tests for Cross-Threat Correlation Engine
Tests pivot extraction, multi-stage attack chain synthesis, and threshold validations.
"""

import unittest
from backend.models.incident import Incident, IncidentEvidenceItem, IncidentStatus
from backend.engines.correlation_engine import correlation_engine


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.inc1 = Incident(
            incident_id="INC-TEST-001",
            threat_type="Phishing",
            classification="PayPal Credential Harvest Lure",
            risk_score=90,
            risk_level="CRITICAL",
            evidence=[
                IncidentEvidenceItem(indicator="Lure", details="Visit http://paypa1-secure-verify.net/signin")
            ],
            explanation="Phishing email lure targeting user account victim@corp.com",
            recommended_actions=["Do not open"],
            timestamp="2026-09-18T08:00:00Z",
            status=IncidentStatus.NEW,
            source_data={
                "username": "victim@corp.com",
                "sender": "alert@paypa1-secure-verify.net",
                "url": "http://paypa1-secure-verify.net/signin"
            }
        )

        self.inc2 = Incident(
            incident_id="INC-TEST-002",
            threat_type="URL Threat",
            classification="Malicious Domain Host",
            risk_score=85,
            risk_level="HIGH",
            evidence=[
                IncidentEvidenceItem(indicator="Host", details="Domain paypa1-secure-verify.net host IP 198.51.100.22")
            ],
            explanation="Malicious domain registered for credential theft",
            recommended_actions=["Block domain"],
            timestamp="2026-09-18T08:15:00Z",
            status=IncidentStatus.INVESTIGATING,
            source_data={
                "target_url": "http://paypa1-secure-verify.net/login.php",
                "ip_address": "198.51.100.22"
            }
        )

        self.inc3 = Incident(
            incident_id="INC-TEST-003",
            threat_type="Account Security",
            classification="Anomalous Login From Malicious IP",
            risk_score=80,
            risk_level="HIGH",
            evidence=[
                IncidentEvidenceItem(indicator="IP", details="Login from 198.51.100.22")
            ],
            explanation="Unusual login for victim@corp.com",
            recommended_actions=["Revoke session"],
            timestamp="2026-09-18T08:30:00Z",
            status=IncidentStatus.NEW,
            source_data={
                "username": "victim@corp.com",
                "ip_address": "198.51.100.22"
            }
        )

        self.inc_unrelated = Incident(
            incident_id="INC-TEST-099",
            threat_type="Phishing",
            classification="Netflix Billing Lure",
            risk_score=75,
            risk_level="HIGH",
            evidence=[],
            explanation="Unrelated email lure",
            recommended_actions=[],
            timestamp="2026-09-18T09:00:00Z",
            status=IncidentStatus.NEW,
            source_data={
                "username": "stranger@other.com",
                "sender": "support@netflix-fake-billing.xyz",
                "url": "http://netflix-fake-billing.xyz"
            }
        )

    def test_multi_stage_correlation(self):
        corpus = [self.inc1, self.inc2, self.inc3, self.inc_unrelated]
        res = correlation_engine.correlate_incident(self.inc1, corpus)

        self.assertTrue(res["has_correlations"])
        related_ids = [r["incident_id"] for r in res["related_incidents"]]
        self.assertIn("INC-TEST-002", related_ids)
        self.assertIn("INC-TEST-003", related_ids)
        self.assertNotIn("INC-TEST-099", related_ids)

        # Attack chain order: inc1 (08:00) -> inc2 (08:15) -> inc3 (08:30)
        chain_ids = [c["incident_id"] for c in res["attack_chain"]]
        self.assertEqual(chain_ids, ["INC-TEST-001", "INC-TEST-002", "INC-TEST-003"])

    def test_unrelated_incident_no_false_correlation(self):
        corpus = [self.inc1, self.inc2, self.inc3, self.inc_unrelated]
        res = correlation_engine.correlate_incident(self.inc_unrelated, corpus)
        self.assertFalse(res["has_correlations"])
        self.assertEqual(len(res["related_incidents"]), 0)


if __name__ == "__main__":
    unittest.main()
