"""
CYBERGUARD Similar-Incident Correlation Unit & Integration Tests

Verifies deterministic, explainable correlation across security incidents:
1. TEST 1: Two unrelated incidents -> No meaningful relationship
2. TEST 2: Same threat type -> Similarity detected
3. TEST 3: Same domain + same threat type -> Strong relationship
4. TEST 4: Same exact URL -> Strong relationship
5. TEST 5: Same domain but different threat type -> Score lower than same domain + same threat type
6. TEST 6: Old incident outside configured time window -> No temporal bonus
7. TEST 7: Incident compared against itself -> No self-correlation
8. TEST 8: Multiple related incidents -> All relevant previous IDs returned
9. TEST 9: No previous incidents -> No related activity
10. TEST 10: API integration & incident creation flow -> Correlation attached
"""

import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.incident import Incident, IncidentEvidenceItem, IncidentStatus
from backend.engines.incident_manager import incident_manager
from backend.services.incident_correlation import (
    find_related_incidents,
    calculate_incident_pair_similarity,
    extract_incident_features,
    DEFAULT_CORRELATION_WEIGHTS
)


class TestSimilarIncidentCorrelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.now_iso = self.now.isoformat()
        self.recent_iso = (self.now - timedelta(hours=2)).isoformat()
        self.old_iso = (self.now - timedelta(days=7)).isoformat()

    def test_01_two_unrelated_incidents(self):
        """TEST 1: Two completely unrelated incidents -> No meaningful relationship."""
        inc_a = Incident(
            incident_id="INC-UNREL-001",
            threat_type="Phishing",
            classification="Generic Phish",
            risk_score=70,
            risk_level="HIGH",
            evidence=[IncidentEvidenceItem(indicator="Urgent Lure", details="...")],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://alpha-finance.com", "sender": "support@alpha-finance.com"}
        )

        inc_b = Incident(
            incident_id="INC-UNREL-002",
            threat_type="Account Security",
            classification="Brute Force",
            risk_score=80,
            risk_level="HIGH",
            evidence=[IncidentEvidenceItem(indicator="Failed Logins", details="...")],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"username": "user123@beta-corp.org", "ip_address": "198.51.100.99"}
        )

        res = find_related_incidents(inc_a, [inc_b], time_window_hours=24.0, threshold=30)
        self.assertFalse(res["related"])
        self.assertEqual(res["correlation_score"], 0)
        self.assertEqual(len(res["related_incident_ids"]), 0)
        self.assertIn("No significant relationship", res["reason"])

    def test_02_same_threat_type(self):
        """TEST 2: Same threat type -> Similarity detected."""
        inc_a = Incident(
            incident_id="INC-TYPE-001",
            threat_type="Phishing",
            classification="PayPal Lure",
            risk_score=75,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://brand-a.net/login"}
        )

        inc_b = Incident(
            incident_id="INC-TYPE-002",
            threat_type="Phishing",
            classification="Netflix Lure",
            risk_score=70,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://brand-b.org/signin"}
        )

        # Pairwise check
        feat_a = extract_incident_features(inc_a)
        feat_b = extract_incident_features(inc_b)
        score, signals, reason = calculate_incident_pair_similarity(feat_a, feat_b, time_window_hours=24.0)

        self.assertIn("same_threat_type", signals)
        self.assertEqual(score, 25)

        # When threshold is set to 25, similarity is detected
        res = find_related_incidents(inc_a, [inc_b], threshold=25)
        self.assertTrue(res["related"])
        self.assertIn("INC-TYPE-002", res["related_incident_ids"])

    def test_03_same_domain_and_same_threat_type(self):
        """TEST 3: Same domain + same threat type -> Strong relationship."""
        inc_a = Incident(
            incident_id="INC-DOM-001",
            threat_type="Phishing",
            classification="Credential Lure",
            risk_score=85,
            risk_level="HIGH",
            evidence=[IncidentEvidenceItem(indicator="Credential Harvesting", details="...")],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://login-secure-portal.xyz/verify"}
        )

        inc_b = Incident(
            incident_id="INC-DOM-002",
            threat_type="Phishing",
            classification="Account Suspension Lure",
            risk_score=80,
            risk_level="HIGH",
            evidence=[IncidentEvidenceItem(indicator="Credential Harvesting", details="...")],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://login-secure-portal.xyz/signin"}
        )

        res = find_related_incidents(inc_a, [inc_b], time_window_hours=24.0, threshold=30)
        self.assertTrue(res["related"])
        self.assertGreaterEqual(res["correlation_score"], 60)
        self.assertIn("INC-DOM-002", res["related_incident_ids"])
        self.assertIn("same_domain", res["matched_signals"])
        self.assertIn("same_threat_type", res["matched_signals"])
        self.assertIn("recent_occurrence", res["matched_signals"])
        self.assertIn("shared_indicators", res["matched_signals"])
        self.assertIn("Potentially related activity", res["reason"])

    def test_04_same_exact_url(self):
        """TEST 4: Same exact URL -> Strong relationship."""
        target_url = "http://paypa1-fake-auth.com/account/login"

        inc_a = Incident(
            incident_id="INC-URL-001",
            threat_type="URL Threat",
            classification="Malicious Link",
            risk_score=90,
            risk_level="CRITICAL",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"target_url": target_url}
        )

        inc_b = Incident(
            incident_id="INC-URL-002",
            threat_type="URL Threat",
            classification="Typosquatted Host",
            risk_score=85,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"url": target_url}
        )

        res = find_related_incidents(inc_a, [inc_b], threshold=30)
        self.assertTrue(res["related"])
        self.assertGreaterEqual(res["correlation_score"], 80)
        self.assertIn("same_exact_url", res["matched_signals"])
        self.assertIn("INC-URL-002", res["related_incident_ids"])

    def test_05_same_domain_different_threat_type(self):
        """TEST 5: Same domain but different threat type has lower score than same domain + same threat type."""
        shared_domain = "evil-campaign.xyz"

        # Inc A: Phishing with evil-campaign.xyz
        inc_a = Incident(
            incident_id="INC-DIFF-001",
            threat_type="Phishing",
            classification="Email Lure",
            risk_score=80,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": f"http://{shared_domain}/signin"}
        )

        # Inc B: URL Threat with evil-campaign.xyz (Different threat_type)
        inc_b_diff_type = Incident(
            incident_id="INC-DIFF-002",
            threat_type="URL Threat",
            classification="Host Analysis",
            risk_score=75,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"url": f"http://{shared_domain}/other"}
        )

        # Inc C: Phishing with evil-campaign.xyz (Same threat_type)
        inc_c_same_type = Incident(
            incident_id="INC-DIFF-003",
            threat_type="Phishing",
            classification="Another Email Lure",
            risk_score=80,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"url": f"http://{shared_domain}/other"}
        )

        feat_a = extract_incident_features(inc_a)
        feat_b = extract_incident_features(inc_b_diff_type)
        feat_c = extract_incident_features(inc_c_same_type)

        score_diff, _, _ = calculate_incident_pair_similarity(feat_a, feat_b, time_window_hours=24.0)
        score_same, _, _ = calculate_incident_pair_similarity(feat_a, feat_c, time_window_hours=24.0)

        # Same domain + different threat_type (35) must be strictly less than same domain + same threat_type (60)
        self.assertLess(score_diff, score_same)
        self.assertEqual(score_diff, 35)
        self.assertEqual(score_same, 60)

    def test_06_old_incident_outside_time_window(self):
        """TEST 6: Old incident outside time window -> no temporal similarity awarded."""
        inc_a = Incident(
            incident_id="INC-TIME-001",
            threat_type="Phishing",
            classification="Phish A",
            risk_score=70,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": "attacker@spoofed.com"}
        )

        inc_recent = Incident(
            incident_id="INC-TIME-002",
            threat_type="Phishing",
            classification="Phish B",
            risk_score=70,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": "attacker@spoofed.com"}
        )

        inc_old = Incident(
            incident_id="INC-TIME-003",
            threat_type="Phishing",
            classification="Phish C",
            risk_score=70,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": "attacker@spoofed.com"}
        )

        feat_a = extract_incident_features(inc_a)
        feat_recent = extract_incident_features(inc_recent)
        feat_old = extract_incident_features(inc_old)

        score_recent, signals_recent, _ = calculate_incident_pair_similarity(feat_a, feat_recent, time_window_hours=24.0)
        score_old, signals_old, _ = calculate_incident_pair_similarity(feat_a, feat_old, time_window_hours=24.0)

        self.assertIn("recent_occurrence", signals_recent)
        self.assertNotIn("recent_occurrence", signals_old)
        self.assertEqual(score_recent - score_old, DEFAULT_CORRELATION_WEIGHTS["recent_occurrence"])

    def test_07_incident_compared_against_itself(self):
        """TEST 7: Incident compared against itself -> no self-correlation."""
        inc_self = Incident(
            incident_id="INC-SELF-001",
            threat_type="Phishing",
            classification="Self Test",
            risk_score=80,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://self-domain.com"}
        )

        res = find_related_incidents(inc_self, [inc_self])
        self.assertFalse(res["related"])
        self.assertEqual(res["correlation_score"], 0)
        self.assertEqual(len(res["related_incident_ids"]), 0)
        self.assertNotIn("INC-SELF-001", res["related_incident_ids"])

    def test_08_multiple_related_incidents(self):
        """TEST 8: Multiple related incidents -> all relevant previous incident IDs returned."""
        shared_sender = "fraud@campaign-source.org"

        inc_target = Incident(
            incident_id="INC-MULT-100",
            threat_type="Digital Impersonation",
            classification="CEO Fraud Target",
            risk_score=88,
            risk_level="CRITICAL",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": shared_sender}
        )

        inc_prev_1 = Incident(
            incident_id="INC-MULT-001",
            threat_type="Digital Impersonation",
            classification="CEO Fraud Batch 1",
            risk_score=85,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": shared_sender}
        )

        inc_prev_2 = Incident(
            incident_id="INC-MULT-002",
            threat_type="Digital Impersonation",
            classification="CEO Fraud Batch 2",
            risk_score=82,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": shared_sender}
        )

        inc_unrelated = Incident(
            incident_id="INC-MULT-099",
            threat_type="Account Security",
            classification="Unrelated Login",
            risk_score=50,
            risk_level="MEDIUM",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"username": "someone_else@other.com"}
        )

        res = find_related_incidents(inc_target, [inc_prev_1, inc_prev_2, inc_unrelated])
        self.assertTrue(res["related"])
        self.assertIn("INC-MULT-001", res["related_incident_ids"])
        self.assertIn("INC-MULT-002", res["related_incident_ids"])
        self.assertNotIn("INC-MULT-099", res["related_incident_ids"])
        self.assertEqual(len(res["related_incident_ids"]), 2)

    def test_09_no_previous_incidents(self):
        """TEST 9: No previous incidents -> no related activity."""
        inc_single = Incident(
            incident_id="INC-SOLO-001",
            threat_type="Phishing",
            classification="Solo Incident",
            risk_score=60,
            risk_level="MEDIUM",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://solo-test.com"}
        )

        res = find_related_incidents(inc_single, [])
        self.assertFalse(res["related"])
        self.assertEqual(res["correlation_score"], 0)
        self.assertEqual(len(res["related_incident_ids"]), 0)
        self.assertIn("No significant relationship", res["reason"])

    def test_10_api_creation_correlation_integration(self):
        """TEST 10: API incident creation automatically attaches correlation metadata."""
        incident_manager.reset_store(seed=True)

        # Submit first phishing analysis
        payload_1 = {
            "message_text": "URGENT: Please verify your banking access at http://phish-cluster-test.com/login",
            "url": "http://phish-cluster-test.com/login",
            "sender": "alert@phish-cluster-test.com"
        }
        res1 = self.client.post("/analyze/phishing", json=payload_1)
        self.assertEqual(res1.status_code, 200)

        # Submit second phishing analysis with same domain & URL
        payload_2 = {
            "message_text": "URGENT: Re-verification required immediately at http://phish-cluster-test.com/login",
            "url": "http://phish-cluster-test.com/login",
            "sender": "alert@phish-cluster-test.com"
        }
        res2 = self.client.post("/analyze/phishing", json=payload_2)
        self.assertEqual(res2.status_code, 200)

        # Fetch incidents list
        incidents_resp = self.client.get("/incidents").json()
        incidents = incidents_resp["incidents"]
        self.assertTrue(len(incidents) >= 2)

        # Latest incident should have related correlation attached
        latest = incidents[0]
        self.assertIsNotNone(latest.get("correlation"))
        self.assertTrue(latest["correlation"]["related"])
        self.assertGreaterEqual(latest["correlation"]["correlation_score"], 60)
        self.assertTrue(len(latest["correlation"]["related_incident_ids"]) >= 1)

        # Fetch incident by ID
        detail_resp = self.client.get(f"/incidents/{latest['incident_id']}")
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertIsNotNone(detail.get("correlation"))
        self.assertTrue(detail["correlation"]["related"])

    def test_11_same_sender_relationship(self):
        """TEST 11: Same sender -> relationship detected according to configured score."""
        shared_sender = "spoofed-executive@corp-notice.com"
        inc_a = Incident(
            incident_id="INC-SEND-001",
            threat_type="Digital Impersonation",
            classification="Executive Lure A",
            risk_score=75,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": shared_sender}
        )
        inc_b = Incident(
            incident_id="INC-SEND-002",
            threat_type="Digital Impersonation",
            classification="Executive Lure B",
            risk_score=70,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"sender": shared_sender}
        )
        feat_a = extract_incident_features(inc_a)
        feat_b = extract_incident_features(inc_b)
        score, signals, _ = calculate_incident_pair_similarity(feat_a, feat_b, time_window_hours=24.0)
        self.assertIn("same_sender", signals)
        self.assertGreaterEqual(score, DEFAULT_CORRELATION_WEIGHTS["same_sender"])

        # Default threshold is 30, same sender + same threat type without temporal is 30 + 25 = 55
        res = find_related_incidents(inc_a, [inc_b], threshold=30)
        self.assertTrue(res["related"])
        self.assertIn("INC-SEND-002", res["related_incident_ids"])

    def test_12_same_ip_relationship(self):
        """TEST 12: Same IP -> relationship detected according to configured score."""
        shared_ip = "198.51.100.77"
        inc_a = Incident(
            incident_id="INC-IP-001",
            threat_type="Account Security",
            classification="Brute Force A",
            risk_score=80,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"ip_address": shared_ip}
        )
        inc_b = Incident(
            incident_id="INC-IP-002",
            threat_type="Account Security",
            classification="Brute Force B",
            risk_score=80,
            risk_level="HIGH",
            evidence=[],
            explanation="...",
            recommended_actions=[],
            timestamp=self.recent_iso,
            status=IncidentStatus.NEW,
            source_data={"ip_address": shared_ip}
        )
        feat_a = extract_incident_features(inc_a)
        feat_b = extract_incident_features(inc_b)
        score, signals, _ = calculate_incident_pair_similarity(feat_a, feat_b, time_window_hours=24.0)
        self.assertIn("same_ip", signals)
        self.assertIn("recent_occurrence", signals)
        # same_ip (25) + same_threat_type (25) + recent_occurrence (10) = 60
        self.assertGreaterEqual(score, 60)

        res = find_related_incidents(inc_a, [inc_b], threshold=30)
        self.assertTrue(res["related"])
        self.assertIn("INC-IP-002", res["related_incident_ids"])

    def test_13_shared_indicators_relationship(self):
        """TEST 13: Shared indicators -> relationship according to configured score."""
        inc_a = Incident(
            incident_id="INC-IND-001",
            threat_type="Phishing",
            classification="Lure A",
            risk_score=60,
            risk_level="MEDIUM",
            evidence=[
                IncidentEvidenceItem(indicator="Credential Harvesting Trigger", details="..."),
                IncidentEvidenceItem(indicator="Urgent Coercive Language", details="...")
            ],
            explanation="...",
            recommended_actions=[],
            timestamp=self.now_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://alpha-sample.com"}
        )
        inc_b = Incident(
            incident_id="INC-IND-002",
            threat_type="Phishing",
            classification="Lure B",
            risk_score=60,
            risk_level="MEDIUM",
            evidence=[
                IncidentEvidenceItem(indicator="Credential Harvesting Trigger", details="..."),
                IncidentEvidenceItem(indicator="Different Pattern", details="...")
            ],
            explanation="...",
            recommended_actions=[],
            timestamp=self.old_iso,
            status=IncidentStatus.NEW,
            source_data={"url": "http://beta-sample.com"}
        )
        feat_a = extract_incident_features(inc_a)
        feat_b = extract_incident_features(inc_b)
        score, signals, _ = calculate_incident_pair_similarity(feat_a, feat_b, time_window_hours=24.0)
        self.assertIn("shared_indicators", signals)
        # same_threat_type (25) + shared_indicators (10) = 35 >= threshold 30
        self.assertEqual(score, 35)

        res = find_related_incidents(inc_a, [inc_b], threshold=30)
        self.assertTrue(res["related"])
        self.assertIn("INC-IND-002", res["related_incident_ids"])

    def test_14_api_correlation_response_schema(self):
        """TEST 14: Correlation API endpoint returns expected schema, sorted items, and pivots."""
        incident_manager.reset_store(seed=True)
        all_incs = incident_manager.get_all_incidents().incidents
        self.assertTrue(len(all_incs) >= 1)

        # Target INC-2026-0001 (seed phishing incident)
        target_id = "INC-2026-0001"
        resp = self.client.get(f"/api/incidents/{target_id}/correlate")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Check top-level schema
        self.assertEqual(data["incident_id"], target_id)
        self.assertIn("correlation", data)
        self.assertIn("related_incidents", data)
        self.assertIn("pivots", data)
        self.assertIn("attack_chain", data)

        # Check correlation metadata schema
        corr = data["correlation"]
        self.assertIn("related", corr)
        self.assertIn("correlation_score", corr)
        self.assertIn("matched_signals", corr)
        self.assertIn("related_incident_ids", corr)
        self.assertIn("reason", corr)

        # Check related incidents list structure and sorting
        related_incs = data["related_incidents"]
        self.assertIsInstance(related_incs, list)
        if len(related_incs) > 1:
            for idx in range(len(related_incs) - 1):
                self.assertGreaterEqual(
                    related_incs[idx]["correlation_score"],
                    related_incs[idx + 1]["correlation_score"],
                    "Related incidents must be sorted descending by correlation score"
                )
        for rel in related_incs:
            self.assertNotEqual(rel["incident_id"], target_id, "Target incident must not correlate to itself")
            self.assertIn("threat_type", rel)
            self.assertIn("correlation_score", rel)
            self.assertIn("matched_signals", rel)

    def test_15_api_vs_automatic_correlation_consistency(self):
        """TEST 15: Automatic ingestion and Correlation API return consistent results for same incident."""
        incident_manager.reset_store(seed=True)

        # Post a distinctive threat pair
        shared_domain = "cluster-test-consistent.xyz"
        res1 = self.client.post("/analyze/phishing", json={
            "message_text": "Verify account immediately",
            "url": f"http://{shared_domain}/signin",
            "sender": f"alerts@{shared_domain}"
        })
        self.assertEqual(res1.status_code, 200)

        res2 = self.client.post("/analyze/phishing", json={
            "message_text": "Account update required immediately",
            "url": f"http://{shared_domain}/verify",
            "sender": f"alerts@{shared_domain}"
        })
        self.assertEqual(res2.status_code, 200)

        # Fetch the newly created incident
        latest_inc = incident_manager.get_all_incidents().incidents[0]
        ingested_corr = latest_inc.correlation
        self.assertIsNotNone(ingested_corr)
        self.assertTrue(ingested_corr.related)

        # Query the Correlation API endpoint for the same incident
        api_resp = self.client.get(f"/api/incidents/{latest_inc.incident_id}/correlate")
        self.assertEqual(api_resp.status_code, 200)
        api_data = api_resp.json()
        api_corr = api_data["correlation"]

        # Results must be perfectly consistent across ingestion and API
        self.assertEqual(ingested_corr.related, api_corr["related"])
        self.assertEqual(ingested_corr.correlation_score, api_corr["correlation_score"])
        self.assertEqual(ingested_corr.matched_signals, api_corr["matched_signals"])
        self.assertEqual(ingested_corr.related_incident_ids, api_corr["related_incident_ids"])
        self.assertEqual(ingested_corr.reason, api_corr["reason"])


if __name__ == "__main__":
    unittest.main()

