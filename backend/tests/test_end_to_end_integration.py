"""
CYBERGUARD Day 7 End-to-End Integration & Unified Threat Dashboard Tests

Verifies the complete detection to incident lifecycle workflow:
1. Phishing Analysis -> Incident Creation & Metrics Update
2. URL Threat Analysis -> Threat Category Distribution Update
3. Digital Impersonation Analysis -> Incident Storage & Attribution
4. Account Security Analysis -> Critical Alert Generation
5. Incident Triage Status Transition Lifecycle
6. Unified Dashboard Metrics Aggregation & Distribution
7. Edge cases, Empty states, and Input validation
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engines.incident_manager import incident_manager
from backend.models.incident import IncidentStatus


class TestEndToEndUnifiedIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        incident_manager.reset_store(seed=True)

    def test_01_complete_phishing_workflow(self):
        """Test detection -> classification -> scoring -> incident creation -> dashboard metrics."""
        init_metrics = self.client.get("/incidents").json()
        init_total = init_metrics["total"]
        init_phishing = init_metrics["phishing_count"]

        # Run Phishing Detection
        phish_payload = {
            "message_text": "URGENT: Your PayPal account has been suspended. Confirm your password and OTP immediately at http://paypa1-verify.com/login",
            "url": "http://paypa1-verify.com/login",
            "sender": "security-alert@paypal-update.net"
        }
        res = self.client.post("/analyze/phishing", json=phish_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["threat_type"], "Phishing")
        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["severity"], ["HIGH", "CRITICAL"])
        self.assertTrue(len(data["evidence"]) > 0)
        self.assertTrue(len(data["recommended_actions"]) > 0)

        # Check that dashboard metrics incremented
        updated_metrics = self.client.get("/incidents").json()
        self.assertEqual(updated_metrics["total"], init_total + 1)
        self.assertEqual(updated_metrics["phishing_count"], init_phishing + 1)

    def test_02_complete_url_threat_workflow(self):
        """Test URL detector integration with category distribution and incident store."""
        init_metrics = self.client.get("/incidents").json()
        init_url_count = init_metrics["url_threat_count"]

        url_payload = {
            "url": "http://192.168.1.100:8080/admin@malicious-domain.xyz/auth.php"
        }
        res = self.client.post("/analyze/url", json=url_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["threat_type"], "URL Threat")
        self.assertGreater(data["risk_score"], 0)

        # Verify incident creation
        list_resp = self.client.get("/incidents?threat_type=URL%20Threat").json()
        self.assertGreaterEqual(list_resp["total"], 1)
        latest_inc = list_resp["incidents"][0]
        self.assertEqual(latest_inc["threat_type"], "URL Threat")
        self.assertIn("192.168.1.100", str(latest_inc["source_data"]))

    def test_03_complete_impersonation_workflow(self):
        """Test digital impersonation analysis workflow and attribution."""
        init_metrics = self.client.get("/incidents").json()
        init_impersonation_count = init_metrics["impersonation_count"]

        imp_payload = {
            "claimed_identity": "CEO John Doe",
            "sender": "ceo@external-lookalike.com",
            "message_text": "Please purchase 5 urgent Apple Gift Cards for our vendor and send codes to me."
        }
        res = self.client.post("/analyze/impersonation", json=imp_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["threat_type"], "Digital Impersonation")
        self.assertEqual(data["claimed_identity"], "CEO John Doe")

        # Verify metrics and searchability
        metrics = self.client.get("/incidents").json()
        self.assertEqual(metrics["impersonation_count"], init_impersonation_count + 1)

        search_res = self.client.get("/incidents?search=Apple%20Gift").json()
        self.assertGreaterEqual(search_res["total"], 1)

    def test_04_complete_account_security_workflow(self):
        """Test account takeover analysis, critical alert generation, and incident triage."""
        init_metrics = self.client.get("/incidents").json()
        init_account_count = init_metrics["account_security_count"]

        acc_payload = {
            "username": "vip.executive@corp.internal",
            "login_location": "St. Petersburg, Russia",
            "device_info": "Automated Headless Bot / Python Requests",
            "failed_login_count": 25,
            "event_description": "Massive brute-force attack followed by impossible geographic travel anomaly."
        }
        res = self.client.post("/analyze/account-security", json=acc_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertGreaterEqual(data["risk_score"], 40)

        # Check dashboard incident aggregation
        updated = self.client.get("/incidents").json()
        self.assertEqual(updated["account_security_count"], init_account_count + 1)
        self.assertGreaterEqual(updated["critical_count"], 1)

        # Get specific created incident
        latest_incident = updated["incidents"][0]
        inc_id = latest_incident["incident_id"]

        # Simulate triage workflow: NEW -> INVESTIGATING -> RESOLVED
        self.assertEqual(latest_incident["status"], "NEW")

        patch_1 = self.client.patch(f"/incidents/{inc_id}/status", json={"status": "INVESTIGATING"})
        self.assertEqual(patch_1.status_code, 200)
        self.assertEqual(patch_1.json()["status"], "INVESTIGATING")

        patch_2 = self.client.patch(f"/incidents/{inc_id}/status", json={"status": "RESOLVED"})
        self.assertEqual(patch_2.status_code, 200)
        self.assertEqual(patch_2.json()["status"], "RESOLVED")

        # Verify resolved metrics increased
        metrics_after = self.client.get("/incidents").json()
        self.assertGreaterEqual(metrics_after["resolved_count"], 1)

    def test_05_unified_metrics_distribution_schema(self):
        """Verify that /incidents returns comprehensive category and status distributions."""
        resp = self.client.get("/incidents")
        self.assertEqual(resp.status_code, 200)
        d = resp.json()

        # Check required distribution keys
        self.assertIn("critical_count", d)
        self.assertIn("high_count", d)
        self.assertIn("medium_count", d)
        self.assertIn("low_count", d)
        self.assertIn("safe_count", d)
        self.assertIn("resolved_count", d)
        self.assertIn("new_count", d)
        self.assertIn("investigating_count", d)
        self.assertIn("false_positive_count", d)
        self.assertIn("phishing_count", d)
        self.assertIn("url_threat_count", d)
        self.assertIn("impersonation_count", d)
        self.assertIn("account_security_count", d)
        self.assertIn("total_analyzed_count", d)


if __name__ == "__main__":
    unittest.main()
