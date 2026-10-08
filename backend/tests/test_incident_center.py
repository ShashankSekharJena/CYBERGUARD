"""
CYBERGUARD Incident Center & Threat Response Dashboard Tests

Tests the centralized incident management lifecycle:
1. Incident creation from a Phishing analysis
2. Incident creation from a URL Threat analysis
3. Incident creation from a Digital Impersonation analysis
4. Incident creation from an Account Security analysis
5. Multi-criteria incident filtering (threat_type, risk_level, status, text search)
6. Incident status updating and status transition validation
7. Empty incident state handling
8. Invalid incident ID handling (404) & validation errors (422)
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engines.incident_manager import incident_manager
from backend.models.incident import IncidentStatus


class TestIncidentCenterLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Reset incident store to baseline seed state before each test
        incident_manager.reset_store(seed=True)

    def test_01_incident_creation_from_phishing_analysis(self):
        """Verify calling /analyze/phishing automatically logs an incident."""
        initial_list = self.client.get("/incidents").json()
        initial_count = initial_list["total"]

        payload = {
            "message_text": "URGENT: Your bank account will be suspended immediately. Click here to confirm your password and security code.",
            "url": "http://192.168.1.1/secure-bank-login",
            "sender": "security@fake-bank-auth.com"
        }
        resp = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Check incidents list now has one more incident
        list_resp = self.client.get("/incidents")
        self.assertEqual(list_resp.status_code, 200)
        incidents_data = list_resp.json()
        self.assertEqual(incidents_data["total"], initial_count + 1)

        # The latest incident should be our phishing event
        latest = incidents_data["incidents"][0]
        self.assertEqual(latest["threat_type"], "Phishing")
        self.assertEqual(latest["risk_score"], data["risk_score"])
        self.assertEqual(latest["risk_level"], data["severity"])
        self.assertEqual(latest["status"], "NEW")
        self.assertTrue(len(latest["evidence"]) > 0)
        self.assertTrue(len(latest["recommended_actions"]) > 0)

    def test_02_incident_creation_from_url_analysis(self):
        """Verify calling /analyze/url automatically logs an incident."""
        initial_count = self.client.get("/incidents").json()["total"]

        payload = {
            "url": "http://192.168.1.50/admin@malicious-redirect.com/login"
        }
        resp = self.client.post("/analyze/url", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        list_resp = self.client.get("/incidents?threat_type=URL%20Threat")
        self.assertEqual(list_resp.status_code, 200)
        incidents = list_resp.json()["incidents"]
        self.assertTrue(any("192.168.1.50" in str(inc.get("source_data")) for inc in incidents))

    def test_03_incident_creation_from_impersonation_analysis(self):
        """Verify calling /analyze/impersonation automatically logs an incident."""
        initial_count = self.client.get("/incidents").json()["total"]

        payload = {
            "claimed_identity": "CEO Executive",
            "sender": "ceo@external-lookalike-domain.com",
            "message_text": "Please purchase 10 Apple gift cards and wire the receipt codes immediately."
        }
        resp = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        list_resp = self.client.get("/incidents?threat_type=Digital%20Impersonation")
        self.assertEqual(list_resp.status_code, 200)
        incidents = list_resp.json()["incidents"]
        self.assertTrue(any(inc["risk_score"] == data["risk_score"] for inc in incidents))

    def test_04_incident_creation_from_account_security_analysis(self):
        """Verify calling /analyze/account-security automatically logs an incident."""
        payload = {
            "username": "victim.user@enterprise.corp",
            "login_location": "Moscow, Russia",
            "device_info": "python-requests/2.31.0 automated script",
            "failed_login_count": 20,
            "event_description": "Massive brute-force attack detected on user credentials."
        }
        resp = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        list_resp = self.client.get("/incidents?search=victim.user@enterprise.corp")
        self.assertEqual(list_resp.status_code, 200)
        results = list_resp.json()
        self.assertGreaterEqual(results["total"], 1)
        self.assertEqual(results["incidents"][0]["threat_type"], "Account Security")

    def test_05_incident_filtering(self):
        """Test multi-dimensional filtering by threat type, risk level, status, and search."""
        # 1. Filter by threat_type
        resp = self.client.get("/incidents?threat_type=Phishing")
        self.assertEqual(resp.status_code, 200)
        for inc in resp.json()["incidents"]:
            self.assertEqual(inc["threat_type"], "Phishing")

        # 2. Filter by risk_level
        resp = self.client.get("/incidents?risk_level=CRITICAL")
        self.assertEqual(resp.status_code, 200)
        for inc in resp.json()["incidents"]:
            self.assertEqual(inc["risk_level"], "CRITICAL")

        # 3. Filter by status
        resp = self.client.get("/incidents?status=INVESTIGATING")
        self.assertEqual(resp.status_code, 200)
        for inc in resp.json()["incidents"]:
            self.assertEqual(inc["status"], "INVESTIGATING")

        # 4. Search text filter
        resp = self.client.get("/incidents?search=PayPal")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.json()["total"], 1)

    def test_06_incident_status_update(self):
        """Test updating incident status from NEW to INVESTIGATING, RESOLVED, FALSE_POSITIVE."""
        # Fetch an existing incident
        all_incidents = self.client.get("/incidents").json()["incidents"]
        self.assertTrue(len(all_incidents) > 0)
        target_id = all_incidents[0]["incident_id"]

        # Update to INVESTIGATING
        patch_resp = self.client.patch(
            f"/incidents/{target_id}/status",
            json={"status": "INVESTIGATING"}
        )
        self.assertEqual(patch_resp.status_code, 200)
        self.assertEqual(patch_resp.json()["status"], "INVESTIGATING")

        # Verify through GET
        get_resp = self.client.get(f"/incidents/{target_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["status"], "INVESTIGATING")

        # Update to RESOLVED
        patch_resp2 = self.client.patch(
            f"/incidents/{target_id}/status",
            json={"status": "RESOLVED"}
        )
        self.assertEqual(patch_resp2.status_code, 200)
        self.assertEqual(patch_resp2.json()["status"], "RESOLVED")

        # Update to FALSE_POSITIVE
        patch_resp3 = self.client.patch(
            f"/incidents/{target_id}/status",
            json={"status": "FALSE_POSITIVE"}
        )
        self.assertEqual(patch_resp3.status_code, 200)
        self.assertEqual(patch_resp3.json()["status"], "FALSE_POSITIVE")

    def test_07_empty_incident_state(self):
        """Test query response when incident store is cleared."""
        incident_manager.reset_store(seed=False)
        resp = self.client.get("/incidents")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(len(data["incidents"]), 0)
        self.assertEqual(data["critical_count"], 0)
        self.assertEqual(data["resolved_count"], 0)

    def test_08_invalid_incident_id_and_validation(self):
        """Test 404 for non-existent incident and 422 for invalid status."""
        # 1. Non-existent ID
        resp = self.client.get("/incidents/INC-9999-9999")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json()["detail"].lower())

        # 2. Patch non-existent ID
        patch_resp = self.client.patch(
            "/incidents/INC-9999-9999/status",
            json={"status": "RESOLVED"}
        )
        self.assertEqual(patch_resp.status_code, 404)

        # 3. Invalid status string
        patch_resp_invalid = self.client.patch(
            "/incidents/INC-2026-0001/status",
            json={"status": "UNKNOWN_CUSTOM_STATUS"}
        )
        self.assertEqual(patch_resp_invalid.status_code, 422)


if __name__ == "__main__":
    unittest.main()
