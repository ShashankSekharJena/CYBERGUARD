"""
CYBERGUARD Digital Impersonation Detector Unit & Integration Tests

Required test scenarios:
1. Fake Bank Support
2. Fake Government Officer
3. Fake Company Recruiter
4. Normal Professional Message
5. Sender Domain / Free Webmail Mismatch
6. Malformed & Empty Inputs Resilience
7. Category Caps & Score Clamping
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.detectors.impersonation_detector import detect_impersonation
from backend.engines.impersonation_risk_engine import calculate_impersonation_risk_score


class TestDigitalImpersonationEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_fake_bank_support(self):
        """Test impersonation of financial institution customer support."""
        payload = {
            "message_text": "Chase Customer Support: Suspicious login attempt detected. Provide your OTP code and password immediately to unlock your account.",
            "claimed_identity": "Chase Bank Customer Support",
            "sender": "support@chase-security-alerts.xyz",
            "url": "http://chase-login-verify.xyz"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["threat_type"], "Digital Impersonation")
        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Brand" in ind or "Chase" in ind for ind in indicators) or "Recognized Brand Reference" in indicators)
        self.assertTrue("OTP / 2FA Token Solicitation" in indicators or "Password / Credential Request" in indicators)

    def test_02_fake_government_officer(self):
        """Test impersonation of federal tax agency threatening legal arrest."""
        payload = {
            "message_text": "IRS Tax Investigation Unit: Unpaid tax balance detected under your SSN. Submit immediate wire transfer within 2 hours or police will execute an arrest warrant.",
            "claimed_identity": "Internal Revenue Service Agent",
            "sender": "investigator-irs-department@gmail.com"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Authority Impersonation (Government Tax Authority)", indicators)
        self.assertIn("Free Webmail Sender Mismatch", indicators)
        self.assertIn("Untraceable Payment Solicitation", indicators)

    def test_03_fake_company_recruiter(self):
        """Test impersonation of corporate talent recruiter requesting gift card purchase."""
        payload = {
            "message_text": "Amazon Talent Acquisition: Congratulations on your job offer! Please purchase $500 Apple gift card for equipment onboarding and send your passport copy.",
            "claimed_identity": "Amazon HR Recruiter",
            "sender": "amazon.careers.team@yahoo.com"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Corporate Recruiter / HR Persona", indicators)
        self.assertIn("Free Webmail Sender Mismatch", indicators)
        self.assertIn("Untraceable Payment Solicitation", indicators)

    def test_04_normal_professional_message(self):
        """Test legitimate day-to-day business communication."""
        payload = {
            "message_text": "Hi Alex, please find the quarterly engineering summary slides attached for tomorrow's sync.",
            "claimed_identity": "Alex Director",
            "sender": "alex.director@company.corp"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 19)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertIsNone(data["confidence"])
        self.assertEqual(len(data["evidence"]), 0)

    def test_05_sender_mismatch_free_webmail(self):
        """Test mismatch when official Microsoft desk uses a free @gmail.com address."""
        payload = {
            "message_text": "Microsoft IT Support: Please confirm your details.",
            "claimed_identity": "Microsoft Corporation",
            "sender": "msft-security-center@gmail.com"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Free Webmail Sender Mismatch", indicators)
        self.assertGreaterEqual(data["risk_score"], 40)

    def test_06_malformed_and_empty_inputs(self):
        """Verify endpoint resilience with empty payloads and abnormal strings."""
        payloads = [
            {},
            {"message_text": "", "claimed_identity": None},
            {"message_text": "A" * 5000, "sender": "invalid-format"},
        ]
        for p in payloads:
            response = self.client.post("/analyze/impersonation", json=p)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIsInstance(data["risk_score"], int)
            self.assertGreaterEqual(data["risk_score"], 0)
            self.assertLessEqual(data["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
