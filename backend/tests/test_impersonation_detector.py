"""
CYBERGUARD Digital Impersonation Detector Unit & Integration Tests

Required test cases:
1. Fake Bank Support (Brand + Support Lure + OTP/Credentials + Lookalike domain/webmail)
2. Fake Government Officer (IRS / Law Enforcement + Arrest threat + Untraceable payment)
3. Fake Company Recruiter (Recruiter persona + Free webmail mismatch + KYC data harvesting)
4. Normal Professional Message (Legitimate communication -> SAFE)
5. Lookalike Domain & Homoglyph detection
6. Score clamping & category caps (0-100)
7. Edge cases & missing parameter handling
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.detectors.impersonation_detector import detect_impersonation
from backend.engines.impersonation_risk_engine import calculate_impersonation_risk_score
from backend.engines.impersonation_explanation_engine import generate_impersonation_explanation
from backend.engines.impersonation_response_engine import generate_impersonation_recommended_actions


class TestDigitalImpersonationEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_fake_bank_support(self):
        """Test preset scenario: Fake bank support asking for OTP/credentials."""
        payload = {
            "message_text": "Dear customer, this is PayPal Support Desk. Case #88219. Suspicious login detected on your account. Send your OTP and password immediately to prevent account suspension.",
            "claimed_identity": "PayPal Security Support",
            "sender": "support-paypal@gmail.com",
            "url": "http://paypa1-security-desk.net/resolve"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["threat_type"], "Digital Impersonation")
        self.assertEqual(data["claimed_identity"], payload["claimed_identity"])
        self.assertEqual(data["sender"], payload["sender"])
        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])
        self.assertIsNone(data["confidence"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Recognized Brand" in ind for ind in indicators))
        self.assertTrue(any("Fake Support" in ind for ind in indicators))
        self.assertTrue(any("Free Webmail" in ind for ind in indicators))
        self.assertTrue(any("OTP" in ind for ind in indicators))
        self.assertTrue(any("Lookalike" in ind for ind in indicators))

        self.assertIn("Transparency Notice", data["explanation"])
        self.assertTrue(any("DO NOT" in action or "OTP" in action for action in data["recommended_actions"]))

    def test_02_fake_government_officer(self):
        """Test preset scenario: Fake government / law enforcement tax refund/warrant scam."""
        payload = {
            "message_text": "INTERNAL REVENUE SERVICE (IRS) FINAL LEGAL NOTICE: An arrest warrant has been issued against you for tax evasion. You must settle the penalty fee immediately via wire transfer or Apple gift cards within 2 hours.",
            "claimed_identity": "IRS Investigation Department",
            "sender": "officer.irs.gov@outlook.com",
            "url": "http://irs-penalty-settlement-gov.xyz"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Authority Impersonation" in ind for ind in indicators))
        self.assertTrue(any("Free Webmail" in ind for ind in indicators))
        self.assertTrue(any("Untraceable Payment" in ind or "Financial" in ind for ind in indicators))
        self.assertTrue(any("Coercive Threat" in ind or "Urgent" in ind for ind in indicators))

        self.assertTrue(any("official .gov" in act for act in data["recommended_actions"]))

    def test_03_fake_company_recruiter(self):
        """Test preset scenario: Fake corporate recruiter / HR talent acquisition."""
        payload = {
            "message_text": "Hi, I am HR Director from Amazon Recruitment Team. We have an executive job offer for you. Please submit your passport copy, SSN, and national ID card immediately to start onboarding.",
            "claimed_identity": "Amazon Human Resources",
            "sender": "amazon.talent.hiring@yahoo.com",
            "url": "http://amazon-career-onboarding.top"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 60)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Recruiter" in ind or "Corporate" in ind for ind in indicators))
        self.assertTrue(any("Sensitive Identity" in ind or "KYC" in ind for ind in indicators))
        self.assertTrue(any("Free Webmail" in ind for ind in indicators))

    def test_04_normal_professional_message(self):
        """Test preset scenario: Legitimate business communication with no threats."""
        payload = {
            "message_text": "Hi Sarah, thanks for meeting today. Attached is the project proposal draft for our quarterly review. Let me know if you have any questions.",
            "claimed_identity": "Sarah Jenkins",
            "sender": "sarah.jenkins@acme-corp.com",
            "url": "https://www.acme-corp.com/projects"
        }
        response = self.client.post("/analyze/impersonation", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertLessEqual(data["risk_score"], 19)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertEqual(len(data["evidence"]), 0)
        self.assertIn("No deceptive impersonation markers", data["explanation"])
        self.assertIn("Transparency Notice", data["explanation"])

    def test_05_lookalike_domain_detection(self):
        """Test lookalike homoglyph domain matching."""
        indicators = detect_impersonation(
            message_text="Please sign in to confirm your identity",
            claimed_identity="Microsoft 365",
            sender="admin@micros0ft-login.com",
            url="http://micros0ft-verify.com"
        )
        has_lookalike = any(item["category"] == "lookalike_domain" for item in indicators)
        self.assertTrue(has_lookalike)

    def test_06_score_clamping_and_caps(self):
        """Test that score cannot exceed 100 or fall below 0 even with maximum triggers."""
        extreme_text = "IRS FBI POLICE CEO CFO Wire transfer bitcoin gift cards send money immediately arrest warrant OTP password SSN passport"
        indicators = detect_impersonation(
            message_text=extreme_text,
            claimed_identity="FBI & IRS & PayPal",
            sender="fbi@gmail.com",
            url="http://paypa1-irs-fbi.net"
        )
        score, level = calculate_impersonation_risk_score(indicators)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(level, "CRITICAL")

    def test_07_empty_payload_handling(self):
        """Test empty and null payload resilience."""
        response = self.client.post("/analyze/impersonation", json={})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertEqual(len(data["evidence"]), 0)


if __name__ == "__main__":
    unittest.main()
