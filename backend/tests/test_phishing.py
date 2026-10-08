"""
CYBERGUARD Phishing Engine Unit & Integration Tests

Covers 8 core scenarios:
1. Empty input
2. Normal safe-looking message
3. Suspicious credential request
4. Suspicious URL (IP host, @ syntax, dangerous scheme)
5. Combined phishing indicators (urgent language + threat + credential lure + lookalike URL)
6. Malformed URL
7. Very long input (10,000+ characters)
8. Duplicate indicators (verify score does not artificially inflate)
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.detectors.phishing_detector import (
    analyze_text,
    analyze_url,
    analyze_domain_mismatch,
    detect_phishing
)
from backend.engines.risk_engine import calculate_risk_score
from backend.engines.explanation_engine import generate_explanation
from backend.engines.response_engine import generate_recommended_actions


class TestPhishingDetectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_empty_input(self):
        """Test with empty JSON payload and None fields."""
        response = self.client.post("/analyze/phishing", json={})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["threat_type"], "Phishing")
        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["severity"], "SAFE")
        self.assertIsNone(data["confidence"])
        self.assertEqual(len(data["evidence"]), 0)
        self.assertIn("No overt phishing indicators", data["explanation"])
        self.assertTrue(len(data["recommended_actions"]) > 0)

    def test_02_safe_normal_message(self):
        """Test with normal everyday business communication."""
        payload = {
            "message_text": "Hi team, the weekly project review meeting is scheduled for 3 PM in Conference Room B.",
            "url": "https://company-intranet.corp/calendar"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 19)
        self.assertEqual(data["severity"], "SAFE")
        self.assertIsNone(data["confidence"])
        self.assertEqual(len(data["evidence"]), 0)

    def test_03_suspicious_credential_request(self):
        """Test with message soliciting passwords and credentials."""
        payload = {
            "message_text": "Please verify your password immediately to avoid disruption to your account."
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreater(data["risk_score"], 0)
        self.assertIn(data["severity"], ["LOW", "MEDIUM", "HIGH"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Credential request", indicators)
        self.assertIn("Urgent language", indicators)
        # Verify recommended actions suggest credential protections
        actions_str = " ".join(data["recommended_actions"])
        self.assertTrue("password" in actions_str.lower() or "credentials" in actions_str.lower())

    def test_04_suspicious_url(self):
        """Test with suspicious URL patterns (raw IP, @ symbol, suspicious TLD)."""
        payload = {
            "message_text": "Check this update.",
            "url": "http://192.168.1.50/login@portal.com/update.xyz"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("IP address in URL", indicators)
        self.assertIn("@ symbol in URL", indicators)
        self.assertGreaterEqual(data["risk_score"], 40)
        self.assertIn(data["severity"], ["MEDIUM", "HIGH"])

    def test_05_combined_phishing_indicators(self):
        """Test realistic phishing attack combining urgency, threat, credential solicitation, and lookalike domain."""
        payload = {
            "message_text": "URGENT: Your PayPal account will be suspended within 24 hours. Click here to verify your password immediately.",
            "url": "http://paypa1-security-verification.com/login"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["severity"], ["HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Urgent language", indicators)
        self.assertIn("Threatening language", indicators)
        self.assertIn("Credential request", indicators)
        self.assertTrue("Possible look-alike domain" in indicators or "Organization domain mismatch" in indicators)
        self.assertIn("Do not click", " ".join(data["recommended_actions"]))

    def test_06_malformed_url(self):
        """Test that malformed or strange URLs do not crash the backend."""
        payloads = [
            {"message_text": "Test message", "url": "http://:::invalid"},
            {"message_text": "Test message", "url": "not_a_url_at_all$$$"},
            {"message_text": "Test message", "url": "javascript:alert(1)"},
        ]
        for p in payloads:
            response = self.client.post("/analyze/phishing", json=p)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIsInstance(data["risk_score"], int)
            self.assertGreaterEqual(data["risk_score"], 0)
            self.assertLessEqual(data["risk_score"], 100)

    def test_07_very_long_input(self):
        """Test with massive input string (10,000+ chars) to ensure no buffer or regex hang."""
        long_text = "Standard notice text with some info. " * 400 + " Urgent: please verify your password immediately."
        payload = {
            "message_text": long_text,
            "url": "https://example.com/very/long/" + ("a" * 250)
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data["risk_score"], int)
        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 100)
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Excessively long URL", indicators)

    def test_08_duplicate_indicators(self):
        """Verify that repeating the same keywords repeatedly does not multiply the score past category caps."""
        single_payload = {
            "message_text": "URGENT: Immediately act now!"
        }
        repeated_payload = {
            "message_text": "URGENT: Immediately act now! ASAP right now immediately act now time sensitive immediately!"
        }
        res_single = self.client.post("/analyze/phishing", json=single_payload).json()
        res_repeated = self.client.post("/analyze/phishing", json=repeated_payload).json()

        # Both trigger only urgency category, so scores should be identical and capped
        self.assertEqual(res_single["risk_score"], res_repeated["risk_score"])
        self.assertEqual(res_single["severity"], res_repeated["severity"])


if __name__ == "__main__":
    unittest.main()
