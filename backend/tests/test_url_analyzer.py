"""
CYBERGUARD URL, Domain & IP Analyzer Unit & Integration Tests

Required test cases:
1. Normal HTTPS URL
2. Suspicious IP URL
3. Shortened URL
4. Fake login URL
5. Malformed URL resilience
6. Score clamping & category caps
7. Legitimate domain (example.com)
8. Suspicious-looking domain (login-secure-example.xyz)
9. Full URL with domain extraction (https://example.com/login)
10. IP address analysis (8.8.8.8)
11. Invalid input validation (not-a-valid-domain)
12. URL containing IP host (http://192.168.1.10/login)
13. Punycode domain detection (xn--pple-43d.com)
14. Normalization and explicit input types
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.detectors.url_detector import detect_url_threats, detect_domain_threats, analyze_ip_address, normalize_target_input, analyze_target_telemetry
from backend.engines.url_risk_engine import calculate_url_risk_score
from backend.engines.url_explanation_engine import generate_url_explanation
from backend.engines.url_response_engine import generate_url_recommended_actions


class TestUrlThreatAnalysisEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # -------------------------------------------------------------
    # Existing Baseline Test Suite (Preserved for 100% Backward Compatibility)
    # -------------------------------------------------------------

    def test_01_normal_https_url(self):
        """Test with legitimate, standard HTTPS URL."""
        payload = {
            "url": "https://www.google.com/search?q=cybersecurity"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["threat_type"], "URL Threat")
        self.assertEqual(data["target_url"], payload["url"])
        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 19)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertIsNone(data["confidence"])
        self.assertEqual(len(data["evidence"]), 0)
        self.assertIn("No anomalous or suspicious", data["explanation"])
        self.assertTrue(len(data["recommended_actions"]) > 0)

    def test_02_suspicious_ip_url(self):
        """Test with raw IP address host and unencrypted HTTP."""
        payload = {
            "url": "http://192.168.1.100/admin/login"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 40)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("IP Address Host", indicators)
        self.assertIn("Unencrypted HTTP Protocol", indicators)
        self.assertIn("Suspicious Security Keywords", indicators)

    def test_03_shortened_url(self):
        """Test with known URL shortener service."""
        payload = {
            "url": "https://bit.ly/3xY9zQ"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("URL Shortener Service", indicators)
        self.assertGreaterEqual(data["risk_score"], 20)
        actions_str = " ".join(data["recommended_actions"])
        self.assertTrue("unshorten" in actions_str.lower() or "expansion" in actions_str.lower() or "shortened" in actions_str.lower())

    def test_04_fake_login_url(self):
        """Test with multi-vector phishing/typosquatting URL."""
        payload = {
            "url": "http://paypa1-account-security-update.xyz/login/verify?token=%20%20%2e"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 70)
        self.assertIn(data["risk_level"], ["HIGH", "CRITICAL"])
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Brand Lookalike Domain", indicators)
        self.assertIn("Suspicious Security Keywords", indicators)
        self.assertIn("Unencrypted HTTP Protocol", indicators)
        self.assertIn("Suspicious Top-Level Domain", indicators)
        self.assertIn("Excessive Domain Hyphenation", indicators)

    def test_05_malformed_url_resilience(self):
        """Ensure backend does not crash on malformed or unusual inputs."""
        test_inputs = [
            "http://:::invalid-port:99999",
            "http://[::1]:9999999/test",
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "not_a_url_at_all$$$###"
        ]
        for u in test_inputs:
            response = self.client.post("/analyze/url", json={"url": u})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIsInstance(data["risk_score"], int)
            self.assertGreaterEqual(data["risk_score"], 0)
            self.assertLessEqual(data["risk_score"], 100)

    def test_06_score_cap_and_boundaries(self):
        """Test that category caps prevent unbounded inflation."""
        payload = {
            "url": "http://192.168.1.1/login/signin/verify/secure/account/password/banking/wallet/confirm/update?a=" + ("x" * 300)
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertLessEqual(data["risk_score"], 100)
        self.assertGreaterEqual(data["risk_score"], 0)

    # -------------------------------------------------------------
    # New Extended Capabilities Test Suite (Requirements A through G)
    # -------------------------------------------------------------

    def test_07_legitimate_domain(self):
        """Requirement A: Legitimate domain (example.com) -> valid domain, no false malicious claim."""
        payload = {
            "input": "example.com",
            "input_type": "domain"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["input_type"], "domain")
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["tld"], ".com")
        self.assertIsNone(data["subdomain"])
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertEqual(data["risk_score"], 0)
        self.assertIsNotNone(data["domain_details"])
        self.assertTrue(data["domain_details"]["is_valid"])
        self.assertIn("No anomalous or suspicious", data["explanation"])

    def test_08_suspicious_looking_domain(self):
        """Requirement B: Suspicious domain (login-secure-example.xyz) -> characteristics extracted & indicators."""
        payload = {
            "input": "login-secure-example.xyz",
            "input_type": "domain"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["input_type"], "domain")
        self.assertEqual(data["domain"], "login-secure-example.xyz")
        self.assertEqual(data["tld"], ".xyz")
        self.assertGreaterEqual(data["risk_score"], 40)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH"])
        
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Suspicious Security Keywords", indicators)
        self.assertIn("Suspicious Top-Level Domain", indicators)
        self.assertIn("Excessive Domain Hyphenation", indicators)

    def test_09_full_url_domain_extraction(self):
        """Requirement C: Full URL (https://example.com/login) -> URL parsed correctly, domain extracted."""
        payload = {
            "input": "https://example.com/login",
            "input_type": "url"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["input_type"], "url")
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["tld"], ".com")
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertIsNotNone(data["domain_details"])

    def test_10_ip_address_analysis(self):
        """Requirement D: IP address (8.8.8.8) -> recognized as IPv4 public IP input."""
        payload = {
            "input": "8.8.8.8",
            "input_type": "ip"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["input_type"], "ip")
        self.assertEqual(data["ip_address"], "8.8.8.8")
        self.assertIsNotNone(data["ip_details"])
        self.assertEqual(data["ip_details"]["version"], "IPv4")
        self.assertFalse(data["ip_details"]["is_private"])
        self.assertTrue(data["ip_details"]["is_global"])
        self.assertTrue(data["ip_details"]["is_valid"])

    def test_11_invalid_domain_input(self):
        """Requirement E: Invalid input (not-a-valid-domain) -> clear validation finding."""
        payload = {
            "input": "not-a-valid-domain",
            "input_type": "domain"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Invalid Domain Format", indicators)
        self.assertIsNotNone(data["domain_details"])
        self.assertFalse(data["domain_details"]["is_valid"])
        self.assertIn("Validation Notice", data["explanation"])

    def test_12_url_containing_ip_host(self):
        """Requirement F: URL containing IP (http://192.168.1.10/login) -> IP hostname detected."""
        payload = {
            "input": "http://192.168.1.10/login",
            "input_type": "url"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["input_type"], "url")
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("IP Address Host", indicators)
        self.assertIsNotNone(data["domain_details"])
        self.assertTrue(data["domain_details"]["is_ip_hostname"])
        self.assertIsNotNone(data["ip_details"])
        self.assertEqual(data["ip_details"]["ip_address"], "192.168.1.10")
        self.assertTrue(data["ip_details"]["is_private"])

    def test_13_punycode_domain(self):
        """Requirement G: Punycode domain -> punycode indicator detected."""
        payload = {
            "input": "xn--pple-43d.com",
            "input_type": "domain"
        }
        response = self.client.post("/analyze/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Punycode / IDN Domain", indicators)
        self.assertIsNotNone(data["domain_details"])
        self.assertTrue(data["domain_details"]["is_punycode"])

    def test_14_auto_detection_mode(self):
        """Test auto-detection mode handles IP, Domain, and URL seamlessly."""
        # 1. Auto IP
        res_ip = self.client.post("/analyze/url", json={"input": "1.1.1.1"}).json()
        self.assertEqual(res_ip["input_type"], "ip")
        self.assertEqual(res_ip["ip_address"], "1.1.1.1")

        # 2. Auto Domain
        res_dom = self.client.post("/analyze/url", json={"input": "github.com"}).json()
        self.assertEqual(res_dom["input_type"], "domain")
        self.assertEqual(res_dom["domain"], "github.com")

        # 3. Auto URL
        res_url = self.client.post("/analyze/url", json={"input": "https://github.com/features"}).json()
        self.assertEqual(res_url["input_type"], "url")
        self.assertEqual(res_url["domain"], "github.com")


if __name__ == "__main__":
    unittest.main()
