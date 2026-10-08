"""
CYBERGUARD Account Security & Takeover Threat Detection Tests

Required test cases:
1. Normal login (safe scenario)
2. Multiple failed logins (brute-force indicator)
3. Suspicious login from unknown device + foreign location
4. Password reset + OTP manipulation (recovery chain attack)
5. Session hijacking + Impossible travel
6. Privilege escalation combined with brute-force
7. Empty payload handling
8. Score clamping (0-100) with maximum triggers
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.detectors.account_security_detector import detect_account_security_threats
from backend.engines.account_security_risk_engine import calculate_account_security_risk_score
from backend.engines.account_security_explanation_engine import generate_account_security_explanation
from backend.engines.account_security_response_engine import generate_account_security_recommended_actions


class TestAccountSecurityDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_normal_login(self):
        """Test a normal login event returns SAFE risk level."""
        payload = {
            "username": "john.doe@company.com",
            "login_location": "New York, USA",
            "device_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "failed_login_count": 0,
            "event_description": "Standard login via corporate SSO portal",
            "ip_address": "10.0.1.50"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["threat_type"], "Account Takeover & Authentication Anomaly")
        self.assertEqual(data["username"], payload["username"])
        self.assertLessEqual(data["risk_score"], 19)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertIsNone(data["confidence"])
        self.assertEqual(len(data["evidence"]), 0)
        self.assertIn("No suspicious", data["explanation"])
        self.assertIn("Transparency Notice", data["explanation"])
        self.assertTrue(len(data["recommended_actions"]) >= 1)

    def test_02_multiple_failed_logins(self):
        """Test brute-force / credential stuffing detection with 15 failed logins."""
        payload = {
            "username": "admin@cyberguard-ops.internal",
            "login_location": "Kyiv, Ukraine",
            "device_info": "Mozilla/5.0 (X11; Linux x86_64)",
            "failed_login_count": 15,
            "event_description": "Multiple rapid failed authentication attempts against admin panel",
            "ip_address": "198.51.100.42"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 30)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Brute-Force" in ind or "Failed Login" in ind for ind in indicators))
        self.assertIn("Transparency Notice", data["explanation"])
        self.assertTrue(len(data["recommended_actions"]) >= 1)

    def test_03_suspicious_unknown_device_foreign_location(self):
        """Test unknown/automated device + high-risk VPN/Tor location."""
        payload = {
            "username": "finance.admin@megacorp.com",
            "login_location": "Tor Exit Node, Anonymized",
            "device_info": "python-requests/2.31.0 (automated bot headless)",
            "failed_login_count": 3,
            "event_description": "Login attempt from unknown automated client via Tor network",
            "ip_address": "185.220.101.55"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 40)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Unknown Device" in ind or "Suspicious" in ind for ind in indicators))
        self.assertTrue(any("Anonymized" in ind or "Proxied" in ind or "High-Risk" in ind for ind in indicators))
        self.assertTrue(len(data["recommended_actions"]) >= 2)

    def test_04_password_reset_otp_manipulation(self):
        """Test password reset abuse + MFA bypass indicators."""
        payload = {
            "username": "ceo@enterprise.global",
            "login_location": "London, UK",
            "device_info": "Safari/17.0 iPhone 15",
            "failed_login_count": 0,
            "event_description": "Multiple password reset requests followed by MFA bypass attempt and authenticator removed from account. SIM swap suspected.",
            "ip_address": "203.0.113.77"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 50)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Password Reset" in ind or "Recovery" in ind for ind in indicators))
        self.assertTrue(any("MFA" in ind or "OTP" in ind or "SIM" in ind or "Authenticator" in ind for ind in indicators))
        self.assertTrue(any("MFA" in act or "multi-factor" in act.lower() for act in data["recommended_actions"]))

    def test_05_session_hijacking_impossible_travel(self):
        """Test session hijacking + impossible travel pattern."""
        payload = {
            "username": "ops-engineer@devteam.io",
            "login_location": "Tokyo, Japan",
            "device_info": "Chrome/120.0 Windows 11",
            "failed_login_count": 0,
            "event_description": "Session hijacking detected via cookie theft. Impossible travel: logged in from New York then Tokyo within 10 minutes. Concurrent session anomaly.",
            "ip_address": "103.5.140.12"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 50)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Session" in ind or "Cookie" in ind for ind in indicators))
        self.assertTrue(any("Impossible Travel" in ind or "Geographic" in ind for ind in indicators))

    def test_06_privilege_escalation_brute_force(self):
        """Test privilege escalation combined with brute-force attempts."""
        payload = {
            "username": "intern.user@company.com",
            "login_location": "Remote VPN Connection",
            "device_info": "curl/7.88.1 (automated)",
            "failed_login_count": 12,
            "event_description": "Privilege escalation detected: intern account elevated to admin role. Unauthorized admin grant followed by access level change.",
            "ip_address": "10.255.0.99"
        }
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertGreaterEqual(data["risk_score"], 60)
        self.assertIn(data["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])

        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertTrue(any("Privilege" in ind or "Role" in ind for ind in indicators))
        self.assertTrue(any("Brute-Force" in ind or "Failed Login" in ind for ind in indicators))
        self.assertTrue(any("security administrator" in act.lower() or "audit" in act.lower() for act in data["recommended_actions"]))

    def test_07_empty_payload_handling(self):
        """Test empty and null payload resilience."""
        response = self.client.post("/analyze/account-security", json={})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["risk_level"], "SAFE")
        self.assertEqual(len(data["evidence"]), 0)
        self.assertIn("No suspicious", data["explanation"])

    def test_08_score_clamping_maximum_triggers(self):
        """Test score clamping to 0-100 even with maximum triggers across all categories."""
        payload = {
            "username": "root@critical-infra.gov",
            "login_location": "North Korea via Tor VPN proxy anonymized darknet",
            "device_info": "headless automated bot selenium puppeteer emulator rooted jailbroken unknown",
            "failed_login_count": 50,
            "event_description": (
                "Critical: password reset multiple reset rapid reset recovery email changed. "
                "MFA bypass OTP bypass SIM swap MFA fatigue push bombing authenticator removed. "
                "Session hijack cookie theft concurrent session duplicate session forced logout. "
                "Impossible travel geographic anomaly location jump. "
                "Privilege escalation admin grant elevated access role change unauthorized admin."
            ),
            "ip_address": "tor vpn proxy relay i2p tunnel"
        }
        indicators = detect_account_security_threats(
            username=payload["username"],
            login_location=payload["login_location"],
            device_info=payload["device_info"],
            failed_login_count=payload["failed_login_count"],
            event_description=payload["event_description"],
            ip_address=payload["ip_address"]
        )
        score, level = calculate_account_security_risk_score(indicators)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(level, "CRITICAL")

        # Also test via API
        response = self.client.post("/analyze/account-security", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertLessEqual(data["risk_score"], 100)
        self.assertGreaterEqual(data["risk_score"], 90)
        self.assertEqual(data["risk_level"], "CRITICAL")


class TestAccountSecurityUnitFunctions(unittest.TestCase):
    """Unit tests for individual engine functions."""

    def test_detector_returns_list(self):
        result = detect_account_security_threats()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_detector_brute_force_thresholds(self):
        # 3 attempts -> low weight
        result = detect_account_security_threats(failed_login_count=3)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["weight"], 15)

        # 5 attempts -> elevated
        result = detect_account_security_threats(failed_login_count=5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["weight"], 25)

        # 10 attempts -> critical
        result = detect_account_security_threats(failed_login_count=10)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["weight"], 40)

    def test_risk_engine_empty(self):
        score, level = calculate_account_security_risk_score([])
        self.assertEqual(score, 0)
        self.assertEqual(level, "SAFE")

    def test_explanation_engine_empty(self):
        explanation = generate_account_security_explanation([], 0, "SAFE", "test_user")
        self.assertIn("No suspicious", explanation)
        self.assertIn("Transparency Notice", explanation)

    def test_response_engine_safe(self):
        actions = generate_account_security_recommended_actions([], "SAFE")
        self.assertTrue(len(actions) >= 1)
        self.assertTrue(any("No immediate" in act or "MFA" in act for act in actions))


if __name__ == "__main__":
    unittest.main()
