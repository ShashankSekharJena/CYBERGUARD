"""
Unit Tests for Defensive Incident Response Playbook Engine
Tests playbook generation across threat categories and verifies advisory non-disruptive guarantees.
"""

import unittest
from backend.engines.playbook_engine import generate_playbook


class TestPlaybookEngine(unittest.TestCase):

    def test_phishing_playbook_generation(self):
        pb = generate_playbook("Phishing", "CRITICAL")
        self.assertEqual(pb.threat_category, "Phishing")
        self.assertEqual(pb.severity_level, "CRITICAL")
        self.assertGreaterEqual(len(pb.steps), 4)
        phases = [s.phase for s in pb.steps]
        self.assertIn("Containment", phases)
        self.assertIn("Remediation", phases)
        self.assertIn("Hardening", phases)
        self.assertIn("ADVISORY", pb.disclaimer)

    def test_account_security_playbook_generation(self):
        pb = generate_playbook("Account Security", "HIGH")
        self.assertEqual(pb.threat_category, "Account Security")
        self.assertTrue(any("MFA" in s.title for s in pb.steps))
        self.assertTrue(any("Session" in s.title for s in pb.steps))

    def test_multimedia_playbook_generation(self):
        pb = generate_playbook("Multimedia Impersonation", "MEDIUM")
        self.assertEqual(pb.threat_category, "Multimedia Impersonation")
        self.assertTrue(any("Forensic" in s.title or "C2PA" in s.description for s in pb.steps))


if __name__ == "__main__":
    unittest.main()
