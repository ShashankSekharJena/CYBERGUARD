"""
Unit Tests for MITRE ATT&CK Mapping Engine
Tests evidence-based mapping to official MITRE techniques and ensures zero fabrication on clean telemetry.
"""

import unittest
from backend.engines.mitre_mapping import map_mitre_techniques


class TestMitreMapping(unittest.TestCase):

    def test_phishing_spearphishing_link_mapping(self):
        evidence = [
            {"indicator": "Domain Mismatch", "details": "Claimed PayPal but domain is paypa1-verify.net"},
            {"indicator": "Urgent Credential Solicitation", "details": "Verify your identity immediately"}
        ]
        mappings = map_mitre_techniques("Phishing", evidence)
        tids = [m.technique_id for m in mappings]
        self.assertIn("T1566.002", tids)
        # Check that high confidence is assigned when multiple indicators match
        m1566 = next(m for m in mappings if m.technique_id == "T1566.002")
        self.assertEqual(m1566.tactic, "Initial Access")
        self.assertEqual(m1566.confidence, "HIGH")

    def test_mfa_fatigue_mapping(self):
        evidence = [
            {"indicator": "MFA Fatigue / Push Bombing Attack", "details": "Detected 6 consecutive MFA requests"}
        ]
        mappings = map_mitre_techniques("Account Security", evidence)
        tids = [m.technique_id for m in mappings]
        self.assertIn("T1621", tids)

    def test_impossible_travel_valid_accounts_mapping(self):
        evidence = [
            {"indicator": "Impossible Travel Velocity Anomaly", "details": "Calculated travel speed 1200 km/h"}
        ]
        mappings = map_mitre_techniques("Account Security", evidence)
        tids = [m.technique_id for m in mappings]
        self.assertIn("T1078", tids)

    def test_empty_evidence_no_hallucination(self):
        evidence = []
        mappings = map_mitre_techniques("Phishing", evidence)
        self.assertEqual(len(mappings), 0)


if __name__ == "__main__":
    unittest.main()
