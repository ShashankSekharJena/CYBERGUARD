"""
Unit Tests for Behavioural Anomaly Detection and Account Security
Tests mathematical impossible travel, MFA fatigue, rapid bursts, and extensible ML anomaly baseline structure.
"""

import unittest
from backend.detectors.account_security_detector import (
    calculate_travel_velocity,
    detect_account_security_threats,
    BaseBehaviouralAnomalyModel
)


class TestBehaviouralAnomalyDetection(unittest.TestCase):

    def test_impossible_travel_calculation_positive(self):
        # New York to London in 30 minutes (0.5 hours)
        # Distance ~5,570 km -> Velocity ~11,140 km/h (>800 km/h threshold)
        v = calculate_travel_velocity(
            "New York, USA", "2026-09-18T10:00:00Z",
            "London, UK", "2026-09-18T10:30:00Z"
        )
        self.assertIsNotNone(v)
        self.assertGreater(v, 800.0)

        indicators, metrics = detect_account_security_threats(
            username="admin@corp.com",
            login_location="London, UK",
            timestamp="2026-09-18T10:30:00Z",
            previous_location="New York, USA",
            previous_timestamp="2026-09-18T10:00:00Z",
            return_metrics=True
        )
        self.assertTrue(metrics["impossible_travel_flag"])
        self.assertTrue(any(i["category"] == "impossible_travel" for i in indicators))

    def test_realistic_travel_no_anomaly(self):
        # New York to London in 10 hours -> ~557 km/h (< 800 km/h)
        v = calculate_travel_velocity(
            "New York, USA", "2026-09-18T00:00:00Z",
            "London, UK", "2026-09-18T10:00:00Z"
        )
        self.assertIsNotNone(v)
        self.assertLess(v, 800.0)

        indicators, metrics = detect_account_security_threats(
            username="analyst@corp.com",
            login_location="London, UK",
            timestamp="2026-09-18T10:00:00Z",
            previous_location="New York, USA",
            previous_timestamp="2026-09-18T00:00:00Z",
            return_metrics=True
        )
        self.assertFalse(metrics["impossible_travel_flag"])

    def test_mfa_fatigue_detection(self):
        indicators, metrics = detect_account_security_threats(
            username="victim@corp.com",
            mfa_attempts=6,
            login_location="Paris, France",
            return_metrics=True
        )
        self.assertTrue(metrics["mfa_fatigue_flag"])
        self.assertTrue(any("MFA Fatigue" in i["indicator"] for i in indicators))

    def test_failed_login_burst_rate(self):
        indicators, metrics = detect_account_security_threats(
            username="user123",
            failed_login_burst_count=8,
            login_location="Berlin, Germany",
            return_metrics=True
        )
        self.assertTrue(metrics["failed_burst_rate_flag"])
        self.assertTrue(any("Burst" in i["indicator"] for i in indicators))

    def test_extensible_ml_anomaly_base(self):
        base_model = BaseBehaviouralAnomalyModel()
        self.assertFalse(base_model.is_trained)
        with self.assertRaises(NotImplementedError):
            base_model.train([])
        with self.assertRaises(NotImplementedError):
            base_model.score_anomaly([])


if __name__ == "__main__":
    unittest.main()
