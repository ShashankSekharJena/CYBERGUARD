"""
CYBERGUARD ML Phishing Classifier Test Suite

Covers the 10 required test cases for the ML Classifier & Hybrid Detection:
1. Model loads successfully.
2. Clearly legitimate message -> Legitimate prediction / low-risk.
3. Clearly phishing-style message -> Phishing prediction.
4. Existing heuristic phishing indicators still work.
5. Existing legitimate-message behavior still works.
6. ML result appears in /analyze/phishing (ml_analysis).
7. Existing API response fields remain compatible.
8. Missing model file is handled gracefully without crashing.
9. Incident creation still works after ML analysis.
10. Similar-incident correlation still works after ML integration.
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.train_phishing_model import get_paths, train_model
from backend.ml.phishing_classifier import PhishingClassifier, phishing_classifier
from backend.engines.incident_manager import incident_manager


class TestMLPhishingClassifierIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Ensure model is trained and available
        dataset_path, primary_model_path, metrics_path = get_paths()
        if not primary_model_path.exists():
            train_model()
        phishing_classifier.load_model()

    def test_01_model_loads_successfully(self):
        """Test 1: Model loads successfully from serialized artifact."""
        clf = PhishingClassifier()
        self.assertTrue(clf.is_available, "Classifier should be loaded and available")
        metrics = clf.get_metrics()
        self.assertIsNotNone(metrics)
        self.assertIn("evaluation_metrics", metrics)

    def test_02_clearly_legitimate_message(self):
        """Test 2: Clearly legitimate message receives legitimate prediction and low-risk assessment."""
        legit_text = "Hi team, please find the quarterly engineering progress notes attached. Our sync is at 3 PM."
        clf = PhishingClassifier()
        res = clf.classify(legit_text)
        self.assertTrue(res["available"])
        self.assertEqual(res["prediction"], "legitimate")
        self.assertFalse(res["is_phishing"])
        self.assertGreater(res["confidence"], 0.50)

    def test_03_clearly_phishing_message(self):
        """Test 3: Clearly phishing-style message receives phishing prediction."""
        phish_text = "URGENT: Your PayPal account access has been restricted. Verify your password immediately."
        clf = PhishingClassifier()
        res = clf.classify(phish_text)
        self.assertTrue(res["available"])
        self.assertEqual(res["prediction"], "phishing")
        self.assertTrue(res["is_phishing"])
        self.assertGreaterEqual(res["phishing_probability"], 0.50)

    def test_04_existing_heuristic_indicators_still_work(self):
        """Test 4: Existing heuristic phishing indicators still work."""
        payload = {
            "message_text": "URGENT: Your account will be suspended immediately. Please verify your password now.",
            "url": "http://192.168.1.100/login@paypa1-security.com/update"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        indicators = [item["indicator"] for item in data["evidence"]]
        self.assertIn("Credential request", indicators)
        self.assertIn("Urgent language", indicators)
        self.assertIn("Threatening language", indicators)
        self.assertTrue(any("IP address" in ind or "@ symbol" in ind or "look-alike" in ind for ind in indicators))

    def test_05_existing_legitimate_message_behavior_still_works(self):
        """Test 5: Existing legitimate-message behavior still produces SAFE severity."""
        payload = {
            "message_text": "Team meeting is rescheduled to Thursday at 10 AM in Conference Room B.",
            "url": "https://intranet.company.corp/meeting"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["severity"], "SAFE")
        self.assertLessEqual(data["risk_score"], 19)

    def test_06_ml_result_appears_in_analyze_phishing(self):
        """Test 6: ML result appears in /analyze/phishing response under ml_analysis."""
        payload = {
            "message_text": "URGENT: Your Netflix account payment failed. Enter your billing credentials now."
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ml_analysis", data)
        self.assertIsNotNone(data["ml_analysis"])
        ml_an = data["ml_analysis"]
        self.assertEqual(ml_an["model"], "TF-IDF + Logistic Regression")
        self.assertIn(ml_an["prediction"], ["phishing", "legitimate"])
        self.assertIsInstance(ml_an["confidence"], (int, float))

    def test_07_existing_api_response_fields_remain_compatible(self):
        """Test 7: All original response fields are present and correctly typed."""
        payload = {
            "message_text": "Review project updates."
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        required_fields = [
            "threat_type", "risk_score", "severity", "confidence",
            "evidence", "explanation", "recommended_actions",
            "ml_details", "detection_source"
        ]
        for field in required_fields:
            self.assertIn(field, data, f"Missing field {field} for backward compatibility")

    def test_08_missing_model_file_handled_gracefully(self):
        """Test 8: Missing model file returns graceful fallback without crashing."""
        non_existent_path = Path("backend/ml/models/non_existent_fake_model.joblib")
        clf = PhishingClassifier(model_path=non_existent_path)
        self.assertFalse(clf.is_available)
        res = clf.classify("Sample text")
        self.assertFalse(res["available"])
        self.assertEqual(res["prediction_label"], "UNAVAILABLE")
        self.assertFalse(res["is_phishing"])
        self.assertEqual(res["confidence"], 0.0)

    def test_09_incident_creation_still_works(self):
        """Test 9: Incident creation still records the incident in Incident Store."""
        initial_count = incident_manager.get_all_incidents().total
        payload = {
            "message_text": "Security notice: Confirm your direct deposit details immediately.",
            "url": "http://hr-portal-direct-deposit.xyz/verify"
        }
        response = self.client.post("/analyze/phishing", json=payload)
        self.assertEqual(response.status_code, 200)
        updated_count = incident_manager.get_all_incidents().total
        self.assertGreater(updated_count, initial_count)

    def test_10_similar_incident_correlation_still_works(self):
        """Test 10: Similar-incident correlation still functions after ML integration."""
        # Record two related incidents with same domain
        payload1 = {
            "message_text": "Urgent alert from payroll.",
            "url": "http://shared-lure-portal.xyz/login1"
        }
        payload2 = {
            "message_text": "Final warning regarding payment.",
            "url": "http://shared-lure-portal.xyz/login2"
        }
        res1 = self.client.post("/analyze/phishing", json=payload1)
        res2 = self.client.post("/analyze/phishing", json=payload2)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res2.status_code, 200)

        # Retrieve all incidents and verify correlation metadata exists
        incidents = incident_manager.get_all_incidents().incidents
        latest = incidents[0]  # newest first
        self.assertIsNotNone(latest.correlation)
        self.assertIn("same_domain", latest.correlation.matched_signals)


if __name__ == "__main__":
    unittest.main()
