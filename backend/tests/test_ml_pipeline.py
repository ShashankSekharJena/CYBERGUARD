"""
Unit and Integration Tests for Machine Learning Phishing Detection Pipeline
Tests dataset loading, model training, evaluation metrics, feature attribution, and predictor inference.
"""

import unittest
from pathlib import Path
from backend.ml.train_phishing_model import train_model, get_paths, load_dataset
from backend.ml.evaluate_model import get_cached_or_live_evaluation
from backend.ml.predictor import PhishingMLPredictor


class TestPhishingMLPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Ensure model is trained and available
        dataset_path, model_path, metrics_path = get_paths()
        if not model_path.exists() or not metrics_path.exists():
            train_model()
        cls.predictor = PhishingMLPredictor(auto_train=True)

    def test_dataset_loading_and_balance(self):
        dataset_path, _, _ = get_paths()
        texts, labels, categories = load_dataset(dataset_path)
        self.assertGreaterEqual(len(texts), 30)
        self.assertEqual(len(texts), len(labels))
        # Ensure both classes are well represented
        phish_count = sum(labels == 1)
        legit_count = sum(labels == 0)
        self.assertGreater(phish_count, 10)
        self.assertGreater(legit_count, 10)

    def test_model_training_and_metrics(self):
        metrics = train_model(test_size=0.25, random_state=42)
        self.assertIn("evaluation_metrics", metrics)
        eval_m = metrics["evaluation_metrics"]
        self.assertGreaterEqual(eval_m["accuracy"], 0.80)
        self.assertGreaterEqual(eval_m["precision"], 0.80)
        self.assertGreaterEqual(eval_m["recall"], 0.80)
        self.assertGreaterEqual(eval_m["f1_score"], 0.80)
        self.assertIn("confusion_matrix", eval_m)
        self.assertIn("top_features", metrics)
        self.assertGreater(len(metrics["top_features"]["phishing_indicators"]), 0)

    def test_evaluation_module(self):
        eval_res = get_cached_or_live_evaluation()
        self.assertIn("evaluation_metrics", eval_res)
        self.assertIn("accuracy", eval_res["evaluation_metrics"])

    def test_phishing_prediction_inference(self):
        sample_phish = "URGENT: Your PayPal account access has been restricted. Verify password immediately."
        res = self.predictor.predict(sample_phish)
        self.assertTrue(res["available"])
        self.assertTrue(res["is_phishing"])
        self.assertEqual(res["prediction_label"], "PHISHING")
        self.assertGreaterEqual(res["confidence"], 0.50)
        self.assertGreater(len(res["top_features"]), 0)

    def test_legitimate_prediction_inference(self):
        sample_legit = "Hi team, please find the quarterly engineering progress notes attached for Friday sync."
        res = self.predictor.predict(sample_legit)
        self.assertTrue(res["available"])
        self.assertFalse(res["is_phishing"])
        self.assertEqual(res["prediction_label"], "LEGITIMATE")
        self.assertGreaterEqual(res["confidence"], 0.50)

    def test_empty_input_graceful_handling(self):
        res = self.predictor.predict("")
        self.assertEqual(res["prediction_label"], "UNKNOWN")
        self.assertFalse(res["is_phishing"])
        self.assertEqual(res["confidence"], 0.0)


if __name__ == "__main__":
    unittest.main()
