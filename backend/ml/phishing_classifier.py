"""
CYBERGUARD Phishing ML Classifier

Loads the trained TF-IDF + Logistic Regression pipeline once and performs
deterministic inference, returning model predictions, probabilities,
and feature contributions without fabricated confidence.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
import joblib
import numpy as np


class PhishingClassifier:
    """
    ML Classifier for Phishing Text using TF-IDF + Logistic Regression.
    Loads trained artifact once and handles inference gracefully.
    """

    def __init__(self, model_path: Optional[Path] = None, metrics_path: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parent.parent.parent
        self._custom_model_path = model_path is not None
        self.primary_model_path = model_path or (base_dir / "backend" / "ml" / "models" / "phishing_text_model.joblib")
        self.legacy_model_path = base_dir / "backend" / "ml" / "phishing_model.joblib"
        self.metrics_path = metrics_path or (base_dir / "backend" / "ml" / "metrics.json")

        self.model_name = "TF-IDF + Logistic Regression"
        self._pipeline = None
        self._metrics: Optional[Dict[str, Any]] = None
        self._is_loaded = False
        self._load_error: Optional[str] = None

        self.load_model()

    def load_model(self) -> bool:
        """Loads serialized pipeline from disk once."""
        try:
            target_path = None
            if self._custom_model_path:
                target_path = self.primary_model_path if self.primary_model_path.exists() else None
            elif self.primary_model_path.exists():
                target_path = self.primary_model_path
            elif self.legacy_model_path.exists():
                target_path = self.legacy_model_path

            if target_path and target_path.exists():
                self._pipeline = joblib.load(target_path)
                self._is_loaded = True
                self._load_error = None
            else:
                self._is_loaded = False
                self._load_error = "Model file not found on disk."

            if self.metrics_path.exists():
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    self._metrics = json.load(f)
        except Exception as e:
            self._is_loaded = False
            self._pipeline = None
            self._load_error = str(e)

        return self._is_loaded

    @property
    def is_available(self) -> bool:
        return self._is_loaded and self._pipeline is not None

    def get_metrics(self) -> Optional[Dict[str, Any]]:
        """Returns loaded evaluation metrics."""
        if self._metrics is not None:
            return self._metrics
        if self.metrics_path.exists():
            try:
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    self._metrics = json.load(f)
                return self._metrics
            except Exception:
                return None
        return None

    def classify(self, text: Optional[str]) -> Dict[str, Any]:
        """
        Inference function returning structured classification results.
        """
        if not text or not isinstance(text, str) or not text.strip():
            return {
                "available": self.is_available,
                "model": self.model_name,
                "prediction": "legitimate",
                "prediction_label": "UNKNOWN",
                "is_phishing": False,
                "confidence": 0.0,
                "probability": 0.0,
                "phishing_probability": 0.0,
                "top_features": [],
                "explanation": "No text provided for machine learning analysis."
            }

        if not self.is_available:
            return {
                "available": False,
                "model": self.model_name,
                "prediction": "unknown",
                "prediction_label": "UNAVAILABLE",
                "is_phishing": False,
                "confidence": 0.0,
                "probability": 0.0,
                "phishing_probability": 0.0,
                "top_features": [],
                "explanation": f"ML model is not loaded ({self._load_error or 'missing artifact'}). Fallback heuristics active."
            }

        clean_text = text.strip()
        probabilities = self._pipeline.predict_proba([clean_text])[0]
        legit_prob = float(probabilities[0])
        phish_prob = float(probabilities[1])

        is_phish = phish_prob >= 0.50
        prediction = "phishing" if is_phish else "legitimate"
        prediction_label = "PHISHING" if is_phish else "LEGITIMATE"
        confidence = phish_prob if is_phish else legit_prob

        # Extract active token contributions from input
        top_features: List[Dict[str, Any]] = []
        try:
            vectorizer = self._pipeline.named_steps["tfidf"]
            classifier = self._pipeline.named_steps["clf"]
            feature_names = vectorizer.get_feature_names_out()
            coefs = classifier.coef_[0]

            X_vec = vectorizer.transform([clean_text])
            non_zero_indices = X_vec.nonzero()[1]

            active_terms = []
            for idx in non_zero_indices:
                weight = float(coefs[idx])
                tfidf_val = float(X_vec[0, idx])
                term = str(feature_names[idx])
                impact = round(weight * tfidf_val, 4)
                active_terms.append({
                    "term": term,
                    "weight": round(weight, 4),
                    "impact": impact,
                    "direction": "phishing" if weight > 0 else "legitimate"
                })

            active_terms.sort(key=lambda x: abs(x["impact"]), reverse=True)
            top_features = active_terms[:8]
        except Exception:
            top_features = []

        if is_phish:
            explanation = (
                f"ML classifier identifies phishing-like language with {round(confidence * 100, 1)}% confidence "
                f"(phishing probability: {round(phish_prob, 3)})."
            )
        else:
            explanation = (
                f"ML classifier evaluated content as legitimate with {round(confidence * 100, 1)}% confidence "
                f"(legitimate probability: {round(legit_prob, 3)})."
            )

        return {
            "available": True,
            "model": self.model_name,
            "prediction": prediction,
            "prediction_label": prediction_label,
            "is_phishing": is_phish,
            "confidence": round(confidence, 4),
            "probability": round(phish_prob if is_phish else legit_prob, 4),
            "phishing_probability": round(phish_prob, 4),
            "top_features": top_features,
            "explanation": explanation
        }


# Singleton instance
phishing_classifier = PhishingClassifier()
