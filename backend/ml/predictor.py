"""
CYBERGUARD Machine Learning Phishing Predictor (Compatibility Layer)

Provides real-time inference using the trained TF-IDF + Logistic Regression pipeline.
Wraps PhishingClassifier to guarantee full backward compatibility across all modules.
"""

from typing import Dict, Any, Optional
from pathlib import Path

try:
    from backend.ml.phishing_classifier import PhishingClassifier, phishing_classifier
    from backend.ml.train_phishing_model import get_paths, train_model
except ImportError:
    from ml.phishing_classifier import PhishingClassifier, phishing_classifier
    from ml.train_phishing_model import get_paths, train_model


class PhishingMLPredictor:
    """
    Inference handler for TF-IDF + Logistic Regression Phishing Classifier.
    """

    def __init__(self, auto_train: bool = True):
        self._classifier = phishing_classifier
        if auto_train and not self._classifier.is_available:
            try:
                train_model()
                self._classifier.load_model()
            except Exception:
                pass

    @property
    def is_available(self) -> bool:
        return self._classifier.is_available

    def get_metrics(self) -> Optional[Dict[str, Any]]:
        return self._classifier.get_metrics()

    def predict(self, text: Optional[str]) -> Dict[str, Any]:
        return self._classifier.classify(text)


# Global singleton instance
predictor = PhishingMLPredictor(auto_train=True)
