"""
CYBERGUARD Phishing Model Evaluation Module

Loads the trained TF-IDF + Logistic Regression model artifact and evaluates performance
against dataset splits, returning detailed accuracy, precision, recall, F1, and confusion matrix.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

try:
    from backend.ml.train_phishing_model import get_paths, load_dataset
except ImportError:
    from ml.train_phishing_model import get_paths, load_dataset


def get_cached_or_live_evaluation(force_recompute: bool = False) -> Dict[str, Any]:
    """
    Returns existing evaluation metrics if available, or computes live metrics on dataset.
    """
    dataset_path, model_path, metrics_path = get_paths()

    if not force_recompute and metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            return json.load(f)

    if not model_path.exists():
        raise FileNotFoundError(
            f"Trained model not found at {model_path}. Run train_phishing_model.py first."
        )

    pipeline = joblib.load(model_path)
    texts, labels, _ = load_dataset(dataset_path)

    y_pred = pipeline.predict(texts)
    y_proba = pipeline.predict_proba(texts)[:, 1]

    acc = float(accuracy_score(labels, y_pred))
    prec = float(precision_score(labels, y_pred, zero_division=0))
    rec = float(recall_score(labels, y_pred, zero_division=0))
    f1 = float(f1_score(labels, y_pred, zero_division=0))
    cm = confusion_matrix(labels, y_pred).tolist()

    return {
        "model_name": "TF-IDF + Logistic Regression Phishing Classifier",
        "dataset_samples": len(texts),
        "evaluation_metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0] if len(cm) > 1 else 0,
                "false_positive": cm[0][1] if len(cm) > 1 else 0,
                "false_negative": cm[1][0] if len(cm) > 1 else 0,
                "true_positive": cm[1][1] if len(cm) > 1 else 0
            }
        },
        "status": "EVALUATED"
    }


if __name__ == "__main__":
    metrics = get_cached_or_live_evaluation()
    print(json.dumps(metrics, indent=2))
