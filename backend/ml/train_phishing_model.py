"""
CYBERGUARD Phishing Model Training Pipeline

Trains a real TF-IDF + Logistic Regression model on labeled phishing and legitimate text.
Performs stratified train/test split, calculates evaluation metrics (Precision, Recall, F1, Confusion Matrix),
and serializes model artifacts for the inference classifier.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, List

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


def get_paths() -> Tuple[Path, Path, Path]:
    """Resolves dataset, primary model file, and metrics paths."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    csv_dataset_path = base_dir / "backend" / "ml" / "data" / "phishing_dataset.csv"
    json_dataset_path = base_dir / "datasets" / "phishing_dataset.json"

    ml_dir = base_dir / "backend" / "ml"
    models_dir = ml_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    primary_model_path = models_dir / "phishing_text_model.joblib"
    metrics_path = ml_dir / "metrics.json"

    dataset_path = csv_dataset_path if csv_dataset_path.exists() else json_dataset_path
    return dataset_path, primary_model_path, metrics_path


def load_dataset(dataset_path: Path) -> Tuple[List[str], np.ndarray, Dict[str, int]]:
    """
    Loads labeled dataset from CSV or JSON.
    Expected labels: 'phishing' (1) and 'legitimate' (0).
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    texts: List[str] = []
    binary_labels: List[int] = []

    if dataset_path.suffix.lower() == ".csv":
        df = pd.read_csv(dataset_path)
        for _, row in df.iterrows():
            raw_text = str(row.get("text", "")).strip()
            raw_label = str(row.get("label", "")).strip().lower()
            if not raw_text:
                continue

            if raw_label in ("phishing", "1", "phish"):
                label_val = 1
            elif raw_label in ("legitimate", "0", "safe", "legit"):
                label_val = 0
            else:
                continue

            texts.append(raw_text)
            binary_labels.append(label_val)
    else:
        with open(dataset_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            raw_text = str(item.get("text", "")).strip()
            raw_label = item.get("label")
            if not raw_text:
                continue
            if raw_label in (1, "1", "phishing"):
                label_val = 1
            elif raw_label in (0, "0", "legitimate", "safe"):
                label_val = 0
            else:
                continue
            texts.append(raw_text)
            binary_labels.append(label_val)

    if len(texts) < 10:
        raise ValueError(f"Insufficient dataset size: {len(texts)} samples")

    labels_arr = np.array(binary_labels, dtype=int)
    phish_count = int(np.sum(labels_arr == 1))
    legit_count = int(np.sum(labels_arr == 0))

    stats = {
        "total_samples": len(texts),
        "phishing_samples": phish_count,
        "legitimate_samples": legit_count
    }

    return texts, labels_arr, stats


def train_model(
    test_size: float = 0.25,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Executes training, evaluation, and serialization workflow.
    """
    dataset_path, primary_model_path, metrics_path = get_paths()
    legacy_model_path = primary_model_path.parent.parent / "phishing_model.joblib"
    texts, labels, stats = load_dataset(dataset_path)

    # Print dataset statistics before training
    print("Dataset Summary:")
    print(f"  Total samples:      {stats['total_samples']}")
    print(f"  Phishing samples:   {stats['phishing_samples']}")
    print(f"  Legitimate samples: {stats['legitimate_samples']}")

    # Stratified Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels
    )

    # Build TF-IDF + Logistic Regression Pipeline
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2500,
            sublinear_tf=True,
            strip_accents="unicode",
            lowercase=True
        )),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=random_state,
            solver="liblinear"
        ))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test set
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    clf_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Extract top indicative features
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]
    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]

    top_phishing_idx = np.argsort(coefs)[-15:][::-1]
    top_legit_idx = np.argsort(coefs)[:15]

    top_phishing_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_phishing_idx
    ]
    top_legit_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_legit_idx
    ]

    metrics_payload = {
        "model_name": "TF-IDF + Logistic Regression Phishing Classifier",
        "algorithm": "LogisticRegression(C=1.0, solver='liblinear')",
        "feature_extractor": "TfidfVectorizer(ngram_range=(1,2), max_features=2500)",
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_statistics": {
            "total_samples": stats["total_samples"],
            "phishing_samples": stats["phishing_samples"],
            "legitimate_samples": stats["legitimate_samples"],
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "test_size_ratio": test_size,
            "random_state": random_state
        },
        "evaluation_metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0] if len(cm) > 1 and len(cm[0]) > 0 else 0,
                "false_positive": cm[0][1] if len(cm) > 1 and len(cm[0]) > 1 else 0,
                "false_negative": cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0,
                "true_positive": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0
            },
            "classification_report": clf_report
        },
        "top_features": {
            "phishing_indicators": top_phishing_features,
            "legitimate_indicators": top_legit_features
        },
        "model_files": [
            str(primary_model_path.name),
            str(legacy_model_path.name)
        ],
        "status": "TRAINED_AND_EVALUATED"
    }

    # Save serialized pipelines
    joblib.dump(pipeline, primary_model_path)
    joblib.dump(pipeline, legacy_model_path)

    # Save metrics JSON
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    return metrics_payload


if __name__ == "__main__":
    print("=" * 60)
    print("CYBERGUARD: Training Real ML Phishing Detection Model")
    print("=" * 60)
    metrics = train_model()
    print("-" * 60)
    print("Evaluation Results on Held-out Test Set:")
    print(f"  Accuracy:  {metrics['evaluation_metrics']['accuracy'] * 100:.2f}%")
    print(f"  Precision: {metrics['evaluation_metrics']['precision'] * 100:.2f}%")
    print(f"  Recall:    {metrics['evaluation_metrics']['recall'] * 100:.2f}%")
    print(f"  F1-Score:  {metrics['evaluation_metrics']['f1_score'] * 100:.2f}%")
    print(f"  Confusion Matrix: {metrics['evaluation_metrics']['confusion_matrix']}")
    print("-" * 60)
    print("Model and evaluation metrics successfully saved.")
