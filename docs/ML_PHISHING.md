# CYBERGUARD Machine Learning Phishing Detection

## 1. Overview & Motivation
Traditional rule-based and heuristic phishing detectors excel at identifying explicit technical indicators, such as IP-based hostnames, credential-solicitation keywords, domain mismatches, homoglyphs, and suspicious URI schemes. However, attackers regularly craft deceptive variations that avoid specific fixed keywords while maintaining coercive or fraudulent intent.

To augment CYBERGUARD without degrading explainability or predictability, a **TF-IDF + Logistic Regression machine learning classifier** was introduced into the phishing detection pipeline. The resulting architecture is a **Hybrid Detection System**:

```
                         Phishing Telemetry Input
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
       Rule-Based / Heuristic Engine     ML Text Classifier
         (Observable Indicators)      (TF-IDF + Logistic Reg.)
                    │                               │
                    └───────────────┬───────────────┘
                                    ▼
                        Hybrid Threat Assessment
                                    ▼
                         Evidence-Based Synthesis
                                    ▼
                        Incident Store & Routing
```

---

## 2. Rule-Based vs. Machine-Learning Detection

| Dimension | Rule-Based / Heuristic Detection | Machine-Learning Detection |
| :--- | :--- | :--- |
| **Primary Focus** | Explicit, observable telemetry & security rules (regex, URL structures, domain mismatches, OTP/PIN requests). | Statistical linguistic patterns & word co-occurrences learned from training data. |
| **Explainability** | High: Every triggered indicator provides concrete rationale (e.g. "IP address in URL"). | High to Moderate: Provides class probability & non-zero TF-IDF token attribution weights. |
| **Generalization** | Limited to predefined rules and patterns. | Discovers statistical phrasing similarities beyond fixed keyword lists. |
| **False Positives** | Low on defined rules, but brittle on novel lures. | Can misclassify out-of-distribution phrases without heuristic cross-checks. |
| **Role in CYBERGUARD** | Ground-truth observable security evidence and safety bounds. | Learned text classification weighting and supplementary confidence score. |

---

## 3. Dataset Specification & Limitations

- **File Location**: [`backend/ml/data/phishing_dataset.csv`](../backend/ml/data/phishing_dataset.csv)
- **Format**: CSV (`text,label`)
- **Labels**: `phishing` (positive class = 1), `legitimate` (negative class = 0)
- **Total Samples**: 85 balanced prototype examples (45 Phishing, 40 Legitimate)
- **Composition**:
  - *Phishing*: Urgent account lock warnings, credential reset lures, OTP/2FA solicitation, fake shipping parcel notices, tax refund claims, corporate invoice update requests.
  - *Legitimate*: Team standup notes, calendar reschedule notifications, AWS billing receipts, code review comments, customer support resolutions, internal HR knowledgebase memos.
- **Dataset Limitations**:
  - The dataset is a compact, curated prototype designed for development, testing, and SIH demonstrations.
  - It does **not** represent real-world global prevalence or adversary distribution.
  - It has not been trained on millions of enterprise emails; production deployment requires large-scale enterprise feeds with domain reputation and spam-filter baselines.

---

## 4. Model Architecture & Feature Extraction

### Feature Extraction: TF-IDF Vectorizer
- **N-gram Range**: `(1, 2)` (captures unigrams like `"verify"`, `"password"` and bigrams like `"your account"`, `"act now"`).
- **Max Features**: 2,500 terms.
- **Sublinear Term Frequency**: Enabled (`sublinear_tf=True`) to dampen the effect of repetitive words.
- **Preprocessing**: Unicode accent stripping and case normalization to lowercase.

### Classification Algorithm: Logistic Regression
- **Estimator**: `sklearn.linear_model.LogisticRegression`
- **Regularization**: `C=1.0` with `liblinear` solver.
- **Reproducibility**: Fixed random seed (`random_state=42`) with stratified train/test split.
- **Probability Calibration**: Outputs true sigmoid posterior probabilities (`predict_proba`) for both classes.

---

## 5. Training & Evaluation Pipeline

The training pipeline in [`backend/ml/train_phishing_model.py`](../backend/ml/train_phishing_model.py) performs:
1. Data loading and label mapping via `pandas`.
2. Stratified train/test split (75% train, 25% test).
3. Pipeline compilation and fitting.
4. Evaluation on held-out test data:
   - **Accuracy**: $95.45\%$
   - **Precision**: $92.31\%$
   - **Recall**: $100.00\%$
   - **F1-Score**: $96.00\%$
   - **Confusion Matrix**: True Negatives: 9, False Positives: 1, False Negatives: 0, True Positives: 12.
5. Extraction of top indicative n-grams and coefficient weights.
6. Serialization via `joblib` to [`backend/ml/models/phishing_text_model.joblib`](../backend/ml/models/phishing_text_model.joblib) and metric storage in [`backend/ml/metrics.json`](../backend/ml/metrics.json).

---

## 6. Real-Time Inference Module

The inference engine in [`backend/ml/phishing_classifier.py`](../backend/ml/phishing_classifier.py):
- Loads the serialized pipeline into memory once on application startup.
- Evaluates raw text submissions and outputs structured predictions:
  ```json
  {
    "available": true,
    "model": "TF-IDF + Logistic Regression",
    "prediction": "phishing",
    "confidence": 0.892,
    "probability": 0.892,
    "phishing_probability": 0.892,
    "top_features": [
      { "term": "verify", "weight": 0.22, "impact": 0.044, "direction": "phishing" },
      { "term": "password", "weight": 0.25, "impact": 0.041, "direction": "phishing" }
    ],
    "explanation": "ML classifier identifies phishing-like language with 89.2% confidence (phishing probability: 0.892)."
  }
  ```
- **Graceful Fallback**: If model artifacts are missing, inference returns `available: false` with zero confidence without crashing, allowing the system to continue purely on heuristic analysis.

---

## 7. Hybrid Decision Logic

To prevent statistical model errors from overriding clear security telemetry:
1. **Rule-Based Precedence**: Explicit heuristic indicators (e.g. deceptive IP addresses, domain mismatches, known credential harvesting patterns) independently generate baseline risk points.
2. **Synergistic Amplification**: If the ML classifier confirms phishing language ($P_{\text{phish}} \ge 0.50$), the risk score is calibrated upward using weighted synergy ($R_{\text{hybrid}} = \min(100, \max(R_{\text{heuristic}}, R_{\text{heuristic}} \times 0.7 + P_{\text{phish}} \times 30))$).
3. **Linguistic Baseline**: If no static rules triggered but the ML model identifies high-confidence phishing language ($P_{\text{phish}} \ge 0.70$), a calibrated baseline score is assigned ($P_{\text{phish}} \times 75$) placing the event into MEDIUM or HIGH risk.
4. **Safety Disclosure**: Risk scores represent heuristic indicators from observable telemetry and statistical modeling, not mathematically verified proof of maliciousness.

---

## 8. Limitations & Prototype Boundaries

1. **Not Deep Learning**: The classifier is a classical TF-IDF linear model, not a large language model or transformer.
2. **No Zero-Day / Novel Obfuscation Guarantees**: Advanced adversarial attacks (e.g. homoglyph evasion inside raw text bodies or image-only text) may evade TF-IDF tokenization.
3. **No Deepfake Detection**: This module handles text semantics and does not perform video/voice generative media analysis.
4. **No Automated Website Scraping**: Analysis is restricted strictly to submitted text and URL telemetry.

---

## 9. Future Improvements
- Token-level subword embeddings (Byte-Pair Encoding / WordPiece).
- Continuous retraining feedback loop integrated with incident analyst triage verdicts.
- Sender reputation graph integration alongside linguistic scoring.
