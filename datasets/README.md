# CYBERGUARD Dataset Notes

`backend/ml/data/phishing_dataset.csv` is the primary phishing training dataset. `datasets/phishing_dataset.json` contains the same 85 text/label records using numeric labels and is retained as the fallback source selected by `backend/ml/train_phishing_model.py` when the CSV file is absent. Keep this copy for that supported fallback path; it is not a separate production dataset.
