# CYBERGUARD

**AI-powered cyber threat detection, investigation and response support.** CYBERGUARD is a local web application for analyzing suspicious messages, URLs, impersonation signals, account activity, and multimodal input, then reviewing evidence and related incidents.

## 1. Overview

CYBERGUARD brings several threat analysis workflows and an incident center into one React interface backed by a FastAPI service. Its outputs are explainable advisory findings for a human analyst.

## 2. Problem

Security teams often review phishing, suspicious URLs, identity claims, and authentication anomalies in separate workflows. It can be difficult to bring evidence together and prioritize follow-up.

## 3. Solution

CYBERGUARD provides threat-specific analysis, risk summaries, evidence, deterministic similar-incident correlation, optional AI-assisted incident investigation, MITRE ATT&CK mappings, and defensive playbook recommendations in one application. Analysts remain responsible for decisions and actions.

## 4. Key features

- Phishing analysis using heuristics and an optional trained text classifier.
- URL threat analysis for suspicious address patterns and telemetry.
- Digital impersonation and account security analysis.
- Multimodal input analysis.
- Incident creation, search, filtering, status updates, and triage.
- Deterministic similar-incident correlation from observable telemetry.
- Evidence-grounded AI Security Analyst, with deterministic fallback when an external model is not configured or available.
- MITRE ATT&CK mapping and advisory response playbooks.

## 5. System architecture

```text
Analyst -> React frontend -> FastAPI API -> threat detectors
                                        |-> phishing ML pipeline (when available)
                                        v
                              risk and analysis engines
                                        v
                                incident manager
                                  |          |
                          correlation    MITRE + playbook
                                  \          /
                               optional AI analyst
                                        v
                                analyst decision
```

See [docs/SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md) for the runtime pipeline and component responsibilities. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes the analysis workflow in more detail.

## 6. Technology stack

- Backend: Python, FastAPI, Uvicorn, Pydantic
- Frontend: React, Vite, Tailwind CSS, Lucide
- ML: scikit-learn, TF-IDF, Logistic Regression, joblib
- Incident storage: in-memory, thread-safe Python store
- Tests: Python `unittest` and FastAPI `TestClient`

## 7. ML phishing model

Phishing text analysis combines heuristic indicators with a TF-IDF plus Logistic Regression classifier when the serialized model is available. The committed primary artifact is [backend/ml/models/phishing_text_model.joblib](backend/ml/models/phishing_text_model.joblib). The prototype training data is [backend/ml/data/phishing_dataset.csv](backend/ml/data/phishing_dataset.csv), and training/evaluation code lives under `backend/ml/`.

The data contains 85 curated samples and is not representative of the full range of real-world phishing. The model is one signal in the phishing risk workflow, not a guarantee of detection. See [docs/ML_PHISHING.md](docs/ML_PHISHING.md).

## 8. AI Security Analyst

The optional AI Security Analyst summarizes incident evidence and supports investigation. It can use an OpenAI-compatible chat completions endpoint when configured with `AI_API_KEY`; `AI_MODEL` and `AI_BASE_URL` select the model and endpoint. If the key is absent or the request fails, the service uses deterministic fallback synthesis. The feature is advisory and does not execute response actions. Review [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) for its incident endpoints and [docs/SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md) for data flow.

The application reads these values from the backend process environment. It does not automatically load `.env`. Keep real credentials in local environment configuration and never commit them.

## 9. Similar Incident Correlation

The correlation service compares incident telemetry using deterministic signals such as shared URLs, domains, senders, users, IP addresses, threat types, indicators, and time proximity. It can surface incidents for analyst review; similarity does not prove common attribution or a coordinated campaign. See [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md#4-similar-incident-correlation-methodology).

## 10. Installation

Prerequisites: Python 3.10+ and Node.js/npm compatible with the frontend dependencies.

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
npm --prefix frontend install
```

On macOS/Linux, activate the environment with `source .venv/bin/activate`.

The Render frontend build must use `VITE_API_URL=https://cyberguard-backend-wt0p.onrender.com` (see [frontend/.env.example](frontend/.env.example)). Vite embeds this variable during the build, so redeploy the frontend after changing it. For local development, leave `VITE_API_URL` unset to use the `http://127.0.0.1:8000` fallback, or set it in `frontend/.env.local`. Set `AI_API_KEY`, `AI_MODEL`, and `AI_BASE_URL` in the backend process environment if you want to enable external AI analysis.

## 11. Run the backend

With the Python environment active, start the API from the repository root:

```powershell
.\scripts\run_backend.ps1
```

The API is available at `http://127.0.0.1:8000`; its interactive docs are at `http://127.0.0.1:8000/docs`.

## 12. Run the frontend

In a second terminal from the repository root:

```bash
npm run dev
```

The frontend is available at `http://localhost:5173`. On Windows, `scripts/run_frontend.ps1` is also available.

## 13. Testing

From the repository root, with the Python environment active:

```bash
python -m unittest discover -s backend/tests -v
npm --prefix frontend run build
```

## 14. Limitations

- Findings and risk scores are advisory and may produce false positives or miss threats.
- The phishing classifier uses a small curated prototype dataset.
- Incident data is in memory and resets when the backend restarts.
- Correlation is heuristic similarity, not attribution.
- AI analysis depends on an optional external service and may be unavailable; fallback output is deterministic.
- Playbooks recommend actions but do not carry them out.

## 15. Project structure

```text
cyberguard/
|-- README.md
|-- LICENSE
|-- .gitignore
|-- .env.example
|-- requirements.txt
|-- package.json
|-- backend/
|   |-- main.py
|   |-- requirements.txt
|   |-- detectors/
|   |-- engines/
|   |-- models/
|   |-- services/
|   |-- ml/
|   |   |-- data/phishing_dataset.csv
|   |   |-- models/phishing_text_model.joblib
|   |   |-- phishing_model.joblib (legacy fallback)
|   |   |-- metrics.json
|   |   `-- training, classifier, predictor, and evaluation modules
|   `-- tests/
|-- frontend/
|   |-- package.json
|   |-- package-lock.json
|   |-- vite.config.js
|   |-- index.html
|   `-- src/ (components, services, assets, and app entry points)
|-- datasets/
|   `-- phishing_dataset.json (CSV fallback data, same records)
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- API_DOCUMENTATION.md
|   |-- DEMO_GUIDE.md
|   |-- ML_PHISHING.md
|   `-- SYSTEM_ARCHITECTURE.md
`-- scripts/
    |-- run_backend.ps1
    |-- run_frontend.ps1
    `-- run_tests.ps1
```

Local virtual environments, Python caches, frontend dependencies, build output, logs, and local secrets are excluded by `.gitignore`.

## 16. Demo workflow

1. Open the dashboard and review the backend connection and incident summary.
2. Submit a phishing message and inspect heuristic evidence and the ML result.
3. Analyze a suspicious URL, impersonation claim, and account security event.
4. Open the Incident Center, review an incident, and update its triage status.
5. Inspect similar incidents, MITRE mapping, and the recommended playbook.
6. Open the AI Security Analyst for an incident and review the advisory summary.

Use the safe sample scenarios and walkthrough in [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

## Documentation

- [Architecture and workflow](docs/ARCHITECTURE.md)
- [System architecture](docs/SYSTEM_ARCHITECTURE.md)
- [API documentation](docs/API_DOCUMENTATION.md)
- [ML phishing details](docs/ML_PHISHING.md)
- [Demo guide](docs/DEMO_GUIDE.md)

## License

MIT. See [LICENSE](LICENSE).
