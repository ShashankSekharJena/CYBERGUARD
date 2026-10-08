# CYBERGUARD System Architecture

CYBERGUARD is an AI-powered cyber threat detection, investigation and response support system. The application analyzes submitted telemetry and presents evidence and advisory findings for a SOC analyst to review. It does not take autonomous response actions.

## Actual processing flow

```text
USER / SOC ANALYST
        |
        v
REACT FRONTEND
        |
        | HTTP / JSON requests
        v
FASTAPI API (backend/main.py)
        |
        v
DETECTION LAYER
  - phishing, URL, impersonation, account security, multimodal
        |
        +--> ML PIPELINE (phishing text only; model available)
        |       - TF-IDF + Logistic Regression
        |       - Heuristic and ML result are fused by phishing risk logic
        |
        v
RISK, EXPLANATION, AND RESPONSE ENGINES
        |
        v
INCIDENT MANAGER (in-memory store)
        |
        +--> SIMILAR INCIDENT CORRELATION
        |       - deterministic telemetry similarity
        |       - run during incident handling and via correlate endpoint
        |
        +--> MITRE ATT&CK MAPPING
        |
        +--> DEFENSIVE PLAYBOOK
        |
        +--> AI SECURITY ANALYST (optional)
                - receives incident evidence and available correlation,
                  MITRE, and playbook context
                - configured OpenAI-compatible endpoint, or deterministic
                  fallback when no key is configured / request fails
        |
        v
SOC ANALYST DECISION
```

The API exposes these stages through separate endpoints as well as the analysis workflow. Phishing analysis runs its heuristic detector and, when the trained model is available, the text classifier. Its risk logic uses the ML result to calibrate a phishing risk score. The other detection families use their respective detector and risk, explanation, and response engines. Analysis outcomes are stored as incidents in the in-memory incident manager.

Similarity correlation is deterministic and evidence-based. The incident manager uses the correlation service when processing incidents, and analysts can request correlation details using `GET /incidents/{incident_id}/correlate`. Correlation indicates related telemetry; it does not establish that events share an operator or campaign.

MITRE ATT&CK mappings and defensive playbooks can be requested for an incident using `/incidents/{incident_id}/mitre` and `/incidents/{incident_id}/playbook`. AI analysis is an optional incident investigation aid. The AI analysis route collects incident evidence, model result where present, correlation data, MITRE mapping, and playbook recommendations as context. The analyst endpoint does not automatically execute playbook actions.

## Components

| Component | Location | Responsibility |
|---|---|---|
| Web interface | `frontend/src/` | Dashboard, analysis forms, incident triage, and AI analyst views |
| API | `backend/main.py` | Request validation, analysis routes, incident routes, and response assembly |
| Detectors | `backend/detectors/` | Threat-specific heuristic evidence extraction |
| ML | `backend/ml/` | Phishing text model training, inference, evaluation, and artifacts |
| Risk and analysis engines | `backend/engines/` | Risk, explanations, actions, correlation, MITRE mapping, and playbooks |
| Services | `backend/services/` | Similar-incident correlation and optional AI analyst integration |
| Data models | `backend/models/` | API and incident data schemas |
| Tests | `backend/tests/` | Unit, integration, and hardening coverage |

## Storage and external dependencies

Incidents are held in memory and are reseeded when the backend restarts. The phishing prototype dataset is stored under `backend/ml/data/`; the project-level JSON copy under `datasets/` is used as the training fallback if the CSV is absent. The trained model artifact is checked into `backend/ml/models/phishing_text_model.joblib`; the identical `backend/ml/phishing_model.joblib` file remains as the legacy loader and trainer fallback.

AI analysis sends sanitized incident evidence to the configured OpenAI-compatible chat completions endpoint only when `AI_API_KEY` is configured. `AI_MODEL` and `AI_BASE_URL` select the model and service URL. Without a key or when a request fails, the service returns a deterministic fallback. Review the data-handling implications before enabling an external endpoint.

## Operational limits

- Detection uses heuristic rules and a small curated phishing training set; results are decision support, not a guarantee of detection.
- The trained phishing model covers text classification and does not replace the other threat-specific detectors.
- Incident storage is in-memory and is not durable across restarts.
- Correlation is deterministic similarity scoring, not proof of a coordinated attack.
- Playbooks are advisory; CYBERGUARD does not automatically block accounts, change credentials, or notify third parties.
