# CYBERGUARD — REST API Documentation

Base URL: `http://127.0.0.1:8000`  
Interactive Swagger UI: `http://127.0.0.1:8000/docs`  
OpenAPI Specification: `http://127.0.0.1:8000/openapi.json`

---

## Table of Contents
1. [Core Endpoints](#1-core-endpoints)
   - [GET /](#get-)
2. [Threat Analysis Endpoints](#2-threat-analysis-endpoints)
   - [POST /analyze/phishing](#post-analyzephishing)
   - [POST /analyze/url (Unified URL, Domain & IP Analyzer)](#post-analyzeurl)
   - [POST /analyze/impersonation](#post-analyzeimpersonation)
   - [POST /analyze/account-security](#post-analyzeaccount-security)
   - [POST /analyze/multimodal](#post-analyzemultimodal)
   - [POST /analyze/login](#post-analyzelogin)
3. [Incident Management & Similar-Incident Correlation Endpoints](#3-incident-management--similar-incident-correlation-endpoints)
   - [GET /incidents](#get-incidents)
   - [GET /incidents/{incident_id}](#get-incidentsincident_id)
   - [PATCH /incidents/{incident_id}/status](#patch-incidentsincident_idstatus)
4. [Similar-Incident Correlation Methodology](#4-similar-incident-correlation-methodology)
5. [Heuristic & Reputation Methodology](#5-heuristic--reputation-methodology)
6. [Standard Error Responses](#6-standard-error-responses)

---

## 1. Core Endpoints

### `GET /`
Returns the operational health and timestamp of the backend node.

---

## 2. Threat Analysis Endpoints

### `POST /analyze/phishing`
Analyzes message body, optional target URL, and sender address for phishing indicators. Automatically logs an incident into the centralized store with similar-incident correlation.

---

### `POST /analyze/url`
Unified URL, Domain, and IP Address Security Analyzer. Performs passive structural and heuristic inspection across three input modes (`url`, `domain`, `ip`, or `auto`). Automatically records an incident with correlation telemetry.

---

### `POST /analyze/impersonation`
Analyzes communication telemetry for digital impersonation of brands, corporate executives, or government authorities.

---

### `POST /analyze/account-security`
Evaluates login and authentication events for brute-force attacks, impossible travel, and MFA tampering.

---

## 3. Incident Management & Similar-Incident Correlation Endpoints

### `GET /incidents`
Query security incidents with multi-dimensional filtering, sorting, and aggregate telemetry counts.

#### Response Schema includes:
- `total`: Total incidents matching query
- `linked_count`: Total incidents with identified related activity
- `incidents`: Array of `Incident` objects, each containing its deterministic `correlation` metadata.

---

### `GET /incidents/{incident_id}`
Retrieves complete details for a specific incident, including its deterministic `correlation` analysis.

#### Response Example:
```json
{
  "incident_id": "INC-2026-0001",
  "threat_type": "Phishing",
  "classification": "Brand Impersonation & Urgent Credential Lure",
  "risk_score": 92,
  "risk_level": "CRITICAL",
  "evidence": [
    {
      "indicator": "High Urgency Keyword",
      "details": "Message contains urgent coercive wording: 'URGENT: Your account access has been restricted'."
    }
  ],
  "explanation": "Critical phishing lure identified imitating PayPal.",
  "recommended_actions": [
    "Do not click the provided link or input credentials.",
    "Block the sender domain at the email gateway."
  ],
  "timestamp": "2026-09-17T08:15:22Z",
  "status": "NEW",
  "source_data": {
    "sender": "security@paypal-notice.com",
    "url": "http://paypa1-secure-verify.net/signin"
  },
  "correlation": {
    "related": true,
    "correlation_score": 75,
    "matched_signals": [
      "same_domain",
      "same_threat_type",
      "recent_occurrence"
    ],
    "related_incident_ids": [
      "INC-2026-0002"
    ],
    "reason": "Potentially related activity detected across 1 previous incident(s) (INC-2026-0002) sharing domain 'paypa1-secure-verify.net', Phishing threat category, occurrences within 24h window. This indicates observable telemetry similarity, not a confirmed coordinated attack."
  }
}
```

---

### `PATCH /incidents/{incident_id}/status`
Updates the triage status of an incident (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

---

### `GET /incidents/{incident_id}/correlate` (also `/api/incidents/{incident_id}/correlate`)
Single source of truth endpoint for similar-incident correlation, entity pivots, and chronological attack progression.

#### Response Example:
```json
{
  "incident_id": "INC-2026-0001",
  "correlation": {
    "related": true,
    "correlation_score": 82,
    "matched_signals": [
      "same_domain",
      "same_threat_type",
      "recent_occurrence"
    ],
    "related_incident_ids": [
      "INC-2026-0002"
    ],
    "reason": "Potentially related activity detected across 1 previous incident(s) (INC-2026-0002) sharing domain 'paypa1-secure-verify.net', Phishing threat category, occurrences within 24h window. This indicates observable telemetry similarity, not a confirmed coordinated attack."
  },
  "related_incidents": [
    {
      "incident_id": "INC-2026-0002",
      "threat_type": "Phishing",
      "correlation_score": 82,
      "matched_signals": [
        "same_domain",
        "same_threat_type"
      ],
      "timestamp": "2026-09-17T08:15:22Z"
    }
  ],
  "pivots": [
    {
      "type": "Domain",
      "value": "paypa1-secure-verify.net",
      "matching_incidents": [
        "INC-2026-0001",
        "INC-2026-0002"
      ]
    }
  ],
  "attack_chain": [
    {
      "step_order": 1,
      "incident_id": "INC-2026-0001",
      "threat_type": "Phishing",
      "classification": "Brand Impersonation & Urgent Credential Lure",
      "timestamp": "2026-09-17T08:15:22Z",
      "risk_level": "CRITICAL"
    },
    {
      "step_order": 2,
      "incident_id": "INC-2026-0002",
      "threat_type": "Phishing",
      "classification": "Credential Harvesting Lure",
      "timestamp": "2026-09-17T08:30:00Z",
      "risk_level": "HIGH"
    }
  ]
}
```

---

## 4. Similar-Incident Correlation Methodology

### Overview & Purpose
When an incident is ingested or queried via API, CYBERGUARD uses a **canonical, single source of truth** deterministic correlation service (`backend/services/incident_correlation.py`). This engine analyzes observable telemetry signals to identify potentially related activity clusters without requiring graph databases or non-deterministic LLMs.

> **Conceptual Disclaimer**:
> The correlation score represents deterministic similarity between observed incident attributes. It is not a probability and does not independently confirm a coordinated attack.

### Observable Correlation Signals & Scoring Weights
| Signal | Weight | Description |
|---|---|---|
| `same_exact_url` | **+40** | Current incident shares the exact target URL with a previous incident |
| `same_domain` | **+35** | Current incident shares the root or second-level domain / host |
| `same_sender` | **+30** | Current incident shares the identical sender address |
| `same_threat_type` | **+25** | Both incidents fall into the same threat vector (e.g. Phishing ↔ Phishing) |
| `same_ip` | **+25** | Identical client or destination IP address |
| `same_user` | **+20** | Targeted user account or username matches |
| `shared_indicators` | **+10** | One or more common security evidence indicators |
| `recent_occurrence` | **+10** | Both incidents occurred within the configured time window (awarded with substantive signal match) |

*Total score is clamped to a maximum of 100.*

### Configuration Parameters
- **Time Window**: `24.0` hours (configurable)
- **Correlation Threshold**: `30` points
  - **0 – 29**: No significant relationship (`related: false`)
  - **30 – 59**: Weak similarity / related activity (`related: true`)
  - **60 – 79**: Related activity (`related: true`)
  - **80 – 100**: Strong similarity (`related: true`)

### Heuristic Limitations & Language Guardrails
> **Crucial Distinction**: The correlation engine identifies **observable telemetry similarity**; it does not claim to prove that incidents belong to a confirmed coordinated attack campaign.
> Wording strictly uses **"Related activity detected"** and **"Potentially related incidents"**, never **"Confirmed attack campaign"**.

---

## 5. Heuristic & Reputation Methodology

### Passive Telemetry Principle
The threat analyzer operates in a strictly passive capacity:
- **No Port Scanning**: Does not initiate connection attempts to arbitrary ports.
- **No Intrusive Web Crawling**: Does not execute remote scripts or submit active payloads.
- **No Exploitation**: Operates entirely on observable lexical structure, DNS public suffix hierarchy, homoglyphs, and keyword markers.

---

## 6. Standard Error Responses

### `404 Not Found` (Incident does not exist)
```json
{
  "detail": "Incident 'INC-9999-9999' was not found in the CYBERGUARD incident repository."
}
```

### `422 Unprocessable Entity` (Schema Validation Error)
```json
{
  "detail": [
    {
      "type": "enum",
      "loc": ["body", "status"],
      "msg": "Input should be 'NEW', 'INVESTIGATING', 'RESOLVED' or 'FALSE_POSITIVE'",
      "input": "INVALID_STATUS"
    }
  ]
}
```
