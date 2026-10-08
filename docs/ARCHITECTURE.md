# CYBERGUARD — System Architecture & Workflow Pipeline

This document details the architectural principles, data models, and the complete operational workflow pipeline of **CYBERGUARD**.

---

## 1. End-to-End Workflow Pipeline

CYBERGUARD operates on a continuous, explainable 7-stage pipeline:

```
+---------------+     +--------------------+     +-------------------+
|  1. DETECTION  | --> | 2. CLASSIFICATION  | --> |   3. RISK SCORE   |
| (Ingest data) |     |  (Tag indicators)  |     |  (Category Caps)  |
+---------------+     +--------------------+     +-------------------+
                                                           |
                                                           v
+---------------+     +--------------------+     +-------------------+
|  6. RESPONSE  | <-- | 5. INCIDENT & ALERT| <-- |  4. EXPLANATION   |
| (Playbooks)   |     | (Store & Correlate)|     | (Human Synthesis) |
+---------------+     +--------------------+     +-------------------+
```

---

### Stage 1: Detection (Telemetry Ingestion)
Raw telemetry is submitted via specialized REST endpoints:
- **Email / Message Text & Sender**: Ingested via `POST /analyze/phishing`.
- **Target Link / URL / Domain / IP**: Ingested via `POST /analyze/url` with support for full URLs, domain names, and IPv4/IPv6 addresses.
- **Claimed Identity & Origin**: Ingested via `POST /analyze/impersonation`.
- **Authentication Events**: Ingested via `POST /analyze/account-security` (failed login counts, IP, device user-agents, impossible travel, and password reset activity).
- **Multimedia Media Files**: Ingested via `POST /analyze/multimodal`.

---

### Stage 2: Classification & Normalization (Heuristic Pattern Tagging)
Each module executes specialized heuristic algorithms that inspect for technical patterns:
- **Phishing Engine**: Scans for urgency triggers, credential solicitation, financial lures, and sender domain lookalikes.
- **Unified URL, Domain & IP Threat Engine**:
  - **Normalization**: Safely decomposes targets into hostnames, registrable domains, subdomains, and TLDs with support for multi-part public suffixes (`.co.uk`, `.com.au`, `.co.in`, etc.).
  - **Observable URL Heuristics**: Evaluates raw IP hosts, `@` userinfo delimiter evasion, URL shortening redirects, non-standard ports, suspicious TLDs, double slash path sequences, and character encoding obfuscation.
  - **Domain Analysis**: Analyzes domain length, subdomain counts, punycode/IDN homoglyphs (`xn--`), numeric-heavy hostname patterns (DGA indicators), consecutive hyphens, and high-abuse TLDs (`.xyz`, `.top`, `.tk`, etc.).
  - **IP Analysis**: Passive syntactic validation, IPv4 vs IPv6 classification, and private/RFC1918 vs public/global address scope detection.
- **Impersonation Engine**: Evaluates domain alignment between claimed organizations (e.g. IRS, CEO, Chase) and external sender addresses.
- **Account Security Engine**: Identifies brute-force spikes, Tor/anonymized proxies, impossible travel velocity across continents, and recovery chain manipulation.

---

### Stage 3: Risk Scoring (Category-Capped Heuristics)
To prevent single anomalies from inflating scores disproportionately, scores ($0-100$) are calculated using weighted, category-capped heuristic engines:

$$\text{Final Risk Score} = \min\left(100, \sum_{c \in \text{Categories}} \min(\text{Subtotal}_c, \text{Cap}_c)\right)$$

#### Severity Rating Tiers:
| Score Range | Severity Level | UI Color Theme | Operational Action |
|---|---|---|---|
| **0 – 19** | `SAFE` | Emerald / Cyan | Normal verified event; no action needed. |
| **20 – 39** | `LOW` | Sky Blue | Minor anomaly; baseline monitoring. |
| **40 – 69** | `MEDIUM` | Amber / Yellow | Elevated risk; advisory review recommended. |
| **70 – 79** | `HIGH` | Orange | High probability of threat; investigate prompt. |
| **80 – 100** | `CRITICAL` | Rose Red (Glowing) | Immediate triage; priority alert dispatched. |

---

### Stage 4: Explanation (Human-Readable Synthesis)
The synthesis engine generates a clear, natural-language narrative explaining:
1. Primary threat classification summary.
2. Key technical evidence observed.
3. Relevant contextual telemetry.
4. Transparent notice stating that score is heuristic and non-destructive.

> [!NOTE]
> **Heuristic Boundary Disclosure**: The analyzer identifies suspicious characteristics based on observable telemetry; it does not prove that a domain or IP is malicious without reliable external reputation or threat-intelligence evidence.

---

### Stage 5: Incident Creation, Storage & Similar-Incident Correlation
When an analysis is executed across any detector, the backend automatically logs an `Incident` into the thread-safe `IncidentManager`.
- Generates a unique Incident ID (e.g. `INC-2026-0007`).
- Assigns initial status: `NEW`.
- **Deterministic Similar-Incident Correlation**: Uses `backend/services/incident_correlation.py` as the **single source of truth** across ingestion, the Incident Center, and `GET /api/incidents/{incident_id}/correlate`. Compares telemetry against previous incidents using 8 deterministic signals (`same_exact_url`, `same_domain`, `same_sender`, `same_threat_type`, `same_ip`, `same_user`, `shared_indicators`, `recent_occurrence` within 24h).
- Attaches an `IncidentCorrelationInfo` metadata object with similarity scores (0-100), matched signals, linked incident IDs, and explainable reasons.
- High-risk and Critical incidents automatically appear in the main **Dashboard Active Threat Alert Center**.

> [!NOTE]
> **Conceptual Disclaimer**: The correlation score represents deterministic similarity between observed incident attributes. It is not a probability and does not independently confirm a coordinated attack.

---

### Stage 6: Response Playbook Generation
The system matches the detected evidence with defensive, safe recommendations:
- **Verify out-of-band**: Contact sender via official directory phone number.
- **Avoid interaction**: Do not enter credentials on redirected hosts or unverified domains.
- **Identity Hardening**: Prompt user to reset password through official corporate SSO and mandate MFA.
- **Gateway Blocking**: Add destination IP / lookalike domain to firewall egress blocklists.

> [!IMPORTANT]
> **Advisory Safety Guardrail**: Playbooks are non-destructive recommendations. CYBERGUARD does not automatically execute unauthorized account locks, port scans, network floods, or external communications.

---

## 2. Storage & Integration Architecture

- **Thread-Safety**: All reads and writes to the centralized incident repository are synchronized with Python's standard `threading.Lock`.
- **Querying & Filtering**: Supports in-memory filtering by `threat_type`, `risk_level`, `status`, text `search` across all attributes, and sorting by `timestamp`, `risk_score`, or `incident_id`.
- **Deterministic Correlation Engine**: Modular correlation service (`backend/services/incident_correlation.py`) that operates without external database or LLM dependencies.
- **Threat Intelligence Extensibility**: Designed with clean provider hooks for live reputation data (e.g. VirusTotal, AlienVault OTX, AbuseIPDB) to be added without modifying the core parsing and classification pipeline.
