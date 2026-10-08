# CYBERGUARD — Safe Hackathon Demo Guide

This guide provides a step-by-step walkthrough for presenting CYBERGUARD during live demonstrations and hackathon evaluations.

---

## 1. Demo Preparation
1. Ensure the **FastAPI Backend** is running on `http://127.0.0.1:8000`.
2. Ensure the **React Frontend** is running on `http://localhost:5173`.
3. Open your browser to `http://localhost:5173`.

---

## 2. 5-Minute Live Presentation Flow

```
[ Dashboard ] ➔ [ 4 Analyzers ] ➔ [ Incident Center ] ➔ [ Playbooks & Triage ] ➔ [ Resolution ]
```

---

### Step 1: Dashboard Overview (1 Minute)
1. Show the **Hero Section** highlighting the **7-Stage Workflow Pipeline**:
   $$\text{Detection} \rightarrow \text{Classification} \rightarrow \text{Risk Score} \rightarrow \text{Explanation} \rightarrow \text{Incident} \rightarrow \text{Alert} \rightarrow \text{Response}$$
2. Point out the **Executive KPI Strip** (Total Analyzed, Incidents, Critical, High, Resolved).
3. Review the **Active Threat Alert Center** displaying priority alerts and the **Threat Category Distribution Charts**.

---

### Step 2: Multi-Vector Threat Analysis Demos (2 Minutes)

#### A. Phishing Analyzer
1. Click **Phishing Analyzer** in the sidebar.
2. Select the preset **"Brand Lookalike Phish"**.
3. Click **Analyze Phishing Threat**.
4. Highlight:
   - Risk score **90 / 100 (CRITICAL)**.
   - Transparent heuristic indicator breakdown (Urgency, Credential Solicitation, Homoglyph Domain).
   - Human-readable synthesis explaining the threat mechanism.

#### B. URL Threat Analyzer
1. Click **URL Threat Analyzer** in the sidebar.
2. Select the preset **"Deceptive @ Userinfo"** (`http://paypal.com@malicious-redirect-portal.net/security/update`).
3. Click **Analyze Target URL**.
4. Highlight:
   - Detection of the `@` userinfo parser delimiter that routes users to the unverified host.

#### C. Impersonation Analyzer
1. Click **Impersonation Analyzer** in the sidebar.
2. Select the preset **"Fake Government Officer"** (IRS pretext from a Gmail account).
3. Click **Analyze Impersonation Threat**.
4. Highlight:
   - Discrepancy detection between the claimed government identity and the generic freemail domain.

#### D. Account Security & Takeover
1. Click **Account Security** in the sidebar.
2. Select the preset **"Brute-Force Attack"** (15 failed logins via Tor exit relay).
3. Click **Analyze Authentication Telemetry**.
4. Highlight:
   - Anomaly score triggered by failed login spike + automated headless client detection.

---

### Step 3: Incident Center & Triage Workflow (1.5 Minutes)
1. Click **Incident Center** in the sidebar.
2. Observe how the 4 tests ran in Step 2 have been automatically recorded as new incidents.
3. Use the **Filter & Search Bar**:
   - Filter by `CRITICAL` risk or type `PayPal` into the search box to demonstrate instant client/server filtering.
4. Click on **INC-2026-0001** (or any newly created incident) to open the **Investigation Drawer**.
5. Review the **Defensive Response Playbook** containing numbered, actionable, non-destructive safety recommendations.
6. Change the triage status:
   - Click **INVESTIGATING** (observe badge color updates to amber).
   - Click **RESOLVED** (observe badge color updates to emerald).

---

### Step 4: Full-Circle Verification on Dashboard (0.5 Minutes)
1. Return to the **Dashboard**.
2. Show that:
   - **Resolved Incidents** count has incremented.
   - The resolved incident has cleared from the **Active Threat Alert Center**.
   - Category distribution percentages reflect the new analyses.

---

## 3. Key Talking Points for Judges
- **Unified Defense**: Combines email text, URLs, identity claims, and authentication anomalies into one coordinated platform.
- **Explainability First**: No black-box magic numbers — every score is backed by granular technical indicators and natural language explanations.
- **Safety by Design**: Advisory defensive playbooks empower security analysts without introducing high-risk automated account lockouts or false-positive disruptions.
- **Rigorous Engineering**: 121 automated unit, integration, and hardening tests, decoupled FastAPI backend, and high-aesthetic dark cybersecurity UI.
