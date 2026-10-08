"""
CYBERGUARD AI Security Analyst Service

Evidence-grounded AI Security Analyst that helps analysts interpret CYBERGUARD's
existing detection evidence and prioritize investigation.

Integrates with OpenAI-compatible LLM endpoints via environment variables:
- AI_API_KEY: Authentication bearer key for the LLM endpoint (never hardcoded)
- AI_MODEL: Model identifier (default: 'gpt-4o-mini')
- AI_BASE_URL: Base URL for OpenAI-compatible completions (default: 'https://api.openai.com/v1')

Provides robust, deterministic fallback synthesis when AI_API_KEY is missing or API calls fail.
"""

import os
import json
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List


def sanitize_evidence_data(data: Any) -> Any:
    """
    Strips passwords, secrets, tokens, or private auth keys from telemetry payloads
    before transmitting to external AI models.
    """
    sensitive_substrings = ("password", "passwd", "token", "secret", "api_key", "authorization", "bearer")
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(sub in k.lower() for sub in sensitive_substrings):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_evidence_data(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_evidence_data(item) for item in data]
    return data


def extract_json_from_llm_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extracts and parses a JSON object from raw LLM output, handling markdown code fences.
    """
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    return None


def call_llm_completion(system_prompt: str, user_prompt: str, timeout_seconds: int = 15) -> Optional[str]:
    """
    Executes an HTTP POST to an OpenAI-compatible /chat/completions endpoint using standard library urllib.
    Returns the content string from the first message choice, or None on failure.
    """
    api_key = os.environ.get("AI_API_KEY", "").strip()
    if not api_key:
        return None

    model = os.environ.get("AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    base_url = (os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").strip() or "https://api.openai.com/v1").rstrip("/")
    endpoint = f"{base_url}/chat/completions"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1200
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=req_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "CYBERGUARD-SecurityAnalyst/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            status_code = response.getcode()
            if status_code != 200:
                return None
            body = response.read().decode("utf-8")
            data = json.loads(body)
            choices = data.get("choices")
            if choices and len(choices) > 0:
                msg = choices[0].get("message", {})
                return msg.get("content")
    except Exception:
        return None

    return None


def generate_fallback_analysis(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic, evidence-grounded fallback analysis using CYBERGUARD's detection heuristics.
    Used whenever AI_API_KEY is absent or the external API call fails.
    """
    incident_id = incident_data.get("incident_id", "INC-ALERT")
    threat_type = incident_data.get("threat_type", "Security Threat")
    classification = incident_data.get("classification", "Suspicious Activity")
    risk_score = incident_data.get("risk_score", 0)
    risk_level = incident_data.get("risk_level", "MEDIUM")
    explanation = incident_data.get("explanation", "Observable telemetry indicators warrant analyst review.")
    indicators = incident_data.get("indicators", [])
    recommended_actions = incident_data.get("recommended_actions", [])

    summary = (
        f"Incident {incident_id} involves a {risk_level}-severity {threat_type} incident "
        f"classified as '{classification}' with a CYBERGUARD risk score of {risk_score}/100. "
        f"{explanation}"
    )

    why_it_matters = (
        f"{risk_level}-severity {threat_type} threats introduce immediate organizational exposure, "
        f"such as credential harvesting, session compromise, or unauthorized network reconnaissance. "
        f"Immediate verification and containment prevent lateral movement and data loss."
    )

    key_evidence: List[str] = []
    if isinstance(indicators, list):
        for item in indicators:
            if isinstance(item, dict):
                ind = item.get("indicator", "Indicator")
                det = item.get("details", "")
                key_evidence.append(f"{ind}: {det}" if det else ind)
            elif isinstance(item, str):
                key_evidence.append(item)
    if not key_evidence:
        key_evidence = [explanation]

    investigation_steps = [
        "Verify indicator telemetry against firewall, proxy, and endpoint detection logs.",
        "Validate sender, domain, or authentication signals via verified out-of-band communication.",
        "Cross-reference correlation telemetry against prior recorded security incidents.",
        "Review DNS query records and egress connection logs for related secondary endpoints."
    ]

    rec_actions = list(recommended_actions) if recommended_actions else [
        "Isolate affected user or host context pending verification.",
        "Block identified malicious URLs, sender domains, or unauthorized IP addresses.",
        "Initiate credential rotation if authentication credentials may have been exposed.",
        "Escalate findings with compiled CYBERGUARD evidence to the SOC tier."
    ]

    limitations = (
        "Analysis is grounded strictly in observable CYBERGUARD telemetry and heuristics. "
        "Heuristic detection does not independently prove confirmed adversary attribution, "
        "compromise extent, or active coordinated campaigns without secondary forensic validation."
    )

    return {
        "summary": summary,
        "why_it_matters": why_it_matters,
        "key_evidence": key_evidence,
        "investigation_steps": investigation_steps,
        "recommended_actions": rec_actions,
        "limitations": limitations,
        "status": "fallback",
        "is_fallback": True
    }


def analyze_incident(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes structured incident data using LLM if configured, otherwise falls back
    to deterministic explanation.
    """
    sanitized_data = sanitize_evidence_data(incident_data)
    api_key = os.environ.get("AI_API_KEY", "").strip()

    if api_key:
        system_prompt = (
            "You are a cybersecurity analyst assisting with an incident investigation.\n\n"
            "Use ONLY the supplied CYBERGUARD evidence.\n"
            "Do not invent indicators, URLs, IPs, malware, attribution, threat intelligence, "
            "MITRE techniques, compromise, or attack campaigns.\n\n"
            "If evidence is insufficient, explicitly say so.\n\n"
            "You MUST respond ONLY with valid JSON with the following exact keys:\n"
            "{\n"
            '  "summary": "...",\n'
            '  "why_it_matters": "...",\n'
            '  "key_evidence": ["...", "..."],\n'
            '  "investigation_steps": ["...", "..."],\n'
            '  "recommended_actions": ["...", "..."],\n'
            '  "limitations": "..."\n'
            "}"
        )

        user_prompt = (
            "Analyze the following CYBERGUARD structured incident evidence:\n"
            f"{json.dumps(sanitized_data, indent=2)}"
        )

        raw_completion = call_llm_completion(system_prompt, user_prompt)
        if raw_completion:
            parsed = extract_json_from_llm_text(raw_completion)
            required_keys = [
                "summary",
                "why_it_matters",
                "key_evidence",
                "investigation_steps",
                "recommended_actions",
                "limitations"
            ]
            if parsed and all(k in parsed for k in required_keys):
                key_evidence = parsed.get("key_evidence") if isinstance(parsed.get("key_evidence"), list) else [str(parsed.get("key_evidence", ""))]
                investigation_steps = parsed.get("investigation_steps") if isinstance(parsed.get("investigation_steps"), list) else [str(parsed.get("investigation_steps", ""))]
                recommended_actions = parsed.get("recommended_actions") if isinstance(parsed.get("recommended_actions"), list) else [str(parsed.get("recommended_actions", ""))]

                return {
                    "summary": str(parsed.get("summary", "")).strip(),
                    "why_it_matters": str(parsed.get("why_it_matters", "")).strip(),
                    "key_evidence": [str(x) for x in key_evidence],
                    "investigation_steps": [str(x) for x in investigation_steps],
                    "recommended_actions": [str(x) for x in recommended_actions],
                    "limitations": str(parsed.get("limitations", "")).strip(),
                    "status": "ai",
                    "is_fallback": False
                }

    # Fallback mode (missing key, API failure, or malformed LLM response)
    return generate_fallback_analysis(incident_data)


def generate_fallback_chat_answer(incident_data: Dict[str, Any], question: str) -> str:
    """
    Evidence-grounded deterministic answering for questions regarding the incident.
    """
    q_lower = question.lower()
    incident_id = incident_data.get("incident_id", "Incident")
    risk_level = incident_data.get("risk_level", "UNKNOWN")
    risk_score = incident_data.get("risk_score", 0)
    classification = incident_data.get("classification", "")
    threat_type = incident_data.get("threat_type", "")
    explanation = incident_data.get("explanation", "")
    indicators = incident_data.get("indicators", [])
    rec_actions = incident_data.get("recommended_actions", [])
    correlation = incident_data.get("correlation results") or incident_data.get("correlation") or {}

    ind_lines = []
    for item in indicators:
        if isinstance(item, dict):
            ind = item.get("indicator", "")
            det = item.get("details", "")
            ind_lines.append(f"{ind}: {det}" if det else ind)
        elif isinstance(item, str):
            ind_lines.append(item)

    # 1. Check out of scope / unsupported questions first
    unsupported_topics = [
        "attribution", "nation", "apt", "actor", "who attacked", "deepfake", "malware hash",
        "external cve", "threat actor", "c2 server ip", "country", "russia", "china", "culprit"
    ]
    if any(topic in q_lower for topic in unsupported_topics):
        return (
            "Insufficient evidence in the available incident data. "
            "CYBERGUARD telemetry does not contain adversary attribution or external threat intelligence feeds."
        )

    # 2. Why risky / critical / score question
    if any(k in q_lower for k in ["why", "critical", "risk", "score", "severity", "classified"]):
        ind_text = "; ".join(ind_lines[:3]) if ind_lines else "Heuristic risk indicators"
        return (
            f"{incident_id} was classified as {risk_level} with a risk score of {risk_score}/100 "
            f"because it matched the threat profile for '{classification}'. "
            f"Observed evidence: {ind_text}. "
            f"Explanation: {explanation}"
        )

    # 3. Evidence / indicators question
    if any(k in q_lower for k in ["evidence", "indicator", "support", "signal", "proof"]):
        if ind_lines:
            items_str = "\n• " + "\n• ".join(ind_lines)
            return f"The evidence supporting this classification comprises:{items_str}"
        return f"Evidence indicators recorded for {incident_id}: {explanation}"

    # 4. Investigation / priority / what should I do first question
    if any(k in q_lower for k in ["investigate", "first", "next", "step", "action", "priority", "do"]):
        first_action = rec_actions[0] if rec_actions else "Verify indicator telemetry against internal security logs."
        return (
            f"Primary investigation priority for {incident_id}: "
            f"1. Isolate and verify the primary indicators ({ind_lines[0] if ind_lines else classification}). "
            f"2. Validate origin out-of-band before taking irreversible action. "
            f"3. Recommended immediate defense: {first_action}"
        )

    # 5. Related incidents / correlations / campaign
    if any(k in q_lower for k in ["related", "similar", "correlat", "campaign", "chain", "other incident"]):
        rel_ids = correlation.get("related_incident_ids") or []
        corr_score = correlation.get("correlation_score", 0)
        reason = correlation.get("reason", "")
        matched = correlation.get("matched_signals") or []
        if rel_ids:
            return (
                f"Correlation analysis identified {len(rel_ids)} related incident(s): {', '.join(rel_ids)} "
                f"(Similarity Score: {corr_score}/100). "
                f"Matched signals: {', '.join(matched) if matched else 'Domain/telemetry overlap'}. "
                f"Rationale: {reason}"
            )
        return (
            f"No significant relationship was detected with prior recorded incidents "
            f"based on observable CYBERGUARD telemetry (Score: 0/100). {reason or ''}".strip()
        )

    # General question about the incident
    return (
        f"Grounded evidence for {incident_id} ({threat_type}): {explanation} "
        f"Risk Level: {risk_level} ({risk_score}/100)."
    )


def ask_incident_question(incident_data: Dict[str, Any], question: str) -> Dict[str, Any]:
    """
    Answers an analyst's question regarding an incident using LLM (if configured)
    or evidence-grounded fallback.
    """
    sanitized_data = sanitize_evidence_data(incident_data)
    api_key = os.environ.get("AI_API_KEY", "").strip()

    if api_key:
        system_prompt = (
            "You are a cybersecurity analyst assisting with an incident investigation.\n\n"
            "Use ONLY the supplied CYBERGUARD evidence.\n"
            "Do not invent indicators, URLs, IPs, malware, attribution, threat intelligence, "
            "MITRE techniques, compromise, or attack campaigns.\n\n"
            "If evidence is insufficient to answer the question, explicitly answer: "
            "'Insufficient evidence in the available incident data.'\n\n"
            "Be concise, evidence-grounded, and objective."
        )

        user_prompt = (
            f"CYBERGUARD Incident Evidence:\n{json.dumps(sanitized_data, indent=2)}\n\n"
            f"Analyst Question: {question}"
        )

        raw_answer = call_llm_completion(system_prompt, user_prompt)
        if raw_answer:
            return {
                "answer": raw_answer.strip(),
                "status": "ai",
                "is_fallback": False
            }

    # Fallback deterministic answer
    fallback_ans = generate_fallback_chat_answer(incident_data, question)
    return {
        "answer": fallback_ans,
        "status": "fallback",
        "is_fallback": True
    }
