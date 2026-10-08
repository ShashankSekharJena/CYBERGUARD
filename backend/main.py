import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from backend.models.phishing import (
        PhishingAnalysisRequest,
        PhishingAnalysisResponse,
        EvidenceItem,
        MLPredictionDetails,
        MLFeatureContribution,
        MLAnalysisSummary
    )
    from backend.models.url import (
        UrlAnalysisRequest,
        UrlAnalysisResponse,
        UrlEvidenceItem,
        DomainDetails,
        IpDetails
    )
    from backend.models.impersonation import (
        ImpersonationAnalysisRequest,
        ImpersonationAnalysisResponse,
        ImpersonationEvidenceItem
    )
    from backend.models.account_security import (
        AccountSecurityRequest,
        AccountSecurityResponse,
        AccountSecurityEvidenceItem,
        BehaviouralAnomalyMetrics
    )
    from backend.models.multimodal import (
        MultimodalAnalysisResponse,
        MetadataSummary,
        ForensicIndicator
    )
    from backend.models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentStatusUpdateRequest,
        IncidentListResponse,
        IncidentCorrelationResponse,
        AiAnalysisResponse,
        AiChatRequest,
        AiChatResponse
    )
    from backend.detectors.phishing_detector import detect_phishing
    from backend.detectors.url_detector import (
        detect_url_threats,
        detect_domain_threats,
        analyze_ip_address,
        normalize_target_input,
        analyze_target_telemetry
    )
    from backend.detectors.impersonation_detector import detect_impersonation
    from backend.detectors.account_security_detector import detect_account_security_threats
    from backend.detectors.multimodal_detector import detect_multimodal_threats
    from backend.ml.predictor import predictor
    from backend.engines.risk_engine import calculate_risk_score
    from backend.engines.explanation_engine import generate_explanation
    from backend.engines.response_engine import generate_recommended_actions
    from backend.engines.url_risk_engine import calculate_url_risk_score
    from backend.engines.url_explanation_engine import generate_url_explanation
    from backend.engines.url_response_engine import generate_url_recommended_actions
    from backend.engines.impersonation_risk_engine import calculate_impersonation_risk_score
    from backend.engines.impersonation_explanation_engine import generate_impersonation_explanation
    from backend.engines.impersonation_response_engine import generate_impersonation_recommended_actions
    from backend.engines.account_security_risk_engine import calculate_account_security_risk_score
    from backend.engines.account_security_explanation_engine import generate_account_security_explanation
    from backend.engines.account_security_response_engine import generate_account_security_recommended_actions
    from backend.engines.multimodal_risk_engine import calculate_multimodal_risk
    from backend.engines.multimodal_explanation_engine import generate_multimodal_explanation
    from backend.engines.multimodal_response_engine import generate_multimodal_recommendations
    from backend.engines.correlation_engine import correlation_engine
    from backend.engines.mitre_mapping import map_mitre_techniques, MitreTechniqueMapping
    from backend.engines.playbook_engine import generate_playbook, IncidentResponsePlaybook
    from backend.engines.incident_manager import incident_manager
    from backend.services.ai_security_analyst import analyze_incident, ask_incident_question
except ImportError:
    from models.phishing import (
        PhishingAnalysisRequest,
        PhishingAnalysisResponse,
        EvidenceItem,
        MLPredictionDetails,
        MLFeatureContribution,
        MLAnalysisSummary
    )
    from models.url import (
        UrlAnalysisRequest,
        UrlAnalysisResponse,
        UrlEvidenceItem,
        DomainDetails,
        IpDetails
    )
    from models.impersonation import (
        ImpersonationAnalysisRequest,
        ImpersonationAnalysisResponse,
        ImpersonationEvidenceItem
    )
    from models.account_security import (
        AccountSecurityRequest,
        AccountSecurityResponse,
        AccountSecurityEvidenceItem,
        BehaviouralAnomalyMetrics
    )
    from models.multimodal import (
        MultimodalAnalysisResponse,
        MetadataSummary,
        ForensicIndicator
    )
    from models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentStatusUpdateRequest,
        IncidentListResponse,
        IncidentCorrelationResponse,
        AiAnalysisResponse,
        AiChatRequest,
        AiChatResponse
    )
    from detectors.phishing_detector import detect_phishing
    from detectors.url_detector import (
        detect_url_threats,
        detect_domain_threats,
        analyze_ip_address,
        normalize_target_input,
        analyze_target_telemetry
    )
    from detectors.impersonation_detector import detect_impersonation
    from detectors.account_security_detector import detect_account_security_threats
    from detectors.multimodal_detector import detect_multimodal_threats
    from ml.predictor import predictor
    from engines.risk_engine import calculate_risk_score
    from engines.explanation_engine import generate_explanation
    from engines.response_engine import generate_recommended_actions
    from engines.url_risk_engine import calculate_url_risk_score
    from engines.url_explanation_engine import generate_url_explanation
    from engines.url_response_engine import generate_url_recommended_actions
    from engines.impersonation_risk_engine import calculate_impersonation_risk_score
    from engines.impersonation_explanation_engine import generate_impersonation_explanation
    from engines.impersonation_response_engine import generate_impersonation_recommended_actions
    from engines.account_security_risk_engine import calculate_account_security_risk_score
    from engines.account_security_explanation_engine import generate_account_security_explanation
    from engines.account_security_response_engine import generate_account_security_recommended_actions
    from engines.multimodal_risk_engine import calculate_multimodal_risk
    from engines.multimodal_explanation_engine import generate_multimodal_explanation
    from engines.multimodal_response_engine import generate_multimodal_recommendations
    from engines.correlation_engine import correlation_engine
    from engines.mitre_mapping import map_mitre_techniques, MitreTechniqueMapping
    from engines.playbook_engine import generate_playbook, IncidentResponsePlaybook
    from engines.incident_manager import incident_manager
    from services.ai_security_analyst import analyze_incident, ask_incident_question

app = FastAPI(
    title="CYBERGUARD API",
    description="AI-powered Cyber Threat, Phishing, URL Threat, Digital Impersonation, and Account Takeover Detection and Response System",
    version="1.0.0"
)

# Enable CORS for React Frontend (strict origins, no '*' with allow_credentials=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5174",
        "http://127.0.0.1:5174"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginAnalysisRequest(BaseModel):
    username: Optional[str] = Field(default=None, description="User account identifier")
    ip_address: Optional[str] = Field(default="127.0.0.1", description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Browser User Agent")
    location: Optional[str] = Field(default=None, description="Reported location")


class MultimodalJsonPayload(BaseModel):
    file_name: str = Field(default="uploaded_media.png", description="File name")
    file_base64: str = Field(..., description="Base64 encoded file content")
    content_type: Optional[str] = Field(default=None, description="MIME content type")


@app.get("/")
def read_root():
    return {
        "message": "CYBERGUARD Backend Running",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Diagnostic login test endpoint
@app.post("/analyze/login")
@app.post("/api/analyze/login")
def analyze_login(payload: Optional[LoginAnalysisRequest] = None):
    return {
        "status": "success",
        "message": "Login API is working",
        "received_data": payload.model_dump() if payload else None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ==========================================
# Phase 1: ML Phishing Metrics & Endpoints
# ==========================================

@app.get("/ml/metrics")
@app.get("/api/ml/metrics")
def get_ml_metrics():
    metrics = predictor.get_metrics()
    if not metrics:
        return {
            "status": "UNAVAILABLE",
            "message": "ML model metrics not yet loaded or model is not trained."
        }
    return metrics


@app.post("/analyze/phishing", response_model=PhishingAnalysisResponse)
@app.post("/api/phishing/analyze", response_model=PhishingAnalysisResponse)
def analyze_phishing(payload: Optional[PhishingAnalysisRequest] = None) -> PhishingAnalysisResponse:
    if payload is None:
        payload = PhishingAnalysisRequest()

    message_text = payload.get_effective_text()
    url = payload.url.strip() if (payload.url and isinstance(payload.url, str)) else None
    sender = payload.sender.strip() if (payload.sender and isinstance(payload.sender, str)) else None

    # 1. Run heuristic detection engine
    raw_indicators = detect_phishing(message_text=message_text, url=url, sender=sender)

    # 2. Run ML Classifier on message text
    ml_prediction_details = None
    ml_summary = None
    ml_confidence = None
    detection_source = "heuristic_fallback"
    ml_res = None

    if message_text and predictor.is_available:
        ml_res = predictor.predict(message_text)
        if ml_res.get("available"):
            detection_source = "hybrid"
            is_phish = ml_res.get("is_phishing", False)
            if is_phish:
                ml_confidence = ml_res.get("confidence")

            ml_summary = MLAnalysisSummary(
                model=ml_res.get("model", "TF-IDF + Logistic Regression"),
                prediction=ml_res.get("prediction", "phishing" if is_phish else "legitimate"),
                confidence=ml_res.get("confidence", 0.0),
                probability=ml_res.get("probability", 0.0),
                phishing_probability=ml_res.get("phishing_probability", 0.0)
            )

            top_feats = [
                MLFeatureContribution(
                    term=f["term"],
                    weight=f["weight"],
                    impact=f["impact"],
                    direction=f["direction"]
                )
                for f in ml_res.get("top_features", [])
            ]
            ml_prediction_details = MLPredictionDetails(
                available=True,
                prediction_label=ml_res.get("prediction_label", "UNKNOWN"),
                is_phishing=is_phish,
                phishing_probability=ml_res.get("phishing_probability", 0.0),
                confidence=ml_res.get("confidence", 0.0),
                top_features=top_feats,
                explanation=ml_res.get("explanation", "")
            )

    # 3. Compute heuristic risk score and severity
    risk_score, severity = calculate_risk_score(raw_indicators)

    # Hybrid Decision Logic:
    # If ML model identifies phishing patterns, calibrate risk score transparently
    if ml_prediction_details and ml_prediction_details.is_phishing:
        phish_p = ml_prediction_details.phishing_probability
        if phish_p >= 0.70 and risk_score < 50:
            risk_score = max(risk_score, int(phish_p * 75))
        elif phish_p >= 0.50 and risk_score > 0:
            risk_score = min(100, max(risk_score, int(risk_score * 0.7 + phish_p * 30)))

        # Update severity bucket
        if risk_score >= 90:
            severity = "CRITICAL"
        elif risk_score >= 70:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        elif risk_score >= 20:
            severity = "LOW"
        else:
            severity = "SAFE"

    # 4. Generate evidence-based human-readable explanation
    explanation = generate_explanation(raw_indicators, risk_score, severity, ml_result=ml_res)

    # 5. Generate tailored recommendations
    recommended_actions = generate_recommended_actions(raw_indicators, severity)

    # 6. Structure evidence items
    evidence = [
        EvidenceItem(
            indicator=item.get("indicator", "Suspicious Indicator"),
            details=item.get("details", "")
        )
        for item in raw_indicators
    ]

    # Auto-record into Centralized Incident Store
    try:
        incident_manager.record_phishing_analysis(
            risk_score=risk_score,
            severity=severity,
            explanation=explanation,
            evidence_items=[{"indicator": ev.indicator, "details": ev.details} for ev in evidence],
            recommended_actions=recommended_actions,
            source_data={"message_text": message_text, "url": url, "sender": sender}
        )
    except Exception:
        pass

    return PhishingAnalysisResponse(
        threat_type="Phishing",
        risk_score=risk_score,
        severity=severity,
        confidence=ml_confidence,
        evidence=evidence,
        explanation=explanation,
        recommended_actions=recommended_actions,
        ml_analysis=ml_summary,
        ml_details=ml_prediction_details,
        detection_source=detection_source
    )


# ==========================================
# Phase 2: Multimodal Impersonation Endpoints
# ==========================================

@app.post("/analyze/multimodal", response_model=MultimodalAnalysisResponse)
@app.post("/api/multimodal/analyze", response_model=MultimodalAnalysisResponse)
async def analyze_multimodal(
    file: Optional[UploadFile] = File(None),
    json_payload: Optional[MultimodalJsonPayload] = None
) -> MultimodalAnalysisResponse:
    file_bytes = b""
    filename = "unknown_file.png"
    content_type = None

    if file is not None:
        filename = file.filename or "uploaded_media"
        content_type = file.content_type
        file_bytes = await file.read()
    elif json_payload is not None:
        filename = json_payload.file_name
        content_type = json_payload.content_type
        try:
            file_bytes = base64.b64decode(json_payload.file_base64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 payload")
    else:
        raise HTTPException(status_code=400, detail="No file or base64 payload provided")

    metadata_dict, raw_indicators = detect_multimodal_threats(
        filename=filename,
        file_bytes=file_bytes,
        content_type=content_type
    )

    risk_score, severity = calculate_multimodal_risk(raw_indicators)

    explanation = generate_multimodal_explanation(
        indicators=raw_indicators,
        metadata=metadata_dict,
        risk_score=risk_score,
        severity=severity
    )

    recommendations = generate_multimodal_recommendations(
        indicators=raw_indicators,
        metadata=metadata_dict,
        severity=severity
    )

    indicators_models = [
        ForensicIndicator(
            indicator=ind.get("indicator", "Indicator"),
            category=ind.get("category", "METADATA"),
            details=ind.get("details", ""),
            severity_contribution=ind.get("severity_contribution", "INFO"),
            weight=ind.get("weight", 10)
        )
        for ind in raw_indicators
    ]

    metadata_model = MetadataSummary(
        file_name=metadata_dict.get("file_name", filename),
        file_size_bytes=metadata_dict.get("file_size_bytes", len(file_bytes)),
        mime_type=metadata_dict.get("mime_type", content_type or "application/octet-stream"),
        file_format=metadata_dict.get("file_format", "UNKNOWN"),
        dimensions=metadata_dict.get("dimensions"),
        creation_date=metadata_dict.get("creation_date"),
        software_tool=metadata_dict.get("software_tool"),
        has_exif=metadata_dict.get("has_exif", False),
        has_provenance=metadata_dict.get("has_provenance", False),
        raw_metadata_dump=metadata_dict.get("raw_metadata_dump", {})
    )

    try:
        incident_manager.record_multimodal_analysis(
            file_name=filename,
            risk_score=risk_score,
            risk_level=severity,
            explanation=explanation,
            evidence_items=[{"indicator": i.indicator, "details": i.details} for i in indicators_models],
            recommended_actions=recommendations,
            source_data={"file_name": filename, "file_size": len(file_bytes), "format": metadata_dict.get("file_format")}
        )
    except Exception:
        pass

    return MultimodalAnalysisResponse(
        threat_type="Multimedia Impersonation",
        risk_score=risk_score,
        severity=severity,
        metadata=metadata_model,
        indicators=indicators_models,
        explanation=explanation,
        manual_verification_recommendations=recommendations
    )


# ==========================================
# Phase 3: URL, Impersonation & Account Security Endpoints
# ==========================================

@app.post("/analyze/url", response_model=UrlAnalysisResponse)
@app.post("/api/url/analyze", response_model=UrlAnalysisResponse)
def analyze_url_endpoint(payload: Optional[UrlAnalysisRequest] = None) -> UrlAnalysisResponse:
    target_input = payload.get_effective_input() if payload else ""
    input_type_hint = payload.get_effective_type() if payload else "auto"

    telemetry = analyze_target_telemetry(target_input, input_type_hint)
    raw_indicators = telemetry["indicators"]
    input_type = telemetry["input_type"]

    risk_score, risk_level = calculate_url_risk_score(raw_indicators)
    explanation = generate_url_explanation(raw_indicators, risk_score, risk_level, target_input, input_type)
    recommended_actions = generate_url_recommended_actions(raw_indicators, risk_level, input_type)

    evidence = [
        UrlEvidenceItem(
            indicator=item.get("indicator", "Suspicious URL Pattern"),
            details=item.get("details", "")
        )
        for item in raw_indicators
    ]

    indicator_names = [item.get("indicator", "") for item in raw_indicators if item.get("indicator")]

    # Determine classification title
    if input_type == "ip":
        threat_type = "IP Security Analysis"
        classification = f"Passive IP Evaluation ({telemetry.get('ip_address') or 'IP'})"
    elif input_type == "domain":
        threat_type = "Domain Security Analysis"
        classification = f"Observable Domain Structure ({telemetry.get('domain') or 'Domain'})"
    else:
        threat_type = "URL Threat"
        classification = "Deceptive URL / Link Structure"

    if evidence and len(evidence) > 0:
        top_ind = evidence[0].indicator
        if top_ind:
            classification = f"{threat_type}: {top_ind}"

    # Build DomainDetails and IpDetails models if present
    domain_details_model = None
    if telemetry.get("domain_details"):
        domain_details_model = DomainDetails(**telemetry["domain_details"])

    ip_details_model = None
    if telemetry.get("ip_details"):
        ip_details_model = IpDetails(**telemetry["ip_details"])

    try:
        incident_manager.record_url_analysis(
            target_url=target_input,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            evidence_items=[{"indicator": ev.indicator, "details": ev.details} for ev in evidence],
            recommended_actions=recommended_actions,
            source_data={
                "target_url": target_input,
                "input_type": input_type,
                "input": target_input,
                "domain": telemetry.get("domain"),
                "subdomain": telemetry.get("subdomain"),
                "tld": telemetry.get("tld"),
                "ip_address": telemetry.get("ip_address")
            }
        )
    except Exception:
        pass

    return UrlAnalysisResponse(
        threat_type=threat_type,
        target_url=target_input,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=None,
        evidence=evidence,
        explanation=explanation,
        recommended_actions=recommended_actions,
        input=target_input,
        input_type=input_type,
        domain=telemetry.get("domain"),
        subdomain=telemetry.get("subdomain"),
        tld=telemetry.get("tld"),
        ip_address=telemetry.get("ip_address"),
        classification=classification,
        severity=risk_level,
        indicators=indicator_names,
        recommended_response=recommended_actions,
        domain_details=domain_details_model,
        ip_details=ip_details_model,
        reputation_status="Not configured (Analysis based on observable URL/domain characteristics)"
    )


@app.post("/analyze/impersonation", response_model=ImpersonationAnalysisResponse)
@app.post("/api/impersonation/analyze", response_model=ImpersonationAnalysisResponse)
def analyze_impersonation_endpoint(payload: Optional[ImpersonationAnalysisRequest] = None) -> ImpersonationAnalysisResponse:
    if payload is None:
        payload = ImpersonationAnalysisRequest()

    message_text = payload.get_effective_message()
    claimed_identity = payload.get_effective_claimed_identity()
    sender = payload.get_effective_sender()
    url = payload.url.strip() if (payload.url and isinstance(payload.url, str)) else None

    raw_indicators = detect_impersonation(
        message_text=message_text,
        claimed_identity=claimed_identity,
        sender=sender,
        url=url
    )

    risk_score, risk_level = calculate_impersonation_risk_score(raw_indicators)
    explanation = generate_impersonation_explanation(
        indicators=raw_indicators,
        risk_score=risk_score,
        risk_level=risk_level,
        claimed_identity=claimed_identity,
        sender=sender
    )
    recommended_actions = generate_impersonation_recommended_actions(raw_indicators, risk_level)

    evidence = [
        ImpersonationEvidenceItem(
            indicator=item.get("indicator", "Impersonation Pattern"),
            details=item.get("details", "")
        )
        for item in raw_indicators
    ]

    try:
        incident_manager.record_impersonation_analysis(
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            evidence_items=[{"indicator": ev.indicator, "details": ev.details} for ev in evidence],
            recommended_actions=recommended_actions,
            claimed_identity=claimed_identity,
            sender=sender,
            source_data={"message_text": message_text, "claimed_identity": claimed_identity, "sender": sender, "url": url}
        )
    except Exception:
        pass

    return ImpersonationAnalysisResponse(
        threat_type="Digital Impersonation",
        claimed_identity=claimed_identity if claimed_identity else None,
        sender=sender if sender else None,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=None,
        evidence=evidence,
        explanation=explanation,
        recommended_actions=recommended_actions
    )


@app.post("/analyze/account-security", response_model=AccountSecurityResponse)
@app.post("/api/account-security/analyze", response_model=AccountSecurityResponse)
def analyze_account_security_endpoint(payload: Optional[AccountSecurityRequest] = None) -> AccountSecurityResponse:
    if payload is None:
        payload = AccountSecurityRequest()

    username = payload.get_effective_username()
    location = payload.get_effective_location()
    device = payload.get_effective_device()
    failed_login_count = payload.failed_login_count or 0
    event_description = (payload.event_description or "").strip()
    ip_address = (payload.ip_address or "").strip()
    timestamp = (payload.timestamp or "").strip()
    previous_location = payload.previous_location
    previous_timestamp = payload.previous_timestamp
    failed_login_burst_count = payload.failed_login_burst_count or 0
    mfa_attempts = payload.mfa_attempts or 0
    active_concurrent_sessions = payload.active_concurrent_sessions or 1
    is_new_device = payload.is_new_device or False

    raw_indicators, behavioural_metrics_dict = detect_account_security_threats(
        username=username,
        login_location=location,
        device_info=device,
        failed_login_count=failed_login_count,
        event_description=event_description,
        ip_address=ip_address,
        timestamp=timestamp,
        previous_location=previous_location,
        previous_timestamp=previous_timestamp,
        failed_login_burst_count=failed_login_burst_count,
        mfa_attempts=mfa_attempts,
        active_concurrent_sessions=active_concurrent_sessions,
        is_new_device=is_new_device,
        return_metrics=True
    )

    risk_score, risk_level = calculate_account_security_risk_score(raw_indicators)
    explanation = generate_account_security_explanation(
        indicators=raw_indicators,
        risk_score=risk_score,
        risk_level=risk_level,
        username=username
    )
    recommended_actions = generate_account_security_recommended_actions(raw_indicators, risk_level)

    evidence = [
        AccountSecurityEvidenceItem(
            indicator=item.get("indicator", "Authentication Anomaly"),
            details=item.get("details", "")
        )
        for item in raw_indicators
    ]

    behavioural_metrics = BehaviouralAnomalyMetrics(
        velocity_kmh=behavioural_metrics_dict.get("velocity_kmh"),
        impossible_travel_flag=behavioural_metrics_dict.get("impossible_travel_flag", False),
        failed_burst_rate_flag=behavioural_metrics_dict.get("failed_burst_rate_flag", False),
        mfa_fatigue_flag=behavioural_metrics_dict.get("mfa_fatigue_flag", False),
        session_concurrency_flag=behavioural_metrics_dict.get("session_concurrency_flag", False),
        new_device_flag=behavioural_metrics_dict.get("new_device_flag", False)
    )

    try:
        incident_manager.record_account_security_analysis(
            username=username,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            evidence_items=[{"indicator": ev.indicator, "details": ev.details} for ev in evidence],
            recommended_actions=recommended_actions,
            source_data={
                "username": username,
                "login_location": location,
                "device_info": device,
                "failed_login_count": failed_login_count,
                "ip_address": ip_address,
                "event_description": event_description,
                "previous_location": previous_location,
                "previous_timestamp": previous_timestamp
            }
        )
    except Exception:
        pass

    return AccountSecurityResponse(
        threat_type="Account Takeover & Authentication Anomaly",
        username=username if username != "unknown_user" else None,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=None,
        evidence=evidence,
        behavioural_metrics=behavioural_metrics,
        explanation=explanation,
        recommended_actions=recommended_actions
    )


# ==========================================
# Incident Center, Correlations, MITRE & Playbooks
# ==========================================

@app.get("/incidents", response_model=IncidentListResponse)
@app.get("/api/incidents", response_model=IncidentListResponse)
def get_incidents(
    threat_type: Optional[str] = Query(None, description="Filter by threat category"),
    risk_level: Optional[str] = Query(None, description="Filter by risk rating"),
    status: Optional[str] = Query(None, description="Filter by triage status"),
    search: Optional[str] = Query(None, description="Search term"),
    sort_by: Optional[str] = Query("timestamp", description="Sort field"),
    order: Optional[str] = Query("desc", description="Sort order")
) -> IncidentListResponse:
    return incident_manager.get_all_incidents(
        threat_type=threat_type,
        risk_level=risk_level,
        status=status,
        search=search,
        sort_by=sort_by or "timestamp",
        order=order or "desc"
    )


@app.get("/incidents/{incident_id}", response_model=Incident)
@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident_details(incident_id: str) -> Incident:
    incident = incident_manager.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' was not found in the CYBERGUARD incident repository."
        )
    return incident


@app.patch("/incidents/{incident_id}/status", response_model=Incident)
@app.patch("/api/incidents/{incident_id}/status", response_model=Incident)
def update_incident_status_endpoint(
    incident_id: str,
    payload: IncidentStatusUpdateRequest
) -> Incident:
    updated_incident = incident_manager.update_incident_status(
        incident_id=incident_id,
        new_status=payload.status
    )
    if not updated_incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' was not found in the CYBERGUARD incident repository."
        )
    return updated_incident


# Phase 4: Correlation Endpoint
@app.get("/incidents/{incident_id}/correlate", response_model=IncidentCorrelationResponse)
@app.get("/api/incidents/{incident_id}/correlate", response_model=IncidentCorrelationResponse)
def correlate_incident_endpoint(incident_id: str) -> IncidentCorrelationResponse:
    target = incident_manager.get_incident_by_id(incident_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    all_incidents = incident_manager.get_all_incidents(limit=200).incidents
    raw_res = correlation_engine.correlate_incident(target, all_incidents)
    return IncidentCorrelationResponse(**raw_res)


# Phase 5: MITRE ATT&CK Mapping Endpoint
@app.get("/incidents/{incident_id}/mitre", response_model=List[MitreTechniqueMapping])
@app.get("/api/incidents/{incident_id}/mitre", response_model=List[MitreTechniqueMapping])
def get_incident_mitre_mapping(incident_id: str) -> List[MitreTechniqueMapping]:
    incident = incident_manager.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return map_mitre_techniques(incident.threat_type, incident.evidence, incident.source_data)


# Phase 6: Defensive Response Playbook Endpoint
@app.get("/incidents/{incident_id}/playbook", response_model=IncidentResponsePlaybook)
@app.get("/api/incidents/{incident_id}/playbook", response_model=IncidentResponsePlaybook)
def get_incident_playbook(incident_id: str) -> IncidentResponsePlaybook:
    incident = incident_manager.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return generate_playbook(incident.threat_type, incident.risk_level, incident.evidence)


def _collect_incident_evidence(incident: Incident) -> Dict[str, Any]:
    """Compiles structured evidence, indicators, MITRE techniques, and playbook recommendations for AI interpretation."""
    try:
        mitre_list = [m.model_dump() if hasattr(m, "model_dump") else m for m in map_mitre_techniques(incident.threat_type, incident.evidence, incident.source_data)]
    except Exception:
        mitre_list = []

    try:
        pb = generate_playbook(incident.threat_type, incident.risk_level, incident.evidence)
        playbook_recs = pb.actions if hasattr(pb, "actions") else (pb.get("actions") if isinstance(pb, dict) else [])
    except Exception:
        playbook_recs = []

    correlation_info = incident.correlation.model_dump() if incident.correlation and hasattr(incident.correlation, "model_dump") else (incident.correlation if isinstance(incident.correlation, dict) else None)

    ml_result = None
    if incident.source_data and isinstance(incident.source_data, dict):
        ml_result = incident.source_data.get("ml_result") or incident.source_data.get("ml_analysis")

    return {
        "incident_id": incident.incident_id,
        "threat_type": incident.threat_type,
        "classification": incident.classification,
        "risk_score": incident.risk_score,
        "risk_level": incident.risk_level,
        "indicators": [{"indicator": ev.indicator, "details": ev.details} for ev in incident.evidence],
        "explanation": incident.explanation,
        "recommended_actions": incident.recommended_actions,
        "source_data": incident.source_data,
        "ml_result": ml_result,
        "correlation results": correlation_info,
        "MITRE mapping": mitre_list,
        "playbook recommendations": playbook_recs,
        "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
        "timestamp": incident.timestamp
    }


# ==========================================
# Phase 7: AI Security Analyst Endpoints
# ==========================================

@app.post("/incidents/{incident_id}/ai-analysis", response_model=AiAnalysisResponse)
@app.post("/api/incidents/{incident_id}/ai-analysis", response_model=AiAnalysisResponse)
def get_incident_ai_analysis(incident_id: str) -> AiAnalysisResponse:
    incident = incident_manager.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' was not found in the CYBERGUARD incident repository."
        )
    evidence_bundle = _collect_incident_evidence(incident)
    analysis = analyze_incident(evidence_bundle)
    return AiAnalysisResponse(**analysis)


@app.post("/incidents/{incident_id}/ai-chat", response_model=AiChatResponse)
@app.post("/api/incidents/{incident_id}/ai-chat", response_model=AiChatResponse)
def ask_incident_ai_question(incident_id: str, payload: AiChatRequest) -> AiChatResponse:
    incident = incident_manager.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' was not found in the CYBERGUARD incident repository."
        )
    evidence_bundle = _collect_incident_evidence(incident)
    response = ask_incident_question(evidence_bundle, payload.question)
    return AiChatResponse(**response)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
