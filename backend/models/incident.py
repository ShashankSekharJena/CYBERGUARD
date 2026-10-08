"""
CYBERGUARD Incident Data Models

Defines structured schemas for centralized incident management across
all detection engines: Phishing, URL Threats, Digital Impersonation, and Account Security.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentEvidenceItem(BaseModel):
    indicator: str = Field(..., description="Short title of the detected technical indicator")
    details: str = Field(..., description="Contextual technical detail and threat explanation")


class IncidentCorrelationInfo(BaseModel):
    related: bool = Field(default=False, description="Whether related incidents were detected above similarity threshold")
    correlation_score: int = Field(default=0, ge=0, le=100, description="Highest similarity score (0-100) among related incidents")
    matched_signals: List[str] = Field(default_factory=list, description="List of matched correlation signals (e.g. same_threat_type, same_domain)")
    related_incident_ids: List[str] = Field(default_factory=list, description="IDs of potentially related incidents")
    reason: str = Field(
        default="No significant relationship found with previous recorded incidents based on observable telemetry.",
        description="Explainable synthesis of relationship findings"
    )
    relationships: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Detailed breakdown of individual incident similarity links"
    )


class RelatedIncidentItem(BaseModel):
    incident_id: str = Field(..., description="Related incident identifier")
    threat_type: str = Field(default="Unknown", description="Threat category of the related incident")
    correlation_score: int = Field(..., ge=0, le=100, description="Deterministic similarity score (0-100)")
    matched_signals: List[str] = Field(default_factory=list, description="Specific telemetry signals matched")
    timestamp: Optional[str] = Field(default=None, description="Event creation timestamp in ISO 8601 format")
    reason: Optional[str] = Field(default=None, description="Pairwise similarity rationale")


class IncidentCorrelationResponse(BaseModel):
    incident_id: str = Field(..., description="Target incident identifier")
    correlation: IncidentCorrelationInfo = Field(..., description="Correlation summary metrics and signals")
    related_incidents: List[RelatedIncidentItem] = Field(default_factory=list, description="Detailed list of related incidents")
    pivots: Optional[List[Dict[str, Any]]] = Field(default=None, description="Shared entity pivots")
    attack_chain: Optional[List[Dict[str, Any]]] = Field(default=None, description="Chronological progression of potentially related activity")

    # Backward compatibility aliases:
    target_incident_id: Optional[str] = Field(default=None, description="Target incident ID alias")
    has_correlations: Optional[bool] = Field(default=None, description="Boolean flag alias")
    shared_entities: Optional[List[Dict[str, Any]]] = Field(default=None, description="Pivots alias")
    correlation_explanation: Optional[str] = Field(default=None, description="Correlation explanation alias")


class Incident(BaseModel):
    incident_id: str = Field(..., description="Unique incident identifier, e.g. INC-2026-0001")
    threat_type: str = Field(..., description="Threat category: Phishing, URL Threat, Digital Impersonation, Account Security, Multimedia Impersonation")
    classification: str = Field(..., description="Specific threat classification summary")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    risk_level: str = Field(..., description="Risk rating: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    evidence: List[IncidentEvidenceItem] = Field(default_factory=list, description="List of detected evidence indicators")
    explanation: str = Field(..., description="Human-readable synthesis explaining findings and heuristic limitations")
    recommended_actions: List[str] = Field(default_factory=list, description="Tailored defensive response recommendations")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Event creation timestamp in ISO 8601 format"
    )
    status: IncidentStatus = Field(default=IncidentStatus.NEW, description="Current triage status of the incident")
    source_data: Optional[Dict[str, Any]] = Field(default=None, description="Contextual input telemetry (e.g. sender, target URL, username)")
    correlation: Optional[IncidentCorrelationInfo] = Field(
        default=None,
        description="Deterministic similarity correlation against previous incidents"
    )


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatus = Field(..., description="New triage status for the incident")


class IncidentListResponse(BaseModel):
    total: int = Field(..., description="Total count of incidents matching current filters")
    incidents: List[Incident] = Field(default_factory=list, description="List of matching incidents")
    critical_count: int = Field(default=0, description="Number of CRITICAL risk incidents in store")
    high_count: int = Field(default=0, description="Number of HIGH risk incidents in store")
    medium_count: int = Field(default=0, description="Number of MEDIUM risk incidents in store")
    low_count: int = Field(default=0, description="Number of LOW risk incidents in store")
    safe_count: int = Field(default=0, description="Number of SAFE risk incidents in store")
    resolved_count: int = Field(default=0, description="Number of RESOLVED incidents in store")
    new_count: int = Field(default=0, description="Number of NEW incidents in store")
    investigating_count: int = Field(default=0, description="Number of INVESTIGATING incidents in store")
    false_positive_count: int = Field(default=0, description="Number of FALSE_POSITIVE incidents in store")
    phishing_count: int = Field(default=0, description="Number of Phishing incidents in store")
    url_threat_count: int = Field(default=0, description="Number of URL Threat incidents in store")
    impersonation_count: int = Field(default=0, description="Number of Digital Impersonation incidents in store")
    account_security_count: int = Field(default=0, description="Number of Account Security incidents in store")
    linked_count: int = Field(default=0, description="Number of incidents with related activity")
    total_analyzed_count: int = Field(default=0, description="Total telemetry analysis runs executed")


class AiAnalysisResponse(BaseModel):
    summary: str = Field(..., description="Executive summary of the incident")
    why_it_matters: str = Field(..., description="Operational and threat impact explanation")
    key_evidence: List[str] = Field(default_factory=list, description="Extracted key technical indicators")
    investigation_steps: List[str] = Field(default_factory=list, description="Prioritized investigation steps")
    recommended_actions: List[str] = Field(default_factory=list, description="Tailored defensive response recommendations")
    limitations: str = Field(..., description="Scope and heuristic boundaries")
    status: str = Field(default="ai", description="'ai' if live model, 'fallback' if heuristic fallback")
    is_fallback: bool = Field(default=False, description="Whether fallback mode was used")


class AiChatRequest(BaseModel):
    question: str = Field(..., description="Analyst question regarding the selected incident")


class AiChatResponse(BaseModel):
    answer: str = Field(..., description="Evidence-grounded response to analyst question")
    status: str = Field(default="ai", description="'ai' if live model, 'fallback' if heuristic fallback")
    is_fallback: bool = Field(default=False, description="Whether fallback mode was used")

