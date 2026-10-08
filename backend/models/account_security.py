from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AccountSecurityRequest(BaseModel):
    username: Optional[str] = Field(
        default=None,
        description="Target user account identifier or email"
    )
    login_location: Optional[str] = Field(
        default=None,
        description="Reported geographic location or city/country"
    )
    device_info: Optional[str] = Field(
        default=None,
        description="Device information, OS, or Browser User-Agent"
    )
    failed_login_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Number of consecutive failed login attempts"
    )
    event_description: Optional[str] = Field(
        default=None,
        description="Summary description of the authentication event or log anomaly"
    )
    ip_address: Optional[str] = Field(
        default=None,
        description="Origin client IP address"
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="Event timestamp (ISO 8601 or standard string)"
    )
    # Behavioural anomaly enhancement parameters
    previous_location: Optional[str] = Field(
        default=None,
        description="Geographic location of the previous successful login"
    )
    previous_timestamp: Optional[str] = Field(
        default=None,
        description="Timestamp of the previous login event"
    )
    failed_login_burst_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Number of failed logins observed in a rapid burst window (< 5 min)"
    )
    mfa_attempts: Optional[int] = Field(
        default=0,
        ge=0,
        description="Number of consecutive MFA push / OTP requests generated"
    )
    active_concurrent_sessions: Optional[int] = Field(
        default=1,
        ge=0,
        description="Number of simultaneous active sessions across distinct locations"
    )
    is_new_device: Optional[bool] = Field(
        default=False,
        description="Whether device fingerprint is unseen in user profile history"
    )

    # Backwards-compatible alias fields
    user_agent: Optional[str] = Field(
        default=None,
        description="Alternative field for device_info"
    )
    location: Optional[str] = Field(
        default=None,
        description="Alternative field for login_location"
    )

    def get_effective_username(self) -> str:
        return (self.username or "unknown_user").strip()

    def get_effective_location(self) -> str:
        if self.login_location and self.login_location.strip():
            return self.login_location.strip()
        if self.location and self.location.strip():
            return self.location.strip()
        return ""

    def get_effective_device(self) -> str:
        if self.device_info and self.device_info.strip():
            return self.device_info.strip()
        if self.user_agent and self.user_agent.strip():
            return self.user_agent.strip()
        return ""


class AccountSecurityEvidenceItem(BaseModel):
    indicator: str = Field(..., description="Short title of the detected technical/authentication anomaly")
    details: str = Field(..., description="Contextual technical detail and threat explanation")


class BehaviouralAnomalyMetrics(BaseModel):
    velocity_kmh: Optional[float] = Field(default=None, description="Calculated travel velocity between consecutive logins")
    impossible_travel_flag: bool = Field(default=False, description="True if travel speed exceeds physical feasibility (>800 km/h)")
    failed_burst_rate_flag: bool = Field(default=False, description="True if rapid failed login rate is triggered")
    mfa_fatigue_flag: bool = Field(default=False, description="True if MFA push spam / fatigue pattern is detected")
    session_concurrency_flag: bool = Field(default=False, description="True if multiple simultaneous distinct geolocations exist")
    new_device_flag: bool = Field(default=False, description="True if device is unrecognized")


class AccountSecurityResponse(BaseModel):
    threat_type: str = Field(default="Account Takeover & Authentication Anomaly", description="Threat classification category")
    username: Optional[str] = Field(default=None, description="Analyzed user account")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    risk_level: str = Field(..., description="Risk level: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[float] = Field(
        default=None,
        description="Confidence score (null until validated ML anomaly model is trained on labeled telemetry)"
    )
    evidence: List[AccountSecurityEvidenceItem] = Field(
        default_factory=list,
        description="List of detected heuristic evidence items"
    )
    behavioural_metrics: Optional[BehaviouralAnomalyMetrics] = Field(
        default=None,
        description="Structured behavioural telemetry and speed calculations"
    )
    explanation: str = Field(..., description="Human-readable synthesis explaining findings and limitations")
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Actionable response and mitigation recommendations"
    )
