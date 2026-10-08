from typing import List, Optional
from pydantic import BaseModel, Field


class ImpersonationAnalysisRequest(BaseModel):
    message_text: Optional[str] = Field(
        default=None,
        description="Message content or communication text to inspect"
    )
    claimed_identity: Optional[str] = Field(
        default=None,
        description="Claimed person, executive title, organization, or brand name"
    )
    sender: Optional[str] = Field(
        default=None,
        description="Sender email address, phone number, or handle"
    )
    url: Optional[str] = Field(
        default=None,
        description="Optional URL or domain provided in the communication"
    )
    # Backward compatibility fields
    target_name: Optional[str] = Field(
        default=None,
        description="Alternative field for claimed identity / organization"
    )
    handle: Optional[str] = Field(
        default=None,
        description="Alternative field for sender handle / address"
    )
    platform: Optional[str] = Field(
        default=None,
        description="Platform or communication surface"
    )

    def get_effective_message(self) -> str:
        """Returns normalized message text."""
        if self.message_text and isinstance(self.message_text, str) and self.message_text.strip():
            return self.message_text.strip()
        return ""

    def get_effective_claimed_identity(self) -> str:
        """Returns effective claimed identity taking claimed_identity or target_name."""
        if self.claimed_identity and isinstance(self.claimed_identity, str) and self.claimed_identity.strip():
            return self.claimed_identity.strip()
        if self.target_name and isinstance(self.target_name, str) and self.target_name.strip():
            return self.target_name.strip()
        return ""

    def get_effective_sender(self) -> str:
        """Returns effective sender identifier."""
        if self.sender and isinstance(self.sender, str) and self.sender.strip():
            return self.sender.strip()
        if self.handle and isinstance(self.handle, str) and self.handle.strip():
            return self.handle.strip()
        return ""

    def get_effective_url(self) -> str:
        """Returns normalized URL string."""
        if self.url and isinstance(self.url, str) and self.url.strip():
            return self.url.strip()
        return ""


class ImpersonationEvidenceItem(BaseModel):
    indicator: str = Field(..., description="Short title of the identified impersonation pattern")
    details: str = Field(..., description="Contextual technical detail and threat explanation")


class ImpersonationAnalysisResponse(BaseModel):
    threat_type: str = Field(default="Digital Impersonation", description="Threat classification category")
    claimed_identity: Optional[str] = Field(default=None, description="Analyzed claimed entity")
    sender: Optional[str] = Field(default=None, description="Analyzed sender identifier")
    url: Optional[str] = Field(default=None, description="Analyzed communication URL")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    risk_level: str = Field(..., description="Risk level: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[float] = Field(
        default=None,
        description="Confidence score (null until validated ML model is integrated)"
    )
    evidence: List[ImpersonationEvidenceItem] = Field(
        default_factory=list,
        description="List of detected evidence items"
    )
    explanation: str = Field(..., description="Human-readable synthesis explaining findings and limitations")
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Actionable precautions for the recipient or organization"
    )
