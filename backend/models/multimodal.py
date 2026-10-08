"""
CYBERGUARD Multimodal Impersonation Data Models

Defines structured schemas for multimedia forensic analysis, metadata inspection,
explainable indicators, and defensive verification recommendations.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ForensicIndicator(BaseModel):
    indicator: str = Field(..., description="Short title of the detected forensic or metadata indicator")
    category: str = Field(..., description="Category: METADATA, SOFTWARE_SIGNATURE, COMPRESSION, PROVENANCE, INTEGRITY")
    details: str = Field(..., description="Detailed technical explanation of what was extracted or observed")
    severity_contribution: str = Field(default="INFO", description="INFO, LOW, MEDIUM, HIGH")
    weight: int = Field(default=10, ge=0, le=100, description="Heuristic score contribution")


class MetadataSummary(BaseModel):
    file_name: str = Field(..., description="Uploaded file name")
    file_size_bytes: int = Field(..., description="File size in bytes")
    mime_type: str = Field(..., description="Detected MIME type")
    file_format: str = Field(..., description="Extracted file format (JPEG, PNG, WEBP, MP4, etc.)")
    dimensions: Optional[str] = Field(default=None, description="Image/Video dimensions, e.g. '1920x1080'")
    creation_date: Optional[str] = Field(default=None, description="Extracted creation timestamp if available in EXIF/header")
    software_tool: Optional[str] = Field(default=None, description="Editing/Generation software tag detected in metadata")
    has_exif: bool = Field(default=False, description="Whether EXIF metadata structure was present")
    has_provenance: bool = Field(default=False, description="Whether C2PA / Content Credentials provenance was detected")
    raw_metadata_dump: Dict[str, Any] = Field(default_factory=dict, description="Key-value dictionary of extracted metadata headers")


class MultimodalAnalysisResponse(BaseModel):
    threat_type: str = Field(default="Multimedia Impersonation", description="Classified threat category")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    severity: str = Field(..., description="Risk severity rating: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    metadata: MetadataSummary = Field(..., description="Extracted technical metadata and header properties")
    indicators: List[ForensicIndicator] = Field(default_factory=list, description="Forensic and metadata anomaly indicators")
    explanation: str = Field(..., description="Explainable synthesis of findings with explicit prototype boundaries")
    manual_verification_recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable verification procedures for human analysts"
    )
    prototype_disclaimer: str = Field(
        default="DISCLAIMER: This is a prototype forensic & metadata analysis tool. Metadata and compression indicators assist human inspection but do NOT constitute definitive proof of synthetic media or deepfakes.",
        description="Mandatory transparency notice"
    )
