from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PhishingAnalysisRequest(BaseModel):
    message_text: Optional[str] = Field(
        default=None,
        description="Email or message text content to analyze"
    )
    url: Optional[str] = Field(
        default=None,
        description="Optional suspicious URL to analyze"
    )
    # Backward compatibility / optional alias fields
    content: Optional[str] = Field(
        default=None,
        description="Alternative field for message text content"
    )
    sender: Optional[str] = Field(
        default=None,
        description="Optional sender email or identifier"
    )

    def get_effective_text(self) -> str:
        """Returns normalized message text taking message_text or content."""
        if self.message_text is not None and self.message_text.strip():
            return self.message_text.strip()
        if self.content is not None and self.content.strip():
            return self.content.strip()
        return ""


class EvidenceItem(BaseModel):
    indicator: str = Field(..., description="Short title of the identified suspicious indicator")
    details: str = Field(..., description="Contextual explanation of what was detected")


class MLFeatureContribution(BaseModel):
    term: str = Field(..., description="N-gram term extracted from text")
    weight: float = Field(..., description="Model coefficient weight")
    impact: float = Field(..., description="Attribution impact (TF-IDF * weight)")
    direction: str = Field(..., description="'phishing' or 'legitimate'")


class MLPredictionDetails(BaseModel):
    available: bool = Field(default=False, description="Whether ML model was evaluated")
    prediction_label: str = Field(default="UNKNOWN", description="PHISHING, LEGITIMATE, or UNKNOWN")
    is_phishing: bool = Field(default=False, description="Binary classification result")
    phishing_probability: float = Field(default=0.0, description="Genuine ML phishing probability (0.0 - 1.0)")
    confidence: float = Field(default=0.0, description="True model confidence score (0.0 - 1.0)")
    top_features: List[MLFeatureContribution] = Field(default_factory=list, description="Top active TF-IDF feature drivers")
    explanation: str = Field(default="", description="Human-readable synthesis of ML classification")


class MLAnalysisSummary(BaseModel):
    model: str = Field(default="TF-IDF + Logistic Regression", description="ML algorithm / pipeline name")
    prediction: str = Field(default="legitimate", description="Prediction outcome ('phishing' or 'legitimate')")
    confidence: float = Field(default=0.0, description="Model confidence score (0.0 - 1.0)")
    probability: float = Field(default=0.0, description="Prediction class probability")
    phishing_probability: Optional[float] = Field(default=0.0, description="Probability of phishing class")


class PhishingAnalysisResponse(BaseModel):
    threat_type: str = Field(default="Phishing", description="Classified threat category")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated heuristic risk score from 0 to 100")
    severity: str = Field(..., description="Severity level: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[float] = Field(
        default=None,
        description="Genuine ML Confidence score derived from TF-IDF + Logistic Regression predictor"
    )
    evidence: List[EvidenceItem] = Field(
        default_factory=list,
        description="List of detected heuristic evidence indicators and descriptions"
    )
    explanation: str = Field(..., description="Human-readable synthesis of the findings and threat context")
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Actionable security recommendations for the recipient or analyst"
    )
    ml_analysis: Optional[MLAnalysisSummary] = Field(
        default=None,
        description="Standardized machine learning prediction summary"
    )
    ml_details: Optional[MLPredictionDetails] = Field(
        default=None,
        description="Detailed ML prediction, probabilities, and feature attributions"
    )
    detection_source: str = Field(
        default="hybrid",
        description="Detection method used: hybrid (ML + heuristic), ml, or heuristic_fallback"
    )
