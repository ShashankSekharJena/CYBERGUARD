from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class UrlAnalysisRequest(BaseModel):
    url: Optional[str] = Field(default=None, description="Target URL string to analyze for threats")
    input: Optional[str] = Field(default=None, description="Target input string (URL, domain, or IP)")
    input_type: Optional[str] = Field(default="auto", description="Input type hint: auto, url, domain, ip")

    def get_effective_input(self) -> str:
        """Returns the primary target input string safely."""
        if self.input is not None and isinstance(self.input, str) and self.input.strip():
            return self.input.strip()
        if self.url is not None and isinstance(self.url, str) and self.url.strip():
            return self.url.strip()
        return ""

    def get_effective_type(self) -> str:
        """Returns normalized input type mode."""
        hint = (self.input_type or "auto").strip().lower()
        if hint in ["url", "domain", "ip"]:
            return hint
        return "auto"


class UrlEvidenceItem(BaseModel):
    indicator: str = Field(..., description="Short title of detected suspicious pattern")
    details: str = Field(..., description="Contextual technical detail and explanation")


class DomainDetails(BaseModel):
    domain: Optional[str] = Field(default=None, description="Registrable domain name (e.g. example.com)")
    subdomain: Optional[str] = Field(default=None, description="Subdomain prefix (e.g. login, secure)")
    tld: Optional[str] = Field(default=None, description="Top-level domain (e.g. .com, .xyz, .co.uk)")
    hostname: Optional[str] = Field(default=None, description="Full hostname")
    domain_length: Optional[int] = Field(default=None, description="Character length of domain")
    subdomain_count: int = Field(default=0, description="Number of subdomain levels")
    is_punycode: bool = Field(default=False, description="Whether domain uses punycode / IDN encoding")
    is_ip_hostname: bool = Field(default=False, description="Whether hostname is a direct IP address")
    has_suspicious_keywords: bool = Field(default=False, description="Whether suspicious security keywords are present in domain")
    has_suspicious_tld: bool = Field(default=False, description="Whether TLD is in high-abuse set")
    has_suspicious_patterns: bool = Field(default=False, description="Whether excessive hyphens or suspicious character patterns exist")
    is_valid: bool = Field(default=True, description="Whether domain syntax is valid")


class IpDetails(BaseModel):
    ip_address: Optional[str] = Field(default=None, description="Parsed IP address")
    version: Optional[str] = Field(default=None, description="IP version: IPv4 or IPv6")
    is_private: bool = Field(default=False, description="Whether IP is RFC1918 / private / loopback / link-local")
    is_global: bool = Field(default=False, description="Whether IP is globally routable / public")
    is_valid: bool = Field(default=True, description="Whether IP address is syntactically valid")
    is_direct_host: bool = Field(default=False, description="Whether IP is used directly instead of a domain name")


class UrlAnalysisResponse(BaseModel):
    # Core existing fields (maintained for 100% backward compatibility)
    threat_type: str = Field(default="URL Threat", description="Threat category classification")
    target_url: str = Field(..., description="The analyzed URL or normalized target")
    risk_score: int = Field(..., ge=0, le=100, description="Heuristic risk score from 0 to 100")
    risk_level: str = Field(..., description="Risk level: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[float] = Field(
        default=None,
        description="Confidence score (null until a validated ML model is integrated)"
    )
    evidence: List[UrlEvidenceItem] = Field(
        default_factory=list,
        description="List of detected heuristic evidence items"
    )
    explanation: str = Field(..., description="Human-readable synthesis explaining findings and limitations")
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Actionable safety recommendations"
    )

    # Extended structured fields
    input: Optional[str] = Field(default=None, description="Submitted user input string")
    input_type: Optional[str] = Field(default="url", description="Detected or requested input type: url, domain, ip")
    domain: Optional[str] = Field(default=None, description="Extracted registrable domain")
    subdomain: Optional[str] = Field(default=None, description="Extracted subdomain")
    tld: Optional[str] = Field(default=None, description="Extracted top-level domain")
    ip_address: Optional[str] = Field(default=None, description="Extracted or submitted IP address")
    classification: Optional[str] = Field(default=None, description="Heuristic classification title")
    severity: Optional[str] = Field(default=None, description="Severity rating alias for risk_level")
    indicators: List[str] = Field(default_factory=list, description="List of detected indicator names")
    recommended_response: List[str] = Field(default_factory=list, description="Actionable response list alias")
    domain_details: Optional[DomainDetails] = Field(default=None, description="Technical domain attributes")
    ip_details: Optional[IpDetails] = Field(default=None, description="Technical IP attributes")
    reputation_status: str = Field(
        default="Not configured (Analysis based on observable URL/domain characteristics)",
        description="Threat intelligence provider status"
    )
