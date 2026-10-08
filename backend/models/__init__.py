"""CYBERGUARD Data Models Package"""

try:
    from backend.models.phishing import (
        PhishingAnalysisRequest,
        PhishingAnalysisResponse,
        EvidenceItem
    )
    from backend.models.url import (
        UrlAnalysisRequest,
        UrlAnalysisResponse,
        UrlEvidenceItem
    )
    from backend.models.impersonation import (
        ImpersonationAnalysisRequest,
        ImpersonationAnalysisResponse,
        ImpersonationEvidenceItem
    )
    from backend.models.account_security import (
        AccountSecurityRequest,
        AccountSecurityResponse,
        AccountSecurityEvidenceItem
    )
    from backend.models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentStatusUpdateRequest,
        IncidentListResponse,
        AiAnalysisResponse,
        AiChatRequest,
        AiChatResponse
    )
except ImportError:
    from models.phishing import (
        PhishingAnalysisRequest,
        PhishingAnalysisResponse,
        EvidenceItem
    )
    from models.url import (
        UrlAnalysisRequest,
        UrlAnalysisResponse,
        UrlEvidenceItem
    )
    from models.impersonation import (
        ImpersonationAnalysisRequest,
        ImpersonationAnalysisResponse,
        ImpersonationEvidenceItem
    )
    from models.account_security import (
        AccountSecurityRequest,
        AccountSecurityResponse,
        AccountSecurityEvidenceItem
    )
    from models.incident import (
        Incident,
        IncidentStatus,
        IncidentEvidenceItem,
        IncidentStatusUpdateRequest,
        IncidentListResponse,
        AiAnalysisResponse,
        AiChatRequest,
        AiChatResponse
    )

__all__ = [
    "PhishingAnalysisRequest",
    "PhishingAnalysisResponse",
    "EvidenceItem",
    "UrlAnalysisRequest",
    "UrlAnalysisResponse",
    "UrlEvidenceItem",
    "ImpersonationAnalysisRequest",
    "ImpersonationAnalysisResponse",
    "ImpersonationEvidenceItem",
    "AccountSecurityRequest",
    "AccountSecurityResponse",
    "AccountSecurityEvidenceItem",
    "Incident",
    "IncidentStatus",
    "IncidentEvidenceItem",
    "IncidentStatusUpdateRequest",
    "IncidentListResponse",
    "AiAnalysisResponse",
    "AiChatRequest",
    "AiChatResponse",
]
