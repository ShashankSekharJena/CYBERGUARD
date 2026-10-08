"""
CYBERGUARD Cross-Threat Correlation Engine

Refactored to delegate to the canonical deterministic correlation service
(backend.services.incident_correlation) ensuring a single source of truth across all modules.
"""

from typing import List, Dict, Any, Optional, Set
try:
    from backend.models.incident import Incident
    from backend.services.incident_correlation import (
        correlate_incident_with_corpus,
        extract_incident_pivots,
        extract_shared_pivots,
        build_attack_chain,
        extract_domain_from_text
    )
except ImportError:
    from models.incident import Incident
    from services.incident_correlation import (
        correlate_incident_with_corpus,
        extract_incident_pivots,
        extract_shared_pivots,
        build_attack_chain,
        extract_domain_from_text
    )


class CorrelationEngine:
    """
    Evidence-grounded cross-threat event correlation engine.
    Delegates directly to canonical incident_correlation service.
    """

    def _extract_domain(self, url_or_email: Optional[str]) -> Optional[str]:
        return extract_domain_from_text(url_or_email)

    def _extract_pivots(self, incident: Incident) -> Dict[str, Set[str]]:
        return extract_incident_pivots(incident)

    def correlate_incident(
        self,
        target_incident: Incident,
        incident_corpus: List[Incident]
    ) -> Dict[str, Any]:
        """
        Executes canonical correlation against incident corpus and constructs attack chain.
        """
        return correlate_incident_with_corpus(
            target_incident=target_incident,
            incident_corpus=incident_corpus
        )


correlation_engine = CorrelationEngine()

