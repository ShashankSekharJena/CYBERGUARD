"""CYBERGUARD Engines Package"""

try:
    from backend.engines.risk_engine import calculate_risk_score, CATEGORY_CAPS, SEVERITY_LEVELS
    from backend.engines.explanation_engine import generate_explanation, explain_indicator
    from backend.engines.response_engine import generate_recommended_actions
    from backend.engines.url_risk_engine import calculate_url_risk_score, URL_CATEGORY_CAPS, URL_RISK_LEVELS
    from backend.engines.url_explanation_engine import generate_url_explanation, explain_url_indicator
    from backend.engines.url_response_engine import generate_url_recommended_actions
    from backend.engines.impersonation_risk_engine import calculate_impersonation_risk_score, IMPERSONATION_CATEGORY_CAPS, IMPERSONATION_RISK_LEVELS
    from backend.engines.impersonation_explanation_engine import generate_impersonation_explanation, explain_impersonation_indicator
    from backend.engines.impersonation_response_engine import generate_impersonation_recommended_actions
    from backend.engines.account_security_risk_engine import calculate_account_security_risk_score, ACCOUNT_SECURITY_CATEGORY_CAPS, ACCOUNT_SECURITY_RISK_LEVELS
    from backend.engines.account_security_explanation_engine import generate_account_security_explanation, explain_account_security_indicator
    from backend.engines.account_security_response_engine import generate_account_security_recommended_actions
    from backend.engines.incident_manager import incident_manager, IncidentManager
except ImportError:
    from engines.risk_engine import calculate_risk_score, CATEGORY_CAPS, SEVERITY_LEVELS
    from engines.explanation_engine import generate_explanation, explain_indicator
    from engines.response_engine import generate_recommended_actions
    from engines.url_risk_engine import calculate_url_risk_score, URL_CATEGORY_CAPS, URL_RISK_LEVELS
    from engines.url_explanation_engine import generate_url_explanation, explain_url_indicator
    from engines.url_response_engine import generate_url_recommended_actions
    from engines.impersonation_risk_engine import calculate_impersonation_risk_score, IMPERSONATION_CATEGORY_CAPS, IMPERSONATION_RISK_LEVELS
    from engines.impersonation_explanation_engine import generate_impersonation_explanation, explain_impersonation_indicator
    from engines.impersonation_response_engine import generate_impersonation_recommended_actions
    from engines.account_security_risk_engine import calculate_account_security_risk_score, ACCOUNT_SECURITY_CATEGORY_CAPS, ACCOUNT_SECURITY_RISK_LEVELS
    from engines.account_security_explanation_engine import generate_account_security_explanation, explain_account_security_indicator
    from engines.account_security_response_engine import generate_account_security_recommended_actions
    from engines.incident_manager import incident_manager, IncidentManager

__all__ = [
    "calculate_risk_score",
    "CATEGORY_CAPS",
    "SEVERITY_LEVELS",
    "generate_explanation",
    "explain_indicator",
    "generate_recommended_actions",
    "calculate_url_risk_score",
    "URL_CATEGORY_CAPS",
    "URL_RISK_LEVELS",
    "generate_url_explanation",
    "explain_url_indicator",
    "generate_url_recommended_actions",
    "calculate_impersonation_risk_score",
    "IMPERSONATION_CATEGORY_CAPS",
    "IMPERSONATION_RISK_LEVELS",
    "generate_impersonation_explanation",
    "explain_impersonation_indicator",
    "generate_impersonation_recommended_actions",
    "calculate_account_security_risk_score",
    "ACCOUNT_SECURITY_CATEGORY_CAPS",
    "ACCOUNT_SECURITY_RISK_LEVELS",
    "generate_account_security_explanation",
    "explain_account_security_indicator",
    "generate_account_security_recommended_actions",
    "incident_manager",
    "IncidentManager",
]
