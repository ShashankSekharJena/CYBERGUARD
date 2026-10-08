"""CYBERGUARD Detection Modules Package"""

try:
    from backend.detectors.phishing_detector import detect_phishing
    from backend.detectors.url_detector import detect_url_threats
    from backend.detectors.impersonation_detector import detect_impersonation
    from backend.detectors.account_security_detector import detect_account_security_threats
except ImportError:
    from detectors.phishing_detector import detect_phishing
    from detectors.url_detector import detect_url_threats
    from detectors.impersonation_detector import detect_impersonation
    from detectors.account_security_detector import detect_account_security_threats

__all__ = [
    "detect_phishing",
    "detect_url_threats",
    "detect_impersonation",
    "detect_account_security_threats",
]
