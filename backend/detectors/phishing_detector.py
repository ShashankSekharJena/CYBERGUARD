"""
CYBERGUARD Phishing Detection Module

Modular heuristic detection functions for:
1. Text Analysis (Urgency, Threats, Credential solicitation, OTP requests, CTAs, Account verification)
2. URL Analysis (IP addresses, Deceptive @ syntax, Suspicious schemes, Excessive length, Structure, Look-alikes)
3. Domain Analysis (Claimed organization vs. target destination mismatch)

NOTE: All detections are heuristic indicators to aid human analysts and scoring algorithms.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any

# Known legitimate brand domains for mismatch and lookalike analysis
KNOWN_ORGANIZATIONS = {
    "paypal": {
        "names": ["paypal", "pay pal"],
        "domains": ["paypal.com", "paypal.me"]
    },
    "microsoft": {
        "names": ["microsoft", "office365", "office 365", "outlook", "onedrive", "azure", "windows"],
        "domains": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com"]
    },
    "google": {
        "names": ["google", "gmail", "google drive", "google cloud", "workspace"],
        "domains": ["google.com", "gmail.com", "googleblog.com", "youtube.com"]
    },
    "apple": {
        "names": ["apple", "icloud", "apple id", "itunes", "app store"],
        "domains": ["apple.com", "icloud.com"]
    },
    "amazon": {
        "names": ["amazon", "amazon prime", "aws"],
        "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com"]
    },
    "netflix": {
        "names": ["netflix"],
        "domains": ["netflix.com"]
    },
    "chase": {
        "names": ["chase", "chase bank", "jpmorgan"],
        "domains": ["chase.com", "jpmorgan.com"]
    },
    "wells fargo": {
        "names": ["wells fargo", "wellsfargo"],
        "domains": ["wellsfargo.com"]
    },
    "bank of america": {
        "names": ["bank of america", "bofa"],
        "domains": ["bankofamerica.com", "bofa.com"]
    },
    "binance": {
        "names": ["binance"],
        "domains": ["binance.com", "binance.us"]
    }
}

# Common homoglyph substitutions used in phishing domains
HOMOGLYPH_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "@": "a",
    "vv": "w",
    "rn": "m"
}

# Top-level domains frequently associated with automated abuse/disposable campaigns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work",
    ".click", ".rest", ".fit", ".casa", ".monster", ".sbs", ".cam"
}


def analyze_text(text: Optional[str]) -> List[Dict[str, Any]]:
    """
    Analyzes message text for psychological triggers, credential solicitation,
    urgency, threats, OTP requests, calls to action, and account verification.
    """
    indicators: List[Dict[str, Any]] = []
    if not text or not isinstance(text, str) or not text.strip():
        return indicators

    normalized_text = text.lower()

    # 1. Urgent Language
    urgent_patterns = [
        (r"\b(immediately|urgent(ly)?|asap|without delay|right now|within\s+\d+\s*(hours?|mins?|minutes?))\b",
         "Urgent language detected conveying high artificial time pressure."),
        (r"\b(act now|time[\s-]sensitive|limited time|critical deadline|final notice)\b",
         "Artificial deadline pressure detected to induce hasty action.")
    ]
    urgent_matched = False
    for pattern, explanation in urgent_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not urgent_matched:
            indicators.append({
                "category": "urgency",
                "indicator": "Urgent language",
                "details": explanation,
                "weight": 15
            })
            urgent_matched = True

    # 2. Threatening Language
    threat_patterns = [
        (r"\b(account\s+(will\s+be\s+)?(blocked|suspended|terminated|disabled|frozen|locked|deleted|closed))\b",
         "Threat of account suspension or lockout detected."),
        (r"\b(legal\s+action|law\s+enforcement|unauthorized\s+(activity|access|login)|security\s+breach|penalty)\b",
         "Threatening reference to legal action or security penalty detected.")
    ]
    threat_matched = False
    for pattern, explanation in threat_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not threat_matched:
            indicators.append({
                "category": "threat",
                "indicator": "Threatening language",
                "details": explanation,
                "weight": 18
            })
            threat_matched = True

    # 3. Credential Requests
    cred_patterns = [
        (r"\b((verify|confirm|validate|update|submit|enter|provide)\s+(your\s+)?(password|passcode|pin|security\s+pin|login\s+credentials|secret))\b",
         "Direct request for sensitive authentication credentials (password/PIN)."),
        (r"\b(reset\s+(your\s+)?password\s+(immediately|now|below)|confirm\s+credentials)\b",
         "Unsolicited request to reset or confirm login credentials.")
    ]
    cred_matched = False
    for pattern, explanation in cred_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not cred_matched:
            indicators.append({
                "category": "credential_request",
                "indicator": "Credential request",
                "details": explanation,
                "weight": 25
            })
            cred_matched = True

    # 4. OTP / One-Time Password Requests
    otp_patterns = [
        (r"\b((share|send|provide|forward|enter)\s+(the\s+|your\s+)?(otp|one[\s-]time\s+pass(word)?|2fa\s+code|mfa\s+code|verification\s+code))\b",
         "Solicitation of multi-factor authentication (OTP/2FA) token."),
        (r"\b(sms\s+code|auth\s+code|security\s+code\s+sent\s+to\s+your\s+phone)\b",
         "Requesting SMS or phone-based second-factor security code.")
    ]
    otp_matched = False
    for pattern, explanation in otp_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not otp_matched:
            indicators.append({
                "category": "otp_request",
                "indicator": "OTP/password request",
                "details": explanation,
                "weight": 30
            })
            otp_matched = True

    # 5. Suspicious Calls to Action
    cta_patterns = [
        (r"\b(click\s+(the\s+)?(link|button)\s+(below|here|immediately)|open\s+the\s+attachment\s+to\s+verify)\b",
         "Urging recipient to click external links or download unsolicited attachments."),
        (r"\b(claim\s+(your\s+)?(prize|reward|refund|settlement|payment|gift\s+card))\b",
         "Financial incentive or reward lure detected.")
    ]
    cta_matched = False
    for pattern, explanation in cta_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not cta_matched:
            indicators.append({
                "category": "call_to_action",
                "indicator": "Suspicious call to action",
                "details": explanation,
                "weight": 12
            })
            cta_matched = True

    # 6. Account Verification Requests
    verify_patterns = [
        (r"\b(verify\s+(your\s+)?(account|identity|details|profile|billing|membership)|re-?activate\s+account)\b",
         "Generic account verification request detected.")
    ]
    verify_matched = False
    for pattern, explanation in verify_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE) and not verify_matched:
            indicators.append({
                "category": "account_verification",
                "indicator": "Account verification request",
                "details": explanation,
                "weight": 15
            })
            verify_matched = True

    return indicators


def analyze_url(url: Optional[str]) -> List[Dict[str, Any]]:
    """
    Analyzes URL structure, scheme, IP host, length, and potential deceptive patterns.
    Treats indicators heuristically without blind assumptions.
    """
    indicators: List[Dict[str, Any]] = []
    if not url or not isinstance(url, str) or not url.strip():
        return indicators

    url_clean = url.strip()

    # Prepend scheme if missing for proper parsing
    parse_target = url_clean
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_target):
        parse_target = "http://" + parse_target

    try:
        parsed = urlparse(parse_target)
    except Exception:
        indicators.append({
            "category": "url_structure",
            "indicator": "Malformed URL",
            "details": "The provided URL has an invalid or unparseable format.",
            "weight": 15
        })
        return indicators

    # Catch malformed hostname errors (e.g., brackets, invalid port, colon placement)
    try:
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        indicators.append({
            "category": "url_structure",
            "indicator": "Malformed URL",
            "details": "The provided URL contains invalid host formatting or port structure.",
            "weight": 15
        })
        return indicators

    # 1. IP Address in Hostname
    is_ip = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            indicators.append({
                "category": "url_ip",
                "indicator": "IP address in URL",
                "details": f"URL uses a raw IP address ({hostname}) rather than a registered domain name.",
                "weight": 25
            })
        except ValueError:
            pass

    # 2. @ Symbol in URL (userinfo deception)
    if "@" in url_clean:
        indicators.append({
            "category": "url_obfuscation",
            "indicator": "@ symbol in URL",
            "details": "URL contains an '@' character, which can obscure the actual target destination host.",
            "weight": 25
        })

    # 3. Suspicious URL Scheme
    scheme = parsed.scheme.lower()
    if scheme in ["javascript", "data", "file", "vbscript"]:
        indicators.append({
            "category": "url_scheme",
            "indicator": "Suspicious URL scheme",
            "details": f"Dangerous URI scheme '{scheme}:' detected, which can execute unauthorized scripts.",
            "weight": 35
        })

    # 4. Excessively Long URL (>120 chars)
    if len(url_clean) > 120:
        indicators.append({
            "category": "url_length",
            "indicator": "Excessively long URL",
            "details": f"URL length ({len(url_clean)} characters) is unusually long, frequently used to obscure malicious tokens.",
            "weight": 12
        })

    # 5. Suspicious URL Structure
    if hostname and not is_ip:
        subdomain_parts = hostname.split(".")
        # If more than 3 subdomain levels (e.g. login.verify.secure.bank.attacker.com)
        if len(subdomain_parts) > 4:
            indicators.append({
                "category": "url_structure",
                "indicator": "Suspicious URL structure",
                "details": f"Excessive sub-domain nesting ({len(subdomain_parts) - 2} levels) detected in '{hostname}'.",
                "weight": 18
            })

        # Multiple hyphens in domain name (common in deceptive phishing setups)
        if hostname.count("-") >= 3:
            indicators.append({
                "category": "url_structure",
                "indicator": "Suspicious domain hyphenation",
                "details": f"Domain name '{hostname}' contains multiple hyphens, often used to mimic legitimate services.",
                "weight": 16
            })

        # Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                indicators.append({
                    "category": "url_tld",
                    "indicator": "Suspicious top-level domain",
                    "details": f"Domain uses high-abuse top-level domain '{tld}'.",
                    "weight": 10
                })
                break

    # 6. Look-alike / Typosquatting / Deceptive Brand keywords in domain
    if hostname and not is_ip:
        # Check homoglyphs (e.g., paypa1, micros0ft, g00gle)
        normalized_host = hostname
        for char, sub in HOMOGLYPH_SUBSTITUTIONS.items():
            normalized_host = normalized_host.replace(char, sub)

        for org_key, org_info in KNOWN_ORGANIZATIONS.items():
            is_legit = any(hostname == dom or hostname.endswith("." + dom) for dom in org_info["domains"])
            if not is_legit:
                # Check if brand name is embedded in unauthorized domain
                if org_key in normalized_host or any(name.replace(" ", "") in normalized_host for name in org_info["names"]):
                    indicators.append({
                        "category": "lookalike_domain",
                        "indicator": "Possible look-alike domain",
                        "details": f"Domain '{hostname}' resembles brand '{org_key.capitalize()}' but is not an authorized official domain.",
                        "weight": 30
                    })
                    break

    return indicators


def analyze_domain_mismatch(
    message_text: Optional[str],
    url: Optional[str],
    sender: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Checks if message or sender claims to represent an organization
    while the provided URL domain does not match official organization domains.
    """
    indicators: List[Dict[str, Any]] = []
    if not url or not isinstance(url, str) or not url.strip():
        return indicators

    url_clean = url.strip()
    parse_target = url_clean if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_clean) else "http://" + url_clean

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return indicators

    if not hostname:
        return indicators

    combined_text = f"{message_text or ''} {sender or ''}".lower()
    if not combined_text.strip():
        return indicators

    for org_key, org_info in KNOWN_ORGANIZATIONS.items():
        # Check if the message explicitly mentions the organization
        claimed = any(re.search(rf"\b{re.escape(name)}\b", combined_text, re.IGNORECASE) for name in org_info["names"])
        if claimed:
            # Check if URL matches any official domain
            is_official = any(hostname == dom or hostname.endswith("." + dom) for dom in org_info["domains"])
            if not is_official:
                indicators.append({
                    "category": "domain_mismatch",
                    "indicator": "Organization domain mismatch",
                    "details": (
                        f"Message references '{org_key.capitalize()}', but the target URL domain "
                        f"('{hostname}') does not match official {org_key.capitalize()} domains."
                    ),
                    "weight": 35
                })
                break  # Avoid multiple mismatch alerts for the same URL

    return indicators


def detect_phishing(
    message_text: Optional[str] = None,
    url: Optional[str] = None,
    sender: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Combines text analysis, URL analysis, and domain mismatch detection into a unified
    deduplicated list of indicators.
    """
    raw_indicators: List[Dict[str, Any]] = []

    # Run modular detectors
    raw_indicators.extend(analyze_text(message_text))
    raw_indicators.extend(analyze_url(url))
    raw_indicators.extend(analyze_domain_mismatch(message_text, url, sender))

    # Deduplicate indicators by indicator name to prevent redundant entries
    unique_indicators: List[Dict[str, Any]] = []
    seen_names = set()

    for item in raw_indicators:
        name = item.get("indicator")
        if name and name not in seen_names:
            seen_names.add(name)
            unique_indicators.append(item)

    return unique_indicators
