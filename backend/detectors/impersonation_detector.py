"""
CYBERGUARD Digital Impersonation Detector

Modular heuristic detection functions for identifying deceptive impersonation attempts:
1. Brand impersonation keywords
2. Fake support & helpdesk lures
3. Suspicious sender identity & free webmail mismatch
4. Authority & executive impersonation (Government, Tax, Law Enforcement, CEO/C-Suite, HR/Recruiter)
5. Financial, credential, & PII solicitation (Wire transfers, Gift cards, OTPs, SSNs, Passwords, KYC)
6. Urgent verification & coercive threats
7. Lookalike & typosquatted domains
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "yandex.com", "zoho.com", "gmx.com",
    "live.com", "icloud.com", "tempmail.com", "guerrillamail.com"
}

KNOWN_ORGANIZATIONS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "binance": ["binance.com", "binance.us"],
    "coinbase": ["coinbase.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "irs": ["irs.gov"],
    "fbi": ["fbi.gov"],
    "treasury": ["treasury.gov"],
    "interpol": ["interpol.int"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
}

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


def detect_impersonation(
    message_text: Optional[str] = None,
    claimed_identity: Optional[str] = None,
    sender: Optional[str] = None,
    url: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Analyzes message telemetry, sender identity, claimed authority, and optional URLs
    for heuristic digital impersonation indicators.
    """
    indicators: List[Dict[str, Any]] = []

    text_content = (message_text or "").strip()
    claimed = (claimed_identity or "").strip()
    sender_str = (sender or "").strip()
    url_str = (url or "").strip()

    combined_text = f"{text_content} {claimed}".lower()
    if not combined_text.strip() and not sender_str and not url_str:
        return indicators

    # 1. Authority Impersonation (Government, Tax, Law Enforcement, Legal)
    gov_patterns = [
        (r"\b(irs|internal\s+revenue\s+service|tax\s+(department|investigation|audit|refund|evasion)|hmrc|income\s+tax\s+department)\b",
         "Government Tax Authority", "Purports to represent a federal or national revenue/tax authority.", 30),
        (r"\b(fbi|federal\s+bureau|police\s+department|law\s+enforcement|sheriff|arrest\s+warrant|court\s+subpoena|legal\s+notice|interpol|federal\s+police)\b",
         "Law Enforcement / Legal Authority", "Claims law enforcement, police, or judicial authority to enforce compliance.", 30),
        (r"\b(customs|border\s+protection|homeland\s+security|immigration\s+office|ministry\s+of\s+home\s+affairs)\b",
         "Government Agency Persona", "Claims regulatory, border, or government agency authority.", 25)
    ]
    for pat, label, desc, weight in gov_patterns:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "authority_impersonation",
                "indicator": f"Authority Impersonation ({label})",
                "details": desc,
                "weight": weight
            })
            break

    # 2. Executive & Corporate Persona Impersonation (CEO, CFO, HR/Recruiter)
    exec_patterns = [
        (r"\b(ceo|chief\s+executive|cfo|chief\s+financial|managing\s+director|board\s+of\s+directors|executive\s+director|president\s+of\s+the\s+company)\b",
         "Executive / C-Suite Persona", "Purports to originate from a corporate executive or C-level officer (BEC pretext).", 25),
        (r"\b(hr\s+department|human\s+resources|recruiter|talent\s+acquisition|hiring\s+manager|recruitment\s+team|job\s+offer|employment\s+opportunity)\b",
         "Corporate Recruiter / HR Persona", "Claims to be a corporate recruiter or HR representative offering unverified employment.", 20)
    ]
    for pat, label, desc, weight in exec_patterns:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "executive_impersonation",
                "indicator": label,
                "details": desc,
                "weight": weight
            })
            break

    # 3. Fake Support & Helpdesk Lures
    support_patterns = [
        (r"\b(technical\s+support|helpdesk|customer\s+support|security\s+desk|support\s+ticket\s*#?\d*|case\s*#?\d{3,}|service\s+desk|account\s+resolution\s+team|fraud\s+prevention\s+department)\b",
         "Fake Support / Helpdesk Pretext", "Employs an IT support, customer care, or fraud department pretext.", 20)
    ]
    for pat, label, desc, weight in support_patterns:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "fake_support",
                "indicator": label,
                "details": desc,
                "weight": weight
            })
            break

    # 4. Brand Impersonation Keywords
    matched_brands = []
    for brand_key, domains in KNOWN_ORGANIZATIONS.items():
        if re.search(rf"\b{re.escape(brand_key)}\b", combined_text, re.IGNORECASE):
            matched_brands.append(brand_key.title())

    if matched_brands:
        displayed = ", ".join(matched_brands[:3])
        indicators.append({
            "category": "brand_mention",
            "indicator": "Recognized Brand Reference",
            "details": f"Communication explicitly references recognized brand or entity ({displayed}) requiring origin validation.",
            "weight": 15
        })

    # 5. Suspicious Sender Identity & Free Webmail Mismatch
    sender_domain = ""
    if "@" in sender_str:
        sender_domain = sender_str.split("@")[-1].lower().strip()

    if sender_domain in FREE_WEBMAIL_DOMAINS:
        # Check if the message claims an official brand, government authority, or executive persona
        has_official_claim = (
            bool(matched_brands) or 
            any(i["category"] in ["authority_impersonation", "executive_impersonation", "fake_support"] for i in indicators) or
            bool(claimed)
        )
        if has_official_claim:
            indicators.append({
                "category": "sender_mismatch",
                "indicator": "Free Webmail Sender Mismatch",
                "details": f"Sender uses a public free webmail domain (@{sender_domain}) while purporting to represent an official organization, authority, or executive.",
                "weight": 35
            })
        else:
            indicators.append({
                "category": "sender_identity",
                "indicator": "Free Webmail Sender",
                "details": f"Communication originates from a free public webmail address (@{sender_domain}).",
                "weight": 10
            })
    elif sender_str and not sender_domain and not re.match(r"^\+?[\d\s\-()]{7,20}$", sender_str):
        # Malformed or suspicious sender format
        indicators.append({
            "category": "sender_identity",
            "indicator": "Anomalous Sender Identifier",
            "details": f"Sender identity '{sender_str}' exhibits non-standard addressing patterns.",
            "weight": 15
        })

    # 6. Financial, Credential, & Personal Data (PII) Solicitation
    # a. Financial Solicitation (Untraceable payments, wire transfers, crypto, gift cards)
    financial_solicitation = [
        (r"\b(gift\s+cards?|apple\s+gift|amazon\s+gift|steam\s+card|google\s+play\s+card|wire\s+transfer|bitcoin|btc\s+wallet|ethereum|crypto\s+payment|zelle|cash\s+app|western\s+union|moneygram)\b",
         "Untraceable Payment Solicitation", "Solicits payment via high-risk, irreversible instruments (gift cards, wire transfers, crypto).", 30),
        (r"\b(purchase|buy\s+voucher|send\s+money|transfer\s+funds|urgent\s+payment|settle\s+fine|penalty\s+fee|processing\s+fee|refundable\s+deposit)\b",
         "Financial Transfer Request", "Demands direct financial transfers or advance fee payments.", 25)
    ]
    for pat, label, desc, weight in financial_solicitation:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "financial_solicitation",
                "indicator": label,
                "details": desc,
                "weight": weight
            })
            break

    # b. Credential / OTP / Personal Data Solicitation
    pii_solicitation = [
        (r"\b(otp|one[\s-]time\s+pass(word)?|2fa\s+code|mfa\s+code|verification\s+code|security\s+code)\b",
         "OTP / 2FA Token Solicitation", "Explicitly requests multi-factor authentication passcodes or one-time verification tokens.", 30),
        (r"\b(password|passcode|login\s+credentials|secret\s+key|private\s+key|pin\s+number|account\s+password)\b",
         "Password / Credential Request", "Solicits account passwords, private keys, or secret PINs.", 30),
        (r"\b(ssn|social\s+security|passport\s+(copy|details|photo|number)|id\s+card|driver'?s\s+license|national\s+id|kyc\s+documents?|date\s+of\s+birth|bank\s+account\s+number)\b",
         "Sensitive Identity / KYC Data Request", "Demands high-risk personally identifiable information (SSN, Passport, Government ID, Bank account).", 25)
    ]
    for pat, label, desc, weight in pii_solicitation:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "data_solicitation",
                "indicator": label,
                "details": desc,
                "weight": weight
            })
            break

    # 7. Urgent Verification & Coercive Pressure
    urgent_coercive = [
        (r"\b(immediately|right\s+now|without\s+delay|within\s+\d+\s*(hours?|mins?|minutes?)|act\s+fast|urgent\s+action\s+required|critical\s+deadline)\b",
         "Urgent Time Pressure", "Imposes restrictive time constraints to coerce immediate compliance without due diligence.", 20),
        (r"\b(arrest|jail|police\s+action|lawsuit|legal\s+proceedings|suspended|terminated|frozen|court\s+warrant|asset\s+seizure|penalty)\b",
         "Coercive Threat & Penalty", "Threatens immediate legal, financial, or account penalties to intimidate the recipient.", 25)
    ]
    for pat, label, desc, weight in urgent_coercive:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({
                "category": "coercive_urgency",
                "indicator": label,
                "details": desc,
                "weight": weight
            })
            break

    # 8. Lookalike Domains in URL or Sender
    check_domains = []
    if sender_domain:
        check_domains.append(sender_domain)
    if url_str:
        try:
            target = url_str if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str) else "http://" + url_str
            parsed = urlparse(target)
            if parsed.hostname:
                check_domains.append(parsed.hostname.lower())
        except Exception:
            pass

    for dom in check_domains:
        normalized_dom = dom
        for char, sub in HOMOGLYPH_SUBSTITUTIONS.items():
            normalized_dom = normalized_dom.replace(char, sub)

        for brand_key, legit_domains in KNOWN_ORGANIZATIONS.items():
            is_legit = any(dom == d or dom.endswith("." + d) for d in legit_domains)
            if not is_legit:
                # Check for brand keyword in domain or normalized homoglyph domain
                if brand_key in normalized_dom or brand_key in dom:
                    indicators.append({
                        "category": "lookalike_domain",
                        "indicator": "Impersonating Lookalike Domain",
                        "details": f"Domain '{dom}' mimics legitimate brand '{brand_key.capitalize()}' without authorized affiliation.",
                        "weight": 35
                    })
                    break

    # Deduplicate indicators by indicator name
    unique_indicators: List[Dict[str, Any]] = []
    seen = set()
    for item in indicators:
        name = item.get("indicator")
        if name and name not in seen:
            seen.add(name)
            unique_indicators.append(item)

    return unique_indicators
