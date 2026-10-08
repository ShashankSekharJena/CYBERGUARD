"""
CYBERGUARD URL, Domain & IP Explanation Engine

Generates transparent, contextual, evidence-based human-readable explanations of URL,
domain, and IP telemetry findings. Clarifies why specific indicators matter and emphasizes
heuristic boundaries.
"""

from typing import Dict, List, Any

URL_INDICATOR_EXPLANATIONS: Dict[str, str] = {
    "IP Address Host": "Raw IP hosts conceal domain registration ownership and circumvent domain reputation tracking.",
    "Excessive Subdomains": "Deeply nested subdomain trees are commonly used by attackers to mimic legitimate security portals or cloud environments.",
    "URL Shortener Service": "Shortening services mask the ultimate destination URL, preventing security inspection prior to redirection.",
    "Suspicious Security Keywords": "Security, login, and verification keywords in unauthorized URLs/domains strongly correlate with credential harvesting campaigns.",
    "Unencrypted HTTP Protocol": "Unencrypted HTTP transports data in plaintext, exposing users to interception, eavesdropping, and man-in-the-middle attacks.",
    "Dangerous URI Scheme": "Scriptable or local URI schemes can execute client-side code or access restricted system resources.",
    "@ Symbol Deception": "The '@' character exploits URL parsing ambiguities to obscure the genuine destination host.",
    "Excessive Domain Hyphenation": "Multiple hyphens are frequently used to construct believable composite domain names that impersonate brands.",
    "Non-Standard Port": "Non-standard network ports are often utilized to bypass standard HTTP proxy and firewall inspection filters.",
    "Suspicious Top-Level Domain": "Certain generic TLDs are frequently favored in disposable or malicious campaigns due to minimal registrar verification and low cost.",
    "Double Slash in Path": "Double slashes in URL paths are often used to exploit open-redirect vulnerabilities or evade web application firewalls.",
    "Excessively Long URL": "Unusually long URLs are frequently designed to push deceptive parameters beyond visible address bar viewports.",
    "Character Encoding Obfuscation": "Percent-encoding and hex tokens are used to obfuscate recognizable malicious patterns from signature filters.",
    "Brand Lookalike Domain": "Typosquatting or homoglyph character substitutions mimic trusted brands to deceive users into credential entry.",
    "Punycode / IDN Domain": "Punycode ('xn--') encoding can visually mimic legitimate Latin brand names using Internationalized Domain Name (IDN) homoglyphs.",
    "Numeric-Heavy Hostname Pattern": "High ratio of numeric characters or long numeric strings is characteristic of disposable domain generation algorithms (DGAs).",
    "Consecutive Domain Hyphens": "Consecutive hyphens ('--') are frequently used to construct deceptive lookalike domain variations.",
    "Internal / Private IP Address": "Target IP address resides in non-routable RFC 1918 / loopback space and cannot be reached from the public internet.",
    "Public IP Target": "Target is a direct publicly routable IP address without domain name abstraction.",
    "Invalid Domain Format": "Submitted input violates standard Fully Qualified Domain Name (FQDN) syntax rules.",
    "Invalid IP Address Format": "Submitted input is not a syntactically valid IPv4 or IPv6 address.",
    "Malformed URL": "The URL structure violates URI formatting standards and cannot be parsed reliably.",
    "Malformed URL Host/Port": "The URL contains invalid host or port syntax.",
}


def explain_url_indicator(name: str) -> str:
    """Returns why a specific indicator matters from a security standpoint."""
    return URL_INDICATOR_EXPLANATIONS.get(
        name,
        "This telemetry pattern deviates from standard web routing and naming conventions."
    )


def generate_url_explanation(
    indicators: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str,
    target: str,
    input_type: str = "url"
) -> str:
    """
    Synthesizes a coherent, honest human-readable explanation of URL/Domain/IP threat findings.
    Adheres strictly to observable evidence without claiming absolute proof.
    """
    has_validation_error = any(item.get("category") == "validation_error" for item in indicators)
    if has_validation_error:
        val_ind = next(item for item in indicators if item.get("category") == "validation_error")
        return (
            f"Validation Notice: {val_ind.get('details', 'The submitted input has invalid syntax.')} "
            f"Please check the submitted {input_type} and verify formatting."
        )

    if not indicators or risk_score == 0:
        return (
            f"No anomalous or suspicious heuristic patterns were detected in the target {input_type} structure. "
            f"Analysis is based on observable technical characteristics and does not prove that the destination is benign without reliable external reputation intelligence."
        )

    indicator_names = [item.get("indicator", "Suspicious pattern") for item in indicators]

    if len(indicators) == 1:
        name = indicator_names[0]
        context = explain_url_indicator(name)
        if name in ["Public IP Target", "Internal / Private IP Address"]:
            return (
                f"Observable IP characteristics detected: {name} ({context}). "
                f"Calculated risk level: {risk_level} ({risk_score}/100). Passive evaluation completed."
            )
        return (
            f"Suspicious {input_type} characteristics detected: {name} ({context}). "
            f"Calculated heuristic risk level: {risk_level} ({risk_score}/100). The analyzer identifies suspicious characteristics; it does not prove that an entity is malicious without reliable external threat-intelligence evidence."
        )

    joined_names = ", ".join(indicator_names)
    if risk_level in ["HIGH", "CRITICAL"]:
        return (
            f"Multiple high-risk {input_type} characteristics detected ({joined_names}). "
            f"The combination of deceptive host routing, keyword lures, or structural obfuscation commonly aligns with phishing or credential harvesting vectors. "
            f"Calculated heuristic risk score: {risk_score}/100 ({risk_level}). This is a heuristic risk indicator based on observable patterns, not a definitive guarantee of maliciousness."
        )
    elif risk_level == "MEDIUM":
        return (
            f"Suspicious {input_type} characteristics detected ({joined_names}). "
            f"While these patterns may occasionally appear in complex enterprise architectures, they represent elevated risk factors. "
            f"Calculated heuristic risk score: {risk_score}/100 ({risk_level})."
        )
    else:  # LOW
        return (
            f"Minor observable {input_type} telemetry patterns detected ({joined_names}). "
            f"Calculated heuristic risk: {risk_level} ({risk_score}/100). Exercise standard verification before submitting credentials or interacting."
        )
