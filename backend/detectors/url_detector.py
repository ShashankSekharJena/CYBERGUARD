"""
CYBERGUARD Advanced URL & Domain Threat Detector

Modular passive heuristic detection functions for deep URL, Domain, and IP inspection:
1. IP host & address analysis (IPv4/IPv6, private vs. public, direct host usage)
2. Domain normalization & public suffix / TLD decomposition
3. Excessive subdomains & subdomain depth analysis
4. URL shortening service identification
5. Suspicious security & authentication keywords
6. Protocol security (HTTP vs. HTTPS / dangerous schemes)
7. Unusual domain structure (hyphenation, numeric-heavy patterns, ports, @ userinfo, double slashes, high-abuse TLDs)
8. Length & character encoding obfuscation
9. Lookalike & brand typosquatting homoglyphs
10. Punycode / IDN encoding identification
11. Passive domain & IP format validation

Passive analysis only: Does NOT execute port scans, vulnerability exploits, or intrusive telemetry.
"""

import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import Dict, List, Optional, Any, Tuple

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "tiny.cc", "rebrand.ly", "cutt.ly", "goo.gl", "qr.net", "v.gd",
    "rb.gy", "shorte.st", "trib.al", "adf.ly", "bit.do", "mcaf.ee",
    "su.pr", "shorturl.at", "t.ly", "bl.ink", "hyperurl.co"
}

# Suspicious keywords commonly leveraged in credential harvesting and account lures
SUSPICIOUS_KEYWORDS = {
    "login": "Authentication / login portal pattern",
    "signin": "Sign-in portal keyword",
    "sign-in": "Sign-in portal keyword",
    "log-in": "Log-in portal keyword",
    "verify": "Account verification lure",
    "verification": "Account verification lure",
    "secure": "Deceptive security branding",
    "security": "Security update pretext",
    "account": "Targeted account management context",
    "banking": "Financial or banking lure",
    "credential": "Direct credential solicitation context",
    "password": "Password management context",
    "passcode": "Passcode/PIN lure",
    "wallet": "Crypto or digital wallet targeting",
    "confirm": "Confirmation / re-activation lure",
    "authenticate": "Authentication solicitation",
    "update": "Urgent update pretext",
    "claim": "Financial prize or reward claim lure",
    "recovery": "Account recovery lure",
    "billing": "Billing / invoice lure",
    "webscr": "PayPal legacy spoofing keyword",
    "ebayisapi": "eBay legacy spoofing keyword"
}

# High-abuse Top Level Domains often favored in automated disposable campaigns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work",
    ".click", ".rest", ".fit", ".casa", ".monster", ".sbs", ".cam", ".vip", ".icu"
}

# Multi-part second-level public suffixes for accurate registrable domain splitting
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "ltd.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    "co.za", "org.za", "gov.za",
    "com.sg", "edu.sg", "gov.sg",
    "com.mx", "org.mx", "gob.mx",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "org.tw", "gov.tw",
    "com.hk", "org.hk", "gov.hk"
}

# Homoglyph replacements
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

# Known organizations for lookalike matching
KNOWN_ORGANIZATIONS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "binance": ["binance.com", "binance.us"]
}


def parse_domain_structure(hostname: str) -> Dict[str, Any]:
    """
    Safely decomposes a hostname into domain, subdomain, tld, and structural metrics.
    Handles multi-part public suffixes (e.g. .co.uk, .com.au) and punycode.
    """
    result = {
        "hostname": hostname,
        "domain": None,
        "subdomain": None,
        "tld": None,
        "domain_length": len(hostname) if hostname else 0,
        "subdomain_count": 0,
        "is_punycode": False,
        "is_ip_hostname": False,
        "is_valid": True
    }

    if not hostname or not isinstance(hostname, str):
        result["is_valid"] = False
        return result

    host_clean = hostname.strip().lower()

    # Check for IP address
    try:
        ipaddress.ip_address(host_clean)
        result["is_ip_hostname"] = True
        result["domain"] = host_clean
        result["hostname"] = host_clean
        return result
    except ValueError:
        pass

    # Check for punycode
    if "xn--" in host_clean:
        result["is_punycode"] = True

    # Validate basic domain structure
    labels = host_clean.split(".")
    if len(labels) < 2 or any(len(label) == 0 for label in labels):
        # Invalid FQDN structure (e.g. "not-a-valid-domain" or trailing/double dots)
        result["is_valid"] = False
        result["domain"] = host_clean
        return result

    # Check for multi-part TLD
    matched_tld = None
    if len(labels) >= 3:
        two_part = f"{labels[-2]}.{labels[-1]}"
        if two_part in MULTI_PART_TLDS:
            matched_tld = "." + two_part
            reg_domain = f"{labels[-3]}.{two_part}"
            sub_parts = labels[:-3]
        else:
            matched_tld = "." + labels[-1]
            reg_domain = f"{labels[-2]}.{labels[-1]}"
            sub_parts = labels[:-2]
    else:
        matched_tld = "." + labels[-1]
        reg_domain = f"{labels[-2]}.{labels[-1]}"
        sub_parts = []

    # Validate TLD syntax (alphabetic or punycode, >= 2 chars)
    tld_body = matched_tld.lstrip(".")
    tld_check_parts = tld_body.split(".")
    for tp in tld_check_parts:
        if not re.match(r"^(xn--)?[a-z0-9]{2,}$", tp):
            result["is_valid"] = False

    result["tld"] = matched_tld
    result["domain"] = reg_domain
    result["domain_length"] = len(reg_domain) if reg_domain else len(host_clean)
    result["subdomain"] = ".".join(sub_parts) if sub_parts else None
    result["subdomain_count"] = len(sub_parts)

    return result


def analyze_ip_address(ip_str: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Performs passive evaluation of an IP address string.
    Returns (ip_details_dict, indicators_list).
    """
    indicators: List[Dict[str, Any]] = []
    ip_clean = ip_str.strip()

    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        is_v4 = ip_obj.version == 4
        version_str = "IPv4" if is_v4 else "IPv6"
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
        is_global = ip_obj.is_global

        ip_details = {
            "ip_address": ip_clean,
            "version": version_str,
            "is_private": is_private,
            "is_global": is_global,
            "is_valid": True,
            "is_direct_host": True
        }

        if is_private:
            indicators.append({
                "category": "ip_address",
                "indicator": "Internal / Private IP Address",
                "details": f"Target address {ip_clean} resides in non-routable RFC 1918 / loopback space and cannot be reached from the public internet.",
                "weight": 0
            })
        else:
            indicators.append({
                "category": "ip_address",
                "indicator": "Public IP Target",
                "details": f"Target address {ip_clean} is a globally routable {version_str} endpoint without domain name abstraction.",
                "weight": 5
            })

        return ip_details, indicators

    except ValueError:
        ip_details = {
            "ip_address": ip_clean,
            "version": None,
            "is_private": False,
            "is_global": False,
            "is_valid": False,
            "is_direct_host": False
        }
        indicators.append({
            "category": "validation_error",
            "indicator": "Invalid IP Address Format",
            "details": f"The submitted string '{ip_clean}' is not a syntactically valid IPv4 or IPv6 address.",
            "weight": 0
        })
        return ip_details, indicators


def normalize_target_input(raw_input: Optional[str], input_type_hint: str = "auto") -> Dict[str, Any]:
    """
    Normalizes user input string and resolves whether it represents a URL, domain, or IP address.
    """
    if not raw_input or not isinstance(raw_input, str):
        return {
            "input": "",
            "input_type": "url",
            "normalized_url": "",
            "hostname": "",
            "is_ip": False,
            "is_valid": False
        }

    cleaned = raw_input.strip()
    hint = (input_type_hint or "auto").strip().lower()

    # Check if direct IP address
    is_ip = False
    try:
        ipaddress.ip_address(cleaned)
        is_ip = True
    except ValueError:
        pass

    if hint == "ip" or (hint == "auto" and is_ip):
        return {
            "input": cleaned,
            "input_type": "ip",
            "normalized_url": f"http://{cleaned}" if is_ip else cleaned,
            "hostname": cleaned,
            "is_ip": is_ip,
            "is_valid": is_ip
        }

    # If hint is domain
    if hint == "domain":
        # Strip scheme or path if user pasted a URL into domain field
        dom_target = cleaned
        if "://" in dom_target:
            try:
                dom_target = urlparse(dom_target).hostname or dom_target
            except Exception:
                pass
        elif "/" in dom_target:
            dom_target = dom_target.split("/")[0]

        # Strip port if present
        if ":" in dom_target and not dom_target.startswith("["):
            dom_target = dom_target.split(":")[0]

        dom_info = parse_domain_structure(dom_target)
        return {
            "input": cleaned,
            "input_type": "domain",
            "normalized_url": f"http://{dom_target}",
            "hostname": dom_target,
            "is_ip": dom_info["is_ip_hostname"],
            "is_valid": dom_info["is_valid"],
            "domain_info": dom_info
        }

    # If hint is URL or Auto
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned))
    has_path_or_query = any(char in cleaned for char in ["/", "?", "#", "@"])

    if hint == "url" or has_scheme or has_path_or_query:
        parse_target = cleaned
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", parse_target):
            parse_target = "http://" + parse_target

        try:
            parsed = urlparse(parse_target)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            hostname = ""

        return {
            "input": cleaned,
            "input_type": "url",
            "normalized_url": parse_target,
            "hostname": hostname,
            "is_ip": False,
            "is_valid": bool(hostname)
        }

    # Fallback auto check: check if it looks like a domain vs invalid
    dom_info = parse_domain_structure(cleaned)
    if dom_info["is_valid"]:
        return {
            "input": cleaned,
            "input_type": "domain",
            "normalized_url": f"http://{cleaned}",
            "hostname": cleaned,
            "is_ip": False,
            "is_valid": True,
            "domain_info": dom_info
        }

    # Malformed / unparseable
    return {
        "input": cleaned,
        "input_type": "domain" if hint == "domain" else "url",
        "normalized_url": cleaned,
        "hostname": cleaned,
        "is_ip": False,
        "is_valid": False,
        "domain_info": dom_info
    }


def detect_domain_threats(hostname: str) -> List[Dict[str, Any]]:
    """
    Performs passive structural analysis of a domain/hostname.
    Returns detected heuristic threat indicators.
    """
    indicators: List[Dict[str, Any]] = []
    if not hostname:
        return indicators

    host_clean = hostname.strip().lower()

    # 1. Domain structure decomposition
    dom_struct = parse_domain_structure(host_clean)
    if not dom_struct["is_valid"] and not dom_struct["is_ip_hostname"]:
        indicators.append({
            "category": "validation_error",
            "indicator": "Invalid Domain Format",
            "details": f"The submitted domain '{host_clean}' violates standard Fully Qualified Domain Name (FQDN) syntax rules.",
            "weight": 0
        })
        return indicators

    # 2. Punycode / Internationalized Domain Name (IDN) homoglyphs
    if dom_struct["is_punycode"]:
        indicators.append({
            "category": "punycode",
            "indicator": "Punycode / IDN Domain",
            "details": f"Domain '{host_clean}' utilizes Punycode ('xn--') encoding, commonly leveraged in IDN homograph impersonation attacks.",
            "weight": 25
        })

    # 3. Numeric-heavy hostname or sequence of digits
    if not dom_struct["is_ip_hostname"]:
        digits_count = sum(c.isdigit() for c in host_clean)
        digit_ratio = digits_count / max(1, len(host_clean))
        has_digit_sequence = bool(re.search(r"\d{4,}", host_clean))

        if digit_ratio >= 0.30 or has_digit_sequence:
            indicators.append({
                "category": "domain_structure",
                "indicator": "Numeric-Heavy Hostname Pattern",
                "details": f"Hostname '{host_clean}' contains a high density of numeric characters ({digits_count} digits), characteristic of algorithmically generated domain (DGA) clusters.",
                "weight": 15
            })

    # 4. Consecutive or unusual hyphens
    if not dom_struct["is_ip_hostname"]:
        if "--" in host_clean and not host_clean.startswith("xn--"):
            indicators.append({
                "category": "domain_structure",
                "indicator": "Consecutive Domain Hyphens",
                "details": f"Hostname '{host_clean}' contains consecutive hyphens ('--') often used to assemble deceptive brand permutations.",
                "weight": 15
            })

    # 5. High-abuse Top Level Domain
    tld = dom_struct.get("tld")
    if tld and tld in SUSPICIOUS_TLDS:
        indicators.append({
            "category": "suspicious_tld",
            "indicator": "Suspicious Top-Level Domain",
            "details": f"Domain utilizes high-abuse top-level domain '{tld}'.",
            "weight": 15
        })

    # 6. Excessive Subdomains
    if dom_struct.get("subdomain_count", 0) > 2:
        indicators.append({
            "category": "subdomains",
            "indicator": "Excessive Subdomains",
            "details": f"Domain contains {dom_struct['subdomain_count']} subdomain levels ('{host_clean}'), often used in phishing to mimic legitimate corporate architectures.",
            "weight": 20
        })

    # 7. Suspicious Keywords in domain / subdomain
    matched_keywords = []
    for kw in SUSPICIOUS_KEYWORDS.keys():
        if re.search(rf"(^|[^a-zA-Z0-9]){re.escape(kw)}([^a-zA-Z0-9]|$)", host_clean, re.IGNORECASE):
            matched_keywords.append(kw)

    if matched_keywords:
        displayed_kw = ", ".join(matched_keywords[:4])
        indicators.append({
            "category": "suspicious_keywords",
            "indicator": "Suspicious Security Keywords",
            "details": f"Domain contains security or authentication keywords ({displayed_kw}) commonly found in credential harvesting lures.",
            "weight": min(25, 10 + len(matched_keywords) * 4)
        })

    # 8. Excessive Hyphenation (>= 2 hyphens)
    if not dom_struct["is_ip_hostname"] and host_clean.count("-") >= 2:
        indicators.append({
            "category": "url_structure",
            "indicator": "Excessive Domain Hyphenation",
            "details": f"Hostname '{host_clean}' contains {host_clean.count('-')} hyphens, commonly used to assemble fake security portals.",
            "weight": 15
        })

    # 9. Brand Lookalike / Typosquatting
    if not dom_struct["is_ip_hostname"]:
        normalized_host = host_clean
        for char, sub in HOMOGLYPH_SUBSTITUTIONS.items():
            normalized_host = normalized_host.replace(char, sub)

        for brand_name, legit_domains in KNOWN_ORGANIZATIONS.items():
            is_legit = any(host_clean == dom or host_clean.endswith("." + dom) for dom in legit_domains)
            if not is_legit:
                if brand_name in normalized_host or brand_name in host_clean:
                    indicators.append({
                        "category": "lookalike_domain",
                        "indicator": "Brand Lookalike Domain",
                        "details": f"Hostname '{host_clean}' closely mimics legitimate brand '{brand_name.capitalize()}' on an unauthorized domain.",
                        "weight": 30
                    })
                    break

    return indicators


def detect_url_threats(url: Optional[str]) -> List[Dict[str, Any]]:
    """
    Performs modular heuristic analysis of a URL and returns a list of detected threat indicators.
    Preserved with full backward compatibility and augmented with domain and structural checks.
    """
    indicators: List[Dict[str, Any]] = []
    if not url or not isinstance(url, str) or not url.strip():
        return indicators

    url_clean = url.strip()

    # Prepend scheme if missing for standardized parsing
    parse_target = url_clean
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", parse_target):
        parse_target = "http://" + parse_target

    try:
        parsed = urlparse(parse_target)
    except Exception:
        indicators.append({
            "category": "url_structure",
            "indicator": "Malformed URL",
            "details": "The provided URL has an invalid format and cannot be parsed safely.",
            "weight": 20
        })
        return indicators

    try:
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except (ValueError, AttributeError):
        indicators.append({
            "category": "url_structure",
            "indicator": "Malformed URL Host/Port",
            "details": "The URL host or port definition violates standard URI syntax.",
            "weight": 20
        })
        return indicators

    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_path_query = f"{path}?{query}".lower()

    # 1. Protocol Security: HTTP vs. HTTPS / Dangerous Schemes
    if scheme in ["javascript", "data", "file", "vbscript"]:
        indicators.append({
            "category": "scheme",
            "indicator": "Dangerous URI Scheme",
            "details": f"URI utilizes '{scheme}:', which can execute unauthorized scripts or load unauthorized local resources.",
            "weight": 35
        })
    elif scheme == "http":
        indicators.append({
            "category": "scheme",
            "indicator": "Unencrypted HTTP Protocol",
            "details": "URL uses unencrypted plain HTTP instead of secure HTTPS, vulnerable to interception and impersonation.",
            "weight": 15
        })

    # 2. IP Address Host Detection
    is_ip = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            indicators.append({
                "category": "ip_host",
                "indicator": "IP Address Host",
                "details": f"URL uses raw IP address ({hostname}) rather than a registered domain name to conceal host identity.",
                "weight": 30
            })
        except ValueError:
            pass

    # 3. URL Shortening Services
    if hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + d) for d in SHORTENER_DOMAINS):
        indicators.append({
            "category": "shortener",
            "indicator": "URL Shortener Service",
            "details": f"URL uses known shortening service '{hostname}', which conceals the ultimate landing page destination.",
            "weight": 20
        })

    # 4. Domain-level threat checks
    if hostname:
        domain_indicators = detect_domain_threats(hostname)
        for d_ind in domain_indicators:
            # Prevent duplicate keywords indicator if already present
            indicators.append(d_ind)

    # 5. Suspicious Keywords in Subdomain or Path
    matched_keywords = []
    text_to_search = f"{hostname} {full_path_query}"
    for kw, kw_desc in SUSPICIOUS_KEYWORDS.items():
        if re.search(rf"(^|[^a-zA-Z0-9]){re.escape(kw)}([^a-zA-Z0-9]|$)", text_to_search, re.IGNORECASE):
            matched_keywords.append(kw)

    if matched_keywords:
        displayed_kw = ", ".join(matched_keywords[:4])
        indicators.append({
            "category": "suspicious_keywords",
            "indicator": "Suspicious Security Keywords",
            "details": f"URL contains security or authentication keywords ({displayed_kw}) commonly found in credential harvesting lures.",
            "weight": min(25, 10 + len(matched_keywords) * 4)
        })

    # 6. Unusual URL Structure
    # a. Userinfo '@' symbol
    if "@" in url_clean:
        indicators.append({
            "category": "url_structure",
            "indicator": "@ Symbol Deception",
            "details": "URL contains an '@' symbol, which causes browsers to ignore preceding text and route to the following host.",
            "weight": 25
        })

    # b. Non-standard Port
    if port and port not in [80, 443]:
        indicators.append({
            "category": "url_structure",
            "indicator": "Non-Standard Port",
            "details": f"URL communicates on non-standard port :{port} instead of standard HTTP (80) or HTTPS (443).",
            "weight": 15
        })

    # c. Double Slash in Path
    if "//" in path:
        indicators.append({
            "category": "url_structure",
            "indicator": "Double Slash in Path",
            "details": "Path contains '//' sequence, commonly used in open redirect exploits or parser evasion.",
            "weight": 18
        })

    # 7. Long URLs and Encoded Character Obfuscation
    # a. URL Length
    if len(url_clean) > 100:
        weight = 15 if len(url_clean) > 150 else 10
        indicators.append({
            "category": "url_length",
            "indicator": "Excessively Long URL",
            "details": f"URL length ({len(url_clean)} characters) is unusually long, frequently engineered to obscure malicious payload tokens.",
            "weight": weight
        })

    # b. Percent-Encoded Obfuscation
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", url_clean)
    if len(encoded_matches) >= 3:
        indicators.append({
            "category": "encoding_obfuscation",
            "indicator": "Character Encoding Obfuscation",
            "details": f"URL contains {len(encoded_matches)} percent-encoded characters, often used to bypass basic keyword filters.",
            "weight": 15
        })

    # Deduplicate indicators by indicator name while preserving order
    unique_indicators: List[Dict[str, Any]] = []
    seen = set()
    for item in indicators:
        name = item.get("indicator")
        if name and name not in seen:
            seen.add(name)
            unique_indicators.append(item)

    return unique_indicators


def analyze_target_telemetry(
    raw_input: Optional[str],
    input_type_hint: str = "auto"
) -> Dict[str, Any]:
    """
    Master analysis function handling URL, Domain, and IP address inputs.
    Extracts structured technical metrics and telemetry indicators.
    """
    normalized = normalize_target_input(raw_input, input_type_hint)
    input_type = normalized["input_type"]
    input_val = normalized["input"]
    hostname = normalized["hostname"]

    raw_indicators: List[Dict[str, Any]] = []
    domain_details = None
    ip_details = None

    if input_type == "ip":
        ip_details, ip_inds = analyze_ip_address(input_val)
        raw_indicators.extend(ip_inds)
        domain_name = None
        subdomain = None
        tld = None
        ip_addr = ip_details["ip_address"]

    elif input_type == "domain":
        dom_struct = parse_domain_structure(hostname)
        dom_inds = detect_domain_threats(hostname)
        raw_indicators.extend(dom_inds)

        domain_details = {
            "domain": dom_struct.get("domain"),
            "subdomain": dom_struct.get("subdomain"),
            "tld": dom_struct.get("tld"),
            "hostname": dom_struct.get("hostname"),
            "domain_length": dom_struct.get("domain_length"),
            "subdomain_count": dom_struct.get("subdomain_count", 0),
            "is_punycode": dom_struct.get("is_punycode", False),
            "is_ip_hostname": dom_struct.get("is_ip_hostname", False),
            "has_suspicious_keywords": any(ind["category"] == "suspicious_keywords" for ind in dom_inds),
            "has_suspicious_tld": any(ind["category"] == "suspicious_tld" for ind in dom_inds),
            "has_suspicious_patterns": any(ind["category"] in ["domain_structure", "lookalike_domain"] for ind in dom_inds),
            "is_valid": dom_struct.get("is_valid", True)
        }

        domain_name = dom_struct.get("domain")
        subdomain = dom_struct.get("subdomain")
        tld = dom_struct.get("tld")
        ip_addr = None

    else:  # input_type == "url"
        url_inds = detect_url_threats(input_val)
        raw_indicators.extend(url_inds)

        dom_struct = parse_domain_structure(hostname)
        is_ip_host = dom_struct.get("is_ip_hostname", False)

        if is_ip_host:
            ip_details, _ = analyze_ip_address(hostname)
            ip_addr = hostname
            domain_name = None
            subdomain = None
            tld = None
        else:
            ip_addr = None
            domain_name = dom_struct.get("domain")
            subdomain = dom_struct.get("subdomain")
            tld = dom_struct.get("tld")

        domain_details = {
            "domain": domain_name,
            "subdomain": subdomain,
            "tld": tld,
            "hostname": hostname,
            "domain_length": dom_struct.get("domain_length", len(hostname)),
            "subdomain_count": dom_struct.get("subdomain_count", 0),
            "is_punycode": dom_struct.get("is_punycode", False),
            "is_ip_hostname": is_ip_host,
            "has_suspicious_keywords": any(ind["category"] == "suspicious_keywords" for ind in url_inds),
            "has_suspicious_tld": any(ind["category"] == "suspicious_tld" for ind in url_inds),
            "has_suspicious_patterns": any(ind["category"] in ["domain_structure", "lookalike_domain", "url_structure"] for ind in url_inds),
            "is_valid": dom_struct.get("is_valid", True) if not is_ip_host else True
        }

    # Deduplicate indicators
    unique_indicators: List[Dict[str, Any]] = []
    seen = set()
    for item in raw_indicators:
        name = item.get("indicator")
        if name and name not in seen:
            seen.add(name)
            unique_indicators.append(item)

    return {
        "input": input_val,
        "input_type": input_type,
        "target_url": input_val,
        "domain": domain_name,
        "subdomain": subdomain,
        "tld": tld,
        "ip_address": ip_addr,
        "hostname": hostname,
        "domain_details": domain_details,
        "ip_details": ip_details,
        "indicators": unique_indicators
    }
