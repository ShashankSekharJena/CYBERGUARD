"""
CYBERGUARD Account Security & Behavioural Anomaly Detector

Provides transparent, rule-based behavioural anomaly detection for:
1. Failed login frequency and rapid burst attacks
2. High-risk and anonymized geographic origins
3. Unrecognized or suspicious device fingerprints
4. Mathematical Impossible Travel calculation (Haversine distance vs elapsed time)
5. Session concurrency and hijacking anomalies
6. Multi-Factor Authentication (MFA) fatigue and manipulation
7. Extensible structure for future Isolation Forest / ML integration.
"""

import math
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union


KNOWN_CITY_COORDINATES: Dict[str, Tuple[float, float]] = {
    "new york": (40.7128, -74.0060),
    "london": (51.5074, -0.1278),
    "tokyo": (35.6762, 139.6503),
    "sydney": (-33.8688, 151.2093),
    "san francisco": (37.7749, -122.4194),
    "paris": (48.8566, 2.3522),
    "berlin": (52.5200, 13.4050),
    "singapore": (1.3521, 103.8198),
    "moscow": (55.7558, 37.6173),
    "beijing": (39.9042, 116.4074),
    "dubai": (25.2048, 55.2708),
    "mumbai": (19.0760, 72.8777),
    "toronto": (43.6532, -79.3832),
    "frankfurt": (50.1109, 8.6821),
    "amsterdam": (52.3676, 4.9041),
    "seoul": (37.5665, 126.9780),
    "sao paulo": (-23.5505, -46.6333),
    "johannesburg": (-26.2041, 28.0473)
}

HIGH_RISK_REGIONS = {
    "north korea", "dprk", "iran", "syria", "crimea",
    "cuba", "myanmar", "libya", "somalia", "sudan",
    "south sudan", "yemen", "afghanistan", "iraq",
    "undisclosed", "anonymized", "tor exit", "vpn",
    "proxy", "darknet", "dark web"
}

ANONYMIZATION_PATTERNS = [
    r"\btor\b", r"\bvpn\b", r"\bproxy\b", r"\bsocks\d?\b",
    r"\banonymiz", r"\bdarknet\b", r"\bdark\s+web\b",
    r"\brelay\b", r"\btunnel\b", r"\bi2p\b"
]

SUSPICIOUS_DEVICE_PATTERNS = [
    r"\b(headless|automated|bot|crawler|script|selenium|puppeteer|playwright|curl|wget|python-requests|httpie)\b",
    r"\b(unknown|unrecognized|new\s+device|first[\s-]+time|unregistered)\b",
    r"\b(rooted|jailbroken|emulator|virtual\s+machine|vm\b|sandbox)\b"
]

PASSWORD_RESET_PATTERNS = [
    (r"\b(password\s+reset|reset\s+password|forgot\s+password|recovery\s+request|account\s+recovery)\b",
     "Password Reset Request Detected",
     "A password reset or account recovery event was triggered, which may indicate unauthorized recovery attempts.",
     20),
    (r"\b(multiple\s+reset|repeated\s+reset|reset\s+flood|rapid\s+reset|bulk\s+reset)\b",
     "Rapid Password Reset Flooding",
     "Multiple consecutive password reset requests detected, suggesting automated recovery abuse.",
     30),
    (r"\b(security\s+question|backup\s+email\s+changed|recovery\s+email\s+changed|phone\s+number\s+changed)\b",
     "Recovery Method Modification",
     "Account recovery contact information (email or phone) was recently modified, a common account takeover preparation step.",
     25),
]

MFA_MANIPULATION_PATTERNS = [
    (r"\b(otp\s+bypass|mfa\s+bypass|2fa\s+bypass|skip\s+verification|bypass\s+authentication)\b",
     "MFA/OTP Bypass Attempt",
     "Indicators of an attempt to bypass multi-factor authentication safeguards.",
     35),
    (r"\b(otp\s+intercept|sms\s+intercept|sim\s+swap|sim\s+cloning|ss7\s+attack|mfa\s+fatigue|push\s+bombing)\b",
     "MFA Interception / SIM Swap Indicator",
     "Patterns consistent with SIM swap, SMS interception, or MFA fatigue attack (push notification bombing).",
     35),
    (r"\b(otp\s+brute|otp\s+guess|code\s+spray|verification\s+code\s+flood|token\s+replay)\b",
     "OTP Brute-Force / Token Replay",
     "Rapid, repeated OTP/verification code submission attempts detected, suggesting code spraying or token replay.",
     30),
    (r"\b(authenticator\s+removed|mfa\s+disabled|2fa\s+disabled|mfa\s+removed|totp\s+reset)\b",
     "MFA Disabled or Authenticator Removed",
     "Multi-factor authentication was disabled or an authenticator app was removed, weakening account defenses.",
     30),
]

SESSION_ANOMALY_PATTERNS = [
    (r"\b(session\s+hijack|cookie\s+theft|cookie\s+replay|session\s+replay|stolen\s+session|session\s+fixation)\b",
     "Session Hijacking / Cookie Theft Indicator",
     "Patterns consistent with session hijacking, cookie replay, or session fixation attack.",
     35),
    (r"\b(concurrent\s+session|multiple\s+active\s+session|simultaneous\s+login|parallel\s+session|duplicate\s+session)\b",
     "Concurrent Session Anomaly",
     "Multiple simultaneous active sessions detected for the same account from different locations or devices.",
     25),
    (r"\b(session\s+expired\s+prematurely|forced\s+logout|session\s+invalidat|unexpected\s+session\s+terminat)\b",
     "Abnormal Session Termination",
     "Unexpected session invalidation or forced logout may indicate active session tampering.",
     20),
]

PRIVILEGE_ESCALATION_PATTERNS = [
    (r"\b(privilege\s+escalat|role\s+change|admin\s+grant|elevated\s+access|superuser|sudo|root\s+access|admin\s+promot)\b",
     "Suspicious Privilege Escalation",
     "Account privileges were elevated or administrative role was granted, potentially without authorization.",
     30),
    (r"\b(new\s+admin|unauthorized\s+admin|self[\s-]+elevated|permission\s+change|access\s+level\s+change|role\s+modification)\b",
     "Unauthorized Role Modification",
     "Account role or permission level was modified outside standard administrative workflows.",
     25),
]

IMPOSSIBLE_TRAVEL_PATTERNS = [
    (r"\b(impossible\s+travel|geographic\s+anomaly|location\s+jump|rapid\s+geolocation\s+change)\b",
     "Impossible Travel Detected",
     "Login attempts from geographically distant locations within an impossibly short timeframe.",
     35),
]


def haversine_distance_km(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """Calculates great-circle distance in kilometers between two lat/lon coordinates."""
    lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
    lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2.0) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2.0) ** 2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371.0
    return r * c


def find_coordinates(location_str: str) -> Optional[Tuple[float, float]]:
    loc_lower = location_str.lower()
    for city, coords in KNOWN_CITY_COORDINATES.items():
        if city in loc_lower:
            return coords
    return None


def parse_timestamp_str(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str.replace("+00:00", "Z"), fmt)
        except Exception:
            continue
    return None


def calculate_travel_velocity(
    loc1_str: Optional[str],
    ts1_str: Optional[str],
    loc2_str: Optional[str],
    ts2_str: Optional[str]
) -> Optional[float]:
    if not loc1_str or not loc2_str or not ts1_str or not ts2_str:
        return None

    coords1 = find_coordinates(loc1_str)
    coords2 = find_coordinates(loc2_str)
    if not coords1 or not coords2:
        return None

    dt1 = parse_timestamp_str(ts1_str)
    dt2 = parse_timestamp_str(ts2_str)
    if not dt1 or not dt2:
        return None

    time_diff_hours = abs((dt2 - dt1).total_seconds()) / 3600.0
    if time_diff_hours < 0.001:
        distance = haversine_distance_km(coords1, coords2)
        return distance * 100.0

    distance = haversine_distance_km(coords1, coords2)
    return distance / time_diff_hours


def detect_account_security_threats(
    username: Optional[str] = None,
    login_location: Optional[str] = None,
    device_info: Optional[str] = None,
    failed_login_count: int = 0,
    event_description: Optional[str] = None,
    ip_address: Optional[str] = None,
    timestamp: Optional[str] = None,
    previous_location: Optional[str] = None,
    previous_timestamp: Optional[str] = None,
    failed_login_burst_count: int = 0,
    mfa_attempts: int = 0,
    active_concurrent_sessions: int = 1,
    is_new_device: bool = False,
    return_metrics: bool = False
) -> Union[List[Dict[str, Any]], Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
    """
    Analyzes authentication and behavioural telemetry for account takeover
    and anomaly indicators.
    """
    indicators: List[Dict[str, Any]] = []

    effective_username = (username or "").strip().lower()
    effective_location = (login_location or "").strip().lower()
    effective_device = (device_info or "").strip().lower()
    effective_event = (event_description or "").strip().lower()
    effective_ip = (ip_address or "").strip().lower()

    combined_text = f"{effective_event} {effective_location} {effective_device} {effective_ip}"

    impossible_travel_flag = False
    velocity_kmh = None
    failed_burst_flag = False
    mfa_fatigue_flag = False
    session_concurrency_flag = False
    new_device_flag = is_new_device

    # 1. Failed Login Count
    if failed_login_count and failed_login_count > 0:
        if failed_login_count >= 10:
            indicators.append({
                "category": "brute_force",
                "indicator": "Critical Brute-Force / Credential Stuffing",
                "details": f"{failed_login_count} consecutive failed login attempts detected. "
                           f"This volume strongly suggests automated credential stuffing or brute-force attack against account '{effective_username or 'unknown'}'.",
                "weight": 40
            })
        elif failed_login_count >= 5:
            indicators.append({
                "category": "brute_force",
                "indicator": "Elevated Failed Login Attempts",
                "details": f"{failed_login_count} consecutive failed login attempts detected for account '{effective_username or 'unknown'}'. "
                           f"This exceeds normal user error thresholds and may indicate targeted credential guessing.",
                "weight": 25
            })
        elif failed_login_count >= 3:
            indicators.append({
                "category": "brute_force",
                "indicator": "Multiple Failed Login Attempts",
                "details": f"{failed_login_count} failed login attempts recorded. "
                           f"While occasionally normal, repeated failures warrant monitoring.",
                "weight": 15
            })

    # Explicit rapid burst count (when provided separately)
    if failed_login_burst_count and failed_login_burst_count >= 5 and failed_login_count == 0:
        indicators.append({
            "category": "brute_force",
            "indicator": "Rapid Authentication Burst Frequency",
            "details": f"High frequency burst rate: {failed_login_burst_count} failed authentications in short succession (<5 min window).",
            "weight": 30
        })
        failed_burst_flag = True

    # 2. MFA Fatigue / Manipulation
    if mfa_attempts and mfa_attempts >= 4:
        indicators.append({
            "category": "mfa_manipulation",
            "indicator": "MFA Fatigue / Push Bombing Attack",
            "details": f"Detected {mfa_attempts} rapid consecutive MFA authorization push requests, indicative of MFA fatigue harassment.",
            "weight": 35
        })
        mfa_fatigue_flag = True

    # 3. Concurrent Active Sessions
    if active_concurrent_sessions and active_concurrent_sessions > 1:
        indicators.append({
            "category": "session_anomaly",
            "indicator": "Concurrent Multi-Location Sessions",
            "details": f"{active_concurrent_sessions} simultaneous active sessions detected across distinct geolocations or IP subnets.",
            "weight": 30
        })
        session_concurrency_flag = True

    # 4. Mathematical Impossible Travel
    if previous_location and login_location and previous_timestamp and timestamp:
        velocity_kmh = calculate_travel_velocity(
            previous_location, previous_timestamp,
            login_location, timestamp
        )
        if velocity_kmh is not None and velocity_kmh > 800.0:
            impossible_travel_flag = True
            indicators.append({
                "category": "impossible_travel",
                "indicator": "Impossible Travel Velocity Anomaly",
                "details": (
                    f"Physical travel velocity between previous login ('{previous_location}') "
                    f"and current login ('{login_location}') was calculated at {velocity_kmh:.1f} km/h, "
                    f"exceeding commercial aviation threshold (800 km/h)."
                ),
                "weight": 40
            })

    # 5. New / Unknown Device
    if is_new_device:
        indicators.append({
            "category": "unknown_device",
            "indicator": "Unrecognized Device Fingerprint",
            "details": f"Authentication executed from a previously unseen device fingerprint / hardware profile: '{device_info or 'unregistered'}'.",
            "weight": 20
        })
        new_device_flag = True

    # Check device / text for suspicious device patterns
    device_search_text = f"{effective_device} {effective_event}"
    for pattern in SUSPICIOUS_DEVICE_PATTERNS:
        if re.search(pattern, device_search_text, re.IGNORECASE):
            indicators.append({
                "category": "unknown_device",
                "indicator": "Suspicious / Unknown Device Fingerprint",
                "details": f"Device information exhibits suspicious characteristics (automated, headless, emulated, or unrecognized): '{device_info or effective_event}'.",
                "weight": 25
            })
            new_device_flag = True
            break

    # 6. High-Risk / Anonymized Origin
    if effective_location:
        is_high_risk = any(region in effective_location for region in HIGH_RISK_REGIONS)
        if is_high_risk:
            indicators.append({
                "category": "unusual_location",
                "indicator": "High-Risk Geographic Login Origin",
                "details": f"Login originated from a location flagged as high-risk or sanctioned region: '{login_location}'. "
                           f"This geographic origin is frequently associated with threat actor infrastructure.",
                "weight": 30
            })

        for pattern in ANONYMIZATION_PATTERNS:
            if re.search(pattern, effective_location, re.IGNORECASE):
                indicators.append({
                    "category": "unusual_location",
                    "indicator": "Anonymized / Proxied Login Origin",
                    "details": f"Login location indicates use of anonymization infrastructure (Tor, VPN, Proxy): '{login_location}'.",
                    "weight": 25
                })
                break

    if effective_ip:
        for pattern in ANONYMIZATION_PATTERNS:
            if re.search(pattern, effective_ip, re.IGNORECASE):
                indicators.append({
                    "category": "unusual_location",
                    "indicator": "Anonymized IP Address Detected",
                    "details": f"Origin IP address '{ip_address}' exhibits anonymization/proxy characteristics.",
                    "weight": 20
                })
                break

    # 7. Additional rule patterns
    for pat, label, desc, weight in PASSWORD_RESET_PATTERNS:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({"category": "password_reset", "indicator": label, "details": desc, "weight": weight})

    for pat, label, desc, weight in MFA_MANIPULATION_PATTERNS:
        if re.search(pat, combined_text, re.IGNORECASE) and not mfa_fatigue_flag:
            indicators.append({"category": "mfa_manipulation", "indicator": label, "details": desc, "weight": weight})

    for pat, label, desc, weight in SESSION_ANOMALY_PATTERNS:
        if re.search(pat, combined_text, re.IGNORECASE) and not session_concurrency_flag:
            indicators.append({"category": "session_anomaly", "indicator": label, "details": desc, "weight": weight})

    for pat, label, desc, weight in IMPOSSIBLE_TRAVEL_PATTERNS:
        if re.search(pat, combined_text, re.IGNORECASE) and not impossible_travel_flag:
            indicators.append({"category": "impossible_travel", "indicator": label, "details": desc, "weight": weight})
            impossible_travel_flag = True

    for pat, label, desc, weight in PRIVILEGE_ESCALATION_PATTERNS:
        if re.search(pat, combined_text, re.IGNORECASE):
            indicators.append({"category": "privilege_escalation", "indicator": label, "details": desc, "weight": weight})

    # Deduplicate indicators

    unique_indicators: List[Dict[str, Any]] = []
    seen = set()
    for item in indicators:
        name = item.get("indicator")
        if name and name not in seen:
            seen.add(name)
            unique_indicators.append(item)

    if not return_metrics:
        return unique_indicators

    behavioural_metrics = {
        "velocity_kmh": round(velocity_kmh, 1) if velocity_kmh is not None else None,
        "impossible_travel_flag": impossible_travel_flag,
        "failed_burst_rate_flag": failed_burst_flag,
        "mfa_fatigue_flag": mfa_fatigue_flag,
        "session_concurrency_flag": session_concurrency_flag,
        "new_device_flag": new_device_flag
    }

    return unique_indicators, behavioural_metrics


class BaseBehaviouralAnomalyModel:
    """
    Abstract base class for future ML-based behavioural anomaly detection (e.g. Isolation Forest).
    Requires a comprehensive historical authentication telemetry dataset before activation.
    """

    def __init__(self):
        self.model = None
        self.is_trained = False

    def train(self, historical_features: Any):
        raise NotImplementedError("Requires historical user behavioural baseline dataset.")

    def score_anomaly(self, feature_vector: Any) -> float:
        raise NotImplementedError("Anomaly scoring requires trained baseline model.")
