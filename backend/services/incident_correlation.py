"""
CYBERGUARD Incident Correlation Service

Provides deterministic, explainable similarity correlation between security incidents.
Analyzes observable telemetry signals:
1. Same threat type / category
2. Same domain or hostname
3. Same exact URL
4. Same sender or user identifier
5. Shared security evidence indicators
6. Temporal proximity within a configurable time window

Deterministic heuristic scoring only: Does NOT introduce an LLM or graph database,
and does NOT claim proof of a coordinated attack campaign.
"""

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urlparse

# =====================================================================
# Configuration Parameters (Deterministic & Configurable)
# =====================================================================

DEFAULT_CORRELATION_WEIGHTS: Dict[str, int] = {
    "same_exact_url": 40,
    "same_domain": 35,
    "same_sender": 30,
    "same_threat_type": 25,
    "same_ip": 25,
    "same_user": 20,
    "shared_indicators": 10,
    "recent_occurrence": 10,
}

DEFAULT_TIME_WINDOW_HOURS: float = 24.0
DEFAULT_CORRELATION_THRESHOLD: int = 30


# =====================================================================
# Helper Extraction Functions
# =====================================================================

def extract_domain_from_text(text: Optional[str]) -> Optional[str]:
    """Safely extracts a lowercase domain or hostname from a URL, email, or hostname string."""
    if not text or not isinstance(text, str):
        return None
    cleaned = text.strip().lower()

    if "@" in cleaned:
        parts = cleaned.split("@")
        if len(parts) > 1 and "." in parts[-1]:
            dom = parts[-1].strip().split("/")[0]
            return dom.lstrip("www.")

    try:
        target = cleaned if "://" in cleaned else "http://" + cleaned
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        if host:
            return host.lstrip("www.")
    except Exception:
        pass

    if "." in cleaned and not cleaned.startswith("http"):
        return cleaned.split("/")[0].lstrip("www.")

    return None


def parse_iso_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Safely parses an ISO 8601 timestamp string into a datetime object with UTC timezone."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        cleaned = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def extract_incident_features(incident: Any) -> Dict[str, Any]:
    """Extracts comparable normalized features from an Incident object or dictionary."""
    if isinstance(incident, dict):
        inc_id = incident.get("incident_id", "")
        threat_type = (incident.get("threat_type") or "").strip().lower()
        timestamp = incident.get("timestamp")
        source = incident.get("source_data") or {}
        evidence = incident.get("evidence") or []
    else:
        inc_id = getattr(incident, "incident_id", "")
        threat_type = (getattr(incident, "threat_type", "") or "").strip().lower()
        timestamp = getattr(incident, "timestamp", None)
        source = getattr(incident, "source_data", None) or {}
        evidence = getattr(incident, "evidence", []) or []

    # 1. Exact URL
    url = (source.get("url") or source.get("target_url") or "").strip().lower()

    # 2. Domain
    domain = (source.get("domain") or source.get("target_domain") or "").strip().lower()
    if not domain and url:
        domain = extract_domain_from_text(url) or ""
    if not domain and source.get("sender"):
        domain = extract_domain_from_text(source.get("sender")) or ""

    # 3. Sender
    sender = (source.get("sender") or source.get("from_address") or "").strip().lower()

    # 4. User / Account
    user = (source.get("username") or source.get("account") or source.get("user") or "").strip().lower()
    if user in ["unknown", "unknown_user", "none", ""]:
        user = ""

    # 5. IP Address
    ip = (source.get("ip_address") or source.get("ip") or "").strip().lower()
    if ip in ["127.0.0.1", "localhost", "0.0.0.0", "none", "unknown", ""]:
        ip = ""

    # 6. Evidence Indicator Names
    indicator_set = set()
    for ev in evidence:
        if isinstance(ev, dict):
            ind = ev.get("indicator")
        else:
            ind = getattr(ev, "indicator", None)
        if ind and isinstance(ind, str) and ind.strip():
            indicator_set.add(ind.strip().lower())

    return {
        "incident_id": inc_id,
        "threat_type": threat_type,
        "timestamp": timestamp,
        "timestamp_dt": parse_iso_timestamp(timestamp),
        "url": url,
        "domain": domain,
        "sender": sender,
        "user": user,
        "ip": ip,
        "indicators": indicator_set
    }


# =====================================================================
# Pairwise Similarity Function
# =====================================================================

def calculate_incident_pair_similarity(
    feat_a: Dict[str, Any],
    feat_b: Dict[str, Any],
    weights: Optional[Dict[str, int]] = None,
    time_window_hours: float = DEFAULT_TIME_WINDOW_HOURS
) -> Tuple[int, List[str], str]:
    """
    Computes a deterministic similarity score (0-100) and matched signals between two incidents.
    """
    w = weights or DEFAULT_CORRELATION_WEIGHTS
    matched_signals: List[str] = []
    score = 0

    # Signal 1: Same Exact URL
    if feat_a["url"] and feat_b["url"] and feat_a["url"] == feat_b["url"]:
        score += w.get("same_exact_url", 40)
        matched_signals.append("same_exact_url")

    # Signal 2: Same Domain / Hostname
    if feat_a["domain"] and feat_b["domain"] and feat_a["domain"] == feat_b["domain"]:
        score += w.get("same_domain", 35)
        matched_signals.append("same_domain")

    # Signal 3: Same Sender
    if feat_a["sender"] and feat_b["sender"] and feat_a["sender"] == feat_b["sender"]:
        score += w.get("same_sender", 30)
        matched_signals.append("same_sender")

    # Signal 4: Same Threat Type / Category
    if feat_a["threat_type"] and feat_b["threat_type"] and feat_a["threat_type"] == feat_b["threat_type"]:
        score += w.get("same_threat_type", 25)
        matched_signals.append("same_threat_type")

    # Signal 5: Same IP Address
    if feat_a["ip"] and feat_b["ip"] and feat_a["ip"] == feat_b["ip"]:
        score += w.get("same_ip", 25)
        matched_signals.append("same_ip")

    # Signal 6: Same User Account
    if feat_a["user"] and feat_b["user"] and feat_a["user"] == feat_b["user"]:
        score += w.get("same_user", 20)
        matched_signals.append("same_user")

    # Signal 7: Shared Security Indicators
    common_indicators = feat_a["indicators"].intersection(feat_b["indicators"])
    if common_indicators:
        score += w.get("shared_indicators", 10)
        matched_signals.append("shared_indicators")

    # Signal 8: Temporal Proximity
    # Awarded when incidents occur within the configured time window.
    # Temporal proximity is a contextual amplifier that requires at least one primary entity
    # or indicator signal (URL, domain, sender, user, IP, or shared indicators) so two completely
    # distinct incidents of a generic threat category are not falsely correlated.
    has_substantive_match = (
        "same_exact_url" in matched_signals
        or "same_domain" in matched_signals
        or "same_sender" in matched_signals
        or "same_ip" in matched_signals
        or "same_user" in matched_signals
        or "shared_indicators" in matched_signals
    )
    if has_substantive_match and feat_a["timestamp_dt"] and feat_b["timestamp_dt"]:
        diff_seconds = abs((feat_a["timestamp_dt"] - feat_b["timestamp_dt"]).total_seconds())
        if diff_seconds <= time_window_hours * 3600:
            score += w.get("recent_occurrence", 10)
            matched_signals.append("recent_occurrence")

    final_score = min(100, score)

    # Explainable relationship summary
    human_signals = []
    if "same_exact_url" in matched_signals:
        human_signals.append("exact URL match")
    elif "same_domain" in matched_signals:
        human_signals.append(f"shared domain '{feat_a['domain']}'")
    if "same_sender" in matched_signals:
        human_signals.append(f"sender '{feat_a['sender']}'")
    if "same_user" in matched_signals:
        human_signals.append(f"user account '{feat_a['user']}'")
    if "same_threat_type" in matched_signals:
        human_signals.append(f"same threat category ({feat_a['threat_type']})")
    if "shared_indicators" in matched_signals:
        human_signals.append(f"{len(common_indicators)} shared indicator(s)")
    if "recent_occurrence" in matched_signals:
        human_signals.append("recent temporal proximity")

    reason = f"Potentially related activity: {', '.join(human_signals)}." if human_signals else "No significant relationship."
    return final_score, matched_signals, reason


# =====================================================================
# Main Correlation Function
# =====================================================================

def find_related_incidents(
    current_incident: Any,
    existing_incidents: List[Any],
    time_window_hours: float = DEFAULT_TIME_WINDOW_HOURS,
    threshold: int = DEFAULT_CORRELATION_THRESHOLD,
    weights: Optional[Dict[str, int]] = None
) -> Dict[str, Any]:
    """
    Compares the current incident against a corpus of existing incidents and identifies
    potentially related incidents based on deterministic telemetry signals.
    """
    feat_curr = extract_incident_features(current_incident)
    curr_id = feat_curr["incident_id"]

    related_matches: List[Dict[str, Any]] = []
    all_matched_signals_set: Set[str] = set()
    highest_score = 0

    for prev in existing_incidents:
        feat_prev = extract_incident_features(prev)
        prev_id = feat_prev["incident_id"]

        # Do not compare an incident against itself
        if prev_id and curr_id and prev_id == curr_id:
            continue

        score, signals, reason = calculate_incident_pair_similarity(
            feat_curr,
            feat_prev,
            weights=weights,
            time_window_hours=time_window_hours
        )

        if score >= threshold:
            related_matches.append({
                "incident_id": prev_id,
                "threat_type": feat_prev["threat_type"].title() if feat_prev["threat_type"] else "Unknown",
                "correlation_score": score,
                "matched_signals": signals,
                "timestamp": feat_prev.get("timestamp"),
                "reason": reason
            })
            for s in signals:
                all_matched_signals_set.add(s)
            if score > highest_score:
                highest_score = score

    # Sort matches by highest correlation score first
    related_matches.sort(key=lambda x: x["correlation_score"], reverse=True)
    related_ids = [m["incident_id"] for m in related_matches if m.get("incident_id")]

    is_related = len(related_ids) > 0

    # Build human-readable synthesis explanation
    if is_related:
        signal_descriptions = []
        if "same_exact_url" in all_matched_signals_set:
            signal_descriptions.append("exact target URL")
        if "same_domain" in all_matched_signals_set:
            signal_descriptions.append(f"domain '{feat_curr['domain']}'" if feat_curr['domain'] else "shared domain")
        if "same_sender" in all_matched_signals_set:
            signal_descriptions.append("sender origin")
        if "same_user" in all_matched_signals_set:
            signal_descriptions.append("targeted user account")
        if "same_threat_type" in all_matched_signals_set:
            signal_descriptions.append(f"{feat_curr['threat_type'].title()} threat category" if feat_curr['threat_type'] else "threat category")
        if "shared_indicators" in all_matched_signals_set:
            signal_descriptions.append("common technical indicators")
        if "recent_occurrence" in all_matched_signals_set:
            signal_descriptions.append(f"occurrences within {int(time_window_hours)}h window")

        signals_text = ", ".join(signal_descriptions) if signal_descriptions else "shared technical telemetry"
        reason_text = (
            f"Potentially related activity detected across {len(related_ids)} previous incident(s) "
            f"({', '.join(related_ids[:3])}{'...' if len(related_ids) > 3 else ''}) "
            f"sharing {signals_text}. This indicates observable telemetry similarity, not a confirmed coordinated attack."
        )
    else:
        reason_text = "No significant relationship found with previous recorded incidents based on observable telemetry."

    return {
        "related": is_related,
        "correlation_score": highest_score,
        "matched_signals": sorted(list(all_matched_signals_set)),
        "related_incident_ids": related_ids,
        "reason": reason_text,
        "relationships": related_matches,
        "related_incidents": related_matches
    }


# =====================================================================
# Entity Pivot & Attack Progression Helpers
# =====================================================================

def extract_incident_pivots(incident: Any) -> Dict[str, Set[str]]:
    """Extracts concrete pivot entities (accounts, ips, domains, senders) from an incident."""
    pivots: Dict[str, Set[str]] = {
        "accounts": set(),
        "ips": set(),
        "domains": set(),
        "senders": set()
    }

    if isinstance(incident, dict):
        source = incident.get("source_data") or {}
        evidence = incident.get("evidence") or []
    else:
        source = getattr(incident, "source_data", None) or {}
        evidence = getattr(incident, "evidence", []) or []

    # 1. Accounts
    user = source.get("username") or source.get("account") or source.get("user")
    if user and isinstance(user, str) and user.strip() and user.lower() not in ("unknown_user", "unknown", "none"):
        pivots["accounts"].add(user.strip().lower())

    # 2. Senders
    sender = source.get("sender") or source.get("from_address")
    if sender and isinstance(sender, str) and sender.strip():
        pivots["senders"].add(sender.strip().lower())
        dom = extract_domain_from_text(sender)
        if dom:
            pivots["domains"].add(dom)

    # 3. URLs and Domains
    url = source.get("url") or source.get("target_url")
    if url and isinstance(url, str) and url.strip():
        dom = extract_domain_from_text(url)
        if dom:
            pivots["domains"].add(dom)

    target_domain = source.get("target_domain") or source.get("domain")
    if target_domain and isinstance(target_domain, str) and target_domain.strip():
        pivots["domains"].add(target_domain.strip().lower())

    # 4. IP Addresses
    ip = source.get("ip_address") or source.get("ip")
    if ip and isinstance(ip, str) and ip.strip() and ip not in ("127.0.0.1", "localhost", "none", "unknown"):
        pivots["ips"].add(ip.strip().lower())

    # 5. Extract from Evidence Items
    for ev in evidence:
        details = (ev.get("details", "") if isinstance(ev, dict) else getattr(ev, "details", "")).lower()
        if not details:
            continue
        for match in re.finditer(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)", details):
            d = match.group(1).lower()
            if not any(d.endswith(ext) for ext in (".exe", ".dll", ".png", ".jpg", ".jpeg", ".gif")):
                pivots["domains"].add(d)
        for match in re.finditer(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", details):
            matched_ip = match.group(0)
            if matched_ip not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                pivots["ips"].add(matched_ip)

    return pivots


def extract_shared_pivots(target_incident: Any, related_incidents: List[Any]) -> List[Dict[str, Any]]:
    """Identifies shared entity pivots across target and related incidents."""
    target_id = target_incident.get("incident_id") if isinstance(target_incident, dict) else getattr(target_incident, "incident_id", "")
    target_pivots = extract_incident_pivots(target_incident)

    shared_entities: List[Dict[str, Any]] = []
    seen_entity_keys: Set[str] = set()

    for inc in related_incidents:
        inc_id = inc.get("incident_id") if isinstance(inc, dict) else getattr(inc, "incident_id", "")
        if inc_id == target_id:
            continue
        inc_pivots = extract_incident_pivots(inc)

        for pivot_type in ("accounts", "ips", "domains", "senders"):
            common = target_pivots[pivot_type].intersection(inc_pivots[pivot_type])
            for val in common:
                ent_key = f"{pivot_type}:{val}"
                if ent_key not in seen_entity_keys:
                    seen_entity_keys.add(ent_key)
                    shared_entities.append({
                        "type": pivot_type[:-1].title(),
                        "value": val,
                        "matching_incidents": [target_id, inc_id]
                    })
                else:
                    for se in shared_entities:
                        if se["type"] == pivot_type[:-1].title() and se["value"] == val:
                            if inc_id not in se["matching_incidents"]:
                                se["matching_incidents"].append(inc_id)

    return shared_entities


def build_attack_chain(target_incident: Any, related_incidents: List[Any]) -> List[Dict[str, Any]]:
    """Synthesizes a chronological progression of potentially related activity."""
    all_involved = [target_incident] + list(related_incidents)
    # Deduplicate by incident_id
    seen_ids = set()
    deduped = []
    for inc in all_involved:
        inc_id = inc.get("incident_id") if isinstance(inc, dict) else getattr(inc, "incident_id", "")
        if inc_id and inc_id not in seen_ids:
            seen_ids.add(inc_id)
            deduped.append(inc)

    def get_ts(item):
        return (item.get("timestamp") if isinstance(item, dict) else getattr(item, "timestamp", None)) or ""

    deduped.sort(key=get_ts)

    attack_chain: List[Dict[str, Any]] = []
    for step_idx, inc in enumerate(deduped, start=1):
        if isinstance(inc, dict):
            attack_chain.append({
                "step_order": step_idx,
                "incident_id": inc.get("incident_id", ""),
                "threat_type": inc.get("threat_type", ""),
                "classification": inc.get("classification", ""),
                "timestamp": inc.get("timestamp"),
                "risk_level": inc.get("risk_level", "")
            })
        else:
            attack_chain.append({
                "step_order": step_idx,
                "incident_id": getattr(inc, "incident_id", ""),
                "threat_type": getattr(inc, "threat_type", ""),
                "classification": getattr(inc, "classification", ""),
                "timestamp": getattr(inc, "timestamp", None),
                "risk_level": getattr(inc, "risk_level", "")
            })

    return attack_chain


def correlate_incident_with_corpus(
    target_incident: Any,
    incident_corpus: List[Any],
    time_window_hours: float = DEFAULT_TIME_WINDOW_HOURS,
    threshold: int = DEFAULT_CORRELATION_THRESHOLD
) -> Dict[str, Any]:
    """
    Canonical end-to-end correlation function for CYBERGUARD.
    Executes deterministic similarity analysis and enriches with shared entity pivots and chronological attack progression.
    """
    target_id = target_incident.get("incident_id") if isinstance(target_incident, dict) else getattr(target_incident, "incident_id", "")
    corr_res = find_related_incidents(
        current_incident=target_incident,
        existing_incidents=incident_corpus,
        time_window_hours=time_window_hours,
        threshold=threshold
    )

    # Locate actual incident objects for related matches to extract pivots & attack chain
    related_id_set = set(corr_res["related_incident_ids"])
    related_incident_objs = [
        inc for inc in incident_corpus
        if (inc.get("incident_id") if isinstance(inc, dict) else getattr(inc, "incident_id", "")) in related_id_set
    ]

    pivots = extract_shared_pivots(target_incident, related_incident_objs)
    attack_chain = build_attack_chain(target_incident, related_incident_objs)

    return {
        "incident_id": target_id,
        "correlation": {
            "related": corr_res["related"],
            "correlation_score": corr_res["correlation_score"],
            "matched_signals": corr_res["matched_signals"],
            "related_incident_ids": corr_res["related_incident_ids"],
            "reason": corr_res["reason"],
            "relationships": corr_res["relationships"]
        },
        "related_incidents": corr_res["relationships"],
        "pivots": pivots,
        "attack_chain": attack_chain,
        # Legacy compatibility fields
        "target_incident_id": target_id,
        "has_correlations": corr_res["related"],
        "shared_entities": pivots,
        "correlation_explanation": corr_res["reason"]
    }
