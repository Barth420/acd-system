"""
pipeline/normalizer.py — Wazuh raw alert → NormalizedAlert (Parth's schema).

This is the heart of Bhavya's pipeline. Wazuh emits messy, varied JSON;
Parth's brain only accepts the strict schema in input_schema.json.
We bridge the two here.

Strategy:
  1. Pull common fields (src_ip, dst_ip, port, rule_id, rule_description) by
     trying multiple known Wazuh field paths.
  2. Classify attack_type from rule_id ranges + rule_description keywords.
  3. Map service from destination port + URL hints.
  4. Compute features from aggregated raw events.
  5. Derive severity from rule level + rule group.

If a raw alert can't be normalized, we DROP IT (return None) — never poison the
brain with garbage. The drop is logged so we can audit later.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from .schemas import (
    AttackType,
    NormalizedAlert,
    NormalizedFeatures,
    ServiceName,
    Severity,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Field extraction helpers — Wazuh fields live in many places
# ──────────────────────────────────────────────────────────────────────────────

def _dig(d: dict, *paths: str, default: Any = None) -> Any:
    """
    Try a sequence of dotted paths against d, return first hit.
    Example: _dig(alert, "data.srcip", "agent.ip", "srcip")
    """
    for path in paths:
        cur: Any = d
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return default


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _is_valid_ipv4(ip: Optional[str]) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip))


# ──────────────────────────────────────────────────────────────────────────────
# Classification — rule_id + keywords → attack_type
# ──────────────────────────────────────────────────────────────────────────────

# Wazuh built-in rule ranges (approximate, used as hints not gospel)
SQL_KEYWORDS = re.compile(
    r"\b(union\s+select|or\s+1=1|--|;\s*drop|information_schema|sleep\s*\(|"
    r"benchmark\s*\(|xp_cmdshell|0x[0-9a-f]+)\b",
    re.IGNORECASE,
)
XSS_KEYWORDS = re.compile(
    r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]*src\s*=",
    re.IGNORECASE,
)
PORT_SCAN_HINTS = re.compile(r"port[\s_-]?scan|nmap|masscan|syn[\s_-]?scan", re.IGNORECASE)
BRUTE_FORCE_HINTS = re.compile(
    r"brute[\s_-]?force|multiple\s+failed|authentication\s+fail|password\s+guess",
    re.IGNORECASE,
)


def classify_attack(rule_id: Optional[int], rule_desc: str, payload: str) -> AttackType:
    """
    Best-effort attack classification.
    Order: explicit keywords > rule_id ranges > unknown.
    """
    haystack = f"{rule_desc} {payload}"

    if SQL_KEYWORDS.search(haystack):
        return "sql_injection"
    if XSS_KEYWORDS.search(haystack):
        return "xss"
    if BRUTE_FORCE_HINTS.search(haystack):
        return "brute_force"
    if PORT_SCAN_HINTS.search(haystack):
        return "port_scan"

    if rule_id is not None:
        # Wazuh ranges (approximate)
        if 5710 <= rule_id <= 5720:
            return "brute_force"
        if 31100 <= rule_id <= 31199:
            # Web attack family — refine by description
            if "sql" in rule_desc.lower():
                return "sql_injection"
            if "xss" in rule_desc.lower() or "script" in rule_desc.lower():
                return "xss"
        if 40100 <= rule_id <= 40110:
            return "port_scan"

    return "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Service mapping — port + url → which microservice
# ──────────────────────────────────────────────────────────────────────────────

PORT_TO_SERVICE: dict[int, ServiceName] = {
    5000: "auth_api",
    5001: "product_api",
    5432: "database",
    3306: "database",
    80: "nginx",
    443: "nginx",
    8080: "nginx",
}


def map_service(dest_port: int, url_path: str = "") -> ServiceName:
    if dest_port in PORT_TO_SERVICE:
        return PORT_TO_SERVICE[dest_port]
    # URL hints (in case nginx fronts everything on 80)
    p = url_path.lower()
    if "/auth" in p or "/login" in p:
        return "auth_api"
    if "/product" in p or "/api/items" in p:
        return "product_api"
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Severity derivation — Wazuh rule level → our enum
# ──────────────────────────────────────────────────────────────────────────────

def derive_severity(rule_level: int) -> Severity:
    if rule_level >= 12:
        return "critical"
    if rule_level >= 9:
        return "high"
    if rule_level >= 5:
        return "medium"
    return "low"


# ──────────────────────────────────────────────────────────────────────────────
# Feature extraction — derive ML features from raw event window
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(raw: dict, attack_type: AttackType) -> NormalizedFeatures:
    """
    Pull/compute the 6 ML features. For single-event alerts we estimate;
    for aggregated alerts (event_count > 1) we use the actual counters.
    """
    event_count = _to_int(_dig(raw, "data.event_count", "event_count"), 1)

    # request_rate: events / (time_window in minutes). Wazuh aggregates over ~1min by default.
    rate = float(event_count)  # treat as per-minute by convention

    failed_auth = _to_int(_dig(raw, "data.failed_attempts", "failed_attempts"), 0)
    if attack_type == "brute_force" and failed_auth == 0:
        # Brute force with no explicit counter: use event count as proxy
        failed_auth = event_count

    payload = str(_dig(raw, "data.url", "data.payload", "full_log", default=""))
    sql_kw = bool(SQL_KEYWORDS.search(payload))

    user_agent = str(_dig(raw, "data.user_agent", "agent.ua", default=""))
    ua_anomaly = (
        not user_agent
        or "curl" in user_agent.lower()
        or "python" in user_agent.lower()
        or "nikto" in user_agent.lower()
        or "sqlmap" in user_agent.lower()
        or "nmap" in user_agent.lower()
    )

    # geo_anomaly: in a real system we'd MaxMind-lookup the source IP.
    # For Phase 1: flag any non-RFC1918 source as a coarse anomaly proxy.
    src_ip = _dig(raw, "data.srcip", "srcip", default="0.0.0.0")
    geo_anom = not _is_rfc1918(src_ip)

    paths_accessed = _to_int(_dig(raw, "data.unique_paths", "unique_paths"), 1)
    if attack_type == "port_scan":
        # Port scans hit many destinations; treat events as path proxy
        paths_accessed = max(paths_accessed, event_count)

    return NormalizedFeatures(
        request_rate_per_min=rate,
        unique_paths_accessed=paths_accessed,
        failed_auth_count=failed_auth,
        payload_contains_sql_keywords=sql_kw,
        user_agent_anomaly=ua_anomaly,
        geo_anomaly=geo_anom,
    )


def _is_rfc1918(ip: str) -> bool:
    if not _is_valid_ipv4(ip):
        return False
    parts = [int(p) for p in ip.split(".")]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def normalize_wazuh_alert(raw: dict) -> Optional[NormalizedAlert]:
    """
    Convert a raw Wazuh alert dict into a NormalizedAlert.
    Returns None if the alert can't be normalized (logs the reason).
    """
    rule_id = _to_int(_dig(raw, "rule.id", "rule_id"), 0) or None
    rule_desc = str(_dig(raw, "rule.description", "rule_desc", default=""))
    rule_level = _to_int(_dig(raw, "rule.level", "level"), 0)

    src_ip = str(_dig(raw, "data.srcip", "srcip", default=""))
    dst_ip = str(_dig(raw, "data.dstip", "agent.ip", "dstip", default="0.0.0.0"))

    if not _is_valid_ipv4(src_ip):
        logger.warning(f"Dropping alert — invalid src_ip: {src_ip!r} (rule_id={rule_id})")
        return None
    if not _is_valid_ipv4(dst_ip):
        # Default the destination to the agent's IP if available, else loopback
        dst_ip = "127.0.0.1"

    dst_port = _to_int(_dig(raw, "data.dstport", "dstport"), 0)
    if dst_port == 0:
        # Try to infer from URL/service hints
        url = str(_dig(raw, "data.url", default=""))
        if ":5000" in url:
            dst_port = 5000
        elif ":5001" in url:
            dst_port = 5001
        else:
            dst_port = 80  # last resort

    payload = str(_dig(raw, "data.url", "data.payload", "full_log", default=""))
    attack_type = classify_attack(rule_id, rule_desc, payload)
    service = map_service(dst_port, payload)
    severity = derive_severity(rule_level)
    features = extract_features(raw, attack_type)

    # Timestamp normalization — Wazuh uses several formats
    ts_raw = str(_dig(raw, "timestamp", "@timestamp", default=""))
    ts_norm = _normalize_timestamp(ts_raw)

    raw_event_count = _to_int(_dig(raw, "data.event_count", "event_count"), 1)
    if raw_event_count < 1:
        raw_event_count = 1

    try:
        return NormalizedAlert(
            alert_id=NormalizedAlert.new_alert_id(),
            timestamp=ts_norm,
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=dst_port,
            service=service,
            attack_type=attack_type,
            severity=severity,
            raw_event_count=raw_event_count,
            features=features,
            wazuh_rule_id=rule_id,
            wazuh_rule_description=rule_desc or None,
        )
    except Exception as e:
        logger.error(f"Normalization failed: {e}", exc_info=True)
        return None


def _normalize_timestamp(ts: str) -> str:
    """Coerce any reasonable timestamp into `YYYY-MM-DDTHH:MM:SSZ` UTC."""
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        # Wazuh sometimes uses "2024-11-15T08:23:11.123+0000" — strip subsecond
        cleaned = re.sub(r"\.\d+", "", ts)
        try:
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            logger.warning(f"Unparseable timestamp {ts!r} — using now()")
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
