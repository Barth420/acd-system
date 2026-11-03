"""
rules.py: log line -> RawAlert (contract D, Wazuh custom rule ids).

The rule ORDER and conditions mirror vitrag/hierarchy/wazuh/local_rules.xml, so the Python forwarder and Wazuh pick the same
rule id for the same log line. tests/test_v4_forwarder.py replays one real log through both (a small evaluator of the XML
subset used here) and compares. Wazuh semantics mirrored: first matching top-level rule wins; a frequency child replaces its
parent once `count >= frequency` same-source events are inside `timeframe`.

  100710/100711/100712  brute force      AUTH_FAILURE lines (5 in 60 s / 20 in 120 s from one source)
  100103/100105         SQL injection    SQL_ERROR | SQLI_ATTEMPT lines (5 in 30 s aggregated)
  100106                XSS              XSS_ATTEMPT lines
  100301                dependency abuse / credential reuse   CREDENTIAL_REUSE | DEPENDENCY_ABUSE | SESSION_REUSE lines
  100302                unauthorized internal admin access    LATERAL_DB_ACCESS lines
  100303                data exfiltration volume anomaly      DATA_EXFIL lines
  100201/100202         reconnaissance   scanner user agents (50 in 30 s aggregated)
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Optional

import controlstate as cs

LOG_SERVICE = {"auth/auth.log": "auth_api", "product/product.log": "product_api", "order/order.log": "order_api",
               "search/search.log": "search_api", "queue/queue.log": "queue", "nginx/access.log": "nginx"}

DESC = {
    100710: ("auth_api: Failed login attempt.", 5),
    100711: ("auth_api: Multiple failed logins from same IP (brute force).", 10),
    100712: ("auth_api: Sustained brute force attack from single IP.", 12),
    100103: ("Web attack: SQL injection attempt detected.", 11),
    100105: ("Web attack: repeated SQL injection attempts from single IP.", 12),
    100106: ("Web attack: XSS attempt detected.", 9),
    100301: ("Dependency abuse or credential reuse detected.", 10),
    100302: ("Unauthorized internal admin access.", 11),
    100303: ("Data exfiltration volume anomaly.", 12),
    100201: ("Reconnaissance tool signature detected.", 8),
    100202: ("Sustained reconnaissance from single IP.", 10),
}
# (child rule, parent events counted, frequency, timeframe seconds)
FREQ = {100712: (100710, 20, 120), 100711: (100710, 5, 60), 100105: (100103, 5, 30), 100202: (100201, 50, 30)}

SQLI_RE = re.compile(r"SQL_ERROR|SQLI_ATTEMPT")
CRED_RE = re.compile(r"CREDENTIAL_REUSE|DEPENDENCY_ABUSE|SESSION_REUSE")
RECON_RE = re.compile(r"nmap|masscan|Nikto|sqlmap")
SRC_RE = re.compile(r"src_ip=(\S+)")
RID_RE = re.compile(r"rid=(\S+)")
UA_RE = re.compile(r"ua=('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\S+)")
NGINX_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d+) \S+ "[^"]*" "([^"]*)"')
SVC_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})")


def parse_ts(line: str) -> Optional[float]:
    m = SVC_TS.match(line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp() + int(m.group(2)) / 1000
    m = re.search(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\]", line)
    if m:
        return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return None


def _ua(line: str) -> str:
    m = UA_RE.search(line)
    return m.group(1).strip("'\"") if m else ""


class Detector:
    def __init__(self) -> None:
        self.win: dict[tuple[int, str], deque[float]] = defaultdict(deque)

    def _count(self, parent: int, src: str, now: float, window: int) -> int:
        q = self.win[(parent, src)]
        while q and q[0] < now - window:
            q.popleft()
        return len(q)

    def _hit(self, parent: int, src: str, now: float) -> None:
        self.win[(parent, src)].append(now)

    def _final(self, base: int, src: str, now: float) -> tuple[int, int]:
        """Record a base-rule event, return (rule id that fires for it, events counted in the window)."""
        self._hit(base, src, now)
        for child, (parent, freq, tf) in FREQ.items():     # dict order = file order (specific child first)
            if parent == base:
                n = self._count(parent, src, now, tf)
                if n >= freq:
                    return child, n
        return base, 1

    def process(self, logkey: str, line: str, now: Optional[float] = None) -> list[dict[str, Any]]:
        service = LOG_SERVICE.get(logkey)
        if service is None:
            return []
        now = parse_ts(line) or now or time.time()
        if service == "nginx":
            m = NGINX_RE.match(line)
            src, ua, url = (m.group(1), m.group(6), m.group(4)) if m else ("", "", "")
        else:
            m = SRC_RE.search(line)
            src, ua, url = (m.group(1) if m else ""), _ua(line), ""
        rids = RID_RE.findall(line)
        rid = rids[-1] if rids else None            # the service appends the real id LAST; earlier text may be attacker-controlled
        base, count, target = None, 1, service
        if "AUTH_FAILURE user=" in line:
            base = 100710
        elif SQLI_RE.search(line):
            base = 100103
            m2 = re.search(r"payload=('(?:[^'\\]|\\.)*'|\S+)|query=('(?:[^'\\]|\\.)*')", line)
            url = (m2.group(1) or m2.group(2)).strip("'") if m2 else ""
        elif "XSS_ATTEMPT" in line:
            base = 100106
        elif CRED_RE.search(line):
            base = 100301
        elif "LATERAL_DB_ACCESS" in line:
            base, target = 100302, "database"
        elif "DATA_EXFIL" in line:
            base, target = 100303, "database"
        elif RECON_RE.search(line):
            base = 100201
        if base is None or not src:
            return []
        rule = base
        if base in (100710, 100103, 100201):
            rule, count = self._final(base, src, now)
        desc, level = DESC[rule]
        ts = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return [{
            "source": "wazuh", "timestamp": ts,
            "raw_data": {
                "rule": {"id": rule, "level": level, "description": desc},
                "data": {"srcip": src, "dstip": "127.0.0.1", "dstport": cs.PORTS[target], "event_count": count,
                         "failed_attempts": count if base == 100710 else 0, "user_agent": ua, "url": url,
                         "request_id": rid, "source_service": service},
                "timestamp": ts,
            },
        }]
