"""
forwarder_minimal/forwarder.py — Log-watching forwarder for MINIMAL MODE.

Replaces Wazuh in minimal mode. Tails the application log files and emits
Wazuh-shaped alerts to Bhavya's /alerts endpoint when attack patterns match.

The output JSON is byte-identical to what the real Wazuh forwarder produces,
so Bhavya's pipeline can't tell the difference.

Detection rules (mirror the rules in vitrag/wazuh/local_rules.xml):
  - Brute force: 5+ AUTH_FAILURE entries from same IP in 60s   → rule 5711, level 10
                 20+ entries in 120s                            → rule 5712, level 12
  - SQL injection: SQL_ERROR or sqlmap UA in product log       → rule 31103, level 11
  - Port scan: nmap/nikto/masscan UA in nginx access log       → rule 40101, level 8
               50+ probes from same IP in 30s                   → rule 40102, level 10

Run inside Docker compose, or locally for testing:
    BHAVYA_API=http://localhost:8000/alerts python forwarder.py
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] log-forwarder — %(message)s",
)
log = logging.getLogger("log_forwarder")


# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

BHAVYA_API = os.getenv("BHAVYA_API", "http://localhost:8000/alerts")
BHAVYA_HEALTHZ = os.getenv("BHAVYA_HEALTHZ", "http://localhost:8000/healthz")

AUTH_LOG = Path(os.getenv("AUTH_LOG", "/shared_logs/auth/auth.log"))
PRODUCT_LOG = Path(os.getenv("PRODUCT_LOG", "/shared_logs/product/product.log"))
NGINX_LOG = Path(os.getenv("NGINX_LOG", "/shared_logs/nginx/access.log"))

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.3"))


# ──────────────────────────────────────────────────────────────────────────────
# Sliding-window aggregator (for brute-force / port-scan detection)
# ──────────────────────────────────────────────────────────────────────────────

class SlidingWindow:
    """Keeps timestamps per source IP, tells you how many fall in the last N seconds."""

    def __init__(self):
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def add(self, src_ip: str) -> None:
        self._events[src_ip].append(time.time())

    def count_in(self, src_ip: str, window_s: float) -> int:
        cutoff = time.time() - window_s
        q = self._events.get(src_ip)
        if not q:
            return 0
        # Trim old entries
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)


auth_failures = SlidingWindow()
nginx_probes = SlidingWindow()


# ──────────────────────────────────────────────────────────────────────────────
# Wazuh-shaped alert builder
# ──────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def post_alert(
    rule_id: int,
    rule_level: int,
    rule_desc: str,
    srcip: str,
    dstip: str,
    dstport: int,
    *,
    event_count: int = 1,
    failed_attempts: int = 0,
    user_agent: str = "",
    url: str = "",
    session: Optional[requests.Session] = None,
) -> bool:
    """
    Build a RawAlert payload that's byte-identical to the real Wazuh
    forwarder's output, then POST it to Bhavya's /alerts.
    """
    payload = {
        "source": "wazuh",  # Bhavya's schema requires "wazuh" or "manual_test"
        "timestamp": _now_iso(),
        "raw_data": {
            "rule": {
                "id": rule_id,
                "level": rule_level,
                "description": rule_desc,
            },
            "data": {
                "srcip": srcip,
                "dstip": dstip,
                "dstport": dstport,
                "event_count": event_count,
                "failed_attempts": failed_attempts,
                "user_agent": user_agent,
                "url": url,
            },
            "timestamp": _now_iso(),
        },
    }

    s = session or requests
    try:
        r = s.post(BHAVYA_API, json=payload, timeout=10)
    except requests.RequestException as e:
        log.warning(f"POST failed: {e}")
        return False

    if 200 <= r.status_code < 300:
        body = r.json()
        log.info(
            f"→ {body.get('attack_type'):>14s} "
            f"service={body.get('service'):<11s} "
            f"severity={body.get('severity'):<8s} "
            f"src={srcip}"
        )
        return True

    if r.status_code == 422:
        log.debug(f"Pipeline dropped alert (422): {r.text[:200]}")
        return False

    log.warning(f"Unexpected status {r.status_code}: {r.text[:200]}")
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Per-log-file detectors
# ──────────────────────────────────────────────────────────────────────────────

# Match the format produced by lab/auth_api/app.py:
#   "AUTH_FAILURE user=alice src_ip=1.2.3.4 ua='curl/...' reason=invalid_credentials"
AUTH_FAIL_RE = re.compile(
    r"AUTH_FAILURE\s+user=(\S+)\s+src_ip=(\S+)\s+ua=['\"]?(.*?)['\"]?\s+reason="
)

# Match: "SQL_ERROR src_ip=1.2.3.4 ua='sqlmap/...' query='...' err=..."
SQL_ERROR_RE = re.compile(r"SQL_ERROR\s+src_ip=(\S+)\s+ua=['\"]?(.*?)['\"]?\s+query=")

# product_api search/query log lines that contain SQL keywords directly
PRODUCT_QUERY_RE = re.compile(
    r"PRODUCT_QUERY\s+src_ip=(\S+)\s+ua=['\"]?(.*?)['\"]?\s+query=['\"](.*?)['\"]"
)

# nginx detailed access log:
# 1.2.3.4 - - [..] "GET /path HTTP/1.1" 200 ... "ref" "User-Agent" "X-Forwarded-For" "request_body"
NGINX_RE = re.compile(
    r'^(\S+) \S+ \S+ \[[^\]]+\] '
    r'"(\S+) (\S+) \S+" (\d+) \S+ '
    r'"[^"]*" "([^"]*)"'
)

SQL_KEYWORDS = re.compile(
    r"\b(union\s+select|or\s+1=1|--|;\s*drop|information_schema|sleep\s*\(|"
    r"benchmark\s*\(|0x[0-9a-f]+)\b",
    re.IGNORECASE,
)
SCANNER_UA = re.compile(r"nmap|masscan|nikto|sqlmap|openvas", re.IGNORECASE)
XSS_RE = re.compile(r"<\s*script|javascript:|onerror\s*=", re.IGNORECASE)


def handle_auth_line(line: str, session: requests.Session) -> None:
    m = AUTH_FAIL_RE.search(line)
    if not m:
        return
    user, srcip, ua = m.group(1), m.group(2), m.group(3)
    auth_failures.add(srcip)
    count_60s = auth_failures.count_in(srcip, 60)
    count_120s = auth_failures.count_in(srcip, 120)

    if count_120s >= 20:
        post_alert(
            5712, 12, "auth_api: Sustained brute force attack from single IP.",
            srcip=srcip, dstip="10.0.0.5", dstport=5000,
            event_count=count_120s, failed_attempts=count_120s,
            user_agent=ua, url="/auth/login", session=session,
        )
    elif count_60s >= 5:
        post_alert(
            5711, 10, "auth_api: Multiple failed logins from same source IP.",
            srcip=srcip, dstip="10.0.0.5", dstport=5000,
            event_count=count_60s, failed_attempts=count_60s,
            user_agent=ua, url="/auth/login", session=session,
        )


def handle_product_line(line: str, session: requests.Session) -> None:
    # SQL error → certain SQLi
    m = SQL_ERROR_RE.search(line)
    if m:
        srcip, ua = m.group(1), m.group(2)
        post_alert(
            31103, 11, "Web attack: SQL injection attempt detected (SQL error).",
            srcip=srcip, dstip="10.0.0.5", dstport=5001,
            event_count=1, user_agent=ua,
            url="/api/products?id=injected", session=session,
        )
        return

    # Query line that contains SQL keywords or scanner UA → likely SQLi attempt
    m = PRODUCT_QUERY_RE.search(line)
    if m:
        srcip, ua, query = m.group(1), m.group(2), m.group(3)
        if SQL_KEYWORDS.search(query) or SCANNER_UA.search(ua):
            post_alert(
                31103, 11, "Web attack: SQL injection signature in query.",
                srcip=srcip, dstip="10.0.0.5", dstport=5001,
                event_count=1, user_agent=ua, url=query, session=session,
            )
        elif XSS_RE.search(query):
            post_alert(
                31105, 9, "Web attack: XSS signature in query.",
                srcip=srcip, dstip="10.0.0.5", dstport=5001,
                event_count=1, user_agent=ua, url=query, session=session,
            )


def handle_nginx_line(line: str, session: requests.Session) -> None:
    m = NGINX_RE.match(line)
    if not m:
        return
    srcip = m.group(1)
    path = m.group(3)
    ua = m.group(5)

    # Scanner UA → port_scan-class alert
    if SCANNER_UA.search(ua):
        nginx_probes.add(srcip)
        count_30s = nginx_probes.count_in(srcip, 30)

        if count_30s >= 50:
            post_alert(
                40102, 10, "Sustained reconnaissance from single IP.",
                srcip=srcip, dstip="10.0.0.5", dstport=80,
                event_count=count_30s, user_agent=ua, url=path, session=session,
            )
        else:
            post_alert(
                40101, 8, "Reconnaissance tool signature in User-Agent.",
                srcip=srcip, dstip="10.0.0.5", dstport=80,
                event_count=1, user_agent=ua, url=path, session=session,
            )


# ──────────────────────────────────────────────────────────────────────────────
# Tailing
# ──────────────────────────────────────────────────────────────────────────────

class FileTailer:
    """Multi-file tail-er that yields (path, line) tuples as new lines arrive."""

    def __init__(self, files: dict[str, Path]):
        self._files = files
        self._handles: dict[str, object] = {}
        self._inodes: dict[str, int] = {}

    def _open(self, name: str) -> bool:
        path = self._files[name]
        try:
            f = path.open("r")
        except FileNotFoundError:
            return False
        f.seek(0, 2)  # start from end — don't replay history
        self._handles[name] = f
        self._inodes[name] = path.stat().st_ino
        log.info(f"Tailing {name}: {path}")
        return True

    def step(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []

        for name, path in self._files.items():
            if name not in self._handles:
                if not self._open(name):
                    continue
            # Detect rotation
            try:
                if path.stat().st_ino != self._inodes[name]:
                    log.info(f"{name}: log rotated, reopening")
                    self._handles[name].close()
                    del self._handles[name]
                    if not self._open(name):
                        continue
            except FileNotFoundError:
                self._handles[name].close()
                del self._handles[name]
                continue

            f = self._handles[name]
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.rstrip("\n")
                if line:
                    out.append((name, line))
        return out


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def wait_for_pipeline() -> None:
    log.info(f"Waiting for Bhavya pipeline at {BHAVYA_HEALTHZ}...")
    for attempt in range(60):
        try:
            r = requests.get(BHAVYA_HEALTHZ, timeout=2)
            if r.status_code == 200:
                log.info(f"Pipeline healthy: {r.json()}")
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    log.warning("Pipeline never became healthy. Continuing anyway.")


def wait_for_logs() -> None:
    targets = {"auth": AUTH_LOG, "product": PRODUCT_LOG, "nginx": NGINX_LOG}
    for attempt in range(120):  # up to 10 min
        ready = {n: p.exists() for n, p in targets.items()}
        if all(ready.values()):
            log.info(f"All log files present: {[str(p) for p in targets.values()]}")
            return
        missing = [n for n, ok in ready.items() if not ok]
        log.info(f"Waiting for log files: missing={missing} (attempt {attempt + 1})")
        time.sleep(5)
    log.warning(
        f"Some log files never appeared. Will tail what exists: "
        f"{[str(p) for p in targets.values() if p.exists()]}"
    )


def main() -> int:
    log.info(f"Minimal-mode forwarder starting. Bhavya API: {BHAVYA_API}")
    wait_for_pipeline()
    wait_for_logs()

    tailer = FileTailer({
        "auth": AUTH_LOG,
        "product": PRODUCT_LOG,
        "nginx": NGINX_LOG,
    })

    session = requests.Session()
    handlers = {
        "auth": handle_auth_line,
        "product": handle_product_line,
        "nginx": handle_nginx_line,
    }

    log.info("Tailing started. Waiting for log activity...")
    while True:
        events = tailer.step()
        for name, line in events:
            handler = handlers.get(name)
            if handler:
                try:
                    handler(line, session)
                except Exception as e:
                    log.error(f"Error handling {name} line: {e}", exc_info=True)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.info("Forwarder stopped by user")
        sys.exit(0)
