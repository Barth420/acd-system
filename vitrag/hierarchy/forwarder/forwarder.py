"""
forwarder.py: tails the lab's shared logs and posts RawAlerts (contract D) to one or more receivers.

  ALERT_URLS   comma separated, default "http://alert-sink:8099/alerts,http://host.docker.internal:8000/alerts"
               (the alert sink always collects; the pipeline is optional: failures are logged, never fatal)
  --sink-only  post to the alert sink only (run without the pipeline)
  --source wazuh  tail Wazuh's alerts.json instead of the logs and add request_id / source_service / dstport
               from the alert's `location` and `full_log` (Wazuh profile)
  --from-start replay existing log content (default: start at the end, like tail -f)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Optional

import requests

import controlstate as cs
from rules import LOG_SERVICE, RID_RE, Detector

log = logging.getLogger("forwarder")
DEFAULT_URLS = "http://alert-sink:8099/alerts,http://host.docker.internal:8000/alerts"
LOCATION_SERVICE = {"/mnt/app_logs/auth/auth.log": "auth_api", "/mnt/app_logs/product/product.log": "product_api",
                    "/mnt/app_logs/order/order.log": "order_api", "/mnt/app_logs/search/search.log": "search_api",
                    "/mnt/app_logs/queue/queue.log": "queue", "/mnt/app_logs/nginx/access.log": "nginx"}


def post_alert(alert: dict[str, Any], urls: Iterable[str], session: Optional[requests.Session] = None) -> int:
    s = session or requests.Session()
    ok = 0
    for u in urls:
        try:
            r = s.post(u, json=alert, timeout=5)
            if r.status_code < 300:
                ok += 1
            else:
                log.warning("%s answered %s: %s", u, r.status_code, r.text[:120])
        except requests.RequestException as e:
            log.warning("post to %s failed: %s", u, e.__class__.__name__)
    return ok


def wazuh_to_raw(w: dict[str, Any]) -> Optional[dict[str, Any]]:
    """A real Wazuh alerts.json entry -> RawAlert carrying the contract-D fields Wazuh cannot decode itself."""
    data = dict(w.get("data") or {})
    service = LOCATION_SERVICE.get(w.get("location", ""))
    if not data.get("srcip") or service is None:
        return None
    full = w.get("full_log", "")
    rids = RID_RE.findall(full)
    target = "database" if w.get("rule", {}).get("id") in ("100302", "100303", 100302, 100303) else service
    data.setdefault("dstip", "127.0.0.1")
    data["dstport"] = cs.PORTS[target]
    data["source_service"] = service
    data["request_id"] = rids[-1] if rids else None
    data.setdefault("event_count", 1)
    rule = dict(w["rule"])
    rule["id"] = int(rule["id"])
    rule["level"] = int(rule["level"])
    return {"source": "wazuh", "timestamp": w.get("timestamp", ""), "raw_data": {**w, "rule": rule, "data": data}}


def follow(path: Path, from_start: bool, stop=lambda: False, poll: float = 0.3):
    """Yield lines appended to `path` (waits for the file to exist; survives rotation/truncation)."""
    while not path.exists():
        if stop():
            return
        time.sleep(poll)
    f = path.open("r", errors="replace")
    if not from_start:
        f.seek(0, 2)
    ino = os.fstat(f.fileno()).st_ino
    while not stop():
        line = f.readline()
        if line:
            yield line.rstrip("\n")
            continue
        try:
            if os.stat(path).st_ino != ino or os.stat(path).st_size < f.tell():
                f.close(); f = path.open("r", errors="replace"); ino = os.fstat(f.fileno()).st_ino
                continue
        except FileNotFoundError:
            pass
        time.sleep(poll)


def run_logs(root: Path, urls: list[str], from_start: bool, stop=lambda: False) -> None:
    import threading
    det, lock, session = Detector(), threading.Lock(), requests.Session()

    def tail(key: str):
        for line in follow(root / key, from_start, stop):
            with lock:
                alerts = det.process(key, line)
            for a in alerts:
                n = post_alert(a, urls, session)
                log.info("rule %s %s src=%s rid=%s delivered=%d", a["raw_data"]["rule"]["id"], key, a["raw_data"]["data"]["srcip"],
                         a["raw_data"]["data"]["request_id"], n)
    for key in LOG_SERVICE:
        threading.Thread(target=tail, args=(key,), daemon=True).start()
    while not stop():
        time.sleep(0.5)


def run_wazuh(path: Path, urls: list[str], from_start: bool, stop=lambda: False) -> None:
    session = requests.Session()
    for line in follow(path, from_start, stop):
        try:
            raw = wazuh_to_raw(json.loads(line))
        except (json.JSONDecodeError, KeyError):
            continue
        if raw:
            post_alert(raw, urls, session)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=["logs", "wazuh"], default=os.getenv("FORWARDER_SOURCE", "logs"))
    ap.add_argument("--sink-only", action="store_true", help="post to the alert sink only (no pipeline)")
    ap.add_argument("--from-start", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] forwarder %(message)s")
    urls = [u.strip() for u in os.getenv("ALERT_URLS", DEFAULT_URLS).split(",") if u.strip()]
    if a.sink_only:
        urls = [u for u in urls if "8000" not in u and "host.docker.internal" not in u] or urls[:1]
    log.info("source=%s targets=%s", a.source, urls)
    if a.source == "wazuh":
        run_wazuh(Path(os.getenv("WAZUH_ALERTS_PATH", "/wazuh-logs/alerts/alerts.json")), urls, a.from_start)
    else:
        run_logs(Path(os.getenv("LOG_ROOT", "/var/log/acd")), urls, a.from_start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
