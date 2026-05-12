"""
forwarder.py — Wazuh alerts → Bhavya's /alerts endpoint.

Tails /var/ossec/logs/alerts/alerts.json (one JSON object per line) and
forwards every new alert as a POST to Bhavya's pipeline.

Resilient:
  - Sleeps and retries on connection errors (Bhavya's API may be slow to start).
  - Skips malformed JSON lines instead of crashing.
  - Reports forward count to stdout every 10 alerts.
  - Handles file rotation (re-opens if inode changes).

Run inside Docker compose, or locally:
    BHAVYA_API=http://localhost:8000/alerts \\
    WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json \\
    python forwarder.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] forwarder — %(message)s",
)
log = logging.getLogger("forwarder")

BHAVYA_API = os.getenv("BHAVYA_API", "http://localhost:8000/alerts")
WAZUH_ALERTS_PATH = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
POLL_INTERVAL = float(os.getenv("FORWARDER_POLL_S", "0.5"))
RETRY_BACKOFF = float(os.getenv("FORWARDER_RETRY_S", "5"))


def _wrap(raw_alert: dict) -> dict:
    """Wrap a Wazuh alert in the RawAlert schema Bhavya's API expects."""
    return {
        "source": "wazuh",
        "timestamp": raw_alert.get(
            "timestamp",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        "raw_data": raw_alert,
    }


def forward(raw_alert: dict, session: requests.Session) -> bool:
    """POST one alert. Returns True on 2xx, False otherwise."""
    payload = _wrap(raw_alert)
    try:
        r = session.post(BHAVYA_API, json=payload, timeout=10)
    except requests.RequestException as e:
        log.warning(f"POST failed: {e}")
        return False

    if 200 <= r.status_code < 300:
        return True

    if r.status_code == 422:
        # Pipeline rejected the alert (couldn't normalize) — that's expected
        # for noisy Wazuh events. Log at debug, don't retry.
        log.debug(f"Pipeline dropped alert (422): {r.text[:200]}")
        return False

    log.warning(f"Unexpected status {r.status_code}: {r.text[:200]}")
    return False


def wait_for_file(path: Path) -> None:
    """Block until the alerts.json file appears (Wazuh may be slow to start)."""
    while not path.exists():
        log.info(f"Waiting for {path} to appear...")
        time.sleep(RETRY_BACKOFF)
    log.info(f"Found {path}, starting tail")


def tail(path: Path) -> None:
    """Tail a JSON-lines file, yielding each parsed object."""
    session = requests.Session()
    forwarded = 0
    dropped = 0
    inode = None

    while True:
        try:
            current_inode = path.stat().st_ino
            if inode is not None and current_inode != inode:
                log.info("Log file rotated, reopening")
            inode = current_inode

            with path.open("r") as f:
                # Start from end on first open so we don't replay old alerts
                if forwarded == 0 and dropped == 0:
                    f.seek(0, 2)

                while True:
                    line = f.readline()
                    if not line:
                        # Check for rotation
                        try:
                            if path.stat().st_ino != inode:
                                break
                        except FileNotFoundError:
                            break
                        time.sleep(POLL_INTERVAL)
                        continue

                    line = line.strip()
                    if not line:
                        continue

                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError as e:
                        log.debug(f"Skipping malformed line: {e}")
                        continue

                    if forward(raw, session):
                        forwarded += 1
                        if forwarded % 10 == 0:
                            log.info(
                                f"Forwarded {forwarded} alerts (dropped {dropped})"
                            )
                    else:
                        dropped += 1
        except FileNotFoundError:
            log.warning("Alerts file disappeared, waiting for it to return")
            time.sleep(RETRY_BACKOFF)


def main() -> int:
    log.info(f"Forwarder starting. Bhavya API: {BHAVYA_API}")
    log.info(f"Watching: {WAZUH_ALERTS_PATH}")

    # Health check Bhavya's API before we start
    healthz = BHAVYA_API.replace("/alerts", "/healthz")
    for attempt in range(60):  # up to 5 min
        try:
            r = requests.get(healthz, timeout=2)
            if r.status_code == 200:
                log.info(f"Bhavya pipeline healthy: {r.json()}")
                break
        except requests.RequestException:
            pass
        log.info(f"Waiting for Bhavya pipeline at {healthz}... ({attempt + 1}/60)")
        time.sleep(RETRY_BACKOFF)
    else:
        log.error("Bhavya pipeline never became healthy. Continuing anyway.")

    path = Path(WAZUH_ALERTS_PATH)
    wait_for_file(path)
    tail(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
