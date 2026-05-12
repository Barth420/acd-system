"""
attack_port_scan.py — Simulated port scan.

We can't reliably run real nmap from arbitrary contexts (and inside Docker
containers it often gets killed), so this script simulates a port scan by
hammering the nginx frontend with rapid requests carrying scanner User-Agents.
This is what Wazuh rule 40101 detects.

For a real nmap scan, run from the WSL2 shell:
    nmap -sV -p 1-10000 localhost

Usage:
    python attack_port_scan.py [--target http://localhost]
"""

from __future__ import annotations

import argparse
import random
import sys
import time

import requests


SCANNER_USER_AGENTS = [
    "nmap-scripting-engine/7.94",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Nikto/2.5.0",
    "masscan/1.3.2",
    "sqlmap/1.7.2#stable",
    "Mozilla/5.0 (compatible; OpenVAS-VT)",
]

PROBE_PATHS = [
    "/", "/admin", "/login", "/wp-admin", "/.env", "/.git/config",
    "/phpmyadmin", "/server-status", "/robots.txt", "/api", "/api/v1",
    "/console", "/manager/html", "/cgi-bin/", "/.well-known/security.txt",
    "/sitemap.xml", "/health", "/metrics", "/swagger", "/graphql",
]


def run(target: str, count: int, delay: float) -> int:
    base = target.rstrip("/")
    print(f"[port_scan] target={base}, probes={count}, delay={delay}s")

    fired = 0
    for i in range(count):
        ua = random.choice(SCANNER_USER_AGENTS)
        path = random.choice(PROBE_PATHS)
        url = f"{base}{path}"
        try:
            r = requests.get(url, headers={"User-Agent": ua}, timeout=3)
            if (i + 1) % 10 == 0:
                print(f"[port_scan] {i + 1}/{count}  last_status={r.status_code}  ua={ua}")
            fired += 1
        except requests.RequestException as e:
            print(f"[port_scan] error: {e}", file=sys.stderr)
        time.sleep(delay)

    print(f"[port_scan] DONE — {fired}/{count} probes sent")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost",
                   help="nginx frontend URL")
    p.add_argument("--count", type=int, default=60, help="Number of probes")
    p.add_argument("--delay", type=float, default=0.3, help="Seconds between probes")
    args = p.parse_args()
    return run(args.target, args.count, args.delay)


if __name__ == "__main__":
    sys.exit(main())
