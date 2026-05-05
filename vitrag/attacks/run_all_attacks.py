"""
run_all_attacks.py — Month 1 milestone smoke test.

Runs all 3 attack scenarios end-to-end and verifies that incidents land in
Bhavya's pipeline. This is the test the Month 1 plan calls for:

    "All 3 attack types produce clean enriched incidents."

Usage:
    python run_all_attacks.py --bhavya http://localhost:8000
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import requests


ATTACKS_DIR = Path(__file__).parent


def run_attack(script: str, args: list[str]) -> int:
    cmd = [sys.executable, str(ATTACKS_DIR / script), *args]
    print(f"\n{'=' * 70}\n>>> {' '.join(cmd)}\n{'=' * 70}")
    return subprocess.call(cmd)


def fetch_incidents(bhavya_url: str) -> list[dict]:
    r = requests.get(f"{bhavya_url.rstrip('/')}/incidents?limit=1000", timeout=5)
    r.raise_for_status()
    return r.json()["items"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target-host", default="http://localhost",
                   help="Lab frontend (nginx) URL — for port_scan + sqli/login fronted by nginx")
    p.add_argument("--auth-target", default="http://localhost:5000")
    p.add_argument("--product-target", default="http://localhost:5001")
    p.add_argument("--bhavya", default="http://localhost:8000",
                   help="Bhavya pipeline URL (for verification)")
    p.add_argument("--skip-verify", action="store_true",
                   help="Skip the post-attack incident-count check")
    args = p.parse_args()

    # Snapshot incident count before
    before_count = 0
    if not args.skip_verify:
        try:
            before = fetch_incidents(args.bhavya)
            before_count = len(before)
            print(f"[verify] Incidents in DB before attacks: {before_count}")
        except Exception as e:
            print(f"[verify] Could not reach Bhavya pipeline: {e}", file=sys.stderr)
            return 1

    # Run all 3 attacks
    rc1 = run_attack(
        "attack_brute_force.py",
        ["--target", args.auth_target, "--count", "60", "--delay", "0.2"],
    )
    time.sleep(3)
    rc2 = run_attack(
        "attack_sql_injection.py",
        ["--target", args.product_target, "--delay", "0.5"],
    )
    time.sleep(3)
    rc3 = run_attack(
        "attack_port_scan.py",
        ["--target", args.target_host, "--count", "60", "--delay", "0.3"],
    )

    # Give Wazuh + forwarder time to catch up
    if not args.skip_verify:
        print("\n[verify] Waiting 20s for Wazuh + forwarder to catch up...")
        time.sleep(20)
        try:
            after = fetch_incidents(args.bhavya)
            after_count = len(after)
            new_count = after_count - before_count
            print(f"[verify] Incidents in DB after attacks: {after_count} (+{new_count})")

            attack_types_seen = {i["attack_type"] for i in after[: max(20, new_count)]}
            print(f"[verify] Attack types observed: {sorted(attack_types_seen)}")

            expected = {"brute_force", "sql_injection", "port_scan"}
            missing = expected - attack_types_seen
            if missing:
                print(f"[verify] MISSING attack types: {missing}", file=sys.stderr)
                print("[verify] Check: Wazuh rules firing? Forwarder running? "
                      "App logs reaching the manager?", file=sys.stderr)
                return 1
            print("[verify] ✓ All 3 attack types confirmed in pipeline.")
        except Exception as e:
            print(f"[verify] Failed to verify: {e}", file=sys.stderr)
            return 1

    return max(rc1, rc2, rc3)


if __name__ == "__main__":
    sys.exit(main())
