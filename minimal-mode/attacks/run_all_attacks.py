"""
attacks/run_all_attacks.py — Minimal mode end-to-end test.

Runs all 3 attack scenarios and verifies that incidents land in Bhavya's
pipeline. Same idea as vitrag/attacks/run_all_attacks.py, but tuned for
the log-watching forwarder's detection thresholds.

The forwarder fires:
  - rule 5711 (medium severity)  at 5  AUTH_FAILURE in  60s
  - rule 5712 (critical severity) at 20 AUTH_FAILURE in 120s
  - rule 31103 on any SQL_ERROR or sqlmap UA query
  - rule 40101 on each scanner UA hit
  - rule 40102 (high severity) at 50 scanner hits in 30s

So we use defaults that comfortably trigger all three.

Usage:
    python attacks/run_all_attacks.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import requests


ATTACKS_DIR = Path(__file__).parent
VITRAG_ATTACKS = ATTACKS_DIR.parent.parent / "vitrag" / "attacks"


def run_attack(script_name: str, args: list[str]) -> int:
    """Try the local attacks dir first, then fall back to vitrag/attacks."""
    candidates = [ATTACKS_DIR / script_name, VITRAG_ATTACKS / script_name]
    for path in candidates:
        if path.exists():
            cmd = [sys.executable, str(path), *args]
            print(f"\n{'=' * 70}\n>>> {' '.join(cmd)}\n{'=' * 70}")
            return subprocess.call(cmd)
    print(f"ERROR: {script_name} not found in {candidates}", file=sys.stderr)
    return 2


def fetch_incidents(bhavya_url: str) -> list[dict]:
    r = requests.get(f"{bhavya_url.rstrip('/')}/incidents?limit=1000", timeout=5)
    r.raise_for_status()
    return r.json()["items"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target-host", default="http://localhost",
                   help="nginx frontend URL")
    p.add_argument("--auth-target", default="http://localhost:5000")
    p.add_argument("--product-target", default="http://localhost:5001")
    p.add_argument("--bhavya", default="http://localhost:8000")
    args = p.parse_args()

    # Check Bhavya is up before doing anything else
    try:
        r = requests.get(f"{args.bhavya}/healthz", timeout=3)
        r.raise_for_status()
        print(f"[verify] Bhavya healthy: {r.json()}")
    except Exception as e:
        print(f"[verify] FAILED to reach Bhavya at {args.bhavya}: {e}", file=sys.stderr)
        print("[verify] Is uvicorn running on port 8000?", file=sys.stderr)
        return 1

    before = fetch_incidents(args.bhavya)
    before_count = len(before)
    print(f"[verify] Incidents in DB before attacks: {before_count}")

    # 30 attempts at 0.2s = 6s real time, ~30 events; comfortably crosses
    # both the 5/60s and 20/120s thresholds for brute_force escalation.
    rc1 = run_attack(
        "attack_brute_force.py",
        ["--target", args.auth_target, "--count", "30", "--delay", "0.2"],
    )
    time.sleep(3)

    rc2 = run_attack(
        "attack_sql_injection.py",
        ["--target", args.product_target, "--delay", "0.4"],
    )
    time.sleep(3)

    # 60 probes at 0.3s = 18s, crosses the 50/30s threshold for sustained recon.
    rc3 = run_attack(
        "attack_port_scan.py",
        ["--target", args.target_host, "--count", "60", "--delay", "0.3"],
    )

    print("\n[verify] Waiting 10s for forwarder to flush...")
    time.sleep(10)

    after = fetch_incidents(args.bhavya)
    after_count = len(after)
    new_count = after_count - before_count
    print(f"[verify] Incidents in DB after attacks: {after_count} (+{new_count})")

    # Look at the most recent batch
    recent = after[: max(20, new_count)]
    attack_types_seen = {i["attack_type"] for i in recent}
    print(f"[verify] Recent attack types: {sorted(attack_types_seen)}")

    expected = {"brute_force", "sql_injection", "port_scan"}
    missing = expected - attack_types_seen
    if missing:
        print(f"[verify] MISSING: {missing}", file=sys.stderr)
        print("[verify] Possible causes:", file=sys.stderr)
        print("[verify]   1. Forwarder not running — `docker compose logs log_forwarder`", file=sys.stderr)
        print("[verify]   2. App logs not being written — `docker compose exec auth_api tail /var/log/auth/auth.log`", file=sys.stderr)
        print("[verify]   3. Forwarder can't reach Bhavya — check host.docker.internal", file=sys.stderr)
        return 1

    print("\n[verify] ✓ All 3 attack types confirmed in pipeline. Phase 1 milestone complete.")
    return max(rc1, rc2, rc3)


if __name__ == "__main__":
    sys.exit(main())


# ─────────────────────────────────────────────────────────────────────────────
# Auto-generate a report after every successful run.
# Triggered by run_all_attacks.py's "if __name__ == '__main__'" block above
# returning successfully.
# ─────────────────────────────────────────────────────────────────────────────

def _auto_generate_report():
    """Run generate_report.py with default args; ignore failures."""
    import subprocess
    from pathlib import Path
    script = Path(__file__).parent.parent / "generate_report.py"
    if not script.exists():
        print(f"[report] skipped — {script} not found")
        return
    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, timeout=30,
        )
        print("\n" + "=" * 70)
        print("AUTO-GENERATED REPORT")
        print("=" * 70)
        print(result.stdout.strip())
        if result.returncode != 0:
            print(f"[report] generator exited {result.returncode}: {result.stderr}")
    except Exception as e:
        print(f"[report] auto-generation failed: {e}")


# Hook into the main() return path
_original_main = main
def main():  # type: ignore[no-redef]
    rc = _original_main()
    if rc == 0:
        _auto_generate_report()
    return rc
