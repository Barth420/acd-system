"""
generate_report.py — Generate a Phase 1 incident report from the live pipeline.

Pulls data from the running Bhavya pipeline (NOT directly from the DB) so the
report reflects exactly what the API sees. Output is a single self-contained
Markdown file with timestamps.

Usage:
    python minimal-mode/generate_report.py
    python minimal-mode/generate_report.py --bhavya http://localhost:8000
    python minimal-mode/generate_report.py --output /mnt/c/Users/Bhavya/Desktop/report.md

If you don't pass --output, files land in ~/acd-system/reports/ with a timestamp.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import requests


def fetch(url: str) -> dict:
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def md_table(rows: list[list[str]], headers: list[str]) -> str:
    out = ["| " + " | ".join(headers) + " |"]
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def build_report(bhavya: str) -> str:
    bhavya = bhavya.rstrip("/")

    # Pull live state from the API
    health = fetch(f"{bhavya}/healthz")
    services = fetch(f"{bhavya}/services")
    graph = fetch(f"{bhavya}/graph")
    incidents = fetch(f"{bhavya}/incidents?limit=1000")

    items = incidents["items"]
    total = len(items)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Aggregations
    by_attack = Counter(i["attack_type"] for i in items)
    by_service = Counter(i["service"] for i in items)
    by_severity = Counter(i["severity"] for i in items)
    by_sensitivity = Counter(i["sensitivity"] for i in items)
    by_source_ip = Counter(i["source_ip"] for i in items)

    # Cross-tab: attack_type x service
    cross = defaultdict(int)
    for i in items:
        cross[(i["attack_type"], i["service"])] += 1

    # Build the markdown
    lines: list[str] = []
    lines.append("# ACD Phase 1 — Incident Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Pipeline:** `{bhavya}`")
    lines.append(f"**Pipeline status:** {health.get('status', 'unknown')}")
    lines.append("")

    # ── Section 1: Summary ────────────────────────────────────────────────
    lines.append("## 1. Summary")
    lines.append("")
    lines.append(f"- **Total enriched incidents stored:** {total}")
    lines.append(f"- **Unique source IPs:** {len(by_source_ip)}")
    lines.append(f"- **Services targeted:** {len(by_service)}")
    lines.append(f"- **Attack types observed:** {len(by_attack)}")
    lines.append("")

    # ── Section 2: Attack-type breakdown ──────────────────────────────────
    lines.append("## 2. Attack Type Breakdown")
    lines.append("")
    if by_attack:
        rows = [[atk, cnt, f"{cnt/total*100:.1f}%"] for atk, cnt in by_attack.most_common()]
        lines.append(md_table(rows, ["Attack Type", "Count", "Share"]))
    else:
        lines.append("_No incidents recorded yet._")
    lines.append("")

    # ── Section 3: Severity distribution ──────────────────────────────────
    lines.append("## 3. Severity Distribution")
    lines.append("")
    if by_severity:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows = [[sev, cnt] for sev, cnt in sorted(by_severity.items(), key=lambda x: order.get(x[0], 99))]
        lines.append(md_table(rows, ["Severity", "Count"]))
    else:
        lines.append("_No incidents recorded yet._")
    lines.append("")

    # ── Section 4: Service exposure ───────────────────────────────────────
    lines.append("## 4. Targeted Services (with sensitivity context)")
    lines.append("")
    svc_lookup = {s["name"]: s for s in services["services"]}
    if by_service:
        rows = []
        for svc, cnt in by_service.most_common():
            ctx = svc_lookup.get(svc, {})
            rows.append([
                svc,
                cnt,
                ctx.get("sensitivity", "—"),
                ctx.get("exposure", "—"),
                ", ".join(ctx.get("dependents", [])) or "(none)",
            ])
        lines.append(md_table(
            rows,
            ["Service", "Incidents", "Sensitivity", "Exposure", "Downstream Dependents"],
        ))
    else:
        lines.append("_No services targeted yet._")
    lines.append("")

    # ── Section 5: Attack × Service cross-tab ─────────────────────────────
    lines.append("## 5. Attack Type × Service")
    lines.append("")
    if cross:
        attack_keys = sorted({a for a, _ in cross})
        service_keys = sorted({s for _, s in cross})
        header = ["Attack ↓ / Service →"] + service_keys + ["TOTAL"]
        rows = []
        for a in attack_keys:
            row = [a]
            row_total = 0
            for s in service_keys:
                v = cross.get((a, s), 0)
                row.append(v if v else "")
                row_total += v
            row.append(row_total)
            rows.append(row)
        lines.append(md_table(rows, header))
    else:
        lines.append("_No cross-tab data._")
    lines.append("")

    # ── Section 6: Top source IPs ─────────────────────────────────────────
    lines.append("## 6. Top Attacker Source IPs")
    lines.append("")
    if by_source_ip:
        rows = [[ip, cnt] for ip, cnt in by_source_ip.most_common(10)]
        lines.append(md_table(rows, ["Source IP", "Incidents"]))
    else:
        lines.append("_No incidents recorded yet._")
    lines.append("")

    # ── Section 7: Dependency graph ───────────────────────────────────────
    lines.append("## 7. Service Dependency Graph (Blast Radius Analysis)")
    lines.append("")
    lines.append("If a service is compromised, the listed services are also at risk:")
    lines.append("")
    rows = []
    for node in graph["nodes"]:
        radius = graph["blast_radius"].get(node, [])
        rows.append([
            node,
            graph["depths"].get(node, 0),
            ", ".join(radius) if radius else "(none — leaf)",
        ])
    lines.append(md_table(rows, ["Service", "Dependency Depth", "Blast Radius"]))
    lines.append("")

    # ── Section 8: Recent incidents ───────────────────────────────────────
    lines.append("## 8. Most Recent 20 Incidents")
    lines.append("")
    if items:
        rows = [
            [
                i["created_at"][:19],
                i["source_ip"],
                i["service"],
                i["attack_type"],
                i["severity"],
                i["sensitivity"],
                i["exposure"],
            ]
            for i in items[:20]
        ]
        lines.append(md_table(
            rows,
            ["Time (UTC)", "Source IP", "Service", "Attack", "Severity", "Sensitivity", "Exposure"],
        ))
    else:
        lines.append("_No incidents recorded yet._")
    lines.append("")

    # ── Section 9: Sample full enriched incident ──────────────────────────
    lines.append("## 9. Sample Enriched Incident (Full JSON)")
    lines.append("")
    if items:
        sample_id = items[0]["incident_id"]
        try:
            sample = fetch(f"{bhavya}/incidents/{sample_id}")
            lines.append(f"`incident_id`: `{sample_id}`")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(sample, indent=2))
            lines.append("```")
        except Exception as e:
            lines.append(f"_Could not fetch sample: {e}_")
    else:
        lines.append("_No incidents recorded yet._")
    lines.append("")

    # ── Footer ────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append("_Generated by `minimal-mode/generate_report.py`._")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bhavya", default="http://localhost:8000",
                   help="Bhavya pipeline base URL (default: http://localhost:8000)")
    p.add_argument("--output", default=None,
                   help="Output file path (default: ~/acd-system/reports/report-<timestamp>.md)")
    args = p.parse_args()

    try:
        report = build_report(args.bhavya)
    except requests.RequestException as e:
        print(f"ERROR: Could not reach Bhavya pipeline at {args.bhavya}: {e}",
              file=sys.stderr)
        print("Hint: is uvicorn running?", file=sys.stderr)
        return 1

    if args.output:
        out_path = Path(args.output).expanduser()
    else:
        out_dir = Path.home() / "acd-system" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = out_dir / f"report-{ts}.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)

    print(f"✓ Report saved: {out_path}")
    print(f"  Size: {out_path.stat().st_size} bytes")
    print(f"  Lines: {report.count(chr(10)) + 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
