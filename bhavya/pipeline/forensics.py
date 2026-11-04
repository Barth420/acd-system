"""
forensics.py — reconstructs an attack's path from stored incidents: where it started, which services it
touched and in what order, and whether each step was actually contained (a containment decision exists for it).

Light by design: orders incidents by time (then insertion order as a tiebreak), collapses consecutive repeats
of the same (service, attack_type) into one step, and marks a path edge "inferred" when the two services
aren't actually adjacent in the dependency graph (the UI draws it differently so nobody mistakes an inference
for observed traffic).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from . import dependency_graph as dg


def _parse(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.fromtimestamp(0, timezone.utc)


def _adjacent(a: str, b: str) -> bool:
    g = dg.get_graph()
    return g.has_edge(a, b) or g.has_edge(b, a)


def reconstruct(incidents: list[dict[str, Any]], decisions: list[dict[str, Any]], since: Optional[str] = None,
                until: Optional[str] = None, ip: Optional[str] = None) -> dict[str, Any]:
    lo = _parse(since) if since else None
    hi = _parse(until) if until else None
    events = []
    for n, inc in enumerate(incidents):
        t = _parse(inc["created_at"])
        if lo and t < lo:
            continue
        if hi and t > hi:
            continue
        if ip and inc["source_ip"] != ip:
            continue
        events.append({**inc, "_order": (t, n)})
    events.sort(key=lambda e: e["_order"])
    for e in events:
        del e["_order"]

    contained_services = {d["compromised_service"] for d in decisions if d["status"] in ("executed", "pending_approval")}

    steps: list[dict[str, Any]] = []
    for e in events:
        if steps and steps[-1]["service"] == e["service"] and steps[-1]["attack_type"] == e["attack_type"]:
            steps[-1]["count"] += 1
            steps[-1]["incident_ids"].append(e["incident_id"])
            continue
        steps.append({"service": e["service"], "attack_type": e["attack_type"], "severity": e["severity"],
                      "source_ip": e["source_ip"], "first_ts": e["created_at"], "count": 1,
                      "contained": e["service"] in contained_services, "incident_ids": [e["incident_id"]]})

    path = []
    for s in steps:
        if not path or path[-1] != s["service"]:
            path.append(s["service"])
    overlay_edges = [{"from": a, "to": b, "inferred": not _adjacent(a, b)} for a, b in zip(path, path[1:])]

    return {"events": events, "steps": steps, "attack_path": path, "origin_service": path[0] if path else None,
           "overlay_edges": overlay_edges}
