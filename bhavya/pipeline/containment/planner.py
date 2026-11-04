"""
planner.py — decides WHAT to do about a compromised service (the decision, not the execution).

Deliberately simple and explainable (not a Monte Carlo risk model): a small, documented rule table maps
severity + attack_type to a mode, plus a fixed two-direction containment pattern. Every number/rule here is a
developer-chosen default, not a measured value — that's stated in the rationale text itself so the UI never
implies otherwise.

Two-direction containment, run against the service that was actually attacked (`compromised`):
  downstream  cut the edge FROM each of its direct dependents (who call it) TO it — they lose only the
              functions that need `compromised`; everything else they do keeps working.
  lateral     (isolated mode only) cut `compromised`'s OWN outbound edges to its dependencies, so a
              fully-isolated service can't be used to pivot further in.
The full transitive blast radius (every service that could eventually be affected) is reported too, but only
the DIRECT dependents/dependencies are actually acted on — the rest are listed as "at risk", not touched,
because cutting something two hops away on a guess is not justified by one alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from .. import dependency_graph as dg
from .. import service_registry as reg
from .capabilities import required_caps


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# severity -> mode for the compromised service itself. A developer-chosen default (documented), not measured.
SEVERITY_MODE = {"critical": "isolated", "high": "fallback", "medium": "read_only", "low": "rate_limited"}
# some attack types always escalate past the plain severity table, because they mean the attacker already
# has something (a credential, a pivot, exfiltrated rows) rather than just probing.
ESCALATE_TO_ISOLATED = {"lateral_movement", "data_exfiltration"}


@dataclass
class Action:
    type: str                     # "set_mode" | "cut_edge"
    target: str                   # service name, or "A->B" for cut_edge
    mode: Optional[str] = None
    reason: str = ""
    result: Optional[str] = None  # filled in by the executor: "ok" | "error: ..."

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "target": self.target, "mode": self.mode, "reason": self.reason, "result": self.result}


@dataclass
class ContainmentDecision:
    decision_id: str
    incident_id: str
    alert_id: str
    compromised_service: str
    attack_type: str
    severity: str
    source_ip: str
    mode: str
    required_capability: list[str]
    direct_dependents: list[str]
    direct_dependencies: list[str]
    blast_radius: list[str]
    actions: list[Action]
    rationale: str
    created_at: str = field(default_factory=now_iso)
    status: str = "planned"       # planned -> executed | execution_failed
    brain_response: Optional[dict[str, Any]] = None   # advisory LLM explanation; see containment/brain.py

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "actions"}
        d["actions"] = [a.to_dict() for a in self.actions]
        return d


def choose_mode(attack_type: str, severity: str) -> str:
    mode = SEVERITY_MODE.get(severity, "rate_limited")
    if attack_type in ESCALATE_TO_ISOLATED:
        mode = "isolated"
    return mode


def plan(*, incident_id: str, alert_id: str, service: str, attack_type: str, severity: str, source_ip: str) -> ContainmentDecision:
    """Build a decision. Does NOT call the controller — see manager.ContainmentManager for execution."""
    if service not in reg.SERVICE_REGISTRY:
        return ContainmentDecision(
            decision_id=f"dec-{uuid4().hex[:10]}", incident_id=incident_id, alert_id=alert_id,
            compromised_service=service, attack_type=attack_type, severity=severity, source_ip=source_ip,
            mode="normal", required_capability=[], direct_dependents=[], direct_dependencies=[], blast_radius=[],
            actions=[], rationale=f"{service!r} is not a known service in the lab topology; no action taken.",
            status="skipped",
        )

    mode = choose_mode(attack_type, severity)
    direct_dependents = dg.downstream_services(service)              # who calls `service` directly
    direct_dependencies = reg.get_service_context(service).dependencies   # what `service` calls directly
    blast = dg.blast_radius(service)                                  # full transitive dependents (contract A)
    caps = required_caps(attack_type)

    # cutting a dependent's edge is a real disruption, so only do it once the compromised service is in a mode
    # more serious than a plain rate limit (rate_limited alone already blocks the capability a port scan /
    # low-severity brute force needs; cutting a dependent's edge on top of that is not justified by one alert).
    cut_dependent_edges = mode in ("read_only", "fallback", "isolated")

    actions: list[Action] = []
    if mode != "normal":
        actions.append(Action("set_mode", service, mode, reason=f"compromised service; {attack_type} typically needs capability {caps or '(none)'}"))
    if cut_dependent_edges:
        for dep in direct_dependents:
            actions.append(Action("cut_edge", f"{dep}->{service}", reason=f"{dep} depends on {service} directly; stop it calling in while {service} is compromised"))
    if mode == "isolated":
        for target in direct_dependencies:
            actions.append(Action("cut_edge", f"{service}->{target}", reason=f"{service} is isolated; also cut its own outbound link to {target} so a foothold here can't pivot onward"))

    ctx = reg.get_service_context(service)
    bits = [f"{attack_type} detected on {service} ({ctx.sensitivity} sensitivity, {ctx.exposure}) from {source_ip}, severity {severity}.",
            f"Setting {service} to '{mode}'." if mode != "normal" else "Severity/attack type did not warrant a mode change."]
    if direct_dependents and cut_dependent_edges:
        bits.append(f"Cutting the inbound edge from each direct dependent ({', '.join(direct_dependents)}) so they stop calling {service}; their other functions keep working.")
    elif direct_dependents:
        bits.append(f"{', '.join(direct_dependents)} {'depends' if len(direct_dependents) == 1 else 'depend'} on {service} directly but {'its' if len(direct_dependents) == 1 else 'their'} edges were not cut: '{mode}' alone already blocks the capability this attack needs.")
    if mode == "isolated" and direct_dependencies:
        bits.append(f"{service} is fully isolated, so its own outbound edges ({', '.join(f'{service}->{d}' for d in direct_dependencies)}) are cut too, to block any pivot.")
    extra_blast = [s for s in blast if s not in direct_dependents]
    if extra_blast:
        bits.append(f"{', '.join(extra_blast)} {'is' if len(extra_blast) == 1 else 'are'} further downstream (indirectly dependent) and reported as at-risk, but not acted on from this single alert.")

    return ContainmentDecision(
        decision_id=f"dec-{uuid4().hex[:10]}", incident_id=incident_id, alert_id=alert_id,
        compromised_service=service, attack_type=attack_type, severity=severity, source_ip=source_ip,
        mode=mode, required_capability=caps, direct_dependents=direct_dependents,
        direct_dependencies=direct_dependencies, blast_radius=blast, actions=actions, rationale=" ".join(bits),
    )
