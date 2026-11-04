"""
manager.py — ContainmentManager: turns an incident into a plan (planner.py), then ACTUALLY calls the real lab
controller to execute it (controller_client.py), and persists the decision (with every action's real result)
so the dashboard and forensics can show not just what was decided but what actually happened when it tried.

If the controller is unreachable or an action fails, that is recorded plainly — the manager never pretends an
action succeeded. Alert ingestion is never blocked by this: call handle_incident from a BackgroundTask.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

from . import planner
from .brain import make_brain
from .controller_client import ControllerClient, ControllerError

logger = logging.getLogger(__name__)


class ContainmentManager:
    def __init__(self, client: Optional[ControllerClient] = None, persist: Optional[Callable[[dict], None]] = None,
                 autonomy: str = "auto", brain: Any = None):
        self.client = client or ControllerClient()
        self.persist = persist
        self.autonomy = autonomy      # "auto": execute immediately. "approve": plan only, wait for approve_decision().
        self.brain = brain if brain is not None else make_brain()   # advisory only -- see brain.py
        self.lock = threading.RLock()
        self.decisions: dict[str, planner.ContainmentDecision] = {}

    def _save(self, d: planner.ContainmentDecision) -> None:
        if self.persist:
            try:
                self.persist(d.to_dict())
            except Exception:  # noqa: BLE001
                logger.exception("failed to persist containment decision")

    def _execute(self, d: planner.ContainmentDecision) -> None:
        failed = 0
        for a in d.actions:
            try:
                if a.type == "set_mode":
                    self.client.set_mode(a.target, a.mode or "normal")
                    a.result = "ok"
                elif a.type == "cut_edge":
                    x, y = a.target.split("->")
                    self.client.cut_edge(x, y)
                    a.result = "ok"
                else:
                    a.result = f"error: unknown action type {a.type}"
                    failed += 1
            except ControllerError as e:
                a.result = f"error: {e}"
                failed += 1
                logger.warning("containment action failed: %s %s -> %s", a.type, a.target, e)
        d.status = "execution_failed" if (d.actions and failed == len(d.actions)) else "executed"
        self._save(d)

    def handle_incident(self, *, incident_id: str, alert_id: str, service: str, attack_type: str, severity: str,
                        source_ip: str) -> planner.ContainmentDecision:
        with self.lock:
            d = planner.plan(incident_id=incident_id, alert_id=alert_id, service=service, attack_type=attack_type,
                             severity=severity, source_ip=source_ip)
            if d.status != "skipped" and self.brain is not None:
                try:
                    d.brain_response = self.brain.explain(service=service, attack_type=attack_type, severity=severity,
                                                          source_ip=source_ip, mode=d.mode)
                except Exception as e:  # noqa: BLE001 — the brain is advisory; it must never break containment
                    d.brain_response = {"backend": "error", "available": False, "reason": str(e)}
            self.decisions[d.decision_id] = d
            self._save(d)
            if d.status == "skipped" or not d.actions:
                return d
            if self.autonomy == "auto":
                self._execute(d)
            else:
                d.status = "pending_approval"
                self._save(d)
            return d

    def approve(self, decision_id: str) -> planner.ContainmentDecision:
        with self.lock:
            d = self.decisions.get(decision_id)
            if d is None:
                raise KeyError(decision_id)
            if d.status != "pending_approval":
                raise ValueError(f"decision is {d.status}, not pending_approval")
            self._execute(d)
            return d

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            items = sorted(self.decisions.values(), key=lambda d: d.created_at, reverse=True)
            return [d.to_dict() for d in items[:limit]]

    def get(self, decision_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            d = self.decisions.get(decision_id)
            return d.to_dict() if d else None
