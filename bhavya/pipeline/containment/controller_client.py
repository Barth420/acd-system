"""
controller_client.py — a thin client for Vitrag's REAL lab controller (contract C, http://localhost:8100).

This is the whole point of this module: the planner doesn't simulate containment, it makes the actual HTTP
calls that set a mode, cut an edge, or read the live topology/state of the running Docker lab. If the
controller can't be reached, every call raises ControllerError and the caller decides what to do (the
containment manager records the failure in the decision log instead of crashing alert ingestion).
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx


class ControllerError(Exception):
    pass


class ControllerClient:
    def __init__(self, base_url: Optional[str] = None, actor: str = "pipeline", timeout: float = 5.0,
                 http: Optional[httpx.Client] = None):
        self.base = (base_url or os.getenv("ACD_CONTROLLER_URL", "http://localhost:8100")).rstrip("/")
        self.actor = actor
        self._http = http or httpx.Client(timeout=timeout, headers={"X-Actor": actor})

    def _call(self, method: str, path: str, json: Any = None) -> dict[str, Any]:
        try:
            r = self._http.request(method, self.base + path, json=json)
        except httpx.HTTPError as e:
            raise ControllerError(f"{self.base}{path}: {e.__class__.__name__}: {e}") from e
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except Exception:  # noqa: BLE001
                msg = r.text
            raise ControllerError(f"{r.status_code} {msg}")
        try:
            return r.json()
        except Exception:  # noqa: BLE001
            return {}

    # reads
    def topology(self) -> dict[str, Any]:
        return self._call("GET", "/topology")

    def state(self) -> dict[str, Any]:
        return self._call("GET", "/state")

    def health(self) -> dict[str, Any]:
        return self._call("GET", "/health")

    def actions(self) -> list[dict[str, Any]]:
        out = self._call("GET", "/actions")
        return out if isinstance(out, list) else []

    # writes (contract C — the ONLY things that actually change the running lab)
    def set_mode(self, service: str, mode: str) -> dict[str, Any]:
        return self._call("POST", f"/services/{service}/mode", {"mode": mode})

    def cut_edge(self, a: str, b: str) -> dict[str, Any]:
        return self._call("POST", "/edges/cut", {"from": a, "to": b})

    def restore_edge(self, a: str, b: str) -> dict[str, Any]:
        return self._call("POST", "/edges/restore", {"from": a, "to": b})

    def rotate_credentials(self, service: str) -> dict[str, Any]:
        return self._call("POST", f"/services/{service}/rotate-credentials")

    def reset(self) -> dict[str, Any]:
        return self._call("POST", "/reset")
