"""
controlstate.py: the control state shared by the controller (writer) and every service (readers).

The controller writes /control/state.json atomically; services re-read it when its mtime changes.
Contract B (v1.1) mode/capability matrix lives here so there is exactly one copy.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

HERE = Path(__file__).resolve().parent
TOPOLOGY: dict[str, Any] = json.loads((HERE / "topology.json").read_text())
SERVICES: list[str] = [s["name"] for s in TOPOLOGY["services"]]
PORTS: dict[str, int] = {s["name"]: s["port"] for s in TOPOLOGY["services"]}
EDGES: list[tuple[str, str]] = [(s["name"], d) for s in TOPOLOGY["services"] for d in s["depends_on"]]

CAPS = ["bulk_requests", "state_write", "dynamic_query", "dependency_calls", "data_egress"]
MODES = ["normal", "rate_limited", "read_only", "fallback", "isolated"]
BLOCKS: dict[str, set[str]] = {
    "normal": set(),
    "rate_limited": {"bulk_requests"},
    "read_only": {"state_write"},
    "fallback": {"dynamic_query", "dependency_calls", "state_write", "data_egress"},
    "isolated": set(CAPS),
}


def initial_key(service: str) -> str:
    """Generation-0 service key. It is also the value planted in the database `secrets` table."""
    return f"lab-key-{service}-gen0"


def default_state() -> dict[str, Any]:
    return {
        "version": 0,
        "services": {s: {"mode": "normal"} for s in SERVICES},
        "cut_edges": [],
        "credentials": {s: {"current": initial_key(s), "generation": 0, "revoked": []} for s in SERVICES},
    }


def write_state(path: str | os.PathLike, state: dict[str, Any]) -> None:
    """Atomic write (temp file + rename) so readers never see a half-written file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".state-", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)


class StateReader:
    """Cached reader: re-parses only when the file's (mtime_ns, size) changes. Missing file = default state."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._sig: Optional[tuple[int, int]] = None
        self._state = default_state()
        self._lock = threading.Lock()

    def get(self) -> dict[str, Any]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return self._state
        sig = (st.st_mtime_ns, st.st_size)
        if sig != self._sig:
            with self._lock:
                try:
                    self._state = json.loads(self.path.read_text())
                    self._sig = sig
                except (json.JSONDecodeError, OSError):
                    pass            # keep the last good state
        return self._state


def mode_of(state: dict[str, Any], service: str) -> str:
    return state.get("services", {}).get(service, {}).get("mode", "normal")


def edge_cut(state: dict[str, Any], a: str, b: str) -> bool:
    return [a, b] in [list(e) for e in state.get("cut_edges", [])]


def blocked_caps(mode: str, needed: Iterable[str]) -> list[str]:
    return [c for c in needed if c in BLOCKS[mode]]


def credential(state: dict[str, Any], service: str) -> dict[str, Any]:
    return state.get("credentials", {}).get(service) or {"current": initial_key(service), "generation": 0, "revoked": []}
