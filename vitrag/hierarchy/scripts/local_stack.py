#!/usr/bin/env python3
"""
scripts/local_stack.py: run the REAL service code as local processes (no Docker).

  postgres -> sqlite file, redis -> sqlite key/value file, nginx -> svc/gateway_local.py.
Used for development and by the test-suite on machines without Docker. It does NOT exercise compose, the Dockerfiles,
the nginx config, docker networks or `docker network disconnect`.

    python scripts/local_stack.py            # starts everything, prints URLs, Ctrl-C to stop
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

HIER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HIER / "shared"))
import controlstate as cs  # noqa: E402

MODULES = {"auth_api": "svc.auth_api", "product_api": "svc.product_api", "order_api": "svc.order_api",
           "search_api": "svc.search_api", "queue": "svc.queue_svc"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalStack:
    def __init__(self, workdir: str | None = None):
        self.dir = Path(workdir or tempfile.mkdtemp(prefix="acd-local-"))
        self.control = self.dir / "control" / "state.json"
        self.logs = self.dir / "logs"
        self.ports = {s: free_port() for s in [*MODULES, "nginx"]}
        self.procs: list[subprocess.Popen] = []

    @property
    def gateway(self) -> str:
        return f"http://127.0.0.1:{self.ports['nginx']}"

    def url(self, svc: str) -> str:
        return f"http://127.0.0.1:{self.ports[svc]}"

    def env(self, name: str) -> dict[str, str]:
        e = {**os.environ, "PYTHONPATH": f"{HIER / 'shared'}:{HIER / 'services'}", "CONTROL_STATE": str(self.control),
             "LOG_ROOT": str(self.logs), "DATABASE_URL": f"sqlite:///{self.dir}/db.sqlite", "CACHE_URL": f"sqlite:///{self.dir}/cache.sqlite",
             "PORT": str(self.ports[name])}
        for s in MODULES:
            e[f"DEP_{s.upper()}_URL"] = self.url(s)
        return e

    def start(self) -> "LocalStack":
        cs.write_state(self.control, cs.default_state())
        for name, mod in MODULES.items():
            self.procs.append(subprocess.Popen([sys.executable, "-m", mod], cwd=HIER / "services", env=self.env(name),
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.procs.append(subprocess.Popen([sys.executable, "-m", "svc.gateway_local"], cwd=HIER / "services", env=self.env("nginx"),
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for name in [*MODULES, "nginx"]:
            self._wait(self.url(name) + "/healthz")
        return self

    @staticmethod
    def _wait(url: str, timeout: float = 25.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            try:
                if httpx.get(url, timeout=1).status_code < 600:
                    return
            except Exception:  # noqa: BLE001
                time.sleep(0.15)
        raise RuntimeError(f"{url} did not come up")

    def set_state(self, **changes) -> None:
        """Test helper: edit the control state directly (the controller does this in real runs)."""
        st = cs.StateReader(self.control).get()
        st = {**st}
        for svc, mode in (changes.get("modes") or {}).items():
            st["services"][svc] = {"mode": mode}
        if "cuts" in changes:
            st["cut_edges"] = [list(e) for e in changes["cuts"]]
        if "credentials" in changes:
            st["credentials"].update(changes["credentials"])
        st["version"] = st.get("version", 0) + 1
        cs.write_state(self.control, st)

    def stop(self) -> None:
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()


if __name__ == "__main__":
    with LocalStack() as st:
        print("gateway:", st.gateway, "| state file:", st.control, "| logs:", st.logs)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
