"""
core.py: the controller's state machine. Everything that changes the lab goes through Lab so it is logged
(append-only actions log), written to /control/state.json atomically, and (for isolation / the gateway) applied to Docker.
"""

from __future__ import annotations

import json
import os
import random
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests

import controlstate as cs
import gateway_rules as gr
from controller.attackers import AgentClient, DirectClient, make_attackers
from controller.dockerops import NullDockerOps
from controller.probes import JOURNEYS, Prober, run_journey
from controller.scenarios import SCENARIOS, ScenarioRunner


class LabError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_direct_probe(gateway_url: str) -> Callable[[str], Optional[bool]]:
    """Reachability probe per service: HTTP /healthz for Flask services and the gateway, TCP connect for postgres/redis."""
    def probe(service: str) -> Optional[bool]:
        try:
            if service == "nginx":
                return requests.get(gateway_url + "/healthz", timeout=2).status_code == 200
            if service in ("database", "cache"):
                if os.getenv("ACD_NO_INFRA_PROBE"):
                    return None                       # local-process runs have no postgres/redis process to probe
                host = os.getenv(f"SERVICE_HOST_{service.upper()}", service)
                port = int(os.getenv(f"SERVICE_PORT_{service.upper()}", cs.PORTS[service]))
                with socket.create_connection((host, port), timeout=2):
                    return True
            url = os.getenv(f"SERVICE_URL_{service.upper()}", f"http://{service}:{cs.PORTS[service]}")
            return requests.get(url + "/healthz", timeout=2).status_code == 200
        except (OSError, requests.RequestException):
            return False
    return probe


class TrafficGen:
    """Benign background traffic: random journeys at rate_per_s, tagged with their own User-Agent."""

    def __init__(self, gateway: str):
        self.gateway = gateway
        self.rate = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.sent = 0

    def start(self, rate: int) -> None:
        self.stop()
        self.rate = max(1, int(rate))
        self._stop = threading.Event()
        stop = self._stop

        def loop():
            users = [("alice", "password"), ("bob", "qwerty"), ("charlie", "changeme")]
            while not stop.is_set():
                name = random.choice([j["name"] for j in JOURNEYS])
                u, p = random.choice(users)
                threading.Thread(target=lambda: run_journey(name, self.gateway, u, p, "acd-benign-traffic"), daemon=True).start()
                self.sent += 1
                stop.wait(1.0 / self.rate)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.rate = 0

    @property
    def running(self) -> bool:
        return self.rate > 0 and not self._stop.is_set()


class Lab:
    def __init__(self, control_path: str | os.PathLike, gateway_url: str, docker: Optional[NullDockerOps] = None,
                 direct: Optional[Callable[[str], Optional[bool]]] = None, probe: bool = True, probe_interval: float = 2.0,
                 gateway_conf_path: Optional[str | os.PathLike] = None, attackers: Optional[dict[str, Any]] = None,
                 sink_url: Optional[str] = None):
        self.control_path = Path(control_path)
        self.gateway_conf_path = Path(gateway_conf_path) if gateway_conf_path else self.control_path.parent / "gateway_http.conf"
        self.actions_path = self.control_path.parent / "actions.jsonl"
        self.docker = docker or NullDockerOps()
        self.gateway_url = gateway_url
        self.lock = threading.RLock()
        self.actions: list[dict[str, Any]] = []
        self.detached: set[str] = set()
        self.state = cs.default_state()
        self._publish()                                    # write the initial state + gateway include
        self.prober = Prober(gateway_url, direct, probe_interval)
        self.traffic = TrafficGen(gateway_url)
        self.runs: dict[str, Any] = {}                     # scenario runs (V3)
        self.attackers = attackers or make_attackers()
        self.sink_url = sink_url or os.getenv("SINK_URL", "http://alert-sink:8099")
        self.scenario_runner = ScenarioRunner(self)
        if probe:
            self.prober.start()

    # -- plumbing ----------------------------------------------------------
    def log(self, actor: str, action: str, args: dict[str, Any], result: str) -> None:
        entry = {"ts": now_iso(), "actor": actor, "action": action, "args": args, "result": result}
        with self.lock:
            self.actions.append(entry)
            with open(self.actions_path, "a") as f:        # append-only on disk as well
                f.write(json.dumps(entry) + "\n")

    def _publish(self) -> None:
        self.state["version"] = self.state.get("version", 0) + 1
        self.state["ts"] = now_iso()
        cs.write_state(self.control_path, self.state)
        conf = gr.render_nginx_conf(self.state)
        old = self.gateway_conf_path.read_text() if self.gateway_conf_path.exists() else None
        if conf != old:
            tmp = self.gateway_conf_path.with_suffix(".tmp")
            tmp.write_text(conf)
            os.replace(tmp, self.gateway_conf_path)
            if old is not None:
                self.docker.reload_gateway()

    @staticmethod
    def _check_service(name: str) -> None:
        if name not in cs.SERVICES:
            raise LabError(f"unknown service {name!r}", 404)

    def _guard(self, actor: str, action: str, args: dict, fn: Callable[[], Any]) -> Any:
        try:
            out = fn()
        except LabError as e:
            self.log(actor, action, args, f"error: {e}")
            raise
        self.log(actor, action, args, "ok")
        return out

    # -- API operations ----------------------------------------------------
    def set_mode(self, name: str, mode: str, actor: str = "unknown") -> dict[str, Any]:
        def go():
            self._check_service(name)
            if mode not in cs.MODES:
                raise LabError(f"invalid mode {mode!r}; one of {cs.MODES}")
            with self.lock:
                prev = cs.mode_of(self.state, name)
                self.state["services"][name] = {"mode": mode}
                self._publish()
                nets: list[str] = []
                if mode == "isolated" and name not in self.detached:
                    nets = self.docker.disconnect(name)
                    self.detached.add(name)
                elif prev == "isolated" and mode != "isolated" and name in self.detached:
                    nets = self.docker.reconnect(name)
                    self.detached.discard(name)
            return {"ok": True, "service": name, "mode": mode, "previous": prev,
                    "network_isolation": "docker" if self.docker.real else "app-level only", "networks_changed": nets}
        return self._guard(actor, "set_mode", {"service": name, "mode": mode}, go)

    def _edge(self, a: str, b: str, cut: bool, actor: str) -> dict[str, Any]:
        def go():
            self._check_service(a)
            self._check_service(b)
            if a == b:
                raise LabError("an edge needs two different services")
            with self.lock:
                edges = [list(e) for e in self.state["cut_edges"]]
                if cut and [a, b] not in edges:
                    edges.append([a, b])
                if not cut:
                    edges = [e for e in edges if e != [a, b]]
                self.state["cut_edges"] = edges
                self._publish()
            return {"ok": True, "from": a, "to": b}
        return self._guard(actor, "cut_edge" if cut else "restore_edge", {"from": a, "to": b}, go)

    def cut_edge(self, a: str, b: str, actor: str = "unknown"):
        return self._edge(a, b, True, actor)

    def restore_edge(self, a: str, b: str, actor: str = "unknown"):
        return self._edge(a, b, False, actor)

    def rotate_credentials(self, name: str, actor: str = "unknown") -> dict[str, Any]:
        def go():
            self._check_service(name)
            with self.lock:
                cred = cs.credential(self.state, name)
                gen = cred["generation"] + 1
                self.state["credentials"][name] = {"current": f"rot-{name}-g{gen}-{secrets.token_hex(6)}", "generation": gen,
                                                   "revoked": [*cred.get("revoked", []), cred["current"]]}
                self._publish()
            return {"ok": True, "service": name, "generation": gen, "revoked_previous": True}
        return self._guard(actor, "rotate_credentials", {"service": name}, go)

    def reset(self, actor: str = "unknown") -> dict[str, Any]:
        def go():
            with self.lock:
                for name in list(self.detached):
                    self.docker.reconnect(name)
                self.detached.clear()
                self.state = {**cs.default_state(), "version": self.state.get("version", 0)}
                self._publish()
                self.prober.reset_window()
            return {"ok": True}
        return self._guard(actor, "reset", {}, go)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            svcs = {}
            for s in cs.SERVICES:
                mode = cs.mode_of(self.state, s)
                run = self.docker.is_running(s)
                svcs[s] = {"mode": mode, "isolated": mode == "isolated", "up": (run if run is not None else True)}
            return {"ts": now_iso(), "services": svcs, "cut_edges": [{"from": a, "to": b} for a, b in self.state["cut_edges"]]}

    def topology(self) -> dict[str, Any]:
        return {"services": cs.TOPOLOGY["services"], "edges": [{"from": a, "to": b} for a, b in cs.EDGES]}

    def health(self) -> dict[str, Any]:
        return self.prober.health()

    # -- scenarios (V3) -----------------------------------------------------
    def list_scenarios(self) -> list[dict[str, Any]]:
        return [{"id": k, "name": v["name"], "description": v["description"]} for k, v in SCENARIOS.items()]

    def run_scenario(self, scenario_id: str, seed: Optional[int], actor: str = "unknown") -> str:
        def go():
            try:
                run = self.scenario_runner.start(scenario_id, seed)
            except KeyError:
                raise LabError(f"unknown scenario {scenario_id!r}", 404)
            with self.lock:
                self.runs[run["run_id"]] = run
            return run["run_id"]
        return self._guard(actor, "run_scenario", {"scenario_id": scenario_id, "seed": seed}, go)

    def get_run(self, run_id: str) -> dict[str, Any]:
        run = self.runs.get(run_id)
        if run is None:
            raise LabError(f"unknown run {run_id!r}", 404)
        return {"status": run["status"], "scenario_id": run["scenario_id"], "started_at": run["started_at"], "ended_at": run["ended_at"]}

    def get_ground_truth(self, run_id: str) -> dict[str, Any]:
        run = self.runs.get(run_id)
        if run is None:
            raise LabError(f"unknown run {run_id!r}", 404)
        with self.lock:
            import copy
            return copy.deepcopy(run["gt"])

    def stop_run(self, run_id: str, actor: str = "unknown") -> dict[str, Any]:
        def go():
            run = self.runs.get(run_id)
            if run is None:
                raise LabError(f"unknown run {run_id!r}", 404)
            run["stop"].set()
            return {"ok": True}
        return self._guard(actor, "stop_run", {"run_id": run_id}, go)

    def close(self) -> None:
        self.prober.stop()
        self.traffic.stop()
