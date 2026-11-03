"""
probes.py: benign user journeys through the gateway, with a 30 s rolling success rate per journey and per service.

overall_availability = share of journeys whose latest-30s success rate is counted: mean of the journey rates.
A response with X-ACD-Blocked ... served=cached counts as success but is reported as "degraded".
Per-service ok / ok_rate_30s come from direct /healthz-style probes of each service (reachability + not isolated), because
attributing a failed journey to one service would blame innocent hops.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable, Optional

import requests

import controlstate as cs

WINDOW_S = 30.0

JOURNEYS = [
    {"name": "login", "path": "nginx>auth_api>database,cache", "uses": ["nginx", "auth_api", "database", "cache"]},
    {"name": "search", "path": "nginx>search_api>cache", "uses": ["nginx", "search_api", "cache"]},
    {"name": "product_view", "path": "nginx>product_api>database", "uses": ["nginx", "product_api", "database"]},
    {"name": "place_order", "path": "nginx>auth_api,order_api>database,queue", "uses": ["nginx", "auth_api", "order_api", "database", "queue"]},
]


class Rolling:
    def __init__(self) -> None:
        self.q: deque[tuple[float, bool]] = deque()
        self.lock = threading.Lock()

    def add(self, ok: bool, now: Optional[float] = None) -> None:
        with self.lock:
            self.q.append((now or time.time(), ok))

    def rate(self, now: Optional[float] = None) -> Optional[float]:
        now = now or time.time()
        with self.lock:
            while self.q and self.q[0][0] < now - WINDOW_S:
                self.q.popleft()
            if not self.q:
                return None
            return sum(1 for _, ok in self.q if ok) / len(self.q)


def classify(r: Optional[requests.Response], exc: Optional[Exception], expect: tuple[int, ...]) -> tuple[bool, str]:
    if exc is not None:
        return False, f"error:{exc.__class__.__name__}"
    blocked = r.headers.get("X-ACD-Blocked")
    if blocked:
        if r.status_code in expect and "served=cached" in blocked:
            return True, "degraded"
        return False, f"blocked:{r.status_code}"
    return (r.status_code in expect), ("ok" if r.status_code in expect else f"http:{r.status_code}")


def run_journey(name: str, gateway: str, user: str = "alice", password: str = "password", ua: str = "acd-probe") -> tuple[bool, str]:
    """Execute one benign journey; returns (ok, last_status). Used by both the prober and the traffic generator."""
    s = requests.Session()
    s.headers["User-Agent"] = ua
    t = 4
    try:
        if name == "login":
            r = s.post(gateway + "/auth/login", json={"username": user, "password": password}, timeout=t)
            return classify(r, None, (200,))
        if name == "search":
            return classify(s.get(gateway + "/search?q=wid", timeout=t), None, (200,))
        if name == "product_view":
            return classify(s.get(gateway + "/api/products?id=1", timeout=t), None, (200,))
        if name == "place_order":
            r = s.post(gateway + "/auth/login", json={"username": user, "password": password}, timeout=t)
            if r.status_code != 200:
                return classify(r, None, (200,))
            tok = r.json()["token"]
            r = s.post(gateway + "/orders", json={"product_id": 1, "qty": 1}, headers={"Authorization": f"Bearer {tok}"}, timeout=t)
            return classify(r, None, (201,))
    except requests.RequestException as e:
        return classify(None, e, ())
    raise ValueError(name)


class Prober:
    def __init__(self, gateway: str, direct: Optional[Callable[[str], Optional[bool]]] = None, interval: float = 2.0):
        self.gateway, self.direct, self.interval = gateway, direct, interval
        self.journeys = {j["name"]: Rolling() for j in JOURNEYS}
        self.services = {s: Rolling() for s in cs.SERVICES}
        self.last: dict[str, str] = {}
        self.last_ok: dict[str, bool] = {}
        self.rounds = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def round(self) -> None:
        for j in JOURNEYS:
            ok, status = run_journey(j["name"], self.gateway)
            self.journeys[j["name"]].add(ok)
            self.last[j["name"]], self.last_ok[j["name"]] = status, ok
        if self.direct:
            for s in cs.SERVICES:
                v = self.direct(s)
                if v is not None:
                    self.services[s].add(v)
        self.rounds += 1

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                t0 = time.time()
                try:
                    self.round()
                except Exception:  # noqa: BLE001  a probe bug must never kill the loop
                    pass
                self._stop.wait(max(0.0, self.interval - (time.time() - t0)))
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def reset_window(self) -> None:
        for r in [*self.journeys.values(), *self.services.values()]:
            with r.lock:
                r.q.clear()

    def health(self) -> dict[str, Any]:
        if self.rounds == 0:
            self.round()                       # never report availability we have not measured
        js = []
        for j in JOURNEYS:
            rate = self.journeys[j["name"]].rate()
            js.append({"name": j["name"], "path": j["path"], "uses": j["uses"],
                       "ok_rate_30s": round(rate if rate is not None else 0.0, 3), "last_status": self.last.get(j["name"], "unknown")})
        overall = sum(x["ok_rate_30s"] for x in js) / len(js)
        svcs = {}
        for s in cs.SERVICES:
            rate = self.services[s].rate()
            if rate is None:                   # no direct probe for this service: derive from the journeys that use it
                used = [x["ok_rate_30s"] for x in js if s in x["uses"]]
                rate = min(used) if used else 0.0
            svcs[s] = {"ok": rate > 0, "ok_rate_30s": round(rate, 3)}
        return {"overall_availability": round(overall, 3), "journeys": js, "services": svcs}
