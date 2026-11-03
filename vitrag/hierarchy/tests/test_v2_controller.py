"""V2: controller API (fakes where Docker is not needed) and probes/availability against the real local stack."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

import controlstate as cs
from controller.app import create_app
from controller.core import Lab
from controller.dockerops import FakeDockerOps
from controller.probes import Rolling, classify


@pytest.fixture()
def fake(tmp_path):
    docker = FakeDockerOps()
    lab = Lab(tmp_path / "control" / "state.json", "http://127.0.0.1:9", docker, probe=False)
    c = TestClient(create_app(lab))
    yield c, lab, docker
    lab.close()


def state_file(lab):
    return json.loads(lab.control_path.read_text())


# ── API shapes (contract C) ──────────────────────────────────────────────────

def test_topology_matches_table_a(fake):
    c, *_ = fake
    t = c.get("/topology").json()
    assert [s["name"] for s in t["services"]] == ["nginx", "auth_api", "product_api", "order_api", "search_api", "database", "cache", "queue"]
    assert {"from": "order_api", "to": "queue"} in t["edges"] and len(t["edges"]) == 12
    by = {s["name"]: s for s in t["services"]}
    assert by["database"]["port"] == 5432 and by["database"]["exposure"] == "internal" and by["auth_api"]["sensitivity"] == "critical"


def test_state_shape(fake):
    c, *_ = fake
    s = c.get("/state").json()
    assert set(s) == {"ts", "services", "cut_edges"} and set(s["services"]) == set(cs.SERVICES)
    assert s["services"]["auth_api"] == {"mode": "normal", "isolated": False, "up": True} and s["cut_edges"] == []


def test_set_mode_updates_state_file_and_state(fake):
    c, lab, _ = fake
    r = c.post("/services/auth_api/mode", json={"mode": "read_only"}, headers={"X-Actor": "tester"})
    assert r.status_code == 200 and r.json()["mode"] == "read_only"
    assert state_file(lab)["services"]["auth_api"]["mode"] == "read_only"
    assert c.get("/state").json()["services"]["auth_api"]["mode"] == "read_only"


def test_errors_are_always_json_error(fake):
    c, *_ = fake
    for resp in (c.post("/services/nope/mode", json={"mode": "normal"}), c.post("/services/auth_api/mode", json={"mode": "turbo"}),
                 c.post("/services/auth_api/mode", json={}), c.post("/edges/cut", json={"from": "auth_api", "to": "ghost"}),
                 c.post("/edges/cut", json={"from": "auth_api", "to": "auth_api"}), c.get("/nothing-here"),
                 c.post("/services/ghost/rotate-credentials")):
        assert resp.status_code >= 400 and list(resp.json()) == ["error"] and isinstance(resp.json()["error"], str), resp.text


def test_cut_and_restore_edges(fake):
    c, lab, _ = fake
    assert c.post("/edges/cut", json={"from": "order_api", "to": "queue"}).status_code == 200
    c.post("/edges/cut", json={"from": "order_api", "to": "queue"})                    # idempotent
    c.post("/edges/cut", json={"from": "queue", "to": "database"})                       # lateral edge between known services is accepted
    assert c.get("/state").json()["cut_edges"] == [{"from": "order_api", "to": "queue"}, {"from": "queue", "to": "database"}]
    c.post("/edges/restore", json={"from": "order_api", "to": "queue"})
    assert c.get("/state").json()["cut_edges"] == [{"from": "queue", "to": "database"}]
    assert state_file(lab)["cut_edges"] == [["queue", "database"]]


def test_isolation_detaches_the_container_and_restore_reattaches(fake):
    c, lab, docker = fake
    r = c.post("/services/database/mode", json={"mode": "isolated"}).json()
    assert docker.calls[-1] == ("disconnect", "database") and c.get("/state").json()["services"]["database"] == {"mode": "isolated", "isolated": True, "up": False}
    c.post("/services/database/mode", json={"mode": "isolated"})                         # no double disconnect
    assert docker.calls.count(("disconnect", "database")) == 1
    c.post("/services/database/mode", json={"mode": "normal"})
    assert docker.calls[-1] == ("reconnect", "database") and c.get("/state").json()["services"]["database"]["up"] is True
    assert r["network_isolation"] == "app-level only"                                   # the fake is not a real docker


def test_non_isolated_modes_do_not_touch_networks(fake):
    c, _, docker = fake
    for m in ("rate_limited", "read_only", "fallback"):
        c.post("/services/search_api/mode", json={"mode": m})
    assert [x for x in docker.calls if x[0] in ("disconnect", "reconnect")] == []


def test_gateway_mode_and_edges_regenerate_the_nginx_include_and_reload(fake):
    c, lab, docker = fake
    n0 = docker.calls.count(("reload_gateway",))
    c.post("/services/nginx/mode", json={"mode": "read_only"})
    assert "capability=state_write" in lab.gateway_conf_path.read_text() and docker.calls.count(("reload_gateway",)) == n0 + 1
    c.post("/edges/cut", json={"from": "nginx", "to": "search_api"})
    assert "edge=nginx-search_api" in lab.gateway_conf_path.read_text() and docker.calls.count(("reload_gateway",)) == n0 + 2
    c.post("/services/auth_api/mode", json={"mode": "fallback"})                          # not a gateway change: no reload
    assert docker.calls.count(("reload_gateway",)) == n0 + 2


def test_rotate_credentials_changes_the_key_and_revokes_the_old_one(fake):
    c, lab, _ = fake
    old = state_file(lab)["credentials"]["product_api"]["current"]
    assert old == cs.initial_key("product_api")
    r = c.post("/services/product_api/rotate-credentials", headers={"X-Actor": "t"}).json()
    cred = state_file(lab)["credentials"]["product_api"]
    assert r["generation"] == 1 and cred["current"] != old and cred["revoked"] == [old]
    c.post("/services/product_api/rotate-credentials")
    assert state_file(lab)["credentials"]["product_api"]["generation"] == 2 and len(state_file(lab)["credentials"]["product_api"]["revoked"]) == 2


def test_reset_restores_everything(fake):
    c, lab, docker = fake
    c.post("/services/database/mode", json={"mode": "isolated"})
    c.post("/services/auth_api/mode", json={"mode": "fallback"})
    c.post("/edges/cut", json={"from": "order_api", "to": "queue"})
    c.post("/services/queue/rotate-credentials")
    assert c.post("/reset").status_code == 200
    s = c.get("/state").json()
    assert all(v["mode"] == "normal" for v in s["services"].values()) and s["cut_edges"] == []
    assert ("reconnect", "database") in docker.calls
    assert state_file(lab)["credentials"]["queue"]["current"] == cs.initial_key("queue")        # leaked gen-0 keys valid again by design


def test_actions_log_is_append_only_attributed_and_includes_errors(fake):
    c, lab, _ = fake
    c.post("/services/auth_api/mode", json={"mode": "read_only"}, headers={"X-Actor": "pipeline"})
    c.post("/services/ghost/mode", json={"mode": "read_only"}, headers={"X-Actor": "pipeline"})
    c.post("/edges/cut", json={"from": "order_api", "to": "queue"}, headers={"X-Actor": "dashboard"})
    a = c.get("/actions").json()
    assert [(x["actor"], x["action"], x["result"][:5]) for x in a] == [("pipeline", "set_mode", "ok"), ("pipeline", "set_mode", "error"), ("dashboard", "cut_edge", "ok")]
    assert set(a[0]) == {"ts", "actor", "action", "args", "result"} and a[0]["args"] == {"service": "auth_api", "mode": "read_only"}
    on_disk = [json.loads(l) for l in lab.actions_path.read_text().splitlines()]
    assert on_disk == a
    c.post("/reset")
    assert c.get("/actions").json()[:3] == a                                              # earlier entries never change


def test_default_actor_is_unknown_and_traffic_endpoints_work(fake):
    c, lab, _ = fake
    assert c.post("/traffic/start", json={"rate_per_s": 2}).json() == {"ok": True, "rate_per_s": 2}
    assert lab.traffic.running
    assert c.post("/traffic/stop").json() == {"ok": True} and not lab.traffic.running
    assert {x["actor"] for x in c.get("/actions").json()} == {"unknown"}


def test_cors_allows_only_the_dashboard_origins(fake):
    c, *_ = fake
    for origin in ("http://localhost:8000", "http://127.0.0.1:8000"):
        r = c.get("/state", headers={"Origin": origin})
        assert r.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-origin" not in c.get("/state", headers={"Origin": "http://evil.example"}).headers
    pre = c.options("/services/auth_api/mode", headers={"Origin": "http://localhost:8000", "Access-Control-Request-Method": "POST"})
    assert pre.status_code == 200 and "POST" in pre.headers["access-control-allow-methods"]


# ── probes ───────────────────────────────────────────────────────────────────

def test_rolling_window_expires_old_samples():
    r = Rolling()
    r.add(False, now=100.0); r.add(True, now=125.0); r.add(True, now=128.0)
    assert r.rate(now=129.0) == pytest.approx(2 / 3)
    assert r.rate(now=140.0) == 1.0                         # the failure at t=100 left the 30 s window
    assert r.rate(now=300.0) is None                        # nothing measured: None, never an invented number


def test_classify_degraded_blocked_and_errors():
    class R:
        def __init__(self, code, h=None): self.status_code, self.headers = code, h or {}
    assert classify(R(200), None, (200,)) == (True, "ok")
    assert classify(R(200, {"X-ACD-Blocked": "mode=fallback; capability=dynamic_query; served=cached"}), None, (200,)) == (True, "degraded")
    assert classify(R(503, {"X-ACD-Blocked": "edge=a-b"}), None, (200,)) == (False, "blocked:503")
    assert classify(R(502), None, (200,)) == (False, "http:502")
    assert classify(None, ConnectionError(), ()) == (False, "error:ConnectionError")


# ── controller against the real local stack ──────────────────────────────────

@pytest.fixture()
def live(stack):
    cs.write_state(stack.control, cs.default_state())
    urls = {s: stack.url(s) for s in ("auth_api", "product_api", "order_api", "search_api", "queue")}

    def direct(service):
        if service == "nginx":
            return httpx.get(stack.gateway + "/healthz").status_code == 200
        if service in urls:
            return httpx.get(urls[service] + "/healthz").status_code == 200
        return None                                         # database/cache have no process in local mode
    lab = Lab(stack.control, stack.gateway, FakeDockerOps(), direct, probe=False)
    yield lab
    lab.reset("test-cleanup")
    lab.close()


def settle(lab):
    lab.prober.reset_window()
    lab.prober.round()


def test_availability_is_measured_through_the_gateway(live):
    settle(live)
    h = live.health()
    assert h["overall_availability"] == 1.0 and {j["name"] for j in h["journeys"]} == {"login", "search", "product_view", "place_order"}
    assert all(j["last_status"] == "ok" for j in h["journeys"]) and h["services"]["auth_api"] == {"ok": True, "ok_rate_30s": 1.0}
    assert next(j for j in h["journeys"] if j["name"] == "place_order")["uses"] == ["nginx", "auth_api", "order_api", "database", "queue"]


def test_isolating_a_service_lowers_only_the_journeys_that_use_it(live):
    live.set_mode("auth_api", "isolated", "test")
    settle(live)
    h = live.health()
    rate = {j["name"]: j["ok_rate_30s"] for j in h["journeys"]}
    assert rate["login"] == 0.0 and rate["place_order"] == 0.0 and rate["search"] == 1.0 and rate["product_view"] == 1.0
    assert h["overall_availability"] == 0.5 and h["services"]["auth_api"]["ok"] is False and h["services"]["search_api"]["ok"] is True


def test_fallback_serves_cached_so_product_view_is_degraded_not_down(live):
    live.set_mode("product_api", "fallback", "test")
    settle(live)
    j = {x["name"]: x for x in live.health()["journeys"]}
    assert j["product_view"]["last_status"] == "degraded" and j["product_view"]["ok_rate_30s"] == 1.0


def test_cut_edge_and_restore_change_measured_availability(live):
    live.cut_edge("nginx", "search_api", "test")
    settle(live)
    assert {j["name"]: j["ok_rate_30s"] for j in live.health()["journeys"]}["search"] == 0.0
    live.restore_edge("nginx", "search_api", "test")
    settle(live)
    assert live.health()["overall_availability"] == 1.0


def test_rotation_invalidates_a_leaked_key_but_services_keep_working(live, stack):
    old = cs.initial_key("product_api")
    h = {"X-Service-Name": "product_api", "X-Service-Key": old}
    assert httpx.get(stack.url("auth_api") + "/auth/admin/users", headers=h).status_code == 200
    live.rotate_credentials("product_api", "test")
    assert httpx.get(stack.url("auth_api") + "/auth/admin/users", headers=h).status_code == 401
    live.set_mode("auth_api", "normal", "test")
    tok = httpx.post(stack.gateway + "/auth/login", json={"username": "bob", "password": "qwerty"}).json()["token"]
    ok = httpx.post(stack.gateway + "/orders", json={"product_id": 1}, headers={"Authorization": f"Bearer {tok}"})
    assert ok.status_code == 201                              # order_api's own (unrotated) key still validates


def test_traffic_generator_produces_benign_requests(live, stack):
    live.traffic.start(10)
    time.sleep(1.5)
    live.traffic.stop()
    log = (stack.logs / "nginx" / "access.log").read_text()
    assert "acd-benign-traffic" in log and live.traffic.sent >= 5
