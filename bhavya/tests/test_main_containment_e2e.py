"""End-to-end: POST /alerts -> containment decision actually executed against a fake controller -> API surfaces it."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from tests.test_containment import make_fake_controller


def make_app(autonomy="auto"):
    # Imported here, not at module top: pipeline.main pulls in pipeline.storage, which binds its SQLite path
    # from ACD_DB_PATH at *import* time. conftest.py's autouse _isolated_db fixture sets that env var before
    # any test BODY runs, but module-level imports happen at collection time, before fixtures run -- importing
    # eagerly here would bind storage to the real bhavya/data/incidents.db instead of the session's temp one.
    from pipeline.containment.controller_client import ControllerClient
    from pipeline.containment.manager import ContainmentManager
    from pipeline.main import create_app

    fake, state, calls = make_fake_controller()
    http = TestClient(fake, base_url="http://fake-controller")
    client = ControllerClient("http://fake-controller", http=http)
    mgr = ContainmentManager(client=client, autonomy=autonomy)
    app = create_app(mgr)
    tc = TestClient(app)
    tc.__enter__()  # trigger the lifespan (init_db) without needing every test to use `with`
    return tc, state, calls, mgr


def sqli_alert():
    return {"source": "wazuh", "timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"rule": {"id": 31103, "level": 11, "description": "Web attack: SQL injection attempt."},
                        "data": {"srcip": "198.51.100.7", "dstip": "10.0.0.5", "dstport": 5001, "event_count": 5,
                                "url": "/api/products?id=1' OR 1=1--", "user_agent": "sqlmap/1.7"},
                        "timestamp": "2026-01-01T00:00:00Z"}}


def hierarchy_alert(rule_id, level, desc, port, **extra):
    data = {"srcip": "203.0.113.50", "dstip": "10.0.0.5", "dstport": port, "event_count": 1}
    data.update(extra)
    return {"source": "wazuh", "timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"rule": {"id": rule_id, "level": level, "description": desc}, "data": data,
                        "timestamp": "2026-01-01T00:00:00Z"}}


def test_alert_triggers_real_containment_against_the_controller():
    c, state, calls, mgr = make_app("auto")
    r = c.post("/alerts", json=sqli_alert())
    assert r.status_code == 201 and r.json()["containment"] == "scheduled"
    # TestClient runs BackgroundTasks synchronously before the response handler returns control to us
    assert state["modes"]["product_api"] == "fallback"
    decisions = c.get("/api/decisions").json()["items"]
    assert decisions and decisions[0]["compromised_service"] == "product_api"
    assert decisions[0]["status"] == "executed"
    assert "nginx->product_api" in {a["target"] for a in decisions[0]["actions"]}


def test_new_hierarchy_services_and_rule_ids_are_recognised():
    c, state, calls, mgr = make_app("auto")
    r = c.post("/alerts", json=hierarchy_alert(100302, 11, "Unauthorized internal admin access.", 5432,
                                               source_service="queue"))
    assert r.status_code == 201
    body = r.json()
    assert body["service"] == "database" and body["attack_type"] == "lateral_movement" and body["severity"] == "high"  # level 11 -> "high" (derive_severity: >=12 critical, >=9 high)
    assert state["modes"]["database"] == "isolated"


def test_approve_flow_through_the_api():
    c, state, calls, mgr = make_app("approve")
    c.post("/alerts", json=sqli_alert())
    pending = c.get("/api/decisions").json()["items"]
    assert pending[0]["status"] == "pending_approval" and state["modes"]["product_api"] == "normal"
    did = pending[0]["decision_id"]
    r = c.post(f"/api/decisions/{did}/approve")
    assert r.status_code == 200 and r.json()["status"] == "executed"
    assert state["modes"]["product_api"] == "fallback"
    assert c.post(f"/api/decisions/{did}/approve").status_code == 409
    assert c.post("/api/decisions/nope/approve").status_code == 404
    assert c.get("/api/decisions/nope").status_code == 404
    assert c.get(f"/api/decisions/{did}").json()["decision_id"] == did


def test_forensics_endpoint_reflects_real_alerts():
    c, state, calls, mgr = make_app("auto")
    ip = "203.0.113.201"  # unique to this test: the incidents table is shared across the whole test session,
                         # so filter by source_ip rather than assuming this test's alerts are the only ones stored
    c.post("/alerts", json=hierarchy_alert(100103, 11, "Web attack: SQL injection attempt.", 5001, srcip=ip))
    c.post("/alerts", json=hierarchy_alert(100301, 10, "Dependency abuse or credential reuse detected.", 5000, srcip=ip))
    rec = c.get(f"/api/forensics?ip={ip}").json()
    assert rec["attack_path"] == ["product_api", "auth_api"]
    assert rec["origin_service"] == "product_api"
    assert all(s["contained"] for s in rec["steps"])


def test_config_endpoint():
    c, *_ = make_app("approve")
    cfg = c.get("/api/config").json()
    assert cfg["autonomy"] == "approve" and cfg["controller_url"] == "http://fake-controller"


def test_ui_is_served():
    c, *_ = make_app()
    r = c.get("/ui")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert c.get("/ui/app.js").status_code == 200 and c.get("/ui/style.css").status_code == 200
    assert c.get("/ui/secret").status_code == 404


def test_lab_proxy_forwards_reads_and_blocks_everything_else():
    c, state, calls, mgr = make_app("auto")
    t = c.get("/api/lab/topology").json()
    assert len(t["services"]) == 8
    s = c.get("/api/lab/state").json()
    assert set(s["services"]) == {"auth_api", "product_api", "order_api", "search_api", "database", "cache", "queue", "nginx"}
    assert c.get("/api/lab/health").status_code == 502  # fake controller doesn't implement /health -> ControllerClient raises -> 502
    assert c.get("/api/lab/services/auth_api/mode").status_code == 403       # not one of the three allowed paths
    assert c.get("/api/lab/../healthz").status_code in (403, 404)


def test_lab_proxy_502_when_controller_unreachable():
    from pipeline.containment.controller_client import ControllerClient
    from pipeline.containment.manager import ContainmentManager
    from pipeline.main import create_app
    mgr = ContainmentManager(client=ControllerClient("http://127.0.0.1:1", timeout=1.0), autonomy="auto")
    c = TestClient(create_app(mgr))
    r = c.get("/api/lab/topology")
    assert r.status_code == 502 and "controller unreachable" in r.json()["detail"]
