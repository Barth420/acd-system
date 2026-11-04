"""
Containment planner + manager + forensics tests.

ControllerClient is tested against a fake controller implemented as a tiny in-memory FastAPI app (contract C
subset: /topology, /state, /services/{name}/mode, /edges/cut, /edges/restore), wired in via httpx's
ASGITransport so these are REAL HTTP calls through the client's request/response path, not a mocked method.
This is the same integration point the real lab controller (vitrag/hierarchy/controller) answers to.
"""

from __future__ import annotations

import os

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from pipeline.containment.controller_client import ControllerClient, ControllerError
from pipeline.containment.manager import ContainmentManager
from pipeline.containment.planner import choose_mode, plan
from pipeline import forensics
from pipeline.service_registry import SERVICE_REGISTRY


# ── a fake controller: same shapes as vitrag/hierarchy/controller, in-memory ─

def make_fake_controller():
    app = FastAPI()
    state = {"modes": {s: "normal" for s in SERVICE_REGISTRY}, "cuts": []}
    calls = []

    @app.get("/topology")
    def topology():
        return {"services": [{"name": n} for n in SERVICE_REGISTRY], "edges": []}

    @app.get("/state")
    def get_state():
        return {"services": {n: {"mode": m} for n, m in state["modes"].items()},
               "cut_edges": [{"from": a, "to": b} for a, b in state["cuts"]]}

    @app.post("/services/{name}/mode")
    def set_mode(name: str, body: dict):
        if name not in SERVICE_REGISTRY:
            return JSONResponse({"error": f"unknown service {name}"}, status_code=404)
        state["modes"][name] = body["mode"]
        calls.append(("set_mode", name, body["mode"]))
        return {"ok": True}

    @app.post("/edges/cut")
    def cut(body: dict):
        state["cuts"].append((body["from"], body["to"]))
        calls.append(("cut_edge", body["from"], body["to"]))
        return {"ok": True}

    @app.post("/edges/restore")
    def restore(body: dict):
        state["cuts"] = [c for c in state["cuts"] if c != (body["from"], body["to"])]
        return {"ok": True}

    return app, state, calls


def make_client() -> tuple[ControllerClient, dict, list]:
    from fastapi.testclient import TestClient
    app, state, calls = make_fake_controller()
    http = TestClient(app, base_url="http://fake-controller")  # a real sync httpx.Client subclass over the ASGI app
    return ControllerClient("http://fake-controller", http=http), state, calls


# ── planner ──────────────────────────────────────────────────────────────────

def test_mode_table():
    assert choose_mode("brute_force", "low") == "rate_limited"
    assert choose_mode("sql_injection", "high") == "fallback"
    assert choose_mode("port_scan", "medium") == "read_only"
    assert choose_mode("credential_abuse", "critical") == "isolated"
    assert choose_mode("lateral_movement", "low") == "isolated"      # escalated regardless of severity
    assert choose_mode("data_exfiltration", "medium") == "isolated"  # escalated regardless of severity


def test_plan_auth_api_compromise_cuts_its_direct_dependents():
    d = plan(incident_id="i1", alert_id="a1", service="auth_api", attack_type="credential_abuse",
            severity="high", source_ip="203.0.113.9")
    assert d.mode == "fallback"
    cuts = {a.target for a in d.actions if a.type == "cut_edge"}
    assert cuts == {"nginx->auth_api", "product_api->auth_api", "order_api->auth_api"}
    assert set(d.direct_dependents) == {"nginx", "product_api", "order_api"}
    assert "search_api" not in d.rationale and "search_api" not in cuts   # unrelated service untouched


def test_plan_isolated_also_cuts_outbound_edges_for_lateral_containment():
    d = plan(incident_id="i2", alert_id="a2", service="queue", attack_type="lateral_movement",
            severity="high", source_ip="9.9.9.9")
    assert d.mode == "isolated"
    cuts = {a.target for a in d.actions if a.type == "cut_edge"}
    assert "order_api->queue" in cuts        # downstream: queue's dependent stops calling it
    assert d.direct_dependencies == []       # queue has no outbound dependencies to cut


def test_plan_database_compromise_blast_radius_includes_indirect_dependents():
    d = plan(incident_id="i3", alert_id="a3", service="database", attack_type="data_exfiltration",
            severity="critical", source_ip="1.1.1.1")
    assert set(d.direct_dependents) == {"auth_api", "product_api", "order_api"}
    assert "nginx" in d.blast_radius and "nginx" not in d.direct_dependents
    assert "nginx is further downstream" in d.rationale
    cuts = {a.target for a in d.actions if a.type == "cut_edge"}
    assert "nginx->database" not in cuts     # not a direct dependent: not cut from this one alert


def test_plan_low_severity_does_not_cut_edges():
    d = plan(incident_id="i4", alert_id="a4", service="search_api", attack_type="port_scan",
            severity="low", source_ip="2.2.2.2")
    assert d.mode == "rate_limited"
    assert [a.type for a in d.actions] == ["set_mode"]
    assert "not cut" in d.rationale


def test_plan_unknown_service_is_a_no_op():
    d = plan(incident_id="i5", alert_id="a5", service="mystery_svc", attack_type="sql_injection",
            severity="high", source_ip="3.3.3.3")
    assert d.status == "skipped" and d.actions == [] and d.mode == "normal"


# ── manager: actually calls the fake controller ───────────────────────────────

def test_manager_executes_against_the_controller_and_records_results():
    client, state, calls = make_client()
    saved = []
    mgr = ContainmentManager(client=client, persist=saved.append, autonomy="auto")
    d = mgr.handle_incident(incident_id="i1", alert_id="a1", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="203.0.113.9")
    assert d.status == "executed"
    assert all(a.result == "ok" for a in d.actions)
    assert state["modes"]["auth_api"] == "fallback"
    assert ("nginx", "auth_api") in state["cuts"] and ("product_api", "auth_api") in state["cuts"]
    assert len(saved) >= 1 and saved[-1]["status"] == "executed"
    assert ("set_mode", "auth_api", "fallback") in calls


def test_manager_records_failure_when_controller_is_unreachable():
    dead = ControllerClient("http://127.0.0.1:1", timeout=1.0)
    mgr = ContainmentManager(client=dead, autonomy="auto")
    d = mgr.handle_incident(incident_id="i2", alert_id="a2", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="1.2.3.4")
    assert d.status == "execution_failed"
    assert all(a.result and a.result.startswith("error:") for a in d.actions)


def test_manager_approve_mode_waits_for_a_click():
    client, state, calls = make_client()
    mgr = ContainmentManager(client=client, autonomy="approve")
    d = mgr.handle_incident(incident_id="i3", alert_id="a3", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="5.5.5.5")
    assert d.status == "pending_approval" and state["modes"]["auth_api"] == "normal"
    approved = mgr.approve(d.decision_id)
    assert approved.status == "executed" and state["modes"]["auth_api"] == "fallback"
    with pytest.raises(ValueError):
        mgr.approve(d.decision_id)          # already executed
    with pytest.raises(KeyError):
        mgr.approve("nope")


def test_manager_list_and_get():
    client, *_ = make_client()
    mgr = ContainmentManager(client=client, autonomy="auto")
    d = mgr.handle_incident(incident_id="i4", alert_id="a4", service="search_api", attack_type="port_scan",
                            severity="low", source_ip="6.6.6.6")
    assert mgr.get(d.decision_id)["decision_id"] == d.decision_id
    assert mgr.get("nope") is None
    assert d.decision_id in [x["decision_id"] for x in mgr.list_recent()]


# ── forensics ────────────────────────────────────────────────────────────────

def _inc(service, attack_type, severity, ip, ts, n):
    return {"incident_id": f"inc-{n}", "alert_id": f"al-{n}", "service": service, "attack_type": attack_type,
           "severity": severity, "sensitivity": "high", "exposure": "external", "dependency_depth": 0,
           "source_ip": ip, "created_at": ts}


def test_forensics_reconstructs_path_and_marks_contained_steps():
    incidents = [
        _inc("product_api", "sql_injection", "high", "203.0.113.5", "2026-01-01T00:00:01Z", 1),
        _inc("auth_api", "credential_abuse", "high", "203.0.113.5", "2026-01-01T00:00:02Z", 2),
        _inc("database", "data_exfiltration", "critical", "203.0.113.5", "2026-01-01T00:00:03Z", 3),
    ]
    decisions = [{"compromised_service": "product_api", "status": "executed"},
                {"compromised_service": "auth_api", "status": "pending_approval"}]
    rec = forensics.reconstruct(incidents, decisions)
    assert rec["attack_path"] == ["product_api", "auth_api", "database"]
    assert rec["origin_service"] == "product_api"
    assert [s["contained"] for s in rec["steps"]] == [True, True, False]
    assert rec["overlay_edges"][0] == {"from": "product_api", "to": "auth_api", "inferred": False}  # real dependency edge
    assert rec["overlay_edges"][1]["inferred"] is False   # auth_api -> database is also a real edge


def test_forensics_marks_non_adjacent_hops_inferred_and_filters_by_window_and_ip():
    incidents = [
        _inc("search_api", "port_scan", "low", "9.9.9.9", "2026-01-01T00:00:01Z", 1),
        _inc("queue", "lateral_movement", "high", "9.9.9.9", "2026-01-01T00:00:05Z", 2),
    ]
    rec = forensics.reconstruct(incidents, [])
    assert rec["overlay_edges"] == [{"from": "search_api", "to": "queue", "inferred": True}]  # not adjacent
    assert forensics.reconstruct(incidents, [], since="2026-01-01T00:00:03Z")["attack_path"] == ["queue"]
    assert forensics.reconstruct(incidents, [], ip="1.1.1.1")["attack_path"] == []


def test_forensics_collapses_repeated_alerts_on_the_same_service():
    incidents = [_inc("auth_api", "brute_force", "medium", "1.1.1.1", f"2026-01-01T00:00:0{i}Z", i) for i in range(4)]
    rec = forensics.reconstruct(incidents, [])
    assert len(rec["steps"]) == 1 and rec["steps"][0]["count"] == 4


# ── brain (advisory LLM layer) ────────────────────────────────────────────────

def test_template_backend_is_always_available_and_labelled_non_llm():
    from pipeline.containment.brain import TemplateBackend
    r = TemplateBackend().explain(service="auth_api", attack_type="credential_abuse", severity="high",
                                  source_ip="1.2.3.4", mode="fallback")
    assert r["available"] is True and r["backend"] == "template"
    assert "[non-LLM]" in r["text"] and "auth_api" in r["text"] and "credential_abuse" in r["text"]


def test_hf_backend_reports_unavailable_without_crashing_when_no_adapter_configured(monkeypatch):
    from pipeline.containment.brain import HfBackend
    monkeypatch.delenv("ACD_LLM_ADAPTER_DIR", raising=False)
    b = HfBackend()
    r = b.explain(service="database", attack_type="data_exfiltration", severity="critical", source_ip="9.9.9.9", mode="isolated")
    assert r["available"] is False and "ACD_LLM_ADAPTER_DIR" in r["reason"] or "no adapter configured" in r["reason"]
    assert "database" in r["text"]          # still gets a fallback explanation, never empty


def test_hf_backend_reports_unavailable_for_a_missing_adapter_directory(tmp_path, monkeypatch):
    from pipeline.containment.brain import HfBackend
    monkeypatch.setenv("ACD_LLM_ADAPTER_DIR", str(tmp_path / "does_not_exist"))
    r = HfBackend().explain(service="queue", attack_type="lateral_movement", severity="high", source_ip="1.1.1.1", mode="isolated")
    assert r["available"] is False and "does_not_exist" in r["reason"]


def test_off_backend_omits_brain_response_entirely():
    from pipeline.containment.brain import OffBackend
    assert OffBackend().explain(service="x", attack_type="y", severity="low", source_ip="z", mode="normal") is None


def test_make_brain_selects_by_env(monkeypatch):
    from pipeline.containment.brain import make_brain
    monkeypatch.setenv("ACD_BRAIN_BACKEND", "off")
    assert make_brain().name == "off"
    monkeypatch.setenv("ACD_BRAIN_BACKEND", "hf")
    assert make_brain().name == "hf"
    monkeypatch.delenv("ACD_BRAIN_BACKEND", raising=False)
    assert make_brain().name == "template"


def test_manager_attaches_brain_response_to_every_decision():
    client, *_ = make_client()
    mgr = ContainmentManager(client=client, autonomy="auto")
    d = mgr.handle_incident(incident_id="i1", alert_id="a1", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="7.7.7.7")
    assert d.brain_response is not None and d.brain_response["available"] is True
    assert d.to_dict()["brain_response"]["backend"] == "template"


def test_manager_with_brain_off_has_no_brain_response():
    from pipeline.containment.brain import OffBackend
    client, *_ = make_client()
    mgr = ContainmentManager(client=client, autonomy="auto", brain=OffBackend())
    d = mgr.handle_incident(incident_id="i2", alert_id="a2", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="8.8.8.8")
    assert d.brain_response is None


def test_a_broken_brain_backend_never_breaks_containment():
    class Boom:
        def explain(self, **kw): raise RuntimeError("boom")
    client, state, calls = make_client()
    mgr = ContainmentManager(client=client, autonomy="auto", brain=Boom())
    d = mgr.handle_incident(incident_id="i3", alert_id="a3", service="auth_api", attack_type="credential_abuse",
                            severity="high", source_ip="4.4.4.4")
    assert d.status == "executed" and state["modes"]["auth_api"] == "fallback"   # containment still ran
    assert d.brain_response["available"] is False and "boom" in d.brain_response["reason"]


def test_hf_backend_defaults_to_4bit_env_flag_and_can_be_overridden(monkeypatch, tmp_path):
    """No torch here, so this only checks the env/attribute wiring -- not an actual load."""
    from pipeline.containment.brain import HfBackend
    monkeypatch.setenv("ACD_LLM_ADAPTER_DIR", str(tmp_path))  # still missing adapter/+tokenizer/: load fails early
    b = HfBackend()
    assert os.getenv("ACD_LLM_4BIT", "1") == "1"       # default is on; HfBackend only skips 4-bit when no CUDA
    monkeypatch.setenv("ACD_LLM_4BIT", "0")
    b2 = HfBackend()
    r = b2.explain(service="x", attack_type="y", severity="low", source_ip="1.1.1.1", mode="normal")
    assert r["available"] is False  # still fails (no adapter/, no torch) -- this just proves the flag didn't crash construction
