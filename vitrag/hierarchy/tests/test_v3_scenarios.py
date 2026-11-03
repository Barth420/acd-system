"""
V3: attack scenarios S0-S6 with ground truth, against the REAL local stack (real services, sqlite/file stand-ins for
postgres/redis, Python stand-in gateway) and the REAL controller code (docker disconnect disabled via FakeDockerOps;
network isolation is V2/compose territory, already covered there). Two real DirectClients bound to 127.0.0.2 / 127.0.0.3
stand in for the attacker-1 / attacker-2 containers, so outcomes and source-IP separation are genuinely observed, not
hard-coded. See attacker/agent.py and controller/attackers.py for why distinct loopback binds give real distinct source IPs.
"""

from __future__ import annotations

import json
import time

import httpx
import pytest

import controlstate as cs
from controller.attackers import DirectClient
from controller.core import Lab
from controller.dockerops import FakeDockerOps
from controller.scenarios import SCENARIOS


@pytest.fixture()
def runner(stack):
    cs.write_state(stack.control, cs.default_state())
    attackers = {"attacker-1": DirectClient("127.0.0.2"), "attacker-2": DirectClient("127.0.0.3")}
    lab = Lab(stack.control, stack.gateway, FakeDockerOps(), probe=False, attackers=attackers, sink_url="http://127.0.0.1:1")
    yield lab, stack
    lab.close()


def run_and_wait(lab, sid, seed=1, timeout=25):
    rid = lab.run_scenario(sid, seed, "test")
    end = time.time() + timeout
    while time.time() < end and lab.get_run(rid)["status"] == "running":
        time.sleep(0.05)
    return rid, lab.get_ground_truth(rid)


def outcomes(gt):
    return [s["outcome"] for s in gt["steps"]]


def read(stack, rel):
    p = stack.logs / rel
    return p.read_text() if p.exists() else ""


# ── API / catalogue ───────────────────────────────────────────────────────────

def test_scenario_catalogue_matches_contract_c():
    assert list(SCENARIOS) == ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
    for sid, s in SCENARIOS.items():
        assert s["name"] and s["description"]


def test_unknown_scenario_is_a_404(runner):
    lab, _ = runner
    with pytest.raises(Exception) as e:
        lab.run_scenario("S9", None, "test")
    assert getattr(e.value, "status", None) == 404


def test_run_and_ground_truth_lifecycle(runner):
    lab, _ = runner
    rid, gt = run_and_wait(lab, "S0")
    assert lab.get_run(rid)["status"] == "finished"
    assert gt["run_id"] == rid and gt["scenario_id"] == "S0" and gt["steps"] == []
    with pytest.raises(Exception):
        lab.get_run("nope")
    with pytest.raises(Exception):
        lab.get_ground_truth("nope")


def test_ground_truth_fills_in_progressively_and_stop_aborts(runner):
    lab, stack = runner
    rid = lab.run_scenario("S5", 1, "test")       # S5: 5 steps, ~1.2-1.8 s apart -> easy to observe partial progress
    time.sleep(1.0)
    partial = lab.get_ground_truth(rid)
    assert 0 <= len(partial["steps"]) < 5 and lab.get_run(rid)["status"] == "running"
    lab.stop_run(rid, "test")
    time.sleep(2.5)
    final = lab.get_ground_truth(rid)
    assert lab.get_run(rid)["status"] == "aborted" and len(final["steps"]) < 5 and lab.get_run(rid)["ended_at"]


# ── each step's shape matches contract E ──────────────────────────────────────

def test_step_records_have_every_contract_e_field(runner):
    lab, _ = runner
    _, gt = run_and_wait(lab, "S1")
    for k in ("run_id", "scenario_id", "seed", "started_at", "steps", "compromised_services", "attack_path"):
        assert k in gt
    for step in gt["steps"]:
        for k in ("step", "t_offset_s", "source", "target_service", "technique", "requires_capability", "description",
                  "expected_attack_type", "injection_payload", "outcome", "blocked_by"):
            assert k in step, (step, k)
        assert step["outcome"] in ("succeeded", "blocked_by_containment", "failed")
        assert step["source"] in ("attacker-1", "attacker-2")
        assert step["blocked_by"] is None or set(step["blocked_by"]) == {"service", "mode"}
    for c in gt["compromised_services"]:
        assert set(c) == {"service", "t_offset_s"}


# ── per-scenario behaviour, against the REAL stack ────────────────────────────

def test_s1_brute_force_then_stolen_session(runner):
    lab, stack = runner
    rid, gt = run_and_wait(lab, "S1", seed=42)
    o = outcomes(gt)
    assert o[:5] == ["failed"] * 5 and o[5] == "succeeded" and o[6] == "succeeded"          # 5 bad guesses, the 6th is 'password'
    assert {c["service"] for c in gt["compromised_services"]} == {"auth_api", "order_api"}
    assert gt["attack_path"] == ["nginx", "auth_api", "order_api"]
    assert all(s["expected_attack_type"] == "brute_force" for s in gt["steps"][:6])
    assert gt["steps"][6]["expected_attack_type"] == "credential_abuse" and gt["steps"][6]["source"] == "attacker-2"
    assert all(not s["injection_payload"] for s in gt["steps"])
    srcips = {l.split("src_ip=")[1].split()[0] for l in read(stack, "auth/auth.log").splitlines() if "src_ip=" in l}
    assert "127.0.0.2" in srcips                                                            # the brute force really came from attacker-1's address


def test_s2_sqli_credential_reuse_database_dump(runner):
    lab, stack = runner
    rid, gt = run_and_wait(lab, "S2", seed=1)
    assert outcomes(gt) == ["succeeded", "succeeded", "succeeded"]
    assert [s["expected_attack_type"] for s in gt["steps"]] == ["sql_injection", "credential_abuse", "data_exfiltration"]
    assert gt["attack_path"] == ["nginx", "product_api", "auth_api", "database"]
    assert {c["service"] for c in gt["compromised_services"]} == {"product_api", "auth_api", "database"}
    assert "CREDENTIAL_REUSE service=product_api" in read(stack, "auth/auth.log")           # the reused key is really logged as reuse
    assert "DATA_EXFIL" in read(stack, "auth/auth.log")


def test_s3_scan_sqli_exfiltration(runner):
    lab, _ = runner
    _, gt = run_and_wait(lab, "S3", seed=1)
    assert gt["steps"][0]["expected_attack_type"] == "port_scan" and gt["steps"][8]["expected_attack_type"] == "sql_injection"
    assert gt["steps"][9]["expected_attack_type"] == "data_exfiltration" and gt["steps"][9]["outcome"] == "succeeded"
    assert gt["attack_path"] == ["nginx", "product_api", "database"]


def test_s4_foothold_queue_then_lateral_database(runner):
    lab, stack = runner
    _, gt = run_and_wait(lab, "S4", seed=1)
    assert outcomes(gt) == ["succeeded", "succeeded"]
    assert gt["steps"][0]["target_service"] == "queue" and gt["steps"][1]["target_service"] == "database"
    assert gt["attack_path"] == ["nginx", "queue", "database"]
    assert "LATERAL_DB_ACCESS" in read(stack, "queue/queue.log")


def test_s5_slow_brute_force_stays_under_rate_limit(runner):
    lab, _ = runner
    rid, gt = run_and_wait(lab, "S5", seed=7, timeout=20)
    assert len(gt["steps"]) == 5 and all(s["technique"] == "T1110.001" for s in gt["steps"])
    assert all(s["outcome"] != "blocked_by_containment" for s in gt["steps"])                # normal mode: nothing to block it on
    assert gt["steps"][-1]["t_offset_s"] - gt["steps"][0]["t_offset_s"] > 4.0                 # genuinely slow, not a burst


def test_s6_spoofed_alerts_and_injection_never_succeed(runner):
    lab, stack = runner
    _, gt = run_and_wait(lab, "S6", seed=1)
    assert all(s["injection_payload"] for s in gt["steps"])
    assert all(s["outcome"] == "failed" for s in gt["steps"])                                # injection never counts as a genuine effect
    assert gt["compromised_services"] == [] and gt["attack_path"] == []
    auth = read(stack, "auth/auth.log")
    assert "SYSTEM:" in auth or "ignore previous instructions" in auth.lower()               # the lab logged the payload as DATA, not as an instruction
    assert "isolate_service=nginx" not in json.dumps([v for v in lab.state["services"].values()])  # it had no actuation effect


def test_s0_is_truly_benign(runner):
    lab, _ = runner
    _, gt = run_and_wait(lab, "S0")
    assert gt["steps"] == [] and gt["compromised_services"] == [] and gt["attack_path"] == []


# ── outcomes are observed, not assumed ────────────────────────────────────────

def test_containment_blocks_a_step_and_it_is_detected_from_the_real_response(runner):
    lab, _ = runner
    lab.set_mode("product_api", "fallback", "test")             # blocks dynamic_query: the SQLi read now gets a 503
    _, gt = run_and_wait(lab, "S2", seed=1)
    assert gt["steps"][0]["outcome"] == "blocked_by_containment"
    assert gt["steps"][0]["blocked_by"] == {"service": "product_api", "mode": "fallback"}
    assert gt["steps"][1]["outcome"] == "succeeded"                                           # unrelated service: unaffected
    assert "product_api" not in {c["service"] for c in gt["compromised_services"]}


def test_isolated_service_is_detected_as_a_refused_connection(runner):
    lab, _ = runner
    lab.set_mode("auth_api", "isolated", "test")                 # app-level only here (FakeDockerOps); the gateway's
    _, gt = run_and_wait(lab, "S1", seed=42)                      # proxy to auth_api still gets a 503 header, which is
    assert gt["steps"][0]["outcome"] == "blocked_by_containment"  # exactly the 'X-ACD-Blocked' detection path, not guesswork
    assert gt["steps"][0]["blocked_by"] == {"service": "auth_api", "mode": "isolated"}


def test_cut_edge_blocks_only_the_dependent_step(runner):
    lab, _ = runner
    lab.cut_edge("order_api", "queue", "test")
    _, gt = run_and_wait(lab, "S4", seed=1)
    assert gt["steps"][0]["outcome"] == "blocked_by_containment"
    assert gt["steps"][0]["blocked_by"] == {"service": "order_api", "mode": "edge_cut"}   # X-ACD-Service names the
                                                                                            # caller whose outbound edge was cut (matches V1/V2)
    assert gt["steps"][1]["outcome"] == "blocked_by_containment"  # both steps route through the same cut edge (order_api -> queue)
    assert gt["steps"][1]["blocked_by"] == {"service": "order_api", "mode": "edge_cut"}
    assert gt["compromised_services"] == [] and gt["attack_path"] == []


def test_wrong_guess_alone_never_counts_as_compromised(runner):
    """A brute-force attempt that is simply wrong must be 'failed', not 'succeeded' or blocked -- outcomes reflect
    what really happened, not an assumption that any unblocked request 'worked'."""
    lab, _ = runner
    _, gt = run_and_wait(lab, "S1", seed=42)
    assert gt["steps"][0]["outcome"] == "failed" and gt["steps"][0]["blocked_by"] is None
    assert not any(c["service"] == "auth_api" and c["t_offset_s"] == gt["steps"][0]["t_offset_s"] for c in gt["compromised_services"])


# ── reproducibility and distinct source IPs ───────────────────────────────────

def test_two_attackers_use_two_distinct_real_source_addresses(runner):
    lab, stack = runner
    _, gt = run_and_wait(lab, "S1", seed=1)
    srcs = {l.split("src_ip=")[1].split()[0] for l in read(stack, "auth/auth.log").splitlines() if "src_ip=" in l}
    srcs |= {l.split("src_ip=")[1].split()[0] for l in read(stack, "order/order.log").splitlines() if "src_ip=" in l}
    assert {"127.0.0.2", "127.0.0.3"} <= srcs      # the shared log file is cumulative across the whole test session,
                                                   # so other tests' traffic may add more addresses; these two must appear


def test_seed_controls_jitter_deterministically(runner):
    lab, _ = runner
    _, gt1 = run_and_wait(lab, "S1", seed=99)
    cs.write_state(lab.control_path, cs.default_state())
    _, gt2 = run_and_wait(lab, "S1", seed=99)
    t1 = [round(s["t_offset_s"], 1) for s in gt1["steps"]]
    t2 = [round(s["t_offset_s"], 1) for s in gt2["steps"]]
    assert t1 == t2                                               # same seed -> same jitter schedule
    assert outcomes(gt1) == outcomes(gt2)


# ── HTTP API ─────────────────────────────────────────────────────────────────

def test_scenario_http_api(client):
    r = client.get("/scenarios")
    assert r.status_code == 200 and [s["id"] for s in r.json()] == list(SCENARIOS)
    r2 = client.post("/scenarios/S0/run", json={"seed": 5})
    assert r2.status_code == 200 and "run_id" in r2.json()
    rid = r2.json()["run_id"]
    time.sleep(0.3)
    assert client.get(f"/runs/{rid}").json()["status"] == "finished"
    assert client.get(f"/runs/{rid}/ground-truth").json()["run_id"] == rid
    assert client.get("/runs/nope").status_code == 404 and client.get("/runs/nope/ground-truth").status_code == 404
    assert client.post("/scenarios/S9/run", json={}).status_code == 404
    r3 = client.post("/scenarios/S5/run")
    rid3 = r3.json()["run_id"]
    assert client.post(f"/runs/{rid3}/stop").status_code == 200
    assert client.post("/runs/nope/stop").status_code == 404


# ── attacker agent (standalone) ───────────────────────────────────────────────

def test_attacker_agent_executes_and_reports_errors():
    from attacker.agent import app as agent_app
    from fastapi.testclient import TestClient as _  # noqa: F401  (ensures flask test client pattern below works standalone)
    client = agent_app.test_client()
    assert client.get("/healthz").get_json()["status"] == "ok"
    bad = client.post("/execute", json={"method": "GET", "url": "http://127.0.0.1:1/nope", "timeout": 1})
    assert bad.get_json()["status"] is None and bad.get_json()["error"]
