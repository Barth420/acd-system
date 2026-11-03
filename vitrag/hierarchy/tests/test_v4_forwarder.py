"""V4: forwarder detections, rule-id parity with the Wazuh rules, alert sink, Wazuh files, compose profile."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

import controlstate as cs
import forwarder as fwd
from rules import DESC, LOG_SERVICE, Detector
from wazuh_eval import Wazuh

HIER = Path(__file__).resolve().parents[1]
WAZUH = Wazuh(HIER / "wazuh" / "local_decoders.xml", HIER / "wazuh" / "local_rules.xml")


def ts(sec: float) -> str:
    t = time.gmtime(1_700_000_000 + int(sec))
    return time.strftime("%Y-%m-%d %H:%M:%S", t) + f",{int((sec % 1) * 1000):03d}"


def L(sec, svc, msg, level="INFO"):
    return f"{ts(sec)} {level} [{svc}] {msg}"


def ids(det, key, line):
    return [a["raw_data"]["rule"]["id"] for a in det.process(key, line)]


# ── detections (synthetic lines in the exact service formats) ────────────────

def test_brute_force_escalates_5_in_60s_and_20_in_120s():
    det = Detector()
    seq = [ids(det, "auth/auth.log", L(i, "auth_api", f"AUTH_FAILURE user=alice src_ip=203.0.113.9 ua='x' reason=invalid_credentials rid=r{i}", "WARNING")) for i in range(25)]
    assert [s[0] for s in seq[:4]] == [100710] * 4 and seq[4] == [100711] and seq[18] == [100711] and seq[19] == [100712]
    other = Detector()
    spaced = [ids(other, "auth/auth.log", L(i * 20, "auth_api", "AUTH_FAILURE user=a src_ip=198.51.100.1 ua='x' reason=invalid_credentials rid=z", "WARNING")) for i in range(8)]
    assert all(s == [100710] for s in spaced)                      # 3 per minute never reaches 5 in 60 s
    assert ids(Detector(), "auth/auth.log", L(0, "auth_api", "AUTH_SUCCESS user=alice src_ip=1.2.3.4 ua='x' rid=r")) == []


def test_sql_injection_xss_and_aggregation():
    det = Detector()
    got = [ids(det, "product/product.log", L(i, "product_api", f"SQLI_ATTEMPT src_ip=203.0.113.7 ua='sqlmap/1.7' payload=\"1'\" rid=r{i}")) for i in range(6)]
    assert [g[0] for g in got[:4]] == [100103] * 4 and got[4] == [100105]          # 100103 wins over the sqlmap recon match; 5th aggregates
    assert ids(Detector(), "product/product.log", L(0, "product_api", "XSS_ATTEMPT src_ip=203.0.113.7 ua='x' q='<script>' rid=r")) == [100106]
    assert ids(Detector(), "product/product.log", L(0, "product_api", "PRODUCT_QUERY src_ip=203.0.113.7 ua='curl' query='SELECT 1' rid=r")) == []


def test_credential_lateral_exfil_ids_targets_and_fields():
    det = Detector()
    a = det.process("auth/auth.log", L(0, "auth_api", "CREDENTIAL_REUSE service=product_api src_ip=203.0.113.50 route=/auth/admin/users via=gateway rid=abc123"))[0]
    d = a["raw_data"]["data"]
    assert a["raw_data"]["rule"] == {"id": 100301, "level": 10, "description": DESC[100301][0]} and a["source"] == "wazuh"
    assert (d["srcip"], d["dstport"], d["source_service"], d["request_id"]) == ("203.0.113.50", 5000, "auth_api", "abc123")
    b = det.process("queue/queue.log", L(1, "queue", "LATERAL_DB_ACCESS db_user=queue_worker src_ip=203.0.113.50 caller=order_api source_service=queue target=database rid=q1"))[0]
    assert b["raw_data"]["rule"]["id"] == 100302 and b["raw_data"]["rule"]["level"] == 11
    assert (b["raw_data"]["data"]["dstport"], b["raw_data"]["data"]["source_service"]) == (5432, "queue")
    c = det.process("auth/auth.log", L(2, "auth_api", "DATA_EXFIL rows=300 src_ip=203.0.113.50 table=users route=/auth/admin/export source_service=auth_api rid=e1"))[0]
    assert c["raw_data"]["rule"]["id"] == 100303 and c["raw_data"]["rule"]["level"] == 12 and c["raw_data"]["data"]["dstport"] == 5432
    assert c["raw_data"]["data"]["source_service"] == "auth_api"
    e = det.process("order/order.log", L(3, "order_api", "SESSION_REUSE user=alice issued_ip=1.1.1.1 src_ip=2.2.2.2 rid=o1"))[0]
    assert e["raw_data"]["rule"]["id"] == 100301 and e["raw_data"]["data"]["dstport"] == 5002


def test_reconnaissance_from_the_gateway_log_and_aggregation():
    det = Detector()
    line = lambda i: f'203.0.113.99 - - [{time.strftime("%d/%b/%Y:%H:%M:%S", time.gmtime(1_700_000_000 + i // 5))} +0000] "GET /p{i} HTTP/1.1" 404 0 "" "Nmap Scripting Engine nmap" "-" "" rid=g{i}'
    out = [ids(det, "nginx/access.log", line(i)) for i in range(55)]
    assert out[0] == [100201] and out[48] == [100201] and out[49] == [100202]
    a = Detector().process("nginx/access.log", line(0))[0]["raw_data"]["data"]
    assert (a["srcip"], a["dstport"], a["source_service"], a["request_id"], a["url"]) == ("203.0.113.99", 80, "nginx", "g0", "/p0")
    assert ids(Detector(), "nginx/access.log", line(0).replace("Nmap Scripting Engine nmap", "Mozilla/5.0")) == []


def test_attacker_controlled_text_cannot_spoof_source_or_request_id():
    det = Detector()
    ua = "x rid=forged src_ip=9.9.9.9"
    a = det.process("product/product.log", L(0, "product_api", f"SQLI_ATTEMPT src_ip=203.0.113.7 ua={ua!r} payload='1' rid=real1"))[0]["raw_data"]["data"]
    assert a["srcip"] == "203.0.113.7" and a["request_id"] == "real1"


def test_every_rule_in_the_table_has_the_contract_level_and_range():
    assert set(DESC) == {100710, 100711, 100712, 100103, 100105, 100106, 100301, 100302, 100303, 100201, 100202}
    assert all(100000 <= i < 101000 for i in DESC)


# ── parity with the Wazuh rule files ─────────────────────────────────────────

def replay(events):
    det, w = Detector(), Wazuh(HIER / "wazuh" / "local_decoders.xml", HIER / "wazuh" / "local_rules.xml")
    mismatches = []
    for key, line in events:
        py = [a["raw_data"]["rule"]["id"] for a in det.process(key, line)]
        wz = w.event(key, line)
        if (py[0] if py else None) != wz:
            mismatches.append((key, line[:90], py, wz))
    return mismatches


def test_python_forwarder_and_wazuh_rules_agree_on_a_synthetic_log():
    ev = []
    for i in range(25):
        ev.append(("auth/auth.log", L(i, "auth_api", f"AUTH_FAILURE user=bob src_ip=203.0.113.9 ua='curl' reason=invalid_credentials rid=r{i}", "WARNING")))
    ev.append(("auth/auth.log", L(30, "auth_api", "AUTH_SUCCESS user=bob src_ip=203.0.113.9 ua='curl' rid=ok")))
    for i in range(7):
        ev.append(("product/product.log", L(40 + i, "product_api", f"SQLI_ATTEMPT src_ip=198.51.100.4 ua='sqlmap/1.7' payload='1' rid=s{i}")))
        ev.append(("product/product.log", L(40 + i, "product_api", f"SQL_ERROR src_ip=198.51.100.4 ua='sqlmap/1.7' query='x' err=boom rid=s{i}", "WARNING")))
    ev.append(("product/product.log", L(60, "product_api", "XSS_ATTEMPT src_ip=198.51.100.5 ua='x' q='<script>' rid=x1")))
    ev.append(("product/product.log", L(61, "product_api", "PRODUCT_QUERY src_ip=198.51.100.5 ua='sqlmap/1.7' query='SELECT 1' rid=x2")))   # recon via the UA
    ev.append(("auth/auth.log", L(62, "auth_api", "CREDENTIAL_REUSE service=product_api src_ip=198.51.100.6 route=/auth/admin/users via=gateway rid=c1")))
    ev.append(("auth/auth.log", L(62, "auth_api", "ADMIN_ACCESS service=product_api src_ip=198.51.100.6 route=/auth/admin/users via=gateway rid=c1")))
    ev.append(("order/order.log", L(63, "order_api", "DEPENDENCY_ABUSE caller=order_api target=queue route=/admin/config src_ip=198.51.100.6 rid=c2")))
    ev.append(("queue/queue.log", L(64, "queue", "LATERAL_DB_ACCESS db_user=queue_worker src_ip=198.51.100.6 caller=order_api source_service=queue target=database rid=c3")))
    ev.append(("auth/auth.log", L(65, "auth_api", "DATA_EXFIL rows=300 src_ip=198.51.100.6 table=users route=/auth/admin/export source_service=auth_api rid=c4")))
    for i in range(60):
        ev.append(("nginx/access.log", f'203.0.113.99 - - [{time.strftime("%d/%b/%Y:%H:%M:%S", time.gmtime(1_700_000_100 + i // 5))} +0000] "GET /z{i} HTTP/1.1" 404 0 "" "nikto" "-" "" rid=n{i}'))
    ev.append(("nginx/access.log", '203.0.113.99 - - [14/Nov/2023:22:15:00 +0000] "GET / HTTP/1.1" 200 0 "" "Mozilla/5.0" "-" "" rid=n999'))
    assert replay(ev) == []


@pytest.fixture()
def real_logs(stack):
    """Drive a few requests through the REAL services so the replayed lines are the ones the services actually write."""
    gw, h = stack.gateway, {"X-Service-Name": "product_api", "X-Service-Key": cs.initial_key("product_api")}
    cs.write_state(stack.control, cs.default_state())
    for pw in ("a", "b", "c", "d", "e", "f"):
        httpx.post(gw + "/auth/login", json={"username": "alice", "password": pw})
    httpx.post(gw + "/auth/login", json={"username": "alice", "password": "password"})
    httpx.get(gw + "/api/products", params={"id": "1'"})
    httpx.get(gw + "/api/products/search", params={"q": "<script>alert(1)</script>"})
    httpx.get(gw + "/api/products?id=2", headers={"User-Agent": "nmap scripting engine"})
    httpx.get(gw + "/auth/admin/users", headers=h)                                         # service key presented via the gateway
    httpx.get(gw + "/auth/admin/export", headers=h)                                        # 300-row export
    httpx.get(gw + "/orders/debug/forward", params={"path": "/admin/config"})
    httpx.post(gw + "/orders/debug/forward", params={"path": "/admin/db_query"}, json={"password": "worker123", "sql": "SELECT 1"})
    time.sleep(0.5)
    ev = []
    for key in LOG_SERVICE:
        p = stack.logs / key
        if p.exists():
            ev += [(key, l) for l in p.read_text().splitlines() if l.strip()]
    return stack, ev


def test_real_service_logs_produce_the_same_rule_ids_in_forwarder_and_wazuh(real_logs):
    _, ev = real_logs
    assert replay(ev) == []
    det = Detector()
    fired = {a["raw_data"]["rule"]["id"] for key, line in ev for a in det.process(key, line)}
    assert {100710, 100711, 100103, 100106, 100301, 100302, 100303, 100201} <= fired, fired


def test_wazuh_files_are_well_formed_and_cover_the_contract_ids():
    rules = ET.fromstring("<r>" + re.sub(r"<!--.*?-->", "", (HIER / "wazuh" / "local_rules.xml").read_text(), flags=re.S) + "</r>")
    got = [int(r.get("id")) for r in rules.iter("rule")]
    assert len(got) == len(set(got)) and set(got) == set(DESC)
    assert all(100000 <= i < 101000 for i in got)
    assert not [r for r in rules.iter("if_sid")], "decoder-triggered rules must stay atomic (no <if_sid>1</if_sid>)"
    assert {int(r.get("id")): int(r.get("level")) for r in rules.iter("rule")} == {k: v[1] for k, v in DESC.items()}
    assert got.index(100712) < got.index(100711)
    oss = (HIER / "wazuh" / "ossec.conf").read_text()
    assert "<rule_dir>etc/rules</rule_dir>" in oss
    for f in ("auth/auth.log", "product/product.log", "nginx/access.log", "order/order.log", "search/search.log", "queue/queue.log"):
        assert f"/mnt/app_logs/{f}" in oss, f


def test_compose_default_stack_has_no_wazuh_and_wazuh_profile_is_isolated():
    c = yaml.safe_load((HIER / "docker-compose.yml").read_text())["services"]
    wz = {n for n in c if n.startswith("wazuh") or n == "forwarder-wazuh"}
    assert wz == {"wazuh.manager", "wazuh.indexer", "wazuh.dashboard", "forwarder-wazuh"}
    assert all(c[n].get("profiles") == ["wazuh"] for n in wz)
    assert not [n for n in c if n not in wz and c[n].get("profiles")]
    assert not c["wazuh.manager"].get("ports") and not c["wazuh.indexer"].get("ports")
    assert c["wazuh.dashboard"]["ports"] == ["127.0.0.1:5601:5601"]
    assert c["alert-sink"]["ports"] == ["127.0.0.1:8099:8099"]


# ── alert sink ───────────────────────────────────────────────────────────────

@pytest.fixture()
def sink(tmp_path, monkeypatch):
    monkeypatch.setenv("SINK_FILE", str(tmp_path / "sink.jsonl"))
    import importlib, alert_sink
    importlib.reload(alert_sink)
    return TestClient(alert_sink.app), alert_sink


def good_alert(rule=100301):
    return {"source": "wazuh", "timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"rule": {"id": rule, "level": 10, "description": "d"}, "data": {"srcip": "203.0.113.1", "dstport": 5000, "request_id": "r1", "source_service": "auth_api"},
                         "timestamp": "2026-01-01T00:00:00Z"}}


def test_sink_accepts_stores_summarises_filters_and_clears(sink, capsys):
    c, mod = sink
    assert c.post("/alerts", json=good_alert(100301)).status_code == 201
    c.post("/alerts", json=good_alert(100301)); c.post("/alerts", json=good_alert(100303))
    assert c.get("/alerts/summary").json() == {"total": 3, "by_rule": {"100301": 2, "100303": 1}}
    assert c.get("/alerts", params={"rule": 100303}).json()["count"] == 1
    assert "[sink]" in capsys.readouterr().out
    assert len(Path(mod.OUT).read_text().splitlines()) == 3
    assert c.delete("/alerts").json() == {"ok": True} and c.get("/alerts/summary").json()["total"] == 0


def test_sink_rejects_malformed_alerts(sink):
    c, _ = sink
    assert c.post("/alerts", json={"source": "wazuh"}).status_code == 422
    assert c.post("/alerts", json={"source": "wazuh", "timestamp": "t", "raw_data": "nope"}).status_code == 422


# ── forwarder end to end: real services -> logs -> forwarder -> sink ─────────

def test_forwarder_delivers_alerts_with_request_id_to_the_sink(stack, tmp_path):
    from local_stack import free_port
    port = free_port()
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "alert_sink:app", "--port", str(port), "--log-level", "warning"],
                         cwd=HIER / "tools", env={"SINK_FILE": str(tmp_path / "s.jsonl"), "PATH": "/usr/bin:/bin", "PYTHONPATH": ""},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/healthz").status_code == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        urls = [f"http://127.0.0.1:{port}/alerts", "http://127.0.0.1:9/alerts"]            # second target is dead on purpose: never fatal
        stop = threading.Event()
        t = threading.Thread(target=fwd.run_logs, args=(stack.logs, urls, False, stop.is_set), daemon=True)
        t.start()
        time.sleep(1.0)                                                                    # tailers are at the end of the existing logs now
        cs.write_state(stack.control, cs.default_state())
        r = httpx.get(stack.gateway + "/api/products", params={"id": "1'"})
        rid = r.headers["X-Request-ID"]
        deadline = time.time() + 8
        got = []
        while time.time() < deadline and not got:
            got = [a for a in httpx.get(f"http://127.0.0.1:{port}/alerts").json()["items"] if a["raw_data"]["data"]["request_id"] == rid]
            time.sleep(0.3)
        stop.set()
        assert got, "no alert with the gateway-issued request id reached the sink"
        d = got[0]["raw_data"]
        assert d["rule"]["id"] == 100103 and d["data"]["source_service"] == "product_api" and d["data"]["dstport"] == 5001
        assert d["data"]["srcip"] == "127.0.0.1" and set(got[0]) >= {"source", "timestamp", "raw_data"}
    finally:
        p.terminate()


def test_wazuh_alert_conversion_adds_the_contract_fields():
    w = {"timestamp": "2026-01-01T00:00:00.000+0000", "rule": {"id": "100303", "level": 12, "description": "Data exfiltration volume anomaly."},
         "location": "/mnt/app_logs/auth/auth.log", "data": {"srcip": "203.0.113.50"},
         "full_log": "2026-01-01 00:00:00,000 INFO [auth_api] DATA_EXFIL rows=300 src_ip=203.0.113.50 ua='rid=fake' rid=real9"}
    raw = fwd.wazuh_to_raw(w)
    d = raw["raw_data"]["data"]
    assert raw["source"] == "wazuh" and raw["raw_data"]["rule"]["id"] == 100303 and isinstance(raw["raw_data"]["rule"]["id"], int)
    assert (d["dstport"], d["source_service"], d["request_id"], d["srcip"]) == (5432, "auth_api", "real9", "203.0.113.50")
    assert fwd.wazuh_to_raw({**w, "location": "/var/log/other.log"}) is None
    assert fwd.wazuh_to_raw({**w, "data": {}}) is None
