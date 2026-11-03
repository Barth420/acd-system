"""V1: the hierarchical lab, run as real processes (sqlite/file stand-ins for postgres/redis, Python stand-in gateway)."""

from __future__ import annotations

import re
import time

import httpx
import pytest

import controlstate as cs


def login(lab, user="alice", pw="password", **kw):
    return httpx.post(lab.gateway + "/auth/login", json={"username": user, "password": pw}, **kw)


def hdr(r, name):
    return r.headers.get(name)


def read(lab, rel):
    p = lab.logs / rel
    return p.read_text() if p.exists() else ""


# ── every service answers, request ids flow ──────────────────────────────────

def test_every_service_has_healthz(lab):
    for s in ["auth_api", "product_api", "order_api", "search_api", "queue"]:
        r = httpx.get(lab.url(s) + "/healthz")
        assert r.status_code == 200 and r.json()["service"] == s
    assert httpx.get(lab.gateway + "/healthz").json()["service"] == "nginx"


def test_benign_journeys_work_through_the_gateway(lab):
    r = login(lab)
    assert r.status_code == 200
    tok = r.json()["token"]
    assert httpx.get(lab.gateway + "/api/products?id=1").json()[0]["name"] == "Widget"
    assert "Widget" in httpx.get(lab.gateway + "/search?q=wid").json()["results"]
    o = httpx.post(lab.gateway + "/orders", json={"product_id": 2, "qty": 3}, headers={"Authorization": f"Bearer {tok}"})
    assert o.status_code == 201 and o.json()["user"] == "alice"
    mine = httpx.get(lab.gateway + "/orders/mine", headers={"Authorization": f"Bearer {tok}"}).json()
    assert mine and mine[0]["qty"] == 3


def test_request_id_is_set_by_the_gateway_and_logged_by_every_hop(lab):
    tok = login(lab).json()["token"]
    r = httpx.post(lab.gateway + "/orders", json={"product_id": 1, "qty": 1}, headers={"Authorization": f"Bearer {tok}", "X-Request-ID": "client-chosen"})
    rid = hdr(r, "X-Request-ID")
    assert rid and rid != "client-chosen"                     # the gateway always issues its own id
    time.sleep(0.3)
    for rel in ("nginx/access.log", "order/order.log", "queue/queue.log"):
        assert f"rid={rid}" in read(lab, rel), rel
    # order_api called auth_api (validate) and the queue with the same id; auth_api logs rid on its own lines
    assert f"rid={rid}" in read(lab, "order/order.log")


def test_log_lines_keep_the_formats_the_existing_wazuh_decoders_parse(lab):
    login(lab, pw="wrong", headers={"User-Agent": "tester"})
    httpx.get(lab.gateway + "/api/products?id=1'")            # provokes a SQL error line
    time.sleep(0.2)
    auth = read(lab, "auth/auth.log")
    m = re.search(r"AUTH_FAILURE user=(\S+) src_ip=(\S+) ua='tester' reason=invalid_credentials rid=\w+", auth)
    assert m and m.group(1) == "alice"                         # same regex as vitrag/wazuh/local_decoders.xml (acd_auth_failure)
    prod = read(lab, "product/product.log")
    assert re.search(r"SQL_ERROR src_ip=\S+ ua=", prod) and re.search(r"SQLI_ATTEMPT src_ip=\S+", prod)


# ── deliberate lab weaknesses are still there (lab only) ─────────────────────

def test_weak_logins_and_injectable_product_query_are_kept(lab):
    assert login(lab, "admin", "admin123").status_code == 200
    rows = httpx.get(lab.gateway + "/api/products", params={"id": "1 OR 1=1"}).json()
    assert len(rows) == 5


# ── mode enforcement (matrix B) ──────────────────────────────────────────────

def test_fallback_serves_cached_answer_for_reads_and_blocks_writes(lab):
    lab.set_state(modes={"product_api": "fallback"})
    r = httpx.get(lab.gateway + "/api/products?id=1")
    assert r.status_code == 200 and "served=cached" in hdr(r, "X-ACD-Blocked") and hdr(r, "X-ACD-Service") == "product_api"
    w = httpx.post(lab.gateway + "/api/products", json={"name": "x"}, headers={"Authorization": "Bearer nope"})
    assert w.status_code == 503 and "capability=" in hdr(w, "X-ACD-Blocked")
    assert httpx.get(lab.gateway + "/search?q=wid").status_code == 200       # unrelated service untouched


def test_read_only_blocks_state_write_but_not_reads(lab):
    lab.set_state(modes={"auth_api": "read_only"})
    r = login(lab)
    assert r.status_code == 503 and hdr(r, "X-ACD-Blocked") == "mode=read_only; capability=state_write"
    assert httpx.get(lab.url("auth_api") + "/auth/whoami?token=x").status_code == 401       # a read still runs (just unauthorised)


def test_isolated_service_refuses_everything_including_healthz(lab):
    lab.set_state(modes={"search_api": "isolated"})
    r = httpx.get(lab.gateway + "/search?q=a")
    assert r.status_code == 503 and "mode=isolated" in hdr(r, "X-ACD-Blocked")
    assert httpx.get(lab.url("search_api") + "/healthz").status_code == 503
    assert httpx.get(lab.gateway + "/api/products?id=1").status_code == 200


def test_cut_edge_fails_only_the_endpoints_that_need_it(lab):
    lab.set_state(cuts=[("product_api", "database")])
    r = httpx.get(lab.gateway + "/api/products?id=1")
    assert r.status_code == 503 and hdr(r, "X-ACD-Blocked") == "edge=product_api-database" and hdr(r, "X-ACD-Service") == "product_api"
    assert httpx.get(lab.gateway + "/api/products/search?q=a").status_code == 200       # does not use the database
    assert login(lab).status_code == 200                                                # auth_api's own database edge is intact
    lab.set_state(cuts=[("order_api", "queue")])
    tok = login(lab).json()["token"]
    o = httpx.post(lab.gateway + "/orders", json={"product_id": 1}, headers={"Authorization": f"Bearer {tok}"})
    assert o.status_code == 503 and hdr(o, "X-ACD-Blocked") == "edge=order_api-queue"
    assert httpx.get(lab.gateway + "/orders/mine", headers={"Authorization": f"Bearer {tok}"}).status_code == 200


def test_infra_target_mode_is_enforced_by_the_caller(lab):
    lab.set_state(modes={"database": "fallback"})
    r = login(lab)
    assert r.status_code == 503 and hdr(r, "X-ACD-Service") == "database" and "mode=fallback" in hdr(r, "X-ACD-Blocked")
    assert httpx.get(lab.gateway + "/search?q=wid").status_code == 200                  # search_api uses the cache, not the database


def test_dependency_service_blocking_propagates_to_the_caller(lab):
    tok = login(lab).json()["token"]
    lab.set_state(modes={"auth_api": "isolated"})
    o = httpx.post(lab.gateway + "/orders", json={"product_id": 1}, headers={"Authorization": f"Bearer {tok}"})
    assert o.status_code == 503 and "mode=isolated" in hdr(o, "X-ACD-Blocked") and hdr(o, "X-ACD-Service") == "auth_api"


def test_rate_limited_blocks_bulk_but_lets_normal_pace_through(lab):
    lab.set_state(modes={"search_api": "rate_limited"})
    codes = [httpx.get(lab.url("search_api") + "/search?q=a").status_code for _ in range(40)]
    assert 429 in codes and 200 in codes
    blocked = httpx.get(lab.url("search_api") + "/search?q=a") if codes[-1] == 429 else None
    time.sleep(1.5)
    assert httpx.get(lab.url("search_api") + "/search?q=a").status_code == 200           # a slow client is not blocked


def test_bulk_read_needs_data_egress(lab):
    key = cs.initial_key("product_api")
    h = {"X-Service-Name": "product_api", "X-Service-Key": key}
    r = httpx.get(lab.url("auth_api") + "/auth/admin/export", headers=h)
    assert r.status_code == 200 and r.json()["rows"] >= 50
    lab.set_state(modes={"auth_api": "fallback"})
    r2 = httpx.get(lab.url("auth_api") + "/auth/admin/export", headers=h)
    assert r2.status_code == 503 and hdr(r2, "X-ACD-Blocked").startswith("mode=fallback")


# ── gateway enforcement ──────────────────────────────────────────────────────

def test_gateway_modes_and_edges(lab):
    lab.set_state(modes={"nginx": "read_only"})
    r = login(lab)
    assert r.status_code == 503 and hdr(r, "X-ACD-Service") == "nginx" and "capability=state_write" in hdr(r, "X-ACD-Blocked")
    assert httpx.get(lab.gateway + "/search?q=a").status_code == 200
    lab.set_state(modes={"nginx": "normal"}, cuts=[("nginx", "search_api")])
    s = httpx.get(lab.gateway + "/search?q=a")
    assert s.status_code == 503 and hdr(s, "X-ACD-Blocked") == "edge=nginx-search_api"
    assert httpx.get(lab.gateway + "/api/products?id=1").status_code == 200
    lab.set_state(modes={"nginx": "fallback"}, cuts=[])
    assert httpx.get(lab.gateway + "/api/products?id=1").status_code == 503
    assert httpx.get(lab.gateway + "/healthz").status_code == 200


# ── credentials ──────────────────────────────────────────────────────────────

def test_service_key_rotation_invalidates_the_old_key(lab):
    old = cs.initial_key("product_api")
    h = {"X-Service-Name": "product_api", "X-Service-Key": old}
    assert httpx.get(lab.url("auth_api") + "/auth/admin/users", headers=h).status_code == 200
    st = cs.default_state()
    st["credentials"]["product_api"] = {"current": "new-key", "generation": 1, "revoked": [old]}
    cs.write_state(lab.control, st)
    r = httpx.get(lab.url("auth_api") + "/auth/admin/users", headers=h)
    assert r.status_code == 401 and r.json()["reason"] == "revoked"
    assert "CREDENTIAL_REJECTED service=product_api" in read(lab, "auth/auth.log")
    ok = httpx.get(lab.url("auth_api") + "/auth/admin/users", headers={**h, "X-Service-Key": "new-key"})
    assert ok.status_code == 200
    assert httpx.get(lab.url("auth_api") + "/auth/admin/users").status_code == 401        # no credentials at all


# ── gateway rules: nginx map and python decision agree ───────────────────────

def test_generated_nginx_map_agrees_with_the_python_decision():
    import gateway_rules as gr
    cases = []
    for mode in cs.MODES:
        for cuts in ([], [["nginx", "auth_api"]], [["nginx", "search_api"], ["nginx", "order_api"]]):
            st = cs.default_state()
            st["services"]["nginx"]["mode"] = mode
            st["cut_edges"] = cuts
            conf = gr.render_nginx_conf(st)
            rows = re.findall(r'^\s+"~(.+)" "(.+)";$', conf, flags=re.M)
            for method in ("GET", "POST"):
                for path in ("/", "/healthz", "/auth/login", "/api/products", "/orders", "/orders/mine", "/search", "/authx"):
                    key = f"{method}:{path}"
                    want = next((reason for rx, reason in rows if re.search(rx, key)), None)
                    assert gr.decision(st, method, path) == want, (mode, cuts, key)
    assert 'default "";' in gr.render_nginx_conf(cs.default_state())
    rl = cs.default_state(); rl["services"]["nginx"]["mode"] = "rate_limited"
    assert "$binary_remote_addr" in gr.render_nginx_conf(rl) and "limit_req_zone" in gr.render_nginx_conf(rl)
