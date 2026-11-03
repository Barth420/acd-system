"""
auth_api (tier 1, :5000). LAB-ONLY weaknesses, kept on purpose: weak passwords, no rate limit on /auth/login, and
an internal admin route that is reachable through the gateway and guarded only by a service key.
Depends on: database (users), cache (sessions).
"""

from __future__ import annotations

import json
import secrets
import time

from flask import g, jsonify, request

from svc.acdlib import Service, blocked, make_cache, make_db, service_key_ok, EXFIL_ROWS

svc = Service("auth_api")
db, cache = make_db(), make_cache()


@svc.route("/healthz", health=True)
def healthz():
    return jsonify({"status": "ok", "service": "auth_api"})


@svc.route("/auth/login", methods=("POST",), caps=("state_write",), deps=(), infra={"database": ["dynamic_query"], "cache": ["state_write"]})
def login():
    data = request.get_json(silent=True) or {}
    user, pw = str(data.get("username", "")), str(data.get("password", ""))
    rows = db.run("SELECT password FROM users WHERE username = ?", (user,))
    if rows and rows[0][0] == pw:
        tok = f"tok_{user}_{secrets.token_hex(4)}"
        cache.set(f"sess:{tok}", json.dumps({"user": user, "ip": g.src_ip, "ts": time.time()}), ex=3600)
        svc.say(f"AUTH_SUCCESS user={user} src_ip={g.src_ip} ua={g.ua!r}")
        return jsonify({"status": "ok", "token": tok})
    svc.say(f"AUTH_FAILURE user={user} src_ip={g.src_ip} ua={g.ua!r} reason=invalid_credentials")
    return jsonify({"status": "error", "msg": "invalid credentials"}), 401


def _bearer() -> str:
    h = request.headers.get("Authorization", "")
    return h[7:] if h.startswith("Bearer ") else request.args.get("token", "")


@svc.route("/auth/whoami", caps=("dynamic_query",), infra={"cache": ["dynamic_query"]})
def whoami():
    raw = cache.get(f"sess:{_bearer()}")
    if not raw:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"user": json.loads(raw)["user"]})


def _service_auth():
    ok, why = service_key_ok(svc, request.headers.get("X-Service-Name"), request.headers.get("X-Service-Key"))
    if not ok:
        svc.say(f"CREDENTIAL_REJECTED service={request.headers.get('X-Service-Name')} src_ip={g.src_ip} reason={why}")
        return jsonify({"error": "bad service credentials", "reason": why}), 401
    return None


@svc.route("/auth/validate", caps=("dynamic_query",), infra={"cache": ["dynamic_query"]})
def validate():
    bad = _service_auth()
    if bad:
        return bad
    raw = cache.get(f"sess:{_bearer()}")
    if not raw:
        return jsonify({"error": "invalid token"}), 401
    s = json.loads(raw)
    return jsonify({"user": s["user"], "issued_ip": s["ip"]})


def _admin_audit(route: str) -> None:
    caller = request.headers.get("X-Service-Name")
    if g.via_gateway:  # a service key presented through the public gateway, not from inside the lab
        svc.say(f"CREDENTIAL_REUSE service={caller} src_ip={g.src_ip} route={route} via=gateway")
    svc.say(f"ADMIN_ACCESS service={caller} src_ip={g.src_ip} route={route} via={'gateway' if g.via_gateway else 'internal'}")


@svc.route("/auth/admin/users", caps=("dynamic_query",), deps=(), infra={"database": ["dynamic_query"]})
def admin_users():
    bad = _service_auth()
    if bad:
        return bad
    _admin_audit("/auth/admin/users")
    limit = min(int(request.args.get("limit", 5)), 20)
    rows = db.run(f"SELECT id, username, role FROM users ORDER BY id LIMIT {limit}")
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])


@svc.route("/auth/admin/export", caps=("dynamic_query", "data_egress"), infra={"database": ["dynamic_query", "data_egress"]})
def admin_export():
    bad = _service_auth()
    if bad:
        return bad
    _admin_audit("/auth/admin/export")
    rows = db.run("SELECT id, username, password, role FROM users ORDER BY id")
    stop = svc.require_egress(len(rows))
    if stop:
        return stop
    if len(rows) >= EXFIL_ROWS:
        svc.say(f"DATA_EXFIL rows={len(rows)} src_ip={g.src_ip} table=users route=/auth/admin/export source_service=auth_api")
    return jsonify({"rows": len(rows), "data": [list(r) for r in rows]})


if __name__ == "__main__":
    svc.run(5000)
