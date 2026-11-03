"""
order_api (tier 1, :5002). Depends on: database, auth_api (token validation), queue (work items).
LAB-ONLY weakness kept on purpose: /orders/debug/forward is an unauthenticated debug proxy to the queue service.
"""

from __future__ import annotations

from flask import g, jsonify, request

from svc.acdlib import Service, make_db

svc = Service("order_api")
db = make_db()


@svc.route("/healthz", health=True)
def healthz():
    return jsonify({"status": "ok", "service": "order_api"})


def _token() -> str:
    return request.headers.get("Authorization", "")[7:]


@svc.route("/orders", methods=("POST",), caps=("state_write",), deps=("auth_api", "queue"), infra={"database": ["state_write"]})
def place_order():
    r = svc.dep_call("auth_api", "GET", f"/auth/validate?token={_token()}")
    if r.status_code != 200:
        return jsonify({"error": "unauthorized"}), 401
    who = r.json()
    if who["issued_ip"] != g.src_ip:
        svc.say(f"SESSION_REUSE user={who['user']} issued_ip={who['issued_ip']} src_ip={g.src_ip}")
    d = request.get_json(silent=True) or {}
    pid, qty = int(d.get("product_id", 1)), int(d.get("qty", 1))
    db.run("INSERT INTO orders(username, product_id, qty) VALUES (?, ?, ?)", (who["user"], pid, qty))
    svc.dep_call("queue", "POST", "/queue/enqueue", json={"user": who["user"], "product_id": pid, "qty": qty})
    svc.say(f"ORDER_PLACED user={who['user']} src_ip={g.src_ip} product_id={pid} qty={qty}")
    return jsonify({"status": "created", "user": who["user"]}), 201


@svc.route("/orders/mine", caps=("dynamic_query",), deps=("auth_api",), infra={"database": ["dynamic_query"]})
def my_orders():
    r = svc.dep_call("auth_api", "GET", f"/auth/validate?token={_token()}")
    if r.status_code != 200:
        return jsonify({"error": "unauthorized"}), 401
    rows = db.run("SELECT id, product_id, qty FROM orders WHERE username = ? ORDER BY id DESC LIMIT 20", (r.json()["user"],))
    return jsonify([{"id": x[0], "product_id": x[1], "qty": x[2]} for x in rows])


@svc.route("/orders/debug/forward", methods=("GET", "POST"), caps=("dependency_calls",), deps=("queue",))
def debug_forward():
    """LAB-ONLY: forwards {path, body} to the queue service with no authentication."""
    path = request.args.get("path", "/queue/stats")
    if path.startswith("/admin"):
        svc.say(f"DEPENDENCY_ABUSE caller=order_api target=queue route={path} src_ip={g.src_ip}")
    r = svc.dep_call("queue", request.method, path, json=request.get_json(silent=True))
    return (r.content, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})


if __name__ == "__main__":
    svc.run(5002)
