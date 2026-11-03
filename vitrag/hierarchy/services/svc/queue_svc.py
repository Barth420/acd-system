"""
queue (tier 2, :5004): tiny in-memory work queue. Depends on: nothing declared (it holds a worker database account).
LAB-ONLY weaknesses kept on purpose: /admin/config exposes the worker's database account without authentication and
/admin/db_query runs queries with it, which is the lab's lateral path from queue to database.
"""

from __future__ import annotations

import os
from collections import deque

from flask import g, jsonify, request

from svc.acdlib import Service, make_db

svc = Service("queue")
items: deque = deque(maxlen=1000)
WORKER_USER, WORKER_PASSWORD = "queue_worker", os.getenv("WORKER_DB_PASSWORD", "worker123")
db = make_db()


@svc.route("/healthz", health=True)
def healthz():
    return jsonify({"status": "ok", "service": "queue"})


@svc.route("/queue/enqueue", methods=("POST",), caps=("state_write",))
def enqueue():
    items.append(request.get_json(silent=True) or {})
    svc.say(f"ENQUEUE src_ip={g.src_ip} depth={len(items)}")
    return jsonify({"status": "queued", "depth": len(items)}), 201


@svc.route("/queue/stats", caps=("dynamic_query",))
def stats():
    return jsonify({"depth": len(items)})


@svc.route("/admin/config", caps=("dynamic_query",))
def admin_config():
    svc.say(f"ADMIN_ACCESS route=/admin/config src_ip={g.src_ip} caller={g.caller}")
    return jsonify({"worker_db_user": WORKER_USER, "worker_db_password": WORKER_PASSWORD, "db_host": "database"})


@svc.route("/admin/db_query", methods=("POST",), caps=("dynamic_query", "dependency_calls"), infra={"database": ["dynamic_query"]})
def admin_db_query():
    d = request.get_json(silent=True) or {}
    if d.get("password") != WORKER_PASSWORD:
        return jsonify({"error": "bad worker password"}), 401
    sql = str(d.get("sql", "SELECT 1"))
    svc.say(f"LATERAL_DB_ACCESS db_user={WORKER_USER} src_ip={g.src_ip} caller={g.caller} source_service=queue target=database")
    rows = db.raw(sql, limit=20)
    return jsonify({"rows": [list(map(str, r)) for r in rows]})


if __name__ == "__main__":
    svc.run(5004)
