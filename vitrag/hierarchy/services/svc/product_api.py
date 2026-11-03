"""
product_api (tier 1, :5001). LAB-ONLY weakness kept on purpose: /api/products builds its SQL by string formatting.
Depends on: database, auth_api (token check on POST).
"""

from __future__ import annotations

import re

from flask import Response, g, jsonify, request

from svc.acdlib import Service, make_db, EXFIL_ROWS

svc = Service("product_api")
db = make_db()
CATALOG_CACHE = [{"id": 1, "name": "Widget", "price": "9.99"}, {"id": 2, "name": "Gadget", "price": "14.99"}]
SQLI_HINT = re.compile(r"(['\"]|union\s+select|\bor\b\s+\S+=\S+|--|;|/\*|information_schema|sleep\s*\()", re.I)
XSS_HINT = re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=", re.I)


def _cached_catalog():
    r = jsonify(CATALOG_CACHE)
    return r


@svc.route("/healthz", health=True)
def healthz():
    return jsonify({"status": "ok", "service": "product_api"})


@svc.route("/api/products", caps=("dynamic_query",), infra={"database": ["dynamic_query"]}, cached=_cached_catalog)
def get_product():
    pid = request.args.get("id", "1")
    # LAB-ONLY: string interpolation into SQL (price is cast to text so UNION results line up on postgres and sqlite)
    query = f"SELECT id, name, CAST(price AS TEXT) FROM products WHERE id = {pid}"
    if SQLI_HINT.search(pid):
        svc.say(f"SQLI_ATTEMPT src_ip={g.src_ip} ua={g.ua!r} payload={pid!r}")
    svc.say(f"PRODUCT_QUERY src_ip={g.src_ip} ua={g.ua!r} query={query!r}")
    try:
        rows = db.raw(query)
    except Exception as e:  # noqa: BLE001 (sqlite3.Error / psycopg2.Error): verbose error is part of the lab
        if e.__class__.__name__ == "UpstreamError":
            raise
        svc.say(f"SQL_ERROR src_ip={g.src_ip} ua={g.ua!r} query={query!r} err={e}")
        return jsonify({"error": "sql error", "detail": str(e), "query": query}), 500
    stop = svc.require_egress(len(rows))
    if stop:
        return stop
    if len(rows) >= EXFIL_ROWS:
        svc.say(f"DATA_EXFIL rows={len(rows)} src_ip={g.src_ip} table=products route=/api/products source_service=product_api")
    if not rows:
        return jsonify({"error": "not found"}), 404
    return jsonify([{"id": r[0], "name": r[1], "price": r[2]} for r in rows])


@svc.route("/api/products/search", caps=("dynamic_query",))
def search():
    q = request.args.get("q", "")
    svc.say(f"PRODUCT_SEARCH src_ip={g.src_ip} ua={g.ua!r} q={q!r}")
    if XSS_HINT.search(q):
        svc.say(f"XSS_ATTEMPT src_ip={g.src_ip} ua={g.ua!r} q={q!r}")
    return Response(f"<html><body>Results for: {q}</body></html>", mimetype="text/html")  # LAB-ONLY: reflected unescaped


@svc.route("/api/products", methods=("POST",), caps=("state_write",), deps=("auth_api",), infra={"database": ["state_write"]})
def add_product():
    tok = request.headers.get("Authorization", "")[7:]
    r = svc.dep_call("auth_api", "GET", f"/auth/validate?token={tok}")
    if r.status_code != 200:
        return jsonify({"error": "unauthorized"}), 401
    d = request.get_json(silent=True) or {}
    db.run("INSERT INTO products(name, price) VALUES (?, ?)", (str(d.get("name", "item"))[:64], float(d.get("price", 1))))
    return jsonify({"status": "created"}), 201


if __name__ == "__main__":
    svc.run(5001)
