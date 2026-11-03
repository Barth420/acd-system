"""search_api (tier 1, :5003). Depends on: cache. /search/popular is static and keeps working in fallback."""

from __future__ import annotations

from flask import g, jsonify, request

from svc.acdlib import Service, make_cache

svc = Service("search_api")
cache = make_cache()
PRODUCTS = {"1": "Widget", "2": "Gadget", "3": "Sprocket", "4": "Gizmo", "5": "Doohickey"}
try:
    for k, v in PRODUCTS.items():
        if cache.get(f"prod:{k}") is None:
            cache.set(f"prod:{k}", v)
except Exception:  # noqa: BLE001  cache may not be up yet; seeded lazily below
    pass


@svc.route("/healthz", health=True)
def healthz():
    return jsonify({"status": "ok", "service": "search_api"})


@svc.route("/search", caps=("dynamic_query",), infra={"cache": ["dynamic_query"]})
def search():
    q = request.args.get("q", "").lower()
    items = cache.items("prod:") or [(f"prod:{k}", v) for k, v in PRODUCTS.items()]
    hits = [v for _, v in items if q in v.lower()]
    svc.say(f"SEARCH src_ip={g.src_ip} ua={g.ua!r} hits={len(hits)}")
    return jsonify({"q": q, "results": hits})


@svc.route("/search/popular")
def popular():
    return jsonify({"results": ["Widget", "Gadget"], "static": True})


if __name__ == "__main__":
    svc.run(5003)
