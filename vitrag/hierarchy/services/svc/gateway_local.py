"""
gateway_local.py: Python stand-in for the nginx gateway, used ONLY for local-process runs and tests
(the compose stack uses the real nginx, see gateway/nginx.conf). Same behaviour: always sets X-Request-ID,
X-Forwarded-For (the real client address) and X-Via-Gateway; blocks according to gateway_rules; writes an access
log in the same shape as nginx's `detailed` format plus rid=.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path

import requests
from flask import Flask, Response, request

import controlstate as cs
import gateway_rules as gr

LOG_ROOT = Path(os.getenv("LOG_ROOT", "/var/log/acd"))
state = cs.StateReader(os.getenv("CONTROL_STATE", "/control/state.json"))
app = Flask("gateway")
(LOG_ROOT / "nginx").mkdir(parents=True, exist_ok=True)
access = logging.getLogger("gateway.access")
access.setLevel(logging.INFO)
if not access.handlers:
    h = logging.FileHandler(LOG_ROOT / "nginx" / "access.log")
    h.setFormatter(logging.Formatter("%(message)s"))
    access.addHandler(h)
UPSTREAM = {s: os.getenv(f"DEP_{s.upper()}_URL", f"http://{s}:{cs.PORTS[s]}") for s in cs.SERVICES}
buckets: dict[str, tuple[float, float]] = {}


def _log(rid: str, status: int, body: bytes) -> None:
    ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
    ua = request.headers.get("User-Agent", "")
    access.info(f'{request.remote_addr} - - [{ts}] "{request.method} {request.full_path.rstrip("?")} HTTP/1.1" {status} 0 '
                f'"{request.headers.get("Referer", "")}" "{ua}" "-" "{body[:200].decode("latin1")}" rid={rid}')


def _reply(rid: str, resp: Response, reason: str = "") -> Response:
    resp.headers["X-Request-ID"] = rid
    if reason:
        resp.headers["X-ACD-Blocked"] = reason
        resp.headers["X-ACD-Service"] = "nginx"
    _log(rid, resp.status_code, request.get_data() or b"")
    return resp


@app.route("/", defaults={"p": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/<path:p>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy(p: str):
    rid = uuid.uuid4().hex[:16]
    path = request.path
    st = state.get()
    reason = gr.decision(st, request.method, path)
    if reason:
        return _reply(rid, Response('{"error":"blocked by containment"}', 503, mimetype="application/json"), reason)
    if gr.rate_limited(st):
        now = time.time()
        tokens, last = buckets.get(request.remote_addr, (10.0, now))
        tokens = min(10.0, tokens + (now - last) * 8.0)
        buckets[request.remote_addr] = (tokens - 1 if tokens >= 1 else tokens, now)
        if tokens < 1:
            return _reply(rid, Response('{"error":"rate limited"}', 429, mimetype="application/json"), "mode=rate_limited; capability=bulk_requests")
    if path == "/healthz":
        return _reply(rid, Response('{"status":"ok","service":"nginx"}', 200, mimetype="application/json"))
    svc = gr.upstream_for(path)
    if not svc:
        return _reply(rid, Response("<html><body><h1>ACD Hierarchy Gateway</h1></body></html>", 200, mimetype="text/html"))
    headers = {k: v for k, v in request.headers if k.lower() not in ("host", "x-request-id", "x-forwarded-for", "x-via-gateway", "content-length")}
    headers.update({"X-Request-ID": rid, "X-Forwarded-For": request.remote_addr or "", "X-Via-Gateway": "1"})
    try:
        r = requests.request(request.method, UPSTREAM[svc] + request.full_path.rstrip("?"), headers=headers,
                             data=request.get_data(), timeout=8, allow_redirects=False)
    except requests.RequestException:
        return _reply(rid, Response('{"error":"bad gateway"}', 502, mimetype="application/json"))
    out = Response(r.content, r.status_code)
    for k in ("Content-Type", "X-ACD-Blocked", "X-ACD-Service", "X-ACD-Upstream-Error"):
        if k in r.headers:
            out.headers[k] = r.headers[k]
    return _reply(rid, out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), threaded=True)
