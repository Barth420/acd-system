"""
attacker/agent.py: a tiny command-driven HTTP agent (attacker-1 / attacker-2).

The controller drives it (contract V3: "attacker containers ... driven by commands from the controller").
Executes exactly one real HTTP request per command, against this lab only, and reports what happened; it never
decides whether that counts as a compromise (the scenario runner in the controller judges outcomes).

  POST /execute {method, url, headers, json, data, timeout} -> {status, headers, error}
  GET  /healthz
In Docker each agent is its own container (attacker-1 / attacker-2) with its own IP on attacker_net, so the
request really originates from a distinct address. Locally (no Docker), the harness binds two agents to
127.0.0.2 and 127.0.0.3 (any 127.0.0.0/8 address is loopback on Linux) and this agent binds its OWN outbound
socket to its bind IP, so even local tests get two distinct real source addresses.
"""

from __future__ import annotations

import os

import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.connection import create_connection
    import urllib3.connection as _uc

    class _BoundHTTPConnection(_uc.HTTPConnection):
        source_address = None

        def connect(self):  # noqa: D401
            self.sock = create_connection((self.host, self.port), self.timeout, source_address=self.source_address)

    HAVE_BIND = True
except Exception:  # noqa: BLE001
    HAVE_BIND = False

app = Flask("attacker-agent")
NAME = os.getenv("AGENT_NAME", "attacker")
BIND_IP = os.getenv("AGENT_BIND_IP")   # set only for the local (no-Docker) fallback


def _session() -> requests.Session:
    s = requests.Session()
    if BIND_IP and HAVE_BIND:
        class _Adapter(HTTPAdapter):
            def init_poolmanager(self, *a, **kw):
                kw["source_address"] = (BIND_IP, 0)
                super().init_poolmanager(*a, **kw)
        s.mount("http://", _Adapter())
        s.mount("https://", _Adapter())
    return s


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "service": NAME, "bind_ip": BIND_IP})


@app.route("/execute", methods=["POST"])
def execute():
    cmd = request.get_json(force=True)
    try:
        r = _session().request(cmd["method"], cmd["url"], headers=cmd.get("headers") or {}, json=cmd.get("json"),
                               data=cmd.get("data"), timeout=cmd.get("timeout", 6), allow_redirects=False)
        return jsonify({"status": r.status_code, "headers": dict(r.headers), "body": r.text[:500000], "error": None})
    except requests.RequestException as e:
        return jsonify({"status": None, "headers": {}, "body": None, "error": f"{e.__class__.__name__}: {e}"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "7000")), threaded=True)
