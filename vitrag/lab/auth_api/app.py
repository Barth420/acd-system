"""
auth_api — Intentionally vulnerable authentication service (Vitrag's lab).

Exposes:
  POST /auth/login   — accepts username+password, no rate limiting
  GET  /auth/whoami  — token introspection

Vulnerabilities baked in (this is a TEST LAB):
  - No rate limiting → brute force friendly
  - Logs every failure to /var/log/auth/auth.log in a Wazuh-friendly format
  - Verbose error responses
  - Plain HTTP

Logs go to /var/log/auth/auth.log so Wazuh can tail them.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

# ── Logging — Wazuh friendly format ─────────────────────────────────────────
LOG_DIR = Path("/var/log/auth")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "auth.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [auth_api] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("auth_api")


# ── App ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# In-memory user store (Phase 1 — replace with DB in Phase 2)
USERS = {
    "admin": "admin123",
    "alice": "password",
    "bob": "qwerty",
}


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    src_ip = _client_ip()
    ua = request.headers.get("User-Agent", "")

    if username in USERS and USERS[username] == password:
        log.info(
            f"AUTH_SUCCESS user={username} src_ip={src_ip} ua={ua!r}"
        )
        return jsonify({"status": "ok", "token": f"tok_{username}_{int(time.time())}"})

    # Failure — emit a structured line that Wazuh can parse
    log.warning(
        f"AUTH_FAILURE user={username} src_ip={src_ip} ua={ua!r} "
        f"reason=invalid_credentials"
    )
    return jsonify({"status": "error", "msg": "invalid credentials"}), 401


@app.route("/auth/whoami", methods=["GET"])
def whoami():
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer tok_"):
        user = token.split("_")[1] if "_" in token else "unknown"
        return jsonify({"user": user})
    return jsonify({"error": "unauthorized"}), 401


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "auth_api"})


if __name__ == "__main__":
    log.info("auth_api starting on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
