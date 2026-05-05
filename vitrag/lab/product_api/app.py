"""
product_api — Intentionally vulnerable product catalog (Vitrag's lab).

Exposes:
  GET  /api/products?id=X    — fetch product by id  (SQLi vulnerable!)
  GET  /api/products/search  — text search          (XSS reflective)
  POST /api/products         — add product          (no auth)

Vulnerabilities baked in:
  - String-formatted SQL → classic injection
  - Reflected query echo → XSS
  - No auth on create

Logs go to /var/log/product/product.log
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

LOG_DIR = Path("/var/log/product")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "product.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [product_api] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("product_api")

DB_FILE = "/tmp/products.db"


def _init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS products "
        "(id INTEGER PRIMARY KEY, name TEXT, price REAL, secret_note TEXT)"
    )
    cur.execute("DELETE FROM products")
    cur.executemany(
        "INSERT INTO products VALUES (?, ?, ?, ?)",
        [
            (1, "Widget", 9.99, "internal-only"),
            (2, "Gadget", 14.99, "do-not-display"),
            (3, "Sprocket", 4.50, "low-margin"),
        ],
    )
    conn.commit()
    conn.close()


_init_db()
app = Flask(__name__)


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")


@app.route("/api/products", methods=["GET"])
def get_product():
    pid = request.args.get("id", "1")
    src_ip = _client_ip()
    ua = request.headers.get("User-Agent", "")

    # !! INTENTIONALLY VULNERABLE — string interpolation into SQL
    query = f"SELECT id, name, price FROM products WHERE id = {pid}"
    log.info(f"PRODUCT_QUERY src_ip={src_ip} ua={ua!r} query={query!r}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return jsonify({"error": "not found"}), 404
        return jsonify(
            [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]
        )
    except sqlite3.Error as e:
        # Verbose error — leaks SQL info, useful for attackers and detectors
        log.warning(
            f"SQL_ERROR src_ip={src_ip} ua={ua!r} query={query!r} err={e}"
        )
        return jsonify({"error": "sql error", "detail": str(e), "query": query}), 500


@app.route("/api/products/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    src_ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    log.info(f"PRODUCT_SEARCH src_ip={src_ip} ua={ua!r} q={q!r}")
    # Reflected XSS — echoes query unescaped
    return f"<html><body>Results for: {q}</body></html>"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "product_api"})


if __name__ == "__main__":
    log.info("product_api starting on 0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001)
