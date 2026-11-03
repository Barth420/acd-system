"""
acdlib.py: shared framework for the lab's Flask services.

Every endpoint DECLARES what it uses:
    caps   capabilities it needs (state_write, dynamic_query, data_egress, ...)
    deps   HTTP dependencies it calls (other Flask services)
    infra  {target: [caps]} for postgres/redis, which cannot enforce modes themselves, so the CALLER enforces
           the target's mode and the cut edge before touching it (app-level enforcement; see docs/vitrag/LAB.md)
Before the handler runs, the framework checks the control state:
    own mode blocks a declared capability   -> 503 + X-ACD-Blocked: mode=<m>; capability=<c>   (or serves a cached answer)
    declared dependency edge is cut         -> 503 + X-ACD-Blocked: edge=<a>-<b>
    infra target's mode blocks the op       -> 503 + X-ACD-Blocked: mode=<m>; capability=<c>  (X-ACD-Service = target)
    rate_limited                            -> per-source token bucket, excess gets 429 + X-ACD-Blocked
Endpoints that need nothing else keep working, which is the point of per-endpoint declarations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from flask import Flask, Response, g, jsonify, request

import controlstate as cs

LOG_ROOT = Path(os.getenv("LOG_ROOT", "/var/log/acd"))
LOG_FILES = {  # same file names the existing Wazuh localfile entries use (auth/auth.log, product/product.log)
    "auth_api": "auth/auth.log", "product_api": "product/product.log", "order_api": "order/order.log",
    "search_api": "search/search.log", "queue": "queue/queue.log",
}
BULK_ROWS = int(os.getenv("BULK_ROWS", "20"))          # more rows than this in one answer = bulk read (data_egress)
EXFIL_ROWS = int(os.getenv("EXFIL_ROWS", "50"))        # volume anomaly threshold that logs DATA_EXFIL
RL_RATE = float(os.getenv("RL_RATE", "8"))             # rate_limited: requests/s per source ...
RL_BURST = float(os.getenv("RL_BURST", "10"))          # ... with this burst


def clean(v, n: int = 64) -> str:
    """Make a caller-supplied identifier safe for a one-line log record (no spaces, '=' or quotes: no field spoofing)."""
    return re.sub(r"[^\w.:/@-]", "_", str(v))[:n]


class UpstreamError(Exception):
    def __init__(self, target: str, detail: str = ""):
        super().__init__(f"{target} unreachable {detail}")
        self.target = target


class BlockedUpstream(Exception):
    def __init__(self, header: str, service: str):
        super().__init__(header)
        self.header, self.service = header, service


def blocked(header: str, service: str, status: int = 503, extra: Optional[dict] = None) -> Response:
    body = {"error": "blocked by containment", "blocked": header, "service": service}
    r = jsonify(body)
    r.status_code = status
    r.headers["X-ACD-Blocked"] = header
    r.headers["X-ACD-Service"] = service
    for k, v in (extra or {}).items():
        r.headers[k] = v
    return r


# ── data stores ──────────────────────────────────────────────────────────────

class Db:
    """postgres (DATABASE_URL=postgresql://...) in compose, sqlite file (sqlite:///path) for local-process runs."""

    def __init__(self, url: str):
        self.url = url
        self.pg = url.startswith("postgres")
        if not self.pg:
            self.path = url.replace("sqlite:///", "")
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._seed_sqlite()

    def _conn(self):
        try:
            if self.pg:
                import psycopg2
                return psycopg2.connect(self.url, connect_timeout=3)
            return sqlite3.connect(self.path, timeout=5)
        except Exception as e:  # noqa: BLE001
            if e.__class__.__name__ in ("OperationalError",) and not isinstance(e, sqlite3.OperationalError):
                raise UpstreamError("database", str(e)[:80])
            raise

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def raw(self, sql: str, limit: Optional[int] = None) -> list[tuple]:
        """Execute a string AS IS. Used only by the deliberately injectable endpoints."""
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(sql)
            rows = cur.fetchall() if cur.description else []
            c.commit()
            return rows if limit is None else rows[:limit]
        finally:
            c.close()

    def run(self, sql: str, params: tuple = ()) -> list[tuple]:
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(self._sql(sql), params)
            rows = cur.fetchall() if cur.description else []
            c.commit()
            return rows
        finally:
            c.close()

    def _seed_sqlite(self) -> None:
        c = sqlite3.connect(self.path, timeout=5)
        cur = c.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, product_id INTEGER, qty INTEGER);
        CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT);
        CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, src_ip TEXT);
        """)
        if cur.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            base = [("admin", "admin123", "admin"), ("alice", "password", "user"), ("bob", "qwerty", "user"), ("charlie", "changeme", "user")]
            cur.executemany("INSERT INTO users(username,password,role) VALUES (?,?,?)", base)
            cur.executemany("INSERT INTO users(username,password,role) VALUES (?,?,?)",
                            [(f"user{i:04d}", f"pw{i:04d}", "user") for i in range(1, 297)])
            cur.executemany("INSERT INTO products(id,name,price) VALUES (?,?,?)",
                            [(1, "Widget", 9.99), (2, "Gadget", 14.99), (3, "Sprocket", 4.5), (4, "Gizmo", 19.0), (5, "Doohickey", 7.25)])
            cur.executemany("INSERT INTO secrets(id,name,value) VALUES (?,?,?)",
                            [(i + 1, f"key:{s}", cs.initial_key(s)) for i, s in enumerate(["product_api", "order_api", "queue", "search_api"])])
        c.commit()
        c.close()


class Cache:
    """redis (CACHE_URL=redis://...) in compose, sqlite key/value file (sqlite:///path) for local-process runs."""

    def __init__(self, url: str):
        self.redis = url.startswith("redis")
        if self.redis:
            import redis
            self.r = redis.Redis.from_url(url, socket_timeout=3, decode_responses=True)
        else:
            self.path = url.replace("sqlite:///", "")
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            c = sqlite3.connect(self.path, timeout=5)
            c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp REAL)")
            c.commit(); c.close()

    def _lite(self, sql: str, params: tuple = ()):
        c = sqlite3.connect(self.path, timeout=5)
        try:
            rows = c.execute(sql, params).fetchall()
            c.commit()
            return rows
        finally:
            c.close()

    def get(self, k: str) -> Optional[str]:
        try:
            if self.redis:
                return self.r.get(k)
        except Exception as e:  # noqa: BLE001
            raise UpstreamError("cache", str(e)[:80])
        rows = self._lite("SELECT v, exp FROM kv WHERE k=?", (k,))
        if not rows or (rows[0][1] and rows[0][1] < time.time()):
            return None
        return rows[0][0]

    def set(self, k: str, v: str, ex: Optional[int] = None) -> None:
        try:
            if self.redis:
                self.r.set(k, v, ex=ex)
                return
        except Exception as e:  # noqa: BLE001
            raise UpstreamError("cache", str(e)[:80])
        self._lite("INSERT OR REPLACE INTO kv(k,v,exp) VALUES (?,?,?)", (k, v, time.time() + ex if ex else None))

    def items(self, prefix: str) -> list[tuple[str, str]]:
        try:
            if self.redis:
                return [(k, self.r.get(k)) for k in self.r.scan_iter(match=prefix + "*")]
        except Exception as e:  # noqa: BLE001
            raise UpstreamError("cache", str(e)[:80])
        return [(k, v) for k, v in self._lite("SELECT k, v FROM kv WHERE k LIKE ?", (prefix + "%",))]


# ── the service wrapper ──────────────────────────────────────────────────────

class Service:
    def __init__(self, name: str):
        self.name = name
        self.app = Flask(name)
        self.state = cs.StateReader(os.getenv("CONTROL_STATE", "/control/state.json"))
        self.buckets: dict[str, tuple[float, float]] = {}
        self.dep_urls = {d: os.getenv(f"DEP_{d.upper()}_URL", f"http://{d}:{cs.PORTS[d]}") for d in cs.SERVICES}
        self.log = logging.getLogger(name)
        self.log.setLevel(logging.INFO)
        if not self.log.handlers:
            fmt = logging.Formatter(f"%(asctime)s %(levelname)s [{name}] %(message)s")
            sh = logging.StreamHandler()
            sh.setFormatter(fmt)
            self.log.addHandler(sh)
            rel = LOG_FILES.get(name)
            if rel:
                p = LOG_ROOT / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(p)
                fh.setFormatter(fmt)
                self.log.addHandler(fh)
        self._wire()

    # request context -------------------------------------------------------
    def _wire(self) -> None:
        @self.app.before_request
        def _ctx():
            g.rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
            fwd = request.headers.get("X-Forwarded-For", "")
            g.src_ip = clean(fwd.split(",")[0].strip() or request.remote_addr or "0.0.0.0", 45)
            g.via_gateway = request.headers.get("X-Via-Gateway") == "1"
            g.caller = request.headers.get("X-Service-Name")
            g.ua = request.headers.get("User-Agent", "")

        @self.app.after_request
        def _hdr(resp):
            resp.headers["X-Request-ID"] = getattr(g, "rid", "")
            return resp

        @self.app.errorhandler(BlockedUpstream)
        def _bu(e: BlockedUpstream):
            return blocked(e.header, e.service)

        @self.app.errorhandler(UpstreamError)
        def _ue(e: UpstreamError):
            self.say(f"UPSTREAM_ERROR target={e.target}")
            r = jsonify({"error": "upstream unreachable", "target": e.target})
            r.status_code = 502
            r.headers["X-ACD-Upstream-Error"] = f"{e.target} unreachable"
            return r

    def say(self, msg: str, level: int = logging.INFO) -> None:
        """Log one line; the request id is always appended as rid=<id>."""
        self.log.log(level, f"{msg} rid={getattr(g, 'rid', '-')}")

    # enforcement -----------------------------------------------------------
    def mode(self, service: Optional[str] = None) -> str:
        return cs.mode_of(self.state.get(), service or self.name)

    def _rate_limited(self) -> bool:
        now = time.time()
        tokens, last = self.buckets.get(g.src_ip, (RL_BURST, now))
        tokens = min(RL_BURST, tokens + (now - last) * RL_RATE)
        if tokens < 1:
            self.buckets[g.src_ip] = (tokens, now)
            return True
        self.buckets[g.src_ip] = (tokens - 1, now)
        return False

    def check(self, caps, deps, infra, cached, health) -> Optional[Response]:
        st = self.state.get()
        mode = cs.mode_of(st, self.name)
        if mode == "isolated":
            return blocked("mode=isolated; capability=all", self.name)
        if health:
            return None
        if mode == "rate_limited" and self._rate_limited():
            return blocked("mode=rate_limited; capability=bulk_requests", self.name, 429)
        need = set(caps)
        if deps or infra:
            need.add("dependency_calls")
        hit = cs.blocked_caps(mode, sorted(need))
        if hit:
            if cached is not None:
                r = cached()
                if r is not None:
                    r.headers["X-ACD-Blocked"] = f"mode={mode}; capability={hit[0]}; served=cached"
                    r.headers["X-ACD-Service"] = self.name
                    return r
            return blocked(f"mode={mode}; capability={hit[0]}", self.name)
        for d in list(deps) + list(infra or {}):
            if cs.edge_cut(st, self.name, d):
                return blocked(f"edge={self.name}-{d}", self.name)
        for target, ops in (infra or {}).items():
            tmode = cs.mode_of(st, target)
            thit = cs.blocked_caps(tmode, ops)
            if thit:
                return blocked(f"mode={tmode}; capability={thit[0]}", target)
        return None

    def route(self, rule: str, methods=("GET",), caps=(), deps=(), infra=None, cached: Optional[Callable] = None, health=False):
        def deco(fn):
            def view(*a, **kw):
                resp = self.check(caps, deps, infra, cached, health)
                if resp is not None:
                    return resp
                return fn(*a, **kw)
            view.__name__ = fn.__name__
            self.app.add_url_rule(rule, endpoint=fn.__name__, view_func=view, methods=list(methods))
            return fn
        return deco

    def require_egress(self, rows: int) -> Optional[Response]:
        """Bulk reads need data_egress; call from a handler after the row count is known."""
        if rows > BULK_ROWS and "data_egress" in cs.BLOCKS[self.mode()]:
            return blocked(f"mode={self.mode()}; capability=data_egress", self.name)
        return None

    # dependencies ----------------------------------------------------------
    def key(self) -> str:
        return cs.credential(self.state.get(), self.name)["current"]

    def dep_call(self, dep: str, method: str, path: str, **kw) -> requests.Response:
        if cs.edge_cut(self.state.get(), self.name, dep):
            raise BlockedUpstream(f"edge={self.name}-{dep}", self.name)
        headers = {"X-Request-ID": g.rid, "X-Forwarded-For": g.src_ip, "X-Service-Name": self.name,
                   "X-Service-Key": self.key(), "User-Agent": f"acd-{self.name}"}
        headers.update(kw.pop("headers", {}))
        try:
            r = requests.request(method, self.dep_urls[dep] + path, headers=headers, timeout=kw.pop("timeout", 4), **kw)
        except requests.RequestException as e:
            raise UpstreamError(dep, e.__class__.__name__)
        if r.status_code in (429, 503) and "X-ACD-Blocked" in r.headers:
            raise BlockedUpstream(r.headers["X-ACD-Blocked"], r.headers.get("X-ACD-Service", dep))
        return r

    def run(self, default_port: int) -> None:
        self.app.run(host="0.0.0.0", port=int(os.getenv("PORT", default_port)), threaded=True)


def make_db() -> Db:
    return Db(os.getenv("DATABASE_URL", "sqlite:////tmp/acd-local/db.sqlite"))


def make_cache() -> Cache:
    return Cache(os.getenv("CACHE_URL", "sqlite:////tmp/acd-local/cache.sqlite"))


def service_key_ok(svc: Service, name: Optional[str], key: Optional[str]) -> tuple[bool, str]:
    """-> (ok, reason). A revoked key (rotated away) is reported separately so detections can name it."""
    if not name or not key or name not in cs.SERVICES:
        return False, "missing_or_unknown"
    cred = cs.credential(svc.state.get(), name)
    if key == cred["current"]:
        return True, "ok"
    return False, "revoked" if key in cred.get("revoked", []) else "invalid"
