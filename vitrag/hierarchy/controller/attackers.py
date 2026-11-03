"""
attackers.py: how the controller reaches attacker-1 / attacker-2.

  AgentClient    POST {url}/execute on a real attacker agent container (Docker; real distinct source IP).
  DirectClient   in-process request bound to a given local source IP (no-Docker fallback; see attacker/agent.py
                 for why 127.0.0.2/.3 give two real distinct addresses even without containers).
Both return the same shape: {status, headers, body, error}.
"""

from __future__ import annotations

from typing import Any, Optional

import requests


class AgentClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def execute(self, method: str, url: str, **kw) -> dict[str, Any]:
        try:
            r = requests.post(f"{self.base_url}/execute", json={"method": method, "url": url, **kw}, timeout=kw.get("timeout", 6) + 4)
            return r.json()
        except requests.RequestException as e:
            return {"status": None, "headers": {}, "body": None, "error": f"agent_unreachable: {e.__class__.__name__}"}


class DirectClient:
    def __init__(self, bind_ip: Optional[str] = None):
        self.bind_ip = bind_ip
        self._session = self._make_session()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        if self.bind_ip:
            from requests.adapters import HTTPAdapter
            try:
                from urllib3.util.connection import create_connection
                import urllib3.connection as uc

                bind_ip = self.bind_ip

                class _Conn(uc.HTTPConnection):
                    def connect(self):
                        self.sock = create_connection((self.host, self.port), self.timeout, source_address=(bind_ip, 0))

                class _Adapter(HTTPAdapter):
                    def init_poolmanager(self, *a, **kw):
                        kw["source_address"] = (bind_ip, 0)
                        super().init_poolmanager(*a, **kw)
                s.mount("http://", _Adapter())
            except Exception:  # noqa: BLE001
                pass
        return s

    def execute(self, method: str, url: str, headers: Optional[dict] = None, json: Any = None, data: Any = None, timeout: float = 6) -> dict[str, Any]:
        try:
            r = self._session.request(method, url, headers=headers or {}, json=json, data=data, timeout=timeout, allow_redirects=False)
            return {"status": r.status_code, "headers": dict(r.headers), "body": r.text[:500000], "error": None}
        except requests.RequestException as e:
            return {"status": None, "headers": {}, "body": None, "error": f"{e.__class__.__name__}: {e}"}


def make_attackers() -> dict[str, "AgentClient | DirectClient"]:
    """
    ATTACKER_URLS=attacker-1=http://attacker-1:7000,attacker-2=http://attacker-2:7000  -> real agent containers (compose default).
    Else ACD_ATTACKER_BIND=127.0.0.2,127.0.0.3  -> in-process DirectClients bound to those source IPs (no-Docker fallback;
    see attacker/agent.py for why distinct loopback addresses still give two real distinct source IPs).
    Else: both names share one unbound DirectClient (degraded fallback: same source IP for both attackers).
    """
    import os
    urls = os.getenv("ATTACKER_URLS", "")
    if urls:
        out = {}
        for pair in urls.split(","):
            name, _, url = pair.partition("=")
            if name and url:
                out[name.strip()] = AgentClient(url.strip())
        if out:
            return out
    binds = [b.strip() for b in os.getenv("ACD_ATTACKER_BIND", "").split(",") if b.strip()]
    if len(binds) >= 2:
        return {"attacker-1": DirectClient(binds[0]), "attacker-2": DirectClient(binds[1])}
    shared = DirectClient()
    return {"attacker-1": shared, "attacker-2": shared}
