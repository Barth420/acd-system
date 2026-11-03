"""
alert_sink.py: a small stand-in for the pipeline's /alerts endpoint, for running the lab without the pipeline.

  POST /alerts          accept a RawAlert (contract D shape), store it, print a one-line summary -> 201
  GET  /alerts          everything received so far (?rule=100301&limit=50)
  GET  /alerts/summary  counts per rule id
  DELETE /alerts        clear
Run:  uvicorn alert_sink:app --port 8099     (compose: service `alert-sink`, published on 127.0.0.1:8099)
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

app = FastAPI(title="ACD alert sink")
STORE: list[dict[str, Any]] = []
OUT = Path(os.getenv("SINK_FILE", "/tmp/acd-alert-sink.jsonl"))


class RawAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str
    timestamp: str
    raw_data: dict[str, Any]


@app.post("/alerts", status_code=201)
def receive(alert: RawAlert):
    rd = alert.raw_data
    rule, data = rd.get("rule", {}), rd.get("data", {})
    rec = {"received": len(STORE) + 1, **alert.model_dump()}
    STORE.append(rec)
    try:
        with OUT.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass
    print(f"[sink] #{rec['received']:>4} rule={rule.get('id')} level={rule.get('level')} src={data.get('srcip')} "
          f"dst={data.get('dstport')} via={data.get('source_service')} rid={data.get('request_id')}", flush=True)
    return {"received": rec["received"], "rule_id": rule.get("id")}


@app.get("/alerts")
def list_alerts(rule: Optional[int] = None, limit: int = 200):
    items = [a for a in STORE if rule is None or a["raw_data"].get("rule", {}).get("id") == rule]
    return {"count": len(items), "items": items[-limit:]}


@app.get("/alerts/summary")
def summary():
    c = Counter(a["raw_data"].get("rule", {}).get("id") for a in STORE)
    return {"total": len(STORE), "by_rule": {str(k): v for k, v in sorted(c.items(), key=lambda kv: str(kv[0]))}}


@app.delete("/alerts")
def clear():
    STORE.clear()
    return {"ok": True}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "alert-sink"}


@app.exception_handler(Exception)
async def _err(_, e: Exception):
    return JSONResponse({"error": str(e)}, status_code=500)
