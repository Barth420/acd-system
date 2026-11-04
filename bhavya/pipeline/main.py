"""
pipeline/main.py — FastAPI application.

Endpoints:
  POST /alerts              — Vitrag's forwarder POSTs raw Wazuh alerts here
  GET  /incidents           — list recent enriched incidents
  GET  /incidents/{id}      — fetch a single incident
  GET  /services            — service registry dump (for debugging)
  GET  /graph                — dependency graph dump (for debugging)
  GET  /healthz              — liveness check

  GET  /api/decisions            — containment decisions (the "why"), newest first
  GET  /api/decisions/{id}       — one decision, with every action's real result
  POST /api/decisions/{id}/approve  — execute a decision that's waiting (ACD_AUTONOMY=approve)
  GET  /api/forensics             — reconstructed attack path + timeline (?since=&until=&ip=)
  GET  /api/config                — what the dashboard needs to know (controller URL, autonomy mode)
  GET  /ui, /ui/{file}            — the dashboard itself

Run:
  cd bhavya
  uvicorn pipeline.main:app --host 0.0.0.0 --port 8000 --reload

Env:
  ACD_CONTROLLER_URL   Vitrag's lab controller (default http://localhost:8100)
  ACD_AUTONOMY         auto (default: contain immediately) | approve (plan only, wait for a click)
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from . import forensics
from .containment.controller_client import ControllerClient
from .containment.manager import ContainmentManager
from .dependency_graph import (
    blast_radius,
    dependency_depth,
    downstream_services,
    get_graph,
)
from .normalizer import normalize_wazuh_alert
from .schemas import EnrichedIncident, RawAlert
from .service_registry import SERVICE_REGISTRY, get_service_context, list_services
from .storage import (
    count_incidents,
    get_decision,
    get_incident,
    init_db,
    list_decisions,
    list_incidents,
    save_decision,
    save_incident,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("acd.pipeline")

UI_DIR = Path(__file__).resolve().parent / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    g = get_graph()
    if app.state.manager is None:
        app.state.manager = ContainmentManager(
            client=ControllerClient(),
            persist=save_decision,
            autonomy=os.getenv("ACD_AUTONOMY", "auto"),
        )
    logger.info(
        f"Pipeline up — {len(SERVICE_REGISTRY)} services registered, "
        f"graph has {g.number_of_nodes()} nodes / {g.number_of_edges()} edges, "
        f"containment autonomy={app.state.manager.autonomy}, controller={app.state.manager.client.base}"
    )
    yield
    logger.info("Pipeline shutting down")


def create_app(manager: Optional[ContainmentManager] = None) -> FastAPI:
    app = FastAPI(
        title="ACD Bhavya Pipeline",
        version="0.3.0",
        description="Defense & Integration pipeline — Wazuh alerts → Normalized → Enriched → Containment → Stored",
        lifespan=lifespan,
    )
    app.state.manager = manager

    # Permissive CORS for local dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ──────────────────────────────────────────────────────────────────────
    # Core pipeline endpoints
    # ──────────────────────────────────────────────────────────────────────

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "acd-bhavya-pipeline",
            "incidents_stored": count_incidents(),
        }

    @app.post("/alerts", status_code=status.HTTP_201_CREATED)
    def ingest_alert(raw_alert: RawAlert, background: BackgroundTasks) -> dict[str, Any]:
        """
        Main ingestion endpoint. Vitrag's forwarder POSTs Wazuh alerts here.
        Pipeline:
            raw → normalize → enrich (service context) → store → containment (background, does not
            delay the response to the forwarder)
        """
        normalized = normalize_wazuh_alert(raw_alert.raw_data)
        if normalized is None:
            logger.warning(f"Alert dropped — could not normalize: {raw_alert.raw_data}")
            raise HTTPException(status_code=422, detail="Could not normalize raw alert (missing required fields).")

        ctx = get_service_context(normalized.service)
        depth = dependency_depth(normalized.service)

        incident = EnrichedIncident(
            normalized_alert=normalized,
            service_context=ctx,
            dependency_depth=depth,
            brain_result=None,
        )
        incident_id = save_incident(incident)

        logger.info(
            f"Stored incident_id={incident_id[:8]}... alert_id={normalized.alert_id[:8]}... "
            f"service={normalized.service} attack={normalized.attack_type} "
            f"severity={normalized.severity} blast_radius={blast_radius(normalized.service)}"
        )

        background.add_task(
            app.state.manager.handle_incident,
            incident_id=incident_id,
            alert_id=normalized.alert_id,
            service=normalized.service,
            attack_type=normalized.attack_type,
            severity=normalized.severity,
            source_ip=normalized.source_ip,
        )

        return {
            "incident_id": incident_id,
            "alert_id": normalized.alert_id,
            "service": normalized.service,
            "attack_type": normalized.attack_type,
            "severity": normalized.severity,
            "sensitivity": ctx.sensitivity,
            "exposure": ctx.exposure,
            "dependency_depth": depth,
            "blast_radius": blast_radius(normalized.service),
            "containment": "scheduled",
        }

    @app.get("/incidents")
    def get_incidents(limit: int = 50) -> dict[str, Any]:
        items = list_incidents(limit=limit)
        return {"count": len(items), "items": items}

    @app.get("/incidents/{incident_id}")
    def get_one(incident_id: str) -> dict[str, Any]:
        item = get_incident(incident_id)
        if not item:
            raise HTTPException(404, "Incident not found")
        return item

    @app.get("/services")
    def get_services() -> dict[str, Any]:
        return {"services": [get_service_context(name).model_dump() for name in list_services()]}

    @app.get("/graph")
    def get_graph_summary() -> dict[str, Any]:
        g = get_graph()
        return {
            "nodes": list(g.nodes()),
            "edges": [{"from": u, "to": v} for u, v in g.edges()],
            "depths": {n: dependency_depth(n) for n in g.nodes()},
            "blast_radius": {n: blast_radius(n) for n in g.nodes()},
            "downstream": {n: downstream_services(n) for n in g.nodes()},
        }

    # ──────────────────────────────────────────────────────────────────────
    # Containment (the "why" the dashboard shows)
    # ──────────────────────────────────────────────────────────────────────

    @app.get("/api/decisions")
    def api_decisions(limit: int = 100) -> dict[str, Any]:
        live = app.state.manager.list_recent(limit)
        if not live:
            live = list_decisions(limit)
        return {"count": len(live), "items": live}

    @app.get("/api/decisions/{decision_id}")
    def api_decision(decision_id: str) -> dict[str, Any]:
        d = app.state.manager.get(decision_id) or get_decision(decision_id)
        if not d:
            raise HTTPException(404, "Decision not found")
        return d

    @app.post("/api/decisions/{decision_id}/approve")
    def api_approve(decision_id: str) -> dict[str, Any]:
        try:
            return app.state.manager.approve(decision_id).to_dict()
        except KeyError:
            raise HTTPException(404, "Decision not found")
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.get("/api/forensics")
    def api_forensics(since: Optional[str] = None, until: Optional[str] = None, ip: Optional[str] = None,
                      limit: int = 500) -> dict[str, Any]:
        incidents = list_incidents(limit=limit)[::-1]  # oldest first
        decisions = app.state.manager.list_recent(limit) or list_decisions(limit)
        return forensics.reconstruct(incidents, decisions, since=since, until=until, ip=ip)

    @app.get("/api/config")
    def api_config() -> dict[str, Any]:
        return {"controller_url": app.state.manager.client.base, "autonomy": app.state.manager.autonomy}

    # Same-origin proxy for the three READ-ONLY controller endpoints the dashboard needs, so the browser never
    # has to call the controller cross-origin (its CORS allowlist is for localhost:8000 specifically; this proxy
    # works regardless of which port the pipeline itself happens to run on). Never proxies writes: the dashboard
    # must go through the planner (POST /api/decisions/{id}/approve), not actuate the lab directly.
    @app.get("/api/lab/{path:path}")
    def lab_proxy(path: str) -> Any:
        # goes through the SAME ControllerClient the manager uses (not a fresh httpx call), so it honours
        # whatever http client was injected (real or test) and stays consistent with everything else this
        # pipeline does against the controller.
        method = {"topology": app.state.manager.client.topology, "state": app.state.manager.client.state,
                 "health": app.state.manager.client.health}.get(path)
        if method is None:
            raise HTTPException(403, f"GET /{path} is not available through this proxy")
        from .containment.controller_client import ControllerError
        try:
            return method()
        except ControllerError as e:
            raise HTTPException(502, f"controller unreachable: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Dashboard (static; see pipeline/ui/)
    # ──────────────────────────────────────────────────────────────────────

    @app.get("/ui", include_in_schema=False)
    def ui_index():
        return FileResponse(UI_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/ui/{name}", include_in_schema=False)
    def ui_asset(name: str):
        if name not in ("app.js", "style.css"):
            raise HTTPException(404)
        return FileResponse(UI_DIR / name, headers={"Cache-Control": "no-store"})

    return app


app = create_app()
