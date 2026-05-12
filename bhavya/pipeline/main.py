"""
pipeline/main.py — FastAPI application.

Endpoints:
  POST /alerts            — Vitrag's forwarder POSTs raw Wazuh alerts here
  GET  /incidents         — list recent enriched incidents
  GET  /incidents/{id}    — fetch a single incident
  GET  /services          — service registry dump (for debugging)
  GET  /graph             — dependency graph dump (for debugging)
  GET  /healthz           — liveness check

Run:
  cd bhavya
  uvicorn pipeline.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

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
    get_incident,
    init_db,
    list_incidents,
    save_incident,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("acd.pipeline")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    g = get_graph()
    logger.info(
        f"Pipeline up — {len(SERVICE_REGISTRY)} services registered, "
        f"graph has {g.number_of_nodes()} nodes / {g.number_of_edges()} edges"
    )
    yield
    logger.info("Pipeline shutting down")


app = FastAPI(
    title="ACD Bhavya Pipeline",
    version="0.1.0",
    description="Defense & Integration pipeline — Wazuh alerts → Normalized → Enriched → Stored",
    lifespan=lifespan,
)

# Permissive CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "acd-bhavya-pipeline",
        "incidents_stored": count_incidents(),
    }


@app.post("/alerts", status_code=status.HTTP_201_CREATED)
def ingest_alert(raw_alert: RawAlert) -> dict[str, Any]:
    """
    Main ingestion endpoint. Vitrag's forwarder POSTs Wazuh alerts here.
    Pipeline:
        raw → normalize → enrich (service context) → graph (dep depth) → store
    """
    # 1. Normalize
    normalized = normalize_wazuh_alert(raw_alert.raw_data)
    if normalized is None:
        logger.warning(f"Alert dropped — could not normalize: {raw_alert.raw_data}")
        raise HTTPException(
            status_code=422,
            detail="Could not normalize raw alert (missing required fields).",
        )

    # 2. Context enrich
    ctx = get_service_context(normalized.service)

    # 3. Graph: dependency depth
    depth = dependency_depth(normalized.service)

    # 4. Build enriched incident
    incident = EnrichedIncident(
        normalized_alert=normalized,
        service_context=ctx,
        dependency_depth=depth,
        brain_result=None,  # Brain integration happens in Phase 2
    )

    # 5. Store
    incident_id = save_incident(incident)

    logger.info(
        f"Stored incident_id={incident_id[:8]}... "
        f"alert_id={normalized.alert_id[:8]}... "
        f"service={normalized.service} attack={normalized.attack_type} "
        f"severity={normalized.severity} blast_radius={blast_radius(normalized.service)}"
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
    return {
        "services": [
            get_service_context(name).model_dump() for name in list_services()
        ]
    }


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
