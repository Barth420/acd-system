"""
pipeline/storage.py — SQLite storage for enriched incidents.

SQLite chosen for Phase 1 because it's zero-config and runs in WSL2 without
a separate container. The schema is intentionally simple — Postgres migration
later is a single connection-string change.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Session

from .schemas import EnrichedIncident

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# DB setup
# ──────────────────────────────────────────────────────────────────────────────

_default_db = Path(__file__).parent.parent / "data" / "incidents.db"
DB_PATH = Path(os.getenv("ACD_DB_PATH", str(_default_db)))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
ENGINE = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    alert_id = Column(String, index=True, nullable=False)
    service = Column(String, index=True, nullable=False)
    attack_type = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    sensitivity = Column(String, nullable=False)
    exposure = Column(String, nullable=False)
    dependency_depth = Column(Integer, nullable=False)
    source_ip = Column(String, nullable=False)
    payload_json = Column(Text, nullable=False)  # full EnrichedIncident as JSON
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


def init_db() -> None:
    Base.metadata.create_all(ENGINE)
    logger.info(f"DB initialized at {DB_PATH}")


def save_incident(incident: EnrichedIncident) -> str:
    """Persist an enriched incident; returns its incident_id."""
    with Session(ENGINE) as s:
        row = IncidentRow(
            incident_id=incident.incident_id,
            alert_id=incident.normalized_alert.alert_id,
            service=incident.normalized_alert.service,
            attack_type=incident.normalized_alert.attack_type,
            severity=incident.normalized_alert.severity,
            sensitivity=incident.service_context.sensitivity,
            exposure=incident.service_context.exposure,
            dependency_depth=incident.dependency_depth,
            source_ip=incident.normalized_alert.source_ip,
            payload_json=incident.model_dump_json(),
        )
        s.add(row)
        s.commit()
    return incident.incident_id


def list_incidents(limit: int = 50) -> list[dict]:
    with Session(ENGINE) as s:
        rows = s.execute(
            select(IncidentRow).order_by(IncidentRow.created_at.desc()).limit(limit)
        ).scalars().all()
        return [
            {
                "incident_id": r.incident_id,
                "alert_id": r.alert_id,
                "service": r.service,
                "attack_type": r.attack_type,
                "severity": r.severity,
                "sensitivity": r.sensitivity,
                "exposure": r.exposure,
                "dependency_depth": r.dependency_depth,
                "source_ip": r.source_ip,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ]


def get_incident(incident_id: str) -> Optional[dict]:
    with Session(ENGINE) as s:
        row = s.execute(
            select(IncidentRow).where(IncidentRow.incident_id == incident_id)
        ).scalar_one_or_none()
        if not row:
            return None
        return json.loads(row.payload_json)


def count_incidents() -> int:
    with Session(ENGINE) as s:
        return s.query(IncidentRow).count()
