"""
core/schemas.py — Pydantic models for the 3 shared schemas.

These are the LOCKED CONTRACTS between team members.
- Schema 1: RawAlert (Vitrag's forwarder → Bhavya's /alerts)
- Schema 2: NormalizedAlert (Bhavya → Parth's brain) — MUST match Parth's input_schema.json
- Schema 3: MLReasoningResult (Parth → Bhavya) — MUST match Parth's output_schema.json

DO NOT modify field names without explicit team discussion.
Locked: Day 14, Month 1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ──────────────────────────────────────────────────────────────────────────────
# SCHEMA 1 — Raw Alert (Vitrag's forwarder → Bhavya's /alerts endpoint)
# ──────────────────────────────────────────────────────────────────────────────

class RawAlert(BaseModel):
    """
    Raw alert as forwarded from Wazuh by Vitrag's forwarder.py.
    This is what hits POST /alerts.
    """
    model_config = ConfigDict(extra="allow")  # Wazuh fields vary; tolerate extras

    source: Literal["wazuh", "manual_test"] = Field(
        ..., description="Where this alert originated."
    )
    timestamp: str = Field(
        ..., description="ISO 8601 timestamp from the original event."
    )
    raw_data: dict[str, Any] = Field(
        ..., description="Original Wazuh alert payload, untouched."
    )

    @field_validator("timestamp")
    @classmethod
    def _check_iso(cls, v: str) -> str:
        # Tolerant — Wazuh emits a few variants; just confirm parseable.
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"timestamp not ISO 8601: {v!r}") from e
        return v


# ──────────────────────────────────────────────────────────────────────────────
# SCHEMA 2 — Normalized Alert (Bhavya → Parth's brain)
# ──────────────────────────────────────────────────────────────────────────────
# This MUST match acd-system-main/schemas/input_schema.json exactly.
# Field names, enums, types — all locked.

ServiceName = Literal["auth_api", "product_api", "database", "nginx", "unknown"]
AttackType = Literal["brute_force", "sql_injection", "port_scan", "xss", "unknown"]
Severity = Literal["low", "medium", "high", "critical"]


class NormalizedFeatures(BaseModel):
    """
    Numeric/boolean features extracted for ML consumption.
    Field set is FROZEN — Parth's training data depends on these names.
    """
    model_config = ConfigDict(extra="forbid")

    request_rate_per_min: float = Field(..., ge=0)
    unique_paths_accessed: int = Field(..., ge=0)
    failed_auth_count: int = Field(..., ge=0)
    payload_contains_sql_keywords: bool
    user_agent_anomaly: bool
    geo_anomaly: bool


class NormalizedAlert(BaseModel):
    """
    The contract Bhavya's pipeline produces and Parth's brain consumes.
    Mirror of acd-system-main/schemas/input_schema.json.
    """
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    timestamp: str  # ISO 8601 UTC
    source_ip: str = Field(..., pattern=r"^(\d{1,3}\.){3}\d{1,3}$")
    destination_ip: str = Field(..., pattern=r"^(\d{1,3}\.){3}\d{1,3}$")
    destination_port: int = Field(..., ge=1, le=65535)
    service: ServiceName
    attack_type: AttackType
    severity: Severity
    raw_event_count: int = Field(..., ge=1)
    features: NormalizedFeatures
    wazuh_rule_id: Optional[int] = None
    wazuh_rule_description: Optional[str] = None

    @staticmethod
    def new_alert_id() -> str:
        return str(uuid4())


# ──────────────────────────────────────────────────────────────────────────────
# Enrichment / Context (internal to Bhavya, not sent to Parth)
# ──────────────────────────────────────────────────────────────────────────────

class ServiceContext(BaseModel):
    """
    What we know about a target service from the registry.
    Used by the context enricher and dependency graph.
    """
    name: ServiceName
    sensitivity: Literal["low", "medium", "high", "critical"]
    exposure: Literal["internal", "external"]
    dependencies: list[str] = Field(default_factory=list)
    dependents: list[str] = Field(default_factory=list)
    role: str = ""


class EnrichedIncident(BaseModel):
    """
    What gets stored in the DB after the full pipeline runs.
    Combines the normalized alert with context + (optional) brain result.
    """
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    normalized_alert: NormalizedAlert
    service_context: ServiceContext
    dependency_depth: int
    brain_result: Optional[dict[str, Any]] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
