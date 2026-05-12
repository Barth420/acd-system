"""
pipeline/service_registry.py — Static knowledge base of all services.

This is the "context" the brain uses: same attack on auth_api (critical, external)
must produce a different reasoning output than the same attack on frontend (low, internal).
"""

from __future__ import annotations

from .schemas import ServiceContext


# ──────────────────────────────────────────────────────────────────────────────
# Registry — keyed by service name (matches Vitrag's docker-compose service names)
# ──────────────────────────────────────────────────────────────────────────────

SERVICE_REGISTRY: dict[str, ServiceContext] = {
    "auth_api": ServiceContext(
        name="auth_api",
        sensitivity="critical",
        exposure="external",
        dependencies=["database"],
        dependents=["product_api", "nginx"],
        role="authentication",
    ),
    "product_api": ServiceContext(
        name="product_api",
        sensitivity="high",
        exposure="external",
        dependencies=["database", "auth_api"],
        dependents=["nginx"],
        role="business-logic",
    ),
    "database": ServiceContext(
        name="database",
        sensitivity="critical",
        exposure="internal",
        dependencies=[],
        dependents=["auth_api", "product_api"],
        role="data-store",
    ),
    "nginx": ServiceContext(
        name="nginx",
        sensitivity="medium",
        exposure="external",
        dependencies=["auth_api", "product_api"],
        dependents=[],
        role="reverse-proxy",
    ),
}


def get_service_context(service: str) -> ServiceContext:
    """
    Look up a service. Falls back to a generic 'unknown' context if not found,
    so the pipeline never crashes on a service name it hasn't seen.
    """
    if service in SERVICE_REGISTRY:
        return SERVICE_REGISTRY[service]
    return ServiceContext(
        name="unknown",
        sensitivity="medium",
        exposure="external",
        dependencies=[],
        dependents=[],
        role="unknown",
    )


def list_services() -> list[str]:
    return list(SERVICE_REGISTRY.keys())
