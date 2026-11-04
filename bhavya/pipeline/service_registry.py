"""
pipeline/service_registry.py — Static knowledge base of all services.

This is the "context" the brain/containment planner uses: the same attack on auth_api (critical, external)
must be treated differently from the same attack on search_api (medium, external).

Extended from the original 4-service Phase-1 subset to the full 8-service lab Vitrag actually runs
(vitrag/hierarchy/shared/topology.json — contract A). Field names and dependency semantics are unchanged.
"""

from __future__ import annotations

from .schemas import ServiceContext

# ──────────────────────────────────────────────────────────────────────────────
# Registry — keyed by service name (matches Vitrag's docker-compose service names)
# ──────────────────────────────────────────────────────────────────────────────

SERVICE_REGISTRY: dict[str, ServiceContext] = {
    "nginx": ServiceContext(
        name="nginx",
        sensitivity="medium",
        exposure="external",
        dependencies=["auth_api", "product_api", "order_api", "search_api"],
        dependents=[],
        role="reverse-proxy",
    ),
    "auth_api": ServiceContext(
        name="auth_api",
        sensitivity="critical",
        exposure="external",
        dependencies=["database", "cache"],
        dependents=["nginx", "product_api", "order_api"],
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
    "order_api": ServiceContext(
        name="order_api",
        sensitivity="high",
        exposure="external",
        dependencies=["database", "auth_api", "queue"],
        dependents=["nginx"],
        role="business-logic",
    ),
    "search_api": ServiceContext(
        name="search_api",
        sensitivity="medium",
        exposure="external",
        dependencies=["cache"],
        dependents=["nginx"],
        role="business-logic",
    ),
    "database": ServiceContext(
        name="database",
        sensitivity="critical",
        exposure="internal",
        dependencies=[],
        dependents=["auth_api", "product_api", "order_api"],
        role="data-store",
    ),
    "cache": ServiceContext(
        name="cache",
        sensitivity="medium",
        exposure="internal",
        dependencies=[],
        dependents=["auth_api", "search_api"],
        role="cache",
    ),
    "queue": ServiceContext(
        name="queue",
        sensitivity="low",
        exposure="internal",
        dependencies=[],
        dependents=["order_api"],
        role="work-queue",
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
