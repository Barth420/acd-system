"""
pipeline/dependency_graph.py — NetworkX dependency graph of services.

Used to compute:
  - Dependency depth (how deep is this service in the chain)
  - Downstream blast radius (which services are at risk if this one is compromised)

Built once at startup from the service registry.
"""

from __future__ import annotations

import networkx as nx

from .service_registry import SERVICE_REGISTRY


def build_graph() -> nx.DiGraph:
    """
    Build a directed graph: edge A -> B means "A depends on B"
    (i.e. if B is compromised, A is at risk).
    """
    g = nx.DiGraph()
    for svc_name, ctx in SERVICE_REGISTRY.items():
        g.add_node(svc_name, **ctx.model_dump())
        for dep in ctx.dependencies:
            g.add_edge(svc_name, dep)
    return g


# Build once, share across requests
_GRAPH: nx.DiGraph = build_graph()


def get_graph() -> nx.DiGraph:
    return _GRAPH


def dependency_depth(service: str) -> int:
    """
    How many hops down does this service go?
    A leaf service (no deps) = 0.
    A service that depends on a service that depends on something = 2.
    Returns 0 for unknown services.
    """
    if service not in _GRAPH:
        return 0
    # Longest path FROM this node following 'depends-on' edges
    descendants = nx.descendants(_GRAPH, service)
    if not descendants:
        return 0
    max_depth = 0
    for desc in descendants:
        try:
            path_len = nx.shortest_path_length(_GRAPH, service, desc)
            max_depth = max(max_depth, path_len)
        except nx.NetworkXNoPath:
            continue
    return max_depth


def downstream_services(service: str) -> list[str]:
    """
    Services that DEPEND on this one. If this service is compromised,
    these are at risk.
    """
    if service not in _GRAPH:
        return []
    # Reverse direction: who has an edge pointing TO this service?
    return list(_GRAPH.predecessors(service))


def blast_radius(service: str) -> list[str]:
    """
    Full transitive set of services that would be affected
    if `service` were compromised.
    """
    if service not in _GRAPH:
        return []
    reverse = _GRAPH.reverse(copy=False)
    return list(nx.descendants(reverse, service))
