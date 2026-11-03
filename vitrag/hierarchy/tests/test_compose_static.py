"""Static checks of docker-compose.yml (no Docker needed): contract A publishing rules and tier networks."""

from __future__ import annotations

from pathlib import Path

import yaml

import controlstate as cs

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text())
SVCS = COMPOSE["services"]


def test_project_and_container_names():
    assert COMPOSE["name"] == "acd-hierarchy"
    for name, s in SVCS.items():
        assert s["container_name"].startswith("acd-h-"), name


def test_all_eight_services_of_table_a_exist():
    assert set(cs.SERVICES) <= set(SVCS)


def test_data_tier_is_never_published_and_published_ports_are_localhost_only():
    for name in ("database", "cache", "queue"):
        assert not SVCS[name].get("ports"), name
    for name, s in SVCS.items():
        for p in s.get("ports", []):
            assert str(p).startswith("127.0.0.1:"), (name, p)
    assert SVCS["nginx"]["ports"] == ["127.0.0.1:8080:80"]
    assert SVCS["controller"]["ports"] == ["127.0.0.1:8100:8100"]
    published = {n for n, s in SVCS.items() if s.get("ports") and not s.get("profiles")}      # the default stack
    assert published == {"nginx", "controller", "alert-sink"}                              # contract A: nothing else reaches the host


def test_attacker_containers_exist_with_distinct_ips_on_their_own_network():
    for name, ip in (("attacker-1", "172.30.9.10"), ("attacker-2", "172.30.9.11")):
        assert "attacker_net" in SVCS[name]["networks"]
        assert SVCS[name]["networks"]["attacker_net"]["ipv4_address"] == ip
        assert not SVCS[name].get("ports")                                  # not published to the host
    assert SVCS["attacker-1"]["networks"]["attacker_net"]["ipv4_address"] != SVCS["attacker-2"]["networks"]["attacker_net"]["ipv4_address"]
    assert {n for n, s in SVCS.items() if s.get("ports") and s.get("profiles")} <= {"wazuh.dashboard"}   # profile-only, documented deviation


def test_tier_networks_are_internal_and_data_tier_is_isolated_from_the_edge():
    nets = COMPOSE["networks"]
    for n in ("net_t0", "net_t1", "net_t2"):
        assert nets[n]["internal"] is True
    assert set(SVCS["database"]["networks"]) == {"net_t2"} == set(SVCS["cache"]["networks"]) == set(SVCS["queue"]["networks"])
    assert "net_t2" not in SVCS["nginx"]["networks"] and "net_t1" not in SVCS["nginx"]["networks"]
    assert set(SVCS["auth_api"]["networks"]) == {"net_t0", "net_t1", "net_t2"}


def test_container_ports_match_table_a():
    for name, port in cs.PORTS.items():
        env = SVCS[name].get("environment", {})
        if "PORT" in env:
            assert env["PORT"] == str(port), name
