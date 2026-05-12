"""
tests/test_pipeline.py — End-to-end pipeline tests.

This is the Month 1 milestone test:
  POST any raw alert → system normalizes, enriches with context,
  runs graph analysis, stores enriched incident. Zero schema errors.

Run:
  cd bhavya
  python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Sample raw Wazuh alerts — match what Vitrag's forwarder will produce
# ──────────────────────────────────────────────────────────────────────────────

SAMPLE_BRUTE_FORCE = {
    "source": "wazuh",
    "timestamp": "2024-11-15T08:23:11Z",
    "raw_data": {
        "rule": {
            "id": 5712,
            "level": 10,
            "description": "sshd: Multiple authentication failures.",
        },
        "data": {
            "srcip": "203.0.113.42",
            "dstip": "10.0.0.5",
            "dstport": 5000,
            "event_count": 412,
            "failed_attempts": 408,
            "user_agent": "curl/7.81.0",
            "url": "/auth/login",
        },
        "timestamp": "2024-11-15T08:23:11Z",
    },
}

SAMPLE_SQLI = {
    "source": "wazuh",
    "timestamp": "2024-11-15T09:14:22Z",
    "raw_data": {
        "rule": {
            "id": 31103,
            "level": 11,
            "description": "Web attack: SQL injection attempt.",
        },
        "data": {
            "srcip": "198.51.100.7",
            "dstip": "10.0.0.5",
            "dstport": 5001,
            "event_count": 5,
            "url": "/api/products?id=1' OR 1=1--",
            "user_agent": "sqlmap/1.7",
        },
        "timestamp": "2024-11-15T09:14:22Z",
    },
}

SAMPLE_PORT_SCAN = {
    "source": "wazuh",
    "timestamp": "2024-11-15T10:01:05Z",
    "raw_data": {
        "rule": {
            "id": 40101,
            "level": 8,
            "description": "Port scan detected (nmap signature).",
        },
        "data": {
            "srcip": "192.0.2.99",
            "dstip": "10.0.0.5",
            "dstport": 22,
            "event_count": 1024,
            "unique_paths": 0,
        },
        "timestamp": "2024-11-15T10:01:05Z",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_services_endpoint_lists_all_four(client):
    r = client.get("/services")
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["services"]]
    assert {"auth_api", "product_api", "database", "nginx"} <= set(names)


def test_graph_has_correct_structure(client):
    r = client.get("/graph")
    assert r.status_code == 200
    data = r.json()
    # auth_api depends on database (so blast_radius of database includes auth_api)
    assert "auth_api" in data["blast_radius"]["database"]
    # product_api also depends on database
    assert "product_api" in data["blast_radius"]["database"]
    # nginx is at the top of the chain
    assert data["depths"]["nginx"] >= 1


def test_brute_force_alert_full_pipeline(client):
    r = client.post("/alerts", json=SAMPLE_BRUTE_FORCE)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["attack_type"] == "brute_force"
    assert body["service"] == "auth_api"
    assert body["sensitivity"] == "critical"
    assert body["exposure"] == "external"
    # auth_api's compromise affects nginx + product_api (downstream)
    assert "nginx" in body["blast_radius"]


def test_sqli_alert_full_pipeline(client):
    r = client.post("/alerts", json=SAMPLE_SQLI)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["attack_type"] == "sql_injection"
    assert body["service"] == "product_api"
    assert body["severity"] == "high"  # rule level 11


def test_port_scan_alert_full_pipeline(client):
    r = client.post("/alerts", json=SAMPLE_PORT_SCAN)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["attack_type"] == "port_scan"


def test_incidents_persisted(client):
    # Submit one and confirm it shows up in /incidents
    r = client.post("/alerts", json=SAMPLE_BRUTE_FORCE)
    assert r.status_code == 201
    incident_id = r.json()["incident_id"]

    r2 = client.get("/incidents")
    assert r2.status_code == 200
    ids = [i["incident_id"] for i in r2.json()["items"]]
    assert incident_id in ids

    r3 = client.get(f"/incidents/{incident_id}")
    assert r3.status_code == 200
    full = r3.json()
    # Verify nested structure conforms to schemas
    assert "normalized_alert" in full
    assert "service_context" in full
    assert "dependency_depth" in full
    na = full["normalized_alert"]
    # All required fields from Parth's input_schema.json present
    for required in [
        "alert_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "service",
        "attack_type",
        "severity",
        "raw_event_count",
        "features",
    ]:
        assert required in na, f"missing required field: {required}"
    # Features structure
    for f in [
        "request_rate_per_min",
        "unique_paths_accessed",
        "failed_auth_count",
        "payload_contains_sql_keywords",
        "user_agent_anomaly",
        "geo_anomaly",
    ]:
        assert f in na["features"], f"missing feature: {f}"


def test_malformed_alert_rejected(client):
    bad = {
        "source": "wazuh",
        "timestamp": "2024-11-15T08:23:11Z",
        "raw_data": {
            # No rule, no srcip — should fail to normalize
            "data": {"foo": "bar"},
        },
    }
    r = client.post("/alerts", json=bad)
    assert r.status_code == 422


def test_invalid_payload_shape_rejected(client):
    # Missing required field 'raw_data'
    r = client.post("/alerts", json={"source": "wazuh", "timestamp": "2024-11-15T08:23:11Z"})
    assert r.status_code == 422


def test_normalized_alert_matches_parth_schema():
    """
    Critical contract test: every field name in our NormalizedAlert
    must exactly match Parth's input_schema.json.
    """
    from pipeline.schemas import NormalizedAlert, NormalizedFeatures

    expected_top_level = {
        "alert_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "service",
        "attack_type",
        "severity",
        "raw_event_count",
        "features",
        "wazuh_rule_id",
        "wazuh_rule_description",
    }
    actual = set(NormalizedAlert.model_fields.keys())
    assert actual == expected_top_level, (
        f"Schema drift! Missing: {expected_top_level - actual}, "
        f"Extra: {actual - expected_top_level}"
    )

    expected_features = {
        "request_rate_per_min",
        "unique_paths_accessed",
        "failed_auth_count",
        "payload_contains_sql_keywords",
        "user_agent_anomaly",
        "geo_anomaly",
    }
    actual_features = set(NormalizedFeatures.model_fields.keys())
    assert actual_features == expected_features
