"""
capabilities.py — contract B: modes/capabilities, and attack_type -> required capability (for the rationale text
shown in the UI; the controller enforces the actual blocking, this module only explains WHY a mode was chosen).
"""

from __future__ import annotations

MODES = ["normal", "rate_limited", "read_only", "fallback", "isolated"]

# attack_type -> capabilities it exercises (contract B: bulk_requests, state_write, dynamic_query,
# dependency_calls, data_egress)
REQUIRED_CAPS: dict[str, list[str]] = {
    "brute_force": ["state_write", "bulk_requests"],
    "sql_injection": ["dynamic_query"],
    "port_scan": ["bulk_requests"],
    "xss": ["dynamic_query"],
    "credential_abuse": ["dependency_calls"],
    "lateral_movement": ["dependency_calls"],
    "data_exfiltration": ["dynamic_query", "data_egress"],
    "unknown": [],
}


def required_caps(attack_type: str) -> list[str]:
    return list(REQUIRED_CAPS.get(attack_type, []))
