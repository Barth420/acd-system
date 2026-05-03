"""
training/generate_dataset.py - Build Phase 2 JSONL datasets for ACD ML Brain.

Generates Wazuh-style normalized alerts for brute force, SQL injection, and
port scan scenarios, then writes:
    data/train.jsonl  - default 800 examples
    data/eval.jsonl   - default 100 examples

Each JSONL line is exactly:
    {"input": incident_json, "output": reasoning_json}
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import validate

from config import (
    DATASET_CONFIG,
    DATA_DIR,
    EVAL_JSONL_PATH,
    INPUT_SCHEMA_PATH,
    MITRE_MAPPING_PATH,
    MODEL_VERSION,
    OUTPUT_SCHEMA_PATH,
    TRAIN_JSONL_PATH,
)


SERVICES = {
    "brute_force": [("auth_api", 5000), ("nginx", 80)],
    "sql_injection": [("product_api", 5001), ("database", 5432), ("nginx", 80)],
    "port_scan": [("nginx", 80), ("unknown", 22), ("product_api", 5001)],
}

WAZUH_RULES = {
    "brute_force": [
        (5710, "sshd: brute force trying to get access to the system."),
        (5712, "Multiple authentication failures from same source."),
        (5503, "PAM login failures above threshold."),
    ],
    "sql_injection": [
        (31103, "Web attack detected: SQL injection attempt."),
        (31110, "SQL injection pattern in request body."),
        (31151, "Database query anomaly with injection indicators."),
    ],
    "port_scan": [
        (40101, "Web scanner activity detected."),
        (40111, "Network scan detected from external source."),
        (40120, "High-volume service enumeration detected."),
    ],
}

SOURCE_NETS = {
    "internal": ["10.0.0.", "172.16.4.", "192.168.1."],
    "external": ["198.51.100.", "203.0.113.", "45.33.32."],
}

ATTACK_ROTATION = [
    "brute_force",
    "sql_injection",
    "port_scan",
    "brute_force",
    "sql_injection",
    "port_scan",
    "brute_force",
    "sql_injection",
    "port_scan",
]


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_technique_index() -> dict[str, dict]:
    mapping = load_json(MITRE_MAPPING_PATH)
    return {item["technique_id"]: item for item in mapping["techniques"]}


TECHNIQUE_PLANS = {
    "brute_force": [
        ["T1110", "T1110.001"],
        ["T1110.003"],
        ["T1110", "T1078"],
        ["T1110.001", "T1499"],
    ],
    "sql_injection": [
        ["T1190", "T1059"],
        ["T1190", "T1005"],
        ["T1190", "T1041", "T1027"],
        ["T1190", "T1059", "T1005"],
    ],
    "port_scan": [
        ["T1595"],
        ["T1595", "T1595.001"],
        ["T1595", "T1595.002"],
        ["T1595", "T1595.001", "T1595.002", "T1499"],
    ],
}


def make_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def make_ip(rng: random.Random, external: bool) -> str:
    nets = SOURCE_NETS["external" if external else "internal"]
    return f"{rng.choice(nets)}{rng.randint(2, 240)}"


def choose_severity(attack_type: str, plan: list[str], features: dict) -> str:
    if attack_type == "sql_injection":
        if "T1041" in plan or features["geo_anomaly"]:
            return "critical"
        return "high" if features["unique_paths_accessed"] >= 5 else "medium"

    if attack_type == "brute_force":
        if "T1499" in plan or features["failed_auth_count"] >= 250:
            return "critical"
        if features["failed_auth_count"] >= 80 or features["geo_anomaly"]:
            return "high"
        if features["failed_auth_count"] >= 20:
            return "medium"
        return "low"

    if features["request_rate_per_min"] >= 600:
        return "high"
    if features["unique_paths_accessed"] >= 80 or features["geo_anomaly"]:
        return "medium"
    return "low"


def build_features(attack_type: str, plan: list[str], rng: random.Random) -> dict:
    if attack_type == "brute_force":
        if "T1110.003" in plan:
            failed_auth = rng.randint(18, 75)
            rate = round(rng.uniform(1.1, 7.5), 1)
        elif "T1499" in plan:
            failed_auth = rng.randint(280, 900)
            rate = round(rng.uniform(450.0, 920.0), 1)
        else:
            failed_auth = rng.randint(60, 360)
            rate = round(rng.uniform(25.0, 160.0), 1)

        return {
            "request_rate_per_min": rate,
            "unique_paths_accessed": rng.choice([1, 1, 2, 3]),
            "failed_auth_count": failed_auth,
            "payload_contains_sql_keywords": False,
            "user_agent_anomaly": rng.random() < 0.62,
            "geo_anomaly": rng.random() < 0.45 or "T1078" in plan,
        }

    if attack_type == "sql_injection":
        if "T1041" in plan:
            rate = round(rng.uniform(0.3, 4.5), 1)
            paths = rng.randint(1, 5)
        elif "T1059" in plan and "T1005" in plan:
            rate = round(rng.uniform(8.0, 40.0), 1)
            paths = rng.randint(6, 18)
        else:
            rate = round(rng.uniform(1.5, 18.0), 1)
            paths = rng.randint(2, 10)

        return {
            "request_rate_per_min": rate,
            "unique_paths_accessed": paths,
            "failed_auth_count": 0,
            "payload_contains_sql_keywords": True,
            "user_agent_anomaly": rng.random() < 0.48 or "T1027" in plan,
            "geo_anomaly": rng.random() < 0.38 or "T1041" in plan,
        }

    if "T1499" in plan:
        rate = round(rng.uniform(620.0, 1150.0), 1)
        paths = rng.randint(260, 700)
    elif "T1595.002" in plan:
        rate = round(rng.uniform(80.0, 320.0), 1)
        paths = rng.randint(60, 240)
    else:
        rate = round(rng.uniform(18.0, 180.0), 1)
        paths = rng.randint(20, 160)

    return {
        "request_rate_per_min": rate,
        "unique_paths_accessed": paths,
        "failed_auth_count": 0,
        "payload_contains_sql_keywords": False,
        "user_agent_anomaly": rng.random() < 0.76,
        "geo_anomaly": rng.random() < 0.72,
    }


def maybe_false_positive(
    attack_type: str,
    index: int,
    alert_id: str,
    processed_at: str,
    features: dict,
    service: str,
) -> dict | None:
    if index % 19 != 0:
        return None

    if attack_type == "brute_force":
        features.update(
            {
                "request_rate_per_min": 0.4,
                "failed_auth_count": 4,
                "user_agent_anomaly": False,
                "geo_anomaly": False,
            }
        )
        return build_output(
            alert_id=alert_id,
            processed_at=processed_at,
            attack_type_confirmed="false_positive",
            plan=["T1110"],
            confidence=0.66,
            severity="low",
            action="alert_only",
            affected_services=[service],
            propagation_risk="none",
            reasoning=(
                "The alert has only 4 failed authentication attempts at 0.4 "
                "requests per minute, with no user-agent or geo anomaly. Those "
                "features are consistent with normal user error rather than an "
                "automated credential attack, so the model should keep the case "
                "visible but avoid disruptive containment."
            ),
            justification=(
                "The evidence is below the brute force threshold. Alert-only "
                "preserves audit visibility without blocking legitimate access."
            ),
        )

    if attack_type == "port_scan":
        features.update(
            {
                "request_rate_per_min": 3.2,
                "unique_paths_accessed": 5,
                "user_agent_anomaly": False,
                "geo_anomaly": False,
            }
        )
        return build_output(
            alert_id=alert_id,
            processed_at=processed_at,
            attack_type_confirmed="false_positive",
            plan=["T1595"],
            confidence=0.62,
            severity="low",
            action="alert_only",
            affected_services=[service],
            propagation_risk="none",
            reasoning=(
                "Only 5 paths were accessed at 3.2 requests per minute from a "
                "non-anomalous source with a normal user-agent. This does not "
                "show the breadth, rate, or scanner signature expected from "
                "active reconnaissance, so it is best treated as benign browsing "
                "or a low-signal Wazuh rule match."
            ),
            justification=(
                "No containment is justified because the scan evidence is weak. "
                "Keeping an alert record is enough for later correlation."
            ),
        )

    return None


def technique_objects(plan: list[str]) -> list[dict]:
    index = load_technique_index()
    return [
        {
            "technique_id": technique_id,
            "technique_name": index[technique_id]["technique_name"],
            "tactic": index[technique_id]["tactic"],
        }
        for technique_id in plan
    ]


def build_reasoning(attack_type: str, plan: list[str], alert: dict) -> str:
    features = alert["features"]
    if attack_type == "brute_force":
        subtype = "password spraying" if "T1110.003" in plan else "password guessing"
        extra = (
            " The very high request rate also creates endpoint denial-of-service risk."
            if "T1499" in plan
            else ""
        )
        return (
            f"The alert shows {features['failed_auth_count']} failed authentication "
            f"attempts against {alert['service']} at "
            f"{features['request_rate_per_min']} requests per minute. The activity "
            f"is concentrated on {features['unique_paths_accessed']} path(s), which "
            f"is consistent with {subtype} rather than broad web scanning. "
            f"payload_contains_sql_keywords is false, so SQL injection is not the "
            f"primary explanation. user_agent_anomaly={features['user_agent_anomaly']} "
            f"and geo_anomaly={features['geo_anomaly']} increase confidence that the "
            f"source is automated or compromised.{extra}"
        )

    if attack_type == "sql_injection":
        exfil = (
            " The low-and-slow pattern plus geo anomaly raises exfiltration concern."
            if "T1041" in plan
            else ""
        )
        return (
            f"The alert contains confirmed SQL keywords in request payloads against "
            f"{alert['service']} with {features['unique_paths_accessed']} affected "
            f"path(s) and {features['request_rate_per_min']} requests per minute. "
            f"There are no failed authentication attempts, so the evidence points "
            f"to exploitation of an application or database path rather than a "
            f"login attack. user_agent_anomaly={features['user_agent_anomaly']} "
            f"and geo_anomaly={features['geo_anomaly']} support malicious intent. "
            f"The database is at risk because the payload pattern maps to public "
            f"application exploitation, command execution, local data collection, "
            f"or obfuscated injection depending on the observed technique set.{exfil}"
        )

    dos = (
        " The request volume is high enough to create an endpoint denial-of-service risk."
        if "T1499" in plan
        else ""
    )
    return (
        f"The alert shows reconnaissance behavior against {alert['service']}: "
        f"{alert['raw_event_count']} events, {features['unique_paths_accessed']} "
        f"unique paths, and {features['request_rate_per_min']} requests per minute. "
        f"failed_auth_count is 0 and payload_contains_sql_keywords is false, so the "
        f"activity is not credential access or SQL injection. "
        f"user_agent_anomaly={features['user_agent_anomaly']} and "
        f"geo_anomaly={features['geo_anomaly']} are consistent with automated "
        f"scanner traffic and vulnerability enumeration.{dos}"
    )


def choose_action(attack_type: str, severity: str, plan: list[str], features: dict) -> str:
    if attack_type == "sql_injection":
        if severity == "critical" or "T1041" in plan:
            return "isolate_service"
        return "escalate_to_human" if features["geo_anomaly"] else "patch_and_restart"

    if attack_type == "brute_force":
        if "T1499" in plan or features["failed_auth_count"] >= 120:
            return "block_ip"
        if "T1110.003" in plan:
            return "force_reauthentication"
        return "rate_limit_ip"

    if "T1499" in plan or features["request_rate_per_min"] >= 600:
        return "block_ip"
    return "rate_limit_ip"


def affected_services_for(attack_type: str, service: str, severity: str) -> list[str]:
    if attack_type == "sql_injection":
        affected = [service]
        if "database" not in affected:
            affected.append("database")
        return affected
    if attack_type == "brute_force":
        return ["auth_api"] if service != "nginx" else ["nginx", "auth_api"]
    return [service]


def propagation_risk_for(attack_type: str, severity: str, plan: list[str]) -> str:
    if severity == "critical":
        return "high"
    if attack_type == "sql_injection":
        return "high" if "T1005" in plan or "T1041" in plan else "medium"
    if attack_type == "brute_force":
        return "high" if "T1078" in plan else "medium"
    return "medium" if "T1595.002" in plan or "T1499" in plan else "low"


def confidence_for(severity: str, features: dict) -> float:
    base = {"low": 0.68, "medium": 0.82, "high": 0.9, "critical": 0.96}[severity]
    if features["user_agent_anomaly"]:
        base += 0.02
    if features["geo_anomaly"]:
        base += 0.02
    return round(min(base, 0.99), 2)


def build_output(
    alert_id: str,
    processed_at: str,
    attack_type_confirmed: str,
    plan: list[str],
    confidence: float,
    severity: str,
    action: str,
    affected_services: list[str],
    propagation_risk: str,
    reasoning: str,
    justification: str,
) -> dict:
    return {
        "alert_id": alert_id,
        "processed_at": processed_at,
        "model_version": MODEL_VERSION,
        "attack_type_confirmed": attack_type_confirmed,
        "mitre_techniques": technique_objects(plan),
        "confidence": confidence,
        "severity_assessment": severity,
        "reasoning": reasoning,
        "recommended_action": action,
        "justification": justification,
        "affected_services": affected_services,
        "propagation_risk": propagation_risk,
    }


def generate_sample(index: int, rng: random.Random) -> dict:
    attack_type = ATTACK_ROTATION[index % len(ATTACK_ROTATION)]
    plan_options = TECHNIQUE_PLANS[attack_type]
    plan = plan_options[index % len(plan_options)]
    service, port = rng.choice(SERVICES[attack_type])
    external = rng.random() < 0.68
    timestamp = datetime(2024, 11, 15, tzinfo=timezone.utc) + timedelta(
        minutes=index * 7 + rng.randint(0, 5)
    )
    processed_at = timestamp + timedelta(seconds=rng.randint(1, 4))
    features = build_features(attack_type, plan, rng)
    severity = choose_severity(attack_type, plan, features)
    alert_id = make_uuid(rng)
    rule_id, rule_desc = rng.choice(WAZUH_RULES[attack_type])

    alert = {
        "alert_id": alert_id,
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": make_ip(rng, external=external),
        "destination_ip": f"10.0.0.{rng.randint(1, 12)}",
        "destination_port": port,
        "service": service,
        "attack_type": attack_type,
        "severity": severity,
        "raw_event_count": max(
            1,
            int(
                features["request_rate_per_min"] * rng.uniform(3.0, 8.0)
                + features["failed_auth_count"]
            ),
        ),
        "features": features,
        "wazuh_rule_id": rule_id,
        "wazuh_rule_description": rule_desc,
    }

    false_positive = maybe_false_positive(
        attack_type=attack_type,
        index=index,
        alert_id=alert_id,
        processed_at=processed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        features=features,
        service=service,
    )

    if false_positive:
        alert["severity"] = "low"
        alert["raw_event_count"] = max(
            1,
            int(
                alert["features"]["request_rate_per_min"] * 4
                + alert["features"]["failed_auth_count"]
                + alert["features"]["unique_paths_accessed"]
            ),
        )
        output = false_positive
    else:
        action = choose_action(attack_type, severity, plan, features)
        affected_services = affected_services_for(attack_type, service, severity)
        propagation_risk = propagation_risk_for(attack_type, severity, plan)
        confidence = confidence_for(severity, features)
        reasoning = build_reasoning(attack_type, plan, alert)
        justification = (
            f"{action} is appropriate because the alert has {severity} severity, "
            f"clear {attack_type} indicators, and propagation risk is "
            f"{propagation_risk}. The action limits attacker progress while "
            f"preserving enough context for analyst review."
        )

        output = build_output(
            alert_id=alert_id,
            processed_at=processed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            attack_type_confirmed=attack_type,
            plan=plan,
            confidence=confidence,
            severity=severity,
            action=action,
            affected_services=affected_services,
            propagation_risk=propagation_risk,
            reasoning=reasoning,
            justification=justification,
        )

    return {"input": alert, "output": output}


def write_jsonl(path: Path, samples: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for sample in samples:
            f.write(json.dumps(sample, separators=(",", ":")) + "\n")


def validate_samples(samples: list[dict]) -> None:
    input_schema = load_json(INPUT_SCHEMA_PATH)
    output_schema = load_json(OUTPUT_SCHEMA_PATH)
    for sample in samples:
        validate(instance=sample["input"], schema=input_schema)
        validate(instance=sample["output"], schema=output_schema)


def summarize(samples: list[dict]) -> dict:
    labels = Counter(sample["output"]["attack_type_confirmed"] for sample in samples)
    techniques = Counter(
        technique["technique_id"]
        for sample in samples
        for technique in sample["output"]["mitre_techniques"]
    )
    return {
        "sample_count": len(samples),
        "labels": dict(sorted(labels.items())),
        "mitre_techniques": dict(sorted(techniques.items())),
    }


def generate_dataset(train_count: int, eval_count: int, seed: int) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    samples = [generate_sample(index, rng) for index in range(train_count + eval_count)]
    return samples[:train_count], samples[train_count:]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ACD Phase 2 JSONL datasets.")
    parser.add_argument("--train-count", type=int, default=DATASET_CONFIG["train_jsonl_count"])
    parser.add_argument("--eval-count", type=int, default=DATASET_CONFIG["eval_jsonl_count"])
    parser.add_argument("--seed", type=int, default=DATASET_CONFIG["seed"])
    parser.add_argument("--train-path", type=Path, default=TRAIN_JSONL_PATH)
    parser.add_argument("--eval-path", type=Path, default=EVAL_JSONL_PATH)
    parser.add_argument(
        "--summary-path",
        type=Path,
        default=DATA_DIR / "dataset_summary.json",
        help="Where to write dataset label and MITRE coverage counts.",
    )
    args = parser.parse_args()

    train_samples, eval_samples = generate_dataset(
        train_count=args.train_count,
        eval_count=args.eval_count,
        seed=args.seed,
    )
    all_samples = train_samples + eval_samples
    validate_samples(all_samples)

    write_jsonl(args.train_path, train_samples)
    write_jsonl(args.eval_path, eval_samples)

    summary = {
        "train": summarize(train_samples),
        "eval": summarize(eval_samples),
        "combined": summarize(all_samples),
    }
    args.summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(args.summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
