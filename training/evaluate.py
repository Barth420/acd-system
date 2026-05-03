"""
training/evaluate.py - Accuracy/F1 evaluation for ACD ML Brain outputs.

Default behavior evaluates a simple rule-based baseline against data/eval.jsonl.
After model inference, pass a predictions JSONL file to evaluate the model:

    python -m training.evaluate --predictions outputs/predictions.jsonl

Prediction lines may be either:
    {"alert_id": "...", "attack_type_confirmed": "sql_injection"}
or:
    {"output": {"alert_id": "...", "attack_type_confirmed": "sql_injection"}}
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from config import EVAL_JSONL_PATH, EVALUATION_CONFIG, OUTPUT_DIR


LABELS = [
    "brute_force",
    "sql_injection",
    "port_scan",
    "xss",
    "unknown",
    "false_positive",
]


def baseline_predict(alert: dict) -> str:
    """Cheap baseline used to prove the eval path and dataset are learnable."""
    features = alert["features"]
    if features["payload_contains_sql_keywords"]:
        return "sql_injection"
    if features["failed_auth_count"] >= 10:
        return "brute_force"
    if (
        features["unique_paths_accessed"] >= 10
        and features["request_rate_per_min"] >= 10
    ):
        return "port_scan"
    return "false_positive"


def load_eval_examples(path: Path) -> list[dict]:
    examples = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "input" not in row or "output" not in row:
                raise ValueError(f"{path}:{line_no} must include input and output.")
            examples.append(row)
    return examples


def load_predictions(path: Path) -> dict[str, str]:
    predictions: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "output" in row:
                output = row["output"]
                alert_id = output.get("alert_id") or row.get("alert_id")
                label = output.get("attack_type_confirmed")
            else:
                alert_id = row.get("alert_id")
                label = row.get("attack_type_confirmed")

            if not alert_id or not label:
                raise ValueError(
                    f"{path}:{line_no} must include alert_id and attack_type_confirmed."
                )
            predictions[alert_id] = label
    return predictions


def macro_f1(y_true: list[str], y_pred: list[str]) -> float:
    scores = []
    for label in sorted(set(y_true) | set(y_pred) | set(LABELS)):
        tp = sum(1 for true, pred in zip(y_true, y_pred) if true == label and pred == label)
        fp = sum(1 for true, pred in zip(y_true, y_pred) if true != label and pred == label)
        fn = sum(1 for true, pred in zip(y_true, y_pred) if true == label and pred != label)
        if tp == 0 and fp == 0 and fn == 0:
            continue
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
    return sum(scores) / len(scores) if scores else 0.0


def confusion_matrix(y_true: list[str], y_pred: list[str]) -> dict[str, dict[str, int]]:
    labels = sorted(set(y_true) | set(y_pred) | set(LABELS))
    matrix = {label: {pred: 0 for pred in labels} for label in labels}
    for true, pred in zip(y_true, y_pred):
        matrix[true][pred] += 1
    return matrix


def evaluate(
    eval_path: Path,
    predictions_path: Path | None = None,
    limit: int | None = None,
) -> dict:
    examples = load_eval_examples(eval_path)
    if limit is not None:
        examples = examples[:limit]
    y_true = [example["output"]["attack_type_confirmed"] for example in examples]

    if predictions_path:
        predictions = load_predictions(predictions_path)
        y_pred = []
        missing = []
        for example in examples:
            alert_id = example["input"]["alert_id"]
            if alert_id not in predictions:
                missing.append(alert_id)
                y_pred.append("unknown")
            else:
                y_pred.append(predictions[alert_id])
        source = str(predictions_path)
    else:
        y_pred = [baseline_predict(example["input"]) for example in examples]
        missing = []
        source = "rule_based_baseline"

    accuracy = sum(1 for true, pred in zip(y_true, y_pred) if true == pred) / len(y_true)
    f1 = macro_f1(y_true, y_pred)
    return {
        "eval_path": str(eval_path),
        "prediction_source": source,
        "sample_count": len(examples),
        "accuracy": round(accuracy, 4),
        "macro_f1": round(f1, 4),
        "target_accuracy": EVALUATION_CONFIG["target_accuracy"],
        "target_macro_f1": EVALUATION_CONFIG["target_macro_f1"],
        "passes_minimum_baseline": (
            accuracy >= EVALUATION_CONFIG["target_accuracy"]
            and f1 >= EVALUATION_CONFIG["target_macro_f1"]
        ),
        "label_counts": dict(sorted(Counter(y_true).items())),
        "prediction_counts": dict(sorted(Counter(y_pred).items())),
        "missing_prediction_count": len(missing),
        "confusion_matrix": confusion_matrix(y_true, y_pred),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ACD ML Brain predictions.")
    parser.add_argument("--eval-path", type=Path, default=EVAL_JSONL_PATH)
    parser.add_argument("--predictions", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--metrics-path",
        type=Path,
        default=OUTPUT_DIR / "evaluation_metrics.json",
    )
    args = parser.parse_args()

    metrics = evaluate(
        eval_path=args.eval_path,
        predictions_path=args.predictions,
        limit=args.limit,
    )
    args.metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(args.metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
