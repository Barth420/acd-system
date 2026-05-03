"""
training/dataset_loader.py - Loads JSONL training/eval examples for QLoRA.

The Phase 2 dataset format is one JSON object per line:
    {"input": {...normalized alert...}, "output": {...MLReasoningResult...}}

The loader keeps backward compatibility with data/training_examples.json while
preferring data/train.jsonl and data/eval.jsonl when they are present.
"""

import json
import logging
from pathlib import Path

from datasets import Dataset
from sklearn.model_selection import train_test_split

from config import (
    DATASET_CONFIG,
    EVAL_JSONL_PATH,
    SYSTEM_PROMPT,
    TRAINING_DATA_PATH,
    TRAIN_JSONL_PATH,
)

logger = logging.getLogger(__name__)


def _format_user_message(alert: dict) -> str:
    """Format the input alert as the user-facing prompt."""
    return (
        "Analyze the following normalized security alert and respond with a valid "
        "MLReasoningResult JSON object:\n\n"
        f"```json\n{json.dumps(alert, indent=2)}\n```"
    )


def _format_phi3_chat(system: str, user: str, assistant: str) -> str:
    """
    Format a single training example using Phi-3-mini instruct chat template.
    The model learns to complete the assistant turn.
    """
    return (
        f"<|system|>\n{system}<|end|>\n"
        f"<|user|>\n{user}<|end|>\n"
        f"<|assistant|>\n{assistant}<|end|>"
    )


def _format_phi3_prompt(system: str, user: str) -> str:
    """Format the non-trainable prompt prefix before the assistant JSON."""
    return (
        f"<|system|>\n{system}<|end|>\n"
        f"<|user|>\n{user}<|end|>\n"
        f"<|assistant|>\n"
    )


def load_jsonl_examples(path: Path | str) -> list[dict]:
    """Load Phase 2 JSONL examples from disk."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"JSONL dataset not found: {path}")

    examples: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            sample = json.loads(line)
            if "input" not in sample or "output" not in sample:
                raise ValueError(
                    f"{path}:{line_no} must contain only an input/output pair."
                )

            examples.append(
                {
                    "id": sample.get("id", f"{path.stem}_{line_no:04d}"),
                    "input": sample["input"],
                    "output": sample["output"],
                }
            )

    logger.info("Loaded %s JSONL examples from %s.", len(examples), path)
    return examples


def load_legacy_examples(path: Path | str = TRAINING_DATA_PATH) -> list[dict]:
    """Load legacy examples from data/training_examples.json."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Training data not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    examples = data.get("examples", [])
    logger.info("Loaded %s legacy JSON examples from %s.", len(examples), path)
    return examples


def load_raw_examples(path: Path | str = TRAINING_DATA_PATH) -> list[dict]:
    """Load examples from either JSONL or the legacy JSON wrapper format."""
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        return load_jsonl_examples(path)
    return load_legacy_examples(path)


def format_examples_for_training(examples: list[dict]) -> list[dict]:
    """
    Convert raw input/output pairs into Phi-3 chat format.

    Returns:
        - id: source example ID for traceability
        - text: full prompt plus completion string for SFTTrainer
        - label: attack_type_confirmed for audits/eval splits
    """
    formatted = []
    for ex in examples:
        alert_input = ex["input"]
        ml_output = ex["output"]
        example_id = ex.get("id", "unknown")

        user_msg = _format_user_message(alert_input)
        assistant_msg = json.dumps(ml_output, separators=(",", ":"))
        prompt_text = _format_phi3_prompt(system=SYSTEM_PROMPT, user=user_msg)
        completion_text = f"{assistant_msg}<|end|>"
        text = f"{prompt_text}{completion_text}"

        formatted.append(
            {
                "id": example_id,
                "text": text,
                "prompt_text": prompt_text,
                "completion_text": completion_text,
                "label": ml_output.get("attack_type_confirmed", "unknown"),
            }
        )

    logger.info("Formatted %s examples for fine-tuning.", len(formatted))
    return formatted


def build_hf_datasets(
    formatted_train_examples: list[dict],
    formatted_eval_examples: list[dict] | None = None,
    validation_split: float = DATASET_CONFIG["validation_split"],
    seed: int = DATASET_CONFIG["seed"],
) -> tuple[Dataset, Dataset]:
    """
    Build HuggingFace train/eval datasets.

    If an explicit eval JSONL is provided, no random split is performed.
    Otherwise the training examples are split with a deterministic seed.
    """
    if formatted_eval_examples is not None:
        if not formatted_train_examples or not formatted_eval_examples:
            raise ValueError("Train and eval datasets must both contain examples.")
        train_dataset = Dataset.from_list(formatted_train_examples)
        eval_dataset = Dataset.from_list(formatted_eval_examples)
        logger.info(
            "Dataset loaded: %s train / %s eval.",
            len(train_dataset),
            len(eval_dataset),
        )
        return train_dataset, eval_dataset

    if len(formatted_train_examples) < 4:
        raise ValueError(
            f"Need at least 4 examples for a train/eval split, "
            f"got {len(formatted_train_examples)}."
        )

    labels = [example["label"] for example in formatted_train_examples]
    train_raw, eval_raw = train_test_split(
        formatted_train_examples,
        test_size=validation_split,
        random_state=seed,
        stratify=labels if len(set(labels)) > 1 else None,
    )

    train_dataset = Dataset.from_list(train_raw)
    eval_dataset = Dataset.from_list(eval_raw)
    logger.info(
        "Dataset split: %s train / %s eval.",
        len(train_dataset),
        len(eval_dataset),
    )
    return train_dataset, eval_dataset


def get_datasets(
    train_path: Path | str = TRAIN_JSONL_PATH,
    eval_path: Path | str | None = EVAL_JSONL_PATH,
) -> tuple[Dataset, Dataset]:
    """
    Load, format, and return train/eval datasets.

    By default this uses data/train.jsonl and data/eval.jsonl. If they do not
    exist yet, it falls back to data/training_examples.json and creates a split.
    """
    train_path = Path(train_path)
    eval_path = Path(eval_path) if eval_path else None

    if train_path.exists() and eval_path and eval_path.exists():
        train_examples = load_jsonl_examples(train_path)
        eval_examples = load_jsonl_examples(eval_path)
        return build_hf_datasets(
            format_examples_for_training(train_examples),
            format_examples_for_training(eval_examples),
        )

    if train_path.exists():
        examples = load_raw_examples(train_path)
    else:
        logger.warning(
            "Phase 2 JSONL dataset not found at %s. Falling back to %s.",
            train_path,
            TRAINING_DATA_PATH,
        )
        examples = load_legacy_examples(TRAINING_DATA_PATH)

    return build_hf_datasets(format_examples_for_training(examples))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_ds, eval_ds = get_datasets()
    print(f"\nTrain samples: {len(train_ds)}")
    print(f"Eval samples: {len(eval_ds)}")
    print(f"\nSample training text (first 500 chars):\n{train_ds[0]['text'][:500]}")
