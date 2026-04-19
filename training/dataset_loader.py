"""
training/dataset_loader.py — Loads and formats training examples for QLoRA fine-tuning.

Converts raw input/output JSON pairs from training_examples.json into
instruction-following (chat) format expected by Phi-3-mini-instruct.

Output format for Phi-3:
    <|system|>
    {system_prompt}<|end|>
    <|user|>
    {user_message}<|end|>
    <|assistant|>
    {assistant_response}<|end|>
"""

import json
import logging
from pathlib import Path
from typing import Any

from datasets import Dataset
from sklearn.model_selection import train_test_split

from config import TRAINING_DATA_PATH, SYSTEM_PROMPT, DATASET_CONFIG

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
    The model learns to complete the <|assistant|> turn.
    """
    return (
        f"<|system|>\n{system}<|end|>\n"
        f"<|user|>\n{user}<|end|>\n"
        f"<|assistant|>\n{assistant}<|end|>"
    )


def load_raw_examples(path: Path = TRAINING_DATA_PATH) -> list[dict]:
    """Load raw training examples from JSON file."""
    if not path.exists():
        raise FileNotFoundError(f"Training data not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    examples = data.get("examples", [])
    logger.info(f"Loaded {len(examples)} raw training examples.")
    return examples


def format_examples_for_training(examples: list[dict]) -> list[dict]:
    """
    Convert raw input/output pairs into Phi-3 chat format.

    Returns a list of dicts with:
        - "text": the full formatted prompt+completion string (for SFTTrainer)
        - "id": original training example ID (for traceability)
    """
    formatted = []
    for ex in examples:
        alert_input = ex["input"]
        ml_output = ex["output"]
        example_id = ex.get("id", "unknown")

        user_msg = _format_user_message(alert_input)
        # The assistant response is the raw JSON string (not indented to save tokens)
        assistant_msg = json.dumps(ml_output, separators=(",", ":"))

        text = _format_phi3_chat(
            system=SYSTEM_PROMPT,
            user=user_msg,
            assistant=assistant_msg,
        )
        formatted.append({"id": example_id, "text": text})

    logger.info(f"Formatted {len(formatted)} examples for fine-tuning.")
    return formatted


def build_hf_datasets(
    formatted_examples: list[dict],
    validation_split: float = DATASET_CONFIG["validation_split"],
    seed: int = DATASET_CONFIG["seed"],
) -> tuple[Dataset, Dataset]:
    """
    Split formatted examples into train/validation HuggingFace Datasets.

    Returns:
        (train_dataset, val_dataset)
    """
    if len(formatted_examples) < 4:
        raise ValueError(
            f"Need at least 4 examples for a train/val split, got {len(formatted_examples)}. "
            "Add more examples to training_examples.json."
        )

    train_raw, val_raw = train_test_split(
        formatted_examples,
        test_size=validation_split,
        random_state=seed,
    )

    train_dataset = Dataset.from_list(train_raw)
    val_dataset = Dataset.from_list(val_raw)

    logger.info(
        f"Dataset split: {len(train_dataset)} train / {len(val_dataset)} validation."
    )
    return train_dataset, val_dataset


def get_datasets() -> tuple[Dataset, Dataset]:
    """
    Top-level convenience function: load, format, and split in one call.

    Usage:
        from training.dataset_loader import get_datasets
        train_ds, val_ds = get_datasets()
    """
    raw = load_raw_examples()
    formatted = format_examples_for_training(raw)
    return build_hf_datasets(formatted)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_ds, val_ds = get_datasets()
    print(f"\nTrain samples: {len(train_ds)}")
    print(f"Val samples: {len(val_ds)}")
    print(f"\nSample training text (first 500 chars):\n{train_ds[0]['text'][:500]}")
