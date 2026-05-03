"""
training/predict_eval.py - Generate eval predictions with the trained LoRA adapter.

This is a Phase 2 ML-only evaluation utility. It loads the quantized base model,
attaches the trained adapter from checkpoints/acd-brain-final, runs generation
for data/eval.jsonl, and writes outputs/predictions.jsonl.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import torch
from peft import PeftModel

from config import BASE_MODEL_ID, EVAL_JSONL_PATH, FINE_TUNED_MODEL_DIR, OUTPUT_DIR
from inference.prompt_builder import build_inference_prompt, extract_json_from_response
from training.dataset_loader import load_jsonl_examples
from training.train import load_quantized_model_and_tokenizer
from utils.validator import validate_output

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def load_adapter_model(adapter_dir: str | Path = FINE_TUNED_MODEL_DIR):
    """Load the base model plus trained LoRA adapter for evaluation."""
    model, tokenizer = load_quantized_model_and_tokenizer(model_id=BASE_MODEL_ID)
    logger.info("Loading LoRA adapter from: %s", adapter_dir)
    model = PeftModel.from_pretrained(model, adapter_dir)
    model.config.use_cache = False
    if hasattr(model, "base_model") and hasattr(model.base_model, "config"):
        model.base_model.config.use_cache = False
    model.eval()
    return model, tokenizer


def generate_prediction(model, tokenizer, alert: dict, max_new_tokens: int) -> dict:
    """Generate and parse one MLReasoningResult prediction."""
    prompt = build_inference_prompt(alert)
    device = next(model.parameters()).device
    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.inference_mode():
        generated = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            use_cache=False,
            repetition_penalty=1.12,
            no_repeat_ngram_size=8,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    completion_ids = generated[0][inputs["input_ids"].shape[1] :]
    raw_response = tokenizer.decode(completion_ids, skip_special_tokens=False)
    json_text = extract_json_from_response(raw_response)
    prediction = json.loads(json_text)

    valid, error = validate_output(prediction)
    if not valid:
        raise ValueError(f"Invalid model output for {alert['alert_id']}: {error}")
    return prediction


def predict_eval(
    eval_path: Path,
    predictions_path: Path,
    max_new_tokens: int,
    limit: int | None = None,
) -> None:
    examples = load_jsonl_examples(eval_path)
    if limit is not None:
        examples = examples[:limit]

    model, tokenizer = load_adapter_model()
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    if predictions_path.exists():
        predictions_path.unlink()

    with open(predictions_path, "w", encoding="utf-8", newline="\n") as f:
        for index, example in enumerate(examples, start=1):
            alert = example["input"]
            logger.info(
                "Predicting %s/%s alert_id=%s",
                index,
                len(examples),
                alert["alert_id"],
            )
            try:
                output = generate_prediction(
                    model=model,
                    tokenizer=tokenizer,
                    alert=alert,
                    max_new_tokens=max_new_tokens,
                )
                row = {"alert_id": alert["alert_id"], "output": output}
            except Exception as exc:
                logger.exception("Prediction failed for alert_id=%s", alert["alert_id"])
                row = {
                    "alert_id": alert["alert_id"],
                    "attack_type_confirmed": "unknown",
                    "error": str(exc),
                }
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    logger.info("Predictions written to: %s", predictions_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate eval predictions.")
    parser.add_argument("--eval-path", type=Path, default=EVAL_JSONL_PATH)
    parser.add_argument(
        "--predictions-path",
        type=Path,
        default=OUTPUT_DIR / "predictions.jsonl",
    )
    parser.add_argument("--max-new-tokens", type=int, default=384)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional smoke-test limit before running the full eval set.",
    )
    args = parser.parse_args()

    predict_eval(
        eval_path=args.eval_path,
        predictions_path=args.predictions_path,
        max_new_tokens=args.max_new_tokens,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
