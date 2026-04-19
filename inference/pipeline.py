"""
inference/pipeline.py — Core inference pipeline for the ACD ML Brain.

Takes a normalized alert JSON, runs it through the fine-tuned model,
and returns a validated MLReasoningResult JSON.

Designed to be called:
  1. Directly as a Python module (from tests, CLI, etc.)
  2. Via a FastAPI endpoint (Bhavya's integration layer)

Usage:
    from inference.pipeline import ACDBrainPipeline

    pipeline = ACDBrainPipeline()
    result = pipeline.analyze(alert_dict)
"""

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline as hf_pipeline

from config import (
    BASE_MODEL_ID,
    FINE_TUNED_MODEL_DIR,
    INFERENCE_CONFIG,
    MODEL_VERSION,
)
from inference.prompt_builder import build_inference_prompt, extract_json_from_response
from utils.validator import validate_input_strict, validate_output_strict, sanitize_alert

logger = logging.getLogger(__name__)


class ACDBrainPipeline:
    """
    Singleton-safe inference pipeline for the ACD ML Brain.

    Load once, call .analyze() many times. Thread-safe for single-GPU usage.

    Args:
        model_dir: Path to fine-tuned LoRA adapter or merged model directory.
                   Defaults to config.FINE_TUNED_MODEL_DIR.
                   Falls back to BASE_MODEL_ID if fine-tuned model is not found.
        use_base_model: Force using the base model even if fine-tuned exists.
                        Useful for debugging or initial demo.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,
        use_base_model: bool = False,
    ):
        self._model = None
        self._tokenizer = None
        self._pipe = None
        self._model_id: str = ""

        effective_dir = model_dir or FINE_TUNED_MODEL_DIR

        if use_base_model or not Path(effective_dir).exists():
            if not use_base_model:
                logger.warning(
                    f"Fine-tuned model not found at '{effective_dir}'. "
                    f"Falling back to base model '{BASE_MODEL_ID}'. "
                    "Run training/train.py first to produce a fine-tuned model."
                )
            self._model_id = BASE_MODEL_ID
        else:
            self._model_id = effective_dir
            logger.info(f"Using fine-tuned model from: {effective_dir}")

        self._load()

    def _load(self):
        """Load model and tokenizer into memory."""
        logger.info(f"Loading model: {self._model_id}")
        start = time.perf_counter()

        # Determine compute dtype based on GPU availability
        dtype = torch.bfloat16 if torch.cuda.is_available() else torch.float32
        device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Device: {device} | Dtype: {dtype}")

        self._tokenizer = AutoTokenizer.from_pretrained(
            self._model_id,
            trust_remote_code=True,
        )
        self._tokenizer.pad_token = self._tokenizer.eos_token

        self._model = AutoModelForCausalLM.from_pretrained(
            self._model_id,
            device_map="auto" if torch.cuda.is_available() else None,
            torch_dtype=dtype,
            trust_remote_code=True,
        )
        self._model.eval()

        elapsed = time.perf_counter() - start
        logger.info(f"Model loaded in {elapsed:.1f}s")

    def analyze(self, alert: dict) -> dict:
        """
        Run the ML Brain on a single normalized alert.

        Args:
            alert: Normalized alert dict, must conform to input_schema.json.

        Returns:
            MLReasoningResult dict conforming to output_schema.json.

        Raises:
            ValueError: If input fails schema validation or model output is unparseable.
        """
        # ── 1. Sanitize + validate input ──────────────────────────────────
        alert = sanitize_alert(alert)
        validate_input_strict(alert)
        alert_id = alert["alert_id"]
        logger.info(f"Processing alert_id={alert_id}")

        # ── 2. Build prompt ───────────────────────────────────────────────
        prompt = build_inference_prompt(alert)

        # ── 3. Tokenize ───────────────────────────────────────────────────
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=2048,
        )

        # Move to GPU if available
        if torch.cuda.is_available():
            inputs = {k: v.cuda() for k, v in inputs.items()}

        prompt_len = inputs["input_ids"].shape[1]

        # ── 4. Generate ───────────────────────────────────────────────────
        start = time.perf_counter()
        with torch.no_grad():
            output_ids = self._model.generate(
                **inputs,
                max_new_tokens=INFERENCE_CONFIG["max_new_tokens"],
                temperature=INFERENCE_CONFIG["temperature"],
                top_p=INFERENCE_CONFIG["top_p"],
                do_sample=INFERENCE_CONFIG["do_sample"],
                repetition_penalty=INFERENCE_CONFIG["repetition_penalty"],
                pad_token_id=self._tokenizer.eos_token_id,
                eos_token_id=self._tokenizer.eos_token_id,
            )
        elapsed = time.perf_counter() - start
        logger.info(f"Generation complete in {elapsed:.2f}s")

        # ── 5. Decode (new tokens only — strip the prompt) ────────────────
        new_token_ids = output_ids[0][prompt_len:]
        raw_output = self._tokenizer.decode(new_token_ids, skip_special_tokens=False)
        logger.debug(f"Raw model output: {raw_output[:500]}")

        # ── 6. Extract and parse JSON ─────────────────────────────────────
        json_str = extract_json_from_response(raw_output)
        result = json.loads(json_str)

        # ── 7. Inject metadata fields ─────────────────────────────────────
        result["alert_id"] = alert_id                          # Ensure echo is correct
        result["processed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result["model_version"] = MODEL_VERSION

        # ── 8. Validate output ────────────────────────────────────────────
        validate_output_strict(result)

        logger.info(
            f"alert_id={alert_id} → {result.get('attack_type_confirmed')} "
            f"(conf={result.get('confidence')}) → {result.get('recommended_action')}"
        )
        return result

    def analyze_batch(self, alerts: list[dict]) -> list[dict]:
        """
        Process a list of alerts sequentially.
        Returns a list of results in the same order. Failed alerts
        are returned with an error stub instead of raising an exception.
        """
        results = []
        for alert in alerts:
            try:
                results.append(self.analyze(alert))
            except Exception as e:
                logger.error(f"Failed to process alert {alert.get('alert_id')}: {e}")
                results.append({
                    "alert_id": alert.get("alert_id", "unknown"),
                    "error": str(e),
                    "processed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "model_version": MODEL_VERSION,
                })
        return results


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point for standalone testing
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    parser = argparse.ArgumentParser(description="ACD Brain — Single Alert Inference")
    parser.add_argument(
        "--alert",
        type=str,
        help="Path to a JSON file containing a single normalized alert.",
    )
    parser.add_argument(
        "--base-model",
        action="store_true",
        help="Force use of base model (no fine-tuning required).",
    )
    args = parser.parse_args()

    # Load alert from file or use a built-in test alert
    if args.alert:
        with open(args.alert, "r") as f:
            alert = json.load(f)
    else:
        logger.info("No --alert provided. Using built-in test alert.")
        alert = {
            "alert_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "timestamp": "2024-11-15T08:23:11Z",
            "source_ip": "192.168.1.45",
            "destination_ip": "10.0.0.2",
            "destination_port": 5000,
            "service": "auth_api",
            "attack_type": "brute_force",
            "severity": "high",
            "raw_event_count": 412,
            "features": {
                "request_rate_per_min": 102.3,
                "unique_paths_accessed": 1,
                "failed_auth_count": 408,
                "payload_contains_sql_keywords": False,
                "user_agent_anomaly": True,
                "geo_anomaly": True,
            },
            "wazuh_rule_id": 5710,
            "wazuh_rule_description": "sshd: brute force trying to get access to the system.",
        }

    brain = ACDBrainPipeline(use_base_model=args.base_model)
    result = brain.analyze(alert)

    print("\n" + "=" * 60)
    print("ML BRAIN OUTPUT")
    print("=" * 60)
    print(json.dumps(result, indent=2))
