"""
config.py — Central configuration for the ACD ML Brain module.
All hyperparameters, paths, and environment-dependent settings live here.
Never hardcode these values in other modules.
"""

import os
from pathlib import Path

# Set Hugging Face cache to G drive to save C drive space
os.environ["HF_HOME"] = "G:/huggingface_cache"

# ─────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.resolve()
SCHEMAS_DIR = BASE_DIR / "schemas"
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"
CHECKPOINT_DIR = BASE_DIR / "checkpoints"

INPUT_SCHEMA_PATH = SCHEMAS_DIR / "input_schema.json"
OUTPUT_SCHEMA_PATH = SCHEMAS_DIR / "output_schema.json"
TRAINING_DATA_PATH = DATA_DIR / "training_examples.json"
MITRE_MAPPING_PATH = DATA_DIR / "mitre_mapping.json"

# ─────────────────────────────────────────────
# Model Selection
# ─────────────────────────────────────────────
# Justification: Phi-3-mini-4k-instruct chosen over Mistral-7B because:
#   1. Runs in 4-bit on a single 8GB VRAM GPU (RTX 3060/4060 tier)
#   2. Phi-3 outperforms Mistral-7B on structured JSON generation tasks
#      in the 3.8B range (Microsoft benchmark, June 2024)
#   3. Faster inference latency (~40% faster than Mistral-7B on same hardware)
#   4. Official support for chat/instruct format with <|user|>/<|assistant|> tags
#   5. Still large enough for multi-step reasoning chains our task requires
# Switch to Mistral-7B if reasoning chain quality degrades after fine-tuning.

BASE_MODEL_ID = os.getenv("ACD_BASE_MODEL", "microsoft/Phi-3-mini-4k-instruct")
FINE_TUNED_MODEL_DIR = os.getenv("ACD_MODEL_DIR", str(CHECKPOINT_DIR / "acd-brain-final"))
MODEL_VERSION = "phi3-mini-acd-v1.0"

# ─────────────────────────────────────────────
# QLoRA Training Hyperparameters
# ─────────────────────────────────────────────

QLORA_CONFIG = {
    # LoRA rank — controls capacity of the adapter. 16 is safe for structured tasks.
    "lora_r": 16,
    # LoRA alpha — scaling factor. Convention: alpha = 2 * r
    "lora_alpha": 32,
    # Dropout for regularization
    "lora_dropout": 0.05,
    # Bias training — none recommended for QLoRA stability
    "bias": "none",
    # Task type for PEFT
    "task_type": "CAUSAL_LM",
    # Which layers to apply LoRA to. For Phi-3:
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
}

TRAINING_CONFIG = {
    "output_dir": str(CHECKPOINT_DIR),
    "num_train_epochs": 5,
    "per_device_train_batch_size": 2,
    "gradient_accumulation_steps": 4,   # Effective batch size = 2 * 4 = 8
    "learning_rate": 2e-4,
    "warmup_ratio": 0.05,
    "lr_scheduler_type": "cosine",
    "logging_steps": 5,
    "save_steps": 50,
    "save_total_limit": 3,
    "fp16": False,          # Use bf16 on Ampere+ GPUs (RTX 30xx/40xx)
    "bf16": True,
    "optim": "paged_adamw_8bit",
    "max_grad_norm": 1.0,
    "report_to": "none",    # Set to "wandb" if W&B is configured
    "remove_unused_columns": False,
    "dataloader_pin_memory": False,
}

# ─────────────────────────────────────────────
# BitsAndBytes 4-bit Quantization
# ─────────────────────────────────────────────

QUANTIZATION_CONFIG = {
    "load_in_4bit": True,
    "bnb_4bit_quant_type": "nf4",
    "bnb_4bit_compute_dtype": "bfloat16",
    "bnb_4bit_use_double_quant": True,
}

# ─────────────────────────────────────────────
# Inference Settings
# ─────────────────────────────────────────────

INFERENCE_CONFIG = {
    # Max tokens for the model's JSON output — keep generous to avoid truncation
    "max_new_tokens": 1024,
    # Temperature: 0.1 for near-deterministic structured output
    "temperature": 0.1,
    "top_p": 0.9,
    "do_sample": True,
    # Repetition penalty prevents JSON key repetition loops
    "repetition_penalty": 1.1,
}

# ─────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────

DATASET_CONFIG = {
    # Ratio of training data to keep for validation
    "validation_split": 0.15,
    # Max sequence length. Phi-3-mini supports 4k, keep conservative.
    "max_seq_length": 2048,
    "seed": 42,
}

# ─────────────────────────────────────────────
# System Prompt
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are the ML Brain of an Autonomous Cyber Defense System (ACD).

Your role:
- Receive a normalized security alert in JSON format.
- Analyze it using your security knowledge and reasoning capabilities.
- Output a structured JSON response following the exact MLReasoningResult schema.

Rules you must follow:
1. Your output MUST be valid JSON and nothing else — no explanation outside the JSON.
2. The "reasoning" field must be a detailed, step-by-step analysis of the alert indicators.
3. The "recommended_action" must be one of the allowed enum values.
4. The "mitre_techniques" must use correct MITRE ATT&CK technique IDs (format: T1234 or T1234.001).
5. The "confidence" must be a float between 0.0 and 1.0.
6. Never invent data not present in the input alert.
7. If evidence is ambiguous, lower the confidence score and recommend "escalate_to_human".
"""
