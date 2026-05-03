"""
training/train.py — QLoRA fine-tuning script for ACD ML Brain.

Runs on a single GPU with 8GB+ VRAM (tested on RTX 3060/4060).
Uses 4-bit quantization (BitsAndBytes) + LoRA adapters (PEFT) + Hugging Face Trainer.

Usage:
    python -m training.train

To switch the base model without editing code:
    set ACD_BASE_MODEL=microsoft/Phi-3-mini-4k-instruct
    set ACD_MODEL_VERSION=phi3-mini-acd-v1.0
    python -m training.train

The fine-tuned LoRA adapter will be saved to:
    checkpoints/acd-brain-final/

To merge adapters with the base model for deployment:
    python -m training.train --merge
"""

import argparse
import inspect
import logging
import sys
import os

# Suppress tokenizer parallelism warning (safe for single-process training)
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import torch
from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

from config import (
    BASE_MODEL_ID,
    CHECKPOINT_DIR,
    FINE_TUNED_MODEL_DIR,
    QLORA_CONFIG,
    TRAINING_CONFIG,
    QUANTIZATION_CONFIG,
    DATASET_CONFIG,
    MODEL_VERSION,
    TRAIN_JSONL_PATH,
    EVAL_JSONL_PATH,
)
from training.dataset_loader import get_datasets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def _resolve_torch_dtype(dtype_name: str):
    """Map config dtype strings to torch dtypes."""
    dtype_map = {
        "float16": torch.float16,
        "fp16": torch.float16,
        "bfloat16": torch.bfloat16,
        "bf16": torch.bfloat16,
        "float32": torch.float32,
        "fp32": torch.float32,
    }
    try:
        return dtype_map[dtype_name.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported compute dtype: {dtype_name}") from exc


def _resolve_precision_flags() -> tuple[bool, bool]:
    """Return fp16/bf16 flags that are supported by the current PyTorch setup."""
    fp16_enabled = TRAINING_CONFIG["fp16"]
    bf16_enabled = TRAINING_CONFIG["bf16"]

    if bf16_enabled:
        bf16_supported = (
            torch.cuda.is_available()
            and hasattr(torch.cuda, "is_bf16_supported")
            and torch.cuda.is_bf16_supported()
        )
        if not bf16_supported:
            logger.warning(
                "bf16 was requested but is not supported by this PyTorch/CUDA setup. "
                "Falling back to fp16=%s.",
                torch.cuda.is_available(),
            )
            bf16_enabled = False
            fp16_enabled = torch.cuda.is_available()

    if fp16_enabled and bf16_enabled:
        logger.warning("Both fp16 and bf16 were enabled; using bf16 only.")
        fp16_enabled = False

    if not torch.cuda.is_available() and (fp16_enabled or bf16_enabled):
        logger.warning("CUDA is not available; disabling fp16/bf16 mixed precision.")
        fp16_enabled = False
        bf16_enabled = False

    return fp16_enabled, bf16_enabled


def _load_model_config(model_id: str):
    """
    Load model config and normalize known Phi-3 RoPE key drift.

    Some Phi-3 configs expose rope_scaling["rope_type"], while older remote
    modeling code expects rope_scaling["type"]. Normalizing here keeps training
    compatible with cached/newer Hugging Face configs without editing cache files.
    """
    config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
    rope_scaling = getattr(config, "rope_scaling", None)
    if isinstance(rope_scaling, dict):
        rope_type = rope_scaling.get("rope_type") or rope_scaling.get("type")
        if rope_type == "default":
            config.rope_scaling = None
            logger.info("Disabled default rope_scaling for %s.", model_id)
        elif "type" not in rope_scaling:
            rope_scaling["type"] = rope_type or "longrope"
            config.rope_scaling = rope_scaling
            logger.info(
                "Normalized rope_scaling.type=%s for %s.",
                rope_scaling["type"],
                model_id,
            )
    return config


def load_quantized_model_and_tokenizer(model_id: str):
    """Load the base model in 4-bit NF4 quantization + its tokenizer."""
    logger.info(f"Loading base model: {model_id}")
    model_config = _load_model_config(model_id)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=QUANTIZATION_CONFIG["load_in_4bit"],
        bnb_4bit_quant_type=QUANTIZATION_CONFIG["bnb_4bit_quant_type"],
        bnb_4bit_compute_dtype=_resolve_torch_dtype(
            QUANTIZATION_CONFIG["bnb_4bit_compute_dtype"]
        ),
        bnb_4bit_use_double_quant=QUANTIZATION_CONFIG["bnb_4bit_use_double_quant"],
    )

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        config=model_config,
        quantization_config=bnb_config,
        device_map="auto",          # Automatic GPU/CPU placement
        trust_remote_code=True,     # Required for Phi-3
        attn_implementation=os.getenv("ACD_ATTENTION_IMPL", "eager"),
    )
    model.config.use_cache = False  # Required for gradient checkpointing
    model.config.pretraining_tp = 1

    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"  # Phi-3 prefers right padding

    logger.info("Model and tokenizer loaded.")
    return model, tokenizer


def apply_qlora(model):
    """Prepare model for k-bit training and apply LoRA adapters."""
    logger.info("Preparing model for QLoRA...")
    model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=QLORA_CONFIG["lora_r"],
        lora_alpha=QLORA_CONFIG["lora_alpha"],
        lora_dropout=QLORA_CONFIG["lora_dropout"],
        bias=QLORA_CONFIG["bias"],
        task_type=QLORA_CONFIG["task_type"],
        target_modules=QLORA_CONFIG["target_modules"],
    )

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    logger.info("LoRA adapters applied.")
    return model


def build_training_args() -> TrainingArguments:
    """Build HuggingFace TrainingArguments from config."""
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    fp16_enabled, bf16_enabled = _resolve_precision_flags()
    args = {
        "output_dir": TRAINING_CONFIG["output_dir"],
        "num_train_epochs": TRAINING_CONFIG["num_train_epochs"],
        "per_device_train_batch_size": TRAINING_CONFIG["per_device_train_batch_size"],
        "gradient_accumulation_steps": TRAINING_CONFIG["gradient_accumulation_steps"],
        "learning_rate": TRAINING_CONFIG["learning_rate"],
        "warmup_ratio": TRAINING_CONFIG["warmup_ratio"],
        "lr_scheduler_type": TRAINING_CONFIG["lr_scheduler_type"],
        "logging_steps": TRAINING_CONFIG["logging_steps"],
        "eval_steps": TRAINING_CONFIG["eval_steps"],
        "evaluation_strategy": "steps",
        "eval_strategy": "steps",
        "save_steps": TRAINING_CONFIG["save_steps"],
        "save_total_limit": TRAINING_CONFIG["save_total_limit"],
        "fp16": fp16_enabled,
        "bf16": bf16_enabled,
        "optim": TRAINING_CONFIG["optim"],
        "max_grad_norm": TRAINING_CONFIG["max_grad_norm"],
        "report_to": TRAINING_CONFIG["report_to"],
        "remove_unused_columns": TRAINING_CONFIG["remove_unused_columns"],
        "dataloader_pin_memory": TRAINING_CONFIG["dataloader_pin_memory"],
        "gradient_checkpointing": True,
        "group_by_length": True,
    }
    accepted_args = set(inspect.signature(TrainingArguments).parameters)
    filtered_args = {key: value for key, value in args.items() if key in accepted_args}
    skipped_args = sorted(set(args) - set(filtered_args))
    if skipped_args:
        logger.warning(
            "Skipping unsupported TrainingArguments for installed transformers: %s",
            ", ".join(skipped_args),
        )
    return TrainingArguments(**filtered_args)


def tokenize_datasets(train_dataset, eval_dataset, tokenizer):
    """Tokenize chat text and mask prompt tokens from the loss."""
    max_seq_length = DATASET_CONFIG["max_seq_length"]

    def tokenize_batch(batch):
        input_ids = []
        attention_mask = []
        labels = []

        for prompt_text, completion_text in zip(
            batch["prompt_text"],
            batch["completion_text"],
        ):
            prompt_ids = tokenizer(
                prompt_text,
                add_special_tokens=False,
            )["input_ids"]
            completion_ids = tokenizer(
                completion_text,
                add_special_tokens=False,
            )["input_ids"]
            ids = (prompt_ids + completion_ids)[:max_seq_length]
            prompt_length = min(len(prompt_ids), len(ids))
            sample_labels = [-100] * prompt_length + ids[prompt_length:]

            input_ids.append(ids)
            attention_mask.append([1] * len(ids))
            labels.append(sample_labels)

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }

    train_tokenized = train_dataset.map(
        tokenize_batch,
        batched=True,
        remove_columns=train_dataset.column_names,
        desc="Tokenizing train dataset",
    )
    eval_tokenized = eval_dataset.map(
        tokenize_batch,
        batched=True,
        remove_columns=eval_dataset.column_names,
        desc="Tokenizing eval dataset",
    )
    logger.info(
        "Tokenized datasets with max_seq_length=%s: %s train / %s eval.",
        max_seq_length,
        len(train_tokenized),
        len(eval_tokenized),
    )
    return train_tokenized, eval_tokenized


class CausalLMDataCollator:
    """Pad causal-LM batches and mask padded label positions with -100."""

    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def __call__(self, features):
        labels = [feature.pop("labels") for feature in features]
        batch = self.tokenizer.pad(
            features,
            padding=True,
            return_tensors="pt",
        )
        max_length = batch["input_ids"].shape[1]
        padded_labels = []
        for label in labels:
            pad_length = max_length - len(label)
            padded_labels.append(label + [-100] * pad_length)
        batch["labels"] = torch.tensor(padded_labels, dtype=torch.long)
        return batch


def train(train_path=TRAIN_JSONL_PATH, eval_path=EVAL_JSONL_PATH):
    """Main training entry point."""
    logger.info("=" * 60)
    logger.info(f"ACD ML Brain — QLoRA Training ({MODEL_VERSION})")
    logger.info(f"Base model: {BASE_MODEL_ID}")
    logger.info("=" * 60)

    # 1. Load datasets
    train_dataset, val_dataset = get_datasets(train_path=train_path, eval_path=eval_path)

    # 2. Load model + tokenizer
    model, tokenizer = load_quantized_model_and_tokenizer(BASE_MODEL_ID)

    # 3. Apply QLoRA
    model = apply_qlora(model)

    # 4. Build training args
    training_args = build_training_args()

    # 5. Tokenize and initialize Trainer
    train_tokenized, val_tokenized = tokenize_datasets(
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        tokenizer=tokenizer,
    )
    data_collator = CausalLMDataCollator(tokenizer=tokenizer)
    trainer = Trainer(
        model=model,
        train_dataset=train_tokenized,
        eval_dataset=val_tokenized,
        data_collator=data_collator,
        args=training_args,
    )

    # 6. Train
    logger.info("Starting training...")
    trainer.train()

    # 7. Save final LoRA adapter
    logger.info(f"Saving final LoRA adapter to: {FINE_TUNED_MODEL_DIR}")
    trainer.model.save_pretrained(FINE_TUNED_MODEL_DIR)
    tokenizer.save_pretrained(FINE_TUNED_MODEL_DIR)
    logger.info("Training complete. LoRA adapter saved.")


def merge_and_save():
    """
    Merge LoRA adapter weights back into the base model for deployment.
    This produces a standalone model directory that doesn't need PEFT at inference.
    """
    from peft import AutoPeftModelForCausalLM

    logger.info(f"Merging LoRA adapter from: {FINE_TUNED_MODEL_DIR}")
    merged_dir = str(CHECKPOINT_DIR / "acd-brain-merged")

    model = AutoPeftModelForCausalLM.from_pretrained(
        FINE_TUNED_MODEL_DIR,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=_resolve_torch_dtype(QUANTIZATION_CONFIG["bnb_4bit_compute_dtype"]),
    )
    model = model.merge_and_unload()
    model.save_pretrained(merged_dir)

    tokenizer = AutoTokenizer.from_pretrained(FINE_TUNED_MODEL_DIR)
    tokenizer.save_pretrained(merged_dir)

    logger.info(f"Merged model saved to: {merged_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACD ML Brain Training")
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge LoRA adapters with base model after training.",
    )
    parser.add_argument(
        "--train-path",
        default=str(TRAIN_JSONL_PATH),
        help="Path to Phase 2 training JSONL. Defaults to data/train.jsonl.",
    )
    parser.add_argument(
        "--eval-path",
        default=str(EVAL_JSONL_PATH),
        help="Path to Phase 2 eval JSONL. Defaults to data/eval.jsonl.",
    )
    args = parser.parse_args()

    train(train_path=args.train_path, eval_path=args.eval_path)
    if args.merge:
        merge_and_save()
