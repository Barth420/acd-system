"""
training/train.py — QLoRA fine-tuning script for ACD ML Brain.

Runs on a single GPU with 8GB+ VRAM (tested on RTX 3060/4060).
Uses 4-bit quantization (BitsAndBytes) + LoRA adapters (PEFT) + SFTTrainer (TRL).

Usage:
    python -m training.train

The fine-tuned LoRA adapter will be saved to:
    checkpoints/acd-brain-final/

To merge adapters with the base model for deployment:
    python -m training.train --merge
"""

import argparse
import logging
import sys
import os

# Suppress tokenizer parallelism warning (safe for single-process training)
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

from config import (
    BASE_MODEL_ID,
    CHECKPOINT_DIR,
    FINE_TUNED_MODEL_DIR,
    QLORA_CONFIG,
    TRAINING_CONFIG,
    QUANTIZATION_CONFIG,
    DATASET_CONFIG,
    MODEL_VERSION,
)
from training.dataset_loader import get_datasets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def load_quantized_model_and_tokenizer(model_id: str):
    """Load the base model in 4-bit NF4 quantization + its tokenizer."""
    logger.info(f"Loading base model: {model_id}")

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=QUANTIZATION_CONFIG["load_in_4bit"],
        bnb_4bit_quant_type=QUANTIZATION_CONFIG["bnb_4bit_quant_type"],
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=QUANTIZATION_CONFIG["bnb_4bit_use_double_quant"],
    )

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map="auto",          # Automatic GPU/CPU placement
        trust_remote_code=True,     # Required for Phi-3
        attn_implementation="eager", # Safer than flash_attention_2 for compat
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
    return TrainingArguments(
        output_dir=TRAINING_CONFIG["output_dir"],
        num_train_epochs=TRAINING_CONFIG["num_train_epochs"],
        per_device_train_batch_size=TRAINING_CONFIG["per_device_train_batch_size"],
        gradient_accumulation_steps=TRAINING_CONFIG["gradient_accumulation_steps"],
        learning_rate=TRAINING_CONFIG["learning_rate"],
        warmup_ratio=TRAINING_CONFIG["warmup_ratio"],
        lr_scheduler_type=TRAINING_CONFIG["lr_scheduler_type"],
        logging_steps=TRAINING_CONFIG["logging_steps"],
        save_steps=TRAINING_CONFIG["save_steps"],
        save_total_limit=TRAINING_CONFIG["save_total_limit"],
        fp16=TRAINING_CONFIG["fp16"],
        bf16=TRAINING_CONFIG["bf16"],
        optim=TRAINING_CONFIG["optim"],
        max_grad_norm=TRAINING_CONFIG["max_grad_norm"],
        report_to=TRAINING_CONFIG["report_to"],
        remove_unused_columns=TRAINING_CONFIG["remove_unused_columns"],
        dataloader_pin_memory=TRAINING_CONFIG["dataloader_pin_memory"],
        gradient_checkpointing=True,
        group_by_length=True,       # Speeds up training by reducing padding
    )


def train():
    """Main training entry point."""
    logger.info("=" * 60)
    logger.info(f"ACD ML Brain — QLoRA Training ({MODEL_VERSION})")
    logger.info(f"Base model: {BASE_MODEL_ID}")
    logger.info("=" * 60)

    # 1. Load datasets
    train_dataset, val_dataset = get_datasets()

    # 2. Load model + tokenizer
    model, tokenizer = load_quantized_model_and_tokenizer(BASE_MODEL_ID)

    # 3. Apply QLoRA
    model = apply_qlora(model)

    # 4. Build training args
    training_args = build_training_args()

    # 5. Initialize SFTTrainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        dataset_text_field="text",      # Column name in our HF Dataset
        max_seq_length=DATASET_CONFIG["max_seq_length"],
        packing=False,                  # Disable packing — examples vary in size
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
        torch_dtype=torch.bfloat16,
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
    args = parser.parse_args()

    train()
    if args.merge:
        merge_and_save()
