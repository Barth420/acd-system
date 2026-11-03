"""Portable Qwen Stage 1 paths and model identity.

Scripts also accept these environment variables directly:
ACD_WINDOWS_APT_ARCHIVE, ACD_CORPUS_DIR, ACD_STAGE1_OUTPUT_DIR,
ACD_EVALUATION_OUTPUT_DIR, ACD_ADAPTER_DIR, ACD_TOKENIZER_DIR, HF_HOME.
"""
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL_ID = os.getenv("ACD_BASE_MODEL", "Qwen/Qwen3-4B-Base")
CORPUS_DIR = Path(os.getenv("ACD_CORPUS_DIR", HERE / "data" / "processed")).expanduser()
STAGE1_OUTPUT_DIR = Path(os.getenv("ACD_STAGE1_OUTPUT_DIR", HERE / "artifacts" / "stage1_10k")).expanduser()
EVALUATION_OUTPUT_DIR = Path(os.getenv("ACD_EVALUATION_OUTPUT_DIR", HERE / "artifacts" / "evaluation")).expanduser()
ADAPTER_DIR = Path(os.getenv("ACD_ADAPTER_DIR", STAGE1_OUTPUT_DIR / "adapter")).expanduser()
TOKENIZER_DIR = Path(os.getenv("ACD_TOKENIZER_DIR", STAGE1_OUTPUT_DIR / "tokenizer")).expanduser()
HF_HOME = Path(os.getenv("HF_HOME", Path.home() / ".cache" / "huggingface")).expanduser()

# Reproduction parameters from the completed V23 Stage 1 run.
MAX_SEQ_LEN = 1024
TRAIN_BLOCK_LIMIT = 10_000
VALIDATION_BLOCK_LIMIT = 512
EPOCHS = 1
TRAIN_BATCH = 1
GRAD_ACCUM = 16
LEARNING_RATE = 2e-4
LORA_R = 16
LORA_ALPHA = 32
SEED = 2026
