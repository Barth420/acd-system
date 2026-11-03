from pathlib import Path
import sys, importlib.util, subprocess, inspect, re, json, os, time, platform
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

HERE = Path(__file__).resolve().parent
DATA = Path(os.getenv("ACD_CORPUS_DIR", str(HERE / "data" / "processed"))).expanduser().resolve()
TRAIN_FILE = DATA / "windows_apt_train.jsonl"
VAL_FILE = DATA / "windows_apt_validation.jsonl"
OUT = Path(os.getenv("ACD_STAGE1_OUTPUT_DIR", str(HERE / "artifacts" / "stage1_10k"))).expanduser().resolve()
CACHE = Path(os.getenv("HF_HOME", str(Path.home() / ".cache" / "huggingface"))).expanduser().resolve()

MODEL_ID = "Qwen/Qwen3-4B-Base"
MAX_SEQ_LEN = 1024
EPOCHS = 1
TRAIN_BATCH = 1
GRAD_ACCUM = 16
LEARNING_RATE = 2e-4
LORA_R = 16
LORA_ALPHA = 32
EVAL_STEPS = 250
SAVE_STEPS = 250

REQUIRED = {
    "torch": "torch",
    "transformers": "transformers",
    "peft": "peft",
    "bitsandbytes": "bitsandbytes",
    "datasets": "datasets",
    "accelerate": "accelerate",
}

def package_check():
    missing = [pip_name for mod, pip_name in REQUIRED.items()
               if importlib.util.find_spec(mod) is None]
    if missing:
        print("Missing packages:", ", ".join(missing))
        print("Install with this command, then rerun this script:")
        print(f'python -m pip install -U {" ".join(missing)}')
        return False
    return True

def sanitize_text(text):
    # Remove common direct identifiers while retaining event and process semantics.
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<EMAIL>", text, flags=re.I)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", text)
    text = re.sub(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,}\b", "<IPV6>", text)
    text = re.sub(r"(?i)([A-Z]:\\Users\\)[^\\\s]+", r"\1<USER>", text)
    text = re.sub(r"(?i)(\\Device\\HarddiskVolume\d+\\Users\\)[^\\\s]+", r"\1<USER>", text)
    # Replace values on explicit identity fields; preserve the field name.
    text = re.sub(
        r"(?im)^(\s*[^:\n]*(?:username|user\.name|subjectusername|targetusername|subjectusername|accountname|samaccountname|hostname|computer|agent\.name|sourceuser|targetuser)[^:\n]*:\s*).+$",
        r"\1<REDACTED>",
        text
    )
    return text

def main():
    print("ACD V23 — QWEN3-4B QLoRA STAGE 1 (10K BLOCKS)")
    print("Platform:", platform.platform())
    if not TRAIN_FILE.exists() or not VAL_FILE.exists():
        print("ERROR: V18 train/validation files not found:")
        print(TRAIN_FILE)
        print(VAL_FILE)
        sys.exit(2)
    if not package_check():
        sys.exit(3)

    import torch
    import transformers
    import peft
    import bitsandbytes
    import datasets
    import accelerate
    from datasets import load_dataset
    from transformers import (
        AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig,
        DataCollatorForLanguageModeling, Trainer, TrainingArguments
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

    if not torch.cuda.is_available():
        print("ERROR: PyTorch cannot access CUDA. Training stopped.")
        print("torch:", torch.__version__, "cuda build:", torch.version.cuda)
        sys.exit(4)

    gpu_name = torch.cuda.get_device_name(0)
    vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
    print("GPU:", gpu_name)
    print(f"VRAM: {vram_gb:.2f} GB")
    print("Torch:", torch.__version__, "CUDA runtime:", torch.version.cuda)
    print("Transformers:", transformers.__version__, "PEFT:", peft.__version__)
    print("bitsandbytes:", bitsandbytes.__version__, "datasets:", datasets.__version__)

    if vram_gb < 14:
        print("ERROR: This configuration expects a GPU with at least 14 GB VRAM.")
        sys.exit(5)

    OUT.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    print("Loading tokenizer:", MODEL_ID)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True, cache_dir=str(CACHE))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    print("Loading and sanitizing JSONL datasets...")
    raw = load_dataset(
        "json",
        data_files={"train": str(TRAIN_FILE), "validation": str(VAL_FILE)},
        cache_dir=str(CACHE)
    )
    def clean_batch(batch):
        return {"text": [sanitize_text(x) for x in batch["text"]]}
    raw = raw.map(clean_batch, batched=True, desc="Redacting common identifiers")

    def tokenize_batch(batch):
        texts = [x + tokenizer.eos_token for x in batch["text"]]
        return tokenizer(texts, add_special_tokens=False, truncation=False)

    tokenized = raw.map(
        tokenize_batch,
        batched=True,
        remove_columns=raw["train"].column_names,
        desc="Tokenizing corpus"
    )

    def pack(batch):
        concatenated = {}
        for k in batch.keys():
            vals = []
            for seq in batch[k]:
                vals.extend(seq)
            concatenated[k] = vals
        total = (len(concatenated["input_ids"]) // MAX_SEQ_LEN) * MAX_SEQ_LEN
        result = {k: [v[i:i+MAX_SEQ_LEN] for i in range(0, total, MAX_SEQ_LEN)]
                  for k, v in concatenated.items()}
        result["labels"] = [x.copy() for x in result["input_ids"]]
        return result

    lm_data = tokenized.map(pack, batched=True, desc=f"Packing {MAX_SEQ_LEN}-token blocks")
    train_ds = lm_data["train"]
    val_ds = lm_data["validation"]
    if len(train_ds) == 0 or len(val_ds) == 0:
        print("ERROR: Tokenized train or validation split is empty.")
        sys.exit(6)
    print("Packed training blocks:", len(train_ds))
    print("Packed validation blocks:", len(val_ds))

    # Stage 1 deliberately trains on a deterministic 10,000-block subset.
    # A capped validation subset keeps stage evaluation proportionate.
    stage_train_blocks = min(10000, len(train_ds))
    stage_val_blocks = min(512, len(val_ds))
    train_ds = train_ds.shuffle(seed=2026).select(range(stage_train_blocks))
    val_ds = val_ds.shuffle(seed=2026).select(range(stage_val_blocks))
    print("STAGE 1 training blocks:", len(train_ds))
    print("STAGE 1 validation blocks:", len(val_ds))
    print("Estimated optimizer steps:", (len(train_ds) + (TRAIN_BATCH * GRAD_ACCUM) - 1) // (TRAIN_BATCH * GRAD_ACCUM))

    # Avoid silently overwriting a previous adapter.
    final_adapter = OUT / "adapter"
    if final_adapter.exists() and any(final_adapter.iterdir()):
        print("ERROR: Existing adapter output detected:", final_adapter)
        print("Rename/archive it before starting a new run.")
        sys.exit(7)

    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype
    )

    print("Loading 4-bit base model. This may download several GB...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        quantization_config=quant_config,
        device_map={"": 0},
        torch_dtype=compute_dtype,
        trust_remote_code=True,
        cache_dir=str(CACHE),
        low_cpu_mem_usage=True
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    lora = LoraConfig(
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"]
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    sig = inspect.signature(TrainingArguments.__init__).parameters
    eval_key = "eval_strategy" if "eval_strategy" in sig else "evaluation_strategy"
    args_dict = dict(
        output_dir=str(OUT / "checkpoints"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=TRAIN_BATCH,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LEARNING_RATE,
        warmup_ratio=0.03,
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        logging_steps=20,
        save_steps=SAVE_STEPS,
        eval_steps=EVAL_STEPS,
        save_total_limit=2,
        bf16=(compute_dtype == torch.bfloat16),
        fp16=(compute_dtype == torch.float16),
        gradient_checkpointing=True,
        optim="paged_adamw_8bit",
        max_grad_norm=0.3,
        dataloader_num_workers=0,
        dataloader_pin_memory=True,
        report_to="none",
        save_safetensors=True,
        logging_dir=str(OUT / "logs")
    )
    args_dict[eval_key] = "steps"

    # Transformers releases differ in their TrainingArguments API.
    # Pass only arguments supported by the installed version.
    supported_args = set(sig.keys())
    filtered_args = {key: value for key, value in args_dict.items() if key in supported_args}
    omitted_args = sorted(set(args_dict) - set(filtered_args))
    if omitted_args:
        print("Compatibility: omitted unsupported TrainingArguments:", ", ".join(omitted_args))
    training_args = TrainingArguments(**filtered_args)

    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
    trainer_kwargs = dict(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collator
    )
    if "processing_class" in inspect.signature(Trainer.__init__).parameters:
        trainer_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in inspect.signature(Trainer.__init__).parameters:
        trainer_kwargs["tokenizer"] = tokenizer
    trainer = Trainer(**trainer_kwargs)

    run_info = {
        "base_model": MODEL_ID,
        "base_model_license": "Apache-2.0 (verify model card before redistribution)",
        "method": "4-bit NF4 QLoRA continued causal-language-model training",
        "dataset": "Windows-APT-2025 V18 serialized events; deterministic stage-1 subset",
        "stage": 1,
        "stage_train_blocks": len(train_ds),
        "stage_validation_blocks": len(val_ds),
        "sampling_seed": 2026,
        "label_status": "unlabelled",
        "sequence_length": MAX_SEQ_LEN,
        "epochs": EPOCHS,
        "stage_scope": "10,000 training blocks maximum; 512 validation blocks maximum",
        "batch_size": TRAIN_BATCH,
        "gradient_accumulation": GRAD_ACCUM,
        "gradient_checkpointing": True,
        "tf32": True,
        "learning_rate": LEARNING_RATE,
        "lora": {"r": LORA_R, "alpha": LORA_ALPHA, "dropout": 0.05},
        "identifier_redaction": "email, IP, Windows user profile path and explicit user/host identity fields",
        "gpu": gpu_name,
        "vram_gb": round(vram_gb, 2),
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "transformers": transformers.__version__,
        "peft": peft.__version__,
        "bitsandbytes": bitsandbytes.__version__,
        "started_local": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    (OUT / "training_config.json").write_text(json.dumps(run_info, indent=2), encoding="utf-8")

    print("Starting training. Keep the PC powered and do not close this terminal.")
    result = trainer.train()
    trainer.save_model(str(final_adapter))
    tokenizer.save_pretrained(str(OUT / "tokenizer"))
    metrics = dict(result.metrics)
    metrics["final_validation"] = trainer.evaluate()
    (OUT / "training_metrics.json").write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
    (OUT / "TRAINING_COMPLETE.txt").write_text(
        "QLoRA domain-adaptation run completed.\n"
        "This adapter is not an attack classifier and has not been evaluated for detection accuracy.\n"
        f"Base model: {MODEL_ID}\nAdapter: {final_adapter}\n"
        "Check base-model and source-dataset licenses before sharing artifacts.\n",
        encoding="utf-8"
    )
    print("TRAINING COMPLETE")
    print("Adapter:", final_adapter)
    print("Metrics:", OUT / "training_metrics.json")

if __name__ == "__main__":
    main()
