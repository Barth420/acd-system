from pathlib import Path
import os, sys, json, math, time, gc, platform

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "max_split_size_mb:128")

HERE = Path(__file__).resolve().parent
DATA = Path(os.getenv("ACD_CORPUS_DIR", str(HERE / "data" / "processed"))).expanduser().resolve()
TRAIN_FILE = DATA / "windows_apt_train.jsonl"
VAL_FILE = DATA / "windows_apt_validation.jsonl"
STAGE1_DIR = Path(os.getenv("ACD_STAGE1_OUTPUT_DIR", str(HERE / "artifacts" / "stage1_10k"))).expanduser().resolve()
OUT = Path(os.getenv("ACD_EVALUATION_OUTPUT_DIR", str(HERE / "artifacts" / "evaluation"))).expanduser().resolve()
ADAPTER = Path(os.getenv("ACD_ADAPTER_DIR", str(STAGE1_DIR / "adapter"))).expanduser().resolve()
TOKENIZER_DIR = Path(os.getenv("ACD_TOKENIZER_DIR", str(STAGE1_DIR / "tokenizer"))).expanduser().resolve()
CACHE = Path(os.getenv("HF_HOME", str(Path.home() / ".cache" / "huggingface"))).expanduser().resolve()
MODEL_ID = "Qwen/Qwen3-4B-Base"
MAX_SEQ_LEN = 1024
VAL_BLOCKS = 512
SEED = 2026

def main():
    print("ACD STEP 2 — BASE VS STAGE 1 ADAPTER EVALUATION V25")
    print("Platform:", platform.platform())
    for path in [TRAIN_FILE, VAL_FILE, ADAPTER, TOKENIZER_DIR]:
        if not path.exists():
            print("ERROR: Required path missing:", path)
            sys.exit(2)

    import torch, transformers, peft, bitsandbytes
    from datasets import load_dataset
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, DataCollatorForLanguageModeling
    from peft import PeftModel
    from torch.utils.data import DataLoader

    if not torch.cuda.is_available():
        print("ERROR: CUDA GPU unavailable.")
        sys.exit(3)

    gpu = torch.cuda.get_device_name(0)
    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    print("GPU:", gpu)
    print("Torch:", torch.__version__, "Transformers:", transformers.__version__, "PEFT:", peft.__version__)
    tokenizer = AutoTokenizer.from_pretrained(str(TOKENIZER_DIR), trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    print("Preparing held-out validation blocks...")
    raw = load_dataset("json", data_files=str(VAL_FILE), split="train", cache_dir=str(CACHE))

    def sanitize(text):
        import re
        text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<EMAIL>", text, flags=re.I)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", text)
        text = re.sub(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,}\b", "<IPV6>", text)
        text = re.sub(r"(?i)([A-Z]:\\Users\\)[^\\\s]+", r"\1<USER>", text)
        text = re.sub(r"(?i)(\\Device\\HarddiskVolume\d+\\Users\\)[^\\\s]+", r"\1<USER>", text)
        text = re.sub(r"(?im)^(\s*[^:\n]*(?:username|user\.name|subjectusername|targetusername|accountname|samaccountname|hostname|computer|agent\.name|sourceuser|targetuser)[^:\n]*:\s*).+$", r"\1<REDACTED>", text)
        return text

    raw = raw.map(lambda b: {"text": [sanitize(x) for x in b["text"]]}, batched=True, desc="Applying V23 redaction")

    def tokenize(b):
        return tokenizer([x + tokenizer.eos_token for x in b["text"]], add_special_tokens=False, truncation=False)

    tokenized = raw.map(tokenize, batched=True, remove_columns=raw.column_names, desc="Tokenizing")
    def pack(b):
        ids = [v for seq in b["input_ids"] for v in seq]
        masks = [v for seq in b["attention_mask"] for v in seq]
        total = (len(ids) // MAX_SEQ_LEN) * MAX_SEQ_LEN
        return {
            "input_ids": [ids[i:i+MAX_SEQ_LEN] for i in range(0, total, MAX_SEQ_LEN)],
            "attention_mask": [masks[i:i+MAX_SEQ_LEN] for i in range(0, total, MAX_SEQ_LEN)]
        }

    packed = tokenized.map(pack, batched=True, desc="Packing validation blocks")
    packed = packed.shuffle(seed=SEED).select(range(min(VAL_BLOCKS, len(packed))))
    print("Validation blocks:", len(packed))
    if not len(packed):
        print("ERROR: Empty validation set.")
        sys.exit(4)

    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
    loader = DataLoader(packed, batch_size=1, shuffle=False, collate_fn=collator)
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=compute_dtype)

    def evaluate(model, name):
        model.eval()
        model.config.use_cache = False
        loss_sum, count, start = 0.0, 0, time.time()
        for i, batch in enumerate(loader, 1):
            batch = {k: v.to("cuda") for k, v in batch.items()}
            with torch.inference_mode():
                loss = float(model(**batch).loss.float().cpu())
            loss_sum += loss
            count += 1
            if i % 64 == 0 or i == len(loader):
                print(f"{name}: {i}/{len(loader)} blocks; {(time.time()-start)/60:.1f} min")
        mean = loss_sum / count
        return {"model": name, "validation_loss": mean,
                "perplexity": math.exp(mean) if mean < 50 else float("inf"),
                "blocks": count, "runtime_seconds": time.time()-start}

    results = []
    print("\n[1/2] Loading and evaluating base model...")
    base = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=quant,
        device_map={"": 0}, torch_dtype=compute_dtype, trust_remote_code=True,
        cache_dir=str(CACHE), low_cpu_mem_usage=True)
    results.append(evaluate(base, "Qwen3-4B-Base"))
    del base
    gc.collect()
    torch.cuda.empty_cache()
    time.sleep(3)

    print("\n[2/2] Loading and evaluating Stage 1 adapter...")
    base2 = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=quant,
        device_map={"": 0}, torch_dtype=compute_dtype, trust_remote_code=True,
        cache_dir=str(CACHE), low_cpu_mem_usage=True)
    adapted = PeftModel.from_pretrained(base2, str(ADAPTER), is_trainable=False)
    results.append(evaluate(adapted, "Qwen3-4B-Base + Stage 1 adapter"))
    del adapted, base2
    gc.collect()
    torch.cuda.empty_cache()

    b, a = results
    reduction = (b["validation_loss"] - a["validation_loss"]) / b["validation_loss"] * 100
    report = {
        "purpose": "Next-token prediction comparison on held-out Windows-APT-2025 event text",
        "not_an_attack_detection_test": True,
        "base_model": MODEL_ID, "adapter_path": str(ADAPTER),
        "validation_file": str(VAL_FILE),
        "validation_blocks": len(packed), "sequence_length": MAX_SEQ_LEN, "selection_seed": SEED,
        "results": results, "adapted_loss_reduction_percent_vs_base": reduction,
        "interpretation": "Lower loss means better next-token prediction on this corpus. It does not establish attack-detection accuracy or general cybersecurity reasoning."
    }
    (OUT / "base_vs_stage1_evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "base_vs_stage1_evaluation.txt").write_text(
        f"ACD STEP 2 — BASE VS STAGE 1\nBase loss: {b['validation_loss']:.6f}\n"
        f"Adapted loss: {a['validation_loss']:.6f}\nLoss reduction: {reduction:.2f}%\n"
        "This is next-token prediction evaluation, not attack-detection evaluation.\n", encoding="utf-8")
    print("\nEVALUATION COMPLETE")
    print(f"Base loss: {b['validation_loss']:.6f} | PPL: {b['perplexity']:.4f}")
    print(f"Adapted loss: {a['validation_loss']:.6f} | PPL: {a['perplexity']:.4f}")
    print(f"Loss reduction: {reduction:.2f}%")
    print("Report:", OUT / "base_vs_stage1_evaluation.json")

if __name__ == "__main__":
    main()
