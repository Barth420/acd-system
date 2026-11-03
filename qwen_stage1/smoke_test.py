"""Load the Qwen Stage 1 adapter and run a tiny generation smoke test.

This verifies artifact loading and text generation only. It does NOT test
attack detection, classification, MITRE mapping, or mitigation decisions.
"""
import os
from pathlib import Path
import sys

MODEL_ID = os.getenv("ACD_BASE_MODEL", "Qwen/Qwen3-4B-Base")
HERE = Path(__file__).resolve().parent
ADAPTER_DIR = Path(os.getenv("ACD_ADAPTER_DIR", HERE / "artifacts" / "stage1_10k" / "adapter")).expanduser()
TOKENIZER_DIR = Path(os.getenv("ACD_TOKENIZER_DIR", HERE / "artifacts" / "stage1_10k" / "tokenizer")).expanduser()
HF_HOME = Path(os.getenv("HF_HOME", Path.home() / ".cache" / "huggingface")).expanduser()

def main():
    if not ADAPTER_DIR.is_dir():
        raise SystemExit(f"Adapter directory not found: {ADAPTER_DIR}\nSet ACD_ADAPTER_DIR to the privately shared adapter folder.")
    if not (ADAPTER_DIR / "adapter_config.json").is_file():
        raise SystemExit(f"adapter_config.json missing from: {ADAPTER_DIR}")

    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel

    if not torch.cuda.is_available():
        raise SystemExit("CUDA GPU unavailable. This smoke test expects a supported CUDA setup.")

    tokenizer_source = TOKENIZER_DIR if TOKENIZER_DIR.is_dir() else MODEL_ID
    print("Base model:", MODEL_ID)
    print("Adapter:", ADAPTER_DIR)
    print("Tokenizer:", tokenizer_source)
    print("GPU:", torch.cuda.get_device_name(0))

    dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    quant = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=dtype,
    )
    tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_source), cache_dir=str(HF_HOME))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        MODEL_ID, quantization_config=quant, device_map={"": 0},
        torch_dtype=dtype, cache_dir=str(HF_HOME), low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(base, str(ADAPTER), is_trainable=False)
    model.eval()

    prompt = (
        "Windows security event:\n"
        "A process was started by a user session. Describe the observable event "
        "in one concise sentence. Do not infer malicious intent without evidence.\n"
        "Description:"
    )
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    with torch.inference_mode():
        output = model.generate(
            **inputs, max_new_tokens=48, do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated = tokenizer.decode(output[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print("\nSMOKE TEST OUTPUT")
    print(generated.strip() or "[No new text generated]")
    print("\nPASS: adapter loaded and generated text.")
    print("This is not evidence of attack-detection capability.")

if __name__ == "__main__":
    main()
