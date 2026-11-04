"""
brain.py — optional LLM explanation layer, ADVISORY ONLY.

The containment DECISION (mode, which edges to cut) always comes from the deterministic planner
(planner.py) — the LLM, if available, never decides anything; it only adds a free-text explanation
of the alert for a human reading the dashboard, shown separately and clearly labelled.

Backends (ACD_BRAIN_BACKEND):
  template (default)  a deterministic, non-LLM sentence built from the same facts the planner used.
                       Always available; this is NOT a model, and is labelled as such in the UI.
  hf                   loads the real fine-tuned adapter (base model + PEFT adapter dir) and generates text.
                       Lazy: transformers/torch/peft are imported only when this backend is actually used,
                       so their absence never breaks the rest of the pipeline. If the adapter directory isn't
                       present, or torch/CUDA aren't available, it reports exactly why instead of guessing.
  off                   brain_response is omitted entirely.

Env for the hf backend (matches qwen_stage1/SETUP.md's convention):
  ACD_LLM_BASE_MODEL     default Qwen/Qwen3-4B-Base
  ACD_LLM_ADAPTER_DIR    local path to the extracted adapter (adapter/ + tokenizer/); REQUIRED for hf
  ACD_LLM_MAX_NEW_TOKENS default 80
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any, Optional


def _fact_sentence(service: str, attack_type: str, severity: str, source_ip: str, mode: str) -> str:
    return (f"[non-LLM] {attack_type} reported on {service} from {source_ip}, severity {severity}; "
           f"the deterministic planner set {service} to '{mode}'. This line is generated text, not a model output.")


class TemplateBackend:
    name = "template"

    def explain(self, *, service: str, attack_type: str, severity: str, source_ip: str, mode: str, **_: Any) -> dict[str, Any]:
        return {"backend": self.name, "available": True, "text": _fact_sentence(service, attack_type, severity, source_ip, mode)}


class OffBackend:
    name = "off"

    def explain(self, **_: Any) -> Optional[dict[str, Any]]:
        return None


class HfBackend:
    """Loads lazily, once, on first use; thread-safe; never imports torch at module import time."""
    name = "hf"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model = None
        self._tokenizer = None
        self._load_error: Optional[str] = None
        self._quantized = False
        self.base_model = os.getenv("ACD_LLM_BASE_MODEL", "Qwen/Qwen3-4B-Base")
        self.adapter_dir = os.getenv("ACD_LLM_ADAPTER_DIR", "")
        self.max_new_tokens = int(os.getenv("ACD_LLM_MAX_NEW_TOKENS", "80"))

    def _load(self) -> Optional[str]:
        """Returns an error string, or None on success. Only ever runs once."""
        if self._model is not None or self._load_error is not None:
            return self._load_error
        with self._lock:
            if self._model is not None or self._load_error is not None:
                return self._load_error
            if not self.adapter_dir:
                self._load_error = ("no adapter configured (set ACD_LLM_ADAPTER_DIR to the extracted adapter folder "
                                   "-- the trained weights are not part of this repository; see qwen_stage1/SETUP.md)")
                return self._load_error
            p = Path(self.adapter_dir)
            if not (p / "adapter").is_dir() or not (p / "tokenizer").is_dir():
                self._load_error = f"ACD_LLM_ADAPTER_DIR={self.adapter_dir!r} does not contain adapter/ and tokenizer/"
                return self._load_error
            try:
                import torch  # noqa: F401
                from peft import PeftModel
                from transformers import AutoModelForCausalLM, AutoTokenizer
            except ImportError as e:
                self._load_error = f"torch/transformers/peft not installed in this environment ({e})"
                return self._load_error
            # The handover guide (qwen_stage1/SETUP.md, "Step 3") is explicit that an unquantized float16 load
            # of the 4B base model may not fit a 16 GB GPU, and warns against assuming it will. Default to the
            # same 4-bit NF4 quantization the adapter was TRAINED with whenever CUDA is available (set
            # ACD_LLM_4BIT=0 to force an unquantized load instead, e.g. for a bigger GPU). bitsandbytes 4-bit is
            # a CUDA kernel, not usable on CPU, so a CPU box always falls back to an unquantized load (the
            # guide's own fallback: "CPU inference may be possible but can be slow").
            use_4bit = torch.cuda.is_available() and os.getenv("ACD_LLM_4BIT", "1") != "0"
            try:
                tok = AutoTokenizer.from_pretrained(str(p / "tokenizer"))
                if use_4bit:
                    from transformers import BitsAndBytesConfig
                    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                             bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True)
                    base = AutoModelForCausalLM.from_pretrained(self.base_model, quantization_config=bnb, device_map="auto")
                else:
                    base = AutoModelForCausalLM.from_pretrained(self.base_model, torch_dtype="auto",
                                                                device_map="auto" if torch.cuda.is_available() else None)
                self._tokenizer = tok
                self._model = PeftModel.from_pretrained(base, str(p / "adapter"))
                self._model.eval()
                self._quantized = use_4bit
            except Exception as e:  # noqa: BLE001 — any load failure is reported, never raised into the request path
                self._load_error = f"{e.__class__.__name__}: {e}"
                self._model = None
            return self._load_error

    def explain(self, *, service: str, attack_type: str, severity: str, source_ip: str, mode: str,
               raw_text: str = "", **_: Any) -> dict[str, Any]:
        err = self._load()
        if err:
            return {"backend": self.name, "available": False, "reason": err,
                   "text": _fact_sentence(service, attack_type, severity, source_ip, mode)}
        import torch
        prompt = raw_text or f"Security event: {attack_type} on {service} from {source_ip}, severity {severity}."
        t0 = time.time()
        try:
            inputs = self._tokenizer(prompt, return_tensors="pt")
            if torch.cuda.is_available():
                inputs = {k: v.cuda() for k, v in inputs.items()}
            with torch.inference_mode():
                out = self._model.generate(**inputs, max_new_tokens=self.max_new_tokens, do_sample=False,
                                           pad_token_id=self._tokenizer.eos_token_id)
            text = self._tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        except Exception as e:  # noqa: BLE001
            return {"backend": self.name, "available": False, "reason": f"generation failed: {e.__class__.__name__}: {e}",
                   "text": _fact_sentence(service, attack_type, severity, source_ip, mode)}
        return {"backend": self.name, "available": True, "text": text.strip(),
               "latency_s": round(time.time() - t0, 2),
               "model": f"{self.base_model} + {Path(self.adapter_dir).name}" + (" (4-bit NF4)" if self._quantized else " (unquantized)"),
               "caveat": "Domain-adapted language model, NOT a trained attack classifier. Read as context, not a verdict."}


def make_brain():
    name = os.getenv("ACD_BRAIN_BACKEND", "template").lower()
    if name == "off":
        return OffBackend()
    if name == "hf":
        return HfBackend()
    return TemplateBackend()
