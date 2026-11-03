# Qwen Stage 1 setup

## Scope

This package contains the V18 Windows-APT corpus builder, the V23 Qwen3-4B QLoRA
Stage 1 training script, the V25 base-versus-adapter next-token evaluation script,
and an adapter loading/generation smoke test.

The smoke test verifies model loading and generation only. Stage 1 is unlabelled
domain adaptation; it is not a validated attack detector or attack classifier.

## Environment

- Python 3.10
- CUDA-capable NVIDIA GPU; the completed run used an RTX 4080 16 GB
- Base model: `Qwen/Qwen3-4B-Base`
- Package versions are pinned in `requirements-stage1.txt`

Create an isolated environment, then install:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\qwen_stage1\requirements-stage1.txt
```

The PyTorch requirement is pinned to the CUDA 12.1 wheel. Confirm that the installed
NVIDIA driver supports the selected CUDA runtime.

## Configure external source data

Do not commit the Windows-APT archive or generated JSONL corpus. After the source
dataset licence and privacy review is complete, set the archive path:

```powershell
$env:ACD_WINDOWS_APT_ARCHIVE = "D:\approved-data\Windows-APT 2025 A Dataset for APT-Inspired Attack.zip"
$env:ACD_CORPUS_DIR = "D:\approved-data\acd-v18-corpus"
```

Build the V18 corpus:

```powershell
python .\qwen_stage1\prepare_corpus_v18.py
```

The script writes train/validation JSONL, a manifest and a text report to
`ACD_CORPUS_DIR`. The corpus is not fully anonymized; do not distribute it until
privacy and licence checks are complete.

## Train Stage 1

```powershell
python .\qwen_stage1\train_stage1.py
```

By default, outputs go to `qwen_stage1\artifacts\stage1_10k`. Override with
`ACD_STAGE1_OUTPUT_DIR` if model artifacts are stored elsewhere. The training script
retains the V23 parameters and refuses to overwrite an existing adapter folder.

## Evaluate Stage 1

Place the adapter and tokenizer in the configured locations, or set:

```powershell
$env:ACD_ADAPTER_DIR = "D:\private-models\stage1\adapter"
$env:ACD_TOKENIZER_DIR = "D:\private-models\stage1\tokenizer"
```

Then run:

```powershell
python .\qwen_stage1\evaluate_stage1.py
```

The evaluation compares next-token prediction loss/perplexity on the held-out V18
validation corpus. It is not an attack-detection benchmark.

## Adapter smoke test

After receiving the adapter and tokenizer through approved private storage:

```powershell
$env:ACD_ADAPTER_DIR = "D:\private-models\stage1\adapter"
$env:ACD_TOKENIZER_DIR = "D:\private-models\stage1\tokenizer"
python .\qwen_stage1\smoke_test.py
```

A passing smoke test means the base model, adapter and tokenizer loaded and generated
text. It does not establish detection accuracy or safe mitigation behaviour.

## Reproducibility and data caveats

- V18 serializes Windows-APT 2025 records as unlabelled text. MITRE fields in those
  records are context, not verified event-level ground-truth labels.
- V23 applies common identifier redaction during training. V18 JSONL itself may still
  contain identifiers and must remain private pending review.
- The V18 content-hash split is not grouped by host, time or scenario. Correlated
  event leakage is possible.
- The adapter is not standalone. It requires `Qwen/Qwen3-4B-Base`.
- Do not claim attack detection, attack classification, or mitigation performance
  from the Stage 1 loss reduction.
- The final inference contract must be aligned with the team's approved schema v2.
