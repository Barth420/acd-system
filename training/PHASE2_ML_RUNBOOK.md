# Phase 2 ML Runbook

This repo stage is limited to dataset creation, QLoRA training, and evaluation.
It does not add APIs, infra, orchestration, or full-system integration.

## Dataset

Generate deterministic JSONL datasets:

```powershell
cd G:\Projects\acd-system
python -m training.generate_dataset
```

Outputs:

- `data/train.jsonl`: 800 training samples
- `data/eval.jsonl`: 100 eval samples
- `data/dataset_summary.json`: label and MITRE coverage counts

Each JSONL row is:

```json
{"input": {"alert_id": "..."}, "output": {"attack_type_confirmed": "..."}}
```

The generated rows use the existing input/output schemas and cover all 13
MITRE techniques in `data/mitre_mapping.json`.

## Training

Install dependencies first:

```powershell
cd G:\Projects\acd-system
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

Verify PyTorch can see the RTX GPU:

```powershell
python -X utf8 -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'NO CUDA')"
```

If that prints `False` or `NO CUDA`, reinstall CUDA PyTorch:

```powershell
pip uninstall -y torch torchvision torchaudio
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```

Run QLoRA fine-tuning:

```powershell
cd G:\Projects\acd-system
python -X utf8 -m training.train
```

The adapter is saved to `checkpoints/acd-brain-final/`.

If you retrain after changing the training code, use a fresh adapter directory:

```powershell
$env:ACD_MODEL_DIR = "G:\Projects\acd-system\checkpoints\acd-brain-final-v2"
python -X utf8 -m training.train
```

The checked-in defaults are conservative. On an RTX 4080, you can usually try a
larger batch/sequence budget:

```powershell
$env:ACD_TRAIN_BATCH_SIZE = "2"
$env:ACD_GRAD_ACCUM_STEPS = "4"
$env:ACD_MAX_SEQ_LENGTH = "2048"
$env:ACD_BF16 = "true"
$env:ACD_FP16 = "false"
python -X utf8 -m training.train
```

If VRAM usage gets too high, return to the defaults:

```powershell
$env:ACD_TRAIN_BATCH_SIZE = "1"
$env:ACD_GRAD_ACCUM_STEPS = "8"
$env:ACD_MAX_SEQ_LENGTH = "1536"
$env:ACD_BF16 = "false"
$env:ACD_FP16 = "true"
```

## Switching Models

The default base model is `microsoft/Phi-3-mini-4k-instruct`. To test another
compatible causal language model, set environment variables before training:

```powershell
$env:ACD_BASE_MODEL = "microsoft/Phi-3-mini-4k-instruct"
$env:ACD_MODEL_VERSION = "phi3-mini-acd-v1.0"
python -X utf8 -m training.train
```

If the model uses different LoRA module names:

```powershell
$env:ACD_LORA_TARGET_MODULES = "q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj"
python -X utf8 -m training.train
```

Large model downloads use `G:\huggingface_cache` by default through `HF_HOME`.

## Evaluation

Run the baseline evaluator:

```powershell
cd G:\Projects\acd-system
python -m training.evaluate
```

It writes `outputs/evaluation_metrics.json` and checks:

- Accuracy
- Macro F1
- Minimum baseline target: 50%

After model inference, evaluate predictions with:

```powershell
python -X utf8 -m training.evaluate --predictions outputs\predictions.jsonl
```

Prediction JSONL rows can be either:

```json
{"alert_id": "...", "attack_type_confirmed": "sql_injection"}
```

or:

```json
{"output": {"alert_id": "...", "attack_type_confirmed": "sql_injection"}}
```

## Trained Adapter Evaluation

After `python -X utf8 -m training.train` finishes, run a quick smoke test:

```powershell
cd G:\Projects\acd-system
python -X utf8 -m training.predict_eval --limit 5
python -X utf8 -m training.evaluate --predictions outputs\predictions.jsonl --limit 5
```

Then run the full 100-sample eval:

```powershell
python -X utf8 -m training.predict_eval
python -X utf8 -m training.evaluate --predictions outputs\predictions.jsonl
```
