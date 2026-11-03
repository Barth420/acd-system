# Qwen Stage 1 — Cybersecurity Domain Adaptation

Primary model: `Qwen/Qwen3-4B-Base`

This directory contains the reproducible Stage 1 workflow:
- `prepare_corpus_v18.py` — Windows-APT V18 unlabelled corpus builder
- `train_stage1.py` — V23 4-bit NF4 QLoRA continued language-model training
- `evaluate_stage1.py` — V25 base-versus-adapter next-token evaluation
- `smoke_test.py` — adapter loading and generation smoke test
- `requirements-stage1.txt` — pinned direct dependencies
- `SETUP.md` — setup and execution instructions

**Scope limitation:** Stage 1 is cybersecurity-domain adaptation, not a validated
attack detector or mitigation system. The inference contract awaits the team's
approved schema v2.

See [SETUP.md](SETUP.md) for exact commands.
