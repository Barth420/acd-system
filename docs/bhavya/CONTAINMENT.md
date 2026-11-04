# Containment planner, forensics, and the dashboard

This rebuilds and wires in the piece that was missing when the lab console could only isolate one service by
hand: when an alert names a compromised service, the pipeline now decides what to do about it and actually
calls Vitrag's **real** lab controller (not a mock) to do it, and shows the reasoning on a dashboard.

## What exists now

```
POST /alerts  ->  normalize  ->  store incident  ->  [background] containment manager:
    planner.plan()        decide a mode for the compromised service + which edges to cut (deterministic,
                           see containment/planner.py's module docstring for the exact rule table)
    brain.explain()        OPTIONAL, advisory-only text explanation (see "LLM" below) -- never decides anything
    controller_client      calls the REAL http://localhost:8100 (or wherever ACD_CONTROLLER_URL points): the
                           same contract-C controller Vitrag's lab implements, with the same actuation the lab
                           console's buttons use
    storage.save_decision  every action's real result (ok / error: ...) is recorded, never assumed
```

Run: `ACD_CONTROLLER_URL=http://localhost:8100 ACD_AUTONOMY=auto uvicorn pipeline.main:app --port 8000`, then
open `http://localhost:8000/ui`.

- `ACD_AUTONOMY=auto` (default): executes immediately. `=approve`: plans only; a decision sits
  `pending_approval` until `POST /api/decisions/{id}/approve`.
- `GET /api/decisions`, `GET /api/decisions/{id}`: every decision, with its rationale and each action's result.
- `GET /api/forensics?since=&until=&ip=`: reconstructs the attack path from stored incidents.
- `GET /api/lab/{topology,state,health}`: same-origin proxy to the controller (the dashboard never calls the
  controller cross-origin, so it isn't tied to the controller's CORS allowlist or which port the pipeline runs on).

## The decision rule (deliberately simple, not a risk model)

Severity -> mode (`critical`→isolated, `high`→fallback, `medium`→read_only, `low`→rate_limited), with
`lateral_movement`/`data_exfiltration` always escalated to isolated regardless of severity. Edge cuts to the
compromised service's **direct** dependents only fire once the mode is at least `read_only` (a plain
`rate_limited` on a low-severity port scan does not disrupt anyone else). `isolated` additionally cuts the
compromised service's own outbound edges, so it can't be used to pivot further in. The full transitive blast
radius is reported in every decision, but only direct neighbours are acted on from a single alert — see
`containment/planner.py` for the exact text each decision explains itself with.

**Every number here (which severity maps to which mode, the `read_only` threshold for cutting edges) is a
developer-chosen default, not a measured or trained value**, and the rationale text says so.

## The LLM ("brain_response")

`ACD_BRAIN_BACKEND` (default `template`):
- `template`: a deterministic sentence built from the same facts the planner used. **Not a model.** Always
  available, labelled `[non-LLM]` in the UI.
- `hf`: the real fine-tuned adapter, loaded lazily (torch/transformers/peft are never imported unless this
  backend is selected). Needs `ACD_LLM_ADAPTER_DIR` pointed at an extracted adapter package (same shape as
  `qwen_stage1/SETUP.md`: an `adapter/` and `tokenizer/` folder) and `ACD_LLM_BASE_MODEL` (default
  `Qwen/Qwen3-4B-Base`). **The trained weights are not part of this repository** — they exist only wherever
  they were originally trained; point `ACD_LLM_ADAPTER_DIR` at wherever you've put them. If the directory isn't
  there, or torch isn't installed, it says exactly why instead of guessing.
- `off`: the dashboard's "What the LLM said" section is omitted entirely.

**The LLM never decides anything.** The mode and edge cuts always come from the deterministic planner above;
`brain_response` is shown in its own clearly-labelled box purely as extra context for a human reading the
decision, and the UI repeats that on every card. A broken or absent LLM backend never blocks containment — it
degrades to the `template` text.

Also note: the Qwen adapter referenced in `qwen_stage1/` is a **domain-adapted language model**, not a trained
attack classifier (see `qwen_stage1/SETUP.md`). Even once wired up, its output should be read as context, not
a verdict — which is exactly what the UI's caveat line says.

## Honest status

Built and tested in this session:
- 39 tests pass (`cd bhavya && .venv/bin/python -m pytest -q`): planner rules, a real `ControllerClient` exercised
  against an in-memory fake controller (same HTTP shapes as the real one), the manager's execute/approve/failure
  paths, forensics reconstruction, the dashboard's served files, and the `/api/lab` proxy.
- **Run live, for real**, against Vitrag's actual controller code (not mocked) via his `scripts/local_stack.py`
  (no Docker needed for this — it's the same Python the real controller runs, just without containers): posting
  a `credential_abuse` alert on `auth_api` made the containment manager call the real controller and actually
  set `auth_api` to `fallback` and cut its three real inbound edges; a subsequent Vitrag attack scenario (S1)
  run against that now-contained lab came back `blocked_by_containment` on every step, confirmed from the
  controller's own `/state` and the scenario's own ground truth — not asserted, observed.
- The dashboard (`/ui`) was driven in headless Chromium against that same live stack; screenshots match the
  behaviour above (origin service highlighted, cut edges shown dashed red, decision rationale and the "What the
  LLM said" section both rendering correctly).

Not run: the `hf` brain backend against real weights (no adapter is reachable from any environment this session
had), and the whole pipeline against the real Docker lab (only against Vitrag's local-process stand-in,
described above — the HTTP contract is identical either way, but it's worth re-confirming on Docker).
