# Phase 2 Integration — Parth's Brain into Bhavya's Pipeline

This document is the contract for hooking Parth's `ACDBrainPipeline` into Bhavya's
FastAPI service. It does NOT need to be implemented in Phase 1 — it's here so
the Phase 2 wiring is mechanical, not exploratory.

## Schema compatibility — already verified

Bhavya's `NormalizedAlert` Pydantic model (in `bhavya/pipeline/schemas.py`)
matches Parth's `acd-system-main/schemas/input_schema.json` field-for-field.

This is enforced by an automated test:

```bash
cd bhavya
pytest tests/test_pipeline.py::test_normalized_alert_matches_parth_schema -v
```

If anyone changes either side, this test fails immediately.

## Wiring the brain in

In `bhavya/pipeline/main.py`, the `ingest_alert` handler currently sets
`brain_result=None`. Phase 2 changes:

```python
# At top of file
import sys
sys.path.insert(0, "/path/to/acd-system-main")
from inference.pipeline import ACDBrainPipeline

# In the lifespan setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.brain = ACDBrainPipeline()    # loads the model once
    yield

# In ingest_alert, replace `brain_result=None` with:
brain_result = app.state.brain.analyze(normalized.model_dump())
incident = EnrichedIncident(
    normalized_alert=normalized,
    service_context=ctx,
    dependency_depth=depth,
    brain_result=brain_result,
)
```

Parth's `ACDBrainPipeline.analyze()`:
- Takes the dict produced by `NormalizedAlert.model_dump()`
- Validates strictly against `input_schema.json`
- Returns a dict matching `output_schema.json`

The dict shape is:
```python
{
  "alert_id": str,                    # echoed
  "processed_at": str,                # ISO 8601
  "model_version": str,
  "attack_type_confirmed": str,       # may differ from input attack_type
  "mitre_techniques": [...],
  "confidence": float,                # 0.0 – 1.0
  "severity_assessment": str,
  "reasoning": str,                   # multi-step chain
  "recommended_action": str,          # block_ip, rate_limit_ip, isolate_service, etc.
  "justification": str,
  "affected_services": [str],
  "propagation_risk": str,
}
```

## Storage already supports this

`EnrichedIncident.brain_result` is typed `Optional[dict[str, Any]]`. SQLite
stores the full Pydantic-serialized JSON in the `payload_json` column.
No DB migration needed when the brain comes online.

## Performance considerations

Parth's brain runs a 3.8B-parameter model. Per-alert latency on an 8 GB GPU
is ~2 seconds; on CPU it can take 20–30s. Bhavya should NOT block the
forwarder on brain inference. Recommended Phase 2 approach:

1. `POST /alerts` immediately stores the enriched incident with `brain_result=null`
   and returns 201.
2. A background worker (Celery, RQ, or `asyncio.create_task`) calls
   `brain.analyze()` and updates the row when done.
3. Add a new endpoint `GET /incidents/{id}/brain` that returns 202 if the
   brain hasn't finished yet, 200 with result if it has.

This is also why the Month 1 plan has Bhavya's pipeline working *before*
Parth's brain is trained — they're decoupled by design.

## Action handoff (Phase 3)

Once the brain emits a `recommended_action`, the response system needs to
execute it. That's outside Month 1/Month 2 scope, but the wiring will be:

```
Bhavya stores incident with brain_result.recommended_action
        ↓
Response orchestrator polls /incidents?has_unexecuted_actions=true
        ↓
Response orchestrator calls into iptables / Docker API / SOAR runbooks
        ↓
Response orchestrator marks the action executed
```

For Phase 1, no orchestrator exists — the recommendations just sit in the DB
for human review.
