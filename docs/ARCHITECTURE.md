# ACD Phase 1 — Architecture

## Data flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  VITRAG'S LAB (Docker Compose)                                       │
│                                                                      │
│  ┌──────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐         │
│  │  nginx   │──▶│ auth_api │──▶│  database  │   │ product_ │         │
│  │  :80     │   │  :5000   │   │   :5432    │   │  api     │         │
│  └────┬─────┘   └────┬─────┘   └──────┬─────┘   │  :5001   │         │
│       │              │                │         └────┬─────┘         │
│       │ access.log   │ auth.log       │              │ product.log   │
│       │              │                │              │               │
│       └──────────────┴────────┬───────┴──────────────┘               │
│                               ▼                                      │
│                    ┌──────────────────────┐                          │
│                    │  shared_logs volume  │                          │
│                    │  (mounted RO into    │                          │
│                    │  Wazuh manager)      │                          │
│                    └──────────┬───────────┘                          │
│                               │                                      │
│                               ▼                                      │
│                    ┌──────────────────────┐                          │
│                    │   Wazuh Manager      │                          │
│                    │   (rules fire on     │                          │
│                    │   matched patterns)  │                          │
│                    └──────────┬───────────┘                          │
│                               │ alerts.json                          │
│                               ▼                                      │
│                    ┌──────────────────────┐                          │
│                    │   forwarder.py       │                          │
│                    │   (tails & POSTs)    │                          │
│                    └──────────┬───────────┘                          │
└───────────────────────────────┼──────────────────────────────────────┘
                                │ HTTP POST {source, timestamp, raw_data}
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  BHAVYA'S PIPELINE (host process, port 8000)                         │
│                                                                      │
│  POST /alerts                                                        │
│       │                                                              │
│       ▼                                                              │
│  ┌─────────────┐    ┌─────────────────┐    ┌───────────────────┐     │
│  │ normalizer  │───▶│ context         │───▶│ dependency graph  │     │
│  │ (raw →      │    │ enricher        │    │ (depth, blast     │     │
│  │ Normalized) │    │ (registry)      │    │ radius)           │     │
│  └─────────────┘    └─────────────────┘    └─────────┬─────────┘     │
│                                                      │               │
│                                                      ▼               │
│                                          ┌─────────────────────┐     │
│                                          │  SQLite             │     │
│                                          │  (EnrichedIncident) │     │
│                                          └─────────────────────┘     │
│                                                      │               │
│  GET /incidents ◀────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ Phase 2: brain_result added here
                                ▼
                       ┌────────────────────┐
                       │  Parth's brain     │
                       │  (acd-system-main) │
                       │  pipeline.analyze()│
                       └────────────────────┘
```

## Service registry — sensitivity × exposure matrix

| Service     | Sensitivity | Exposure | Depends on        | Used by             |
|-------------|-------------|----------|-------------------|---------------------|
| auth_api    | critical    | external | database          | product_api, nginx  |
| product_api | high        | external | database, auth_api| nginx               |
| database    | critical    | internal | —                 | auth_api, product_api |
| nginx       | medium      | external | auth_api, product_api | —              |

**Why this matters for the brain (Phase 2):** the same brute_force attack on auth_api (critical/external) must produce a different recommendation than the same attack on a low-sensitivity service. The `service_context` field in every enriched incident gives the brain that grounding.

## The 3 locked schemas

### Schema 1 — RawAlert (forwarder → Bhavya)
```json
{
  "source": "wazuh",
  "timestamp": "ISO8601",
  "raw_data": { /* Wazuh's native alert object */ }
}
```

### Schema 2 — NormalizedAlert (Bhavya → Parth)
**Locked.** Defined in `acd-system-main/schemas/input_schema.json`, mirrored exactly in `bhavya/pipeline/schemas.py::NormalizedAlert`. Drift is caught by `tests/test_pipeline.py::test_normalized_alert_matches_parth_schema`.

### Schema 3 — MLReasoningResult (Parth → Bhavya)
**Locked.** Defined in `acd-system-main/schemas/output_schema.json`. Bhavya stores it as `EnrichedIncident.brain_result` in Phase 2.

## Wazuh rule → attack_type mapping

| Wazuh rule range | Bhavya's attack_type | Notes                            |
|------------------|----------------------|----------------------------------|
| 5710–5720        | `brute_force`        | Auth failure aggregation rules   |
| 31100–31199      | `sql_injection` or `xss` | Refined by description keyword |
| 40100–40110      | `port_scan`          | Recon detection                  |
| (other)          | `unknown`            | Falls through; brain may reclassify |

Plus keyword-based fallback in the normalizer for cases where the rule_id doesn't fit a known range.
