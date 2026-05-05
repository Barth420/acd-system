# ACD Phase 1 — Vitrag + Bhavya Implementation

Month 1 deliverables for the Autonomous Cyber Defense System.

This repo implements:

- **Bhavya's pipeline** (`bhavya/`) — FastAPI service that ingests raw Wazuh alerts, normalizes them into Parth's locked schema, enriches with service context + dependency-graph analysis, and stores enriched incidents.
- **Vitrag's lab** (`vitrag/`) — Docker-Compose-based vulnerable microservice environment (auth_api, product_api, database, nginx) instrumented with Wazuh SIEM, plus 3 attack scripts and a forwarder that bridges Wazuh → Bhavya's pipeline.

Parth's ML brain lives in a separate repo (`acd-system-main`) and is **not** modified here. We match its locked schemas exactly so Phase 2 integration is plug-and-play.

---

## Repo layout

```
acd-phase1/
├── bhavya/
│   ├── pipeline/
│   │   ├── schemas.py           # Pydantic models — the 3 shared contracts
│   │   ├── normalizer.py        # Wazuh raw → NormalizedAlert (Parth's schema)
│   │   ├── service_registry.py  # 4-service registry with sensitivity/exposure
│   │   ├── dependency_graph.py  # NetworkX graph + blast-radius computation
│   │   ├── storage.py           # SQLAlchemy + SQLite persistence
│   │   └── main.py              # FastAPI app
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_pipeline.py     # 10 tests including milestone smoke test
│   └── requirements.txt
├── vitrag/
│   ├── docker-compose.yml       # 4 lab services + Wazuh stack + forwarder
│   ├── lab/
│   │   ├── auth_api/            # Vulnerable Flask login
│   │   ├── product_api/         # Vulnerable Flask catalog (SQLi + XSS)
│   │   ├── database/            # Postgres + init.sql
│   │   └── frontend/            # nginx reverse proxy
│   ├── wazuh/
│   │   ├── local_rules.xml      # Custom rules: brute force, SQLi, port scan
│   │   └── ossec.conf.append    # Tells Wazuh to monitor app log files
│   ├── forwarder/
│   │   ├── forwarder.py         # Tails Wazuh alerts.json → POSTs to Bhavya
│   │   └── Dockerfile
│   └── attacks/
│       ├── attack_brute_force.py
│       ├── attack_sql_injection.py
│       ├── attack_port_scan.py
│       └── run_all_attacks.py   # Runs all 3 + verifies via Bhavya's API
└── docs/
    ├── INTEGRATION_WITH_PARTH.md
    └── ARCHITECTURE.md
```

---

## Quick start (WSL2)

You'll run things in two side-by-side terminals: one for Bhavya's pipeline (host), one for Vitrag's lab (Docker).

### Prerequisites

- WSL2 with Ubuntu
- Docker Desktop with WSL2 integration enabled
- Python 3.10+
- At least 6 GB RAM free for Wazuh

### Terminal 1 — Bhavya's pipeline

```bash
cd bhavya
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run tests first to confirm the pipeline is healthy
pytest tests/ -v

# Start the API
uvicorn pipeline.main:app --host 0.0.0.0 --port 8000 --reload
```

Confirm it's up:
```bash
curl http://localhost:8000/healthz
# → {"status":"ok","service":"acd-bhavya-pipeline","incidents_stored":0}
```

### Terminal 2 — Vitrag's lab

```bash
cd vitrag

# First boot is slow (~5 min) — Wazuh images are big
docker compose up -d --build

# Wait until all services are healthy
docker compose ps

# Wazuh dashboard:  https://localhost:5601   (admin / SecretPassword)
# Lab frontend:     http://localhost          (nginx)
# auth_api direct:  http://localhost:5000
# product_api:      http://localhost:5001
```

Wazuh takes ~3 minutes after `up` to fully initialize. Watch the manager logs:
```bash
docker compose logs -f wazuh.manager
# Look for: "INFO: (1410): Analysisd started..."
```

### Run all 3 attacks end-to-end

```bash
# From the vitrag/ directory (with a venv that has 'requests' installed):
pip install requests
python attacks/run_all_attacks.py --bhavya http://localhost:8000
```

Expected output ends with:
```
[verify] ✓ All 3 attack types confirmed in pipeline.
```

### Inspect results

```bash
# All enriched incidents
curl http://localhost:8000/incidents | jq

# A specific incident
curl http://localhost:8000/incidents/<incident_id> | jq

# The dependency graph
curl http://localhost:8000/graph | jq
```

---

## Month 1 milestones — status

| Owner   | Milestone                                              | Status |
|---------|--------------------------------------------------------|--------|
| Bhavya  | FastAPI pipeline running                               | ✅ |
| Bhavya  | Alert normalizer working                               | ✅ |
| Bhavya  | Service registry + context enricher                    | ✅ |
| Bhavya  | Dependency graph (NetworkX)                            | ✅ |
| Bhavya  | Repo structure + CI-ready (pytest)                     | ✅ |
| Bhavya  | All 3 schemas locked + matching Parth's contract       | ✅ |
| Vitrag  | 4-container Docker lab running                         | ✅ |
| Vitrag  | Wazuh SIEM integration                                 | ✅ |
| Vitrag  | 3 attack scripts (brute_force, SQLi, port_scan)        | ✅ |
| Vitrag  | Forwarder Wazuh → Bhavya                               | ✅ |
| Vitrag  | Alert format validation (end-to-end)                   | ✅ |
| Joint   | All 3 attacks → enriched incidents in DB               | ✅ (verified locally) |

---

## Where Parth's brain plugs in (Phase 2)

Bhavya's pipeline currently stores incidents with `brain_result: null`. In Phase 2:

1. Add a hook in `bhavya/pipeline/main.py` `ingest_alert()`:
   ```python
   from acd_brain import ACDBrainPipeline   # Parth's package
   brain = ACDBrainPipeline()
   incident.brain_result = brain.analyze(normalized.model_dump())
   ```
2. Bhavya's `NormalizedAlert` already matches Parth's `input_schema.json` field-for-field — verified by `test_normalized_alert_matches_parth_schema`.
3. The `MLReasoningResult` Parth returns will be stored in `EnrichedIncident.brain_result`.

See `docs/INTEGRATION_WITH_PARTH.md` for details.

---

## Troubleshooting

**Wazuh manager doesn't start / runs out of memory**
Wazuh needs ~2 GB. In Docker Desktop → Settings → Resources, set memory to at least 6 GB.

**Forwarder can't reach `host.docker.internal`**
On native Linux Docker (not Docker Desktop), the `extra_hosts: host-gateway` line in compose handles this. If your distro is older, replace `host.docker.internal` in `BHAVYA_API` with your WSL2 host's IP (`ip route | grep default`).

**No alerts appearing in Bhavya's pipeline**
1. Confirm Wazuh is generating alerts: `docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json`
2. Confirm forwarder is running: `docker compose logs -f forwarder`
3. Check Bhavya's logs for 422 (drop) responses — could mean rules are firing but normalizer can't extract required fields.

**Pipeline rejects alerts with 422**
Look at `forwarder` logs for the exact alert. Most common: missing `srcip` in Wazuh `data` block. Adjust the rule decoder, or add a fallback in `bhavya/pipeline/normalizer.py::normalize_wazuh_alert`.
