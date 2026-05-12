# Minimal Mode — Phase 1 Without Wazuh

Use this when you can't run the full Wazuh stack (slow network, low RAM, locked-down environment) but still want to demo the end-to-end pipeline.

## What you get vs full mode

| Feature | Full mode (`vitrag/`) | Minimal mode (this dir) |
|---|---|---|
| 4 vulnerable services | ✅ | ✅ |
| Real attacks generate real logs | ✅ | ✅ |
| Logs → alerts → enriched incidents | ✅ | ✅ |
| All 3 attack types detected | ✅ | ✅ |
| Bhavya's pipeline test | ✅ | ✅ |
| Wazuh SIEM dashboard UI | ✅ | ❌ |
| Wazuh rules engine | ✅ | ❌ (Python regex instead) |
| Image download size | ~1.5 GB | ~200 MB |
| First-boot time | ~5 min | ~30 sec |

The pipeline-side experience is **identical**. The forwarder posts the same JSON shape Wazuh would.

## How it works

```
[real attacks] → [vulnerable apps] → [app log files] → [log_forwarder]
                                                              │
                                                              ▼
                                                   POST {Wazuh-shaped JSON}
                                                              │
                                                              ▼
                                              [Bhavya's pipeline → SQLite]
```

The `log_forwarder` container watches `auth.log`, `product.log`, and `access.log` on a shared volume. When it sees attack patterns (multiple auth failures, SQL keywords, scanner User-Agents), it builds a `RawAlert` JSON object — byte-identical to what the real Wazuh forwarder produces — and POSTs it to Bhavya's `/alerts` endpoint.

## Detection rules

Mirror the rules in `vitrag/wazuh/local_rules.xml`:

| Rule ID | Trigger | Severity |
|---|---|---|
| 5711 | 5+ AUTH_FAILURE from same IP in 60s | high (level 10) |
| 5712 | 20+ AUTH_FAILURE in 120s | critical (level 12) |
| 31103 | SQL_ERROR or sqlmap UA in product log | high (level 11) |
| 31105 | XSS pattern in product log | medium (level 9) |
| 40101 | Scanner UA (nmap/nikto/masscan) hit on nginx | medium (level 8) |
| 40102 | 50+ scanner hits from same IP in 30s | high (level 10) |

## Quick start

Prereq: Bhavya's pipeline already running on `localhost:8000` (see main `PHASE1_README.md`).

```bash
# From the repo root:
cd minimal-mode

# Build and start everything (~30 seconds)
docker compose -f docker-compose.minimal.yml up -d --build

# Watch services come up
docker compose -f docker-compose.minimal.yml ps
docker compose -f docker-compose.minimal.yml logs -f log_forwarder
# Look for: "Pipeline healthy: ..." then "Tailing started."
# Press Ctrl+C to stop watching (containers keep running)
```

## Run the 3 attacks

In another terminal:

```bash
cd ~/acd-system
source bhavya/.venv/bin/activate

# This runs all 3 attacks, then queries Bhavya's API to verify
python minimal-mode/attacks/run_all_attacks.py
```

Expected final line:
```
[verify] ✓ All 3 attack types confirmed in pipeline. Phase 1 milestone complete.
```

## Inspect results

```bash
# Count of stored incidents
curl http://localhost:8000/healthz

# Most recent 50 incidents
curl http://localhost:8000/incidents | python3 -m json.tool

# Live forwarder logs
docker compose -f docker-compose.minimal.yml logs -f log_forwarder
```

## Tear down

```bash
cd minimal-mode
docker compose -f docker-compose.minimal.yml down -v
```

## Adding Wazuh later

Whenever the network cooperates, switch back to full mode by using the original `vitrag/docker-compose.yml`. Bhavya's pipeline doesn't need any changes — it accepts the same `RawAlert` schema from either forwarder.

## Troubleshooting

**"Pipeline never became healthy"**
The forwarder can't reach Bhavya at `host.docker.internal:8000`. Confirm uvicorn is running on the host and bound to `0.0.0.0` (not just `127.0.0.1`). On native Linux Docker, `host.docker.internal` is mapped via `extra_hosts: host-gateway` — already set in the compose file.

**No alerts appearing in Bhavya's pipeline**
1. Confirm logs are being written: `docker compose exec auth_api tail /var/log/auth/auth.log`
2. Check forwarder logs: `docker compose logs log_forwarder` — you should see `Tailing auth: /shared_logs/auth/auth.log` etc.
3. Trigger a manual auth failure: `curl -X POST http://localhost:5000/auth/login -H 'Content-Type: application/json' -d '{"username":"x","password":"y"}'` — that should appear in the forwarder log within a second or two.

**`run_all_attacks.py` shows missing attack types**
Common cause: brute-force threshold not crossed. The forwarder needs 5+ failures in 60s to fire the brute-force alert. Check that `attack_brute_force.py` is sending requests fast enough (default is 30 attempts at 0.2s = comfortably above threshold).
