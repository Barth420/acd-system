# Hierarchy lab: how to run it and how it works

Everything is under `vitrag/hierarchy/`. The old 4-service lab (`vitrag/docker-compose.yml`) is untouched and must NOT run at the
same time (it publishes host ports 5002 and 8080); `scripts/up.sh` refuses to start while project `acd-phase1` or
`acd-phase1-minimal` is up.

> **Verification status.** The build sandbox had no Docker daemon. The Python code (services, controller, forwarder, sink, console)
> is tested as real processes via `scripts/local_stack.py`. The compose file is validated statically (`docker compose config`).
> **Not run anywhere yet:** the containers/Dockerfiles, the nginx config, `docker network disconnect`, the tier networks, and Wazuh.
> Run `scripts/smoke.sh` on a machine with Docker before trusting them.

## Run it

```bash
cd vitrag/hierarchy
scripts/up.sh              # default stack: 8 services + controller + alert sink + forwarder (no Wazuh)
scripts/smoke.sh           # starts it (if needed), hits every service, checks request ids reach the logs
scripts/down.sh            # stop (add --volumes to drop the database and logs)
scripts/up.sh --wazuh && scripts/start-wazuh.sh    # optional: Wazuh behind the `wazuh` profile (about 3 GB RAM)
```

| URL | What | Published |
|---|---|---|
| http://127.0.0.1:8080 | gateway (nginx), the only application entry point | yes |
| http://127.0.0.1:8100 | controller API (contract C); lab console at `/ui` | yes |
| http://127.0.0.1:8099 | alert sink (`/alerts`, `/alerts/summary`) | yes |
| http://127.0.0.1:5601 | Wazuh dashboard (profile `wazuh` only) | profile only |
| tier-1 services, database, cache, queue | docker networks only | **no** |

No Docker? Run the same service code locally (sqlite and a file key/value store stand in for postgres and redis, a Python proxy for nginx):

```bash
python3 -m venv vitrag/hierarchy/.venv && vitrag/hierarchy/.venv/bin/pip install flask requests httpx pytest fastapi uvicorn pyyaml
vitrag/hierarchy/.venv/bin/python vitrag/hierarchy/scripts/local_stack.py      # prints the gateway URL and the state file
cd vitrag/hierarchy && .venv/bin/python -m pytest -q                           # the whole test-suite
```

## Architecture

```
attacker_net ── nginx ── net_t0 ── auth_api / product_api / order_api / search_api ── net_t1 (peers)
                                          │                                       └── net_t2 ── database (postgres)
controller :8100  (ctl_net + t0/t1/t2) ───┘                                                   ├── cache (redis)
alert sink :8099 <── forwarder (reads the app_logs volume)                                    └── queue (Flask)
```

* One docker network per tier. `net_t0`, `net_t1`, `net_t2` are `internal` (no route out). The data tier sits on `net_t2` only, so the
  gateway has no path to it. Containers carry the contract names (`nginx`, `auth_api`, ...) as DNS names.
* Every service logs to the shared `app_logs` volume in the format the existing Wazuh decoders parse, with `rid=<request id>` appended.
  The gateway issues a fresh `X-Request-ID` per request (client-supplied ids are ignored), every service logs it and passes it on.
* Each endpoint declares the capabilities, dependencies and data-store operations it uses (`services/svc/acdlib.py`).

## How modes and isolation are enforced

The controller is the only writer of `/control/state.json` (modes, cut edges, per-service credentials). Three layers apply it:

1. **Flask services** read the file (cached by mtime) and enforce their *own* mode on each request: a request whose endpoint needs a blocked
   capability gets `503` + `X-ACD-Blocked: mode=<m>; capability=<c>` (and `X-ACD-Service`). `rate_limited` is a per-source token bucket
   (429). `fallback` serves a cached answer where the endpoint declares one (product view; header ends `served=cached`). Bulk reads
   (> 20 rows) additionally need `data_egress`. A cut edge `A->B` fails only endpoints of A that declare B: `X-ACD-Blocked: edge=A-B`.
2. **Postgres and redis** cannot read the file, so the *caller* enforces the target's mode and the cut edge before touching it.
3. **nginx** cannot either: the controller renders `/control/gateway_http.conf` (a `map` that yields `$acd_blocked`, plus the `limit_req_zone`)
   from the same state and sends SIGHUP. A test proves the generated map and the Python decision function agree.

`isolated` is real as well as flagged: the controller runs `docker network disconnect` on all of the container's networks and
re-attaches it (with its service-name alias) when the mode changes. Callers then see a refused connection (HTTP 502 at the gateway,
no `X-ACD-Blocked` header) instead of a polite 503.

**Trade-offs.** App-level enforcement is precise and cheap (per endpoint and per capability, instant, no container restarts) but it
is only as trustworthy as the application: a compromised service could ignore the state file. Network disconnect is enforced by
Docker, not by the code, but it is all-or-nothing (no "read only"), slower, and breaks the service's own health checks. The lab uses
both: app-level for graduated modes and edges, the network for isolation. Per-service `ok` in `/health` comes from direct probes, so
an isolated service is visible as down.

**Controller placement.** It runs in compose with the docker socket mounted (see DECISIONS.md #12). That is root-level control of
Docker: acceptable for this local lab only; keep it on 127.0.0.1.

## Credentials

Each service has a key (`credentials[service]`). Keys start at generation 0 (`lab-key-<service>-gen0`), also planted in the database
`secrets` table. `POST /services/{name}/rotate-credentials` issues a new key and moves the old one to `revoked`; the services read the
state file, so the old key stops working immediately. `POST /reset` restores generation 0.

## Wazuh certificates (V0 was skipped)

V0 asked to untrack the private keys committed in `7d5be0a` under `vitrag/wazuh-certificates/`. That was **skipped on instruction**:
the keys are still in the working tree and in git history and must be treated as exposed (anyone with repo access holds the root CA key).
Do not reuse them anywhere real. Regeneration, per the Wazuh 4.7 certificate tool (not run in this session):

```bash
cd vitrag
git rm -r --cached wazuh-certificates && echo "wazuh-certificates/" >> .gitignore   # untrack, then
rm -rf wazuh-certificates && bash wazuh-certs-tool.sh -A                            # needs openssl; reads vitrag/config.yml
cd hierarchy && scripts/up.sh --wazuh && scripts/start-wazuh.sh                      # confirm the stack still comes up
```
Rotating the keys does not remove the old ones from history; that needs a history rewrite and a force push everyone has to coordinate.

## Files

`docker-compose.yml`; `services/` (shared image + the five Flask services + the Python stand-in gateway); `gateway/` (nginx config);
`db/init.sql`; `controller/` (API, probes, docker ops, console in `ui/`); `forwarder/`; `tools/alert_sink.py`; `wazuh/`; `shared/`
(topology, control state, gateway rules); `scripts/`; `tests/`.
