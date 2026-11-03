# Plan: lab, actuators, lab console

Existing code read first: `vitrag/lab/*` (old 4-service lab), `vitrag/wazuh/*` (decoders match the log prefixes
`AUTH_FAILURE user=`, `SQL_ERROR|SQLI_ATTEMPT`, `XSS_ATTEMPT`; rules 100710-100712, 100103, 100105-106, 100201-202),
`vitrag/start-wazuh.sh`, `minimal-mode/forwarder_minimal`. All new work lives in `vitrag/hierarchy/`; the old lab is untouched.

```
gateway (nginx) -> tier-1 Flask services -> database (postgres) / cache (redis);  queue (Flask)
controller :8100  writes /control/state.json (+ nginx map), docker network disconnect, probes journeys
forwarder         tails the shared logs -> alert sink :8099 and/or the pipeline
```

Order (agreed with the human): V1 lab, V2 controller, V4 forwarder + sink + Wazuh additions, V5 console UI, V6 docs
and up/down, then V3 (attack scenarios) last, after checking in. V0 (certificate cleanup) was skipped on the human's
instruction.

Environment limit: the build sandbox has no Docker daemon. Anything not needing Docker is tested as real processes
(`scripts/local_stack.py`: the real service code with sqlite/file stand-ins for postgres/redis and a Python stand-in for
nginx). Compose, Dockerfiles, the nginx config, `docker network disconnect` and Wazuh are written but not run here.
