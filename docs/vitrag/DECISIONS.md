# Decisions and assumptions (vitrag track)

## Process
1. V0 was skipped on the human's instruction. The Wazuh private keys committed in `7d5be0a` under
   `vitrag/wazuh-certificates/` are untouched; they are in git history and must be treated as exposed.
2. Branch `feat/vitrag-lab` was created from `origin/main` (7d5be0a) after `git pull`.
3. The build sandbox has no Docker daemon, so compose, Dockerfiles, nginx config, `docker network disconnect`
   and Wazuh are written but not run. See PLAN.md for what is tested instead.
4. Work order was changed by the human: V3 (attack scenarios) is done last, after a check-in.

## V1 / V2: lab and controller
5. One shared Python image holds all five Flask services (compose chooses the module); this keeps the build small and the
   memory budget low. Postgres, redis and nginx are stock images.
6. Networks: `net_t0` (gateway <-> tier 1), `net_t1` (tier-1 peers), `net_t2` (tier 1 <-> data tier) are `internal`;
   `ctl_net` (controller, alert sink) and `attacker_net` are not. database/cache/queue sit on `net_t2` only. The gateway sits
   on `attacker_net` + `net_t0` and cannot reach `net_t2` (checked by smoke.sh, not run here).
7. Enforcement is split. Flask services read `/control/state.json` and enforce their OWN mode on incoming requests. Postgres and
   redis cannot, so the CALLER enforces the target's mode and the cut edge before touching it (declared per endpoint via
   `infra=`). The gateway (nginx) cannot read the state file: the controller renders a `map` + `limit_req_zone` include and sends
   SIGHUP. A test checks the generated map agrees with the Python decision function. Real isolation is the network
   disconnect on top of the flag: refused connections show up as 502 at the gateway, with no X-ACD-Blocked header.
8. `rate_limited` is a per-source token bucket (8 req/s, burst 10) at the gateway and in each service, not a per-endpoint
   property, because "bulk" is a request pattern. `fallback` serves a cached answer for endpoints that declare one (product
   view, with `X-ACD-Blocked: ...; served=cached`) and 503 for everything else that needs a blocked capability.
9. `X-ACD-Service: <name>` is an extra response header I added next to `X-ACD-Blocked`, naming the service that blocked, so
   ground truth can fill `blocked_by.service`. For an infra target (database/cache) it names the target.
10. Edge cuts are accepted between ANY two distinct known services, not only declared dependencies: `queue -> database` (the
    lateral path of scenario S4) is a real code path (`queue /admin/db_query` declares the database) and can be cut. This
    answers the question raised in the other track.
11. Rotation is per service: a new key replaces `credentials[service].current`, the old one moves to `revoked`. The shared
    volume acts as the secret store (a lab simplification). `reset` restores the generation-0 keys, which are also the
    values planted in the database `secrets` table, so runs are reproducible; consequently keys leaked in an earlier run are
    valid again after a reset.
12. Controller placement: it runs IN compose with the docker socket mounted. A host process would need the control volume,
    the docker networks and a route to every service. Trade-off: the mounted socket gives the controller (and anything that
    compromises it) root-level control of the Docker host. Acceptable for a local lab only; the controller is published on
    127.0.0.1 and must never be exposed further.
13. Per-service `ok`/`ok_rate_30s` come from direct probes (HTTP /healthz, TCP connect for postgres/redis), not from journeys,
    so one broken hop does not mark every service on the path as down. `overall_availability` is the mean of the four journey
    rates (login, search, product_view, place_order). The health endpoint runs a probe round itself if none has run yet, so it
    never reports a number it has not measured.
