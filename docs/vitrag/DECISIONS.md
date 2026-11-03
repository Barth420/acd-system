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

## V4: forwarder, alert sink, Wazuh
14. Reused from 54e6deb / 7d5be0a: `<rule_dir>etc/rules</rule_dir>` in ossec.conf (copied verbatim), the 100xxx id range, atomic
    decoder-triggered rules without `<if_sid>1</if_sid>`, the four `acd_*` decoders (unchanged: services keep the log prefixes
    and only append `rid=`), `start-wazuh.sh` (copied; container names, compose dir and the forwarder swap changed), the
    docker-cp of ossec.conf into the `wazuh_etc` volume, the certificate bind mounts and `securityadmin`. Changed or added:
    three decoders (`acd_cred_reuse`, `acd_lateral`, `acd_exfil`) and a last-resort `acd_service_line` decoder (any line with
    `src_ip=` yields srcip); rules 100301-100303; localfile entries for order/search/queue logs; 100712 listed BEFORE 100711 so the
    sustained-brute-force rule is reachable (the old order let the 5-event rule always win); recon rules listed last.
15. Contract D ambiguity, resolved by me, **CONFIRM**: the contract calls 100105 "SQL injection (aggregated)" and 100106 "XSS", but
    the existing local_rules.xml has 100105 = XSS and 100106 = URL-encoded XSS. In the hierarchy rule set 100105 is aggregated
    SQLi (5 x 100103 from one source in 30 s) at **level 12** (the old file's level 9 would put the aggregate below the single
    event) and 100106 is XSS at level 9. The old lab's file is untouched.
16. 100302 ("unauthorized internal admin access") is emitted for `LATERAL_DB_ACCESS` (queue's worker account used against the
    database). The auth_api `ADMIN_ACCESS` line is informational only: alerting on it would add a second, misleading alert to every
    credential-reuse event. 100301 covers `CREDENTIAL_REUSE`, `DEPENDENCY_ABUSE` and `SESSION_REUSE`; 100303 covers `DATA_EXFIL`
    (>= 50 rows in one answer). `dstport` is the logging service's container port, except 100302/100303 where the data lives in the
    database (5432); `source_service` is always the service that logged the line (contract D).
17. Parity between the Python forwarder and the Wazuh rules is checked by `tests/wazuh_eval.py`, a small evaluator of the XML subset
    used here, replaying synthetic sequences and one log written by the real services. **This checks the two rule sets in this repo
    agree; it is not Wazuh.** Unverified against a real manager: whether `frequency="5"` fires on the 5th or the 6th event, and
    first-match ordering of sibling rules. Wazuh itself has never been run in this session.
18. Log injection: every caller-controlled identifier (username, X-Service-Name, source address) is passed through `clean()` before it
    is logged, and the forwarder takes the LAST `rid=` in a line, so attacker text cannot forge a source address or request id in an
    alert. The user agent is logged `repr`-quoted and is still carried in alerts as data (it is the S6 injection carrier).
19. The forwarder posts to the alert sink and (best effort) the pipeline at `host.docker.internal:8000`; `--sink-only` runs without the
    pipeline. With `--wazuh`, `up.sh` stops the log forwarder and `forwarder-wazuh` (tails Wazuh's alerts.json, adds request id,
    source_service and dstport from the alert's `location` / `full_log`) takes over, so alerts are not duplicated. The Wazuh dashboard
    is published on 127.0.0.1:5601 under the profile only (a deviation from "only three published ports", needed to use it).

## V3: attack scenarios
20. Attacker identity: real containers (`attacker-1` 172.30.9.10, `attacker-2` 172.30.9.11 on `attacker_net`, controlled
    by the controller via `POST /execute`) in Docker. For no-Docker testing, `controller/attackers.py` falls back to
    in-process `DirectClient`s bound to `127.0.0.2`/`127.0.0.3` — genuinely distinct source addresses (the whole
    `127.0.0.0/8` range is loopback on Linux), not a label. All scenario steps go through the public gateway only,
    including the ones the brief called "internal routes" (`/orders/debug/forward`, `/auth/admin/*`): these are
    internal/admin *routes*, reachable via the gateway, not container-network-internal addresses — matches "attacks
    run only against this local lab; bind to localhost and the docker networks."
21. Outcome judging (see `controller/scenarios.py` module docstring and `docs/vitrag/SCENARIOS.md`): blocked only on an
    observed `X-ACD-Blocked` header or a connection failure the state snapshot explains as isolation; otherwise each
    step's own `validate()` decides succeeded vs failed from the real response (a login returning a token, an export
    returning ≥50 rows, a non-empty row list) — a wrong password guess is `failed`, not `succeeded`, and never
    assumed compromised.
22. `target_service` in a ground-truth step names the asset the step's intent targets (e.g. "database" for a dump
    delivered through product_api or auth_api), not necessarily the literal HTTP endpoint, so `compromised_services`
    reads the way contract E's own example does. `blocked_by.service` on an edge cut names the CALLER whose outbound
    edge was cut (`X-ACD-Service`, set by `acdlib.dep_call`), consistent with V1/V2 — found and documented, not
    changed, while writing V3 tests.
23. Bugs found only by running real scenarios against the real stack (not assumed from reading the code): (a) the
    attacker client's 4000-character response-body cap silently truncated large bulk-dump JSON, which made a
    genuinely successful 300-row export validate as "failed" — raised to 500 KB; (b) `aux["service_key"]` called
    `Lab.state.get()` as if `state` were the `StateReader` used elsewhere, but `Lab.state` is the live dict —
    fixed. Both are now exercised by `test_s2_sqli_credential_reuse_database_dump` and
    `test_s3_scan_sqli_exfiltration`.
24. S6 is built so both its steps always resolve to `failed`: the point is that instruction-injection text in a
    username/User-Agent, and a forged POST straight to the alert sink impersonating Wazuh, have no real effect on
    the lab — not to simulate an attack that "works."
25. Seeds (`random.Random(seed)`) control step-timing jitter only (0.05-1.8 s ranges, chosen by me, not measured);
    the attack logic and payloads are fixed per scenario. `test_seed_controls_jitter_deterministically` checks same
    seed -> same timing and outcomes.
