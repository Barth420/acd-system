# Attack scenarios (V3)

All scenarios drive the lab through its gateway only, using **only the lab's existing deliberate weaknesses**
(weak logins, string-built SQL in product_api, the unauthenticated debug proxy in order_api, the unauthenticated
`/admin/config` in queue). No exploit targets anything outside this lab. Two attacker agents (`attacker-1`,
`attacker-2`) execute the HTTP steps the controller sends them, each with its own real source address (distinct
container IPs in Docker; two distinct loopback binds — `127.0.0.2` / `127.0.0.3` — in the no-Docker fallback, see
`attacker/agent.py`). `POST /scenarios/{id}/run` returns a `run_id`; `GET /runs/{run_id}/ground-truth` fills in as
steps execute (contract E).

**Outcome is never assumed.** A step is `blocked_by_containment` only when the response carries
`X-ACD-Blocked` (503/429, or a 502 whose path maps to a service the state snapshot shows as `isolated`), or the
request errored and the state snapshot shows the target isolated. Otherwise each step's own validator decides
whether the attacker's intent genuinely succeeded (a login returning a token, an export returning ≥50 rows, a
row count > 0); only then does it count toward `compromised_services`/`attack_path`.

| id | name | steps (capability) | expected attack types | compromised / attack_path |
|---|---|---|---|---|
| S0 | Benign only | none | — | none |
| S1 | Brute force then stolen session | 6× password guess on auth_api (`state_write`), then order_api replay from attacker-2 (`dependency_calls`) | brute_force, credential_abuse | auth_api, order_api → `nginx, auth_api, order_api` |
| S2 | SQLi, credential reuse, database dump | SQLi on product_api (`dynamic_query`), reused product_api key against `/auth/admin/users` (`dependency_calls`), bulk export (`data_egress`) | sql_injection, credential_abuse, data_exfiltration | product_api, auth_api, database → `nginx, product_api, auth_api, database` |
| S3 | Scan then SQLi then exfiltration | 8× recon probe (`bulk_requests`), SQLi probe, UNION dump through the same injection (`data_egress`) | port_scan, sql_injection, data_exfiltration | product_api, database → `nginx, product_api, database` |
| S4 | Foothold on queue then lateral move | unauthenticated `/admin/config` via order_api's debug proxy (`dependency_calls`), then `/admin/db_query` with the leaked worker password (`dependency_calls`) | credential_abuse, lateral_movement | queue, database → `nginx, queue, database` (order_api is a pass-through proxy, not itself compromised) |
| S5 | Slow brute force | 5× password guess on auth_api, ~1.2-1.8 s apart | brute_force | none (stays under the rate threshold by design) |
| S6 | Spoofed alerts and injection text | a login with instruction-injection text in username/User-Agent; a forged alert POSTed straight to the alert sink impersonating Wazuh | n/a (`injection_payload=true` on both; both always `failed`) | none |

## Why S6 always "fails"
Both steps are deliberately designed so the lab's own logging and the controller treat the injected text as
**data**, never as instructions: the login is rejected like any other bad password, and the forged alert is just
another row in the sink. `validate()` always returns `False` for these steps, so they can never be marked
`succeeded` or contribute to `compromised_services`; the point is to demonstrate that spoofing has no effect, not
to simulate a working attack.

## Honest limits
* `target_service` in a step is the asset the step's INTENT targets (e.g. "database" for a dump step even though
  the HTTP request goes to product_api), not necessarily the literal HTTP endpoint — chosen so
  `compromised_services`/`attack_path` read the way contract E's examples do. The literal route is in `description`.
* `blocked_by.service` on an edge cut names the CALLER whose outbound edge was cut (consistent with
  `X-ACD-Service` set by `acdlib.dep_call`, established in V1/V2), not the service being called.
* Timing (`gap_s`, jitter) is seeded (`random.Random(seed)`) for reproducibility, but the numbers themselves
  (0.05-1.8 s) are arbitrary choices, not measured attacker behaviour.
* Scenarios run against the REAL local stack and controller code in this session (see `tests/test_v3_scenarios.py`);
  Docker-specific parts (real attacker containers, real network isolation mid-scenario) are unverified here.
