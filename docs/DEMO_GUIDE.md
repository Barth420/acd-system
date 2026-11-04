# ACD — explaining the code and demoing it to your professor

One doc, three jobs: (1) what each piece of code actually does, in plain words, (2) an exact script for a
live demo, (3) answers to the questions you'll likely get asked. Read section 2 the night before and rehearse
it once end to end — the timings below assume you have.

---

## 1. What this project is, and what each piece of code does

**The idea in one sentence:** when an attack hits one microservice, don't just block that service — figure out
which *other* services are connected to it, cut them off from the compromised one too (so the attack can't
spread), while everything unrelated keeps running, then reconstruct what happened afterward.

Three people, three parts, one shared contract (the exact service list, modes, and APIs every part agrees on
— see `vitrag/hierarchy/shared/topology.json` and `docs/vitrag/LAB.md` §"Architecture").

### Part 1 — the lab (Vitrag): a fake-but-real company to attack

`vitrag/hierarchy/` — 8 real services (Flask apps + Postgres + Redis), arranged in tiers: a gateway (`nginx`)
in front, 4 business services (`auth_api`, `product_api`, `order_api`, `search_api`), and 3 backing stores
(`database`, `cache`, `queue`). Each one depends on some of the others — e.g. `order_api` needs `auth_api`
(to check who's logged in) and `database` and `queue`.

- **`controller/`** — the thing that can actually *do* something to the lab: set a service to a degraded mode
  (`rate_limited` / `read_only` / `fallback` / `isolated`), cut the network link between two services, rotate
  a leaked credential, or run a scripted attack. This is the only thing with the power to change the lab.
- **`attacker/agent.py`** — two little programs (`attacker-1`, `attacker-2`) that actually send the attack
  traffic, each from its own IP address, on command from the controller.
- **`controller/scenarios.py`** — 7 canned attack scenarios (S0–S6) it can run on demand, e.g. "S2: SQL
  injection on `product_api`, then credential reuse on `auth_api`, then a database dump." Every step records
  whether it *actually* succeeded, got blocked, or just failed — read from the real HTTP response, never
  assumed.
- **`forwarder/`** — tails the services' log files and turns suspicious lines into alerts, the same shape a
  real SIEM (Wazuh) would produce.
- **`controller/ui/`** (`:8100/ui`) — a control panel: the service map with live colors, buttons to manually
  degrade/isolate a service, the scenario launcher, and a live results table as a scenario runs.

### Part 2 — the brain (Bhavya): decide what to do, and explain why

`bhavya/pipeline/` — receives alerts from the forwarder and decides how to respond.

- **`normalizer.py`** — turns a messy raw alert (Wazuh-shaped JSON) into a clean, typed record: which
  service, what kind of attack, how severe.
- **`containment/planner.py`** — **the core decision.** A small, fixed rule table (not a black box): severity
  → how hard to degrade the compromised service, plus "cut the inbound edge from everything that calls it
  directly" (and, if fully isolated, "cut its own outbound links too, so it can't be used to pivot further
  in"). Every decision writes down *why* in plain English.
- **`containment/manager.py`** — actually calls the lab controller (Part 1) to carry out the decision, and
  records whether each individual action really succeeded.
- **`containment/brain.py`** — an *optional*, clearly-labeled add-on: a short explanatory sentence next to
  each decision. Default is a template sentence (not an LLM, says so outright); it *can* load a real
  fine-tuned language model instead, but that model only ever adds context — it never makes the decision.
- **`forensics.py`** — after the fact, walks back through stored alerts to answer "where did this start, and
  what did it touch, in what order?"
- **`pipeline/ui/`** (`:8000/ui`) — the dashboard: live service map, the list of containment decisions with
  their reasoning, and the forensics timeline.

### Part 3 — the brain's brain (Parth): the language model

`qwen_stage1/`, `inference/`, `config.py` — a Qwen3-4B language model, adapted (not fully trained) on
Windows security-event text. **Be precise about this when you present it:** it is a *domain-adapted* model
that got better at predicting the next word in this kind of text, not a trained classifier — it has not been
shown to reliably detect attacks or assign correct labels. It plugs into Part 2's `brain.py` as the optional
explanation add-on, never as the decision-maker.

---

## 2. The live demo script

**Total time: ~12–15 minutes.** Do this in order. Have three terminal tabs and two browser tabs ready before
your professor sits down.

### Before she arrives (5 min, do this alone)

```bash
cd vitrag/hierarchy
scripts/up.sh                 # starts the 8-service lab + controller + alert sink (no Wazuh)
scripts/smoke.sh              # confirms everything actually came up — watch for "SMOKE PASSED"
```

```bash
cd ../../bhavya
pip install -r requirements.txt
ACD_CONTROLLER_URL=http://localhost:8100 ACD_AUTONOMY=auto \
  uvicorn pipeline.main:app --host 0.0.0.0 --port 8000 --reload
```

Open two browser tabs: `http://127.0.0.1:8100/ui` (the lab console) and `http://127.0.0.1:8000/ui` (the
dashboard). Confirm both say "controller: up" / "pipeline: up" in green. If either is red, fix it now, not
in front of her — see §4 below.

### Do I need to open Wazuh? **No.**

Wazuh is optional and sits behind a separate profile (`scripts/up.sh --wazuh`) specifically so the default
demo doesn't depend on a ~3GB SIEM stack. The forwarder already turns log lines into real alerts without it.
**Don't open it unless she specifically asks about SIEM integration** — if she does, see §5, last item.

### Minute 0–2 — orient her

On the lab console (`:8100/ui`), point at the graph: "This is a small company — a gateway, four services,
three backing stores. Each arrow is a real dependency: `order_api` calls `auth_api`, `database`, and `queue`."
Switch to the dashboard (`:8000/ui`), same graph: "This side watches for attacks and decides what to do."

### Minute 2–5 — run a real attack

On the lab console, **Scenarios** panel: pick **S2 — SQL injection on product_api, credential reuse on
auth_api, database dump**, leave seed blank, click **Run**. Narrate while it plays (it takes a few seconds):
"A real attacker process is sending real HTTP requests at this lab right now — SQL injection against
`product_api`, then it reuses a leaked key against `auth_api`'s internal admin route, then pulls data out."

Switch to the dashboard, **Containment** tab. New decision cards should already be appearing.

### Minute 5–9 — this is the actual point of the project

Open the `product_api` decision card and read the rationale out loud — it names the attack, the service, why
that mode was chosen, and which other services had their connection to it cut, and why. Then:

1. Switch to **Overview**: the graph now shows `product_api`/`auth_api` in red/orange with dashed red lines —
   the edges that got cut. "These three other services physically can't reach the compromised one anymore."
2. Point at an *untouched* service (e.g. `search_api`): "This one has nothing to do with `product_api`, so it
   was never touched — it's still serving normally." This is the "don't break what isn't broken" half of the
   pitch; say it explicitly.
3. Open the **"What the LLM said"** box on a decision card and read the caveat line out loud yourself: *"This
   text is advisory only. The mode and edge cuts above were decided by the deterministic planner, not by this
   text."* This is a strength, not a weakness — say so: "We deliberately don't let the language model make
   security decisions; it only explains them for a human."

### Minute 9–12 — forensics

Dashboard → **Forensics** tab → **Reconstruct**. Point at the timeline: "This isn't live monitoring, it's
looking backward through what was stored — which service was hit first, what it led to, in what order,
confirmed by the graph overlay." Note the dashed vs solid edges if any appear: "Dashed means we inferred that
hop; solid means we actually observed the alert on that service."

### Minute 12–15 — optional second pass, if time allows

- **Reset the lab** (console → Reset lab button), then run **S1 — Brute force then stolen session on
  order_api** to show a *different* shape of attack and a different decision (several failed login guesses
  first, outcome `failed` not blocked, then the one that works).
- Or switch autonomy to `approve` mode (`POST /api/autonomy {"autonomy":"approve"}` or just mention it) and
  explain the decision would wait for a human click instead of firing automatically — useful if she asks
  "what if it's wrong?"

---

## 3. One sentence each, if she asks "what does X do?"

| She points at... | You say |
|---|---|
| The lab (`:8100`) | "This is the target — a real small system we built to attack safely." |
| The controller | "The only thing allowed to change the lab — degrade a service, cut a link, run a scenario." |
| The forwarder | "Turns suspicious log lines into alerts, the same shape a real SIEM produces." |
| The planner | "A fixed, readable rule table — not a black box — that decides how hard to degrade a service and which connections to cut." |
| The brain / LLM box | "Optional. Explains a decision in plain English. Never makes the decision." |
| Forensics | "Looks backward through stored alerts to answer 'where did this start, what did it touch.'" |
| Wazuh | "A real SIEM we support, but it's optional — the demo works without it." |

---

## 4. If something breaks right before she arrives

- **A tab says "unreachable"**: the relevant process isn't running — re-run the start command for that part
  from §2.
- **`scripts/smoke.sh` fails**: don't try to debug live. Restart clean: `docker compose up -d --force-recreate`
  in `vitrag/hierarchy/`, wait 20s, re-run `smoke.sh`.
- **A scenario shows every step as `failed` instead of `succeeded`/`blocked_by_containment`**: the lab gateway
  (`nginx`) probably isn't actually serving — check `docker compose ps`, it should say `Up`, not `Restarting`.
- **Nothing to fall back on?** Everything in §2 also runs without Docker at all via
  `vitrag/hierarchy/scripts/local_stack.py` — slower to explain but a safe backup if Docker itself is the
  problem on the day.

---

## 5. Honest answers to likely questions

Don't oversell these — the project's own docs are blunt about them on purpose, and it reads better to say so
yourself than to get caught by a follow-up question.

- **"How did you pick these thresholds (which severity → which mode)?"** — "They're defaults we chose and
  documented as defaults, not measured or trained values. That's written directly in
  `docs/bhavya/CONTAINMENT.md` and the code's own docstring."
- **"Is the LLM detecting the attack?"** — "No. The attack type and severity come from the alert itself
  (the rule that fired). The LLM only adds an explanation sentence after the decision is already made."
- **"Have you trained an actual classifier?"** — if you haven't yet: "Not yet — that's a planned next step
  using labeled datasets like UNSW-NB15; right now detection is rule/signature-based, same as a real SIEM."
  If you have by the time of the demo, show its precision/recall/F1 honestly, including what it gets wrong.
- **"Does this work with a real SIEM?"** — "Yes — Wazuh integration exists and is tested, it's just switched
  off by default to keep the demo lightweight." If she wants to see it: `scripts/up.sh --wazuh && scripts/start-wazuh.sh`,
  then open `https://localhost:5601` (admin / SecretPassword) and show an alert landing there too — budget
  an extra 2–3 minutes for Wazuh's own startup time if you do this.
- **"What happens if the containment decision is wrong?"** — "Two answers: switching `ACD_AUTONOMY` to
  `approve` makes every decision wait for a human click before it executes anything; and separately, cut
  edges and modes can always be manually restored from the lab console."
- **"Is this running in a real cloud / production environment?"** — "No — everything is local, bound to
  `localhost`, built explicitly as a safe, isolated lab. That's a stated constraint, not an oversight."
