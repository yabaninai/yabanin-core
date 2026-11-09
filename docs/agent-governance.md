# Agent Governance

Agents are a first-class principal in Yabanin. An *agent* is a machine identity
(an automated worker, a CI pipeline, an OpenCode session) that authenticates the
same way a human's API key does — but is tracked separately so you can budget,
tag, and analyze its spend independently of any team.

This page covers the six pieces that make agents governable:

1. **Agent keys** (`yag_*`) — the credential an agent uses.
2. **Per-agent budgets** — a hard daily spend cap per agent.
3. **Task tagging + token budgets** — attribute spend to a logical task and cap
   tokens per task / per session.
4. **Guard hooks** — deterministic pre-egress PII / secret / injection checks.
5. **Delegated (child) keys** — time-boxed, grant-limited, budget-capped keys
   an agent's operator mints for sub-tasks.
6. **Agent profiles** — a role object (tier hint + grant template + budget cap
   + guard mode) a key is issued against.

Defaults are feature-specific. The decision response header is enabled by
default; task token caps default to zero (disabled). Consult each feature
section and the configuration table before enabling additional controls.

---

## Decision header

The gateway emits a machine-readable routing decision as the
`X-Yabanin-Decision` response header (and, when enabled, on the analytics
event). The header is a compact JSON object describing *why* the request landed
on the model it used:

```
X-Yabanin-Decision: {"source":"tier_router","class":"easy","confidence":0.92,"threshold":0.7,"from":"gpt-4o","to":"gpt-4o-mini","reason":"time_window_downgrade"}
```

| Field | Meaning |
|---|---|
| `source` | Who chose the model: `cache_exact`, `cache_semantic`, `tier_router`, `rule_override`, or `passthrough`. |
| `class` | Classifier class used (`easy` / `medium` / `hard`); empty when no classifier ran. |
| `confidence` | Classifier confidence [0..1]; 0 when no classifier ran. |
| `threshold` | Per-org routing threshold the confidence was compared against. |
| `from` | The model the decision moved **from** (client-requested or pre-override). |
| `to` | The model the decision moved **to**. |
| `reason` | Optional free-form reason, e.g. `always_premium`, `always_cheap`, `time_window_downgrade`. |
| `affinity` / `preferred` | KV-cache-aware session-affinity outcome (`used` / `miss`) and the preferred warm model. |

Enable/disable the header with `YABANIN_DECISION_HEADER` (default on) and the
analytics-event copy with `YABANIN_DECISION_EVENT` (default on).

---

## Agent keys

Agent keys are a separate credential class from API keys. They are created and
revoked through the **admin API** (the `yb` CLI does not manage them):

```
POST   /api/agent-keys                 {"name": "nightly-etl", "org_id": "<org>"}   → 201
GET    /api/agent-keys?org_id=<org>
GET    /api/agent-keys/<id>
POST   /api/agent-keys/delegate        mint a delegated child key (below)
POST   /api/agent-keys/<id>/revoke
GET    /api/agent-keys/<id>/budget     read the agent's daily budget
PUT    /api/agent-keys/<id>/budget     upsert (daily_limit_cents)
DELETE /api/agent-keys/<id>/budget     remove (returns the agent to denied)
```

`POST /api/agent-keys` generates a `yag_` key and returns the **plaintext
exactly once** in the response; only its `sha256` is stored. Example of the
returned key (shape: `yag_` + 32 hex chars):

```json
{
  "key": "yag_9f2c1a4b7e8d30f6a5c9b2d1e4f7a8c3",
  "key_id": "8d4f…",
  "name": "nightly-etl",
  "org_id": "…",
  "active": true
}
```

An agent authenticates by sending the key as the `Authorization: Bearer <yag_…>`
credential. On a match the gateway:

- sets the request's `org_id`, `agent_id` (the principal), and any team scope;
- tags `request_logs` with `agent_id` so spend is attributable;
- enforces the per-agent budget if one is configured.

Agent keys are revocable (soft delete: `active=false`, `revoked_at` stamped). A
revoked key fails authentication.

### Per-agent budgets

Configure a daily limit per agent in the `agent_budgets` table
(`agent_id`, `daily_limit_cents`). Behavior (fail-safe, mirrors team budgets):

| Condition | Result |
|---|---|
| No `agent_budgets` row for the agent | **403** `agent_budget_not_configured` — an agent without a budget may not spend. |
| Daily spend ≥ limit | **429** `agent_budget_exceeded` — retry later. |
| Budget store unavailable | **503** `agent_budget_check_unavailable` — fail closed (never allow unbounded spend during a DB outage). |
| Within limit | request proceeds; spend is recorded in `agent_spend_daily (agent_id, day)`. |

Agents **without** a configured row are denied, so enabling per-agent budgets is
a deliberate act: create the row for each agent you authorize to spend.

### Delegated (child) keys

An agent's operator can mint a **child key** for a bounded sub-task without
handing out the parent credential:

```
POST /api/agent-keys/delegate
{"parent_agent": "<agent-key id>", "org_id": "<org>", "name": "subtask-render",
 "ttl": 86400, "budget_caps": 500, "mcp_grants": ["knowledge"]}
```

(`ttl` is seconds, capped at 90d; `mcp_grants` lists **server names** the
child may call — each intersected with the parent's granted servers.)

The child key is the same `yag_` shape and authenticates like any agent key.
Invariants (enforced at mint time, TTL at resolve time):

| Invariant | Enforcement |
|---|---|
| Grants ⊆ parent's enabled grants | the stored grants are the **intersection** of the requested set with the parent's — a child can never widen what its parent may call |
| Child budget ≤ parent's headroom | the delegation is refused when it would exceed the parent's remaining daily limit |
| Parent must be budgeted | a capped delegation requires the parent to have a configured `agent_budgets` row (an unbudgeted parent cannot grant caps it does not have); the request is refused, not silently capped |
| Headroom formula (mint time) | `child_cap ≤ parent_limit − parent_spend_today − Σ(active, non-expired sibling caps)`, checked atomically under the per-org advisory lock with the parent row locked (`FOR UPDATE`); sibling caps count only while their keys are active |
| Inherited limits (spend time) | every spend also walks the delegation chain (depth ≤ 4) and fails closed if any ancestor's subtree spend — parent plus all children — has reached the ancestor's limit (**429** naming the ancestor); a cycle in `parent_id` is a configuration error and fails closed |
| Time-boxed | `expires_at` is checked in the key **resolver** on every request: an expired child key fails authentication, and the expired outcome is never cached (no TTL drift) |
| Attribution | spend lands on the child's own `agent_id` (`agent_spend_daily`), reportable to the parent by task tag |
| Structure | `parent_id` is stamped — a child is always a child; only root keys (no parent) can delegate |

### Agent profiles

A **profile** bundles the role settings a class of agents shares — a routing
**tier hint**, a template of **MCP grants**, a **daily budget cap** (cents)
and a **guard mode** — so issuing a key against the profile inherits all of
them instead of configuring each key by hand:

```
POST   /api/agent-profiles           {"name": "ci-runner", "tier_hint": "cheap", ...}
GET    /api/agent-profiles
GET    /api/agent-profiles/<id>
PUT    /api/agent-profiles/<id>
DELETE /api/agent-profiles/<id>
```

`POST /api/agent-keys` with `profile_id` issues the key **on the profile**:
the budget row is created from the profile's cap and the MCP grants are
applied from the template. Invariant: the profile's grant template can never
reference a server the org has not registered (grants ⊆ the org's own
registry) — issuing never widens the org's blast radius.

### MCP grants and per-user credentials

An MCP grant (`mcp_server_grants`) is what an agent may call; an MCP
**credential** is how the call authenticates upstream. The grant is the
ceiling for every credential flow step (details in
[MCP gateway §6](./mcp-gateway.md#6-upstream-credentials-mc-13)):

- A per-user credential can only be submitted (headers) or begun (oauth)
  while the agent holds an **enabled** grant on that server — the store
  enforces it on submit, begin and token writes.
- Revoking the grant **orphans** the credential (status `orphaned`): the
  row and its `enc:`-encrypted secret stay, but no invoke uses it.
  Re-granting the same `(server, agent)` pair **restores** the credential —
  the human does not have to re-authorize.
- A child key's `mcp_grants` (see delegated keys above) intersect with the
  parent's, so a delegated agent can never hold a credential flow wider
  than its parent's grants.

Grant ceiling, never a widening: credentials resolve per invoke
(per-user active → server-level enabled → none) and can never extend the
SSRF-guarded egress surface.

---

## Task tagging & token budgets

### `X-Yabanin-Task`

Send the `X-Yabanin-Task` header to attribute a request to a logical task
(e.g. a batch job, a feature, a tenant's workload). Format:
`[A-Za-z0-9._:-]{1,128}`. An untagged request is fine — it lands in the
`'(untagged)'` bucket in analytics. An invalid value is rejected with **400**
`invalid_task_id`.

Task tags feed:

- **per-task token budgets** (below), and
- **CTOR / task cost analytics** — `GET /api/analytics/tasks?group_by=task`
  and the dashboard's **Tasks** screen (grouped cost / counterfactual /
  savings per task, with CSV export for chargebacks).

### `Yabanin-Task:` commit trailer + `YABANIN_TASK` CI env

For agentic development (one agent-driven task → one or more commits → one
PR), the task tag is carried on the **commits themselves** so the PR's spend
is reconstructable from git:

1. **Trailer convention.** Add a `Yabanin-Task:` trailer to every commit the
   task produces (value = the task tag, `[A-Za-z0-9._:-]{1,128}`, same format
   as the `X-Yabanin-Task` header):

   ```
   git commit -m "feat: …" -m "Yabanin-Task: a142-add-login"
   ```

   A `git trailer` (not a free-form body line) is what `git interpret-trailers`
   and the CI check below rely on.

2. **Tag the actual requests.** For a shared gateway, send
   `X-Yabanin-Task: a142-add-login` with each model request, use `yb ci exec`,
   or configure the key's `task` label. Setting an environment variable only
   in a remote agent's shell does not transmit a header automatically.

   A dedicated gateway process can instead use a deployment-wide fallback:

   ```sh
   export YABANIN_TASK=a142-add-login
   # Start the dedicated gateway in this environment.
   ```

   The gateway reads this setting at startup and applies it where no
   higher-priority task tag is present. Do not use a per-task fallback on a
   shared gateway that handles unrelated tasks. The resolved tag lands in
   `request_logs.task_id`, connecting Tasks analytics with the commit trailer.

The pairing is what makes the PR cost auditable: *trailer* on the commits
(what was shipped under the tag) + *request tag* on the traffic (what the tag
spent). The Tasks screen's CSV export (group, cost, counterfactual, savings,
cache hits, request count) is the chargeback-ready artifact for that number.

### Token budgets (per task / per session)

Optional in-memory cumulative token caps over a 24-hour window:

| Env | Default | Meaning |
|---|---|---|
| `YABANIN_TASK_TOKEN_BUDGET` | `0` (off) | Token cap per `X-Yabanin-Task`. Recommended starting value: **500000**. |
| `YABANIN_SESSION_TOKEN_BUDGET` | `0` (off) | Token cap per `X-Session-Id`. Recommended starting value: **200000**. |

`0` means that scope is **off** (no state is built, zero behavior change). When
a cap is set:

- **Before forwarding**, the gateway checks the running total. At or above
  **80%** of the cap it sets the response header
  `X-Yabanin-Budget-Warning: token budget at or above 80%` and lets the request
  through (a heads-up, not a stop). At or above **100%** it returns **429**
  `token_budget_exceeded` with a `Retry-After` header.
- **After the response**, it records the final token usage (prompt + completion)
  against both the task and session budgets. This runs on **both** the chat and
  streaming paths.

The 429/warning semantics are the same as the other budget gates: a warning is
non-fatal, an exceed is a structured 429 the client can back off on.

---

## Guard hooks

Guard hooks run **pre-egress** on the outbound model response and the inbound
prompt. They are deterministic regex/checksum detectors for sensitive data and
prompt injection — **not** a DLP system (see the caveat below).

Modes (`YABANIN_GUARD_MODE`, default `off`):

| Mode | Behavior |
|---|---|
| `off` | No scanning (default). Zero overhead. |
| `log` | Detect and emit a metric/log; do not alter the response. |
| `redact` | Replace detected spans with a placeholder before the response is returned. |
| `deny` | Reject the request (400 `guard_denied`) when a detection fires. |

Detected **categories** include (non-exhaustive):

- **PII**: INN (10/12-digit Russian taxpayer ID, with check-digit validation),
  SNILS (social-security number, with control digits), and PAN (Luhn-valid
  payment card numbers).
- **Secrets**: private key material (PEM header detection), high-entropy
  token/key patterns.
- **Prompt injection**: a small set of high-precision patterns (instruction
  override / exfiltration phrasing).

### False-positive limitations

The detectors are intentionally **conservative**: a bare 10- or 12-digit run of
digits is only flagged when it also passes the corresponding check-digit / Luhn
validation, so ordinary numbers (IDs, phone numbers, amounts) are not flagged.
This keeps the false-positive rate low, but it is not zero — and it is **not a
data-loss-prevention control**. Guard hooks are a *guardrail* that surfaces and
can block obvious sensitive data; they do not guarantee that no sensitive data
ever leaves. Regulated deployments should pair them with egress filtering and
the residency/lineage controls.

---

## CTOR / task cost analytics

`GET /api/analytics/tasks` returns, per group, the real cost, the
**counterfactual** cost (what the same work would have cost at the premium
tier), the resulting savings, and cache hits:

```
GET /api/analytics/tasks?org_id=<org>&from=<RFC3339>&to=<RFC3339>&group_by=task&limit=100
```

- `group_by` is `task`, `session`, or `agent` (default `task`).
- `from` / `to` are RFC3339 (defaults: last 24h → now).
- `limit` is capped at **500** (default 100); groups are ordered by cost
  descending.
- Rows with no group value fall into the `'(untagged)'` bucket.

Example (one group):

```json
{
  "org_id": "…",
  "from": "2026-09-01T00:00:00Z",
  "to": "2026-09-02T00:00:00Z",
  "group_by": "task",
  "groups": [
    {
      "group": "nightly-etl",
      "cost_usd": 10.0,
      "counterfactual_usd": 20.0,
      "savings_usd": 10.0,
      "cache_hits": 5,
      "request_count": 50
    },
    { "group": "(untagged)", "cost_usd": 3.0, "counterfactual_usd": 6.0, "savings_usd": 3.0, "cache_hits": 1, "request_count": 10 }
  ],
  "total_cost_usd": 13.0
}
```

`counterfactual_usd` is the recorded estimate for the premium-tier baseline.
`savings_usd` compares that baseline with recorded routed cost; it is a
counterfactual estimate, not a measured reduction in a provider invoice.
Interpret it together with price coverage, usage reporting and the selected
baseline.

---

## Environment reference

| Variable | Default | Purpose |
|---|---|---|
| `YABANIN_GUARD_MODE` | `off` | Guard hooks mode: `off` / `log` / `redact` / `deny`. |
| `YABANIN_TASK_TOKEN_BUDGET` | `0` | Per-task token cap (0 = off). |
| `YABANIN_SESSION_TOKEN_BUDGET` | `0` | Per-session token cap (0 = off). |
| `YABANIN_TIME_ROUTING` | `false` | Enable cheap-hours / batch tier downgrade. |
| `YABANIN_TIME_CHEAP_WINDOW` | `22:00-07:00` | Cheap window (`HH:MM-HH:MM`, may cross midnight). |
| `YABANIN_DECISION_HEADER` | `true` | Emit `X-Yabanin-Decision` response header. |
| `YABANIN_DECISION_EVENT` | `true` | Carry the decision on the analytics event. |

Headers a client can send:

| Header | Purpose |
|---|---|
| `X-Yabanin-Task` | Attribute the request to a logical task (feeds token budgets + analytics). |
| `X-Yabanin-Batch: true` | Force a cheap-tier downgrade (batch work). |
| `X-Yabanin-Priority: high` | Opt out of cheap-hours downgrade for this request. |
| `X-Session-Id` | Session identity (feeds the session token budget). |
