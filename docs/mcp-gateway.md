# MCP Gateway

Yabanin's **MCP aggregator** is a gateway-side proxy that lets an organization
expose *any* external Model Context Protocol (MCP) server to its agents — with
agent-only access control, per-agent tool allow-lists, an audit trail, identity
forwarding, upstream credentials (server-level + per-user lazy authorization),
observability, and parameter guards. It is **off by default**: the
whole route group is mounted only when `YABANIN_MCP_GATEWAY=1`.

> **The name is not the protocol.** Despite the "MCP gateway" name, what
> ships today is an **invoke API**: a plain HTTP endpoint
> `POST /api/mcp/invoke` (JSON request, agent key `yag_*`) that itself calls
> external MCP servers over JSON-RPC. **An MCP client cannot connect to
> it**: there is no `tools/list` and no client-facing MCP transport here.
> A native MCP endpoint on the gateway (a `tools/list` catalog and a
> Streamable HTTP server) is planned future work (cards **RM-100** and
> **RM-101**); until that lands, the aggregator's only programmatic
> interface is the invoke API described in §5.

> The **outbound partner bridge** described in §1 is a separate, already-shipped
> feature and is out of scope here. The bridge answers "agents call Yabanin
> tools"; the aggregator answers the inverse — "Yabanin agents call arbitrary
> external MCP servers", safely.

## 1. What exists today (out of scope for the aggregator)

Yabanin already ships an **outbound MCP partner bridge**
(`pkg/mcppartner`, `services/run/mcp.go`, binary subcommand `mcp`):

- **Transports:** stdio (Claude Code) and HTTP-SSE on `:8787`
  (`YABANIN_MCP_HTTP=1`).
- **Tools exposed:** `tr_route`, `tr_spend_report`, `tr_set_policy`,
  `tr_lineage_verify`, plus optional `tr_delegate` / `tr_delegation_status`.
- **Auth:** partner API key (`YABANIN_PARTNER_API_KEY`), sent as Bearer to the
  gateway `:8082` and admin `:8086`.
- **Upstream client:** bounded `http.Client` (30 s timeout); this client talks
  to Yabanin's own endpoints only — it never dials arbitrary user-supplied
  URLs.

The aggregator is the new work: server registry + access control, identity
forwarding, metrics, and parameter guards — all on the **gateway** data plane.

## 2. Behavior

- **Agent-only access.** A tool call is accepted only for an agent-principal
  key (`yag_*`, the agent-principal keys). A regular `yab_` API key has no agent
  identity and is rejected with `403 agent_only` before anything is looked up.
  The inbound `X-Agent-Id` header is **stripped on ingress** and re-set only
  from the resolved `yag_*` principal, so a client cannot spoof an agent.
- **Per-agent grants + tool allow-list.** An agent may invoke a server only if
  it holds an **enabled grant** for `(org, agent, server)`; a missing or
  disabled grant is indistinguishable from "server unavailable"
  (`404 not_found`) — an agent cannot enumerate which of its calls are
  grant-blocked. The **effective tool set** is the *intersection* of the
  server's allow-list (`mcp_servers.allowed_tools`, the ceiling) and the
  grant's allow-list (`mcp_server_grants.allowed_tools`). A `[]` on either side
  means "all of that side".
- **SSRF-guarded egress.** The upstream URL passes the `pkg/ssrf` guard
  (DNS allow-list + reserved-IP rejection) at registration **and again at every
  invoke** (the rebind window). The proxy follows no redirects and uses bounded
  connect/read timeouts.
- **Audit trail.** Every tool call is recorded to the **same** event stream the
  gateway uses for chat requests, so `loggerd` persists a `request_logs` row
  tagged with `task_id`, `agent_id`, and `upstream_url`. The row is labeled
  `ModelUsed = "mcp:<server>:<tool>"` (distinguishable from a model inference).
  The gateway does **not** write `request_logs` directly.
- **Identity forwarding.** The verified principal rides upstream as
  `X-Yabanin-Agent-Id`, `X-Yabanin-Agent-Name`, and `X-Yabanin-Team-Id`
  headers. These are **attribution, not authorization**: the external server
  may use them to attribute the call, but they are never a credential, and the
  gateway sets them only from the verified principal (never from the client).
- **Observability.** `gateway_mcp_calls_total{server,tool,outcome}` counts every
  call (success or failure); one OTel span per call (`mcp.tools/call`) carries
  `mcp.server` / `mcp.tool` / `mcp.org` / `mcp.agent_id` and the final
  `mcp.outcome`. Both are recorded even when no audit logger is wired.
  `gateway_toolpolicy_decisions_total{org,server,tool,outcome}` counts every
  guardrail decision (allow / deny / mask / flag / error — `error` is a
  fail-open policy-store outage, the call ran UNGUARDED).
- **Tool-call guardrails.** Tool **input** params pass the pre-egress guard hooks
  (`guardhooks.Scan`) with the modes inherited from `guard_mode`
  (`YABANIN_GUARD_MODE`: off / log / redact / deny). `redact` replaces detected
  secrets/PII before egress **and** before the audit trail (the original client
  params never reach the audit); `deny` drops the call (`409 denied`).
  On top of that, per-server **guardrail rules** (`tool_policies.rules`) add
  schema/size/regex checks on args and post-checks on results — see §7.

**Non-goals (for now)**

- stdio upstream servers (no process spawning on the gateway — a new host
  security surface; revisit after HTTP-SSE is proven).
- Cross-org server sharing — servers are per-org.
- Per-model **latency** on the comparison screen — the dashboard's Model
  comparison screen shows shadow-eval **cost** per model, **org-wide** latency
  percentiles (captioned as not per-model) and an evalgate-sampled **quality**
  section (ADL-04: per cheap/premium pair on the judged overlap + per task
  class, with a human-applied routing recommendation). Latency per model is
  not measured.

## 3. Architecture

```
agent (yag_* key, X-Yabanin-Task)
  │  POST /api/mcp/invoke   {"server":"knowledge","tool":"search","params":{...}}
  ▼
┌─────────────────────────── gateway proxy (:8082) ───────────────────────────┐
│ 0. agent-only: resolved yag_* principal, else 403 agent_only                │
│ 1. server row: enabled? (404 not_found)                                     │
│ 1b. grant: enabled grant for (org, agent, server)? (404 not_found)          │
│ 2. tool allowed? server allow-list ∩ grant allow-list (404 not_found)       │
│ 2c. toolpolicy guardrails: server-aware deny + args rules                   │
│     (schema/max_bytes/deny_regex) → 400 mcp_tool_blocked             │
│ 3. ssrf: AllowList re-check (400 ssrf_blocked)                              │
│ 4. guard: guardhooks.Scan(params) → off/log/redact/deny (409 denied)        │
│ 5. creds: resolve outbound auth — per-user active → server-level enabled    │
│    → none; 401/403 upstream → one force-refresh retry, else lazy            │
│    mcp_auth_required with the human flow URL (§6)                           │
│ 5b. proxy: JSON-RPC tools/call POST → upstream (bounded timeout)            │
│    headers: X-Yabanin-Agent-Id / X-Yabanin-Agent-Name / X-Yabanin-Team-Id   │
│ 6. record: gateway_mcp_calls_total{server,tool,outcome} + OTel span         │
│    + audit event → loggerd → request_logs (task_id, agent_id, upstream_url) │
│ 6b. toolpolicy result post-check (secrets/deny_regex: flag|mask|deny)       │
│     → 400 mcp_tool_blocked / redacted result                         │
└──────────────────────────────────────────────────────────────────────────────┘
  ▼
external MCP server (HTTP-SSE, e.g. an org's internal knowledge server)
```

The proxy lives in the **gateway** data plane (`:8082`, the `/api/mcp/...`
route group), not admin — agent traffic is data-plane. Admin owns the
`mcp_servers` CRUD and the per-agent grant CRUD; the gateway reads both via the
same store the org/routing settings use.

Default: **off**. The route group is compiled in but mounted only when
`YABANIN_MCP_GATEWAY=1` **and** a database pool exists. A deployment that sets
no new env var behaves exactly as before.

## 4. Data model

Two tables, both per-org:

```sql
-- Baseline 0001_init: the server registry.
CREATE TABLE mcp_servers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name          text NOT NULL,               -- [a-z0-9][a-z0-9_-]*
    display_name  text,
    url           text NOT NULL,               -- https://… (the SSRF-guarded host)
    transport     text NOT NULL DEFAULT 'http',  -- only 'http' is proxied
    allowed_tools jsonb NOT NULL DEFAULT '[]',  -- [] = all tools the server offers
    enabled       boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_mcp_servers_org ON mcp_servers (org_id) WHERE enabled;

-- Baseline 0001_init: per-agent grants (one row per agent per server).
CREATE TABLE mcp_server_grants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id      uuid NOT NULL REFERENCES agent_keys(id) ON DELETE CASCADE,
    server_name   text NOT NULL,               -- same name rules as mcp_servers
    allowed_tools jsonb NOT NULL DEFAULT '[]',  -- [] = every tool the SERVER allows
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, agent_id, server_name)
);
CREATE INDEX idx_mcp_server_grants_org_agent  ON mcp_server_grants (org_id, agent_id)  WHERE enabled;
CREATE INDEX idx_mcp_server_grants_org_server ON mcp_server_grants (org_id, server_name) WHERE enabled;
```

The grant references `agent_keys.id` (the agent principal). A grant is an
**authorization fact** (who may call what), not a credential — no secret
material. A disabled grant is inert until an operator enables it (the same
availability behavior as `mcp_servers.enabled`).

Migration `0007` adds the credential tables — `mcp_server_credentials`
(server-level) and `mcp_user_credentials` (per-`(server, agent)`) — described
in §6.

## 5. Endpoints

**Admin** (control plane, root-only auth, org-scoped):

```
POST   /api/organizations/{id}/mcp/servers                 create server
GET    /api/organizations/{id}/mcp/servers                 list servers
GET    /api/organizations/{id}/mcp/servers/{name}          get one server
PATCH  /api/organizations/{id}/mcp/servers/{name}          update (incl. enabled)
DELETE /api/organizations/{id}/mcp/servers/{name}          delete server

GET    /api/organizations/{id}/mcp/servers/{name}/grants               list grants
POST   /api/organizations/{id}/mcp/servers/{name}/grants               create grant
PATCH  /api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}    update grant
DELETE /api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}    revoke grant

PUT    /api/organizations/{id}/mcp/servers/{name}/credential           upsert server-level credential
GET    /api/organizations/{id}/mcp/servers/{name}/credential           read the masked row
DELETE /api/organizations/{id}/mcp/servers/{name}/credential           delete
```

The SSRF domain allow-list for server URLs is the deployment's
`YABANIN_MCP_ALLOWED_UPSTREAMS` (comma-separated exact domains or `*.suffix`;
empty = fail-closed, every host rejected). Grant creation requires the
referenced server to exist for the org (`404` otherwise) and returns `409` on
the unique-violation duplicate.

**Gateway** (data plane, agent auth `yag_*`):

```
POST /api/mcp/invoke     {"server":"knowledge","tool":"search","params":{...}}
→ 200 {tool result}      | 401 mcp_auth_required | 403 agent_only | 404 not_found
                         | 400 ssrf_blocked | 400 mcp_tool_blocked | 409 denied
                         | 504 timeout    | 502 upstream

POST /api/mcp/credentials/{server}    headers submit/rotate (per-user, grant ceiling)
POST /api/mcp/auth/{server}/begin     oauth: consent URL + pending row
GET  /api/mcp/auth/{server}/callback  oauth: code exchange (public — the IdP
                                      redirects the human's browser here)
```

A single invoke endpoint (not a per-server path) keeps the route table stable
as servers are added/removed; the server is a *value*, not a path segment.
`params` is the tool input object; the proxy serializes it into the upstream
JSON-RPC `tools/call` request. The response is either `application/json`
(single result) or `text/event-stream` (the result as the last data frame);
both are handled and collapsed to the final `result`. Tool calls are
request/response from the agent's perspective (no partial streaming).

| Code | HTTP | Meaning |
|------|------|---------|
| `agent_only` | 403 | the caller is not an agent-principal (`yag_*`) key |
| `mcp_auth_required` | 401 | no usable credential for the upstream (or the stored one is dead); the body carries `{"error":{"code":"mcp_auth_required","kind":"headers\|oauth","url":"/api/mcp/…"}}` — the human flow that resolves it (§6) |
| `not_found` | 404 | server missing/disabled, **or** no agent grant, **or** tool not on the effective allow-list |
| `ssrf_blocked` | 400 | the URL failed the per-invoke SSRF guard |
| `mcp_tool_blocked` | 400 | the tool-policy guardrails blocked the call or its result (deny policy, args schema/max-size/regex rule, or a deny-mode result post-check); the message names the failing check, never the matched value |
| `denied` | 409 | the parameter guard (`deny` mode) rejected the params |
| `timeout` | 504 | the upstream exceeded the read/connect timeout |
| `upstream` | 502 | the upstream returned non-2xx or a malformed body |

## 6. Upstream credentials (MC-1..3)

An upstream MCP server may require auth. The aggregator resolves outbound
credentials on every invoke through a fixed chain — **per-user (active) →
server-level (enabled) → none** — and never lets a credential widen the
egress surface: the SSRF allow-list check on the server URL runs *before*
any credential resolution, so a registered-but-disallowed host stays blocked
with or without a credential.

### Auth types

| Auth type | Who sets it | Resolution on invoke |
|---|---|---|
| `none` (`-`) | — | the call proceeds unauthenticated (the legacy behavior); the upstream verdict decides |
| `headers` (server-level) | admin via the admin API (`PUT …/credential`) | applied to every agent's invoke when enabled |
| `headers` (per-user) | the agent's human via the lazy flow (`POST /api/mcp/credentials/{server}`) | applied only for that `(server, agent)` pair, when `active` |
| `oauth` (server-level or per-user) | admin, or the lazy `begin`/`callback` flow | access token applied; a 401/403 upstream triggers exactly **one** force-refresh retry; a dead token becomes `needs_reauth` (sticky) |

### Lazy authorization (`mcp_auth_required`)

When no usable credential exists (or the stored one is dead), the invoke
answers `401` with a structured body:

```json
{"error": {"code": "mcp_auth_required", "kind": "headers",
           "url": "/api/mcp/credentials/knowledge"}}
```

`kind` names the credential kind that would satisfy the server (`headers` →
the submit endpoint, `oauth` → the begin endpoint) and `url` is the
human-relative path to start that flow. The submit/begin flows require an
agent-principal (`yag_`) key and honor `X-Audit-Reason`.

### Lifecycle statuses (per-user credentials)

| Status | Meaning |
|---|---|
| `pending` | the lazy flow started (oauth consent pending) |
| `active` | resolved and used on invokes |
| `orphaned` | the grant on the server was revoked — the credential is inert; re-granting restores it (`RestoreMCPUserCredentials`) |
| `needs_reauth` | the upstream terminally rejected the token (sticky until re-auth) |
| `needs_update` | the stored secret failed validation after an upstream change |

`version` increments on every rotation or status transition so the gateway
resolver cache invalidates immediately.

### Security invariants

- Plaintext secret material exists only as a call argument into
  store/resolve methods; **every read returns the masked row only**
  (`secret_last4`, `has_secret`) — no API response can carry the plaintext
  or the ciphertext, and no struct field could hold it.
- Secrets are encrypted at rest with the `enc:`-prefixed envelope
  (`pkg/encryption`, BYOK parity, migration `0007` tables). Writes are
  fail-closed: without a configured encryptor the write is refused — a
  missing encryption config can never silently downgrade to plaintext.
- Every operation runs in one transaction whose `app.current_org` GUC is
  pinned — the `org_isolation` RLS contract (ENABLE + FORCE,
  least-privilege role). A foreign org's rows are invisible and unwritable.
- Every CRUD/status step lands in the hash-chained audit journal.
- Plaintext is bounded (8 KiB per secret payload) and never logged or
  serialized by the proxy.
- A per-user upsert requires an **enabled grant** on the server — the grant
  stays the ceiling for every flow step (see
  [Agent governance](agent-governance.md#mcp-grants-and-per-user-credentials)).

## 7. Tool-call guardrails

On top of the plain allow/deny registry ([Tool policies](tool-policies.md)),
a `tool_policies` row may carry a `rules` document evaluated at the
(org, server, tool, subject) granularity:

- **Args guards** run pre-egress: a JSON-Schema (draft 2020-12) on the
  serialized args, a `max_bytes` size cap and `deny_regex` RE2 patterns. A
  violation blocks the call with `400 mcp_tool_blocked` before any upstream
  traffic.
- **Result post-checks** run on the serialized upstream result: the
  `guardhooks` secret/PII/injection detectors and custom `deny_regex` with a
  per-rule mode `flag | mask | deny` — mask returns the redacted result,
  deny drops it with `400 mcp_tool_blocked`.

Matching rules compose **union + most-restrictive** (a rule can only add
restrictions); every finding carries only the check source and a span/JSON
pointer — matched values never appear in errors, findings or metrics. Fail
modes are per rule (`fail: closed|open`, default closed): once an org
declares a fail-closed rule, a policy-store outage blocks guarded invokes
until the store recovers. No `rules` on any row = the pre-guardrail
behavior, bit-for-bit.

Decisions are counted in `gateway_toolpolicy_decisions_total{org,server,tool,outcome}`
(`error` is a fail-open policy-store outage — the call ran UNGUARDED).

## 8. Risk matrix

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| R1 | **SSRF**: org registers `http://169.254.169.254/…` or a DNS-rebinding host pointing at cloud metadata / internal services | High | `pkg/ssrf` `AllowList.ValidateUpstream` (DNS allow-list + reserved-IP rejection) at *registration* and again at *every invoke* (the rebind window); no redirects followed; static deployment allow-list for domains (`YABANIN_MCP_ALLOWED_UPSTREAMS`) |
| R2 | **Prompt-injection / tool-weaponization**: a model-induced tool call exfiltrates org data via a malicious external server's tool schema or params | High | agent-only access, per-agent grants, per-server tool allow-list (intersection), guard hooks on params, org toolpolicy deny policies + args rules (schema/max-size/regex) pre-egress, default OFF, audit trail with redacted params; per-agent budgets bound the blast radius of repeated calls |
| R3 | **Secret egress**: params carry org API keys / PII to an external server | Medium | `guardhooks.Scan` (incl. national PII detectors) in `redact`/`deny` mode per `guard_mode` before egress; `deny` drops the call with 409 + audit event; Tool-result post-checks (secrets detectors, flag/mask/deny per rule) stop secret-laden tool RESULTS from reaching the agent |
| R4 | **Credential leakage**: storing per-server upstream tokens in Postgres | Medium | secrets only as `enc:`-encrypted envelopes at rest (fail-closed writes without an encryptor); RLS org isolation (`app.current_org` GUC); reads return masked rows only (`secret_last4`/`has_secret` — plaintext never crosses the API); every CRUD/status step in the hash-chained audit journal; a credential never widens egress (SSRF check precedes resolution) (§6) |
| R5 | **Denial of service / cost**: an agent loops tool calls; upstream bills per call | Medium | per-agent token/spend budgets inherited; bounded proxy connect + read timeouts; `gateway_mcp_calls_total` makes loop rates visible |
| R6 | **Identity spoofing**: upstream trusts `X-Yabanin-Agent-*` headers forged by an org's own agent | Low | headers are *attribution*, not authorization; the gateway never forwards caller-supplied values of these headers (stripped on ingress, set from the verified agent principal) |
| R7 | **Audit gap**: tool call happens but is not logged | Medium | the call is answered regardless of audit (availability over audit); the `gateway_mcp_calls_total` metric and OTel span are recorded even when the audit publish is dropped, so a gap is visible |
| R8 | **SSE stream hijack / slow-loris upstream** | Low | bounded read timeout on the SSE body, max response size, no idle keep-alive reuse to user-supplied hosts beyond the standard pool |
| R9 | **Dependency**: MCP client surface for HTTP-SSE | Low | a thin client wrapper (JSON-RPC over HTTP/SSE) so the transport layer is swappable; security gate on every change |
| R10 | **Scope creep into stdio upstreams** (process spawning on the gateway) | Medium | explicit non-goal (§2); stdio remains outbound-bridge-only |

## 9. Security invariants (checked by the repo security gate on every aggregator change)

1. No user-controlled URL reaches `http.Client` without passing the SSRF
   guard twice (registration + invoke) — and always **before** credential
   resolution, so a credential cannot extend egress.
2. Credential secrets are stored only as `enc:` envelopes, read back only as
   masked rows (`secret_last4`/`has_secret`) under org-isolation RLS, and
   every mutation is audited; no secret material is stored in
   `mcp_servers` / `mcp_server_grants` or logged un-redacted; audit events
   carry `params-redacted`.
3. Agent identity comes only from the verified `yag_*` principal; the
   `X-Yabanin-Agent-*` headers are set by the proxy and stripped from inbound
   requests.
4. The feature is OFF by default (`YABANIN_MCP_GATEWAY` unset ⇒ route group
   not mounted ⇒ zero behavior change).

## 10. Configuration reference

| Env var | Default | Meaning |
|---------|---------|---------|
| `YABANIN_MCP_GATEWAY` | unset (off) | `1` mounts the `/api/mcp/invoke` route group (requires a DB pool). |
| `YABANIN_MCP_ALLOWED_UPSTREAMS` | empty | Comma-separated exact domains or `*.suffix` the upstream URL host must match. Empty = fail-closed (every host rejected). |
| `YABANIN_GUARD_MODE` | `off` | `off` / `log` / `redact` / `deny` — the parameter-guard mode applied to tool inputs (inherited from the chat-path guard hooks). |

Deployment wiring: the admin service parses
`YABANIN_MCP_ALLOWED_UPSTREAMS` from the environment (`config.Load("")` is
env-only — a mounted config.yaml is not read) and passes the list to the
registry CRUD; the gateway parses the same variable for the invoke-time
re-check, the credential-token-URL guard and the server-side tool executor —
ONE list governs registration and every dial-out. In compose deployments the
variable must therefore be passed to BOTH the `admin` and the `gateway`
services in your deployment manifests. The public export does not provide a
production Compose environment renderer; verify the effective environment in
both running services. An empty or unset list means registration answers 400
(`host not in the allowed domains list`) — fail-closed by design, not a malfunction.

## 11. Acceptance summary

| Component | Acceptance |
|-----------|------------|
| Registry + proxy | `mcp_servers` CRUD in admin; invoke proxy for HTTP-SSE; default OFF; SSRF guard on register + invoke; bounded timeouts; tests cover redirect-deny, reserved-IP, timeout |
| Access + audit | invoke rejects non-`yag_` keys (`403 agent_only`) and non-granted agent/server/tool (`404`); every call → `request_logs` row with `task_id`/`agent_id`/`upstream_url` + audit event (redacted params), labeled `mcp:<server>:<tool>`; grant CRUD in admin |
| Identity | upstream receives `X-Yabanin-Agent-Id` / `-Name` / `X-Yabanin-Team-Id`; inbound copies stripped; values come from the verified principal |
| Observability | `gateway_mcp_calls_total{server,tool,outcome}` present under `/metrics`; one OTel span (`mcp.tools/call`) per call with server/tool/outcome attrs |
| Parameter guards | params pass `guardhooks.Scan`; `redact` mode replaces secrets; `deny` mode drops the call (409) + audit; modes inherited from `guard_mode` |
| Tool-call guardrails | `tool_policies.rules` (args schema/max_bytes/deny_regex pre-egress; result secrets/regex flag/mask/deny post-egress); schema violation → `400 mcp_tool_blocked` before any upstream traffic; secret in result → masked or denied per rule; findings carry spans/categories only (value-free, pinned by tests); `-race` green on Decide/Guard concurrency; org rules isolated per org |
| Upstream credentials (MC-1..3) | server-level + per-user creds as `enc:` envelopes under org-isolation RLS; masked reads only; invoke resolves per-user → server-level → none with one refresh retry; lazy `mcp_auth_required` with the human flow URL; grant ceiling + orphaning/restore; audit journal on every CRUD/status step |
| Model comparison screen | dashboard compare screen (`#compare`): per-model shadow-eval cost + org-wide latency (captioned not per-model) + evalgate-sampled quality per pair/task-class (ADL-04) with a human-applied routing recommendation; applied-scope captions; renders on all viewports |
