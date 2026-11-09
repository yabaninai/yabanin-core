# API Contract

Machine-readable version: `contracts/api-contract.json` (schema_version 1).
Verified by tests: `pkg/gateway/api_contract_test.go` (gateway),
`sdks/go/yabanin_test.go` (SDK parity). Shape changes are breaking: bump
schema_version and update every parity test.

## 1. Error envelope

Any non-2xx JSON response is exactly `{"error":{message,type,param?,code?}}`;
message and type are non-empty. SSE errors use the same envelope as a
data event, terminated by `data: [DONE]` (an error code present on the
JSON envelope rides the same `code` field on the SSE frame).

Adapter capability refusals — a request whose feature axis (streaming,
tools) the target model's provider adapter cannot serve — are
reported `400 invalid_request_error` with the stable code
`capability_not_supported` and a precise human message, before any upstream
call. The refusal is final: no retry, no failover to a different model, and
no silent downgrade of the capability away. Clients must drop the feature
or switch models.

## 2. Success body / nullability

- `chat.completion`: id/object/choices (non-empty array), content is a
  non-empty string (never null); usage tokens are numbers.
- Unknown cost = null/absent, NEVER 0 (0 means an zero-cost/local
  response). Verified against gateway contracts; the UI follows the rule.

## 3. Pagination

`{page>=1, page_size, total (from COUNT — measured), total_pages}` on all
admin list endpoints; the dashboard client types pin this shape.

## 4. Units

Money over the API is a float in `*_usd` (cost_usd/cost_in_usd).
Micro-USD is the internal ledger-fixture representation and never crosses
the API. Tokens are numbers.

## 5. SSE

Chunks carry `object=chat.completion.chunk`; the stream ends with the
literal `data: [DONE]`, including after an error. Client cancellation is
propagated upstream (cancel), and partial usage is recorded as observed
(see ADR-0001 for the accounting window).

The SSE surface is three separate contracts that no compatibility matrix
may mix. (1) The chat-SSE stream contract above applies to chat-shaped
endpoints. (2) `/v1/realtime` is an SSE-only session relay of its own: the
upstream event stream is forwarded byte-identically as `text/event-stream`
(no chat chunk framing, no `[DONE]` injection — see the `/realtime`
operation in [openapi.yaml](openapi.yaml)); its limits and billing differ
(10 MiB body, 64 MiB relay aborted — never truncated, last usage-bearing
event bills). (3) Realtime audio/video transports — WebSocket and WebRTC —
and video routes are owner-deferred and out of the release: a WebSocket
upgrade on `/v1/realtime` is refused `400 unsupported_feature` before
admission, and non-OpenAI-compat providers are refused
`400 realtime_not_supported_for_provider` before any upstream call — no
unsupported transport is accepted silently.

## 6. Admin route families (policy / prompt / identity parity)

Org-scoped families added since the beta; each is gated by an org
permission (`org:<perm>` — root bypasses) and reads through the org-scoped
store (RLS), so cross-org resource ids in the path answer `404`, never
another org's data. Unwired (store not configured) routes answer `503` —
routes are pinned by the inventory, wiring is deployment-dependent.

**Policy pipelines** (`org:policies.manage` — policies are security
objects; version history is immutable):

```
GET|POST /api/organizations/{id}/policies
GET|PUT|DELETE /api/organizations/{id}/policies/{policyId}
GET /api/organizations/{id}/policies/drift        managed | drift | unmanaged
GET /api/organizations/{id}/policy-decisions      ?page&page_size&verdict&mode&policy_id
```

Contract rules: bodies carry `yaml` (a `ypp/v1` Policy document) +
`attachments` (`key_label`, `model_pattern`, `endpoint`, `priority`);
every mutation appends a new immutable version and bumps the org version
key; the admin plane validates YAML syntax only (full compilation happens
gateway-side at load — an unknown detector name stores fine and fails
visibly in the decision log). Decision rows expose verdict
(`allow|flag|mask|deny`), mode (`shadow|enforce`), policy id/version and
hashed evidence only — quoted content never persists (90-day retention).

**Prompt studio** (`org:policies.manage` — prompts are pipeline inputs:

judge prompts decide verdicts; partials are substituted into policy and
prompt bodies):

```
GET|POST /api/organizations/{id}/prompts
GET|PUT|DELETE /api/organizations/{id}/prompts/{promptId}
POST /api/organizations/{id}/prompts/{promptId}/labels     bind {label, version}
GET|POST /api/organizations/{id}/partials
PUT|DELETE /api/organizations/{id}/partials/{partialName}
```

Contract rules: names are ref-safe `[A-Za-z0-9_.-]+`, unique per org;
edits APPEND immutable versions (label bindings are the mutable pointer);
bodies may carry `{{var}}` / `{{partials.name}}` placeholders — rendering
happens on render/render-template paths, never mutating stored versions.

**MCP credentials** (`root` for the admin CRUD; `org` agent auth on the
gateway flow):

```
PUT|GET|DELETE /api/organizations/{id}/mcp/servers/{name}/credential
POST /api/mcp/credentials/{server}          agent key; headers submit/rotate
POST /api/mcp/auth/{server}/begin           agent key; oauth consent URL
GET  /api/mcp/auth/{server}/callback        public (IdP redirect target)
```

See §7 for the secret-display contract and
[MCP Gateway](../mcp-gateway.md#6-upstream-credentials-mc-13) for the
auth-chain semantics.

**Tool governance** (`root` on the admin plane — per-org tool-call
policies; store nil without a DB → `503`):

```
GET|POST /api/organizations/{id}/tool-policies
GET  /api/organizations/{id}/tool-policies/presets
POST /api/organizations/{id}/tool-policies/presets/{preset}   apply
GET|PATCH|DELETE /api/organizations/{id}/tool-policies/{name}
POST /api/tool-policies        dashboard create alias; org via body org_id
```

Contract rules: create answers `201` with the stored policy; a duplicate
`(org, name)` answers `409` — retry with a different name is safe, a
blind retry is not. The unscoped create alias mounts the identical
handler in the same root group (org targeted via the body `org_id` the
org-scope check consumes) — one capability, one guard chain
(`session+csrf+root+orgscope`), no permission bypass; the fully-wired
golden walk pins the chain parity and the drift gate keeps the spec entry
explicit.

**SCIM provisioning** (`org:members.manage` for tokens; bearer `scim` auth
for the server):

```
POST|GET /api/organizations/{id}/scim/tokens
DELETE /api/organizations/{id}/scim/tokens/{tokenID}
/scim/v2/ServiceProviderConfig | /scim/v2/Users[/{id}] | /scim/v2/Groups[/{id}]
```

## 7. Secret-display contract

Raw secrets cross the API exactly once, on creation, and only where the
flow requires it (SCIM bearer tokens, agent keys); everything stored is
read back masked: credential rows expose `secret_last4` + `has_secret`,
never the plaintext or ciphertext. An at-rest secret is an `enc:`
envelope; a write without a configured encryptor fails — no silent
plaintext fallback.

## 8. Extensions pass-through (chat)

On the OpenAI-compatible chat surface the gateway forwards provider
extensions explicitly, never silently dropping them: unknown request
fields (top-level or per-message) reach the upstream with their exact
JSON value bytes — including integers beyond float64's 2^53 window — and
unknown upstream response fields (top-level, choice, message, usage) reach
the client byte-for-byte on both the JSON and SSE surfaces. The only
permitted rewrites are: egress-guard redaction and vertical prompt masks
(patched into the raw JSON, other fields untouched), per-hop model
override (patches only the `model` key), opt-in `reasoning_effort`
injection (patches only that key), and `stream_options.include_usage`
injection (RM-03). Cross-API adapter surfaces (Anthropic-format requests
translated to OpenAI upstreams) intentionally do not carry unmodeled
fields; unsupported modeled fields are rejected with a precise reason, not
silently lost. Concretely: a client-supplied
`reasoning_effort` on a translated route (Anthropic/Bedrock/Vertex
adapters) is rejected with `400 invalid_request_error` naming the field
and why — the same refusal on the OpenAI-compatible route never happens,
because there the field is forwarded verbatim to the upstream. Pinned at
`pkg/gateway/n07p1t05_negative_surface_test.go` (wire corpus, JSON and
SSE surfaces, upstream untouched on refusal) with consumer proof in
`sdks/go/compat_openai_test.go`
(`TestOpenAICompat_ReasoningEffortRefusalSurfacesExactReason`). Cache
replay is a projection, not a byte mirror: role,
content, refusal and tool calls replay verbatim, other extensions do not
cross the replay boundary. Pinned at `pkg/gateway/n07p1t04_extensions_test.go`
(value fidelity, response verbatim) with consumer proofs in
`sdks/go/compat_extensions_test.go` and `sdks/go/compat_extensions_request_test.go`
(`ChatResponse.Extra` captures unknown top-level keys verbatim;
`ChatRequest.Extra` sends them, extra_body semantics).

## 9. Deprecation lifecycle

A surface is deprecated in the spec, not in prose. The operation carries
`deprecated: true` plus lifecycle metadata, machine-checked on both spec
files by services/admin/handlers (openapi_schema_gate_test.go):

- `x-deprecated-since` — announcement date (RFC3339 date);
- `x-sunset` — earliest removal date, at least the minimum notice window
  (180 days) after the announcement;
- `x-migration` — where clients move instead (route, header, or doc
  pointer; "none" only when there is genuinely no successor).

The wire mirrors the metadata: a deprecated response carries `Deprecation`
and `Sunset` headers (IMF-fixdate, same dates as the spec), so the notice
reaches clients that never read the spec. The handler and the spec are
kept in lock-step by test (cache_handlers_lifecycle_test.go for the
current deprecated route).

Removal is one change: the operation, its metadata and its headers
disappear together. The gates fail the inconsistent states — lifecycle
metadata without the flag (half-deprecated), a removed handler still
documented, or a documented route no longer served (route inventory), or a
`$ref` that lost its schema (schema gate). Deprecated routes stay served
(410 Gone where the implementation is already removed) until sunset.
SDK-shipped routes are pinned to the documented operations by the same
gate file (TestSDKConsumedRoutesDocumented): an SDK route that loses its
spec operation fails the suite, so SDK compatibility is enforced against
the documented surface, not against folklore.

## 10. Dashboard hash contract (policy decisions ↔ request explorer)

The dashboard keeps page state in the hash query (`#<page>?<params>`) and
rewrites it param-by-param: opening the request inspector writes or clears
only the `inspect` param (`replaceState` — view state, not navigation), and
every other param (page id, org scope, filters, sort, locale) survives.
`inspect=request:<id>` is the EntityDrawer deep link: a shared URL opens
the drawer on load. This is the same contract as `useHashParam` /
`useTableUrlState` (web/dashboard/src/hooks/useInspectParam.ts,
AUX-17).

Cross-page links never copy params by hand; they are built by
`relatedListHref` (web/dashboard/src/lib/inspectUrl.ts), which starts from
the CURRENT hash query, deletes any stale `inspect` param, and applies the
extras (blank extras are skipped) — so a param never leaks stale state
between pages. The TRACE links:

- Decisions log row → explorer: `#requests-explorer?…&inspect=request:<id>`
  with `org` and the current filters carried along, so the lookup stays
  inside the same org (PolicyDecisionsPage).
- Explorer inspector → decisions log:
  `#policy-decisions?…&org=…&request=<request_id>` (view defaults to the
  evaluations view; `request` maps to the API `request_id` filter).
- Policy editor effect box → decisions log:
  `#policy-decisions?org=…&policy=<id>` (evaluations) and the
  `&view=requests` roll-up of the requests this policy affected.

`#policy-decisions` params: `org` (scope), `view` (`decisions` default,
unknown value falls back to `decisions`), `verdict` (`allow|flag|mask|deny`),
`mode` (`shadow|enforce`), `policy` (→ API `policy_id`), `request` (→ API
`request_id`). The Evaluations/Requests toggle writes only the `view`
param, so `verdict`/`mode`/`policy`/`request` filters survive a view
switch.

The inspector's decision section is a PREVIEW of the decision log, not the
log: it renders the ≤ 5 freshest evaluations of the inspected request,
then a "more evaluations exist" hint plus the open-log link (testids
`inspector-policy-decisions`, `inspector-decision-row`,
`inspector-decisions-open-log`). Presentation contract: an enforce row
reads `Applied action: <verdict>`, a shadow row reads `Shadow finding
(would-have, not applied)` — a shadow verdict never reads as an applied
action; `findings_valid: false` renders a degraded-record notice while the
verdict above still stands. Empty state: no evaluation was recorded for
this request (no policy attached, or the evaluation predates the 90-day
retention). When the request id is unknown in the log (predates it, was
purged, or is wrong), the drawer says so and the decision section remains —
the two stores are separate records, so the decision log may still hold
evidence for a purged request row.

Request rows carry `routing_decision`, a compact JSON string that may embed a
`rule` identity triple `{namespace, id, version}`. The current routing override
path stamps namespace `"routing"` and the content hash captured at match time as
its version. The API `rule_id` filter matches the stored decision's `rule.id`
(`admin.openapi.yaml`, `listOrgRequests`). Treat missing identities as unknown;
do not infer a policy or tool-rule identity from a routing-only record.
