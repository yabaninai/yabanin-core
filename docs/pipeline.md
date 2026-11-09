# Policy Pipeline (YPP)

The Yabanin Policy Pipeline (YPP) is a programmable inspection and mutation
conveyor that runs over gateway traffic: declarative YAML policies, external
HTTP scanners, LLM judges, content mutators and conditional branching —
composed and executed at one place, the gateway middleware. It is **off by
default**: with `YABANIN_POLICY_MODE` unset the pipeline runtime is never
built and request handling is bit-for-bit identical to a deployment without
the feature.

Policies are org-scoped security objects. Enforcement reads the policystore
only — there are no per-request (SDK-supplied) policy configs, so a client
can never bypass an admin's policy.

To contribute a new pipeline step or condition engine — including the
frozen-name contract and the operator allow-list boundary that constrains
outbound callout steps — follow
[extensions/pipeline-steps.md](extensions/pipeline-steps.md).

## 1. Architecture

```
pkg/pipeline          pure core: payload/finding/result types, the Step
                      contract, YAML compilation, the execution engine.
                      No DB/HTTP/LLM/logging side effects.
pkg/pipeline/builtins 20 deterministic steps (15 detectors + 5 mutators).
pkg/pipeline/callout  external HTTP detector/mutator steps (SSRF-guarded).
pkg/pipeline/llmjudge LLM-judge step through the gateway's own upstream pool.
pkg/pipeline/script   `when` condition engines: expr (default), lua, starlark.
pkg/pipeline/streaming SSE primitives: prefix gate, chunk carry, final check.
pkg/policystore       versioned policy storage + attachments (migration 0008).
gateway middleware    the single integration point: compiles org policies per
                      version, runs attached pipelines on each hook.
```

The gateway builds one engine per process with the full step registry:
builtins, callout (only when an egress allow-list is configured), llm_judge,
the `builtin/toolpolicy` tool guard, the `decide` verdict step and a no-op
`route_hint` placeholder, plus all three condition engines (`expr`, `lua`,
`starlark`).

## 2. Concepts

### Hooks and payload kinds

A policy declares which gateway surfaces (`hooks`) it runs on. The hook
determines the payload kind handed to the steps:

| Hook | Payload kind | Fires |
|---|---|---|
| `pre_upstream` | `request` | before the upstream call |
| `post_upstream` | `response` | after the upstream response |
| `stream_prefix` | `stream_prefix` | buffered stream prefix (see §7) |
| `stream_final` | `stream_final` | full stream aggregate |
| `tool_pre` | `tool_args` | before a tool/MCP invocation |
| `tool_post` | `tool_result` | after a tool/MCP invocation |

The payload carries the message list, the raw body (and for `stream_*` the
chunk text), plus read-only request metadata (`org`, `key`, `model`,
`provider`, labels, tags) and, on request payloads, the upstream request
headers.

### Actions and composition

Every finding carries one action on the fixed strictness scale
**deny > mask > flag > allow**:

- `deny` — block the request / tool call / stream (short-circuits the run).
- `mask` — proceed, but only with the mutated payload.
- `flag` — proceed unchanged, record the observation.
- `allow` — nothing to act on.

When several attached policies match a request, **all of them run** (ordered
by attachment priority, org → key → model): findings are unioned, the verdict
is the most restrictive observed, and the first `deny` short-circuits the
remaining work (skipped steps still appear in the trace). Unknown actions
from a buggy step rank as deny — fail closed. Detectors always observe the
latest mutated text, including across policy boundaries.

Every compiled step of every run is traced exactly once (`ran`, `skipped`,
`error`, `timeout`, with duration and error) — the decision log depends on
this completeness.

### Modes and the kill switch

- `mode: enforce` — findings raise the verdict; mutators rewrite the payload.
- `mode: shadow` — the policy **never** mutates and **never** raises the
  verdict; findings are recorded for "what would have happened" diffing.
  This is the recommended rollout path (shadow → review decision log →
  enforce).

The process-wide kill switch `YABANIN_POLICY_MODE` (default `off`):

| Value | Behavior |
|---|---|
| `off` | runtime never built; every hook is a no-op (default) |
| `shadow` | every policy downgraded to shadow at compile time |
| `enforce` | policies run in their stored mode |

An unknown value resolves to `off` with a warning. Judge calls the gateway
itself makes carry an internal marker (§6.2); inbound traffic presenting the
judge header is rejected, not exempted (§6.2).

## 3. Policy YAML (apiVersion `ypp/v1`)

One policy per document; the file name must equal the policy `name` when
managed as code (§8). Real worked examples live in
`deploy/policies/_example/pii-guard.yaml` and the `deploy/policies/_pack/`
packs.

```yaml
apiVersion: ypp/v1
kind: Policy
name: pii-guard                 # required identity (metrics, decision log)
mode: shadow                    # shadow | enforce
hooks: [pre_upstream]           # at least one, no duplicates
steps:
  - id: scan                    # parallel group head: the detectors below
    parallel: [pii, secrets]    # run concurrently, join before the next step
  - id: pii
    detector: builtin/national-pii
  - id: secrets
    detector: builtin/secrets
  - id: verdict
    decide: |
      deny  if findings.any(f -> f.category matches 'secrets.*' and f.severity == 'high')
      mask  if findings.any(f -> f.action == 'mask')
      flag  otherwise
```

Validation is strict: unknown YAML fields are load errors; `apiVersion` must
be `ypp/v1`, `kind` must be `Policy`, `name` and `mode` are required, step
ids are unique, and every step carries exactly one kind field
(`detector` | `mutator` | `callout` | `llm_judge` | `decide` | `route_hint`).

Per-step options:

| Field | Meaning |
|---|---|
| `when` | optional condition source (§4); compiled once at policy load |
| `when_engine` | pin the condition engine (`expr`/`lua`/`starlark`); required once more than one engine is registered |
| `timeout` | per-step budget, Go duration syntax (`50ms`, `2s`); a timeout follows `on_error` |
| `on_error` | `fail_closed` (default; the failure denies and short-circuits) \| `fail_open` \| `fail_open+flag` (adds a synthetic `step_error` flag finding) |
| `parallel` | ids of this policy's steps that run concurrently with this step as one join group; every participant must be a detector (groups are read-only; mutators in groups are a compile error), no nesting |
| `params` | step factory parameters (§5); kind-reserved keys (`url`, `model`, `prompt_ref`, `expr`, `target`) collide as compile errors |

Attachment (who the policy applies to) is stored with the policy, not in the
YAML — see §8 for the git-declared reconcile block and the admin API (§9).

## 4. Conditions (`when`)

A `when` source is evaluated at run time against the read-only context of the
run so far: findings recorded, step traces (durations/outcomes), and request
meta. Compilation happens once per step at policy load; a condition with no
registered engine is a **load** error, never a silent skip. Condition errors
follow the step's `on_error` mode (fail-closed by default).

Three engines ship and are registered by the gateway: `expr` (minimal,
loop-free — the intended default), `lua` (sandboxed gopher-lua with
instruction budget) and `starlark`. Engines are swappable behind one
interface; switching the language does not change the YAML policy model.

The `decide` step kind is a separate, engine-independent verdict DSL
(line-based, first matching rule wins):

```
deny  if findings.any(f -> f.category matches 'secrets.*' and f.severity == 'high')
mask  if findings.any(f -> f.action == 'mask')
flag  otherwise
```

Fields: `category`, `severity`, `action`, `step`, `span`; operators `==` and
`matches` (`*` trailing-star prefix); an `otherwise` line sets the fallback
(default `allow`). A `decide` step raises the verdict only — it never
mutates or appends findings.

## 5. Builtin steps

Registry names are frozen — policies reference them by string. Common
optional params on every step:

- `kinds` — restrict the payload kinds inspected (default: all six kinds;
  the JSON-schema step defaults to output kinds, request-only steps pin
  `request`).
- `action` — the action the step's findings carry: `flag` (default),
  `mask` or `deny` (`allow` is not a detector action). Factory validation
  failures are policy **load** errors.

### Detectors

| Step | Category(ies) | Params (besides common) |
|---|---|---|
| `builtin/national-pii` | `innsnils`, `pan`, `ru_passport`, `ogrn` + BR/IN/MY/AE/ZA/NG/KE/EG identity numbers | — (fixed RU + 9-jurisdiction set; checksum/Luhn-validated) |
| `builtin/secrets` | `secret` (+ credential-keyed JSON values) | — (provider key shapes, PEM headers, JWT shapes; evidence is never quoted — `[REDACTED_SECRET]`) |
| `builtin/injection` | `injection` | — (RU + EN prompt-injection phrases) |
| `builtin/word-count` | `word_count` | `min`, `max` (at least one bound required; `max` 0 = unbounded) |
| `builtin/char-count` | `char_count` | `min`, `max` (runes, not bytes) |
| `builtin/sentence-count` | `sentence_count` | `min`, `max` (offline terminator heuristic) |
| `builtin/contains` | `contains` | `words` (required list), `mode` `any`\|`all`\|`none` (default `any`), `case_insensitive` (default true) |
| `builtin/regex` | `regex` | `pattern` (required, RE2; nested quantifiers and expansion bombs are load errors), `invert`, `case_insensitive`, `max_input` (default 1 MiB, cap 64 MiB — oversize fails the step) |
| `builtin/json-schema` | `json_schema` | `schema` (required inline JSON Schema; compiled at load) |
| `builtin/json-keys` | `json_keys` | `keys` (required dotted paths), `mode` `any`\|`all`\|`none` (default `all`) |
| `builtin/url-check` | `url` | `schemes` (default `["https","http"]`), `allow_hosts`, `deny_hosts` (`*.suffix` wildcards); fully offline — never fetches |
| `builtin/code-detect` | `code.<lang>` | `languages` (subset of `sql`\|`python`\|`typescript`, default all) |
| `builtin/language` | `language` | `allowed` (required non-empty subset of `ru`\|`en`\|`other`; script-dominance heuristic) |
| `builtin/model-whitelist` | `model` | `models` (required glob patterns; unknown/empty model = violation) |
| `builtin/metadata-required` | `metadata` | `keys` (meta fields/labels) and/or `labels` (label=value pairs); at least one required |

### Mutators

| Step | Effect | Params |
|---|---|---|
| `builtin/redact` | replaces sensitive spans of the run's findings (and/or its own patterns) with `[REDACTED:<category>:n]` tokens | `categories` (exact names or trailing `.*`), `patterns` (list of `{category, pattern}`), `max_input` |
| `builtin/pseudonymize` | reversible pseudonymization: spans become stable `{{YPP_n}}` aliases; substitution flows **outbound only** — there is no reverse substitution into responses | `categories`, `patterns`, `carry` `none` (default)\|`session`, `max_input` |
| `builtin/header-rewrite` | edits upstream request headers (removals apply before sets; CRLF/NUL injection is a load error) | `set` (map), `remove` (list); request-only |
| `builtin/model-rewrite` | rewrites the request model (the data-boundary seam: route PII-bearing requests to an in-region model); every rewrite is recorded as a `model_rewrite` flag finding | `to` (required), `from` (optional precondition); request-only |
| `builtin/partials-substitute` | substitutes `{{partials.NAME}}` tokens (single pass, never rescanned) | `on_missing` `skip` (default)\|`error`; the source store is wired server-side (prompt studio, §6.1) |

`builtin/pseudonymize` with `carry: session` persists the alias map through
the session carrier so the same original maps to the same alias across
turns; the carrier is stripped before dispatch upstream or to the client.

Two further step kinds are registered by the gateway: `builtin/toolpolicy`
(the tool-call guardrails of [Tool policies](tool-policies.md) as a pipeline
step) and the `decide` / `route_hint` seam steps (§4). `route_hint` is
currently a no-op placeholder — routing semantics are a later decision.

## 6. External steps

### 6.1 Callout (HTTP detectors/mutators)

A `callout:` step POSTs a payload projection to an external scanner and maps
the response into findings (mode `detect`) or applies mutated content back
(mode `mutate`).

```yaml
- id: presidio
  callout: http://presidio.internal:3000/analyze
  params:
    mode: detect                 # detect | mutate
    expose: messages             # messages (default) | body | fields:a,b,c
    response: findings           # findings (default) | boolean (JSON true/false)
    finding_category: presidio   # default category for boolean mode
    max_response_bytes: 65536
  timeout: 250ms
  on_error: fail_open+flag
```

**Projections** (`expose`) bound what leaves the gateway: `messages` sends
the message contents (joined with `\n` for detect, one array element per
message for mutate), `body` sends the raw body (documented risk — enable
only for scanners contractually bound to the same data domain), `fields:a,b`
sends only those top-level fields of a JSON-object body. Org/key/model
metadata never leaves.

**Response contracts.** `detect`/`findings` expects
`{"findings":[{"category","severity","action","span","evidence"}]}` —
`category` is required, unknown actions rank as deny. `detect`/`boolean`
expects JSON `true`/`false`. `mutate` must answer
`{"content": ...}` matching the projection exactly: same number of messages,
a body string, or an object whose key set equals the projected field set.
A scanner verdict (valid 2xx) is never an error; network failures,
non-2xx, contract violations and breaker rejections are step errors that
follow `on_error`.

**Egress security (non-negotiable).** Steps only build when the operator
configured `YABANIN_POLICY_CALLOUT_ALLOW_HOSTS` (comma-separated exact
domains or `*.suffix`); every URL is validated against the list at policy
compile time. At dial time an SSRF guard pins DNS answers and refuses all
reserved addresses (loopback, RFC1918, link-local/cloud metadata), closing
the DNS-rebinding window. No redirects, no retries, a per-URL circuit
breaker, singleflight deduplication of concurrent identical calls, and a
per-step timeout. Without an allow-list, callout policies fail at load —
egress can never be wider than the operator's list.

### 6.2 LLM judge

An `llm_judge` step sends one conversation turn to a judge model through the
gateway's own upstream machinery (the same SSRF-guarded pool client traffic
uses — sovereign and on-prem classifiers are first-class targets) and maps
the verdict to findings:

```yaml
- id: judge_tox
  llm_judge:
    model: "$(sovereign-classifier)"   # required; literal or $(registry indirection)
    prompt_ref: "judges/toxicity@2"    # required; versioned prompt resource
  params:
    mode: input          # input (last user turn, default) | output (last assistant turn)
    threshold: 0.8       # confidence >= threshold → deny; below → flag (default 0.8)
    categories: [toxicity]
  timeout: 2s
  on_error: fail_open+flag
```

Prompt references resolve through a versioned `PromptSource` — embedded
files (`judges/<name>/<version>.md`, e.g. `judges/toxicity@1`, `@2`) are the
default, and prompt studio supplies the org-level source. Temperature is
pinned to 0 so verdicts are deterministic. Judge findings are namespaced
`judge.<category>` and never collide with detector categories. A malformed
verdict is a step error (`on_error` applies); an omitted confidence counts
as 1.0 (fail-closed).

**Recursion exclusion (hard contract).** Every judge call the gateway itself
makes carries `judge=true` in the payload meta and the `X-Yabanin-Judge:
true` header on the wire; the internal payload marker exempts that synthetic
call from the pipelines, so a judge model served by the same gateway never
re-enters. The wire header alone grants nothing: any inbound request
presenting `X-Yabanin-Judge` — value `true`, `false`, arbitrary, empty, or
repeated — is untrusted and is rejected with `400 judge_reentry_unsupported`
at the shared pre-upstream boundary after authentication and route
resolution, before any upstream call. A cold policy-store failure in enforce
mode keeps its existing `503` precedence over this rejection. The outbound
adapter refuses to send unmarked judge calls.

## 7. Streaming semantics

Streaming policies use a prefix gate, chunk carry, and a final check in the
SSE path:

1. **Stream defaults.** When the policy runtime is active in enforcement
   mode and a policy is attached to `stream_prefix`, a kinds-less
   `builtin/redact` or
   `builtin/pseudonymize` includes `stream_prefix` by default. The same
   kinds-less default includes `stream_final` when that hook is attached; an
   explicit `kinds` list narrows the step scope. This is the same common
   default described in §5. `stream_final` examines the completed stream after
   issuance and cannot prevent or retract bytes already sent.
2. **Prefix gate and chunk carry.** When a `stream_prefix` policy is attached,
   the gateway evaluates one captured prefix snapshot. Defaults are 64
   approximate tokens or 500 ms from the first nonempty delta, whichever fires
   first; `prefix_tokens` or `prefix_delay_ms` may override them. A shorter
   buffered stream is flushed at end-of-stream. A complete value found in that
   snapshot can be transformed before release. Chunk carry applies the
   replacement learned for that value to later occurrences, including
   occurrences split across chunks. It does not discover a new value absent
   from the snapshot or first seen after passthrough begins, so such values are
   not guaranteed to be found or hidden. Mutated SSE content frames are
   re-encoded while preserving event framing; `[DONE]` and frames without
   content deltas pass through unchanged. When stream caching is enabled, the
   transform runs before the cache recording writer, so client and cache
   observe the same transformed bytes.
3. **Emitted-bytes boundary.** A streaming transform governs exactly three
   regions, and nothing outside them. Bytes already written to the client are
   immutable: no later decision rewrites, recalls or unsends them — a
   `stream_final` deny over delivered bytes degrades to a flagged outcome
   (item 6). Bytes in flight — the prefix hold-back buffer and the
   chunk-carry hold-back tail — are mutable until released: chunk carry holds
   back exactly the bytes that could still start or complete a match, and at
   most `maxLen-1` of them (the longest learned pattern minus one) at any
   chunk boundary — the pipeline cannot withhold the stream to validate
   future tokens, and its delivery delay is capped by the pattern set
   (pinned by the chunk-span corpus in `pkg/pipeline/streaming`). Bytes
   already sealed into a stored cache entry are final as well: the cache
   write seam applies a document mutator only until the write is sealed, and
   a later mutator installation never revises stored entries. No stage
   promises to inspect future tokens. A forbidden value that is incomplete
   when the prefix snapshot releases keeps its emitted half verbatim; the
   remainder is transformed only where a complete occurrence passes through
   the carry processor afterwards — a value the snapshot never saw complete
   assembles in the client's view even though it never rides a single wire
   frame. The cache write seam has one documented asymmetry today:
   `CacheService.Write` seals the original response bytes for the synchronous
   exact layer before the seam runs, so a wiring that installs a mutator must
   keep the abstain default or explicitly unify both layers (pinned by
   boundary tests in `pkg/cache`).
4. **Prefix deny.** A `deny` from the prefix snapshot aborts before any held
   bytes are released; the gateway sends a canonical error frame and
   `data: [DONE]`.
5. **If output is unchanged.** Check that policy runtime is enabled in
   enforcement mode, the policy is attached to the intended organization,
   model, endpoint, and `stream_prefix` hook, and an explicit `kinds` list
   does not exclude `stream_prefix`. Check that the complete synthetic target
   arrives in the captured prefix before it flushes. Correct the attachment or
   `kinds`, or adjust the prefix parameters, then validate with a local
   synthetic stream. A larger prefix window can delay the first byte and still
   cannot guarantee discovery of a value that first appears after passthrough
   begins.
6. **Final check.** Delivered frames accumulate into the synthetic
   `chat.completion` document, which `stream_final` policies examine after
   issuance. A final `deny` cannot unsend bytes; it degrades to a flagged
   outcome recorded in the decision log and metrics.

## 8. Config-as-code (git → policystore)

Git is the authoritative source for policy declarations. See
`deploy/policies/README.md` for the full workflow; the short version:

- Declarations live at `deploy/policies/<org-slug>/<policy-name>.yaml` —
  document 1 is the policy (stored verbatim), the optional document 2 after
  `---` is the reconcile block (`enabled`, `attachments`).
- `yb policies reconcile` plans the diff (dry-run by default);
  `--apply` converges the database onto git; `--prune` (danger) also deletes
  DB policies not covered by declarations. CI runs the dry-run so a broken
  declaration fails the build.
- **Drift is reported, never merged silently**: a DB edit made past git is
  `DRIFT` in the plan and is overwritten by a new version on apply (versions
  are immutable, so nothing is destroyed). The admin API
  `GET /api/organizations/{id}/policies/drift` reports per-policy status
  `managed` / `drift` / `unmanaged` without a repo checkout.
- The `deploy/policies/_pack/sovereign-default.yaml` pack (national PII +
  secrets + injection, shadow mode, org-wide attachment) ships **OFF** — it
  reconciles only with `--include-pack`, and even then lands disabled.

Every applied change records the current git SHA as the version's `git_sha`,
so the decision log and metrics tie back to the exact declaration revision.

Reconcile invalidation depends on the CLI and gateways using the same Postgres
policy store and Redis policy-version store. With `--apply`, after a successful
per-organization apply that changed policies, the CLI attempts to update that
organization's Redis policy-version key. Each gateway probes the key on
requests and consumes a changed readable version on its next request; there is
no background push. Dry-run, unchanged apply, and failed per-organization
apply do not issue a version bump. A Redis bump failure is reported as a
warning and does not roll back database writes. A per-organization apply
consists of multiple store operations, so a later operation can fail after
earlier writes have committed; the command reports the organization failure
and does not bump its key. Correct the cause and rerun reconcile to converge.

Any readable version that differs from a known cached version triggers a
store-refresh attempt on the next request. A missing Redis key reads as version
`0`, so it triggers that attempt when the cached version is known and nonzero.
The 30-second hard-cache-age boundary applies when a version probe is
unavailable, its readable value equals the cached version (including a missing
key that reads as `0` when the cached version is also `0`), or the successful
store load did not capture a version. These probes do not renew cache age,
which is measured from the last successful policy-store load. At or after the
boundary, the next request attempts a store refresh. A failed store load keeps
the last-known-good snapshot and its original age; a later request retries,
and a successful load picks up the stored policy. Refresh is request-driven,
and policy-store availability still matters.

## 9. Policystore and admin API

The policystore (migration `0008`) versions policies immutably and keeps
per-org attachments (`key_label`, `model_pattern`, `endpoint`, `priority` —
smaller priority runs earlier; default 100). Admin surface, gated by the
`policies.manage` org permission:

```
GET    /api/organizations/{id}/policies                     list
POST   /api/organizations/{id}/policies                     create (yaml + attachments)
GET    /api/organizations/{id}/policies/drift               git-drift status per policy
GET    /api/organizations/{id}/policies/{policyId}          detail: policy + versions + attachments
PUT    /api/organizations/{id}/policies/{policyId}          update yaml / enable / active_version / attachments
DELETE /api/organizations/{id}/policies/{policyId}          delete (cascades versions + attachments)
```

The admin plane validates YAML syntax only (kind/apiVersion/steps presence);
full compilation happens when the gateway loads a version, so a document
with unknown detector names stores fine and fails **visibly** in the
decision log. A successful admin API policy mutation attempts to update the
organization's policy-version key. Gateway instances probe that key on
requests and attempt a store refresh on the next request when a readable
version differs from the known cached version. A missing key reads as version
`0`, so a missing key triggers that attempt when the cached version is known
and nonzero. When the version probe is unavailable, its readable value equals
the cached version (including missing-as-`0` when the cached version is `0`),
or the successful store load did not capture a version, a cached entry is
reconsidered for reload on the first request at or after 30 seconds from its
last successful policy-store load. A failed store refresh retains the
last-known-good entry and retries on a later request; this is a request-driven
fallback, not an immediate push or a guarantee of fresh data while the store
is unavailable.

### Atomic activation and rollback

Prerequisites: policies for the organization are managed through the admin API
above or `yb policies reconcile` (§8), and the gateway kill switch is `enforce`
for rejection behavior (`shadow` only observes). Activation is a pointer move,
never a content edit: `PUT /api/organizations/{id}/policies/{policyId}` with
`active_version` points the pipeline at one immutable stored version; rollback
is the same call with an older version number. A successful mutation bumps the
organization's policy-version key.

Happy path: after activation, each gateway instance notices the changed key on
its next request, reloads the organization's policy set, and swaps its compiled
copy in one step. The reload reads pipelines, active versions, and attachments
from one repeatable-read database transaction, so the new set cannot mix rows
written at different times.

Limitations and typical failure recovery:

- **One request, one snapshot.** A request — including its streaming and retry
  continuations — reuses the snapshot it loaded at entry and never mixes
  policies loaded before and after an activation. Reload is request-driven:
  instances that serve no traffic do not reload.
- **All-or-nothing compile.** The reload compiles the organization's whole
  candidate set. One invalid active version (a dangling version reference,
  unparseable YAML, an unknown step) rejects the entire candidate; the previous
  snapshot keeps serving and a partial set is never installed.
- **Activation during a reload (version race).** The gateway reads the version
  key before and after the store read. A change in between retries the load
  once; a change again fails the refresh, the previous snapshot keeps serving,
  and a later request retries. A request therefore sees either the old or the
  new complete set — never an intermediate one — but the moment of switchover
  is not coordinated across gateway instances, so different instances can serve
  different complete sets for up to one request each.
- **Unsuccessful new version on a cold organization.** When no previous good
  snapshot exists, an invalid active version answers
  `503 policy_configuration_unavailable` in enforce mode regardless of the
  cold-failure setting; an unavailable policy store answers
  `503 policy_temporarily_unavailable` unless
  `YABANIN_POLICY_COLD_FAILURE_MODE` is `fail-open`. In shadow mode both
  conditions are logged and counted while traffic continues without policy
  evaluation. An organization that already serves a good snapshot keeps serving
  it; load failures never evict a usable entry.
- **Recovery.** Fix the declaration and re-apply, or roll back by activating
  the older immutable version; gateways converge on a subsequent request.
  Convergence relies on the version bump; when the bump failed, the 30-second
  cache boundary from §8/§9 applies instead.

Load failures are visible as `policy load failed` warnings with a failure class
(`store_read`, `invalid_config`, `context_canceled`, `runtime_unavailable`) and
the `gateway_policy_load_failures_total` metric (mode × cache state: `cold` =
no previous snapshot, `stale` = previous snapshot kept serving).

### Decision log

Every run's decisions land in the decision log (`policy_decisions` table,
**90-day retention** enforced by the loggerd purge loop,
`PolicyDecisionsRetentionDays`): per-step trace, verdict, policy id + version
and content hashes. Findings evidence is stored hashed — quoted user content never
persists outside shadow/debug retention. The analytics event carries the
`policy` field: a JSON array of decision records (policy id/name/version,
mode, verdict, category/severity/action findings, duration) in execution
order; absent or empty means the pipeline did not evaluate the request.

```
GET /api/organizations/{id}/policy-decisions?page=&page_size=&verdict=&mode=&policy_id=
```

### Metrics

| Series | Labels |
|---|---|
| `gateway_policy_load_failures_total` | mode, cache_state (`cold` = no previous snapshot, `stale` = previous snapshot kept serving) |
| `gateway_policy_runs_total` | policy, endpoint, outcome (allow/flag/mask/deny) |
| `gateway_policy_denies_total` | policy, endpoint |
| `gateway_policy_masks_total` | policy, endpoint |
| `gateway_policy_shadow_flags_total` | policy, endpoint (findings recorded by shadow runs) |
| `gateway_policy_duration_ms` | policy, endpoint |

Plus `pipeline_llmjudge_duration_seconds{model,outcome}`,
`pipeline_llmjudge_verdicts_total{model,outcome}` and the
`pipeline_callout_*` family. No payload content, category or severity is
ever a label value.

## 10. Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `YABANIN_POLICY_MODE` | `off` | Kill switch: `off` / `shadow` / `enforce` (§2). |
| `YABANIN_POLICY_COLD_FAILURE_MODE` | `fail-closed` | Cold organizations (no successful policy snapshot) while the store is unavailable: `fail-closed` rejects with 503, `fail-open` continues without policy evaluation. Invalid policy configuration always rejects in enforce mode (§9). |
| `YABANIN_POLICY_CALLOUT_ALLOW_HOSTS` | empty | Comma-separated host patterns callout steps may dial; empty disables callout steps entirely. |

Streaming prefix defaults (64 tokens / 500 ms) are policy parameters on the
`stream_prefix` attachment, not environment knobs.
