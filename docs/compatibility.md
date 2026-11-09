# Compatibility

Verified client and API surface for the Yabanin gateway. Statuses:
`source-reviewed` (code inspected, no live test), `tested` (reproduced in
the current version), `unsupported` (no route/support in the checked
version), `not verified` (no test evidence either way).

`tested` below means `pkg/gateway/compat_test.go` drove an `httptest` upstream
with a synthetic fixture. It does not mean a live CLI was launched, unless
the row's evidence names a real-binary run (see the dated Codex CLI row).
Setup sketches:
[Codex](clients/codex.md),
[Claude Code](clients/claude-code.md),
[OpenCode](clients/opencode.md),
[Continue](clients/continue.md),
[Cline](clients/cline.md).

| Client / version | Inbound API | Streaming | Tool behavior | Provider / configuration | Evidence date | Status | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Codex-shaped client | `POST /v1/responses` | ✓ | custom tool call returned as `custom_tool_call` | OpenAI-compatible upstream, translation | fixture, 2026-09-30; mock-CLI e2e 2026-10-18 | tested | stateless surface: `previous_response_id` is unsupported (400) on both paths. Dropped fields (incl. `reasoning.effort`) are announced in `X-Yabanin-Unsupported` |
| Claude Code-shaped client | `POST /v1/messages` | ✓ | `tool_use` / `tool_result` round-trip in the client format | OpenAI-compatible upstream, translation | fixture, 2026-09-30 | tested | translation drops `thinking`, hosted tools, and `cache_control` |
| Claude Code-shaped client | `POST /v1/messages` | ✓ | native body forwarded, including `cache_control` | `provider=anthropic` | fixture, 2026-09-30 | tested | native mode does not apply tool gating |
| Claude Code-shaped client (consumer configuration matrix) | `POST /v1/messages` | ✓ | refusal paths only | old + new auth configurations (`strict` with `Authorization` Bearer or Claude Code `x-api-key`; legacy `header` mode with the static key unset resolves org keys), unknown-model policy (`fallback` substitutes + advertises `X-Yabanin-Model-Fallback`; `reject` → 404 Anthropic `not_found_error` naming the model), unsupported request shapes → 400 Anthropic `invalid_request_error`, no upstream call | fixture, 2026-11-01 (`TestMessages_ConsumerAuthGenerations`, `TestMessages_UnknownModelPolicyMatrix`, `TestMessages_UnsupportedRequestExplicitRefusal`) | tested | `header` mode still enforces the static key when one is configured; pure header-mode without a resolver and without a static key refuses every token (fail-closed) |
| OpenCode-shaped client | `POST /v1/chat/completions` | ✓ | function tool call passed through | OpenAI-compatible upstream | fixture, 2026-09-30 | tested | content arrays are forwarded as chat content parts |
| Cline-shaped client | `POST /v1/chat/completions` | ✓ | non-stream and streaming `tool_calls` (fragments merge by `index`) | OpenAI-compatible upstream | fixture, 2026-09-30; streaming 2026-10-12 | tested | streaming evidence is fixture-level (`cline_chat_stream`); the live CLI row below stays `not verified` |
| Continue-shaped client | `POST /v1/completions` | — | not a tool call; `prompt` and `suffix` forwarded | OpenAI-compatible upstream | fixture, 2026-09-30 | tested | FIM only; this row is not chat |
| Model list | `GET /v1/models` | — | — | gateway catalog, no upstream call | fixture, 2026-09-30 | tested | empty database advertises the configured fallback model |
| OpenAI Batch/Files clients | `/v1/files`, `/v1/batches` | — | JSONL chat-completions batches; results via output/error files | Postgres bytea + claim/lease queue | integration tests, 2026-10-18 | tested | only purpose=batch uploads and /v1/chat/completions lines; 100 MiB / 1000 requests / 30-day retention; no live OpenAI SDK run |
| OpenAI-compatible clients | `POST /v1/chat/completions` | ✓ | passthrough | any configured provider | 2026-09-17 | source-reviewed | client-side parity depends on each client's envelope parsing |
| MCP tool invocation | `POST /api/mcp/invoke` | — | single tool call per request | external MCP servers (allow-listed) | 2026-09-17 | source-reviewed | agent keys (yag_) only; default OFF |
| Codex CLI | `POST /v1/responses` | ✓ | — | live binary (codex-cli 0.166.0, config.toml `wire_api="responses"`) | real-binary e2e, 2026-11-03 (previous run: 0.162.1 on 2026-10-18) | tested | `codex exec` → gateway on a live port → mock chat upstream behind it; the CLI's final answer is asserted (`TestResponses_CodexCLI_RealE2E`), plus tools loop, capability-error and mid-stream-cancel scenarios (`TestResponses_CodexCLI_RealE2E_ToolsLoop` / `_UnsupportedToolCall` / `_ClientCancel`). No paid upstream; the mock stands in for the provider |
| Claude Code CLI | `POST /v1/messages` | ✓ | — | live binary | — | not verified | fixture coverage is not a live CLI run |
| OpenCode CLI | `POST /v1/chat/completions` | ✓ | — | live binary | — | not verified | fixture coverage is not a live CLI run |
| Continue CLI | `POST /v1/completions` | — | — | live binary | — | not verified | fixture coverage is not a live CLI run |
| Cline | `POST /v1/chat/completions` | — | — | live binary | — | not verified | fixture coverage is not a live CLI run |

Not verified: other client transports (WebSocket, gRPC), agent frameworks
beyond the listed keys. Absence of a test means `not verified`, not
`unsupported`; `unsupported` requires the checked absence of a route or
feature in the stated version.

## History original-retention compatibility matrix

The org original-text retention toggle (`organizations.retain_original_text`,
migration 0008; fail-closed platform default `false`) crossed with the real
supported consumers. `OFF` = processed text only; originals
(`upstream_request` / `upstream_response` captures) are withheld. Read-side
statuses: `tested` = pinned by `TestOriginalRetentionCompatibilityMatrix` /
`TestOriginalRetentionUnsupportedCasesFailLoudly`
(`services/admin/handlers/request_retention_compat_test.go`) or the cited
test. Write-side consumers are the durable-history writer (loggerd) and the
Redis publisher; their evidence is cited per row.

| Retention configuration | History list | History detail | History export | Archive search | loggerd writer / publisher | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Pre-toggle row (NULL override — organizations predating migration 0008; also restore-from-backup state) | 200, metadata + own/grant payload per the authz matrix; never originals | originals grant **not** honored (fail-closed OFF); payload.read works | `scope=read` 200 (processed payload); `scope=originals` → 403 `original payload retention is disabled`, audited `original_retention_disabled`, grant not consumed | 200, hot-source metadata only | producer pre-XADD capture strip + history row/DLQ envelope strip (fail-closed OFF) | tested |
| Explicit `false` (opt-out) | identical to pre-toggle | identical | identical | identical | identical | tested |
| Explicit `true` (opt-in) | identical to pre-toggle (the toggle never widens the list) | originals grant honored — `upstream_request` served to `payload.read_originals` holders | `scope=originals` 200 with original captures; `scope=read` still never unlocks originals | identical to pre-toggle (no originals in list rows) | byte-identical pre-toggle capture behavior (opt-in parity; joint PG+Redis toggle/read matrix) | tested |
| Retention store error / unwired store / empty org (any config) | — | — | `scope=originals` → 503, audited `retention_unavailable`, grant not consumed | — | resolver answers OFF, never caches the error answer | tested |
| Unknown/unsupported values | boolean column: no third value exists; `NULL`/`false`/`true` are the only representable states. Unknown **wire** `content_profile` values fail closed to metadata-only (`EffectiveLogContentProfile`; `TestEffectiveLogContentProfile`) | PATCH bodies `{}` / non-bool / unknown values → 400, store never mutated (`TestOrgOriginalRetentionHandlerRejectsMalformedBody`, `TestOriginalRetentionUnsupportedCasesFailLoudly`) | unknown `scope` → 400; unknown grant scope → store-level `ErrInvalidRequestPayloadGrant` | — | — | unsupported (loud failure, never an implicit allow) |

Decision seam note: content read authorization is a mandatory check on
`pipeline.AuthorizationVerdict` (deny > grant > role, including scoped deny rules). A check that **cannot run** (evaluator/decision source
unavailable) denies with the typed `unavailable` class and is journalled as
`request_content_authz.unavailable`; future external decision
providers plug in through `pipeline.DecisionProvider` /
`pipeline.DecideExternal` with the same fail-closed contract — the core ships
zero provider implementations; no OPA integration is included.

## Guard packs compatibility matrix

Offline detector packs (`guardpacks.v1` manifest + one SHA-256-verified
`detector.json`, `YABANIN_GUARD_PACK_DIR` / `YABANIN_GUARD_ACTIVE_PACKS`) —
verified matrix; statuses are `tested` (pinned by `pkg/guardhooks` /
`pkg/gateway` tests) unless stated otherwise.

### Manifest version matrix (unsupported ⇒ loud, never silent)

| `schema_version` | `runtime_api` | Result |
| --- | --- | --- |
| `guardpacks.v1` | `guardrails.v1` | loads (the only supported cell) |
| `guardpacks.v0` / `guardpacks.v2` / unknown / empty | any | rejected: `incompatible schema version` at decode, before any file is opened |
| any | `guardrails.v0` / `guardrails.v2` / unknown / empty | rejected: `incompatible runtime API` |
| declared `signature` (any) without a configured verifier | any | rejected fail-closed: `signature declared but no verifier configured` |
| signature scheme ≠ `guardpack-sig.v1` or algorithm ≠ `ed25519` | any | rejected explicitly before the verifier is consulted (never silently re-interpreted) |

A pack rejected at decode or load never stages: no shadow hook, nothing
activatable (`TestPackManifestCompatMatrix`).

### Size and shape boundaries (at-limit accepted, one-over rejected)

| Boundary | At limit | Over limit |
| --- | --- | --- |
| Manifest bytes | 1 MiB exactly decodes | +1 byte ⇒ `exceeds` before decode |
| `detector.json` bytes | 4 MiB exactly loads and enforces | +1 byte ⇒ `exceeds` before decode |
| Files per manifest | 64 entries decode | 65 ⇒ `file limit` (pack shape requires exactly one `detector.json` anyway) |
| Detectors per pack | 256 load and all enforce | 257 ⇒ `detector limit` before any regex compile |
| Findings per evaluation | 10 000 retained | rest dropped + `gateway_guard_findings_truncated_total` increments (pack regex path pinned) |

Lifecycle edges — empty pack directory, zero detectors, duplicate
`rule_id`+`rule_version` (one pack or across staged packs), invalid regex,
path traversal/symlink escape — are loud rejections that stage nothing
(`TestPackBoundaryCorpus` and the pack/lifecycle tests it extends). Duplicate
`rule_id` with a **different** `rule_version` is a distinct identity and is
accepted by contract.

### Activation, rollback, interruption

| Scenario | Behavior |
| --- | --- |
| Stage → activate → rollback → second rollback | two-slot history stays real; every CAS names exactly the version whose detectors the hook enforces (`lifecycle_second_rollback_test.go`) |
| Rollback with a failing durable CAS | refused before any state swap; retry after recovery converges; chain stays real (`TestPackLifecycleRollbackSurvivesCASConflict`) |
| Double activation without a fresh candidate | second `Activate` refused (`no staged pack`), no extra CAS write; a CAS-error activation keeps the candidate staged for the operator retry (`TestPackActivateDoubleActivationNoSideEffects`) |
| Activation interrupted mid-materialization (CAS won, process died) | the durable row is the single activation point: admin hydration and gateway restarts ADOPT the row with zero CAS writes, then the next operator transition CASes exactly what the row expects (`TestGuardPackActivationInterruptedMidMaterializationConverges`) |
| Watcher probe interrupted (cancelled context) while the row moves | last known-good hook keeps enforcing, `gateway_guard_pack_watch_failures_total` increments, convergence on the first healthy probe; adoption never writes the row (`TestGuardPackWatcherProbeInterruptedKeepsLastKnownGood`) |

### False-positive feedback path

Findings surface on exactly three channels: the structured log line
(`guard hook detection` / `guard detection (shadow)`, categories only — never
inspected content), Prometheus counters (`gateway_guard_hooks_total`,
`gateway_guard_findings_truncated_total`), and the request outcome (deny 400 /
MCP 409 in enforce mode; audit-only forward in shadow). The durable audit
journal records **lifecycle actions** (`guard_pack` activate/rollback), not
individual findings. Findings never mutate policy: no CAS write, no re-stage,
no automatic activation or rule adjustment — a false positive is fixed by the
operator editing the pack and explicitly activating the new version
(`TestGuardPackFindingsNeverMutatePolicyState`).

### Pack features and limits

Core supports operator-authored packs on disk: manifest and file SHA-256
verification, regex detector compilation, egress and MCP enforcement, and
root-only validate, simulate, activate, rollback and status operations. Activation
uses durable compare-and-swap coordination across gateway replicas; lifecycle
actions are recorded in the audit journal.

Signed packs can be verified with Ed25519 against an explicitly configured static
key set (`YABANIN_GUARD_PACK_VERIFY_KEYS_DIR` or
`YABANIN_GUARD_PACK_VERIFY_KEYS`). Verification checks integrity, not licensing.

Key generation, signing, distribution and automatic rotation are not included.
Changing trusted keys requires a configuration change and re-staging. There are
no revocation lists or multi-scheme negotiation. The `detector.json` format does
not declare HTTP detector endpoints. The admin UI does not collect each gateway
replica's applied version; use gateway metrics and adoption logs for that view.

### Remote detector endpoints — HTTPS requirements

**Decision: https is the production requirement for a remote guard detector
endpoint; cleartext `http` is tolerated only for loopback/test rigs, and a
cleartext non-loopback endpoint announces itself with a loud warning at
construction** (`callout.NewGuardDetector`, pinned by
`TestGuardDetectorHTTPSPosture`). Rationale:

- The pack-facing standalone adapter (`guardhooks.NewHTTPDetector`) already
  enforces https **unconditionally** — strict by construction, stricter than a
  config-gated flag, so there is nothing to switch on for packs that use it.
- The callout adapter keeps `http` accepted so loopback httptest rigs (and
  same-host dev detectors) work; the operator allow-list plus the dial-time
  reserved-IP guard remain the hard controls there. The warn converts the
  former silent convention into an explicit setting.
- Pack-declared HTTP detector endpoints do not exist yet (no `http_detector`
  spec kind in `detector.json`); when that integration is implemented it must use the
  https-only adapter or gate cleartext behind an explicit config flag
  (default strict). Transport hardening (allow-list, no redirects, no
  retries, breaker, singleflight, bounded payloads) is unchanged and applies
  to both adapters.

## Client verification limits

The Codex CLI row records a real binary talking to a gateway backed by a
mock provider. Other live-CLI rows remain `not verified` until a dated run
is recorded. Synthetic fixtures, HTTP smoke scripts, and a running CLI do
not by themselves establish compatibility with a live paid provider.
