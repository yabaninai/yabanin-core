# Coding-client integration modes audit

Read-only audit of documented coding-client integration claims against source
at base `ffc01005dfde91953161ea02b96feae8756c0e1c` (branch `task/cpc00-01`,
worktree `core-cpc00-a`), performed 2026-11-10. This document is the only file
changed by this child. No implementation, test or credential file was touched,
and no credential content was read, printed or copied — file names, paths and
code paths only.

Scope: coding-client integration modes and claim authorization. This child
installs no product gate; it classifies existing evidence. A requirement
quoted below is not evidence that a product gate is installed.

Classifications:

- **source-verified** — the documented claim matches code at the cited
  `file:line` at the base above.
- **fixture-only-evidence** — the behavior exists at source, but tests drive
  fixtures or mock upstreams, not the real client binary.
- **documented-unverified** — the docs themselves state that no live evidence
  exists.
- **stale** — doc text and the source/test pin disagree at this base.

## 1. Responses API (`docs/clients/codex.md`, `docs/compatibility.md`)

| Claim | Source at base | Mode | Policy point | Evidence | Classification |
| --- | --- | --- | --- | --- | --- |
| Native forwarding when the resolved provider is `openai` and the org has no deny tool policy; otherwise translated (`codex.md:45-47`) | `wantResponsesNative` `pkg/gateway/responses_endpoint.go:82-106`: provider list gate `:83`/`:98`, deny-policy fallback `:101-104`; default list `openai` from `YABANIN_RESPONSES_NATIVE_PROVIDERS` `pkg/config/config.go:926-935` (field `:144-148`, wiring `:440`) | native (conditional) | `policyPreUpstream` OP-8 point `pkg/gateway/responses_native.go:49`; `client.Do` `/v1/responses` `:104`/`:167` | Go fixtures with mock upstreams only: `responses_cancel_test.go:43`, `responses_endpoint_test.go:217-333`, `responses_failure_test.go:116,144`, `events_golden_test.go:1095,1143`, `prompt_cache_transparency_test.go:151` | source-verified (dispatch); native branch is fixture-only-evidence — no real binary has traversed it (see §4) |
| `previous_response_id` rejected with 400 everywhere; stateless on both paths (`codex.md:58-60`, compatibility row 20) | `RejectPreviousResponseID` runs in the handler before dispatch, `responses_endpoint.go:25` | both | n/a (fail before policy) | fixtures + real binary (translated path) | source-verified |
| Dropped fields announced in `X-Yabanin-Unsupported`, never silently (`codex.md:61-63`) | `ResponsesToChat` `:33`, header from `meta.Dropped` `:39` | translated only | n/a | fixtures | source-verified (nothing is dropped on the native branch by construction) |
| `prompt_cache_key` session UUID mapped to session affinity; full-history resend flow (`codex.md:72-77`) | `PromptCacheKey` → `X-Session-Id` when a valid task id `responses_endpoint.go:46-48` | translated | n/a | real codex-cli run on the translated path | source-verified |
| Stream-break/hangup settlement semantics (`codex.md:64-71`) | `writeResponsesStreamFailed`, `relayResponsesSSE`, `finishResponsesNative` `pkg/gateway/responses_native.go:238,266,372` | both | n/a | mid-stream cancel real-binary scenario `responses_codex_real_test.go:760` (translated path) | source-verified |
| Codex real-binary e2e verified `0.162.1`/`0.163.0`/`0.166.0` (`codex.md:4-10,80-83`, compatibility row 31, `sdk-versions.md:220`) | Test card pin is `codexExpectedVersion = "0.167.0"` `responses_codex_real_test.go:199-201`; `requirePinnedCodex` loud-skips on mismatch `:205-233` | — | — | the 0.167.0 re-run record exists in the test card but not in the three doc locations | **stale** (doc version pins lag the card pin; refresh after the next recorded run) |

## 2. Messages API (`docs/clients/claude-code.md`, compatibility rows 21-23)

| Claim | Source at base | Mode | Policy point | Evidence | Classification |
| --- | --- | --- | --- | --- | --- |
| `provider=anthropic` forwarded as-is incl. `cache_control`; any other provider translated (`claude-code.md:43-45`) | probe `resolveModelInfo` → `messagesNative` `pkg/gateway/messages_endpoint.go:31-32`; else `AnthropicToChat` `:36` with `X-Yabanin-Dropped` `:46` | native (conditional) / translated | `policyPreUpstream` OP-8 point `pkg/gateway/messages_native.go:50`; `client.Do` `/v1/messages` `:100,153` | `messages_claudecode_loop_test.go:1-8` states the real Claude Code binary is not exercised; consumer-auth/matrix fixtures per compatibility row 23 | source-verified; fixture-only-evidence (live row stays `not verified`, compatibility row 32) |
| Translation drops `thinking`, hosted tools, `cache_control` (`claude-code.md:56`) | dropped-fields header path `messages_endpoint.go:36-46` | translated | n/a | fixtures | source-verified |
| "Native Anthropic mode does not apply tool gating" (`claude-code.md:57`, compatibility row 22) | No `toolPolicies`/toolgate reference exists in `messages_native.go` at base, and unlike Responses there is no deny-policy dispatch fallback (`messages_endpoint.go:31-33` has no `HasDenyPolicies` check). Gating lives on chat paths only: `gateToolCallsJSON` `pkg/gateway/toolgate.go:47` (deny check `:48`), SSE gate `pkg/gateway/stream.go:772` | native | general policy still runs (`policyPreUpstream` `messages_native.go:50` → `gateway_policy.go:1465`); only tool-specific gating is absent | fixtures | source-verified — and the gap is tool-specific, not total: state the absent enforcement precisely (specific tool gating) rather than claiming all policy is absent; enforcing or explicitly rejecting tool calls on the native path is residual work (§6.2) |
| Token estimates via `POST /v1/messages/count_tokens` (`claude-code.md:45`) | `countTokens` `pkg/gateway/messages_count.go:15`: anthropic passthrough `:37-39`; otherwise `X-Yabanin-Estimated` with bytes/4 heuristic `:47` | both | `SkipSpendChecks` admission | fixtures | source-verified (the estimate marker makes the heuristic explicit on the wire) |
| (undocumented behavior) `x-claude-code-session-id` copied to `X-Session-Id` when a valid task id | `messages_endpoint.go:19-23` | both | session affinity | fixtures | source-verified, unclaimed in docs |
| (undocumented behavior) Anthropic-shaped error envelope on `/v1/messages*` | `anthropicErrorEnvelope` `messages_endpoint.go:100`, registered `gateway.go:1972` | both | n/a | fixtures | source-verified, unclaimed in docs |

## 3. Harness, client-config and adapters docs

| Claim | Source at base | Evidence | Classification |
| --- | --- | --- | --- |
| `yb harness` command table (`docs/harness.md:6-13`) | `harnessCmd` `pkg/trcli/harness.go:25`, `list :34`, `connect :85` (flags `--dry-run/--force/--session/--session-ttl`), `runHarnessConnect :108`, `disconnect :179`, `status :227`, `doctor :257/:268` (key not printed), `key :317`, `lookupAPIKey :559` (env → credstore; no secret content handled here) | CLI unit tests | source-verified |
| Managed blocks; refused tools listed with reasons; `0600` backups (`docs/harness.md:14-27`) | codex adapter `pkg/harness/adapters/codex.go:36` (`RemoveManagedBlocks "codex:top"/"codex:provider"`; refuses unmanaged `[model_providers.yabanin]`), journal/state under `~/.yabanin/harness` (`pkg/harness/state.go`) | adapter tests | source-verified |
| Session keys; "a mint failure prints the parent key and a warning on stderr so the tool keeps working" (`docs/harness.md:31-49`) | `harnessKey` `pkg/trcli/session_harness.go:27`; parent-key fallbacks at `:48,52,60,71,73-77`; `parentKeyFallback :85` | unit tests | source-verified as a description — **audit point (a)**: this documented fallback conflicts with the least-privilege harness-key rule that a stronger fallback key must never be granted after a failed least-privilege setup; also `docs/harness.md:47-49` admits installed-helper checks were not run. Residual (§6.3) |
| Concurrent user edits: plan/apply conflicts detected, not clobbered; rollback preserves unrelated edits (`docs/extensions/adapters.md:88-105`) | `Engine.Apply` `pkg/harness/engine.go:108` with `matchesBefore` `:120/:145` ("file changed since planning" `:153/:158`); `Rollback :236` exact-restore via post-edit hash, else adapter `Unapply`, else reported conflict; cross-process `flock` `pkg/harness/lock_unix.go:18` | engine tests | source-verified — **audit point (b)** resolved: edits concurrent with planning abort the apply; rollback never silently discards user changes |
| Adapter contract and render/apply separation (`docs/extensions/adapters.md:51-71,107-125`) | `Adapter` interface `pkg/harness/adapters/registry.go`; render-only `pkg/trcli/client_config.go` → `pkg/clientconfig` (no shared renderer interface); apply only via `harness.Engine` | unit tests | source-verified |
| `clientconfig.Params` never carries the raw API key (`docs/extensions/adapters.md:13-18`) | `pkg/clientconfig/clientconfig.go:5` ("The API key itself is never included"); render helpers `render.go` are pure string builders | golden tests | source-verified |

## 4. Real-binary evidence today

The **only** real coding-client binary evidence at this base is codex-cli:

- Scenarios: `TestResponses_CodexCLI_RealE2E` (`pkg/gateway/responses_codex_real_test.go:63`), `_ToolsLoop :444`, `_UnsupportedToolCall :673`, `_ClientCancel :760`; plus the scripted mock-CLI e2e `TestResponses_CodexCLI_MockE2E` (`responses_codex_cli_test.go:135,271`), which is not a real binary.
- Pin: `codexExpectedVersion "0.167.0"` with loud skip on mismatch (`responses_codex_real_test.go:199-233`).
- Path caveat: all four real-binary tests build the gateway through
  `responsesTestGateway` (`responses_endpoint_test.go:24`; call sites
  `responses_codex_real_test.go:95,509,704,803`), which does **not** set
  `ResponsesNativeProviders` — `responses_codex_real_test.go` contains zero
  occurrences of that field at base (the `responses_endpoint_test.go` fixture
  tests set it themselves after the helper returns, not via the shared helper;
  see §1). The
  real binary therefore exercised the **translated** Responses→chat path with
  a mock chat upstream behind the gateway. The **native Responses branch has
  zero real-binary evidence**; its evidence is Go fixtures with mock upstreams
  (§1). No paid upstream is covered anywhere (`codex.md:9-10`,
  compatibility `:170-175`).
- Claude Code: fixture-only (`messages_claudecode_loop_test.go:1-8`); the live
  row is honestly `not verified` (compatibility row 32). Same for OpenCode,
  Continue, Cline (rows 33-35) — **documented-unverified**, no overclaim found.
- Subscription-bridge: every `node:test` suite uses `fakeRunner` or pure
  functions (`runners.test.ts`, `contract.test.ts:60-203`, `listen.test.ts`);
  no test executes the real Codex SDK or a real Cursor CLI —
  **fixture-only-evidence**.

## 5. Subscription-bridge (`services/subscription-bridge/`) audit asks

| Audit ask | Source at base | Status |
| --- | --- | --- |
| SDK auth choice | Codex: `realCodexRunner` `src/runners.ts:81-110` constructs `new Codex()` with **no credentials** — ambient local login; `sandboxMode` read-only/workspace-write, `approvalPolicy "never"`, `networkAccessEnabled false`. Cursor: `cursorChildEnv :132` deletes `CURSOR_API_KEY` so the CLI uses subscription login; `buildCursorCliArgs :158` emits no key flags; `realCursorRunner :217` throws if any `--api-key` arg appears | verified at source; no key material on any child command line |
| File-existence readiness | `codexLoggedIn :76-78` = `CODEX_API_KEY` env or `~/.codex/auth.json` **exists** — existence, not entitlement — existing names do not prove subscription rights. Cursor readiness runs `agent status` and string-matches `cursorStatusLooksLoggedIn :143` (`cursorCliLoggedIn :206-214`) | confirmed gap: readiness ≠ entitlement; `/readyz`,`/v1/status` surface it (`src/server.ts:69-84`) |
| Bounded output | Summaries capped at 4000 chars (`boundText :314`; `parseCursorPrintJson :175`), but `spawnCaptured :269-312` buffers full child stdout/stderr in memory with **no byte cap** | partial — residual |
| Child shutdown | AbortSignal/timeout → `SIGTERM` (`:289-299`); default timeout 14 min (`server.ts:139-140`); `close()` aborts all runs (`server.ts:184-189`); Codex SDK takes `{signal}` in `thread.run`. **No SIGKILL escalation** if SIGTERM is ignored | partial — residual |
| Launch-root constraint and concurrency limits | `confinePath server.ts:26-43` (realpath confinement; `workspace_escape :121-124`); changed-files post-filter `:146-148`; `WRITE_LIMIT=1`/`ANALYZE_LIMIT=2` `:7-8` admission `:125-135` (`concurrency_limit`); loopback-only bind `:22-24/:46-48` + Host-header check `:59-62` | verified at source; all bridge behavior evidence is fake-runner (`contract.test.ts`) |
| (observed) no request authentication on the bridge | Loopback bind + Host header check are the only access controls (`server.ts:46-48,59-62`); any local process reaching the port may delegate | residual security note (§6.5) |
| (observed) Cursor changed-file reporting absent | `realCursorRunner` returns `changed_files: []` unconditionally | residual (Codex extracts paths from SDK items, post-filtered) |

## 6. Residual work register (input to follow-up work)

1. **Native Responses path has no real-binary evidence** — the first
   qualification run should drive codex-cli through a gateway configured with
   `ResponsesNativeProviders`; "full supported native protocol" must not be
   claimed for the API-funded mode until such a run is recorded.
2. **Messages native tool gating** — the native Messages path must enforce or
   explicitly reject tool calls under a deny policy; today the deny-policy
   dispatch fallback exists only for Responses
   (`responses_endpoint.go:101-104`), not Messages.
3. **Parent-key fallback after mint failure** — documented and implemented, but
   conflicts with the least-privilege harness-key rule that a stronger
   fallback key must never be granted after a failed least-privilege setup
   (`session_harness.go:48-85`); decide in follow-up work whether the fallback
   is removed, narrowed or owner-accepted.
4. **Doc version staleness** — codex pin 0.167.0 in the test card vs 0.166.0 in
   `codex.md`, `compatibility.md:31`, `sdk-versions.md:220`.
5. **Subscription-bridge**: unbounded child stdout/stderr buffering, no SIGKILL
   escalation, Cursor changed-file reporting absent, no bridge request
   authentication beyond loopback, readiness-by-file-existence semantics.
6. **Claude Code live row** remains `not verified`; any claim that it is
   verified needs a dated real-binary run, not the fixture loop.

No undocumented capability claim was found in `docs/clients/opencode.md`,
`continue.md` or `cline.md` — each is documented-unverified and matches the
compatibility matrix. Existing implementations were preserved; this child
changed no product behavior.
