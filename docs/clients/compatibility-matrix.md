# Coding-client compatibility and acceptance matrix

Source-bound snapshot at commit `6da73e63ec580812204a8e01bd07e9fc3f2e3954`
(branch `task/cpc00-04`, worktree `core-cpc00-d`), written 2026-11-11. This
document is the per-version, per-mode matrix of **supported**, **unsupported**
and **unverified** coding-client features. One row exists for each actual
client version and mode found in source at that commit; every row carries the
exact existing evidence, the acceptance profile that validates the claim, and
the concrete check a tester runs. Recording anything here grants nothing and
installs no gate; a row is a claim bound to cited evidence, not a promise
about newer client versions.

Companions: `docs/clients/mode-contracts.md` freezes the mode contracts
(M1/M2/M3, S1–S6), `docs/clients/ownership-map.md` maps commands and
credential paths, `docs/clients/modes-audit.md` classified evidence at its
own earlier base, `docs/compatibility.md` owns the gateway protocol rows and
`docs/clients/sdk-versions.md` the SDK packages. This matrix binds their
claims to concrete client versions and modes at the base above.

Rules used throughout:

- Credential safety: credential **names, flows and file paths only**. No
  credential value was read, printed or recorded while building this document.
- Citation promise: every `path:line` citation below resolves at the commit
  named above (checked mechanically; see §7).
- A client version not pinned anywhere in source cannot have a per-version
  compatibility claim; its rows below are per-protocol and stay unverified
  against any real binary.

## 1. Evidence classes

| Tag | Class | Meaning |
| --- | --- | --- |
| E1 | real-binary run | A test drives an actual client binary through the real gateway code on a live port; the binary version is pinned in source and a run is recorded |
| E2 | real-protocol capture | An anonymized wire body captured from a named real client version, replayed against the gateway (`pkg/gateway/testdata/compat/real/manifest.json`); it pins the wire shape of exactly that version — it is not a live run and does not refresh an E1 row |
| E3 | shape fixture | A synthetic request built by a test ("X-shaped"); **not real-client evidence** — cited only as fixture-shaped, unverified against the real client |
| E4 | source-verified | The code path exists at the cited `file:line` and is pinned by unit tests at internal seams; no client-protocol claim |
| — | unverified | No evidence either way; absence of a test is not absence of behavior |
| — | unsupported | Checked absence of a route or feature, with the refusing code path cited |

E2 provenance and invalidation rules live in the manifest itself
(`pkg/gateway/testdata/compat/real/manifest.json`: a row is bound to
`(client_version, captured_at)`; any client update invalidates it until
recaptured).

## 2. Actual client versions in source

| Version | Client | Pinned at | Highest evidence |
| --- | --- | --- | --- |
| 0.167.0 | Codex CLI | `pkg/gateway/responses_codex_real_test.go:201` (card pin; evidence base re-verified 2026-11-09 `:191`) | E1 |
| 0.166.0 | Codex CLI | `pkg/gateway/testdata/compat/real/manifest.json:48-53` (capture 2026-11-03); documented e2e `docs/clients/codex.md:7`, `docs/compatibility.md:31` | E1 + E2 |
| 0.163.0, 0.162.1 | Codex CLI | documented e2e history only (`docs/clients/codex.md:6`, `docs/compatibility.md:31`) | E1 (historic) |
| 1.19.5 | OpenCode CLI | `pkg/gateway/testdata/compat/real/manifest.json:20`, `:35` (captures 2026-11-03); recorded loop note `pkg/gateway/chat_opencode_real_test.go:152-154` | E1 (harness + recorded note) + E2 |
| 0.153.0 | `@openai/codex-sdk` (bridge codex runner) | `services/subscription-bridge/package.json:15-17` (optionalDependency pin) | E3 (fake runners only) |
| (unpinned) | Cursor CLI (bridge cursor runner) | no version pin; binary override `services/subscription-bridge/src/runners.ts:150` | E3 |
| (unpinned) | Claude Code | no pin; the loop suite states the binary is not exercised (`pkg/gateway/messages_claudecode_loop_test.go:3-5`) | E3 |
| (unpinned) | Cline, Continue | no pin (`docs/compatibility.md:34-35` live rows `not verified`) | E3 |
| (unpinned) | Aider | no pin; render/adapter only | E4 |
| (scripted) | mock codex CLI | `pkg/gateway/responses_codex_cli_test.go:135`, `:271` — a scripted mock, explicitly **not** a real binary; regression harness only | E3 by construction |

## 3. Modes

Mode contracts are frozen in `docs/clients/mode-contracts.md`: M1 personal
direct-client (§2), M2 local app-bound ChatGPT via the subscription bridge
(§3), M3 organization API (§4), S1–S6 additional modes (§5). Protocol paths
inside M1/M3 that this matrix splits on:

- Responses: native forwarding vs chat translation, dispatch at
  `pkg/gateway/responses_endpoint.go:29` (`:82-106`).
- Messages: native `provider=anthropic` forwarding vs translation
  (`pkg/gateway/messages_endpoint.go:31-36`).
- Chat passthrough (`pkg/gateway/gateway.go:1946`) and FIM completions
  (`pkg/gateway/gateway.go:1950`).

## 4. Matrix

Column key — **Status**: supported / unsupported / unverified. **Evidence**:
class tag from §1 plus the exact citation. **Profile**: the acceptance
profile (§5) whose oracle validates the claim. **Acceptance check**: the
concrete check a tester runs against the real product artifact.

### 4.1 Codex CLI × M1 × Responses (translated)

The only client path with E1 evidence. All four real-binary scenarios build
the gateway through `responsesTestGateway`
(`pkg/gateway/responses_endpoint_test.go:24`), which never sets
`ResponsesNativeProviders` (zero occurrences in
`pkg/gateway/responses_codex_real_test.go`), so the real binary exercised the
**translated** Responses→chat path against a mock upstream. Version binding:
E1 scenarios are pinned 0.167.0
(`pkg/gateway/responses_codex_real_test.go:201`) with the recorded evidence
base "2026-11-03, codex-cli 0.166.0; re-verified 2026-11-09 on 0.167.0"
(`pkg/gateway/responses_codex_real_test.go:191`); the E2 wire capture is
0.166.0 (`pkg/gateway/testdata/compat/real/manifest.json:48-61`). Doc rows still cite
0.166.0 as latest (`docs/compatibility.md:31`, `docs/clients/sdk-versions.md:220`)
— see §6.

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Full client loop: `codex exec` → `/v1/responses` → translated chat upstream → CLI prints the answer | supported | E1 `pkg/gateway/responses_codex_real_test.go:63`, `:191` | IP-CODING | `go test ./pkg/gateway -run TestResponses_CodexCLI_RealE2E -count=1` with a 0.167.0 binary (`YABANIN_CODEX_BIN`); independent stream parser + durable admissions reconcile one logical request |
| Multi-turn tool loop on the stateless full-history resend (`store=false`, `previous_response_id=null` every turn) | supported | E1 `pkg/gateway/responses_codex_real_test.go:444`; wire shape E2 `manifest.json:54` (`store=false`, `prompt_cache_key`, encrypted-reasoning include) | IP-CODING | `go test ./pkg/gateway -run TestResponses_CodexCLI_RealE2E_ToolsLoop`; assert tool-call IDs preserved end-to-end and no duplicate paid execution |
| Unsupported tool call fed back verbatim (`unsupported call: <name>`), never a fake success | supported | E1 `pkg/gateway/responses_codex_real_test.go:673` | IP-CODING | `go test ./pkg/gateway -run TestResponses_CodexCLI_RealE2E_UnsupportedToolCall`; assert the CLI run completes with the limitation reported |
| Mid-stream client cancel (SIGINT): honest CLI death, exactly one terminal gateway event, relay torn down | supported | E1 `pkg/gateway/responses_codex_real_test.go:760` | IP-CODING | `go test ./pkg/gateway -run TestResponses_CodexCLI_RealE2E_ClientCancel`; ledger shows no false success and no charge for the interrupted stream |
| `previous_response_id` refused with 400 (stateless surface, both paths) | supported (refusal) | E1 real session-id refusal recorded `pkg/gateway/responses_codex_real_test.go:187-190`; refusing path `pkg/gateway/responses_endpoint.go:25`; E3 `pkg/gateway/compat_test.go:34` | IP-CODING | send a request with `previous_response_id` through the pinned binary and directly; both must return 400 with zero upstream calls |
| Dropped fields announced in `X-Yabanin-Unsupported` (e.g. `reasoning.effort` downgrade) | supported | E1 disclosed on the wire `pkg/gateway/responses_codex_real_test.go:187-190`; header set on the translated branch `pkg/gateway/responses_endpoint.go:38-40`; claim `docs/clients/codex.md:62-64` | IP-CODING | capture the response headers during the ToolsLoop run; every dropped field appears in the header, none silently |
| `prompt_cache_key` session UUID → session affinity | supported | E1 loop `pkg/gateway/responses_codex_real_test.go:444`; wire shape E2 `pkg/gateway/testdata/compat/real/manifest.json:54`; mapping `pkg/gateway/responses_endpoint.go:46-47`; claim `docs/clients/codex.md:72-77` | IP-CODING | multi-turn run: all turns of one session land on the same affinity key in the durable request rows |
| Bearer auth via `env_key`/helper (no key material in config) | supported | E1 (the e2e renders `config.toml` with `env_key`); render `pkg/clientconfig/codex.go:49`; invariant `pkg/clientconfig/clientconfig.go:5`; goldens `pkg/clientconfig/render_test.go:12` | IP-PLAN-AUTH | `yb client-config --client codex`; assert output contains no key value; inspect the e2e-workdir config for key material |
| Paid (non-mock) upstream | unverified | no evidence either way; limitation recorded `docs/compatibility.md:31`, `docs/clients/codex.md:6-9` | IP-CODING | live provider run, separately labeled, with recipient-side cost reconciliation |
| ChatGPT-OAuth login (`codex login`) as gateway auth | unsupported | `docs/clients/codex.md:78-79`; gateway accepts bearer keys only (`pkg/gateway/auth.go:81-84`) — no OAuth route exists | IP-PLAN-AUTH | attempt an OAuth-flow login against the gateway; expect refusal; negative control: assert no token-exchange route answers |

### 4.2 Codex CLI × M1 × Responses (native)

Native forwarding requires the resolved provider in
`ResponsesNativeProviders` (default `openai`,
`pkg/config/config.go:926-927`, wiring `:440`) and no deny tool policy
(`pkg/gateway/responses_endpoint.go:102`); otherwise dispatch falls back to
translation (`:29`).

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Unchanged body forwarding, non-stream and stream (`/v1/responses` upstream) | supported (fixture-shaped, unverified against real client) | E3 `pkg/gateway/responses_endpoint_test.go:217`, `:294`, `:333`; upstream calls `pkg/gateway/responses_native.go:104`, `:167` | IP-CODING | first qualification run: pinned codex binary through a gateway configured with `ResponsesNativeProviders`; independent wire capture must show byte-identical forwarding |
| General policy enforcement before upstream (masking/label policy) | supported (fixture-shaped) | E4 `pkg/gateway/responses_native.go:49` | IP-CODING | policy-on run with a synthetic secret canary; canary must not reach the recipient |
| Stream-break settlement: `response.failed` appended, `request.failed`, no charge | supported (fixture-shaped) | E4 `pkg/gateway/responses_native.go:212`, `:228-232`, `:238-240` | IP-CODING | kill the upstream mid-stream; durable ledger records one failed request and zero charge |
| Real codex-cli on the native branch | unverified | zero E1/E2 evidence: `responsesTestGateway` never sets `ResponsesNativeProviders` (see 4.1 preamble); E2 capture 0.166.0 was taken on the translated path | IP-CODING | the qualification run above; until recorded, no native-fidelity claim may be made |
| Deny-policy orgs silently staying native | unsupported (by design: falls back to translated) | dispatch fallback `pkg/gateway/responses_endpoint.go:102` | IP-CODING | org with a deny tool policy: request is translated, announced via `X-Yabanin-Unsupported` |

### 4.3 `@openai/codex-sdk` 0.153.0 × M2 (subscription bridge codex runner)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| HTTP surface `/healthz` `/readyz` `/v1/status` `/v1/cancel` `/v1/delegate` | supported (fixture-shaped) | E3 `services/subscription-bridge/src/server.ts:65`, `:69`, `:75`, `:85`, `:93`; suite `src/contract.test.ts` | IP-CODING | `make test-subscription-bridge` (fake runners); then a real-login run below |
| Ambient subscription login: SDK constructed with no credentials | supported (fixture-shaped) | E4 `services/subscription-bridge/src/runners.ts:91`; sandbox `:90`, approval `never` `:96`, network off `:97` | IP-PLAN-AUTH | outbound host/principal recorder during a real delegated run: recipients are provider endpoints only, never the Yabanin gateway; filesystem inspection proves no gateway credential exists in the bridge |
| Readiness = `CODEX_API_KEY` presence or `~/.codex/auth.json` existing (names only) | supported (heuristic; not entitlement) | E4 `services/subscription-bridge/src/runners.ts:76-78` | IP-PLAN-AUTH | revoked-subscription fault from IP-PLAN-AUTH: readiness may say ready; the run must surface `provider_not_authorized` |
| Workspace confinement (`workspace_escape`), WRITE=1/ANALYZE=2, changed-files post-filter | supported (fixture-shaped) | E4 `services/subscription-bridge/src/server.ts:121-123`, `:7-8`, `:126`, `:131`, `:147`; tests `src/contract.test.ts` | IP-CODING | delegate a task with a workspace path outside the launch root: refused; concurrently push 2 writes: one admitted, one `concurrency_limit` |
| Provider quota/auth failures → stable `quota_exhausted` / `provider_not_authorized` | supported (fixture-shaped) | E3 `services/subscription-bridge/src/contract.test.ts:66`, `:74`, `:78`, `:86` | IP-PLAN-AUTH | quota-to-paid fault: exhausted subscription must never fall back to charging a Yabanin budget (billing ledger oracle) |
| Runs in-memory only; no durable state | supported (fixture-shaped) | E4 `services/subscription-bridge/src/server.ts:49` | IP-PLAN-AUTH | restart the bridge: zero runs survive; gateway-side spend rows are the only record |
| Real Codex SDK / real subscription execution | unverified | every runner test uses `fakeRunner` (`src/contract.test.ts:7`, `:15`; `src/runners.test.ts`) — no test executes the pinned SDK | IP-PLAN-AUTH | real-login run recorded with the oracle set above; until then the 0.153.0 pin has no real-execution evidence |
| `--api-key` CLI arguments to the runner | unsupported | refusing path `services/subscription-bridge/src/runners.ts:226-228` | IP-PLAN-AUTH | attempt delegation with `--api-key`: refused before spawn |
| Non-loopback bind (remote serving) | unsupported | refusing path `services/subscription-bridge/src/server.ts:46-47`; pinned `src/listen.test.ts:6-8` | IP-PLAN-AUTH | `YABANIN_BRIDGE_HOST=0.0.0.0` startup fails; by enforcement, not convention |
| Bridge handling Yabanin gateway credentials | unsupported (absence) | exhaustive-search negative control NC2, `docs/clients/ownership-map.md:249` | IP-PLAN-AUTH | key-store/filesystem inspection during a full run: no `yb_`/`ybs_`/`yag_` material anywhere in bridge state |
| Multi-user host safety (no per-request bridge auth) | unverified (and recorded unsafe) | loopback bind + Host check only (`src/server.ts:60-61`); residual 3, `docs/clients/mode-contracts.md` §6 | IP-PLAN-AUTH | any second local process can delegate; out-of-scope for qualification until an owner decision |

### 4.4 Cursor CLI (unpinned) × M2 (subscription bridge cursor runner)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Subscription login: `CURSOR_API_KEY` deleted from the child env | supported (fixture-shaped) | E3 unit `services/subscription-bridge/src/runners.ts:134`; pinned `src/runners.test.ts:29-32` | IP-PLAN-AUTH | env capture of a real run: no `CURSOR_API_KEY` in the child; the CLI uses its app login |
| Binary/model wiring (`YABANIN_CURSOR_AGENT`, `CURSOR_MODEL`) | supported (fixture-shaped) | E4 `src/runners.ts:150`, `:165` | IP-CODING | run with the override binary; recipient wire events match the real agent CLI |
| Real Cursor CLI execution | unverified | fake-runner suites only; readiness is an `agent status` text heuristic (`src/runners.ts:76-78` for codex; cursor path `:217`) | IP-CODING | record a real cursor-agent delegation run with the 4.3 oracle set |
| Changed-file reporting | unsupported | `realCursorRunner` returns `changed_files: []` unconditionally, `src/runners.ts:254` | IP-CODING | a real run that edits files still reports none; treat as known absent, verify workspace diff independently |
| `--api-key` CLI arguments | unsupported | shared refusal `src/runners.ts:226-228` | IP-PLAN-AUTH | same probe as 4.3 |

### 4.5 Claude Code (unpinned) × M1 × Messages (native `provider=anthropic`)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Native forwarding incl. `cache_control` | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:59`; path `pkg/gateway/messages_endpoint.go:31-32` → `pkg/gateway/messages_native.go:100`, `:153`; claim `docs/clients/claude-code.md:43-45`; row `docs/compatibility.md:22` | IP-CODING | record a real Claude Code binary run against an anthropic-resolved model; independent parser asserts byte-faithful upstream body |
| `count_tokens` passthrough for anthropic | supported (fixture-shaped) | E4 `pkg/gateway/messages_count.go:63` (estimate marker only on the translated path `:41`) | IP-CODING | count_tokens round-trip in the live run returns provider numbers, no `X-Yabanin-Estimated` marker |
| Tool-specific deny gating on the native path | unsupported (absent enforcement; general policy still runs) | no toolgate reference in `pkg/gateway/messages_native.go` at this base (checked); general policy `:50`; chat-side gating exists only in `pkg/gateway/toolgate.go:47` and `pkg/gateway/stream.go:772`; documented `docs/clients/claude-code.md:57`; residual `docs/clients/modes-audit.md:101` | IP-CODING | org with a deny tool policy: native Messages forwards the tool anyway — enforce or explicitly reject is recorded residual work |
| Real Claude Code binary | unverified | loop suite states the binary is not exercised, `pkg/gateway/messages_claudecode_loop_test.go:3-5`; row `docs/compatibility.md:32` | IP-CODING | a dated real-binary run replaces the fixture without changing the loop (`:3-5`) |

### 4.6 Claude Code (unpinned) × M1 × Messages (translated)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Translation to chat completions; `thinking`, hosted tools, `cache_control` dropped and announced via `X-Yabanin-Dropped` | supported (fixture-shaped) | E3 `pkg/gateway/messages_endpoint.go:36`, `:46`; `pkg/gateway/compat_test.go:59`; claim `docs/clients/claude-code.md:56`; row `docs/compatibility.md:21` | IP-CODING | fixture replay asserts the header lists every dropped field; a real-binary run must observe the same header |
| `tool_use` / `tool_result` round-trip in the client format | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:59`; row `docs/compatibility.md:21` | IP-CODING | multi-turn loop with a hermetic executor: `pkg/gateway/messages_claudecode_loop_test.go:334`; tool IDs survive the round-trip |
| Consumer configuration matrix (strict/header auth generations, unknown-model policy, explicit refusal of unsupported shapes) | supported (fixture-shaped) | E3 `pkg/gateway/messages_consumer_compat_test.go:48`, `:115`, `:185`; row `docs/compatibility.md:23` | IP-PLAN-AUTH | re-run the three matrix tests; negative control: pure header-mode without resolver and static key must refuse every token (fail-closed) |
| `x-api-key` header accepted (normalized into `Authorization`, never forwarded) | supported (fixture-shaped) | E4 `pkg/gateway/auth.go:73-78` | IP-PLAN-AUTH | send `x-api-key`; assert upstream sees only `Authorization` |
| `x-claude-code-session-id` → session affinity | supported (fixture-shaped) | E4 `pkg/gateway/messages_endpoint.go:19-22` | IP-CODING | two turns with one session id land on one affinity key |
| Multi-step task loop contract (per-round billed requests) | supported (fixture-shaped) | E3 loop `pkg/gateway/messages_claudecode_loop_test.go:207`, `:334` | IP-CODING | loop run: N rounds → N settled requests in the ledger, no duplicates |

### 4.7 OpenCode 1.19.5 × M1 (chat passthrough)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Main-turn wire shape: `@ai-sdk/openai-compatible` body, 10 tool definitions, `tool_choice=auto`, stream usage | supported | E2 capture 1.19.5 `pkg/gateway/testdata/compat/real/manifest.json:33-38` (pins `:33-46`), replayed by `pkg/gateway/compat_real_fixtures_test.go:176` | IP-CODING | re-run the replay suite; the manifest anonymization subtest must stay green (no leaked identifiers) |
| Secondary thread-title probe (separate system-only completion, `max_tokens=32000`, stream usage) | supported | E2 `pkg/gateway/testdata/compat/real/manifest.json:18-30` | IP-CODING | same replay; assert the gateway answers both requests of one CLI turn without a duplicate logical request |
| Real-binary loop: `opencode run` → `/v1/chat/completions` → SSE → CLI prints the answer | supported | E1 harness `pkg/gateway/chat_opencode_real_test.go:59`; completed loop recorded 2026-11-02 on 1.19.5 `:152-154` (loud skip when the binary is absent `:63-66`); doc row still says `not verified` — see §6 | IP-CODING | `go test ./pkg/gateway -run TestChatCompletions_OpenCodeCLI_RealE2E -count=1` with `YABANIN_OPENCODE_BIN`; assert CLI output carries the magic answer, upstream hit ≥ 1, one `request.completed` observed |
| Function tool calls passed through; content arrays as chat parts | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:103`; row `docs/compatibility.md:24` | IP-CODING | covered by the E2 replay for 1.19.5 exactly; any newer opencode needs a fresh capture |
| Provider config render: `apiKey` always `{env:…}`, never a secret | supported | E4 `pkg/clientconfig/opencode.go:23-28`; goldens `pkg/clientconfig/render_test.go:12` | IP-PLAN-AUTH | `yb client-config --client opencode`; assert no key value in output |
| Live provider upstream | unverified | captures and e2e used a mock upstream (`manifest.json` limitations) | IP-CODING | live run, separately labeled |

### 4.8 Cline (unpinned) × M1 (chat)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Non-stream `tool_calls` round-trip | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:150`; row `docs/compatibility.md:25` | IP-CODING | replay fixture; a real Cline session stays unverified |
| Streaming `tool_calls` fragments merged by `index` | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:174` (2026-10-12); row `docs/compatibility.md:25` | IP-CODING | replay; negative control: dropping one fragment must break the merge assertion |
| Harness auto-edit | unsupported | refusing list `pkg/harness/adapters/registry.go:48` ("settings live in VS Code extension state"); render is instructions-only `pkg/clientconfig/cline.go:15` | — (harness scope, not a protocol claim) | `yb harness list` shows cline unsupported with the recorded reason |
| Live Cline session | unverified | row `docs/compatibility.md:35` | IP-CODING | a dated real Cline session through the gateway |

### 4.9 Continue (unpinned) × M1 (chat + FIM)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| FIM completions: `prompt` and `suffix` forwarded | supported (fixture-shaped) | E3 `pkg/gateway/compat_test.go:127`; suffix passthrough pinned `pkg/gateway/completions_endpoint_test.go:32-40`, stream `:59`; row `docs/compatibility.md:26` | IP-CODING | replay fixtures; assert `suffix` reaches the upstream body verbatim |
| Chat model config render | supported | E4 `pkg/clientconfig/continue.go`; goldens `pkg/clientconfig/render_test.go:12` | IP-PLAN-AUTH | render output contains an env reference, never a key value |
| Key helper | unsupported (client cannot call one) | recorded note `pkg/clientconfig/continue.go:43-44` | IP-PLAN-AUTH | render without `--key-mode helper`; env reference is the only mode |
| Harness auto-edit without opt-in | unsupported (gated) | refusal `pkg/harness/adapters/continue.go:27` (`--experimental` required) | — (harness scope) | `yb harness connect continue` without the flag changes nothing |
| Live Continue process | unverified | row `docs/compatibility.md:34` | IP-CODING | a dated real Continue chat + autocomplete run |

### 4.10 Aider (unpinned) × M1 (chat via env/helper)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| Config render: helper or env key line, base URL/model | supported | E4 `pkg/clientconfig/aider.go:31`, `:33`; goldens `pkg/clientconfig/render_test.go:12`; adapter in the supported list `pkg/harness/adapters/registry.go:46` | IP-PLAN-AUTH | render both modes; no key value in output |
| Aider-specific protocol behavior | unverified | no aider fixture or run exists; its transport is the generic chat row (`docs/compatibility.md:29`, source-reviewed) | IP-CODING | a dated real aider run; until then no aider-specific claim |

### 4.11 Mode-level invariants (any client version, M1/M3 data plane)

| Feature | Status | Evidence | Profile | Acceptance check |
| --- | --- | --- | --- | --- |
| `previous_response_id` refused everywhere (stateless gateway) | supported | `pkg/gateway/responses_endpoint.go:25`; E1 4.1 | IP-CODING | direct probe returns 400 with zero upstream calls |
| `x-api-key` normalized; client `X-User-Id` stripped, server-set from the resolved key | supported | E4 `pkg/gateway/auth.go:73-78`, `:65-67`, `:154` | IP-PLAN-AUTH | send forged `X-User-Id` + `x-api-key`; upstream sees neither |
| Label headers stripped after resolution; diagnostics on response | supported | E4 `pkg/gateway/labels_mw.go:37`, `:47-52` | IP-CODING | labeled request: affinity/labels recorded, headers not forwarded |
| Session-key mint gate (403 `session_mint_not_allowed`), TTL 60–43200, parent-expiry cap, 60/min rate | supported | E4 `pkg/gateway/sessionkeys_api.go:78-79`, `:102`, `:139-147`, `:124`, `:195`; tests `pkg/gateway/sessionkeys_api_test.go:169`, `:217`, `:332` | IP-PLAN-AUTH | matrix tests; negative: key without `can_mint_sessions` is refused, never falls back |
| Own-usage read gate (`can_read_usage`) | supported | E4 `pkg/gateway/sessionkeys_api.go:384`; test `pkg/gateway/sessionkeys_api_test.go:251` | IP-PLAN-AUTH | usage denied for plain keys; allowed only with the flag |
| Data-plane keys are not agent principals (403 `agent_only`) | supported | E4 `pkg/gateway/mcpserver_backend.go:404`, `pkg/gateway/a2a.go:34` | IP-PLAN-AUTH | invoke `/api/mcp/invoke` and `/api/a2a/send` with a `yb_` key: 403, no side effects |
| Key kinds on the wire: `yb_`, `ybs_`, `yag_` | supported | E4 `pkg/auth/personalkey.go:11`, `pkg/auth/sessionkeys.go:10`, `pkg/auth/agentkey.go:12` | IP-PLAN-AUTH | resolver distinguishes all three; wrong-kind usage fails closed |
| Static-key (`strict`/`header`) and JWT service-account auth modes (S4) | supported | E4 `pkg/gateway/auth.go:100`, `:118-119`; fail-closed header-mode row `docs/compatibility.md:23` | IP-PLAN-AUTH | consumer matrix tests; pure header-mode without resolver/static key refuses every token |
| Harness helper session-key fallback to the parent key on mint failure | supported (documented least-privilege residual) | E4 `pkg/trcli/session_harness.go:48-78`, `:85-88`; documented `docs/harness.md:39-41` | IP-PLAN-AUTH | break the mint path; helper prints the parent key with a warning — residual, owner decision pending |
| Gemini native ingress (`generateContent`/`streamGenerateContent`) | unsupported | no gateway route exists (checked at this base); harness refusal reason `pkg/harness/adapters/registry.go:54` | IP-CODING | probe returns the gateway 404 surface, never a translation |
| Harness-managed config edits: plan/apply/rollback with conflict detection | supported | E4 `pkg/harness/engine.go:108`, `:120`, `:145-158`, `:236`; tests `pkg/harness/engine_test.go:13`, `:54`, `:71`, `:105` | — (harness scope) | engine tests; concurrent edit between plan and apply aborts, never clobbers |

## 5. Acceptance profiles

Two profiles validate this matrix's claims. They are requirements with
independent oracles — a green row above is existing evidence, not an executed
profile run.

- **IP-CODING — native official coding-client protocol fidelity.** Pinned
  actual client binaries against production artifacts with a separate
  controllable upstream and a read-only ledger oracle: multi-turn edit/test
  and tool calls, cancel/retry, token counting, native capability modes.
  Oracle: recipient wire events, tool execution and file diff reconciled by
  an independent stream parser against durable admissions/settlements; no
  duplicate paid or action execution. Validates every §4 protocol row
  (columns above).
- **IP-PLAN-AUTH — personal subscription and shared API boundaries.** Two
  users/orgs with distinct canaries, the real supported auth adapter, and a
  separately recorded own-account qualification: cross-user invocation,
  token export, remote persistence, replayed callback, refresh race,
  quota-to-paid fallback. Oracle: independent outbound host/principal
  recorder plus filesystem/key-store inspection and the billing ledger;
  synthetic auth cannot prove provider permission. Validates every
  credential/mode-boundary row (auth surfaces, session minting, bridge
  subscription boundary, renders, key kinds).

Rows marked "— (harness scope)" are local config-file mechanics outside both
profiles' client-protocol scope; their acceptance checks are the cited
product tests.

## 6. Unverified register and doc/source discrepancies

Recorded only; no fix is authorized by this matrix.

1. **Native Responses path has no real-client evidence** (4.2): the pinned
   codex binary has never traversed it; first qualification run required
   before any native-fidelity claim.
2. **Claude Code live row** stays unverified (4.5/4.6); a dated real-binary
   run is required to move it.
3. **Bridge runners are fixture-only** (4.3/4.4): no test executes the
   pinned `@openai/codex-sdk` 0.153.0 or a real Cursor CLI; readiness is
   file-existence, not entitlement.
4. **OpenCode doc row lags its evidence** (4.7): `docs/compatibility.md:33`
   still lists the live binary as `not verified` while the e2e harness and
   the recorded 1.19.5 loop note exist in source; row refresh belongs to the
   compatibility-matrix owner.
5. **Codex version pins lag the card** (4.1): card 0.167.0
   (`pkg/gateway/responses_codex_real_test.go:201`, evidence base `:191`)
   vs 0.166.0 in `docs/compatibility.md:31`, `docs/clients/sdk-versions.md:220`
   and `docs/clients/codex.md:7`.
6. **Harness helper fallback** to the parent key after a failed session mint
   (4.11) remains a documented least-privilege conflict awaiting an owner
   decision; `docs/harness.md:47-49` also records that installed-helper
   checks were not run.
7. **M1 server/VM client side** and **paid-upstream runs** stay unverified
   (`docs/clients/mode-contracts.md` §2.4, §6).

## 7. Citation verification

Every `path:line` and `path:line-line` citation above was re-resolved
mechanically against the worktree at
`6da73e63ec580812204a8e01bd07e9fc3f2e3954` immediately before commit:
176 unique `path:line`/`path:line-line` citations (208 occurrences), 176
resolved, 0 unresolved, plus a content spot-check of every
enforcement-critical line (refusing paths, gates, pins; 86 checks, 0
failed). The check script and output belong to the task handoff, not to
this repository. Citations to companion docs point at their own snapshot
bases where those docs state one (`docs/clients/ownership-map.md:3`,
`docs/clients/modes-audit.md:3`, `docs/clients/mode-contracts.md:3`).
