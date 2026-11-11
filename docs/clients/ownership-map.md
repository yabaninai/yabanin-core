# Client surface ownership map

Source-bound snapshot at commit `243ab5b34d04ba0e83fb10df7b206f88e42629d7`. This
document maps every user-facing command and credential path across the harness,
client-config rendering, the LiteLLM migration commands, CI attribution, `yb run`
label injection and the subscription bridge, and records
residual work only — it does not decide any fix. It is the ownership companion
to `docs/clients/modes-audit.md`, which classifies integration modes and
evidence.

Rules used throughout:

- Credential safety: this document contains credential **names, flows and file
  paths only**. No credential value was read, copied or recorded while building
  it. Synthetic `sk-…` strings under `pkg/clientconfig/testdata/` are fixture
  inputs for the LiteLLM secret-refusal tests, not real credentials.
- Citation promise: every `path:line` citation below resolves at the commit
  named above (checked mechanically against that tree).
- Oracles: each table answers the process oracle (who spawns/reads what), the
  recipient oracle (env var names, file paths, HTTP header names) and the
  durable-state oracle (what persists where, with file modes).

## 1. Command inventory

The tables in §1.1–§1.4 enumerate all 18 credential/client leaf commands: §1.1
four profile/key commands, §1.2 six `yb harness` leaves (`yb harness connect
--session` is a flag variant of `yb harness connect`), §1.3 `yb client-config`
plus the three `yb migrate-litellm` leaves, §1.4 four `yb ci` leaves; the bare
`yb migrate-litellm` group only dispatches to its leaves. `yb run` injects
attribution labels only (producer rows in §2.1); the credential-free
`yb delegate` surface is §1.5 and the subscription bridge is §1.6.

### 1.1 Profiles and stored keys — owner `pkg/trcli`

| Command | Entry point | Effect | Credential flow (names only) | Durable state |
| --- | --- | --- | --- | --- |
| `yb login` | `pkg/trcli/login.go:21` | Store a gateway key under a profile (default `default`) | Key read from stdin (`--key-stdin`) or a terminal password prompt — never argv (`pkg/trcli/login.go:149`); validated with `GET /v1/models`, `/healthz` fallback (`pkg/trcli/login.go:171`); stored via credential store `Put` (`pkg/trcli/login.go:57`) | Profile `{gateway_url, key_ref, labels}` in `~/.yabanin/config.json` (`pkg/trcli/login.go:64`, `pkg/trcli/login.go:234`) |
| `yb logout` | `pkg/trcli/login.go:73` | Delete a stored key and profile | Credential store `Delete` (`pkg/trcli/login.go:90`) | Removes the whole `~/.yabanin/sessions` cache (`pkg/trcli/login.go:93`) |
| `yb key print` | `pkg/trcli/login.go:101` | Print the stored key without a trailing newline | Env `YABANIN_API_KEY` wins over the store (`pkg/trcli/login.go:112`); otherwise store `Get` (`pkg/trcli/login.go:129`); written to stdout (`pkg/trcli/login.go:133`) | none |
| `yb keys list` | `pkg/trcli/keys.go:11` | List organization API keys via the admin API | `--api-key` flag (argv) sent as the `X-Admin-Key` service key; `YABANIN_ADMIN_URL` is the fallback base URL (`pkg/trcli/adminclient.go:160`) | none |

### 1.2 Harness — owners `pkg/harness`, `pkg/harness/adapters`, `pkg/trcli`

| Command | Entry point | Effect | Credential flow | Durable state |
| --- | --- | --- | --- | --- |
| `yb harness list` | `pkg/trcli/harness.go:34` | Tool, support, installed, config path, connected/drift | Reads config files only; per-tool detection via adapter `Detect` with a managed-block marker (`pkg/harness/adapters/codex.go:26`) and a literal `codex --version` probe (`pkg/trcli/harness.go:611`) | none (reads tool configs) |
| `yb harness connect [<tool>]` | `pkg/trcli/harness.go:85` | Plan, diff, confirm, apply tool edits inside managed blocks (`docs/harness.md:19`) | `--gateway-url`; gateway probed with the `default` profile key (`pkg/trcli/harness.go:468`); models fetched via `GET /v1/models` (`pkg/trcli/harness.go:436`) | Transactions under `~/.yabanin/harness` with per-file backups, modes and pre/post SHA256 (`pkg/harness/state.go:25`, `docs/harness.md:29`) |
| `yb harness connect --session [--session-ttl 8h]` | flags `pkg/trcli/harness.go:103` | Remember session mode for the tool | Persists `{session: true, ttl}` per tool (`pkg/trcli/session_harness.go:13`) | `harness.<tool>` map in `~/.yabanin/config.json` (`pkg/trcli/session_harness.go:22`) |
| `yb harness disconnect` | `pkg/trcli/harness.go:179` | Roll back the last applied transaction | none | Restores backups recorded in the transaction |
| `yb harness status` | `pkg/trcli/harness.go:227` | Show transactions and drift | none | reads `~/.yabanin/harness` |
| `yb harness doctor [<tool>]` | `pkg/trcli/harness.go:257` | Check config and gateway without printing the key | Warns when the stored `default` key is missing (`pkg/trcli/harness.go:278`); warns when `ANTHROPIC_API_KEY` could override the helper (`pkg/trcli/harness.go:283`); probes `/v1/responses` and `/v1/messages` with the key (`pkg/trcli/harness.go:494`); validates config parses (`pkg/trcli/harness.go:306`) | none |
| `yb harness key --tool <tool>` | `pkg/trcli/harness.go:317` | Print the key used by tool helpers | Resolves via `harnessKey`: session key when enabled, else the `default` parent key (`pkg/trcli/session_harness.go:27`) | Reads/writes the session cache (§3) |

Supported adapters: codex, claude-code, opencode, continue, aider, shell
(`pkg/harness/adapters/registry.go:46`). Unsupported with recorded reasons:
cursor, cline, roo-code, kilo-code, zed, jetbrains, copilot, gemini-cli
(`pkg/harness/adapters/registry.go:47`).

### 1.3 Client config rendering — owners `pkg/clientconfig`, `pkg/trcli`

| Command | Entry point | Effect | Credential flow | Durable state |
| --- | --- | --- | --- | --- |
| `yb client-config --client <c>` | `pkg/trcli/client_config.go:16` | Print a client configuration pointing at the gateway (never applies it) | `--key-env` (default `YABANIN_API_KEY`, `pkg/trcli/client_config.go:31`), `--key-mode env\|helper` (`pkg/trcli/client_config.go:32`); the rendered output never contains key material (`pkg/clientconfig/clientconfig.go:5`) | none (stdout only) |
| `yb migrate-litellm dry-run` | `pkg/trcli/litellm_migrate.go:65` (group `:23`) | Analyze an operator LiteLLM proxy config into the reviewed migration report — no writes | Reads operator LiteLLM YAML (`--config`, `pkg/trcli/litellm_migrate.go:71`) that may contain credential values; refused-secret fields are never copied into the report (refusal note below) | optional `--out` report file, mode `0600` (`pkg/trcli/litellm_migrate.go:92`); stdout otherwise |
| `yb migrate-litellm apply` | `pkg/trcli/litellm_migrate.go:117` | Apply a reviewed migration report to the target catalog; without `--yes` prints a write-free preview, and the gated apply refuses before any write | Consumes only the reviewed dry-run report — never raw LiteLLM configuration (`pkg/trcli/litellm_migrate.go:5`, `--report` required `:196`); refusals list every problem | Writes the target catalog (`--catalog`) and apply ledger `<catalog>.litellm-apply-ledger.json` (default `pkg/clientconfig/litellm_apply.go:73`) with `.litellm-backup` siblings (`:85`); atomic `0600` writes (`:612`) |
| `yb migrate-litellm rollback` | `pkg/trcli/litellm_migrate.go:203` | Roll back the last apply, restoring byte-identical pre-state | none — reads the catalog/ledger backup set only | Restores both touched files from the backups; backups are removed only after both are restored and verified (`pkg/clientconfig/litellm_apply.go:912`, catalog write `:948`, ledger write `:967`) |

Renders (`pkg/trcli/client_config.go:73`): codex TOML, claude-code settings
JSON or env snippet, opencode provider JSON, continue YAML, cline
instructions, aider YAML plus env line. Key recipient per client:

| Client | Rendered key recipient | Citation |
| --- | --- | --- |
| codex | helper `auth.command = ["yb","harness","key","--tool","codex"]` with `refresh_interval_ms = 300000`, or `env_key` | `pkg/clientconfig/codex.go:44` |
| claude-code | `apiKeyHelper = "yb harness key --tool claude-code"`, or `ANTHROPIC_AUTH_TOKEN="$YABANIN_API_KEY"` env export | `pkg/clientconfig/claudecode.go:20`, `pkg/clientconfig/claudecode.go:56` |
| opencode | provider `apiKey` is always `{env:YABANIN_API_KEY}` — never a secret | `pkg/clientconfig/opencode.go:23` |
| continue | model `apiKey: ${YABANIN_API_KEY}`; a helper cannot be used (recorded note) | `pkg/clientconfig/continue.go:30`, `pkg/clientconfig/continue.go:44` |
| cline | instructions only (VS Code extension state is not edited): `yb key print` output or the env var | `pkg/clientconfig/cline.go:15` |
| aider | `export AIDER_OPENAI_API_KEY="$(yb harness key --tool aider)"` (helper) or `="$YABANIN_API_KEY"` (env) | `pkg/clientconfig/aider.go:31` |

The LiteLLM migration report refuses credential-bearing fields outright:
`api_key` and `master_key` are refused secrets and report values are scrubbed
(`pkg/clientconfig/litellm_migrate.go:229`, `pkg/clientconfig/litellm_migrate.go:356`,
`pkg/clientconfig/litellm_migrate.go:442`).

### 1.4 CI attribution — owner `pkg/trcli`

| Command | Entry point | Effect | Credential flow |
| --- | --- | --- | --- |
| `yb ci env` | `pkg/trcli/ci.go:27` | Print attribution variables (shell, github, gitlab-dotenv, json) | `--session` mints a session key and prints it (`pkg/trcli/ci.go:45`); `gitlab-dotenv` refuses secrets unless `--allow-secret-dotenv` (`pkg/trcli/ci.go:54`); key comes from `--key-env` (default `YABANIN_CI_KEY`, `pkg/trcli/ci.go:22`, resolved at `pkg/trcli/ci.go:225`) |
| `yb ci exec -- <cmd>` | `pkg/trcli/ci_exec.go:18` | Run a child command with attribution env | `--session auto\|on\|off`, default `auto` (`pkg/trcli/ci_exec.go:29`); parent key kept on mint failure in `auto` (`pkg/trcli/ci_exec.go:51`), strict `on` exits 5 (`pkg/trcli/ci_exec.go:48`); child env at `pkg/trcli/ci_exec.go:123`; finishes the session afterwards (`pkg/trcli/ci_exec.go:74`) |
| `yb ci finish` | `pkg/trcli/ci.go:124` | Finish a session key and write the CI report | `--session-id` + status; `finishSessionKey` (`pkg/trcli/ci.go:147`) |
| `yb ci report` | `pkg/trcli/ci.go:75` | Pipeline usage report | Usage denied for keys without `can_read_usage` (`pkg/trcli/ci.go:91`) |

`yb ci exec` tool overlays: a temporary `CODEX_HOME` with an env-mode config
(`pkg/trcli/ci_exec.go:149`), an `OPENCODE_CONFIG_CONTENT` merge
(`pkg/trcli/ci_exec.go:166`), and `--isolate` pointing `CLAUDE_CONFIG_DIR` at an
empty temp directory (`pkg/trcli/ci_exec.go:174`).

All CI commands require `YABANIN_GATEWAY_URL` (`pkg/trcli/ci.go:198`).

### 1.5 Delegation operator surface — owner `pkg/trcli` (no credentials)

`yb delegate run|status|resume|cancel|review [approve|reject]` drives episodes
through the in-process FakeExecutor only (`pkg/trcli/delegate.go:41`,
`pkg/trcli/delegate.go:60`); state is one JSON file per episode under
`<workspace>/.yabanin/delegate` (`pkg/trcli/delegate.go:49`) with optional
isolated git worktrees under `.yabanin/worktrees` (`pkg/trcli/delegate.go:88`).
`yb delegate jit …` operates the Postgres-backed elevation queue
(`pkg/trcli/delegate.go:328`). None of these commands reads or stores gateway
credentials; `--pg-uri` is passed per invocation as a flag.

### 1.6 Subscription bridge — owner `services/subscription-bridge`

Node service (`"private": true`, engines `node >=22.13.0`,
`services/subscription-bridge/package.json:4`, `:8`). HTTP surface
(`services/subscription-bridge/src/server.ts:57`): `GET /healthz` (`:65`),
`GET /readyz` (`:69`), `GET /v1/status` (`:75`), `POST /v1/cancel` (`:85`),
`POST /v1/delegate` (`:93`). The bridge never receives Yabanin gateway
credentials (§6 NC2); provider identity stays with the local provider CLIs.

## 2. Credential paths (names and flows only)

### 2.1 Client-side environment variables

| Env var | Producer | Consumer | Citation |
| --- | --- | --- | --- |
| `YABANIN_API_KEY` | `yb ci env`/`yb ci exec` child env (`pkg/trcli/ci.go:276`, `pkg/trcli/ci_exec.go:129`); shell rc managed block via `yb key print` (`pkg/harness/adapters/shell.go:65`) | key lookups (`pkg/trcli/harness.go:563`), `yb key print` (`pkg/trcli/login.go:112`), rendered `{env:…}`/`${…}` references | `pkg/clientconfig/clientconfig.go:25` |
| `YABANIN_CI_KEY` (default `--key-env`) | caller of `yb ci` | `lookupCIKey` (`pkg/trcli/ci.go:225`) | `pkg/trcli/ci.go:22` |
| `YABANIN_GATEWAY_URL` | caller | overrides stored profile URL (`pkg/trcli/login.go:266`); required for CI (`pkg/trcli/ci.go:198`); session gateway fallback (`pkg/trcli/session_harness.go:54`) | — |
| `YABANIN_LABELS` | `yb ci env`/`yb ci exec` (`pkg/trcli/ci.go:266`); `yb run <tool> -- <cmd>` injects the encoded labels (codex and default branches, `pkg/trcli/run.go:83`, `:96`) | codex `env_http_headers X-Yabanin-Labels` (`pkg/clientconfig/codex.go:40`) | — |
| `YABANIN_SESSION_KEY_ID` | `yb ci env`/`yb ci exec` (`pkg/trcli/ci.go:279`, `pkg/trcli/ci_exec.go:134`) | pipeline tooling (informational) | — |
| `ANTHROPIC_BASE_URL` | `yb ci env`/`yb ci exec` (`pkg/trcli/ci.go:267`) | Claude Code | `pkg/harness/adapters/claudecode.go:63` |
| `ANTHROPIC_AUTH_TOKEN` | `yb ci env`/`yb ci exec` (`pkg/trcli/ci.go:275`, `pkg/trcli/ci_exec.go:131`); rendered snippet (`pkg/clientconfig/claudecode.go:56`) | Claude Code | `pkg/harness/adapters/claudecode.go:53` |
| `ANTHROPIC_CUSTOM_HEADERS` | `yb ci` builds it with the labels header (`pkg/trcli/ci.go:268`); `yb run claude-code -- <cmd>` appends the `X-Yabanin-Labels` line (`pkg/trcli/run.go:88`); harness merges (`pkg/harness/adapters/claudecode.go:66`) | Claude Code | — |
| `CLAUDE_CODE_GATEWAY_HINT_HEADERS` | rendered claude settings/snippet | Claude Code | `pkg/clientconfig/claudecode.go:34` |
| `OPENAI_API_KEY` | `yb ci env`/`yb ci exec` (`pkg/trcli/ci.go:274`, `pkg/trcli/ci_exec.go:130`) | OpenAI-compatible tools | — |
| `OPENAI_BASE_URL` | `--openai-env` (`pkg/trcli/ci.go:271`, `pkg/trcli/ci_exec.go:137`) | OpenAI-compatible tools | — |
| `AIDER_OPENAI_API_KEY` | rendered env line / harness fish block | Aider | `pkg/clientconfig/aider.go:31`, `pkg/harness/adapters/aider.go:39` |
| `CLAUDE_CONFIG_DIR` | `yb ci exec --isolate` | Claude Code (temp, empty) | `pkg/trcli/ci_exec.go:182` |
| `CODEX_HOME` | `yb ci exec` overlay | Codex CLI; also honored by the harness adapter when resolving `config.toml` | `pkg/trcli/ci_exec.go:164`, `pkg/harness/adapters/codex.go:75` |
| `OPENCODE_CONFIG_CONTENT` | `yb ci exec` overlay merge; `yb run opencode -- <cmd>` merges the labels into the config content (`pkg/trcli/run.go:90`, `:94`) | OpenCode | `pkg/trcli/ci_exec.go:172` |

`yb run <tool> -- <cmd>` (`pkg/trcli/run.go:32`) is labels-only: its env
injection (`pkg/trcli/run.go:80`) carries attribution labels — or a label
header/config merge — and never key material.

### 2.2 Subscription-bridge environment variables

| Env var | Role | Citation |
| --- | --- | --- |
| `YABANIN_BRIDGE_HOST` | bind host, default `127.0.0.1` | `services/subscription-bridge/src/index.ts:4` |
| `YABANIN_BRIDGE_PORT` | bind port, default `8091` | `services/subscription-bridge/src/index.ts:5` |
| `YABANIN_DELEGATION_WORKSPACE` | launch root for workspace confinement, else cwd | `services/subscription-bridge/src/index.ts:6` |
| `YABANIN_BRIDGE_FAKE` | force fake runners | `services/subscription-bridge/src/runners.ts:20` |
| `YABANIN_CURSOR_AGENT` | cursor agent binary override | `services/subscription-bridge/src/runners.ts:150` |
| `CURSOR_MODEL` | model passed to the cursor CLI | `services/subscription-bridge/src/runners.ts:165` |
| `CODEX_API_KEY` | presence check only (readiness heuristic) | `services/subscription-bridge/src/runners.ts:77` |
| `CURSOR_API_KEY` | deleted from the cursor child env so the CLI uses its subscription login | `services/subscription-bridge/src/runners.ts:134` |

### 2.3 Helper command invocations (process oracle)

| Helper | Spawned by | Citation |
| --- | --- | --- |
| `yb harness key --tool codex` | Codex `auth.command` (refresh 5 min) | `pkg/clientconfig/codex.go:44` |
| `yb harness key --tool claude-code` | Claude Code `apiKeyHelper` | `pkg/clientconfig/claudecode.go:20` |
| `yb harness key --tool aider` | shell rc env line (helper mode) | `pkg/harness/adapters/aider.go:39` |
| `yb key print` | shell rc managed block (parent key) | `pkg/harness/adapters/shell.go:65` |
| `codex --version` | harness detection | `pkg/trcli/harness.go:611` |
| `agent status` / `agent -p …` (cursor CLI) | bridge readiness/run | `services/subscription-bridge/src/runners.ts:206`, `:231` |
| `security -i`, `secret-tool` | credential store backends; secrets travel on stdin, never argv | `pkg/trcli/credstore/store.go:34`, `:44` |

### 2.4 HTTP headers (client → gateway)

| Header | Role | Citation |
| --- | --- | --- |
| `Authorization: Bearer` | key transport (mint `pkg/trcli/session.go:71`, finish `:111`, probes `pkg/trcli/harness.go:526`, login check `pkg/trcli/login.go:206`) | gateway parse `pkg/gateway/auth.go:81` |
| `x-api-key` | Claude Code transport; normalized into `Authorization` and deleted upstream | `pkg/gateway/auth.go:71` |
| `X-Yabanin-Labels` (and `X-Yabanin-Label-*` per-key) | request labels; stripped after resolution | `pkg/gateway/labels_mw.go:36`, strip `:74` |
| `X-Yabanin-Labels-Dropped` / `X-Yabanin-Labels-Missing` | response diagnostics | `pkg/gateway/labels_mw.go:48`, `:51` |
| `X-Session-Id` | default-generated on Messages; from `PromptCacheKey` on Responses | `pkg/gateway/messages_endpoint.go:19`, `pkg/gateway/responses_endpoint.go:46` |
| `X-Org-Id` | label-policy selection | `pkg/gateway/labels_mw.go:39` |
| `X-Yabanin-Task`, `X-Yabanin-Repo` | task/repo label bridging | `pkg/gateway/labels_mw.go:87` |
| `X-Admin-Key` | admin API service key (`yb keys list`) | `pkg/trcli/adminclient.go:167` |

### 2.5 Key material identifiers

| Prefix | Kind | Citation |
| --- | --- | --- |
| `yag_` | agent key | `pkg/auth/agentkey.go:12` |
| `ybs_` | session key | `pkg/auth/sessionkeys.go:10` |
| `yb_` | personal (developer-portal) key | `pkg/auth/personalkey.go:11` |

## 3. Durable state

| Path / store | Owner | Mode | Content | Residual/notes |
| --- | --- | --- | --- | --- |
| `~/.yabanin/config.json` | `pkg/trcli` | dir `0700`, file `0600` (`pkg/trcli/login.go:284`) | profiles `{gateway_url, key_ref, labels}` (`pkg/trcli/login.go:217`), harness `{session, ttl}` (`pkg/trcli/login.go:223`) | no credential value, only store refs |
| credential store | `pkg/trcli/credstore` | — | `secret-tool` when installed (`pkg/trcli/credstore/open_linux.go`), macOS keychain via `security -i`, else file fallback | fallback below |
| `~/.yabanin/credentials.json` | `pkg/trcli/credstore` | `0600` (`pkg/trcli/credstore/file.go:38`) | plaintext key map — fallback when `secret-tool` is absent (warning `pkg/trcli/credstore/file.go:10`) | R5 |
| `~/.yabanin/sessions/<sha256>.json` | `pkg/trcli` | dir `0700` (`pkg/trcli/session.go:210`), file `0600` (`:236`) | cached session key `{id, key, expires_at, labels}`; cache key = `tool\|gateway\|labels` (`pkg/trcli/session.go:207`); valid until 10 min before expiry (`:225`); sweep ≤100 files (`:247`); deleted by `yb logout` (`pkg/trcli/login.go:93`) | contains the session key value |
| `~/.yabanin/harness` | `pkg/harness` | `0600` (`docs/harness.md:29`) | applied transactions, backups, pre/post SHA256 (`pkg/harness/state.go:25`) | — |
| `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`) | adapters | — | managed block; helper auth or `env_key` | `pkg/harness/adapters/codex.go:78` |
| `~/.claude/settings.json` | adapters | — | `apiKeyHelper`, `env` block; conflicting helper requires `--force` | `pkg/harness/adapters/claudecode.go:45` |
| `~/.config/opencode/opencode.json` | adapters | — | managed provider; `.jsonc` refuses auto-edit | `pkg/harness/adapters/opencode.go:22`, `:32` |
| `~/.continue/config.yaml` | adapters | — | models list (`--experimental`) | `pkg/harness/adapters/continue.go:20` |
| `~/.aider.conf.yml` + shell rc line | adapters | — | base URL/model + env key line | `pkg/harness/adapters/aider.go:21`, `:39` |
| `~/.bashrc` / `~/.zshrc` / `~/.config/fish/config.fish` | adapters | — | `export YABANIN_API_KEY="$(yb key print …)"` | `pkg/harness/adapters/shell.go:44`, `:65` |
| `yabanin-ci.json`, `yabanin-pipeline.json` | `pkg/trcli` | `0600` (`pkg/trcli/ci.go:369`) | attribution/usage reports, session id, no key value | — |
| `<workspace>/.yabanin/delegate`, `.yabanin/worktrees` | `pkg/trcli` | — | episode state, evidence envelopes, isolated worktrees | `pkg/trcli/delegate.go:49`, `:88` |
| (none) | subscription-bridge | — | runs are in-memory only (`services/subscription-bridge/src/server.ts:49`); no credential persistence | — |

## 4. Gateway client-facing surfaces — owner `pkg/gateway`

| Surface | Location | Policy |
| --- | --- | --- |
| `/v1/yabanin` route group (auth-only) | `pkg/gateway/gateway.go:1979` | session keys: mint (`:1981`), revoke (`:1982`), finish (`:1983`), usage (`:1984`), own usage (`:1985`), label policy (`:1986`) |
| session-key mint policy | `pkg/gateway/sessionkeys_api.go:78` | parent must be a plain API key (no agent, no session), `CanMintSessions`, else `403 session_mint_not_allowed`; TTL 60–43200 s (`:26`, `:102`); session cannot outlive parent (`:139`); mint rate limit `yb:skey:mint:{parent}:{minute}`, 60/min (`:28`, `:195`); log records id/parent/ttl, never the key (`:164`) |
| auth normalization | `pkg/gateway/auth.go:71` | `x-api-key` copied to `Authorization` when absent, then deleted; `Authorization` header read at `:81`, `TrimPrefix("Bearer ")` at `:88` (lowercase fallback `:90`) |
| label middleware | `pkg/gateway/labels_mw.go:34` | merges request + principal labels, rejects secret-shaped values, strips label headers after resolution, emits dropped/missing diagnostics |

## 5. CI and quality ownership

- Pull-request CI: `go vet` (`.github/workflows/ci.yml:44`), `gofmt` check
  (`:51`), `go test -race -count=1 -short ./...` (`:54`), integration-tagged
  suites with strict env parsing `YABANIN_CONFIG_STRICT=1` (`:335`, `:403`).
- The `quality-changed` job runs
  `make quality-changed QUALITY_BASE=origin/main QUALITY_EXECUTE=1 QUALITY_JOBS=2`
  (`.github/workflows/ci.yml:313`, job at `:262`).
- Bridge tests: `make test-subscription-bridge` — `node --test` over
  contract/listen/runners suites (`Makefile:78`); wired into quality via the
  `bridge` profile (`scripts/quality/quality.py:189`, `Makefile:312`); fake
  runners are the default for local runs (`Makefile:362`).
- Dependency updates for the bridge: `.github/dependabot.yml:140`.

No CI workflow exercises `yb harness`, `yb client-config`, session-key minting
or the subscription bridge against a live gateway (§6 NC1).

## 6. Negative controls — verified claims of absence

Each claim was verified with an exhaustive search over the named scope at the
snapshot commit; the exact search is given so it can be re-run.

- **NC1 — no CI workflow exercises the mapped client surfaces.**
  Search: `grep -rnE "harness|client-config|clientconfig|session-keys|subscription-bridge|YABANIN_|yb exec|yb key" .github/workflows/`
  Result: one match, `YABANIN_CONFIG_STRICT` (`.github/workflows/ci.yml:335`),
  which is strict env parsing for gateway integration tests — unrelated to
  harness/client-config/session-keys/bridge. No workflow runs those surfaces.
- **NC2 — the subscription bridge never handles Yabanin gateway credentials.**
  Search: `grep -rnE "YABANIN_API_KEY|YABANIN_CI_KEY|Authorization|Bearer|ybs_|yag_" services/subscription-bridge/src/`
  Result: no matches. Provider-key handling is limited to a `CODEX_API_KEY`
  presence check (`services/subscription-bridge/src/runners.ts:77`) and the
  deletion of `CURSOR_API_KEY` from the cursor child env (`:134`, asserted by
  `services/subscription-bridge/src/runners.test.ts:29`).
- **NC3 — no client renderer writes key material into config output.**
  Search: `grep -rnE "apiKey|api_key|master_key" pkg/clientconfig/` (excluding
  `_test.go`)
  Result: every match is an env reference (`{env:YABANIN_API_KEY}`,
  `${YABANIN_API_KEY}`), an `apiKeyHelper` command string, or the LiteLLM
  refusal catalog; matches under `testdata/` are synthetic fixture inputs for
  the refusal tests. No renderer interpolates a key value; stated invariant at
  `pkg/clientconfig/clientconfig.go:5`.
- **NC4 — the shell adapter never mints session keys.**
  Search: `grep -rnE "session|mint|harness key" pkg/harness/adapters/shell.go`
  Result: no matches. The shell key source is `yb key print` — the parent key
  (`pkg/harness/adapters/shell.go:65`, fish variant `:68`).

## 7. Residual work

Recorded only; every fix decision stays with the owner follow-up. Ordered by
credential-least-privilege impact.

1. **Harness helper session-key parent fallback (least-privilege conflict).**
   `harnessKey` silently returns the long-lived parent key when session labels,
   cache, TTL parsing or minting fail (`pkg/trcli/session_harness.go:48`, `:52`,
   `:60`, `:71`, `:77`; `parentKeyFallback` `:85`). This is documented behavior
   (`docs/harness.md:38`), but it means a tool configured for session keys can
   run with parent-key privileges after any gateway hiccup, and the helper path
   has no strict mode — unlike `yb ci exec --session on`. Decision deferred.
2. **`yb ci exec --session` defaults to the permissive mode.** Default `auto`
   falls back to the parent key with a stderr note (`pkg/trcli/ci_exec.go:51`,
   messages `:217`); strict `on` exists but exits 5 (`:48`). The default is the
   fallback path.
3. **Readiness-by-file-existence / text heuristics.** Bridge codex readiness is
   `CODEX_API_KEY` presence or `~/.codex/auth.json` existing
   (`services/subscription-bridge/src/runners.ts:76`, surfaced at
   `services/subscription-bridge/src/server.ts:69`); cursor readiness parses
   `agent status` text (`services/subscription-bridge/src/runners.ts:143`);
   harness "connected" is a managed-block marker in the tool config
   (`pkg/harness/adapters/codex.go:26`). None is an authenticated round-trip;
   only `yb harness doctor` probes the gateway (`pkg/trcli/harness.go:289`).
4. **Bridge HTTP surface has no per-request authentication.** Loopback bind and
   Host-header checks only (`services/subscription-bridge/src/server.ts:45`,
   `:59`); any local process can call `/v1/delegate` (workspace-confined
   `:121`, concurrency-limited `:125`).
5. **Plaintext credential fallback file.** `~/.yabanin/credentials.json`
   (`0600`) whenever `secret-tool` is absent — surfaced as a warning string
   only (`pkg/trcli/credstore/file.go:10`, `:38`).
6. **Harness-minted session keys are never finished.** The helper path mints
   and caches but never calls finish; unused keys live until TTL
   (`docs/harness.md:40`). Only `yb ci exec`/`yb ci finish` finish sessions
   (`pkg/trcli/ci_exec.go:74`, `pkg/trcli/ci.go:147`).
7. **Shell rc materializes the parent key into every interactive shell** via
   `yb key print` (`pkg/harness/adapters/shell.go:65`) — long-lived parent-key
   exposure in the environment; shell sessions are never session keys (NC4).
8. **No CI workflow covers the mapped client surfaces.** Harness, client-config,
   session minting and the bridge have no workflow-level evidence; bridge
   coverage is node:test contract tests with fake runners only (§5, NC1).
9. **`CODEX_HOME` interaction.** `yb ci exec` points `CODEX_HOME` at a temp
   config (`pkg/trcli/ci_exec.go:164`) and the harness adapter honors
   `CODEX_HOME` (`pkg/harness/adapters/codex.go:75`), so harness commands run
   inside a `ci exec` child target the temporary config, not `~/.codex`.
10. **Helper stdout and env-override precedence.** `yb harness key` and
    `yb key print` write key material to stdout by design
    (`pkg/trcli/harness.go:330`, `pkg/trcli/login.go:133`), and `YABANIN_API_KEY`
    in the environment overrides the store on every lookup
    (`pkg/trcli/harness.go:563`, `pkg/trcli/login.go:112`) — helper invocation
    inherits the caller's environment on shared hosts.
11. **Admin service key travels as an argv flag.** `yb keys list` requires
    `--api-key` (`pkg/trcli/adminclient.go:167`); argv values are visible in
    local process listings, unlike every other command's stdin/env path.
