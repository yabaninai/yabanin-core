# Deployment and credential-mode contracts

Source-bound snapshot at commit `34eb9783af26e7780d4ffa8a7c3e2deaf7593428`
(branch `task/cpc00-03`, worktree `core-cpc00-c`), written 2026-11-11. This
document freezes the contracts of the three primary deployment/credential
modes by which a coding client reaches inference — personal direct-client,
local app-bound ChatGPT, and organization API — and enumerates the
additional modes found in source. For each frozen mode it records: credential
kinds and ownership, env/header injection points, rights scope as actually
enforced on the wire, server/VM qualification state, and durable state.

This is the contract companion of `docs/clients/ownership-map.md` (command
and credential-path inventory), `docs/clients/modes-audit.md` (evidence
classification) and `docs/ui-grant-scope-matrix.md` (admin-plane grants); it
does not repeat their tables, it binds modes to their rows. Recording a gap
here grants nothing: every qualification gap below is a residual for an owner
decision, and none of the text authorizes a deployment, permission or
release.

Rules used throughout:

- Credential safety: credential **names, flows and file paths only**. No
  credential value was read, printed or recorded while building this
  document.
- Citation promise: every `path:line` citation below resolves at the commit
  named above (checked mechanically against that tree; see §7).
- Qualification vocabulary matches `docs/compatibility.md`: **verified**
  (cited evidence exists at this base), **unverified** (no evidence — absence
  of a test is not absence of behavior), **unsupported** (checked absence of
  a route or feature, with the check cited).

## 1. Mode inventory

| Mode | Contract in one line | Credential kind | Section |
| --- | --- | --- | --- |
| M1 personal direct-client | A developer's coding client authenticates to the gateway with a self-minted developer-portal key on the developer's own workstation | `yb_` personal key | §2 |
| M2 local app-bound ChatGPT | Coding work is delegated through the subscription bridge to a locally installed Codex/Cursor CLI running under the human's ambient app subscription login; the bridge never handles gateway credentials | none (provider login stays local) | §3 |
| M3 organization API | An operator-issued org key drives programmatic/headless clients against the gateway data plane | `yb_` org key (+ optional `ybs_` children) | §4 |
| S1–S6 additional modes | Session attribution, agent-principal, partner bridge, static-key/JWT auth, BYOK, admin plane | see §5 | §5 |

## 2. M1 — personal direct-client

A human developer points a coding client (Codex CLI, Claude Code, OpenCode,
Continue, Aider, Cline) at the gateway using a key they minted themselves in
the developer portal. The gateway is API-funded: inference spend flows
through the org's configured upstreams, not the developer's app subscription.
Codex's ChatGPT-OAuth login is explicitly not a gateway auth path
(`docs/clients/codex.md:78`).

### 2.1 Credential kinds and ownership

- `yb_` personal key = prefix + 64 hex, plaintext shown once, only its
  sha256 stored (`pkg/auth/personalkey.go:11`, `:20`; store insert
  `pkg/adminstore/developers.go:192`).
- Minted by the developer in the portal (opt-in deployment feature:
  `YABANIN_PORTAL_ENABLED`, default off — `pkg/config/config.go:736`), max 5
  active keys default, optional TTL (`services/admin/handlers/portal.go:312`,
  `:320`). Portal listing never returns hashes
  (`pkg/adminstore/developers.go:162`).
- The key row carries `org_id`, `team_id` and `user_id` from the developer
  profile (`pkg/adminstore/developers.go:186`); spend is attributed to that
  user (`pkg/gateway/admission.go:407`).
- Ownership/storage rows: credential store (secret-tool / keychain / file
  fallback) and `~/.yabanin/*` paths in `docs/clients/ownership-map.md` §3.
- Capability flags: personal keys mint with `can_mint_sessions=false` and
  `can_read_usage=false` — the insert does not set them
  (`pkg/adminstore/developers.go:192`) and the columns default false
  (`migrations/0001_init.up.sql:393`). Only an org admin holding
  `keys.manage` can flip the flags afterwards via the CAS surface
  (`services/admin/handlers/api_key_labels.go:95`; grant row
  `docs/ui-grant-scope-matrix.md:78`).

### 2.2 Injection points

- Rendered config never contains key material (invariant
  `pkg/clientconfig/clientconfig.go:5`); the key is delivered as a helper
  command or an env reference: Codex `auth.command`/`env_key`
  (`pkg/clientconfig/codex.go:41`), Claude Code `apiKeyHelper` or
  `ANTHROPIC_AUTH_TOKEN` (`pkg/clientconfig/claudecode.go:19`, `:56`), shell
  rc export (`pkg/harness/adapters/shell.go:65`).
- Wire transport: `Authorization: Bearer` (`pkg/gateway/auth.go:81`); the
  Claude Code `x-api-key` header is normalized into `Authorization` and
  deleted (`pkg/gateway/auth.go:73`). Full env/header recipient tables:
  `docs/clients/ownership-map.md` §2.1, §2.4.
- Identity propagation is server-set only: `X-User-Id` is set from the
  resolved personal key and client copies are stripped at ingress
  (`pkg/gateway/auth.go:65`, `:153`).

### 2.3 Rights scope (enforced)

- The resolver turns the key into org/team/user context
  (`pkg/auth/resolver.go:301`); inference runs the full admission chain
  (budgets, labels, policies) on the `/v1` surface
  (`pkg/gateway/gateway.go:1943`).
- Not an agent principal: MCP tool-calls and A2A sends answer 403
  `agent_only` for a `yb_` key (`pkg/gateway/mcpserver_backend.go:401`,
  `pkg/gateway/a2a.go:31`).
- Session-key minting is denied unless an admin flipped
  `can_mint_sessions`: 403 `session_mint_not_allowed`
  (`pkg/gateway/sessionkeys_api.go:77`); own-usage read likewise requires
  `can_read_usage` (`pkg/gateway/sessionkeys_api.go:384`).
- Portal surface: only the portal-session routes of
  `services/admin/handlers/router_portal.go:22`; a personal key is a data-plane
  credential and opens no admin route.

### 2.4 Server/VM qualification

- Workstation deployment: **verified** at source for the connect/mint/store
  chain (unit tests; `docs/clients/modes-audit.md` §3) and by the codex-cli
  real-binary e2e on the translated Responses path with a mock upstream
  (`pkg/gateway/responses_codex_real_test.go:63`; scope and caveats at
  `docs/clients/codex.md:80`).
- Server/VM deployment of the client side (harness, credstore, helper): 
  **unverified** — no test or doc exercises `yb login`/`yb harness`/credstore
  on a headless host, and no CI workflow covers these surfaces at all
  (`docs/clients/ownership-map.md` §6 NC1). Without `secret-tool` the store
  falls back to plaintext `~/.yabanin/credentials.json`
  (`pkg/trcli/credstore/file.go:10`); helper stdout and `YABANIN_API_KEY`
  env override are shared-host exposures (`docs/clients/ownership-map.md`
  §7.10). Gaps recorded in §6; nothing here authorizes a server rollout.

### 2.5 Durable state

Server side: `api_keys` row (hash-only), request logs, audit rows. Client
side: exactly the rows of `docs/clients/ownership-map.md` §3 (config,
credstore, session cache, harness transactions, tool configs, shell rc).

## 3. M2 — local app-bound ChatGPT (subscription bridge)

Coding work is delegated (`tr_delegate`) to a locally installed Codex CLI or
Cursor CLI that runs under the human's ambient ChatGPT/Cursor subscription
login. The bridge is a Node service the gateway-side partner process talks
to over loopback HTTP; the subscription — not a Yabanin key — is the
entitlement that gates the run.

### 3.1 Credential kinds and ownership

- No Yabanin credential exists in this mode's delegation path: the bridge
  source contains no gateway-key handling (negative control NC2,
  `docs/clients/ownership-map.md` §6). The Codex SDK is constructed with no
  credentials (ambient local login, `services/subscription-bridge/src/runners.ts:81`);
  `CURSOR_API_KEY` is deleted from the cursor child env so the CLI uses its
  subscription login (`services/subscription-bridge/src/runners.ts:134`,
  pinned by `services/subscription-bridge/src/runners.test.ts:29`), and any
  `--api-key` CLI argument is refused (`services/subscription-bridge/src/runners.ts:226`).
- Provider identity stays with the local app login (readiness is
  `CODEX_API_KEY` presence or `~/.codex/auth.json` existing — names only,
  `services/subscription-bridge/src/runners.ts:76`).
- The gateway-side process that reaches the bridge is the MCP partner
  service, which authenticates to gateway/admin planes with
  `YABANIN_PARTNER_API_KEY` (required — `services/run/mcp.go:26`) and
  `YABANIN_ADMIN_API_KEY` (`services/run/mcp.go:31`); that is mode S3 (§5),
  not part of the bridge contract itself.

### 3.2 Injection points

- Bridge env: `YABANIN_BRIDGE_HOST`/`YABANIN_BRIDGE_PORT` (defaults
  `127.0.0.1:8091`), `YABANIN_DELEGATION_WORKSPACE`
  (`services/subscription-bridge/src/index.ts:4`), fake-runner switch
  `YABANIN_BRIDGE_FAKE` (`services/subscription-bridge/src/runners.ts:20`); full
  table at `docs/clients/ownership-map.md` §2.2.
- Gateway→bridge wiring: `DelegationFromEnv()` builds the executor from the
  environment (`pkg/mcppartner/delegation.go:21`); `tr_delegate` registers
  only when delegation is enabled (`pkg/mcppartner/server.go:89`).
- The bridge HTTP surface: `GET /healthz`, `/readyz`, `/v1/status`,
  `POST /v1/cancel`, `POST /v1/delegate`
  (`docs/clients/ownership-map.md` §1.6).

### 3.3 Rights scope (enforced)

- Bridge access control is loopback-only binding — refused at construction
  for non-loopback hosts (`services/subscription-bridge/src/server.ts:46`,
  pinned by `services/subscription-bridge/src/listen.test.ts:6`) — plus a
  loopback Host-header check (`services/subscription-bridge/src/server.ts:60`).
  There is **no per-request authentication**; any local process reaching the
  port may delegate (`docs/clients/ownership-map.md` §7.4).
- Delegation effects are confined: workspace paths are realpath-confined to
  the launch root, else `workspace_escape`
  (`services/subscription-bridge/src/server.ts:121`); concurrency is capped
  at WRITE=1/ANALYZE=2 (`services/subscription-bridge/src/server.ts:7`,
  admission `:126`); body and output limits per
  `docs/clients/modes-audit.md` §5.
- The subscription's own entitlement is the gating right: provider quota and
  auth failures surface as stable `quota_exhausted` /
  `provider_not_authorized` errors
  (`services/subscription-bridge/src/contract.test.ts:66`, `:78`).

### 3.4 Server/VM qualification

- Single-user workstation: confinement **verified** at source
  (`docs/clients/modes-audit.md` §5), but all behavior evidence is
  fake-runner node:test suites — **fixture-only**; no test executes the real
  Codex SDK or a real Cursor CLI (`docs/clients/modes-audit.md` §4).
- Remote serving is **unsupported by enforcement**: the bridge refuses any
  non-loopback bind, so it cannot listen on a network interface at all
  (`services/subscription-bridge/src/server.ts:46`,
  `services/subscription-bridge/src/listen.test.ts:6`). This is a designed
  boundary, not a defect.
- Co-located server/VM deployment (bridge + partner process on one host): 
  **unverified** — no evidence exists, and with no per-request auth a
  multi-user host would let every local process spend the logged-in
  subscription (§6 residual 3). Recorded as a gap; not authorized here.

### 3.5 Durable state

None in the bridge: runs are in-memory only
(`services/subscription-bridge/src/server.ts:49`;
`docs/clients/ownership-map.md` §3 row). The provider CLIs own their login
state; the gateway side records only what `tr_route`/`tr_delegate` produce
(spend rows; episode state, which without a bridge URL is FakeExecutor-local
JSON under the workspace — `docs/clients/ownership-map.md` §1.5).

## 4. M3 — organization API

An operator issues org keys through the admin console/API and runs
programmatic clients — CI pipelines, servers, LiteLLM-migrated proxies —
against the gateway data plane. Same key kind as M1 (`yb_`); the differences
are issuance (admin, not portal), the managed capability flags, and optional
`ybs_` session children.

### 4.1 Credential kinds and ownership

- `yb_` org key created via `POST /api/api-keys` under `keys.manage`
  (`services/admin/handlers/router_keys.go:17`; store insert
  `pkg/adminstore/keys.go:17`; grant row `docs/ui-grant-scope-matrix.md:78`).
- `can_mint_sessions` / `can_read_usage` start false (column defaults,
  `migrations/0001_init.up.sql:393`) and are set only through the
  admin CAS surface (`services/admin/handlers/api_key_labels.go:95`).
- Optional `ybs_` session children (`pkg/auth/sessionkeys.go:10`): minted by
  the parent over `/v1/yabanin/session-keys` (`pkg/gateway/gateway.go:1980`),
  TTL 60–43200 s default 7200 (`pkg/gateway/sessionkeys_api.go:24`), capped
  at the parent's expiry (AUTH-03, `pkg/gateway/sessionkeys_api.go:139`),
  mint rate 60/min per parent (`pkg/gateway/sessionkeys_api.go:189`).
- Machine-client secret handling is the operator's: the LiteLLM migration
  refuses to copy `api_key`/`master_key` values into its reports
  (`pkg/trcli/litellm_migrate.go:229`); CI commands take the parent from
  `YABANIN_CI_KEY`/env (`pkg/trcli/ci.go:22`, resolution `:225`).

### 4.2 Injection points

- Wire transport identical to M1: `Authorization: Bearer`
  (`pkg/gateway/auth.go:81`), `x-api-key` normalized (`pkg/gateway/auth.go:73`).
- Client env injection for CI: `YABANIN_API_KEY`, `OPENAI_API_KEY`,
  `ANTHROPIC_AUTH_TOKEN` etc. (`docs/clients/ownership-map.md` §2.1); admin
  listing uses the separate `X-Admin-Key` service key
  (`pkg/trcli/adminclient.go:167`).

### 4.3 Rights scope (enforced)

- Resolution to org context and the full `/v1` inference surface under the
  admission chain (`pkg/gateway/auth.go:133`, `pkg/gateway/gateway.go:1943`);
  label headers are stripped after resolution
  (`pkg/gateway/labels_mw.go:74` via `docs/clients/ownership-map.md` §2.4).
- Session mint only with `CanMintSessions` (403
  `session_mint_not_allowed` otherwise,
  `pkg/gateway/sessionkeys_api.go:77`; matrix test
  `pkg/gateway/sessionkeys_api_test.go:169`); own usage only with
  `CanReadUsage` (`pkg/gateway/sessionkeys_api.go:384`; test
  `pkg/gateway/sessionkeys_api_test.go:251`).
- Not agent principals: `/api/mcp/invoke` and `/api/a2a/send` answer 403
  `agent_only` (`pkg/gateway/mcpserver_backend.go:401`,
  `pkg/gateway/a2a.go:31`).
- The data-plane key opens no admin route: `/internal` accepts only the
  separate `X-Admin-Key` service key
  (`services/admin/handlers/internal_api.go:28`), and the partner client
  keeps the two planes strictly separated (`pkg/mcppartner/client.go:97`).

### 4.4 Server/VM qualification

- Gateway server side: **verified** — documented deployment paths (localhost
  quickstart, offline Docker bundle, air-gapped Kubernetes/Helm —
  `docs/deployment-options.md:10`), quickstart smoke driving the seeded key
  through `/v1/models` and chat (`docs/quickstart.md:181`, `:200`), and
  test-pinned auth/session behavior (resolver cache/revocation
  `pkg/auth/resolver_test.go:178`, `pkg/auth/resolver_revocation_test.go`;
  session budget/expiry `pkg/gateway/sessionkeys_api_test.go:268`, `:332`).
- Client-side org-key workflows (CI mint/finish, LiteLLM apply):
  unit/integration tested only; no CI workflow covers them (NC1,
  `docs/clients/ownership-map.md` §6). LiteLLM apply is reviewed-report
  gated with backups (`docs/clients/ownership-map.md` §1.3).
- The operator-managed public stand is a deployment fact of its operator,
  not a qualification of this repository (`docs/ops/public-stand.md:6`).

### 4.5 Durable state

Server side: `api_keys`, `session_keys`, request logs, audit rows. Operator
side: the migrated catalog plus apply ledger and `.litellm-backup` siblings,
`0600` (`docs/clients/ownership-map.md` §1.3); CI reports `yabanin-ci.json`
/ `yabanin-pipeline.json`, `0600`, no key value
(`docs/clients/ownership-map.md` §3).

## 5. Additional modes found in source (enumerated, not frozen here)

| # | Mode | Contract pointer | Gate/notes |
| --- | --- | --- | --- |
| S1 | Session-key attribution (`ybs_` from a `yb_` parent) — harness helper and `yb ci exec` | `docs/harness.md:33`; `pkg/trcli/session_harness.go:27`; `pkg/trcli/ci_exec.go:29` | mint gate `pkg/gateway/sessionkeys_api.go:77`; documented parent-key fallback on mint failure is a least-privilege residual (`docs/clients/ownership-map.md` §7.1) |
| S2 | Agent-principal (`yag_`) for MCP tool-calls and A2A | `pkg/auth/agentkey.go:12`; issuance `services/admin/handlers/agentkeys.go:63` under `agent_keys.manage` (`services/admin/handlers/router_keys.go:25`) | agent-only gates `pkg/gateway/mcpserver_backend.go:401`, `pkg/gateway/a2a.go:31` |
| S3 | MCP partner bridge (`tr_route`/`tr_spend_report`/`tr_set_policy`/`tr_lineage_verify`/`tr_delegate`) | `services/run/mcp.go:14`; tools `pkg/mcppartner/server.go:21` | partner key required (`services/run/mcp.go:26`); gateway hops Bearer, admin hops `X-Admin-Key` (`pkg/mcppartner/client.go:92`, `:100`) |
| S4 | Static-key auth modes (`strict`/`header` static + fallback keys) and the JWT service-account path | `pkg/gateway/auth.go:106`; JWT `pkg/gateway/auth.go:100`, `pkg/gateway/auth_jwt.go:33` | resolver-only auth allowed in `header` mode; JWT is RS256/ES256 + JWKS, fail-closed |
| S5 | BYOK org provider credentials (org owns upstream keys) | `services/admin/handlers/org_credentials.go:266` under `keys.manage`; flow `docs/byok.md:27` | client keeps its `yb_` gateway key; upstream auth is org-side (`docs/clients/claude-code.md:51`) |
| S6 | Admin plane (dashboard sessions, `X-Admin-Key`, SCIM bearer, portal sessions) | vocabulary and route matrix `docs/ui-grant-scope-matrix.md:36` | out of client-mode scope by construction |

## 6. Residual register (gaps — recorded, not granted)

1. **M1 server/VM unverified.** No harness/credstore evidence on headless
   hosts; without `secret-tool` the only store is the plaintext fallback
   (`pkg/trcli/credstore/file.go:10`); helper stdout and env override are
   shared-host exposures (`docs/clients/ownership-map.md` §7.10). A server
   qualification run is an owner decision away.
2. **M1/M3 capability-flag flipping is admin-plane only.** Whether the
   portal should ever mint `can_mint_sessions` keys is undecided; today it
   never does (`pkg/adminstore/developers.go:192`).
3. **M2 bridge has no per-request authentication** beyond loopback bind and
   Host check (`services/subscription-bridge/src/server.ts:46`, `:60`;
   `docs/clients/modes-audit.md` §6.5) — multi-user server/VM deployment is
   unsafe under the current design and is not authorized by this document.
4. **M2 evidence is fixture-only** (fake runners,
   `docs/clients/modes-audit.md` §4) and the runner supervision has recorded
   gaps (unbounded child output buffering, no SIGKILL escalation — §6.5
   there); readiness is file-existence, not entitlement (§7.3 of the
   ownership map).
5. **M1 codex native Responses path has no real-binary evidence**
   (`docs/clients/modes-audit.md` §6.1); the M1 verdict in §2.4 covers the
   translated path only.
6. **No CI workflow covers any client mode** (NC1,
   `docs/clients/ownership-map.md` §6); `yb keys list` carries its service
   key in argv (§7.11).
7. **Comment accuracy:** `pkg/gateway/auth.go:96` lists a `ypk_` prefix that
   no issuer mints (it exists only as a test-fixture key shape,
   `pkg/mcpserver/server_test.go:60`); issued prefixes are `yb_`, `yag_`,
   `ybs_` (`docs/clients/ownership-map.md` §2.5).

## 7. Citation verification

Every `path:line` citation above was re-resolved mechanically against the
worktree at `34eb9783af26e7780d4ffa8a7c3e2deaf7593428` immediately before
commit: 88 unique citations, 88 resolved, 0 unresolved, plus a content
spot-check of every enforcement-critical line. The check output belongs to
the task handoff, not to this repository. Citations to the companion docs
point at their own snapshot bases where those docs state one
(`docs/clients/ownership-map.md:3`, `docs/clients/modes-audit.md:4`,
`docs/ui-grant-scope-matrix.md:8`).
