# Changelog

Notable changes to Yabanin Core between developer previews, written for both
engineering and product readers. Each entry names the code range it covers;
release artifacts are tagged and published separately with their own evidence.

## Preview 2 — 2026-11-24

Everything merged to `main` between Preview 1 ([v0.1.0-preview.1], source
`7b85b18`) and merge commit `6c8156f` (qualified candidate `5cce324`, delivered
through [#98] and [#109]; ~600 commits, ~115k insertions).

Preview 2 is the **dependable installation and first request** milestone:
install Core cleanly, connect a provider, send a request, inspect what was
actually recorded, and recover the installation.

### Installation and first run

- One-command clean install: the Docker Compose quickstart starts PostgreSQL,
  Redis, the gateway and a mock provider, with no implicit paid-model traffic.
  An optional showcase stand generates demo traffic with a console to inspect
  it.
- A guided onboarding wizard in the dashboard walks an operator from provider
  configuration and model selection through the first request, shows the
  recorded evidence of that request, and sets up the first team budget.
- Clean-install scope: this preview provides no upgrade path from Preview 1 and
  no rollback procedure.

### Gateway and request handling

- OpenAI-compatible endpoint surface: chat, completions, embeddings, batch,
  images and effort parameters, with SSE streaming passthrough.
- Deterministic retries with exactly-once accounting and cancellation; retry
  attribution is recorded per attempt (`retry_count=0` is bound to the first
  attempt).
- Retry scheduling honors upstream `Retry-After` headers, including hints
  observed on streams.
- Streaming robustness repairs: no torn SSE frames on client cancellation, the
  idle-reader watchdog fires exactly once, and timeout-writer header/flush
  races are fixed.

### Authorization and tenancy

- Revoked or cross-tenant access produces no forbidden effect; tenant
  isolation and revocation are enforced by dedicated oracles and verified by a
  live two-tenant browser journey.
- Dual-form authorization (API key and session) with a consistent deny
  identity for SSE refusals.
- Tool policies are enforced on tool-invoking requests (ToolGate), including
  per-choice declarations and policy revocation.
- Unknown-model requests under a reject policy return a clean 404, are logged
  with the verbatim error, and create no billing side effects.

### Accounting and budgets

- Fixed accounting event loss under burst load: the publisher backlog was
  enlarged and made observable; re-qualification recorded zero dropped
  `request_logs` rows.
- Every completed paid request yields exactly one settlement intent; wallet,
  team spend and ledger entries reconcile exactly, with crash-recovery and
  settlement-fencing coverage, including interrupted streams.
- Token/cost budget hardening: provider outages surface under a single
  sentinel cause and the budget enforcer pool is isolated.
- Schema additions (migrations 0028–0034): request invocations and their
  contract, tool-fact invocations, session organization scope, and grant-row
  identity for request payloads.

### Request journey and dashboard

- Request ids are wired end to end; the request explorer shows what was
  actually recorded, and missing journey stages are shown as missing rather
  than reconstructed from current configuration.
- Cache-hit requests now appear in history.
- Dashboard: routing topology view, edge window, request inspector with
  pinning, pagination and a responsive request window; navigation keeps the
  selected organization and scope, covered by a dedicated org-presentation
  browser journey.
- Request export and request-detail row identity hardened.

### Recovery

- Same-version backup and restore verified against data created by this build:
  request chain, wallet, teams and row census all match after restore.
- Restore refuses to run against a populated target; the refusal itself is
  tested, not just the happy path.
- Disaster-recovery proof suite and local qualification snapshot targets for
  operators.

### Security and release engineering

- Release evidence pipeline: OCI build receipts, SPDX SBOM generation with
  pinned tooling, delivered-set and offline-verification gates, NOTICE
  mirroring, upstream license fixtures, and a public
  [release-evidence guide](docs/release-evidence.md).
- The mock-provider image ships complete Alpine package notices and a
  verifiable source companion.
- The SAML advisory GO-2026-6909 was re-reviewed against the pinned dependency
  (both upstream fixes present) and the scanner binding refreshed; no new
  waivers were introduced.
- Static-analysis campaign across the gateway closed 65 open lint/security
  findings to zero.

### SDKs and documentation

- Go, Node and Python SDKs updated; the Python SDK builds as an installable
  wheel with pinned build tooling and Apache-2.0 license and notice hygiene.
- English documentation and quickstart updated; docs-site build and language
  gates run in CI.

### Known limitations

- **Full-load qualification deferred to Preview 3.** Load preflight, dry-run
  and canary passed; the 1000-VU execute with three-way accounting
  reconciliation did not complete on the current self-hosted runner. A control
  run of the previously passing build reproduces the same latency crossing,
  isolating the cause to host capacity, not a product regression. Thresholds
  are unchanged.
- **Temporary quality-gate exception.** The critical-go seed-replay verdict
  runs with an explicit override bound to the Preview 2 task base
  (`CRITICAL_SEED_BLOCK_OVERRIDE_BASE`); every other check remains strict. The
  override and its CI propagation are removed in Preview 3.
- UI acceptance is desktop-only; narrower mobile viewports are unverified.
- Clean install only: no Preview 1 migration or rollback.

### Verification snapshot

Full evidence and discussion are in [#98] and [#109].

- Full local quality profile: **PASS, all 29 gates** on the merged tree
  (manifest `20261124T010850Z-19a6863b`), covering race-enabled Go tests,
  routing, guards, journey, dashboard, policy, complexity and security gates.
- Required PR checks **SUCCESS** (run
  [45310635305](https://github.com/yabaninai/yabanin-core/actions/runs/45310635305));
  post-merge main CI **SUCCESS** (run
  [45320263186](https://github.com/yabaninai/yabanin-core/actions/runs/45320263186)),
  including race tests, security and critical-go on the merge commit.
- Desktop clean-install / first-request / backup-restore drill **PASS** on the
  exact merged tree, with populated-target refusal and zero leftover
  containers after teardown.

### Looking ahead: Preview 3

- Complete the deferred full-load execute with independent accounting
  reconciliation on suitable runner capacity.
- Replace the temporary seed-block handling with a reviewed acceptance design;
  continue the recorded coverage and complexity follow-ups.
- Daily-operation scope: identities, credentials and grants; model routing and
  policy; pricing, credits and budgets; multidimensional accounting.

## Preview 1 — v0.1.0-preview.1 (2026-11-09)

Initial developer preview for Linux amd64. See the
[release notes](https://github.com/yabaninai/yabanin-core/releases/tag/v0.1.0-preview.1).

[#98]: https://github.com/yabaninai/yabanin-core/pull/98
[#109]: https://github.com/yabaninai/yabanin-core/pull/109
[v0.1.0-preview.1]: https://github.com/yabaninai/yabanin-core/releases/tag/v0.1.0-preview.1
