# Loop Execution SPI (pkg/loopexec) — v1, edition `experimental`

Related: [Agent Loop SPI](AGENT-LOOP-SPI.md) and [API contract](CONTRACT.md).

## What this SPI is

`pkg/loopexec` is the **open, Apache-2.0 core seam** between a loop engine
(a thing that decides which tools to call) and the guarded execution path
(the thing that actually executes them, under allow-list, subject,
credential and SSRF policy). The seam is deliberately small:

- **`Config`** — the loop-execution configuration: `Edition`
  (`experimental` in v1, fail-closed — anything else is refused by
  `Validate`), `Scope` (org/project/route), `AllowedTools`
  (server-qualified `server:tool` allow-list; **empty means none** — an
  unconfigured route executes no tools), `MaxToolCalls` (zero means "not
  configured" and engines must refuse to start — zero-bound denial).
- **`Call`** — one executor-addressed request: scope, server, tool,
  `Action` (`invoke` in v1; `list` exists for catalog parity), model-proposed
  `Params`, the authenticated `Subject` and the `agentloop.CredentialRef`
  (service or delegated-user; a denied user grant never escalates to
  service credentials).
- **`Result`** — the post-guard outcome: released `Payload`, `SideEffect`
  (the shared `agentloop` vocabulary: `none` / `done` / `uncertain`) and
  latency.
- **`Executor`** — one server's guarded execution path. The core adapter is
  `loopexec.NewBuiltinExecutor`, which routes through
  `toolexec.ExecuteGuarded` (allow-list, subject binding, SSRF checks,
  per-tool policy) and classifies side effects: mutating tools with an
  unconfirmed outcome report `uncertain`.
- **`Registry`** — write-once server→executor map; a call with no executor
  is refused, never dispatched to a default.

Sentinels (`ErrNoExecutor`, `ErrNotPermitted`, `ErrUnknownTool`,
`ErrSubjectRequired`) are pre-egress refusals: a call classified with one of
them never touched an external system, so a caller may treat the failure as
confirmed. Any other executor error must be treated as **post-egress
unknown** — the external effect may have happened.

## Versioning

v1 is additive-only, like `AGENT-LOOP-SPI.md`: new optional surface arrives
as new interfaces or appended enum values; a breaking change ships as a
parallel `SPIVersion = "v2"`, never as a mutation of v1. The edition marker
(`experimental`) is load-bearing: v1 executors and engines refuse any other
edition string, so an experimental capability can never run unmarked.

## Invariants engines must honor

1. **Fail-closed configuration**: `Config.Validate` gates every run; a
   zero tool budget or step bound refuses to start.
2. **Subject travels with the request**: the model never names a subject;
   `Call.Subject` is filled from the authenticated principal.
3. **Params are proposals**: model-provided `Params` reach executors only
   through the guard path, which decides whether they may execute.
4. **Uncertain stays uncertain**: a `Result` with
   `SideEffectUncertain`, or an executor error that is not a pre-egress
   sentinel, is never reported as success, never counted as zero cost, and
   never blindly retried within a run.
5. **No self-approval**: `approval_required` decisions park on the durable
   approval mechanism; an agent must not approve its own calls.
   Resumption after approval is a fresh run with full rechecks — approval
   never carries permissions forward.
6. **Per-grant action enforcement**: the MCP grant check consults the
   per-grant `allowed_actions` column (migration 0020). Column default `["invoke","list"]` preserves pre-0020 behavior;
   an explicit empty list denies both actions. The delegation-chain path is
   tools-only — chain allowances never assert actions.
