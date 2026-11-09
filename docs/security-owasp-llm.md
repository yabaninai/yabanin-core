# OWASP Top-10 for LLM Applications — Yabanin Control Mapping

This page maps the **OWASP Top-10 for LLM Applications (2025/2026 list)** to
the controls that actually exist in the Yabanin codebase — what each control
is, how it is enabled, and, explicitly, where coverage ends. Every control
names its code path or doc; nothing on this page is roadmap dressed up as
shipping software (planned items are labeled as such).

Yabanin is a gateway, not an LLM application: most risks below are about
what the *applications behind the gateway* do. The gateway's role is to give
the operator enforcement points those applications cannot bypass —
policy is admin-owned and org-scoped, never per-request
([Policy Pipeline](pipeline.md) §1).

Status legend: **built-in** (ships in the code), **opt-in** (built-in, off by
default, enabled by config/policy), **author-it** (no dedicated control; the
operator authors one from pipeline primitives), **not covered** (no control;
named so nobody assumes one exists).

## LLM01 — Prompt Injection

**Risk:** untrusted input steers the model (directly, or indirectly via tool
results and retrieved documents).

| Control | Status | Where |
|---|---|---|
| Deterministic injection-phrase detector (RU + EN) | built-in, opt-in | `pkg/guardhooks/finding.go` (`regex:injection`), pipeline step `builtin/injection` ([pipeline.md §5](pipeline.md)) |
| Guard modes on egress/tool params: `off / log / redact / deny` | built-in, opt-in | `pkg/guardhooks/hook.go`, `YABANIN_GUARD_MODE` ([agent-governance.md](agent-governance.md)) |
| Custom deny/allow lists per org (`contains`, `regex` steps) | author-it | `builtin/contains`, `builtin/regex` (RE2, expansion-bomb-safe) |
| Semantic second opinion | author-it | `llm_judge` step (`pkg/pipeline/llmjudge`) — org-authored judge prompts, temperature pinned to 0 |
| External scanner callouts (self-hosted Presidio, Lakera-class) | author-it | `pkg/pipeline/callout` — egress allow-list + SSRF guard |
| Blast-radius reduction: per-agent tool grants, allow-list intersection, args schema/regex guards, result post-checks | built-in, opt-in | `pkg/mcpagg`, `pkg/toolpolicy` ([mcp-gateway.md §7](mcp-gateway.md), [tool-policies.md](tool-policies.md)) |
| Pipeline self-protection: gateway-made judge calls carry the internal `judge=true` marker and are exempt; inbound requests presenting `X-Yabanin-Judge` (any value, even empty or duplicated) are rejected instead of exempted, so a hostile payload cannot trigger recursion; unknown step actions rank as deny | built-in | [pipeline.md §6.2](pipeline.md), `pkg/pipeline/engine.go` |

**Enable:** set `YABANIN_GUARD_MODE=redact|deny`, or attach a policy with
`builtin/injection` on `pre_upstream` / `tool_pre`; the
`deploy/policies/_pack/sovereign-default.yaml` pack includes it (ships OFF —
[pipeline.md §8](pipeline.md)).

**Limitations:** detection is deterministic phrase/regex matching —
there is no built-in *semantic* injection classifier; a judge/callout step is
the intended answer. Indirect injection arriving inside tool *results* is
scanned by rule post-checks (secrets/PII/deny_regex), not by semantics. The
pre-pipeline checks documented in [security-audit.md](security-audit.md)
("prompt injection is inherent") still holds for deployments that never
enable guards.

## LLM02 — Sensitive Info Disclosure

**Risk:** PII/secrets leak into prompts, responses, logs, or other orgs' hands.

| Control | Status | Where |
|---|---|---|
| National PII detectors with checksum validation: RU (INN, SNILS, internal passport, OGRN, phone) + BR/IN/MY/AE/ZA/NG/KE/EG, PAN with Luhn | built-in, opt-in | `pkg/guardhooks/finding.go`, `pkg/guardhooks/ru_ids.go`; pipeline `builtin/national-pii` |
| Secret-shape detectors (provider keys, PEM, JWT) + credential-keyed JSON values | built-in, opt-in | `pkg/guardhooks/credkeys.go`; pipeline `builtin/secrets` (evidence quoted as `[REDACTED_SECRET]`) |
| Redaction and reversible pseudonymization (`{{YPP_n}}` aliases, outbound-only — no reverse substitution into responses) | built-in, opt-in | `builtin/redact`, `builtin/pseudonymize` ([pipeline.md §5](pipeline.md)) |
| Data-boundary routing: rewrite the model to an in-region one when PII is found | built-in, opt-in | `builtin/model-rewrite` ([pipeline.md §5](pipeline.md)) |
| Callout projections bound what leaves the gateway (`messages` / `fields:a,b`; metadata never leaves) | built-in | `pkg/pipeline/callout`, [pipeline.md §6.1](pipeline.md) |
| Encryption at rest: `enc:` AES-256-GCM envelopes, fail-closed writes | built-in | `pkg/encryption`, [mcp-gateway.md §6](mcp-gateway.md) |
| Org isolation: row-level security with `app.current_org` GUC pinned per transaction | built-in | `pkg/adminstore`, `pkg/mcpagg` (sqlcontract tests) |
| Masked reads: BYOK keys and MCP credentials read back as last-4 / `has_secret` only; plaintext never crosses the API | built-in | `pkg/mcpagg/creds.go`, [byok.md](byok.md) |
| Log hygiene: `redactPII` on event payloads, URL credential stripping, decision log stores content hashes — quoted user content persists only in shadow/debug retention | built-in | `pkg/eventpublisher/redis_publisher.go`, [pipeline.md §9](pipeline.md) |

**Enable:** `YABANIN_GUARD_MODE` for the always-on path; policies for
pseudonymize/mask/deny per org, key-label, model, endpoint.

**Limitations:** the offline jurisdiction set is fixed (RU + 9); other
jurisdictions need an authored `regex` step or a callout detector. The
guardhooks confidence threshold is 0.9+ (checksum/strict-format), so
format-only matches are not redacted. Pseudonymization deliberately never
re-substitutes into responses — workflows needing the
originals must resolve them out-of-band.

## LLM03 — Supply Chain

**Risk:** vulnerable dependencies, tampered models, or untrusted components in
the serving path.

| Control | Status | Where |
|---|---|---|
| `govulncheck` (symbol-level) in the quality gates + `go mod verify` | built-in | `make analyze-security`, `_quality-security` (Makefile), `scripts/quality/dep_audit.py` |
| Pinned analyzer/toolchain versions; finding triage script | built-in | `make install-analysis-tools` (Makefile), `scripts/security/govulncheck-classify.sh` |
| Container hardening: read-only filesystems, no-new-privileges, internal bridge network | built-in | [security-audit.md](security-audit.md) |
| Model supply control: model allow-list step + org/model whitelists per key/team | built-in, opt-in | `builtin/model-whitelist`, `pkg/whitelist` |
| Policy/prompt provenance: policies reconcile from git and record the git SHA; judge prompts are versioned resources | built-in | [pipeline.md §8](pipeline.md), `pkg/policystore` |

**Limitations:** scanning covers Go only — the dashboard/site npm
tree and Docker base images are not govulnchecked here. There is no SBOM
generation or attestation. Models are upstream *services*: the whitelist
constrains *which* models serve, not the integrity of their weights; a
model-provenance scheme is not covered. Callout scanners are third-party
services inside the trust boundary once an operator allow-lists them.

## LLM04 — Data and Model Poisoning

**Risk:** training/fine-tuning data, embeddings, or cached content poisoned
to change behavior.

Yabanin operates no fine-tuning or training-data pipeline, so the classic
poisoning surface does not exist here; the adjacent surfaces are:

| Control | Status | Where |
|---|---|---|
| Per-org cache keying (`cache:{org_id}:…`) — no cross-org cache reads; semantic layer can be disabled per org (`exact`/`off` privacy modes); admin-only toggle with audit | built-in | [cache-architecture.md](cache-architecture.md), `pkg/cache` |
| Cache precision measured and published, so a semantic near-hit is a documented trade-off rather than a silent behavior change | built-in | [cache-precision.md](cache-precision.md) |
| Immutable policy versions + git reconciliation (a poisoned DB edit shows as DRIFT and is overwritten by git on apply) | built-in | [pipeline.md §8](pipeline.md) |
| Versioned judge prompts (`judges/<name>@<version>`) — a tampered prompt changes the version, not the semantics of existing references | built-in | `pkg/pipeline/llmjudge` |

**Limitations:** the ML task classifier (`pkg/classifier`,
`make train-classifier`) trains on gateway traffic metadata — its training
corpus has no provenance/attestation chain. Customer-side vector stores and
fine-tuning datasets are entirely outside this codebase.

## LLM05 — Improper Output Handling

**Risk:** model output passed unchecked into downstream contexts (shells,
SQL, browsers, tools).

| Control | Status | Where |
|---|---|---|
| Output hooks: `post_upstream`, `stream_prefix`, `stream_final` run the same policy engine over responses and stream aggregates | built-in, opt-in | [pipeline.md §2, §7](pipeline.md) |
| Structured-output checks: JSON Schema / JSON keys validation; code-language detection; URL scheme/host checks | built-in, opt-in | `builtin/json-schema`, `builtin/json-keys`, `builtin/code-detect`, `builtin/url-check` |
| Streaming safety: prefix gate checks one captured snapshot before buffered bytes are released; chunk carry applies a replacement learned from a complete prefix match to later occurrences, including split occurrences, but does not guarantee detection of incomplete or later-new values | built-in, opt-in | [pipeline.md §7](pipeline.md), `pkg/pipeline/streaming` |
| Tool-result post-checks (secrets/PII/deny_regex, flag/mask/deny) before an agent sees a tool result | built-in, opt-in | `pkg/toolpolicy/guard.go`, [mcp-gateway.md §7](mcp-gateway.md) |

**Enable:** attach a policy to output hooks; output kinds are the default
scope of the JSON-schema step.

**Limitations:** the gateway treats output as *data* — it does not
context-encode output for a downstream renderer (HTML/SQL/shell escaping
stays the application's job) and does not sandbox what clients do with
results. A `stream_final` deny cannot unsend already-streamed bytes; it
degrades to a flagged decision-log record ([pipeline.md §7](pipeline.md)).

## LLM06 — Excessive Agency

**Risk:** agents take more actions, or more consequential ones, than
intended.

| Control | Status | Where |
|---|---|---|
| Agent-principal keys (`yag_*`) — tool calls rejected for non-agent keys; `X-Agent-Id` stripped on ingress and re-set only from the verified principal | built-in | `pkg/mcpagg/proxy.go`, [mcp-gateway.md §2](mcp-gateway.md) |
| Static least privilege: per-agent grants, effective tool set = server allow-list ∩ grant allow-list; a blocked call is indistinguishable from "server unavailable" (404) | built-in | `pkg/mcpagg/catalog.go`, [mcp-gateway.md §2](mcp-gateway.md) |
| Per-call parameter guards: JSON-Schema on args, `max_bytes`, `deny_regex` (pre-egress 400), org deny policies for model-declared tool_calls | built-in, opt-in | `pkg/toolpolicy` ([tool-policies.md](tool-policies.md)) |
| Cost/blast-radius ceilings: per-agent daily budgets, per-task token budgets, org RPM/TPM caps | built-in | `pkg/budget/agent.go`, [agent-governance.md](agent-governance.md), LLM10 below |
| Full attribution: every call → `request_logs` row + hash-chained audit + `gateway_mcp_calls_total` / OTel span | built-in | [mcp-gateway.md §2](mcp-gateway.md), `pkg/auditlog` (sha256 chain) |
| Native MCP endpoint reuses the same invoke guard chain; stateless HMAC-signed sessions | built-in | `pkg/mcpserver` |

**Limitations:** grants are static enables — there is no per-call
human-approval/consent workflow; if an agent should never call a tool
unattended, the grant must not exist. Agency limits are only as good as the
allow-lists admins configure.

## LLM07 — System Prompt Leakage

**Risk:** the system prompt (instructions, secrets embedded in it) is
revealed through output.

| Control | Status | Where |
|---|---|---|
| Secret-shape detectors over responses (`post_upstream` / `stream_final`) catch secret-shaped content leaving the model | author-it | `builtin/secrets` with output kinds |
| Deny/flag lists of canonical prompt fragments | author-it | `builtin/contains`, `builtin/regex` |
| Server-side partials: shared prompt fragments live in prompt studio and are substituted server-side, never shipped to clients | built-in | [pipeline.md §5](pipeline.md) (`builtin/partials-substitute`) |

**Limitations:** there is **no dedicated system-prompt-leakage
detector** — no classifier for "this text looks like our system prompt".
Mitigation must be authored as policies (contains/regex/judge), and none of
them can stop a model from paraphrasing its instructions. Keep secrets out of
system prompts; the gateway cannot retroactively fix a prompt that contains
them.

## LLM08 — Vector and Embedding Weaknesses

**Risk:** embedding inversion, cross-tenant vector leakage, poisoned
retrieval.

Yabanin's embeddings endpoint is a pass-through; the gateway operates no
customer vector store. The nearest in-gateway vector surface is the semantic
cache:

| Control | Status | Where |
|---|---|---|
| Per-org keying of all cache layers — no cross-org semantic hits | built-in | [cache-architecture.md](cache-architecture.md) |
| Org privacy modes: semantic layer switchable to `exact` or `off`; exact layer always org-keyed | built-in | [cache-architecture.md](cache-architecture.md) |
| Measured precision/recall of the semantic judgment, published | built-in | [cache-precision.md](cache-precision.md) |
| Cache policy changes admin-only + audited; TTL + janitor bounds stale entries | built-in | [cache-architecture.md](cache-architecture.md) |

**Limitations:** no embedding-inversion or membership-inference
detection exists. Similarity thresholds trade precision for savings; an org
whose threat model treats near-duplicate answers as leakage must run the
semantic layer off.

## LLM09 — Misinformation

**Risk:** the model states falsehoods with confidence.

**Not covered by dedicated controls.** There is no grounding check, factuality
scorer, or retrieval-verification in the codebase, and this page refuses to
dress one up. What exists is adjacent:

| Control | Status | Where |
|---|---|---|
| Org-authored judge steps can score outputs against any rubric, factuality included (deterministic temperature, threshold → deny/flag) | author-it | `pkg/pipeline/llmjudge` |
| Quality sampling (evalgate) measures judged quality per model pair/task class — a measurement, not a prevention | built-in | [evaluation.md](evaluation.md), [mcp-gateway.md §2](mcp-gateway.md) |
| Jurisdictional lineage signs recorded routing metadata; it does not independently prove physical processing location or response correctness | built-in | [lineage.md](lineage.md) |

## LLM10 — Unbounded Consumption

**Risk:** runaway agents, cost bombs, resource exhaustion.

| Control | Status | Where |
|---|---|---|
| Org caps: RPM / TPM, split input/output TPM (ITPM/OTPM), per-key TPM; `YABANIN_ORG_CAPS=shadow|enforce`, fail-closed on store errors, beta defaults (60 RPM / 200k TPM / $50) | built-in | `pkg/adminstore/orgcaps.go`, `pkg/gateway/ratelimit.go` |
| Per-key/team rate limits (`YABANIN_KEY_RATE_LIMITS`), fair-share priorities on retry | built-in, opt-in | `pkg/gateway/ratelimit.go` |
| Budgets with reservations: team monthly / agent daily hard limits → 429; fail-closed admission (store outage = 503, spend never unbounded); soft limits logged | built-in | `pkg/budget`, [security-audit.md](security-audit.md), [runbooks/budget-reservations-alerts.md](runbooks/budget-reservations-alerts.md) |
| Circuit breakers, per-endpoint or global (`YABANIN_CIRCUIT_SCOPE`) — a flapping upstream stops consuming spend | built-in | `pkg/circuit`, `pkg/gateway/circuit_wiring.go` |
| Bounded work everywhere: streaming prefix buffer (64 tokens / 500 ms), bounded MCP proxy timeouts + max response size, callout singleflight + per-step timeouts, regex `max_input` caps (1 MiB default / 64 MiB hard) | built-in | [pipeline.md](pipeline.md), [mcp-gateway.md](mcp-gateway.md) |
| Loop visibility: `gateway_mcp_calls_total`, `gateway_policy_*`, spend analytics | built-in | [mcp-gateway.md §2](mcp-gateway.md), [analytics.md](analytics.md) |

**Limitations:** default caps are beta defaults — a deployment that
raises them owns the consequences. Rate caps are per-org/per-key, not
per-end-user; an org with many humans behind one key needs key-level caps or
upstream quotas. Per-provider breaker isolation (one global breaker today) is
a limitation to account for when configuring routing.

## Enabling controls — quick reference

| Layer | Switch | Default |
|---|---|---|
| Guard hooks (PII/secrets/injection on chat egress + tool params) | `YABANIN_GUARD_MODE=log\|redact\|deny` | `off` |
| Policy pipeline | `YABANIN_POLICY_MODE=shadow\|enforce` + attached policies | `off` |
| Sovereign default pack (PII + secrets + injection) | `yb policies reconcile --include-pack`, lands disabled | off |
| Tool guardrails on MCP/A2A | org tool policies + per-server rules | off (no rules = passthrough) |
| MCP/A2A/native-MCP surfaces | `YABANIN_MCP_GATEWAY=1` (+ A2A equivalent) | off |
| Org caps / key limits | `YABANIN_ORG_CAPS=enforce` / `YABANIN_KEY_RATE_LIMITS` | shadow / off |
| Callout egress | `YABANIN_POLICY_CALLOUT_ALLOW_HOSTS` | empty = callout steps unavailable (fail-closed) |
| MCP upstream egress | `YABANIN_MCP_ALLOWED_UPSTREAMS` | empty = every host rejected (fail-closed) |

The default-deny behavior of every egress knob is deliberate: with nothing
configured, nothing dials out.

## Related

- [Policy Pipeline](pipeline.md) — the enforcement engine and its fail modes
- [MCP Gateway](mcp-gateway.md) — tool-surface threat model (R1–R10)
- [Tool Policies](tool-policies.md), [Agent Governance](agent-governance.md)
- [Security controls](security.md) — auth surfaces, secrets at rest, supply chain
- [Security checks and threat model](security-audit.md)
