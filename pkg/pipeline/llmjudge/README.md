# pkg/pipeline/llmjudge — LLM-judge pipeline step (OP-3)

The `llm_judge` step sends one conversation turn to a judge model and
converts the model's verdict into pipeline findings and a verdict action. It
is the LLM-backed counterpart to the deterministic builtin detectors: same
`Step` contract, same finding vocabulary, but the "detector" is a model call
through the gateway's own upstream machinery.

## Contracts (downstream lanes)

| Contract | Owner seam | Notes |
|---|---|---|
| `JudgeClient` | OP-8 wires, this package ships `UpstreamJudgeClient` | pure seam between pipeline core and model transport; stubs in tests |
| `PromptSource` | **OP-11** replaces `Deps.Prompts` | versioned refs (`judges/toxicity@2`); embedded FS is the default source |
| `ModelResolver` | OP-8 wires over the gateway resolver path | resolves `$(sovereign-classifier)` indirections → `Target` (≈ `resolver.ModelInfo`) |
| `KeyResolver` | OP-8 wires over `resolveUpstreamKey` | same priority chain (org BYOK → per-model key → global); the package never touches credentials |
| Registration | OP-8 | `llmjudge.Register(engine.Steps(), llmjudge.Deps{...})` at startup, or `SetDefaultDeps` + `Factory` |

`ModelResolver`/`KeyResolver` exist so the judge uses the **same**
credential and endpoint machinery as client traffic — but through a clean
package interface, without importing the gateway struct.

## Recursion exclusion (hard contract)

Every judge call carries the marker `judge=true`:

- payload-level: `RequestMeta.Labels["judge"]="true"` on the synthetic call
  meta (`IsJudgeMeta` is the canonical check);
- wire-level: `X-Yabanin-Judge: true` HTTP header on the outbound call.

A judge model can itself be served by this gateway (sovereign on-prem
classifier behind the same deployment). The gateway middleware (OP-8) MUST
skip all policy pipelines only for traffic where `IsJudgeMeta(meta)` holds —
the internal synthetic-call marker. The wire header is not an exemption:
inbound HTTP requests presenting `X-Yabanin-Judge` — `true`, `false`,
arbitrary, empty, or repeated — are untrusted and are rejected (`400
judge_reentry_unsupported`) after authentication, before any upstream call.
The packaged adapter refuses to send unmarked calls, so the exclusion cannot
be lost silently between the step and the wire. Tests: `step_test.go`
(payload marker), `e2e_test.go` (wire marker), and the gateway reentry
boundary in `pkg/gateway/gateway_policy_reentry_test.go`.

## Step params

```yaml
- id: judge_tox
  llm_judge:
    model: "$(sovereign-classifier)"   # required; literal or $(indirection)
    prompt_ref: "judges/toxicity@2"    # required; versioned resource
  params:
    mode: input          # input (last user turn) | output (last assistant turn); default input
    threshold: 0.8       # confidence above which a finding denies; default 0.8, range (0,1]
    categories:          # optional taxonomy pinned in the prompt; empty → prompt default
      - toxicity
  timeout: 2s            # judge latency is request latency — always set this
  on_error: fail_open+flag
```

`mode`/`categories`/`threshold` are ordinary params (strict YAML: unknown
keys are load errors). All validation happens at policy load: unknown prompt
ref, bad threshold, unwired client — the policy never compiles, so a broken
judge step can never silently degrade at request time.

The step is a read-only `Detector` (parallel-group eligible, never mutates
the payload). Temperature is pinned to 0 — verdicts must be deterministic
for the same input, otherwise threshold tuning is meaningless (enforced by
`TestFixtures_Consistency`).

## Verdict format and parsing

The judge model must answer with one JSON object:

```json
{"findings": [{"category": "toxicity", "severity": "low|medium|high",
  "confidence": 0.93, "evidence": "short quote", "span": "start:end"}],
 "summary": "one line"}
```

Parsing is strictly bounded (`ParseVerdict`): markdown fences are stripped,
the raw text must parse as JSON, with one fallback retry on the substring
from the first `{` to the last `}` (models prepend stray prose). Anything
still unparsable is a **malformed verdict → step error → the policy's
`on_error` mode**. Findings without a category are malformed; confidence is
clamped to `[0,1]`; an omitted confidence counts as **1.0 (fail-closed)**.

Judge findings are namespaced `judge.<category>` (e.g. `judge.toxicity`) so
`when` conditions and decision-log queries never collide with detector
categories.

## Verdict → Action mapping (threshold rule)

Per finding: `confidence >= threshold` → **deny**; `0 <= confidence <
threshold` → **flag**. No findings → allow.

- **Default `threshold: 0.8`.** Rationale: a judge that is well-calibrated
  claims violations with high confidence (≥ 0.9); 0.8 leaves headroom for
  calibration drift while staying far above the noise band of borderline
  tone. The quality suite fixes calibration points: toxic ≈ 0.97 (denies at
  the default), boundary ≈ 0.55 (flags), clean = 0 (allows).
- **Raise the threshold** (→ 0.9+) when false denies cost more than missed
  violations (trusted internal tenants, shadow-mode rollouts). Documented
  consequence: a 0.97-confidence toxic claim degrades to flag at 0.99 —
  see `TestFixtures_ThresholdDocExample`.
- **Lower the threshold** (→ 0.5–0.6) for high-risk surfaces (tool args,
  regulated orgs): boundary cases then deny — accepted as the policy's
  explicit trade-off, never silently.
- Consistency precondition: the mapping is only meaningful with
  deterministic judging. Keep `temperature` at the pinned 0 and re-run the
  fixture suite after any prompt version bump.

`on_error` recommendation: **`fail_open+flag`** — a judge outage or
malformed verdict must degrade to an observable flag (decision-log keeps the
step error), not to a blanket deny of all traffic. Set `fail_closed`
explicitly when the judge is the only control on a high-risk surface. Note
the engine's global step default is `fail_closed`; judge policies should
declare `on_error: fail_open+flag` per step (gateway wiring may promote this
to the default for `llm_judge` kinds — OP-8 decision).

## Metrics

- `pipeline_llmjudge_duration_seconds{model, outcome}` — histogram; the
  judge round trip is added to request latency, so this is the budget
  surface (p95 vs the step `timeout`).
- `pipeline_llmjudge_verdicts_total{model, outcome}` — counter; `outcome` ∈
  `allow | flag | mask | deny | error`.
- `model` is the **resolved** model name (registry identity, bounded
  cardinality), or the raw policy reference if resolution failed; never
  request content.

## Offline / sovereign positioning

Transport is `upstream.Pool` — the same SSRF-guarded, adapter-based client
pool the gateway uses for client traffic. Sovereign and on-prem classifiers
are first-class judge targets: the `$(sovereign-classifier)` indirection
resolves through the registry to whatever endpoint the model row declares
(loopback included). No external safety API is contacted; the quality suite
runs entirely against a loopback mock (`fixtures_test.go`).

## Embedded prompts

`judges/<name>/<version>.md`, loaded by `EmbeddedPromptSource`. Refs are
immutable; shipping a new instruction set means adding a new version file
and updating policy refs (old versions stay loadable — audit parity with
policy versioning). Prompt studio (OP-11) swaps the source via `Deps`;
embedded files remain the fallback.
