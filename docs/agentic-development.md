# Agentic development lifecycle

Software teams increasingly ship with AI agents in the loop: agents plan,
gather context, write code, run verification, and open PRs. Yabanin is the
control plane for that lifecycle — every model call, every tool invocation,
and every dollar flows through the gateway with identity, budgets, guards,
and an audit trail.

This page maps the lifecycle stage by stage and states exactly what Yabanin
does at each step. Where a capability is a recommendation rather than an
automation, we say so — nothing here silently changes your routing.

## The lifecycle, stage by stage

| Stage | What the agent does | What Yabanin provides |
|---|---|---|
| **1. Plan / intent** | Opens a session, picks up a task | Task tagging (`X-Yabanin-Task`); per-task cost analytics; agent keys (`yag_*`) give each agent its own identity |
| **2. Context** | Reads docs, queries internal systems | The MCP gateway: your org registers external MCP servers; agents call them only with per-agent grants, guarded parameters, and a full audit trail |
| **3. Generate** | Writes code | Model routing by task shape (classifier + tiers), fallback/failover chains, per-agent token & spend budgets |
| **4. Verify** | Runs tests, evals | Offline eval suites (`yb evaluate routing`, `yb evaluate guards`) as regression gates; LLM-as-judge sampling on production traffic |
| **5. Review / attest** | Opens a PR | Decision header on every response (which model, why, what it cost); jurisdictional lineage attestations — agent-produced work is auditable end to end |
| **6. Operate** | Long-running sessions | Spend reports per agent/task, model comparison on real traffic (shadow evaluation), budget alerts |
| **× Delegation** | Agent spawns sub-agents | Scoped sub-agent keys with their own grants and budgets; the bridge's `tr_delegate` flow |

## A day of an agent team, through Yabanin

1. **Morning.** A coding agent session starts with a `yag_` key. Every request
   carries the task tag; spend lands on the task, not on a shared bucket.
2. **Context gathering.** The agent needs internal knowledge. It calls the
   org's MCP server through the gateway. No grant — no call. Guard hooks scan
   tool parameters for secrets before anything leaves.
3. **Generation.** Routing picks the right tier for each request — cheap
   models for boilerplate, premium for the hard function — within the
   agent's budget.
4. **Verification.** The routing change the team shipped last week runs
   through `yb evaluate routing` in CI; a regression fails the check before
   it reaches production.
5. **Review.** The PR's changes trace to models and costs via the decision
   header; lineage attestations answer "which jurisdiction processed this".
6. **Friday.** The model-comparison screen shows what the shadow evaluation
   measured on the team's own traffic. A human decides whether to switch the
   routing — Yabanin recommends, it does not auto-apply.

## Connect your agent

Point your coding agent at the gateway's **OpenAI-compatible** endpoint. The
only contract the gateway exposes is the base URL plus a bearer key:

- **Base URL** — `http://<gateway-host>:<port>/v1` (the same port the gateway
  listens on; `…/v1/chat/completions` for completions, `…/v1/models` to list
  what the org has registered).
- **Key** — an org API key (`yb_…`) or, for agent work, a per-agent key
  (`yag_…`). Send it as `Authorization: Bearer <key>`.
- **Model** — name the model (or tier) you want; the gateway routes it by task
  shape. The routing decision is returned on the `X-Yabanin-Decision` header.

Every tool below is just a different spelling of that one call. Replace
`http://127.0.0.1:18082` with your gateway address and `yb_…` / `yag_…` with a
real key. These are verified against the gateway contract; none of them require
a running stand to read.

### OpenCode (`make opencode-remote-wire` does this)

`make opencode-remote-wire` writes an `opencode.jsonc` that defaults new
sessions to the `glm-research` orchestrator (`yabanin/glm-5.3`) and routes
`glm-build` plus the legacy `yabanin` / `luna` / `sol-review` / `reason` /
`code` / `complex-code` execution agents through the gateway on
`yabanin/glm-5.3-flash`. The minimal form (the local dev stand
`make stand-opencode` was retired 2026-10-12):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "yabanin/glm-5.3",
  "default_agent": "glm-research",
  "provider": {
    "yabanin": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Yabanin Gateway",
      "options": {
        "baseURL": "https://yabanin.ai/gw/v1",
        "apiKey": "yb_…"
      },
      "models": {
        "glm-5.3": { "name": "GLM-5.3 (orchestration)" },
        "glm-5.3-flash": { "name": "GLM-5.3 Flash (execution)" }
      }
    }
  },
  "agent": {
    "glm-research": { "model": "yabanin/glm-5.3" },
    "glm-build": { "model": "yabanin/glm-5.3-flash" },
    "reason": { "model": "yabanin/glm-5.3-flash" },
    "code": { "model": "yabanin/glm-5.3-flash" },
    "complex-code": { "model": "yabanin/glm-5.3-flash" }
  }
}
```

The model names are deployment configuration (your registry / org routing), not
a fixed list — point each agent at whatever your org registers. See
[OpenCode Integration](./opencode-integration.md) for the routing contract and
the `tr_delegate` subscription-executor sidecar.

### Claude Code

Claude Code is configured with an Anthropic base URL + API key. Point it at the
gateway so the traffic flows through it (the gateway serves the OpenAI-compatible
`/v1` surface; the key is sent as the client's API key):

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:18082/v1"
export ANTHROPIC_API_KEY="yb_…"          # or a yag_… agent key
claude
```

> Verify the exact model name your org registered (`GET /v1/models`) — Claude
> Code sends its configured model string verbatim, so it must match a registered
> model or routing tier.

### Cursor (custom OpenAI base URL)

In **Settings → Models** add a custom OpenAI-compatible endpoint:

- **Base URL:** `http://127.0.0.1:18082/v1`
- **API key:** `yb_…` or `yag_…`
- **Model:** the model / tier name your org registered

Cursor then sends ordinary `chat/completions` requests through the gateway, so
routing, budgets, and the decision header all apply.

### Aider (openai-compatible)

```bash
aider --model openai/glm-5.3 \
  --openai-api-base http://127.0.0.1:18082/v1 \
  --openai-api-key yb_…
```

`--model openai/<name>` makes Aider use the OpenAI-compatible client; the
`/v1` base URL is what the gateway serves.

### Go SDK (raw `chat/completions`)

```go
resp, err := http.Post(
	"http://127.0.0.1:18082/v1/chat/completions",
	"application/json",
	strings.NewReader(`{"model":"glm-5.3","messages":[{"role":"user","content":"ping"}],"max_tokens":8}`),
)
if err != nil { /* handle */ }
defer resp.Body.Close()
// The routing decision (model chosen, why, cost) is on resp.Header["X-Yabanin-Decision"].
```

Use `Authorization: Bearer <key>` (set the header on the request) rather than
embedding the key in a body.

### Node SDK

```ts
import OpenAI from 'openai'

const client = new OpenAI({
  baseURL: 'http://127.0.0.1:18082/v1',
  apiKey: 'yb_…', // or a yag_… agent key
})

const res = await client.chat.completions.create({
  model: 'glm-5.3',
  messages: [{ role: 'user', content: 'ping' }],
  max_tokens: 8,
})
// res.id and the routing decision come back on the response headers.
```

### Governing the connection

Whichever tool you use, the same agent-governance surface applies:

- **Give each agent its own key** (`yag_…`) so spend and blast radius are
  per-agent, not "the team's key". An **agent role profile** (Control Plane →
  "Agent profiles") is a reusable template: issuing a key on a profile inherits
  its tier hint, daily budget cap, and MCP grants — and a profile's grants can
  never exceed the MCP servers registered for your org.
- **Tag the work.** Send `X-Yabanin-Task: <scope>/<task>` so cost lands on the
  task; cap it with `YABANIN_TASK_TOKEN_BUDGET`.
- **Cap the session.** `YABANIN_TASK_TOKEN_BUDGET` / `YABANIN_SESSION_TOKEN_BUDGET`;
  at 100% the gateway returns a `429` the client backs off on.
- **Verify the lineage.** `yb lineage verify --org <org>` after a run.

See [OpenCode Integration](./opencode-integration.md#governing-an-opencode-session)
for the full set of governance recommendations.

## Gateway boundaries

Gateway policies apply to configured traffic only. Three things remain
outside the gateway, by design:

- **Workspace isolation** — the file tree an agent works in is the runner's
  scope, not the gateway's.
- **Code review and release approval** — acceptance of agent-produced
  changes is your CI/review process, not a gateway verdict.
- **Direct tool and SDK connections** — a gateway cannot govern traffic
  that bypasses it. Review tool and SDK paths separately.

## Which model actually did the work?

Check the recorded execution, not just the model requested by the client.
A fallback or routing decision may change the served model mid-flight.
The explorer inspector shows both the requested and the served model,
alongside the routing decision that explains the change.

## What did the attempts cost?

Include failed requests and retries where records are available. Show
missing usage or prices as unknown, not as zero.

## What we deliberately do not do

- **No auto-applied routing changes.** Quality feedback surfaces
  measurements and recommendations; a human confirms policy changes.
- **No unaudited tool calls.** An agent cannot reach an external system
  without a grant, and every call is recorded (parameters redacted).
- **No shared identity.** Agents are principals of their own — keys, budgets,
  and blast radius are per-agent, never "the team's key".

## Where the numbers come from

The comparison and spend figures shown in the dashboard are measured on your
traffic (shadow evaluation overlap, request logs) and captioned with the
scope they were computed over. Where a metric is not yet available — per-model
latency, quality scores — the screen says so instead of inventing a number.
