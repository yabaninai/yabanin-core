---
title: Tool Policies
description: "Per-org tool-call governance: deny rules for MCP/A2A invokes, server-side executors, and the tool_calls the model declares — with starter presets."
sidebar_position: 43
---

# Tool Policies

Tool policies are per-org rules that decide which tool calls your agents may
perform. One rule binds a **subject** (an agent key id, or `*` = every agent
of the org) to a **tool pattern** and an **action** (`allow` / `deny`).

**An org with no policies allows everything** — wiring is free, behavior only
changes when an operator defines rules.

## Where policies apply

| Surface | Effect |
|---|---|
| MCP invokes (`/api/mcp/invoke`) | the raw tool name is checked **before** the proxy egresses; deny → `403 policy_denied` |
| A2A sends (`/api/a2a/send`) | the tool name `a2a:<agent>` is checked the same way |
| Built-in executors (`yabanin:web_fetch`, …) | checked as `yabanin:<tool>` before execution |
| Model responses (`/v1/chat/completions`, JSON and SSE) | `tool_calls` the model **declares** are checked before the client sees them: denied calls are stripped, and a choice whose every call was denied finishes with `stop` instead of `tool_calls` — the client-side executor never receives them |

Denied calls are counted per org and tool in the
`gateway_tool_policy_denied_total` metric — the tracking surface for policy
decisions (the response itself no longer contains the denied calls).

## Evaluation order

The most specific match wins:

1. exact tool name > longer wildcard prefix > shorter wildcard > `*`
2. an agent-specific subject beats `*`
3. the lower `priority` number (0–1000, default 100)
4. stable name order

Wildcards are trailing-star only (`web_*`, `mcp:github:*`); interior stars
are rejected. So `deny web_*` + `allow web_search` composes, and a
per-agent exception beats an org-wide deny.

## Server-side execution (built-in tools)

The virtual `yabanin` MCP server runs tools **in the gateway process**, so
egress happens from the gateway's network position and jurisdiction — not
from the developer's machine:

```
POST /api/mcp/invoke {"server":"yabanin","tool":"web_fetch","params":{"url":"https://example.com/doc"}}
```

### The built-in catalog

| Tool | Effective policy name | What it does |
|---|---|---|
| `web_fetch` | `yabanin:web_fetch` | HTTP GET a URL; text-like content only, 2 MiB cap |
| `http_request` | `yabanin:http_<method>` | Arbitrary HTTP method (get/post/put/patch/delete) with a JSON body — the policy name composes with the method, so `network-readonly` denies `yabanin:http_post` naturally |
| `http_head` | `yabanin:http_head` | HEAD request: response headers (credential headers stripped) without the body |
| `dns_lookup` | `yabanin:dns_lookup` | Resolve a hostname to its A/AAAA records from the gateway's resolver |
| `time_now` | `yabanin:time_now` | Current gateway time (RFC3339 UTC + epoch); no egress |

**Discovery** (agent-principals only; tools the org policy denies are
hidden from the catalog):

```
GET /api/mcp/yabanin/tools
```

All dial-out tools share the deployment SSRF allow-list + reserved-IP
check (one dial-out surface with the MCP registry) and run the pre-egress
guard hooks on their params; every execution lands on the standard audit
trail as `mcp:yabanin:<tool>` with agent/task attribution.

## Starter presets

Applied from the admin console (Tool Policy screen) or the API; presets
create **editable rows** — they are templates, not hidden behavior, and
applying twice skips existing rows:

- **network-off** — deny outbound-network-looking tools for every agent
  (web fetch/browse/http families, including the server-side executor)
- **network-readonly** — allow read-shaped network tools, deny write-shaped
  names (`http_post`, `post_*`, `send_*`, …)
- **internal-only** — deny everything except `yabanin:web_fetch` (all
  egress through the controlled point)

Preset patterns are best-effort over **common** tool names; they are
not exhaustive — review and extend them for your stack.

## Admin API (root-only, org-scoped)

| Method | Path |
|---|---|
| POST | `/api/organizations/{id}/tool-policies` |
| GET | `/api/organizations/{id}/tool-policies` |
| GET | `/api/organizations/{id}/tool-policies/{name}` |
| PATCH | `/api/organizations/{id}/tool-policies/{name}` |
| DELETE | `/api/organizations/{id}/tool-policies/{name}` |
| GET | `/api/organizations/{id}/tool-policies/presets` |
| POST | `/api/organizations/{id}/tool-policies/presets/{preset}` |

Engine decisions are cached per org for 5 seconds; every CRUD mutation
drops the cache immediately.

## Deferred (documented non-goals of v1)

- **Approval workflows** (deny / allow / *ask-an-admin* with a pending
  queue) — the schema's `action` column anticipates it, the engine and UI
  ship allow/deny only.
- Tool classes beyond name patterns (readOnly/destructive annotations),
  semantic tool matching, per-tool quotas.
