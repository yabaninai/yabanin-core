---
title: A2A Gateway
description: "Agent-to-agent messaging through Yabanin: an org-managed registry of external A2A agents, agent-only sends, SSRF guarding, parameter guards and an audit trail."
sidebar_position: 42
---

# A2A Gateway

Yabanin's **A2A gateway** is the agent-to-agent counterpart of the
[MCP gateway](mcp-gateway.md): an organization registers its external
A2A (Agent2Agent protocol) agents in an org-scoped registry, and the org's
agent principals (`yag_` keys) send them messages through the gateway — with
agent-only access control, SSRF guarding, pre-egress parameter guards and a
per-send audit trail. It is **off by default**: the route group is mounted
only when `YABANIN_A2A_GATEWAY=1`.

## v1 scope

The proxy carries the A2A JSON-RPC **`message/send`** method
(request/response). **Streaming (`message/stream`) and push notifications are
not proxied in v1** — they are a later increment, not a hidden gap. The
gateway wraps the client's `params` (the A2A `message` object) into the
JSON-RPC envelope itself, so callers cannot smuggle arbitrary methods.

## How it works

```
agent (yag_ key) ──► POST /api/a2a/send {"agent":"helper","params":{...}}
                        │
                        ├─ auth: agent-principal only (org keys → 403 agent_only)
                        ├─ registry: (org, name) must exist and be enabled
                        ├─ SSRF: per-send re-validation (rebind window)
                        ├─ guard: pre-egress scan of the message params
                        └─ upstream: JSON-RPC message/send → the agent's URL
                             result (raw JSON-RPC result) ──► back to the caller
```

Every send is audited to the same `request_logs` trail as model traffic:
`model_used` carries the `a2a:<agent>` label, the (guard-redacted) params ride
the payload, and `X-Yabanin-Task` tags attribute the send to a task.

## Registry

`a2a_agents` (migration 0015) — org-scoped, `https://`-only URLs, `UNIQUE
(org_id, name)`, **inert until enabled**. Admin CRUD (root-only,
org-scoped):

| Method | Path |
|---|---|
| POST | `/api/organizations/{id}/a2a/agents` |
| GET | `/api/organizations/{id}/a2a/agents` |
| GET | `/api/organizations/{id}/a2a/agents/{name}` |
| PATCH | `/api/organizations/{id}/a2a/agents/{name}` |
| DELETE | `/api/organizations/{id}/a2a/agents/{name}` |

Registration (and every URL update) runs the SSRF guard: `https`-only, no
credentials in the URL, the deployment's domain allow-list
(`YABANIN_A2A_ALLOWED_UPSTREAMS`, comma-separated; **empty = no domain
allowed — fail-closed**), and DNS resolution that rejects reserved-IP answers
(metadata endpoints, RFC1918, loopback, link-local, CGNAT). The guard re-runs
on **every send** — a DNS-rebind window between registration and use is not
exploitable.

## Gateway API

```bash
curl -X POST "$BASE_URL/api/a2a/send" \
  -H "Authorization: Bearer yag_..." \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "helper",
    "params": {"message": {"messageId": "m-1", "role": "user",
                            "parts": [{"kind": "text", "text": "status?"}]}}
  }'
```

Error contract: `agent_only` (403), `not_found` (404 — a missing, disabled or
other-org agent is indistinguishable), `ssrf_blocked` (400), `denied` (409,
guard), `upstream` (502), `timeout` (504).

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `YABANIN_A2A_GATEWAY` | `false` | Mount the `/api/a2a/send` route group |
| `YABANIN_A2A_ALLOWED_UPSTREAMS` | *(empty)* | SSRF domain allow-list for agent URLs (empty = fail-closed) |

Upstream calls are bounded: 10s connect, 30s read, 8 MiB response cap,
redirects refused. Identity headers (`X-Yabanin-Agent-Id/-Name/-Team-Id`)
ride upstream from the verified principal — client copies are stripped on
ingress.

## Compared to the MCP gateway

Same discipline (SSRF, guards, audit, agent-only), different object: the MCP
registry points at *tools*, the A2A registry at *agents*. Per-agent grant
tables (the MCP pattern) are a planned increment for A2A — v1 authorizes
sends at the org level.
