// MC-4 (MCP-CREDENTIALS-PLAN-2026-10-05): the MCP credentials client module.
//
// Frozen contracts, read from the handlers (services/admin/handlers/
// mcp_credentials_handlers.go, mcp_servers_handlers.go, router_mcp.go) and
// the gateway flow (pkg/gateway/mcpcredflow.go):
//
//   GET    /api/organizations/{org}/mcp/servers                        → McpServer[]
//   PUT    /api/organizations/{org}/mcp/servers/{name}/credential      body {kind, secret} → masked row
//   GET    /api/organizations/{org}/mcp/servers/{name}/credential      → masked row (404 = no credential)
//   DELETE /api/organizations/{org}/mcp/servers/{name}/credential
//   GET    /api/organizations/{org}/mcp/servers/{name}/grants          → Grant[]
//   DELETE /api/organizations/{org}/mcp/servers/{name}/grants/{agent}  (revoking a grant orphans the
//                                                                      agent's user credentials server-side)
//
// Per-user credential rows (one per server × agent key, statuses
// pending/active/orphaned/needs_reauth/needs_update) are read from
//
//   GET /api/organizations/{org}/mcp/user-credentials
//
// method exists (adminstore.Store.ListMCPUserCredentials) but no admin route
// mounts it in the current backend build. The client answers `null` for a
// 404 or a non-array body so the page can render its explicit
// "endpoint not available" state instead of a fake empty table.
//
// Secrets are WRITE-ONLY everywhere: a submitted value rides the request
// body exactly once and is never retained by this module (no module state,
// no storage). Every read response carries the mask only (has_secret +
// secret_last4) — a response shape carrying more is a backend breach and is
// never rendered.
//
// The gateway flow endpoints (POST /api/mcp/credentials/{server},
// POST /api/mcp/auth/{server}/begin) are agent-principal (yag_) surfaces.
// They are exposed here for the page's per-row actions; in a deployment
// where the dashboard origin does not proxy them the requests fail with the
// backend's error and the page renders that honestly (the handoff records
// the gap).

import { fetchJSON, postJSON } from './http.ts'
import type { RequestOptions } from './transport.ts'
import { listMcpServers, type McpServer } from './mcp.ts'

export type { McpServer }
export { listMcpServers }

/** Per-user credential statuses (migration 0007 vocabulary, adminstore). */
export type McpUserCredStatus = 'pending' | 'active' | 'orphaned' | 'needs_reauth' | 'needs_update'

/** Credential kinds the store validates. */
export type McpCredKind = 'headers' | 'oauth'

/** Masked server-level credential row (adminstore.MCPServerCredential). */
export interface McpServerCredential {
  server_name: string
  kind: string
  secret_last4: string
  has_secret: boolean
  enabled: boolean
  version: number
  created_at: string
  updated_at: string
}

/** Masked per-user credential row (adminstore.MCPUserCredential). */
export interface McpUserCredential {
  id: string
  org_id: string
  server_id: string
  server_name: string
  agent_key_id: string
  kind: string
  secret_last4: string
  status: McpUserCredStatus
  version: number
  expires_at: string | null
  created_at: string
  updated_at: string
  has_secret: boolean
}

/** Per-agent grant (mcpagg.Grant). */
export interface McpGrant {
  id: string
  org_id: string
  agent_id: string
  server_name: string
  allowed_tools: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

/** PUT …/credential body — the secret material rides the body exactly once. */
export interface McpCredentialPut {
  kind: McpCredKind
  /** Headers object ({Authorization: "Bearer …"}) or oauth client config. */
  secret: Record<string, unknown>
}

/** POST /api/mcp/auth/{server}/begin response (gateway mcpcredflow.go). */
export interface McpOAuthBegin {
  url: string
  state: string
  redirect: string
}

export async function getMcpServerCredential(orgId: string, name: string, opts?: RequestOptions): Promise<McpServerCredential | null> {
  try {
    return await fetchJSON<McpServerCredential>(
      `/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}/credential`, opts)
  } catch (err) {
    if (err instanceof Error && 'status' in err && (err as { status?: number }).status === 404) return null
    throw err
  }
}

export async function putMcpServerCredential(orgId: string, name: string, put: McpCredentialPut, opts?: RequestOptions): Promise<McpServerCredential> {
  return postJSON<McpServerCredential>(
    `/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}/credential`, put, 'PUT', opts)
}

export async function deleteMcpServerCredential(orgId: string, name: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}/credential`, {}, 'DELETE', opts)
}

export async function listMcpGrants(orgId: string, name: string, opts?: RequestOptions): Promise<McpGrant[]> {
  const rows = await fetchJSON<McpGrant[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}/grants`, opts)
  return Array.isArray(rows) ? rows : []
}

export async function deleteMcpGrant(orgId: string, name: string, agentId: string, opts?: RequestOptions): Promise<void> {
  await postJSON(
    `/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}/grants/${encodeURIComponent(agentId)}`,
    {}, 'DELETE', opts)
}

/**
 * Lists the org's per-user credential rows. `null` = the admin list endpoint
 * is not available in this backend build (404) or answered a non-array body —
 * the page renders its explicit unavailable state, never a fake empty table.
 */
export async function listMcpUserCredentials(orgId: string, opts?: RequestOptions): Promise<McpUserCredential[] | null> {
  let rows: unknown
  try {
    rows = await fetchJSON<unknown>(`/organizations/${encodeURIComponent(orgId)}/mcp/user-credentials`, opts)
  } catch (err) {
    if (err instanceof Error && 'status' in err && (err as { status?: number }).status === 404) return null
    throw err
  }
  if (Array.isArray(rows)) return rows as McpUserCredential[]
  if (rows !== null && typeof rows === 'object' && Array.isArray((rows as { data?: unknown }).data)) {
    return (rows as { data: McpUserCredential[] }).data
  }
  return null
}

/**
 * Revokes (deletes) the agent's credential on the server. Same PROPOSED
 * admin surface as listMcpUserCredentials (the store method
 * adminstore.Store.DeleteMCPUserCredential exists; the route is part of the
 * MC-4 contract-hole documentation in the lane handoff).
 */
export async function deleteMcpUserCredential(orgId: string, server: string, agentId: string, opts?: RequestOptions): Promise<void> {
  await postJSON(
    `/organizations/${encodeURIComponent(orgId)}/mcp/user-credentials/${encodeURIComponent(server)}/${encodeURIComponent(agentId)}`,
    {}, 'DELETE', opts)
}

/**
 * Submits (or rotates) the agent's headers credential — gateway flow,
 * agent-principal surface. The values object is serialized into the body
 * exactly once; nothing is retained here.
 */
export async function submitMcpUserHeaders(orgId: string, server: string, headers: Record<string, string>, opts?: RequestOptions): Promise<McpUserCredential> {
  return postJSON<McpUserCredential>(
    `/mcp/credentials/${encodeURIComponent(server)}`, { headers }, 'POST',
    { ...opts, headers: { ...(opts?.headers ?? {}), 'X-Org-Id': orgId } })
}

/** Starts the agent's oauth flow — gateway flow, agent-principal surface. */
export async function beginMcpUserOAuth(orgId: string, server: string, opts?: RequestOptions): Promise<McpOAuthBegin> {
  return postJSON<McpOAuthBegin>(
    `/mcp/auth/${encodeURIComponent(server)}/begin`, {}, 'POST',
    { ...opts, headers: { ...(opts?.headers ?? {}), 'X-Org-Id': orgId } })
}
