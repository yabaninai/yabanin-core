// MC-4 (MCP-CREDENTIALS-PLAN-2026-10-05): pure helpers for the MCP
// credentials page. Side-effect free so the contract logic (masking, the
// status→tone map, the headers/oauth payload assembly, row assembly) is
// unit-testable without a DOM — the page renders, these decide.
//
// Secret hygiene lives here too: payload builders take plain values and
// return ONE serialized object for the request body; nothing is cached and
// no builder ever round-trips a value back into UI state (the dialogs clear
// their drafts on close — see McpCredentialsPage).

import type { McpGrant, McpServer, McpServerCredential, McpUserCredStatus } from '../../api/mcpCredentials'

/** "ab12" → "••••ab12"; a missing fragment stays unknown (never invented). */
export function maskSecretLast4(last4: string | undefined | null): string {
  const fragment = (last4 ?? '').trim()
  return fragment ? `••••${fragment}` : ''
}

/** The visual tone of a per-user credential status (Astra color semantics). */
export type StatusTone = 'success' | 'warning' | 'danger' | 'muted'

export function statusTone(status: McpUserCredStatus): StatusTone {
  switch (status) {
    case 'active':
      return 'success'
    case 'pending':
    case 'needs_update':
      return 'warning'
    case 'needs_reauth':
      return 'danger'
    case 'orphaned':
      return 'muted'
  }
}

/** Literal i18n keys per status — keeps the t() arguments static for the
 * i18n keys gate (no dynamic key composition). */
export function statusLabelKey(status: McpUserCredStatus): string {
  switch (status) {
    case 'active':
      return 'mcpCreds.statusActive'
    case 'pending':
      return 'mcpCreds.statusPending'
    case 'orphaned':
      return 'mcpCreds.statusOrphaned'
    case 'needs_reauth':
      return 'mcpCreds.statusNeedsReauth'
    case 'needs_update':
      return 'mcpCreds.statusNeedsUpdate'
  }
}

export interface HeaderPairDraft {
  name: string
  value: string
}

export type HeadersPayload =
  | { ok: true; payload: Record<string, string> }
  | { ok: false; problem: 'empty' | 'missingName' | 'missingValue' | 'crlf' | 'duplicate' }

/**
 * Builds the headers secret payload from the form drafts. Enforces the same
 * shape the store validates server-side (adminstore.ValidateMCPSecretHeaders):
 * at least one entry, HTTP-token names, values without CR/LF, no duplicate
 * names. The result goes into the request body exactly once.
 */
export function buildHeadersPayload(pairs: HeaderPairDraft[]): HeadersPayload {
  const payload: Record<string, string> = {}
  for (const pair of pairs) {
    const name = pair.name.trim()
    const value = pair.value
    if (!name && !value.trim()) continue // fully blank row — skipped
    if (!name) return { ok: false, problem: 'missingName' }
    if (!value.trim()) return { ok: false, problem: 'missingValue' }
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) return { ok: false, problem: 'missingName' }
    if (/[\r\n\0]/.test(value)) return { ok: false, problem: 'crlf' }
    if (name in payload) return { ok: false, problem: 'duplicate' }
    payload[name] = value
  }
  if (Object.keys(payload).length === 0) return { ok: false, problem: 'empty' }
  return { ok: true, payload }
}

export interface OauthDraft {
  clientId: string
  clientSecret: string
  authUrl: string
  tokenUrl: string
  scopes: string
}

export type OauthPayload =
  | { ok: true; payload: Record<string, string> }
  | { ok: false; problem: 'clientId' | 'clientSecret' | 'authUrl' | 'tokenUrl' }

/**
 * Builds the server-level oauth client configuration the MC-3 flows read
 * (client_id, client_secret, auth_url, token_url, scopes — see the gateway's
 * oauthServerConfig). The client secret lands in the body once.
 */
export function buildOauthPayload(draft: OauthDraft): OauthPayload {
  const clientId = draft.clientId.trim()
  const clientSecret = draft.clientSecret.trim()
  const authUrl = draft.authUrl.trim()
  const tokenUrl = draft.tokenUrl.trim()
  if (!clientId) return { ok: false, problem: 'clientId' }
  if (!clientSecret) return { ok: false, problem: 'clientSecret' }
  if (!/^https:\/\//.test(authUrl)) return { ok: false, problem: 'authUrl' }
  if (!/^https:\/\//.test(tokenUrl)) return { ok: false, problem: 'tokenUrl' }
  const payload: Record<string, string> = {
    client_id: clientId,
    client_secret: clientSecret,
    auth_url: authUrl,
    token_url: tokenUrl,
  }
  const scopes = draft.scopes.trim()
  if (scopes) payload.scopes = scopes
  return { ok: true, payload }
}

/** One row of the server-credentials table: a server joined with its
 * masked credential (missing credential → null). */
export interface ServerCredRow {
  server: McpServer
  cred: McpServerCredential | null
}

export function assembleServerRows(servers: McpServer[], creds: Array<McpServerCredential | null>): ServerCredRow[] {
  const byName = new Map<string, McpServerCredential>()
  for (const cred of creds) {
    if (cred) byName.set(cred.server_name, cred)
  }
  return servers.map(server => ({ server, cred: byName.get(server.name) ?? null }))
}

/** Rows missing a grant for a live server (display fact, never invented). */
export function agentIdsWithoutGrant(grants: McpGrant[]): Set<string> {
  return new Set(grants.filter(g => !g.enabled).map(g => g.agent_id))
}
