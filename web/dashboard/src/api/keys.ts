// A key's raw secret never travels: the client generates it, hashes it
// (SHA-256) and only the hash reaches the server.

import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type Paginated, type ListSortParams, type RequestOptions } from './http.ts'

export interface APIKey {
  id: string
  name: string
  org_id?: string
  team_id?: string
  active?: boolean
  created_at?: string
  labels?: Record<string, string>
  labels_locked?: boolean
  can_mint_sessions?: boolean
  can_read_usage?: boolean
  // optional and the UI renders the related column/section only when the
  // API actually provides it. Money values are USD units (spend) or cents
  // (rate/limit knobs never appear here — see agentKeys.ts budgets).
  last_used_at?: string | null
  expires_at?: string | null
  requests_7d?: number | null
  spend_usd_7d?: number | null
  rate_limit_rpm?: number | null
  rate_limit_tpm?: number | null
  budget_id?: string | null
}

export interface APIKeyLabelsUpdate {
  labels: Record<string, string>
  labels_locked: boolean
  can_mint_sessions: boolean
  can_read_usage: boolean
}

export async function listAPIKeys(orgId: string, page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<Paginated<APIKey>> {
  return fetchJSON(`/api-keys?org_id=${encodeURIComponent(orgId)}&${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

/** Generates a key client-side (only its SHA-256 hash ever reaches the server). */
export async function createAPIKey(name: string, orgId: string, teamId?: string, opts?: RequestOptions): Promise<{ key: APIKey; rawKey: string }> {
  const rawKey = generateRawKey()
  const keyHash = await sha256Hex(rawKey)
  // An omitted team_id resolves to the org's default team server-side.
  const key = await postJSON<APIKey>(
    '/api-keys',
    { name, org_id: orgId, key_hash: keyHash, ...(teamId ? { team_id: teamId } : {}) },
    'POST', opts,
  )
  return { key, rawKey }
}

export async function rotateAPIKey(id: string, opts?: RequestOptions): Promise<string> {
  const rawKey = generateRawKey()
  const keyHash = await sha256Hex(rawKey)
  await postJSON(`/api-keys/${encodeURIComponent(id)}/rotate`, { key_hash: keyHash }, 'POST', opts)
  return rawKey
}

/** UI-VF-1: PUT /api/api-keys/{id} — activate/deactivate. Deactivation also purges resolver keys server-side. */
export async function setAPIKeyActive(id: string, active: boolean, opts?: RequestOptions): Promise<void> {
  await postJSON(`/api-keys/${encodeURIComponent(id)}`, { active }, 'PUT', opts)
}

/** UI-VF-1: DELETE /api/api-keys/{id}. */
export async function deleteAPIKey(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/api-keys/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}

export async function updateAPIKeyLabels(id: string, body: APIKeyLabelsUpdate, opts?: RequestOptions): Promise<APIKey> {
  return postJSON<APIKey>(`/api-keys/${encodeURIComponent(id)}/labels`, body, 'PUT', opts)
}

function generateRawKey(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return 'yb_' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
}
