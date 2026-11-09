
import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

// A2A agent registry (a2aagg.Agent shape; store nil → 503).
export interface A2aAgent {
  id: string
  org_id: string
  name: string
  display_name?: string
  url: string
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export async function listA2aAgents(orgId: string, opts?: RequestOptions): Promise<A2aAgent[]> {
  const rows = await fetchJSON<A2aAgent[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/a2a/agents`, opts)
  return Array.isArray(rows) ? rows : []
}

export async function updateA2aAgent(
  orgId: string, name: string, patch: { enabled?: boolean }, opts?: RequestOptions,
): Promise<A2aAgent> {
  return postJSON<A2aAgent>(
    `/organizations/${encodeURIComponent(orgId)}/a2a/agents/${encodeURIComponent(name)}`,
    patch, 'PATCH', opts)
}
