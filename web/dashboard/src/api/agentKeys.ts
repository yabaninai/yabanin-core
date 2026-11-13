// unchanged).

import { sendMutation, type RequestOptions } from './transport.ts'
import { fetchJSON, postJSON } from './http.ts'

export interface AgentKey {
  id: string
  org_id: string
  name: string
  active: boolean
  created_at: string
  revoked_at?: string | null
}

export interface AgentBudget {
  agent_id: string
  daily_limit_cents: number
  updated_at: string
}

export async function listAgentKeys(orgId: string, opts?: RequestOptions): Promise<AgentKey[]> {
  const result = await fetchJSON<AgentKey[]>(`/agent-keys?org_id=${encodeURIComponent(orgId)}`, opts)
  return Array.isArray(result) ? result : []
}

export interface AgentProfile {
  id: string
  org_id: string
  name: string
  tier_hint: string
  mcp_grants: string[]
  budget_cap_cents: number | null
  guard_mode: string
  created_at: string
  updated_at: string
}

export interface CreateAgentProfileInput {
  name: string
  tier_hint?: string
  mcp_grants?: string[]
  budget_cap_cents?: number | null
  guard_mode?: string
}

export async function listAgentProfiles(orgId: string, opts?: RequestOptions): Promise<AgentProfile[]> {
  const result = await fetchJSON<{ data: AgentProfile[] }>(`/agent-profiles?org_id=${encodeURIComponent(orgId)}`, opts)
  return Array.isArray(result?.data) ? result.data : []
}

export async function createAgentProfile(orgId: string, input: CreateAgentProfileInput, opts?: RequestOptions): Promise<AgentProfile> {
  return postJSON<AgentProfile>(`/agent-profiles`, { org_id: orgId, ...input }, 'POST', opts)
}

export async function updateAgentProfile(id: string, input: Partial<CreateAgentProfileInput>, opts?: RequestOptions): Promise<AgentProfile> {
  return postJSON<AgentProfile>(`/agent-profiles/${encodeURIComponent(id)}`, input, 'PUT', opts)
}

export async function deleteAgentProfile(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/agent-profiles/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}

// createAgentKey optionally issues the key "on a profile": the key
// then inherits the profile's tier hint, budget cap, and MCP grants.
export interface CreateAgentKeyResponse {
  key: string
  key_id: string
  name: string
  org_id: string
  active: boolean
  profile_id?: string
  profile_name?: string
  tier_hint?: string
  guard_mode?: string
  inherited_mcp_grants?: string[]
}

export async function createAgentKey(name: string, orgId: string, profileId?: string, opts?: RequestOptions): Promise<CreateAgentKeyResponse> {
  return postJSON<CreateAgentKeyResponse>(`/agent-keys`, { name, org_id: orgId, ...(profileId ? { profile_id: profileId } : {}) }, 'POST', opts)
}

export async function revokeAgentKey(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/agent-keys/${encodeURIComponent(id)}/revoke`, {}, 'POST', opts)
}

export async function getAgentBudget(agentId: string, opts?: RequestOptions): Promise<AgentBudget> {
  return fetchJSON<AgentBudget>(`/agent-keys/${encodeURIComponent(agentId)}/budget`, opts)
}

export async function upsertAgentBudget(agentId: string, dailyLimitCents: number, opts?: RequestOptions): Promise<AgentBudget> {
  return postJSON<AgentBudget>(`/agent-keys/${encodeURIComponent(agentId)}/budget`, { daily_limit_cents: dailyLimitCents }, 'PUT', opts)
}

export async function deleteAgentBudget(agentId: string, opts?: RequestOptions): Promise<void> {
  const outcome = await sendMutation(`/api/agent-keys/${encodeURIComponent(agentId)}/budget`, { method: 'DELETE' }, opts)
  if (!outcome.ok) throw outcome.error
}
