// unchanged).

import { sendMutation, type RequestOptions } from './transport.ts'
import { fetchJSON, postJSON } from './http.ts'

// TOOL-01/04: tool-call policies — per-org rules (subject × tool pattern →
// allow/deny) that gate MCP/A2A invokes, the built-in executors and the
// tool_calls the model declares in its response.
export interface ToolPolicy {
  id: string
  org_id: string
  name: string
  subject: string
  tool: string
  action: 'allow' | 'deny'
  priority: number
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface ToolPolicyPreset {
  ID: string
  Description: string
}

export async function listToolPolicies(orgId: string, opts?: RequestOptions): Promise<ToolPolicy[]> {
  const rows = await fetchJSON<ToolPolicy[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/tool-policies`, opts)
  return rows ?? []
}

export async function createToolPolicy(input: {
  org_id: string; name: string; subject: string; tool: string; action: string; priority: number; enabled: boolean
}, opts?: RequestOptions): Promise<ToolPolicy> {
  return postJSON<ToolPolicy>('/tool-policies', input, 'POST', opts)
}

export async function updateToolPolicy(orgId: string, name: string, patch: Partial<{
  subject: string; tool: string; action: string; priority: number; enabled: boolean
}>, opts?: RequestOptions): Promise<ToolPolicy> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/tool-policies/${encodeURIComponent(name)}`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) },
    opts)
  if (!outcome.ok) throw outcome.error
  return outcome.body as ToolPolicy
}

export async function deleteToolPolicy(orgId: string, name: string, opts?: RequestOptions): Promise<void> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/tool-policies/${encodeURIComponent(name)}`,
    { method: 'DELETE' }, opts)
  if (!outcome.ok) throw outcome.error
}

export async function listToolPolicyPresets(orgId: string, opts?: RequestOptions): Promise<ToolPolicyPreset[]> {
  const rows = await fetchJSON<ToolPolicyPreset[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/tool-policies/presets`, opts)
  return rows ?? []
}

export async function applyToolPolicyPreset(orgId: string, presetId: string, opts?: RequestOptions): Promise<{ preset: string; created: number; skipped_existing: number }> {
  const outcome = await sendMutation<{ preset: string; created: number; skipped_existing: number }>(
    `/api/organizations/${encodeURIComponent(orgId)}/tool-policies/presets/${encodeURIComponent(presetId)}`,
    { method: 'POST' }, opts)
  if (!outcome.ok) throw outcome.error
  return outcome.body as { preset: string; created: number; skipped_existing: number }
}
