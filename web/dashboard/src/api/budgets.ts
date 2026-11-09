// (AUX-15; extracted from client.ts unchanged).

import { sendMutation, type RequestOptions } from './transport.ts'
import { fetchJSON, postJSON, type Paginated } from './http.ts'

// ===== Budgets & alerts center (AUX-15) =====
//
// Existing endpoints only: team budgets (budgets.manage), agent-key budgets
// (agent_keys.manage), the org spend alert and the cross-org credits
// low-balance report (both MustBeRoot server-side). The spend-alert PATCH
// overwrites BOTH fields server-side, so callers always send the full pair.

export interface TeamSpendSummary {
  team_id: string
  /** UTC budget period, "YYYY-MM". */
  period: string
  spend_usd: number
  request_count: number
  monthly_limit_usd: number
  hard_limit: boolean
}

export async function listOrgTeamBudgets(orgId: string, opts?: RequestOptions): Promise<TeamSpendSummary[]> {
  const rows = await fetchJSON<TeamSpendSummary[]>(
    `/organizations/${encodeURIComponent(orgId)}/team-budgets`, opts)
  return Array.isArray(rows) ? rows : []
}

export async function upsertTeamBudget(
  teamId: string, monthlyLimitUSD: number, hardLimit: boolean, opts?: RequestOptions,
): Promise<void> {
  await postJSON<{ status: string }>(
    `/teams/${encodeURIComponent(teamId)}/budget`,
    { monthly_limit_usd: monthlyLimitUSD, hard_limit: hardLimit }, 'PUT', opts)
}

export async function deleteTeamBudget(teamId: string, opts?: RequestOptions): Promise<void> {
  await postJSON<{ status: string }>(`/teams/${encodeURIComponent(teamId)}/budget`, {}, 'DELETE', opts)
}

export interface OrgSpendAlertSettings {
  /** null = alerts disabled. */
  threshold_usd: number | null
  /** null = no webhook configured. */
  webhook_url: string | null
  last_alert_at: string | null
  /** Computed server-side, not stored. */
  spend_today: number
}

export async function getOrgSpendAlert(orgId: string, opts?: RequestOptions): Promise<OrgSpendAlertSettings> {
  return fetchJSON<OrgSpendAlertSettings>(`/organizations/${encodeURIComponent(orgId)}/spend-alert`, opts)
}

export interface OrgSpendAlertPatch {
  threshold_usd: number | null
  webhook_url: string | null
}

export async function updateOrgSpendAlert(orgId: string, patch: OrgSpendAlertPatch, opts?: RequestOptions): Promise<void> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/spend-alert`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) },
    opts)
  if (!outcome.ok) throw outcome.error
}

export interface TeamEntry {
  id: string
  org_id: string
  name: string
}

/** Root-only teams list — used to resolve display names for budgeted teams. */
export async function listTeamsByOrg(orgId: string, opts?: RequestOptions): Promise<TeamEntry[]> {
  const page = await fetchJSON<Paginated<TeamEntry>>(`/teams?org_id=${encodeURIComponent(orgId)}`, opts)
  return Array.isArray(page?.data) ? page.data : []
}
