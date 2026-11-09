// client.ts unchanged).

import { ApiError } from './transport.ts'
import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type ListSortParams, type RequestOptions } from './http.ts'
import type { APIKeyLabelsUpdate } from './keys.ts'

// AUX-14a: the audit journal (GET /api/audit-logs, MustBeRoot). The response
// is the handler's own shape (audit_logs/total/page/page_size), not the
// generic Paginated envelope. Sorting follows the AUX-02 contract (allowlist
// id/action/resource/admin_id/admin_name/ip_address/timestamp; unknown column
// → 400 invalid_sort, surfaced as an error). The endpoint has NO filter
// parameters — none are invented here.
// AUX-14b: mutating entries can carry `before`/`after` entity snapshots
// (secret-like fields already redacted server-side) and the operator
// `reason` (X-Audit-Reason header captured at write time).
export interface AuditLogEntry {
  id: string
  action: string
  resource: string
  details?: string
  admin_id: string
  admin_name: string
  ip_address: string
  timestamp: string
  before?: unknown
  after?: unknown
  reason?: string
}

export interface AuditLogsResponse {
  audit_logs: AuditLogEntry[]
  total: number
  page: number
  page_size: number
}

export async function listAuditLogs(page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<AuditLogsResponse> {
  return fetchJSON(`/audit-logs?${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

// AUX-14b: the audit page's rollback replays the reverse call on these
// existing root-only routes (no dedicated endpoint).

// ===== AF-09: preconditioned rollback calls (audit journal) ================
//
// The audit page replays the recorded reverse call on the EXISTING mutation
// routes; every rollback additionally carries the entry's recorded AFTER
// state as an expectation. The server compares it atomically (DB CAS — the
// compare is part of the same SQL statement as the write) and answers
// 409 {"error":"conflict","current":{…}} on divergence, so a stale rollback
// can never overwrite a newer state (10→20→100: rollback of the first
// change conflicts; 100 survives). Only the mutation's own relevant fields
// travel in the expectation — never a full entity with secrets. A plain
// client-side GET before the PUT is NOT sufficient: without the server-side
// CAS the race window stays open.

/** Team budget expectation: `absent` restores a deleted budget only while no row exists. */
export interface TeamBudgetExpectation {
  absent?: boolean
  monthly_limit_usd?: number
  hard_limit?: boolean
}

/** Agent budget expectation: `absent` restores a deleted cap only while no row exists. */
export interface AgentBudgetExpectation {
  absent?: boolean
  daily_limit_cents?: number
}

/** Label-surface expectation compared as a whole (labels + flags). */
export interface APIKeyLabelsExpectation {
  labels: Record<string, string>
  labels_locked: boolean
  can_mint_sessions: boolean
  can_read_usage: boolean
}

export type RollbackCall =
  | { kind: 'apiKeyActive'; id: string; active: boolean; expectedActive: boolean }
  | { kind: 'apiKeyLabels'; id: string; body: APIKeyLabelsUpdate; expected: APIKeyLabelsExpectation }
  | { kind: 'ruleEnabled'; id: string; enabled: boolean; expectedEnabled: boolean }
  | {
      kind: 'teamBudgetPut'
      teamId: string
      monthlyLimitUSD: number
      hardLimit: boolean
      expected: TeamBudgetExpectation
    }
  | { kind: 'teamBudgetDelete'; teamId: string; expected: TeamBudgetExpectation }
  | { kind: 'agentBudgetPut'; agentId: string; dailyLimitCents: number; expected: AgentBudgetExpectation }
  | { kind: 'agentBudgetDelete'; agentId: string; expectedDailyLimitCents: number }
  | { kind: 'keyWhitelistAdd'; apiKeyId: string; modelName: string; allowed: boolean }
  | { kind: 'keyWhitelistRemove'; apiKeyId: string; modelName: string; expectedAllowed: boolean }
  | { kind: 'teamWhitelistAdd'; teamId: string; modelName: string; allowed: boolean }
  | { kind: 'teamWhitelistRemove'; teamId: string; modelName: string; expectedAllowed: boolean }

/** Sends the recorded reverse call with its precondition (X-Audit-Reason rides in opts). */
export async function executeRollback(call: RollbackCall, opts?: RequestOptions): Promise<void> {
  switch (call.kind) {
    case 'apiKeyActive':
      await postJSON(`/api-keys/${encodeURIComponent(call.id)}`,
        { active: call.active, expected_active: call.expectedActive }, 'PUT', opts)
      return
    case 'apiKeyLabels':
      await postJSON(`/api-keys/${encodeURIComponent(call.id)}/labels`,
        { ...call.body, expected: call.expected }, 'PUT', opts)
      return
    case 'ruleEnabled':
      await postJSON(`/rules/${encodeURIComponent(call.id)}/enable`,
        { enabled: call.enabled, expected_enabled: call.expectedEnabled }, 'PUT', opts)
      return
    case 'teamBudgetPut':
      await postJSON(`/teams/${encodeURIComponent(call.teamId)}/budget`,
        { monthly_limit_usd: call.monthlyLimitUSD, hard_limit: call.hardLimit, expected: call.expected }, 'PUT', opts)
      return
    case 'teamBudgetDelete':
      await postJSON(`/teams/${encodeURIComponent(call.teamId)}/budget`, { expected: call.expected }, 'DELETE', opts)
      return
    case 'agentBudgetPut':
      await postJSON(`/agent-keys/${encodeURIComponent(call.agentId)}/budget`,
        { daily_limit_cents: call.dailyLimitCents, expected: call.expected }, 'PUT', opts)
      return
    case 'agentBudgetDelete':
      await postJSON(`/agent-keys/${encodeURIComponent(call.agentId)}/budget`,
        { expected_daily_limit_cents: call.expectedDailyLimitCents }, 'DELETE', opts)
      return
    case 'keyWhitelistAdd':
      await postJSON(`/whitelist/api-keys/${encodeURIComponent(call.apiKeyId)}`,
        { model_name: call.modelName, allowed: call.allowed, expected_absent: true }, 'POST', opts)
      return
    case 'keyWhitelistRemove':
      await postJSON(`/whitelist/api-keys/${encodeURIComponent(call.apiKeyId)}/${encodeURIComponent(call.modelName)}`,
        { expected_allowed: call.expectedAllowed }, 'DELETE', opts)
      return
    case 'teamWhitelistAdd':
      await postJSON(`/whitelist/teams/${encodeURIComponent(call.teamId)}`,
        { model_name: call.modelName, allowed: call.allowed, expected_absent: true }, 'POST', opts)
      return
    case 'teamWhitelistRemove':
      await postJSON(`/whitelist/teams/${encodeURIComponent(call.teamId)}/${encodeURIComponent(call.modelName)}`,
        { expected_allowed: call.expectedAllowed }, 'DELETE', opts)
      return
  }
}

/**
 * Extracts the server-reported current state from a rollback conflict.
 * Returns null unless `err` is the AF-09 409 envelope
 * {"error":"conflict","current":{…}} — the honest surface for the dialog.
 */
export function rollbackConflictCurrent(err: unknown): { error: string; current?: unknown } | null {
  if (!(err instanceof ApiError) || err.status !== 409) return null
  try {
    const parsed = JSON.parse(err.body ?? '') as { error?: string; current?: unknown }
    if (parsed.error !== 'conflict') return null
    return { error: parsed.error, current: parsed.current }
  } catch {
    return { error: 'conflict' }
  }
}
