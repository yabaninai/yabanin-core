// AF-09: rollback planning for the audit journal (moved out of the page so
// the snapshot→plan validation is node-testable).
//
// The rollback is NOT a dedicated endpoint: for the four safe families
// (label, enable, budget, allowlist) the page replays the recorded reverse
// call on the existing mutation route — see executeRollback in api/client.
// AUX-14b base contract: every plan is built only from a fully-shaped
// before/after snapshot; a missing or unexpected field means no plan (honest
// absence), never a guessed request.
//
// AF-09 addition: each plan carries the entry's recorded AFTER state as the
// rollback precondition. The server compares it atomically (DB CAS) and
// answers 409 with the current state on divergence, so a stale rollback
// (10→20→100: undo of the first change) conflicts instead of overwriting
// the newer state, and an old enable/disable rollback cannot cancel a newer
// security decision. The precondition rides only the mutation's own
// relevant fields — no full entity, no secrets.
//
// - `before` names where the entity was BEFORE the audited change → the
//   rollback's target value.
// - `after` is the recorded result of the audited change → the rollback's
//   expected CURRENT state; if it no longer matches, the server refuses.

import type { RollbackCall, AuditLogEntry } from '../api/client'

export type { RollbackCall } from '../api/client'

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)
const asStr = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null)
const asBool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null)
const asNum = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const asStringRecord = (v: unknown): Record<string, string> | null => {
  if (!isRecord(v)) return null
  for (const value of Object.values(v)) {
    if (typeof value !== 'string') return null
  }
  return v as Record<string, string>
}

// The entity id rides after ":" in the resource (api_key:<id>) or inside the
// free-form details ("id=…" for most mutations, "name=…" for models).
export function entityId(e: AuditLogEntry): string | null {
  const idx = e.resource.indexOf(':')
  if (idx >= 0 && idx < e.resource.length - 1) return e.resource.slice(idx + 1)
  const m = /\bid=([^,]+)/.exec(e.details ?? '')
  return m ? m[1] : null
}

export function rollbackPlan(e: AuditLogEntry): RollbackCall | null {
  const before = isRecord(e.before) ? e.before : null
  const after = isRecord(e.after) ? e.after : null
  const id = entityId(e)
  switch (e.action) {
    // label: restore the previous label set, expecting the recorded after set.
    case 'api_key.labels_update': {
      if (!id || !before || !after) return null
      const labels = asStringRecord(before.labels)
      const locked = asBool(before.labels_locked)
      const mint = asBool(before.can_mint_sessions)
      const usage = asBool(before.can_read_usage)
      const expLabels = asStringRecord(after.labels)
      const expLocked = asBool(after.labels_locked)
      const expMint = asBool(after.can_mint_sessions)
      const expUsage = asBool(after.can_read_usage)
      if (
        !labels || locked === null || mint === null || usage === null ||
        !expLabels || expLocked === null || expMint === null || expUsage === null
      ) return null
      return {
        kind: 'apiKeyLabels',
        id,
        body: { labels, labels_locked: locked, can_mint_sessions: mint, can_read_usage: usage },
        expected: { labels: expLabels, labels_locked: expLocked, can_mint_sessions: expMint, can_read_usage: expUsage },
      }
    }
    case 'update': {
      // enable: api_key active toggle → the inverse PUT with the recorded
      // after.active as the expectation.
      if (e.resource.split(':')[0] === 'api_key') {
        if (!id || !before || !after) return null
        const was = asBool(before.active)
        const now = asBool(after.active)
        if (was === null || now === null || was === now) return null
        return { kind: 'apiKeyActive', id, active: was, expectedActive: now }
      }
      // enable: routing rule toggle → the inverse PUT with the recorded
      // after.enabled as the expectation.
      if (e.resource.split(':')[0] === 'routing_rule') {
        if (!id || !before || !after) return null
        const was = asBool(before.enabled)
        const now = asBool(after.enabled)
        if (was === null || now === null || was === now) return null
        return { kind: 'ruleEnabled', id, enabled: was, expectedEnabled: now }
      }
      // budget: team budget update → restore the previous config (expecting
      // the recorded after values), or delete the budget this action created
      // (conditional delete expecting those values).
      if (e.resource === 'team_budget') {
        const teamId = asStr(before?.team_id) ?? asStr(after?.team_id) ?? id
        if (!teamId || !after || asNum(after.monthly_limit_usd) === null) return null
        const nowLimit = asNum(after.monthly_limit_usd) as number
        const nowHard = asBool(after.hard_limit)
        if (nowHard === null) return null
        if (!before) return { kind: 'teamBudgetDelete', teamId, expected: { monthly_limit_usd: nowLimit, hard_limit: nowHard } }
        const wasLimit = asNum(before.monthly_limit_usd)
        const wasHard = asBool(before.hard_limit)
        if (wasLimit === null || wasHard === null) return null
        return {
          kind: 'teamBudgetPut',
          teamId,
          monthlyLimitUSD: wasLimit,
          hardLimit: wasHard,
          expected: { monthly_limit_usd: nowLimit, hard_limit: nowHard },
        }
      }
      return null
    }
    // budget: agent budget upsert → restore the previous cap (expecting the
    // recorded after value), or delete the budget this action created.
    case 'upsert': {
      if (e.resource !== 'agent_budget' || !after) return null
      const agentId = asStr(before?.agent_id) ?? asStr(after.agent_id) ?? id
      if (!agentId || asNum(after.daily_limit_cents) === null) return null
      const now = asNum(after.daily_limit_cents) as number
      if (!before) return { kind: 'agentBudgetDelete', agentId, expectedDailyLimitCents: now }
      const was = asNum(before.daily_limit_cents)
      if (was === null) return null
      return { kind: 'agentBudgetPut', agentId, dailyLimitCents: was, expected: { daily_limit_cents: now } }
    }
    // budget: a budget deletion is undone by re-setting the removed cap,
    // which requires the budget to still be absent.
    case 'delete': {
      if (e.resource === 'agent_budget' && before) {
        const agentId = asStr(before.agent_id) ?? id
        const was = asNum(before.daily_limit_cents)
        if (!agentId || was === null) return null
        return { kind: 'agentBudgetPut', agentId, dailyLimitCents: was, expected: { absent: true } }
      }
      if (e.resource === 'team_budget' && before) {
        const teamId = asStr(before.team_id) ?? id
        const wasLimit = asNum(before.monthly_limit_usd)
        const wasHard = asBool(before.hard_limit)
        if (!teamId || wasLimit === null || wasHard === null) return null
        return {
          kind: 'teamBudgetPut',
          teamId,
          monthlyLimitUSD: wasLimit,
          hardLimit: wasHard,
          expected: { absent: true },
        }
      }
      return null
    }
    // allowlist: an added entry is undone by a conditional remove (only
    // while the entry still carries the added allowed value); a removed
    // entry is restored only while it stays absent.
    case 'add_key_whitelist': {
      const target = asStr(after?.target_id)
      const model = asStr(after?.model_name)
      const allowed = asBool(after?.allowed)
      if (!target || !model || allowed === null) return null
      return { kind: 'keyWhitelistRemove', apiKeyId: target, modelName: model, expectedAllowed: allowed }
    }
    case 'remove_key_whitelist': {
      const target = asStr(before?.target_id)
      const model = asStr(before?.model_name)
      const allowed = asBool(before?.allowed)
      if (!target || !model || allowed === null) return null
      return { kind: 'keyWhitelistAdd', apiKeyId: target, modelName: model, allowed }
    }
    case 'add_team_whitelist': {
      const target = asStr(after?.target_id)
      const model = asStr(after?.model_name)
      const allowed = asBool(after?.allowed)
      if (!target || !model || allowed === null) return null
      return { kind: 'teamWhitelistRemove', teamId: target, modelName: model, expectedAllowed: allowed }
    }
    case 'remove_team_whitelist': {
      const target = asStr(before?.target_id)
      const model = asStr(before?.model_name)
      const allowed = asBool(before?.allowed)
      if (!target || !model || allowed === null) return null
      return { kind: 'teamWhitelistAdd', teamId: target, modelName: model, allowed }
    }
    default:
      return null
  }
}
