// AF-09: rollback plan building — every plan carries the recorded after
// state as the precondition; missing or truncated snapshots produce no plan
// (honest absence), never a guessed request.
import { test } from 'node:test'
import * as assert from 'node:assert/strict'

import { rollbackPlan } from './rollbackPlan.ts'
import type { AuditLogEntry } from '../api/client.ts'

function entry(overrides: Partial<AuditLogEntry>): AuditLogEntry {
  return {
    id: 'e-1',
    action: 'update',
    resource: 'api_key:key-1',
    details: 'id=key-1',
    admin_id: 'a',
    admin_name: 'Admin',
    ip_address: '10.0.0.1',
    timestamp: '2026-10-02T00:00:00Z',
    ...overrides,
  }
}

test('apiKeyActive rollback carries the recorded after as the precondition', () => {
  const plan = rollbackPlan(entry({
    resource: 'api_key:key-9',
    before: { id: 'key-9', active: true },
    after: { id: 'key-9', active: false },
  }))
  assert.deepEqual(plan, {
    kind: 'apiKeyActive',
    id: 'key-9',
    active: true,
    expectedActive: false,
  })
})

test('rule enable rollback carries expectedEnabled from the recorded after', () => {
  const plan = rollbackPlan(entry({
    resource: 'routing_rule:rule-1',
    before: { id: 'rule-1', enabled: true },
    after: { id: 'rule-1', enabled: false },
  }))
  assert.deepEqual(plan, {
    kind: 'ruleEnabled',
    id: 'rule-1',
    enabled: true,
    expectedEnabled: false,
  })
})

test('label rollback expects the full recorded after surface', () => {
  const plan = rollbackPlan(entry({
    action: 'api_key.labels_update',
    resource: 'api_key:key-1',
    before: { id: 'key-1', labels: { team: 'old' }, labels_locked: false, can_mint_sessions: false, can_read_usage: true },
    after: { id: 'key-1', labels: { team: 'new' }, labels_locked: true, can_mint_sessions: true, can_read_usage: true },
  }))
  assert.deepEqual(plan, {
    kind: 'apiKeyLabels',
    id: 'key-1',
    body: { labels: { team: 'old' }, labels_locked: false, can_mint_sessions: false, can_read_usage: true },
    expected: { labels: { team: 'new' }, labels_locked: true, can_mint_sessions: true, can_read_usage: true },
  })
})

test('team budget 10→20→100: the first change rolls back to 10 expecting the recorded 20', () => {
  const plan = rollbackPlan(entry({
    resource: 'team_budget',
    details: 'team=team-1 limit=20.00 hard=true',
    before: { team_id: 'team-1', monthly_limit_usd: 10, hard_limit: true },
    after: { team_id: 'team-1', monthly_limit_usd: 20, hard_limit: true },
  }))
  assert.deepEqual(plan, {
    kind: 'teamBudgetPut',
    teamId: 'team-1',
    monthlyLimitUSD: 10,
    hardLimit: true,
    expected: { monthly_limit_usd: 20, hard_limit: true },
  })
})

test('team budget creation rollback is a conditional delete expecting the created values', () => {
  const plan = rollbackPlan(entry({
    resource: 'team_budget',
    details: 'team=team-1 limit=20.00 hard=true',
    before: null,
    after: { team_id: 'team-1', monthly_limit_usd: 20, hard_limit: true },
  }))
  assert.deepEqual(plan, {
    kind: 'teamBudgetDelete',
    teamId: 'team-1',
    expected: { monthly_limit_usd: 20, hard_limit: true },
  })
})

test('budget deletion rollback restores only while the budget is absent', () => {
  const plan = rollbackPlan(entry({
    action: 'delete',
    resource: 'team_budget',
    details: 'team=team-1',
    before: { team_id: 'team-1', monthly_limit_usd: 50, hard_limit: false },
    after: undefined,
  }))
  assert.deepEqual(plan, {
    kind: 'teamBudgetPut',
    teamId: 'team-1',
    monthlyLimitUSD: 50,
    hardLimit: false,
    expected: { absent: true },
  })

  const agentPlan = rollbackPlan(entry({
    action: 'delete',
    resource: 'agent_budget',
    details: 'id=agent-1',
    before: { agent_id: 'agent-1', daily_limit_cents: 5000 },
  }))
  assert.deepEqual(agentPlan, {
    kind: 'agentBudgetPut',
    agentId: 'agent-1',
    dailyLimitCents: 5000,
    expected: { absent: true },
  })
})

test('agent budget upsert rollback expects the recorded after cap', () => {
  const plan = rollbackPlan(entry({
    action: 'upsert',
    resource: 'agent_budget',
    details: 'id=agent-1,cents=7000',
    before: { agent_id: 'agent-1', daily_limit_cents: 5000 },
    after: { agent_id: 'agent-1', daily_limit_cents: 7000 },
  }))
  assert.deepEqual(plan, {
    kind: 'agentBudgetPut',
    agentId: 'agent-1',
    dailyLimitCents: 5000,
    expected: { daily_limit_cents: 7000 },
  })

  const createPlan = rollbackPlan(entry({
    action: 'upsert',
    resource: 'agent_budget',
    details: 'id=agent-1,cents=7000',
    before: null,
    after: { agent_id: 'agent-1', daily_limit_cents: 7000 },
  }))
  assert.deepEqual(createPlan, {
    kind: 'agentBudgetDelete',
    agentId: 'agent-1',
    expectedDailyLimitCents: 7000,
  })
})

test('allowlist rollbacks carry the recorded allowed / absence expectations', () => {
  const removeOfAdd = rollbackPlan(entry({
    action: 'add_key_whitelist',
    resource: 'key_whitelist',
    details: 'target_id=key-1,model_name=m-1,allowed=true',
    before: null,
    after: { target_id: 'key-1', model_name: 'm-1', allowed: true },
  }))
  assert.deepEqual(removeOfAdd, {
    kind: 'keyWhitelistRemove',
    apiKeyId: 'key-1',
    modelName: 'm-1',
    expectedAllowed: true,
  })

  const addOfRemove = rollbackPlan(entry({
    action: 'remove_key_whitelist',
    resource: 'key_whitelist',
    details: 'target_id=key-1,model_name=m-1',
    before: { target_id: 'key-1', model_name: 'm-1', allowed: false },
    after: null,
  }))
  assert.deepEqual(addOfRemove, {
    kind: 'keyWhitelistAdd',
    apiKeyId: 'key-1',
    modelName: 'm-1',
    allowed: false,
  })

  const teamRemoveOfAdd = rollbackPlan(entry({
    action: 'add_team_whitelist',
    resource: 'team_whitelist',
    details: 'target_id=team-1,model_name=m-1,allowed=false',
    before: null,
    after: { target_id: 'team-1', model_name: 'm-1', allowed: false },
  }))
  assert.deepEqual(teamRemoveOfAdd, {
    kind: 'teamWhitelistRemove',
    teamId: 'team-1',
    modelName: 'm-1',
    expectedAllowed: false,
  })

  const teamAddOfRemove = rollbackPlan(entry({
    action: 'remove_team_whitelist',
    resource: 'team_whitelist',
    details: 'target_id=team-1,model_name=m-1',
    before: { target_id: 'team-1', model_name: 'm-1', allowed: true },
    after: null,
  }))
  assert.deepEqual(teamAddOfRemove, {
    kind: 'teamWhitelistAdd',
    teamId: 'team-1',
    modelName: 'm-1',
    allowed: true,
  })
})

test('missing or truncated snapshots produce no plan', () => {
  // No after at all (enable family needs it for the precondition).
  assert.equal(rollbackPlan(entry({
    resource: 'api_key:key-1',
    before: { id: 'key-1', active: true },
  })), null)
  // Truncated after (field missing).
  assert.equal(rollbackPlan(entry({
    resource: 'api_key:key-1',
    before: { id: 'key-1', active: true },
    after: { id: 'key-1' },
  })), null)
  // Truncated before (rollback target unknown).
  assert.equal(rollbackPlan(entry({
    resource: 'api_key:key-1',
    before: { id: 'key-1' },
    after: { id: 'key-1', active: false },
  })), null)
  // Whitelist add without the recorded allowed value — no conditional
  // remove can be built.
  assert.equal(rollbackPlan(entry({
    action: 'add_key_whitelist',
    resource: 'key_whitelist',
    details: 'target_id=key-1,model_name=m-1',
    before: null,
    after: { target_id: 'key-1', model_name: 'm-1' },
  })), null)
  // Label update without the after surface.
  assert.equal(rollbackPlan(entry({
    action: 'api_key.labels_update',
    resource: 'api_key:key-1',
    before: { id: 'key-1', labels: {}, labels_locked: false, can_mint_sessions: false, can_read_usage: false },
    after: { id: 'key-1', labels: { team: 'x' }, labels_locked: true },
  })), null)
  // Non-reversible action (rotate has no safe inverse).
  assert.equal(rollbackPlan(entry({
    action: 'rotate_api_key',
    resource: 'api_key:key-1',
    before: { id: 'key-1', key_hash: '[redacted]' },
    after: { id: 'key-1', key_hash: '[redacted]' },
  })), null)
})
