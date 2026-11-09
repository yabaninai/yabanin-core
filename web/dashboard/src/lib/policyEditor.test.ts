// two field-scoped staleness rules (yaml save vs activate/rollback).

import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { PolicyDetail } from '../api/policyPipelines'
import {
  activeVersionDetail, baselineFromDetail, defaultDiffPair, isRollback, isStaleForActivate, isStaleForYaml,
  newestVersion,
} from './policyEditor.ts'

function detail(versions: number[], current: number): PolicyDetail {
  return {
    policy: { id: 'pp_1', org_id: 'o', name: 'p', enabled: true, current_version: current, created_at: '', updated_at: '' },
    versions: versions.map(v => ({
      id: `v${v}`, policy_id: 'pp_1', org_id: 'o', version: v, yaml: `--- v${v}`, git_sha: '',
      label: v === current ? 'active' : 'draft', created_by: 'ops@example', created_at: '',
    })),
    attachments: [],
  }
}

test('baseline: newest version + active version (0 = none)', () => {
  const b = baselineFromDetail(detail([3, 2, 1], 2))
  assert.deepEqual(b, { latestVersion: 3, activeVersion: 2 })
  assert.deepEqual(baselineFromDetail(detail([], 0)), { latestVersion: 0, activeVersion: 0 })
})

test('a yaml save is stale exactly when the LATEST version moved', () => {
  const loaded = { latestVersion: 2, activeVersion: 2 }
  assert.equal(isStaleForYaml(loaded, { latestVersion: 3, activeVersion: 2 }), true,
    'operator B appended/activated v3 — A must not blind-save over it')
  assert.equal(isStaleForYaml(loaded, { latestVersion: 2, activeVersion: 1 }), false,
    'a pure rollback does not move the latest — saving a draft is still safe')
  assert.equal(isStaleForYaml(loaded, loaded), false)
})

test('an activate is stale when the ACTIVE version (or the set) moved', () => {
  const loaded = { latestVersion: 3, activeVersion: 2 }
  assert.equal(isStaleForActivate(loaded, { latestVersion: 3, activeVersion: 3 }), true,
    'someone activated v3 while A still edits from v2')
  assert.equal(isStaleForActivate(loaded, { latestVersion: 4, activeVersion: 2 }), true,
    'a new version appeared — A decides against a moved world')
  assert.equal(isStaleForActivate(loaded, loaded), false)
})

test('history helpers: newest, active, default pair, rollback', () => {
  const d = detail([3, 2, 1], 2)
  assert.equal(newestVersion(d)?.version, 3)
  assert.equal(activeVersionDetail(d)?.version, 2)
  assert.deepEqual(defaultDiffPair(d.versions), { a: 2, b: 3 }, 'default diff = the two newest')
  assert.equal(defaultDiffPair([d.versions[0]]), null)
  assert.equal(isRollback(1, 2), true, 'activating older than active = rollback')
  assert.equal(isRollback(3, 2), false)
  assert.equal(isRollback(2, 0), false, 'no active version yet — nothing to roll back to')
})
