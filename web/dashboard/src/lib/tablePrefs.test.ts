import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTablePrefs, tablePrefsKey } from './tablePrefs.ts'

// AUX-22: the localStorage record is user-editable JSON — parsing must
// validate and degrade to defaults, never throw, and must not leak unbound
// junk (wrong types, over-long keys, too many entries, duplicates) into the
// renderer state.

test('parseTablePrefs falls back to defaults for non-objects and garbage', () => {
  assert.deepEqual(parseTablePrefs(null), { hiddenColumns: [], density: 'comfortable' })
  assert.deepEqual(parseTablePrefs('compact'), { hiddenColumns: [], density: 'comfortable' })
  assert.deepEqual(parseTablePrefs(42), { hiddenColumns: [], density: 'comfortable' })
  assert.deepEqual(parseTablePrefs({ hiddenColumns: 'cost_usd' }), { hiddenColumns: [], density: 'comfortable' })
})

test('parseTablePrefs validates density and drops junk column entries', () => {
  assert.deepEqual(parseTablePrefs({ hiddenColumns: ['cost_usd', 'group'], density: 'compact' }),
    { hiddenColumns: ['cost_usd', 'group'], density: 'compact' })
  // An unknown density reads as the default; a missing dir never breaks.
  assert.deepEqual(parseTablePrefs({ density: 'cozy' }), { hiddenColumns: [], density: 'comfortable' })
  assert.deepEqual(parseTablePrefs({ hiddenColumns: ['', '   ', 42, null, 'cost_usd'] }),
    { hiddenColumns: ['cost_usd'], density: 'comfortable' })
  // Duplicates collapse; the list is capped and over-long keys are dropped.
  assert.deepEqual(parseTablePrefs({ hiddenColumns: ['a', 'a', 'b'] }).hiddenColumns, ['a', 'b'])
  assert.ok(parseTablePrefs({ hiddenColumns: Array.from({ length: 100 }, (_, i) => `c${i}`) }).hiddenColumns.length <= 64)
  assert.deepEqual(parseTablePrefs({ hiddenColumns: ['x'.repeat(65)] }).hiddenColumns, [])
})

test('the storage key carries the table id (per-table isolation)', () => {
  assert.equal(tablePrefsKey('lineage'), 'yabanin.tablePrefs.v1:lineage')
  assert.equal(tablePrefsKey('tasks'), 'yabanin.tablePrefs.v1:tasks')
})
