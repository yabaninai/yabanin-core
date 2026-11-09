// (empty field is never red), the clause builder (real grammar shapes) and
// the && join for the constructor.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ALL_OPS, appendClause, buildClause, isListOp, showsError, visibleIssues } from './helpers.ts'
import { validateMatchExpr } from '../../lib/matchExpr.ts'

const t = (key: string) => key

test('visibleIssues: an empty or whitespace-only field is neutral (D-18)', () => {
  assert.deepEqual(visibleIssues('', validateMatchExpr('', t)), [])
  assert.deepEqual(visibleIssues('   ', validateMatchExpr('   ', t)), [])
})

test('visibleIssues: a typed expression surfaces its real issues', () => {
  const issues = validateMatchExpr('model_requested', t)
  assert.equal(issues.length, 1)
  assert.deepEqual(visibleIssues('model_requested', issues), issues)
  assert.deepEqual(visibleIssues('model_requested == "gpt-4"', validateMatchExpr('model_requested == "gpt-4"', t)), [])
})

test('showsError: red styling only for a non-empty invalid expression', () => {
  assert.equal(showsError('', validateMatchExpr('', t)), false)
  assert.equal(showsError('model_requested', validateMatchExpr('model_requested', t)), true)
  // Warning-level issues alone never turn the field red.
  assert.equal(showsError('model == "gpt"', [{ level: 'warning', message: 'w' }]), false)
})

test('buildClause quotes comparison values, leaves in/not_in lists bare', () => {
  assert.equal(buildClause('model_requested', ' == ', 'gpt-4'), 'model_requested == "gpt-4"')
  assert.equal(buildClause('user_agent', ' contains ', 'opencode'), 'user_agent contains "opencode"')
  assert.equal(buildClause('model_requested', ' in ', 'gpt-4, gpt-4o'), 'model_requested in gpt-4, gpt-4o')
  assert.equal(buildClause('session_id', ' not_in ', 'ci-'), 'session_id not_in ci-')
})

test('appendClause joins with && and never double-joins an empty base', () => {
  assert.equal(appendClause('', 'a == "b"'), 'a == "b"')
  assert.equal(appendClause('a == "b"', 'c starts_with "d"'), 'a == "b" && c starts_with "d"')
  assert.equal(appendClause('  ', 'a == "b"'), 'a == "b"')
})

test('isListOp drives the value placeholder; op set matches the grammar', () => {
  assert.equal(isListOp(' in '), true)
  assert.equal(isListOp(' not_in '), true)
  assert.equal(isListOp(' == '), false)
  assert.ok(ALL_OPS.includes(' contains '))
  assert.equal(ALL_OPS.length, 7)
})
