// LedgerPanel + CreditsPage wiring source pins (node --test, no DOM).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const panel = readFileSync(join(here, 'credits', 'LedgerPanel.tsx'), 'utf8')
const page = readFileSync(join(here, 'CreditsPage.tsx'), 'utf8')

test('the reconciliation verdict is the server verdict, rendered as a state', () => {
  assert.ok(panel.includes('ledger.ledger_consistent'))
  assert.ok(panel.includes("consistent === false"), 'false must be distinguishable')
  assert.ok(panel.includes('credits.ledger.inconsistentTitle'), 'false renders an ERROR notice, never softened')
  assert.ok(/consistent === true\s*\?\s*t\('credits\.ledger\.consistent'\)/.test(panel), 'true renders consistent')
  assert.ok(panel.includes('credits.ledger.notReported'), 'null/absent renders not-reported, never ok')
})

test('full count vs shown rows are distinct numbers, both honest', () => {
  assert.ok(panel.includes('ledger.transaction_count'))
  assert.ok(panel.includes('ledger.transactions.length < ledger.transaction_count'))
  assert.ok(panel.includes('credits.ledger.rowsShown'))
})

test('starter grant distinguishes claimed from configured-only', () => {
  assert.ok(panel.includes('grant.claimed'))
  assert.ok(panel.includes('credits.ledger.grantClaimed'))
  assert.ok(panel.includes('credits.ledger.grantUnclaimed'))
})

test('credits_scale renders verbatim', () => {
  assert.ok(panel.includes('{ledger.credits_scale}'))
  assert.ok(!/credits_scale\s*=[^=]/.test(panel), 'the panel must not compute a scale')
})

test('a ledger failure never breaks the wallet surface (separate settle)', () => {
  assert.ok(page.includes('getCreditsLedger(org, 50'), 'ledger rides the same applied org')
  assert.ok(page.includes('void getCreditsLedger'), 'the ledger promise is settled independently of the wallet pair')
  assert.ok(page.includes('e instanceof ApiError && e.status === 501'), '501 is its own state')
})

test('org switching drops the previous org ledger before the new load', () => {
  assert.ok(page.includes('setLedger(null)'), 'ledger state resets on org switch/clear')
})

test('distinct ledger notices: 501 not-deployed vs load error with retry', () => {
  assert.ok(page.includes('credits.ledger.notDeployed'))
  assert.ok(page.includes('credits.ledger.loadFailedTitle'))
  assert.ok(page.includes('ledgerError && !loading'))
})
