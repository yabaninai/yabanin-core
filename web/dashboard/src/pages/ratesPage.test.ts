// RatesPage source pins (node --test, no DOM — the JSX page is asserted at
// source level, same convention as r101FailureStates.test.ts /
// onboardingWizard.test.ts). The behavior surface that matters tonight:
// read-only, session-scoped, distinct failure states, copyable digest.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const pageSource = readFileSync(join(here, 'RatesPage.tsx'), 'utf8')
const appSource = readFileSync(join(here, '..', 'App.tsx'), 'utf8')

test('catalog stays read-only — mutations live only in the root-gated promotion section', () => {
  assert.ok(pageSource.includes('getRatesCatalog'), 'the catalog must load via the typed client')
  for (const banned of ['postJSON', 'sendMutation', '/rates/diff', '/rates/promote']) {
    assert.ok(!pageSource.includes(banned), `the page must not call mutations directly: ${banned}`)
  }
  assert.ok(pageSource.includes('RatesPromotionSection'), 'slice 5 mounts the promotion workflow below the catalog')
})

test('distinct failure states: session error vs load error vs unavailable', () => {
  assert.ok(pageSource.includes('status === 401 || error.status === 403'))
  assert.ok(pageSource.includes("state=\"error\""), 'an error notice renders')
  assert.ok(pageSource.includes('rates.sessionRequired'), '401/403 gets the session message, not a raw dump')
  assert.ok(pageSource.includes('rates.notAvailable'), 'a catalog-less answer renders the unavailable notice, not a fake empty table')
})

test('loading is a distinct state, never a blank panel', () => {
  assert.ok(pageSource.includes('<StateNotice state="loading" />'))
})

test('the citation is the audit anchor: digest renders copyable (IdChip)', () => {
  assert.ok(pageSource.includes('IdChip value={catalog.ref.digest}'), 'the committed digest must be copyable in full')
  assert.ok(pageSource.includes('IdChip value={catalog.ref.pack_digest}'))
})

test('catalog notices surface as warnings, never silently dropped', () => {
  assert.ok(pageSource.includes('catalog.ref.notices?.length'))
  assert.ok(pageSource.includes('state="warning"'))
})

test('entries render through the Astra DataTable with an explicit empty answer', () => {
  assert.ok(pageSource.includes('DataTable'))
  assert.ok(pageSource.includes('empty={t(\'rates.emptyModels\')}'))
})

test('App wires the route as anySession (server gate = any admin session)', () => {
  assert.ok(appSource.includes("page === 'rates' && <RatesPage />"), 'route must render')
  assert.ok(appSource.includes("access: { anySession: true }"), 'nav visibility must not be root-only — the server allows any admin session')
  assert.ok(appSource.includes('anySession?: boolean'), 'NavAccess documents the anySession gate')
})
