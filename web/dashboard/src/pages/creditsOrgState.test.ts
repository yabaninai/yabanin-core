import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// UI-01 (audit addendum, baseline 6a6bd4dc): the Credits screen kept the
// previous organization's balance/transactions on screen while another org
// loaded — and even after the new org's request failed or returned nothing.
// The component also let a superseded org-A completion settle the shared
// loading flag (finally without a generation check), so org B's in-flight
// load read as "settled" while stale rows were displayed.
//
// The JSX page cannot execute under the node strip-types harness; these pins
// hold the corrected state machine at source level, and the behavior itself
// is executed as a browser fixture in e2e/astra/ui01-credits-org-stale.spec.ts
// (regression proven against the baseline source in the browser harness).

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'CreditsPage.tsx'), 'utf8')

describe('UI-01 Credits org state machine', () => {
  it('every load carries a generation; a superseded completion writes nothing', () => {
    assert.match(src, /const gen = \+\+loadGen\.current/,
      'each load takes a fresh generation before the fetch')
    assert.match(src, /if \(gen !== loadGen\.current\) return \/\/ superseded: a newer org owns the screen/,
      'a stale SUCCESS may not write balance/txns')
    assert.match(src, /if \(gen !== loadGen\.current\) return \/\/ superseded failure stays silent/,
      'a stale FAILURE may not render as an error')
  })

  it('only the newest generation settles the loading flag', () => {
    // the defect: an aborted org-A load ran setLoading(false) while org B was
    // still in flight, making the screen look settled with A's stale rows
    assert.match(src, /if \(gen === loadGen\.current\) setLoading\(false\)/,
      'finally must be generation-guarded, not unconditional')
    assert.ok(!/finally \{\s*setLoading\(false\)\s*\}/.test(src),
      'no unconditional finally setLoading(false) may remain')
  })

  it('switching orgs drops the previous org data before the new fetch', () => {
    assert.match(src, /if \(dataOrg\.current !== org\) \{[\s\S]*?setBalance\(null\)[\s\S]*?setTxns\(\[\]\)/,
      'org change clears balance/txns up front, not only on success')
    assert.match(src, /dataOrg\.current = org\s*\n\s*\} catch/,
      'data is bound to the applied org only after a settled load')
  })

  it('clearing the org resets to the not-loaded state (no stale wallet)', () => {
    assert.match(src, /if \(!org\) \{[\s\S]*?setBalance\(null\)[\s\S]*?setTxns\(\[\]\)[\s\S]*?dataOrg\.current = ''/,
      'an empty org settles every piece of org-bound state back to none')
  })

  it('an empty history renders as an explicit empty notice after a settled load', () => {
    // zero rows is a real answer; before, the table silently vanished and the
    // screen showed nothing about the history section at all
    assert.match(src, /balance && !loading && !error && txns\.length === 0 && \(\s*<StateNotice state="empty"/,
      'empty transactions need a settled balance, no loading, no error')
  })

  it('a loading org shows an explicit loading notice (not a silent blank)', () => {
    assert.match(src, /\{loading && !error && <StateNotice state="loading" \/>\}/,
      'in-flight load renders the loading state')
  })
})
