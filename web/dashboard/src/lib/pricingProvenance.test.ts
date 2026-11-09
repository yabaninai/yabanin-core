// pricing_as_of label (source + date + sha256) into the collapsed evidence —
// a 7-char ref plus the date — and the full text for the disclosure. The
// collapsed ref must stay short even for the long pinned upstream URL the
// bundled snapshot cites.
import { test } from 'node:test'
import * as assert from 'node:assert/strict'

import { collapsedProvenanceRef, parsePricingProvenance } from './pricingProvenance.ts'

test('splits the pinned upstream label into source, date, sha256 and a 7-char ref', () => {
  const raw = 'github.com/BerriAI/litellm@61a73c59b049a8cd6c559168d7f3a2557a1a8cf7/model_prices_and_context_window.json 2026-09-30 sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
  const p = parsePricingProvenance(raw)
  assert.equal(p.raw, raw)
  assert.equal(p.source, 'github.com/BerriAI/litellm@61a73c59b049a8cd6c559168d7f3a2557a1a8cf7/model_prices_and_context_window.json')
  assert.equal(p.date, '2026-09-30')
  assert.equal(p.sha256, 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
  assert.equal(p.ref, '61a73c5')
})

test('offline bundled label falls back to the sha256 prefix as the ref', () => {
  const p = parsePricingProvenance('bundled.json (offline) 2026-09-30 sha256:feed0000')
  assert.equal(p.source, 'bundled.json (offline)')
  assert.equal(p.date, '2026-09-30')
  assert.equal(p.ref, 'feed000')
})

test('degrades gracefully when the label carries no date or sha256', () => {
  const p = parsePricingProvenance('pkg/pricing/pricing.go (bundled historical list prices)')
  assert.equal(p.source, 'pkg/pricing/pricing.go (bundled historical list prices)')
  assert.equal(p.date, undefined)
  assert.equal(p.sha256, undefined)
  assert.equal(p.ref, undefined)
})

test('the collapsed ref never exceeds 7 characters', () => {
  const p = parsePricingProvenance('github.com/BerriAI/litellm@61a73c59b049 2026-09-30 sha256:ff')
  assert.ok((p.ref ?? '').length <= 7)
  assert.equal(p.ref, '61a73c5')
})

// CORE-REF-04: the default snapshot cites the yabanin reference catalog.
// The parser exposes the structured pieces — catalog version + digest
// prefix — and keeps ref at the version pin; collapsedProvenanceRef composes
// the `catalog:<version> digest:<hex-prefix>` node the provenance UI shows.
const GENESIS_DIGEST = 'c6b3f43ee0e15c21b08cefbdb61dfab4412f9f2dd6dabbf12c45371d9bd60708'

test('catalog label parses into the structured citation and a version ref', () => {
  const raw = `yabanin-catalog@0.1.0 2026-11-02 sha256:${GENESIS_DIGEST}`
  const p = parsePricingProvenance(raw)
  assert.equal(p.raw, raw)
  assert.equal(p.source, 'yabanin-catalog@0.1.0')
  assert.equal(p.date, '2026-11-02')
  assert.equal(p.sha256, `sha256:${GENESIS_DIGEST}`)
  assert.deepEqual(p.catalog, { version: '0.1.0', digestPrefix: 'c6b3f43' })
  assert.equal(p.ref, '0.1.0')
})

test('catalog label without a sealed digest degrades without a catalog citation', () => {
  const p = parsePricingProvenance('yabanin-catalog@0.2.0-draft 2026-11-02')
  assert.equal(p.source, 'yabanin-catalog@0.2.0-draft')
  assert.equal(p.date, '2026-11-02')
  assert.equal(p.catalog, undefined)
  assert.equal(p.ref, '0.2.0-d') // version pin, truncated to the 7-char budget
})

test('collapsedProvenanceRef renders the catalog node shape for catalog labels', () => {
  const raw = `yabanin-catalog@0.1.0 2026-11-02 sha256:${GENESIS_DIGEST}`
  assert.equal(collapsedProvenanceRef(parsePricingProvenance(raw)), 'catalog:0.1.0 digest:c6b3f43')
})

test('collapsedProvenanceRef falls back to the plain ref for non-catalog labels', () => {
  const raw = 'github.com/BerriAI/litellm@61a73c59b049 2026-09-30 sha256:ff'
  assert.equal(collapsedProvenanceRef(parsePricingProvenance(raw)), '61a73c5')
  assert.equal(collapsedProvenanceRef(parsePricingProvenance('bundled.json (offline)')), undefined)
})
