import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

// CORE-TRACE-04: source-level pins for the routing rule identity in the
// request drawer. CV-02 moved the routing_decision PARSE into the pure view
// model (src/lib/requestJourney.ts — execution-level fixtures live in
// src/lib/requestJourney.test.ts, including the rule-ref round-trip); the
// page keeps the chip rendering. The guarantees are unchanged: the matched
// rule's identity ref must surface when the stored decision carries one —
// short id + content version on screen, full id in the tooltip — and must
// NOT be fabricated or reformatted when the ref is absent (legacy rows,
// passthrough, cache hits).
//
// Wire contract (pkg/gateway/decision.go DecisionRuleRef): the ref rides
// inside routing_decision as rule:{namespace,id,version}; namespace is the
// producer's business, the UI renders id/version only.

const here = dirname(fileURLToPath(import.meta.url))
const page = readFileSync(join(here, 'RequestExplorerPage.tsx'), 'utf8')
const model = readFileSync(join(here, '..', 'lib', 'requestJourney.ts'), 'utf8')

describe('RequestExplorerPage routing rule identity (CORE-TRACE-04)', () => {
  it('the view model accepts the rule ref (id + version) from routing_decision', () => {
    assert.match(
      model,
      /rule\?: \{ id\?: string; version\?: string \}/,
      'the parsed decision must accept the rule ref (id + version) verbatim',
    )
    // Execution-level proof (stronger than any regex): the rule-ref
    // round-trip is pinned in src/lib/requestJourney.test.ts
    // ('parseStoredDecision: rule ref (id + version) round-trips verbatim').
  })

  it('shows a rule chip (short id + version) with the FULL id in the tooltip', () => {
    // Tooltip carries the complete uuid — two same-name rules stay
    // distinguishable without opening anything else.
    assert.match(page, /title=\{`rule \$\{ruleID\}\$\{version\}`\}/, 'full-id tooltip')
    // Short id on screen (first 8 chars) + content version, mono chip.
    assert.match(page, /ruleID\.length > 8 \? ruleID\.slice\(0, 8\) : ruleID/, 'short-id derivation')
    assert.match(page, /rule \{short\}\{version\}/, 'chip text renders short id + version')
  })

  it('never fabricates an identity: absent ref renders no chip', () => {
    assert.match(page, /if \(!ruleID\) return null/, 'absent ref must render no chip at all')
    // Version is optional-honest: no "v" invented for an empty ref.
    assert.match(
      page,
      /typeof d\.rule\?\.version === 'string' && d\.rule\.version \? ` · v\$\{d\.rule\.version\}` : ''/,
      'version suffix only when actually present',
    )
  })

  it('chip uses Astra tokens only (no hardcoded colors)', () => {
    const chip = page.slice(page.indexOf('title={`rule ${ruleID}${version}`}') - 200, page.indexOf('rule {short}{version}') + 40)
    assert.ok(chip.length > 100, 'chip block located')
    assert.match(chip, /var\(--astra-rule-strong\)/, 'border via Astra token')
    assert.match(chip, /var\(--astra-text-muted\)/, 'text via Astra token')
    assert.match(chip, /var\(--astra-font-code\)/, 'mono via Astra token')
    assert.doesNotMatch(chip, /#[0-9a-fA-F]{3,8}\b/, 'no hardcoded hex in the chip')
  })

  it('an unreadable stored decision renders the raw stored string, never a guess', () => {
    // parseFailed keeps the verbatim column on screen (CV-02: absence or
    // corruption is stated, not reconstructed).
    assert.match(page, /j\.decision\.parseFailed/, 'the page keys on the model parse state')
    assert.match(page, /\{d\.routing_decision\}/, 'the raw stored decision string is displayed verbatim')
  })
})
