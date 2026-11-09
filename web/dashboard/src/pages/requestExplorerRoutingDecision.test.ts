import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

// CORE-TRACE-04: source-level pins for the routing-decision renderer in
// RequestExplorerPage.tsx (a .tsx the node harness cannot render). The page
// must surface the matched routing rule's identity ref when the stored
// decision carries one — short id + content version on screen, full id in
// the tooltip — and must NOT fabricate or reformat anything when the ref is
// absent (legacy rows, passthrough, cache hits).
//
// Wire contract (pkg/gateway/decision.go DecisionRuleRef): the ref rides
// inside routing_decision as rule:{namespace,id,version}; namespace is the
// producer's business, the page renders id/version only.

const here = dirname(fileURLToPath(import.meta.url))
const page = readFileSync(join(here, 'RequestExplorerPage.tsx'), 'utf8')

describe('RequestExplorerPage routing rule identity (CORE-TRACE-04)', () => {
  it('renderRoutingDecision parses the optional rule ref from the stored decision', () => {
    assert.match(
      page,
      /rule\?: \{ id\?: string; version\?: string \}/,
      'renderRoutingDecision must accept the rule ref (id + version) from routing_decision',
    )
  })

  it('shows a rule chip (short id + version) with the FULL id in the tooltip', () => {
    // Tooltip carries the complete uuid — two same-name rules stay
    // distinguishable without opening anything else.
    assert.match(page, /title=\{`rule \$\{ruleID\}\$\{version\}`\}/, 'full-id tooltip')
    // Short id on screen (first 8 chars) + content version, mono chip.
    assert.match(page, /ruleID\.length > 8 \? ruleID\.slice\(0, 8\) : ruleID/, 'short-id derivation')
    assert.match(page, /rule \{short\}\{version\}/, 'chip text renders short id + version')
  })

  it('never fabricates an identity: absent ref renders the plain text', () => {
    assert.match(page, /if \(!ruleID\) return text/, 'absent ref must return the unchanged text')
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
})
