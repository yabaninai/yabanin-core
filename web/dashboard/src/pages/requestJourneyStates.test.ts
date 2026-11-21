import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

// CV-02: source-level pins for the recorded-journey rendering in
// RequestExplorerPage.tsx (a .tsx the node harness cannot render). The page
// must consume the pure view model (web/dashboard/src/lib/requestJourney.ts)
// so every displayed fact binds to a stored request_logs column, keep
// absence explicit (a pre-upstream termination renders NO attempt facts;
// null counters render as "not recorded", never 0/1), clear drawer state on
// tenant change, and refuse unknown/unauthorized requests honestly when
// opened straight from a URL.

const here = dirname(fileURLToPath(import.meta.url))
const page = readFileSync(join(here, 'RequestExplorerPage.tsx'), 'utf8')

describe('RequestExplorerPage recorded journey (CV-02)', () => {
  it('the drawer timeline consumes the pure journey view model', () => {
    assert.match(
      page,
      /from '\.\.\/lib\/requestJourney(\.ts)?'/,
      'the page must import the journey view model (facts bind to stored columns)',
    )
    assert.match(page, /buildRequestJourney\(/, 'the journey is built from the detail row')
    // execution-level behavior of the model itself is pinned in
    // src/lib/requestJourney.test.ts (fixtures, reconciliation, controls).
  })

  it('a pre-upstream termination renders the blocked state, not attempt fiction', () => {
    assert.match(
      page,
      /j\.upstream\.reached/,
      'the upstream branch keys on the model state (model_used === "" ⇒ blocked)',
    )
    assert.match(page, /journeyBlockedTitle/, 'the explicit no-upstream-attempt title is rendered')
    assert.match(
      page,
      /journeyBlockedDetail/,
      'the blocked copy states nothing was sent upstream',
    )
    // Negative control: attempt/retry/TTFT facts render ONLY in the served
    // branch — a blocked row (NULL counters) can never show them.
    const served = page.slice(page.indexOf('j.upstream.reached'), page.indexOf('journeyStageResponse'))
    assert.ok(served.length > 50, 'served branch located')
    assert.match(served, /attemptCount/, 'served branch shows attempts')
    assert.match(served, /firstTokenMs/, 'served branch shows time to first token')
  })

  it('unknown counters render as not-recorded, never as 0 or 1', () => {
    const served = page.slice(page.indexOf('j.upstream.reached'), page.indexOf('journeyStageResponse'))
    assert.match(
      served,
      /attemptCount != null/,
      'null attempt_count must render the absence marker, not a number',
    )
    assert.match(served, /journeyUnknown/, 'the explicit not-recorded marker exists')
  })

  it('absent routing decision (legacy row) is stated, not skipped silently', () => {
    assert.match(
      page,
      /journeyDecisionNotRecorded/,
      'legacy rows render an explicit no-decision-recorded marker',
    )
  })

  it('tenant change clears the drawer before refetching', () => {
    // The effect keyed on [inspectId, org] must reset record/detail/loading
    // synchronously — a stale org's request can never linger in the drawer.
    assert.match(
      page,
      /\}, \[inspectId, org\]\)/,
      'drawer data effect depends on both the request id and the org',
    )
    const effect = page.slice(page.indexOf('setInspectRecord(null)'), page.indexOf('}, [inspectId, org, rowKeysJSON])'))
    assert.ok(effect.includes('setInspectDetail(null)'), 'detail state is cleared on scope change')
    assert.ok(effect.includes('setInspectorLoading(true)'), 'loading state is reset on scope change')
  })

  it('an unauthorized or unknown request id opened by URL is refused honestly', () => {
    assert.match(
      page,
      /!inspectorLoading && !inspectDetail/,
      'a settled fetch with no detail row renders the unknown-request notice',
    )
    assert.match(page, /detailRequestUnknownTitle/, 'the unknown-request diagnosis is titled')
    assert.match(
      page,
      /getRequestDetail\(org, inspectId, undefined, rowKeys\)/,
      'the detail is fetched within the current org scope only, forwarding the URL selector values when present',
    )
  })

  it('a malformed row selector is forwarded, never collapsed or silently retried', () => {
    // 0028: the selector is REACTIVE over its complete ordered value list.
    // A scalar hook reads .get() (first value), so row_key=12 ->
    // row_key=12&row_key=99 — or absent -> row_key= — leaves the
    // dependency IDENTICAL on a mounted page and the previous successful
    // detail stays shown for a URL the server would reject with 400.
    assert.match(
      page,
      /useHashParamValues\(INSPECT_ROW_PARAM\)/,
      'the selector is hook state over ALL ordered values, not the scalar first value',
    )
    assert.match(
      page,
      /JSON\.stringify\(inspectRowKeys\)/,
      'the detail effect identity is the full selector snapshot, so every selector mutation re-runs it',
    )
    assert.match(
      page,
      /inspectRowKeys\.length > 0 \? inspectRowKeys : undefined/,
      'an absent selector keeps the legacy correlation read; present values forward verbatim',
    )
    // The row highlight must not pretend a malformed selector chose a row.
    assert.match(page, /rowSelectorUsable/, 'the highlight gates on a usable single non-blank selector')
  })

  it('evidence links carry actual ids only', () => {
    assert.match(
      page,
      /#lineage\?req=\$\{encodeURIComponent\(inspectId\)\}/,
      'the lineage link embeds the actual request id',
    )
    assert.match(page, /decisionsLink/, 'the policy-decisions link is built from real ids')
  })
})
