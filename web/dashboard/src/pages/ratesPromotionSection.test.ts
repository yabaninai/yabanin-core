// RatesPromotionSection source pins (node --test, no DOM — same convention
// as capsStatusSection.test.ts). The behaviors that must not regress:
// typed-client mutations only, two-step confirmation with a MANDATORY
// reason, refusal-as-data with no fake retry, the /api/rates/ build ceiling
// (16 MiB) as a client guard (never blamed on pack content), the durable
// swap note, double-submit protection, and the root-gated mount on
// RatesPage.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'RatesPromotionSection.tsx'), 'utf8')
const page = readFileSync(join(here, 'RatesPage.tsx'), 'utf8')

test('mutations go through the typed client — diff first, promote second', () => {
  assert.ok(src.includes('await diffRatesPack(pack'), 'diff must use the typed client')
  assert.ok(src.includes('await promoteRatesPack(pack'), 'promote must use the typed client')
  for (const banned of ['postJSON', 'sendMutation', 'fetch(']) {
    assert.ok(!src.includes(banned), `mutations must not bypass the client: ${banned}`)
  }
})

test('promote is a confirmed second step: a reason is mandatory, empty blocks the button', () => {
  assert.ok(src.includes("promoteReason.trim().length > 0"), 'the promote guard must require a trimmed non-empty reason')
  assert.ok(src.includes('disabled={!canPromote}'), 'the promote button must carry the guard')
  assert.ok(src.includes('rates.promotion.promoteReasonRequired'), 'the disabled state says WHY')
})

test('a 422 refusal is data: rendered whole, promote disabled, no fake retry', () => {
  assert.ok(src.includes('parseRatesRefusal(e)'), 'refusals are parsed from the ApiError body')
  assert.ok(src.includes('refusal.refusal_reason'), 'the server refusal reason renders')
  assert.ok(src.includes("!(refusal?.refused ?? false)"), 'a refused pack cannot be promoted from this UI')
  assert.ok(src.includes('rates.promotion.refusedNoRetry'), 'the disabled promote explains itself')
})

test('the 16 MiB /api/rates/ ceiling is a client guard AND copy, never blamed on the pack', () => {
  assert.ok(src.includes('RATES_PACK_BODY_LIMIT_BYTES = 16_777_216'))
  assert.ok(src.includes('new TextEncoder().encode(pack).length'), 'byte count, not char count')
  assert.ok(src.includes('rates.promotion.tooLarge'))
  assert.ok(src.includes('rates.promotion.bodyLimit'), 'the limit is stated up front as a build property')
  assert.ok(!/pack (is|was) (invalid|malformed)/i.test(src), 'the UI never asserts pack invalidity')
})

test('the durable swap semantics are stated next to every applied result', () => {
  assert.ok(src.includes('rates.promotion.restartNote'))
  assert.ok(src.includes('promo.applied'))
})

test('double-submit protection: in-flight disables both actions', () => {
  assert.ok(src.includes("busy === null"), 'the guard reads the busy state')
  assert.ok(src.includes("setBusy('diff')"), 'diff marks busy')
  assert.ok(src.includes("setBusy('promote')"), 'promote marks busy')
  assert.ok(src.includes("disabled={!canDiff}"), 'diff button carries the guard')
})

test('a success refreshes the committed catalog above (no stale citation)', () => {
  assert.ok(src.includes('onPromoted()'), 'the component reports promotion')
  assert.ok(page.includes('onPromoted={() => void load()}'), 'RatesPage reloads the catalog on promotion')
})

test('RatesPage confines mutations to the section and root-gates it', () => {
  for (const banned of ['postJSON', 'sendMutation', 'diffRatesPack', 'promoteRatesPack', '/rates/diff', '/rates/promote']) {
    assert.ok(!page.includes(banned), `the page must not call mutations directly: ${banned}`)
  }
  assert.ok(page.includes('<RatesPromotionSection onPromoted={'), 'the section must be mounted')
  assert.ok(page.includes('!perms.loading && (perms.isRoot || perms.me === null)'), 'mount gate: root, or unknown /me (server arbitrates)')
})

test('operator-facing failures stay distinct: 400 server text vs 401/403 session vs refusal', () => {
  assert.ok(src.includes('error.status === 400'))
  assert.ok(src.includes('rates.promotion.badRequest'))
  assert.ok(src.includes('rates.promotion.rootRequired'))
  assert.ok(src.includes('rates.promotion.fileReadFailed'), 'a local file read failure is its own message')
})
