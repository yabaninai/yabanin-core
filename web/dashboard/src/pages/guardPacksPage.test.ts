import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

// N02-P08 (T02/T06): source-level pins for GuardPacksPage.tsx (a .tsx the
// node harness cannot render) plus the edition-honesty pins:
//
//   - the full G0–G6 UI chain is present as distinct, assertable stages
//     (list → validate → simulate → activate/rollback → runtime status →
//     journal), each with stable testids the browser spec drives;
//   - the negative states render the SERVER's own message (404 / 409 with
//     the live durable state / store failure / unwired);
//   - the runtime strip names the DURABLE requested version — the page never
//     claims an applied version or a watcher-failure count it cannot know;
//   - edition honesty: the free BYO cycle carries NO paywall vocabulary in
//     any locale (PRODUCT-CONTRACT: no invented gated capability);
//   - i18n: the guardPacks key set is identical across all eight locales.

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = join(here, '..')
const pageSource = readFileSync(join(srcDir, 'pages', 'GuardPacksPage.tsx'), 'utf8')
const modelSource = readFileSync(join(srcDir, 'pages', 'guardPacksModel.ts'), 'utf8')
const LOCALES = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar'] as const

function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v !== null && typeof v === 'object'
      ? flatKeys(v as Record<string, unknown>, prefix ? `${prefix}.${k}` : k)
      : [prefix ? `${prefix}.${k}` : k],
  )
}

function load(locale: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(srcDir, 'i18n', `${locale}.json`), 'utf8')) as Record<string, unknown>
}

describe('guard packs page structure (N02-P08 UI chain)', () => {
  it('delegates decisions to the pinned model (no inline re-derivation)', () => {
    for (const fn of ['guardPackErrorView', 'activePackDir', 'statusView(', 'filterGuardPackJournal', 'packRows(']) {
      assert.ok(pageSource.includes(fn), `the page must use the model helper ${fn}`)
    }
    assert.ok(modelSource.includes("import type { AuditLogEntry } from '../api/audit.ts'"),
      'the journal filter types against the shared audit contract')
  })

  it('every chain stage has a stable testid for the browser spec', () => {
    for (const id of [
      'guardpacks-status', 'guardpacks-status-active', 'guardpacks-status-loadable',
      'guardpacks-packs', 'guardpacks-validate-', 'guardpacks-activate-',
      'guardpacks-simulate', 'guardpacks-sample-input', 'guardpacks-simulate-run',
      'guardpacks-rollback', 'guardpacks-outcome-activated', 'guardpacks-outcome-error',
      'guardpacks-outcome-conflict-state', 'guardpacks-journal-entries', 'guardpacks-journal-link',
    ]) {
      assert.ok(pageSource.includes(id), `missing testid ${id}`)
    }
  })

  it('mutations refresh the durable view (activate → list+status refetch)', () => {
    assert.ok(pageSource.includes('await refresh()'),
      'after activate/rollback the page must re-read the durable state')
  })

  it('failure states render the server message verbatim (no invented success)', () => {
    assert.ok(pageSource.includes('{outcome.view.serverMessage}'),
      'the error panel shows the API’s own message')
  })
})

describe('edition honesty (PRODUCT-CONTRACT: free BYO cycle, no paywall copy)', () => {
  it('no paywall vocabulary in the page or in any guardPacks/guardrails locale block', () => {
    // Line comments are stripped so this test's own vocabulary does not
    // trip the scan; string literals and copy are what must stay clean.
    const codeOnly = pageSource.split('\n').filter(l => !l.trim().startsWith('//')).join('\n')
    const sources = [codeOnly]
    for (const locale of LOCALES) {
      const bundle = load(locale)
      sources.push(JSON.stringify({ guardPacks: bundle.guardPacks, guardrails: bundle.guardrails }))
    }
    const banned = ['upgrade', 'upsell', 'paid plan', 'paywall', 'subscription', 'enterprise plan', 'premium tier']
    for (const src of sources) {
      const lower = src.toLowerCase()
      for (const word of banned) {
        assert.ok(!lower.includes(word), `paywall vocabulary "${word}" must not appear in the guard-pack surface`)
      }
    }
  })

  it('the runtime strip claims the durable requested state, never an applied version', () => {
    const en = (load('en').guardPacks ?? {}) as Record<string, unknown>
    assert.equal(en.statusActive, 'Requested active version',
      'the strip must name the DURABLE requested version (the admin cannot know replica-applied versions)')
    const keys = flatKeys(en)
    for (const key of keys) {
      assert.ok(!/applied/i.test(key) && !/failure_?count|watch_?failures/i.test(key),
        `fabricated telemetry key not allowed: ${key}`)
    }
  })
})

describe('guard packs i18n parity (eight locales, one key set)', () => {
  const enBundle = load('en')
  const enKeys = new Set(flatKeys(enBundle.guardPacks as Record<string, unknown>, 'guardPacks')).add('app.navGuardPacks').add('guardrails.packsDesc')

  it('every locale carries exactly the en key set', () => {
    for (const locale of LOCALES) {
      const bundle = load(locale)
      const keys = new Set(flatKeys((bundle.guardPacks ?? {}) as Record<string, unknown>, 'guardPacks'))
      keys.add('app.navGuardPacks').add('guardrails.packsDesc')
      assert.deepEqual([...keys].sort(), [...enKeys].sort(), `${locale}.guardPacks key set drifted from en.json`)
      assert.equal(typeof (bundle.app as Record<string, unknown>).navGuardPacks, 'string', `${locale}.app.navGuardPacks missing`)
      assert.notEqual((bundle.app as Record<string, unknown>).navGuardPacks, '', `${locale}.app.navGuardPacks empty`)
    }
  })

  it('every errorKind key exists in en (all six honest failure kinds)', () => {
    for (const kind of ['notFound', 'conflict', 'conflictState', 'storeFailure', 'unwired', 'http']) {
      assert.ok(enKeys.has(`guardPacks.errorKind.${kind}`), `guardPacks.errorKind.${kind} missing from en.json`)
    }
  })

  it('non-empty everywhere: no locale ships a blank guardPacks string', () => {
    for (const locale of LOCALES) {
      const bundle = load(locale)
      const block = (bundle.guardPacks ?? {}) as Record<string, unknown>
      for (const key of flatKeys(block)) {
        const value = key.split('.').reduce<unknown>((acc, part) => (acc as Record<string, unknown>)?.[part], block)
        assert.equal(typeof value, 'string', `${locale}.guardPacks.${key} must be a string`)
        assert.ok((value as string).length > 0, `${locale}.guardPacks.${key} is empty`)
      }
    }
  })
})
