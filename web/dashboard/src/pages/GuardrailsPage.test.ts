import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// read-only link composition over the EXISTING policy screens — tool-policy,
// rules, label-policy — with no new backend endpoints and no fabricated
// metrics. Like App.navGates.test.ts this fixture is source-level: the page
// is a JSX component the node strip-types harness cannot execute, but the
// decisions it encodes are data (the SURFACES table) and structure (no data
// fetching), and both must stay pinned:
//
//   1. the summary links EXACTLY the three screens the owner named;
//   2. every card's gate mirrors the target screen's NAV_SECTIONS gate in
//      App.tsx (the same table App.navGates.test.ts pins to the server), so
//      the summary cannot drift from the screens it links;
//   3. the page fetches nothing (no effects, no api imports — an honest
//      summary, not a stale duplicate of the screens' data);
//   4. the guardrails copy exists in ALL eight locales (same key set —
//      docs/i18n/glossary.md parity rule).

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = join(here, '..')
const pageSource = readFileSync(join(srcDir, 'pages', 'GuardrailsPage.tsx'), 'utf8')
const appSource = readFileSync(join(srcDir, 'App.tsx'), 'utf8')

const D_R101_1_SURFACES = ['tool-policy', 'rules', 'label-policy', 'guard-packs'] as const

// One SURFACES entry: id, icon, titleKey, descKey, access.
const SURFACE_RE = /id: '([\w-]+)',\s+icon: (\w+),\s+titleKey: '([\w.]+)',\s+descKey: '([\w.]+)',\s+access: \{([^}]*)\}/g

// App.tsx NAV_SECTIONS item line (single-line, same extractor as the
// navGates fixture).
const NAV_ITEM_RE = /^\s*\{ id: '([\w-]+)', labelKey: '([\w.]+)', icon: <\w+ size=\{16\} \/>, access: (\{.+?\}) \},\s*$/

function parseSurfaces(source: string): Array<{ id: string; titleKey: string; descKey: string; rootOnly: boolean; anyOrg: string[] }> {
  const out: Array<{ id: string; titleKey: string; descKey: string; rootOnly: boolean; anyOrg: string[] }> = []
  for (const m of source.matchAll(SURFACE_RE)) {
    out.push({
      id: m[1],
      titleKey: m[3],
      descKey: m[4],
      rootOnly: /rootOnly: true/.test(m[5]),
      anyOrg: (/anyOrg: \[([^\]]*)\]/.exec(m[5])?.[1] ?? '')
        .split(',').map(s => s.trim().replaceAll("'", '')).filter(Boolean),
    })
  }
  return out
}

function parseNavItems(source: string): Record<string, { labelKey: string; rootOnly: boolean; anyOrg: string[] }> {
  const out: Record<string, { labelKey: string; rootOnly: boolean; anyOrg: string[] }> = {}
  for (const line of source.split('\n')) {
    const m = NAV_ITEM_RE.exec(line)
    if (!m) continue
    out[m[1]] = {
      labelKey: m[2],
      rootOnly: /rootOnly: true/.test(m[3]),
      anyOrg: (/anyOrg: \[([^\]]*)\]/.exec(m[3])?.[1] ?? '')
        .split(',').map(s => s.trim().replaceAll("'", '')).filter(Boolean),
    }
  }
  return out
}

function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v !== null && typeof v === 'object'
      ? flatKeys(v as Record<string, unknown>, prefix ? `${prefix}.${k}` : k)
      : [prefix ? `${prefix}.${k}` : k],
  )
}

describe('guardrails summary screen (R101-02, D-R101-1)', () => {
  const surfaces = (() => {
    const parsed = parseSurfaces(pageSource)
    // N02-P08 added the fourth card (detector packs, root-only); the parse
    // count moves with the named list above, never silently.
    assert.equal(parsed.length, 4, `expected 4 SURFACES entries, parsed ${parsed.length}`)
    return parsed
  })()
  const nav = parseNavItems(appSource)

  it('links exactly the policy surfaces the owner named (no more, no fewer)', () => {
    assert.deepEqual(surfaces.map(s => s.id), [...D_R101_1_SURFACES])
  })

  it('every card title is the target screen\u2019s nav labelKey', () => {
    for (const s of surfaces) {
      assert.ok(nav[s.id], `${s.id} is not a NAV_SECTIONS page`)
      assert.equal(s.titleKey, nav[s.id].labelKey,
        `${s.id} card title must reuse the nav labelKey (${nav[s.id].labelKey})`)
    }
  })

  it('every card gate mirrors the target screen\u2019s NAV_SECTIONS gate', () => {
    for (const s of surfaces) {
      const gate = nav[s.id]
      assert.ok(gate, `${s.id} missing from App.tsx NAV_SECTIONS`)
      assert.equal(s.rootOnly, gate.rootOnly, `${s.id} rootOnly drift`)
      assert.deepEqual(s.anyOrg, gate.anyOrg, `${s.id} anyOrg drift`)
    }
  })

  it('fetches nothing: no effects and no api imports (read-only composition)', () => {
    for (const banned of ['useEffect', 'fetchJSON', 'postJSON', 'fetch(', "from '../api", 'from \'../hooks/useShellScope']) {
      assert.ok(!pageSource.includes(banned), `the summary must not contain "${banned}"`)
    }
  })

  it('every guardrails copy key exists in all eight locales (same key set)', () => {
    const locales = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar']
    const bundles = locales.map(l => {
      const raw = JSON.parse(readFileSync(join(srcDir, 'i18n', `${l}.json`), 'utf8')) as Record<string, unknown>
      return [l, raw] as const
    })
    const enKeys = new Set(flatKeys(bundles[0][1].guardrails as Record<string, unknown>, 'guardrails'))
    // The page may only reference keys the en bundle actually has.
    for (const s of surfaces) {
      assert.ok(enKeys.has(s.descKey), `${s.descKey} missing from en.json guardrails`)
      assert.match(s.titleKey, /^app\./, 'card titles resolve through the app namespace')
    }
    for (const [locale, bundle] of bundles) {
      const app = bundle.app as Record<string, unknown>
      assert.equal(typeof app.navGuardrails, 'string', `${locale}.app.navGuardrails missing`)
      assert.notEqual(app.navGuardrails, '', `${locale}.app.navGuardrails empty`)
      const keys = new Set(flatKeys(bundle.guardrails as Record<string, unknown> ?? {}, 'guardrails'))
      assert.deepEqual([...keys].sort(), [...enKeys].sort(),
        `${locale}.guardrails key set drifted from en.json`)
    }
  })
})
