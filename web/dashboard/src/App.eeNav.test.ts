import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// D-UI-2 (owner decision 2026-11-06): the dashboard nav carries a STATIC
// Enterprise section — every item rendered locked (grey + lock), never
// hidden, all linking to the EE app root /ee/ (A2 minimal core seam; the
// UI-BOUNDARY approach-A research §2-A2 + verdict named the surfaces).
//
// Why source-level: App.tsx/Sidebar.tsx are JSX the node strip-types
// harness cannot execute (same reason as App.navGates.test.ts). The
// decisions this fixture pins are data (the EE item table) and structure
// (locked rendering, aria pattern, locale copy), and both must stay put:
//
//   1. the EE section is exactly the pinned placeholder list, every item
//      locked with href /ee/;
//   2. core NEVER decides entitlement: EE items carry no access gate, sit
//      OUTSIDE the navGates-pinned NAV_SECTIONS table, are not Page ids and
//      never enter the command palette — and the no-entitlement contract is
//      documented in the source (the comment this test anchors);
//   3. the section rides along unfiltered (never hidden, D-UI-2);
//   4. Sidebar renders locked items as focusable anchors (no dead buttons):
//      aria-disabled + the muted-ink grey + the lock icon + the explanatory
//      tooltip (design standard §9 Disabled: readable label + reason);
//   5. the six EE copy keys exist in ALL eight locales (parity rule,
//      docs/i18n/glossary.md).

const here = dirname(fileURLToPath(import.meta.url))
const appSource = readFileSync(join(here, 'App.tsx'), 'utf8')
const sidebarSource = readFileSync(join(here, 'components', 'shell', 'Sidebar.tsx'), 'utf8')

const LOCALES = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar'] as const
const EE_KEYS = [
  'app.sectionEnterprise',
  'app.navEeIdentity',
  'app.navEeThreatPosture',
  'app.navEeLoopRuns',
  'app.navEeSettings',
  'app.navEeLocked',
] as const

type EEItem = { id: string; labelKey: string; icon: string; href: string; locked: boolean; hasAccessGate: boolean }

const EXPECTED_EE_ITEMS = [
  { id: 'ee-identity', labelKey: 'app.navEeIdentity' },
  { id: 'ee-threat-posture', labelKey: 'app.navEeThreatPosture' },
  { id: 'ee-loop-runs', labelKey: 'app.navEeLoopRuns' },
  { id: 'ee-settings', labelKey: 'app.navEeSettings' },
] as const

// One EE_NAV_SECTION item line (kept on a single line, same convention the
// navGates fixture pins for NAV_SECTIONS lines).
const EE_ITEM_LINE = /^\s*\{ id: '(ee-[\w-]+)', labelKey: '([\w.]+)', icon: <(\w+) size=\{16\} \/>, href: '([^']+)', locked: (true|false) \},?\s*$/

function parseEeSection(source: string): { labelKey: string; items: EEItem[] } {
  const start = source.indexOf('const EE_NAV_SECTION')
  assert.ok(start > -1, 'EE_NAV_SECTION not found in App.tsx')
  const end = source.indexOf('\n}', start)
  assert.ok(end > start, 'EE_NAV_SECTION body not terminated')
  const body = source.slice(start, end)
  const label = /labelKey: '([\w.]+)'/.exec(body)
  assert.ok(label, 'EE section labelKey not found')
  const items: EEItem[] = []
  for (const line of body.split('\n')) {
    const m = EE_ITEM_LINE.exec(line)
    if (!m) continue
    items.push({
      id: m[1],
      labelKey: m[2],
      icon: m[3],
      href: m[4],
      locked: m[5] === 'true',
      hasAccessGate: /access:/.test(line),
    })
  }
  return { labelKey: label[1], items }
}

describe('Enterprise nav section (D-UI-2 static grey-with-lock seam)', () => {
  const ee = parseEeSection(appSource)

  it('the section is exactly the pinned placeholder list, every item locked at /ee/', () => {
    assert.equal(ee.labelKey, 'app.sectionEnterprise')
    assert.deepEqual(
      ee.items.map(i => ({ id: i.id, labelKey: i.labelKey })),
      EXPECTED_EE_ITEMS.map(i => ({ id: i.id, labelKey: i.labelKey })),
      'the EE placeholder table drifted — update this pin and the locale bundles together',
    )
    for (const item of ee.items) {
      assert.equal(item.href, '/ee/', `${item.id}: every v1 EE item points at the EE app root (it owns real routing)`)
      assert.equal(item.locked, true, `${item.id}: D-UI-2 requires EVERY EE item locked in core v1`)
      assert.ok(item.icon, `${item.id}: an icon from the existing lucide set is required`)
    }
    assert.ok(ee.items.length >= 3 && ee.items.length <= 4, 'the dispatch allows 3-4 placeholder items')
  })

  it('core NEVER decides entitlement: no access gate, outside NAV_SECTIONS, not a Page, not a palette command', () => {
    // 0 entitlement logic: EE items carry no NavAccess gate at all.
    for (const item of ee.items) {
      assert.equal(item.hasAccessGate, false, `${item.id}: an access gate on an EE item is entitlement logic in core`)
    }
    // The gate table the navGates fixture pins must stay untouched by EE.
    const navStart = appSource.indexOf('const NAV_SECTIONS')
    const navEnd = appSource.indexOf('\n]', navStart)
    const navBody = appSource.slice(navStart, navEnd)
    assert.ok(!/ee-/.test(navBody), 'EE ids must not leak into NAV_SECTIONS (they are not pages)')
    // Not hash routes: EE ids must not join the Page union (readPage would
    // otherwise seat the SPA router on an external app).
    const pageType = appSource.slice(appSource.indexOf('type Page ='), appSource.indexOf('type NavAccess'))
    assert.ok(!/ee-/.test(pageType), 'EE ids must not be Page ids — /ee/ is a separate app, not a hash route')
    // The no-entitlement contract stays documented at the seam.
    const eeComment = appSource.slice(appSource.indexOf('D-UI-2 (owner decision 2026-11-06)'), appSource.indexOf('const EE_NAV_SECTION'))
    assert.ok(/never decides entitlement/.test(eeComment)
      && /NO runtime/.test(eeComment)
      && /entitlement detection/.test(eeComment),
      'the EE seam must keep the one-liner: static always-locked in core, the EE app at /ee/ shows the live state')
  })

  it('never hidden: the section rides along unfiltered after the access-gated sections', () => {
    // D-UI-2: EE items are shown GREY WITH LOCK, never hidden — the memo
    // must append EE_NAV_SECTION without passing it through navVisible.
    const memoOk = /useMemo<NavSectionView\[\]>\s*\(\s*\(\)\s*=>\s*\[\s*\.\.\.NAV_SECTIONS[\s\S]*?EE_NAV_SECTION,/.test(appSource)
    assert.ok(memoOk, 'visibleSections must append EE_NAV_SECTION (unfiltered) — hiding it would violate D-UI-2')
  })

  it('locked rendering: focusable anchor, aria-disabled, grey token, lock icon, tooltip', () => {
    // The anchor (not a dead button): href + aria-disabled + title tooltip.
    const anchorOk = sidebarSource.includes('href={item.href}')
      && sidebarSource.includes('aria-disabled="true"')
      && sidebarSource.includes("title={t('app.navEeLocked')}")
    assert.ok(anchorOk, 'locked items must render as <a href={item.href}> with aria-disabled and the explanatory title')
    // Keyboard reachable: no negative tabIndex anywhere in the locked branch.
    assert.ok(!/tabIndex=\{-1\}/.test(sidebarSource), 'locked items stay keyboard-focusable (Enter navigates to /ee/)')
    // Grey = the muted ink token (no new colors; lint-design holds the line).
    assert.ok(/text-\[color:var\(--astra-text-muted\)\]/.test(sidebarSource), 'locked items grey via the existing muted ink token')
    // The lock marker comes from the existing icon set.
    assert.ok(/import \{ ChevronDown, Lock, Search \} from 'lucide-react'/.test(sidebarSource), 'the Lock icon import must stay')
    assert.ok(/<Lock size=\{14\}/.test(sidebarSource), 'the lock marker must render on locked items')
    // Interactive target size shared with the other nav items.
    assert.ok(/min-h-\[44px\]/.test(sidebarSource), 'nav interactive targets stay >=44px')
  })

  it('every EE copy key exists and is non-empty in ALL eight locales', () => {
    for (const loc of LOCALES) {
      const bundle = JSON.parse(readFileSync(join(here, 'i18n', `${loc}.json`), 'utf8')) as { app?: Record<string, string> }
      const app = bundle.app ?? {}
      for (const key of EE_KEYS) {
        const leaf = key.slice('app.'.length)
        assert.equal(typeof app[leaf], 'string', `${loc}: ${key} missing`)
        assert.ok((app[leaf] ?? '').trim().length > 0, `${loc}: ${key} is empty`)
      }
    }
  })
})
