//
// Scans src/**/*.{ts,tsx} (excluding *.test.ts[x]) for literal t('…')/t("…")
// call sites and asserts every referenced key exists in en.json. A key is
// present when the exact key resolves to a non-empty string OR any i18next
// v4 plural variant (key_zero/one/two/few/many/other) exists — a call like
// t('chart.rows', { count }) may resolve through suffixes alone.
//
// Calls whose first argument is not fully literal (variables, template
// interpolations, ternaries with a non-literal branch) cannot be verified
// statically. Every file containing such calls must be listed in
// DYNAMIC_ALLOWLIST with a one-line reason; the set must match exactly, so
// the list cannot rot: a file that gains or drops dynamic keys both fail
// this gate and the entry must be added or removed in the same change.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const SRC_DIR = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '')
const EN = JSON.parse(readFileSync(new URL('../i18n/en.json', import.meta.url), 'utf8')) as Record<string, unknown>

const PLURAL_SUFFIXES = ['zero', 'one', 'two', 'few', 'many', 'other'] as const

// Exact set of files with non-static t() first arguments. Key = path relative
// to src/, value = why the keys there cannot be literal.
const DYNAMIC_ALLOWLIST: Record<string, string> = {
  'pages/budgets/CapsStatusSection.tsx': 'cap labelKey from the CAP_LABELS map over the server\'s closed cap-id vocabulary (usd_monthly_budget / carbon_monthly_grams / credits_floor, currencies brief §6.2) + status key budgets.capsStatus.status.<status> over the closed ok/near/over/unknown set',
  'pages/budgets/UnitsSpendSection.tsx': 'family/fidelity labelKey maps over the server\'s closed adminstore vocabularies (money/resource/impact, exact/estimated/simulated/unknown, currencies brief §6.1) + the coverage-note key list built from the rollup counts',
  'App.tsx': 'nav section / breadcrumb labelKey fields from the navigation registry',
  'components/shell/Breadcrumbs.tsx': 'section/page labelKey passed as props from the navigation registry (IMP-31)',
  'components/shell/Sidebar.tsx': 'nav section/item labelKey fields from the access-filtered sections (IMP-31)',
  'components/shell/UserMenu.tsx': 'locale endonym labels resolved through a lookup map (IMP-31)',
  'components/astra/BoardPanelCard.tsx': 'board panel titleKey/descKey fields and analytics.metric.* fallbacks per panel',
  'components/astra/EvidenceLabel.tsx': 'evidence tier / signature status resolved through lookup maps',
  'components/astra/FilterBar.tsx': 'YQL token hints rendered via t(k) over a token list',
  'components/astra/FreshnessControl.tsx': 'freshness window option labelKey from the options list',
  'components/astra/SignalInbox.tsx': 'signal severity / messageKey / linkKey fields from the API payload',
  'components/astra/StateNotice.tsx': 'state descriptor titleKey from the states map',
  'lib/analyticsSummary.ts': 'metric labelKey from the metric registry',
  'lib/pricingCoverage.ts': 'note keys composed from the cost/overview copy namespace parameter',
  'pages/AnalyticsExplorerPage.tsx': 'metric/dim/gran/chartKind/group keys built from runtime column names; saved-question titleKey',
  'pages/DashboardsPage.tsx': 'board and panel titleKey fields from board definitions',
  'pages/GuardrailsPage.tsx': 'surface titleKey/descKey fields and the access-reason key from the SURFACES registry',
  'pages/LineagePage.tsx': 'evidence key passed through the evidenceText helper',
  'pages/McpCredentialsPage.tsx': 'validation problem keys composed from the buildHeadersPayload/buildOauthPayload problem value',
  'pages/OrgSettingsPage.tsx': 'settings tab labels from the TAB_LABEL_KEYS map',
  'pages/RequestExplorerPage.tsx': 'evidence tier keys from the EXPLORER_EVIDENCE_KEYS map',
  'pages/TasksPage.tsx': 'tasks.group_${groupBy} keys built from the runtime groupBy value',
  'components/astra/RoutingGraph.tsx': 'warning-code / node-kind / edge-kind / lane-band label keys from the WARN_KEY / NODE_KIND_KEY / EDGE_KIND_KEY / BAND_KEY lookup maps over the server\'s closed code and kind vocabularies (CV-01)',
}

type Ctx = { kind: 'top' } | { kind: 'tplExpr'; depth: number }

// Blank out comment bodies while staying string-aware (a `//` inside a URL
// template literal must not truncate the scan). Newlines are preserved so
// reported line numbers stay accurate.
function stripComments(src: string): string {
  const out = src.split('')
  const ctx: Ctx[] = [{ kind: 'top' }]
  let mode: 'code' | 'sq' | 'dq' | 'tpl' = 'code'
  let i = 0
  const n = src.length
  while (i < n) {
    const c = src[i]
    if (mode === 'code') {
      const top = ctx[ctx.length - 1]
      if (c === '/' && src[i + 1] === '/') {
        while (i < n && src[i] !== '\n') { out[i] = ' '; i++ }
      } else if (c === '/' && src[i + 1] === '*') {
        out[i] = ' '; out[i + 1] = ' '; i += 2
        while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
          if (src[i] !== '\n') out[i] = ' '
          i++
        }
        if (i < n) { out[i] = ' '; out[i + 1] = ' '; i += 2 }
      } else if (c === "'") { mode = 'sq'; i++ } else if (c === '"') { mode = 'dq'; i++ } else if (c === '`') { mode = 'tpl'; i++ } else if (c === '(' || c === '[' || c === '{') {
        if (top.kind === 'tplExpr') top.depth++
        i++
      } else if (c === ')' || c === ']') {
        if (top.kind === 'tplExpr') top.depth--
        i++
      } else if (c === '}') {
        if (top.kind === 'tplExpr' && top.depth === 0) { ctx.pop(); mode = 'tpl' } else if (top.kind === 'tplExpr') top.depth--
        i++
      } else i++
    } else if (mode === 'sq' || mode === 'dq') {
      if (c === '\\') i += 2
      else if ((mode === 'sq' && c === "'") || (mode === 'dq' && c === '"')) { mode = 'code'; i++ } else i++
    } else {
      if (c === '\\') i += 2
      else if (c === '`') { mode = 'code'; i++ } else if (c === '$' && src[i + 1] === '{') { ctx.push({ kind: 'tplExpr', depth: 0 }); mode = 'code'; i += 2 } else i++
    }
  }
  return out.join('')
}

// Read a quoted string literal at position i. Returns the raw inner text and
// the position after the closing quote, or null.
function readLiteral(src: string, i: number): { inner: string; end: number } | null {
  const quote = src[i]
  if (quote !== "'" && quote !== '"') return null
  let j = i + 1
  let inner = ''
  while (j < src.length) {
    const c = src[j]
    if (c === '\\') { inner += src[j + 1] ?? ''; j += 2; continue }
    if (c === quote) return { inner, end: j + 1 }
    inner += c
    j++
  }
  return null
}

// Shared bracket/quote walker state: `depth` counts ()[]{} in plain code,
// `expr` stacks the nesting inside active template ${…} expressions.
// Returns the top-level delimiter index, or -1.
function walk(
  src: string,
  start: number,
  onCode: (c: string, depth: number, inExpr: boolean) => 'stop' | void,
): number {
  const expr: { depth: number }[] = []
  let depth = 0
  let mode: 'code' | 'sq' | 'dq' | 'tpl' = 'code'
  let i = start
  while (i < src.length) {
    const c = src[i]
    if (mode === 'code') {
      if (c === "'") mode = 'sq'
      else if (c === '"') mode = 'dq'
      else if (c === '`') mode = 'tpl'
      else if (c === '(' || c === '[' || c === '{') { if (expr.length > 0) expr[expr.length - 1].depth++; else depth++ } else if (c === ')' || c === ']') {
        if (expr.length > 0) expr[expr.length - 1].depth--
        else if (depth === 0) {
          if (onCode(c, depth, false) === 'stop') return i
          return -1
        } else depth--
      } else if (c === '}') {
        const top = expr[expr.length - 1]
        if (top && top.depth === 0) { expr.pop(); mode = 'tpl' } else if (top) top.depth--
        else if (depth > 0) depth--
        else {
          if (onCode(c, depth, false) === 'stop') return i
          return -1
        }
      } else if (c === ',' && depth === 0 && expr.length === 0) {
        if (onCode(c, depth, false) === 'stop') return i
      } else if (c === '?') {
        if (src[i + 1] === '?' || src[i + 1] === '.') i++
        else if (onCode('?', depth, expr.length > 0) === 'stop') return i
      } else if (onCode(c, depth, expr.length > 0) === 'stop') {
        return i
      }
      i++
    } else if (mode === 'sq' || mode === 'dq') {
      if (c === '\\') i += 2
      else { if ((mode === 'sq' && c === "'") || (mode === 'dq' && c === '"')) mode = 'code'; i++ }
    } else {
      if (c === '\\') i += 2
      else if (c === '`') mode = 'code'
      else if (c === '$' && src[i + 1] === '{') { expr.push({ depth: 0 }); mode = 'code'; i += 2 } else i++
    }
  }
  return -1
}

// Split the first argument off a t( call starting right after the open paren.
// Returns null when the call itself is malformed (unbalanced).
function firstArg(src: string, start: number): { arg: string; end: number } | null {
  let end = -1
  const at = walk(src, start, c => {
    if (c === ')' || c === ',') { end = c === ')' ? 1 : 0; return 'stop' }
  })
  if (at < 0 || end < 0) return null
  return { arg: src.slice(start, at), end: at + 1 }
}

type Parsed = { keys: string[]; rest: string }

// Parse a t() first argument into literal keys, or null when any part of the
// expression is not a plain '…'/"…" literal (possibly combined with ? :).
function parseKeys(expr: string): Parsed | null {
  const s = expr.trim()
  const lit = readLiteral(s, 0)
  if (lit) {
    const rest = s.slice(lit.end).trim()
    if (rest === '' || rest.startsWith(',')) return { keys: [lit.inner], rest }
    return null
  }
  // Ternary of literals: cond ? 'a' : 'b' (nested ternaries allowed).
  const q = topLevel(s, '?')
  if (q < 0) return null
  const cond = s.slice(0, q).trim()
  if (!/^[\w$][\w$.]*$/.test(cond)) return null
  const restAll = s.slice(q + 1)
  const colon = topLevel(restAll, ':')
  if (colon < 0) return null
  const left = parseKeys(restAll.slice(0, colon))
  const right = parseKeys(restAll.slice(colon + 1))
  if (!left || !right) return null
  if (left.rest !== '' || right.rest !== '') return null
  return { keys: [...left.keys, ...right.keys], rest: '' }
}

// Position of the first top-level ?: / : outside strings and brackets.
// `?.` and `??` are skipped by the walker; only conditional operators match.
function topLevel(s: string, which: '?' | ':'): number {
  return walk(s, 0, c => (c === which ? 'stop' : undefined))
}

function resolveKey(key: string): unknown {
  let v: unknown = EN
  for (const part of key.split('.')) {
    if (v === null || typeof v !== 'object') return undefined
    v = (v as Record<string, unknown>)[part]
  }
  return v
}

function keyExists(key: string): boolean {
  const direct = resolveKey(key)
  if (typeof direct === 'string' && direct.length > 0) return true
  return PLURAL_SUFFIXES.some(suf => {
    const v = resolveKey(`${key}_${suf}`)
    return typeof v === 'string' && v.length > 0
  })
}

function listSourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = `${dir}/${name.name}`
    if (name.isDirectory()) out.push(...listSourceFiles(full))
    else if (/\.(ts|tsx)$/.test(name.name) && !/\.test\.tsx?$/.test(name.name) && !name.name.endsWith('.d.ts')) out.push(full)
  }
  return out
}

type Site = { file: string; line: number; keys: string[] }

function scan(): { literal: Site[]; dynamic: Map<string, string[]> } {
  const literal: Site[] = []
  const dynamic = new Map<string, string[]>()
  for (const full of listSourceFiles(SRC_DIR)) {
    const rel = full.slice(SRC_DIR.length + 1)
    const cleaned = stripComments(readFileSync(full, 'utf8'))
    const call = /\bt\s*\(/g
    for (let m = call.exec(cleaned); m; m = call.exec(cleaned)) {
      const argStart = m.index + m[0].length
      const arg = firstArg(cleaned, argStart)
      if (!arg) continue
      const parsed = parseKeys(arg.arg)
      const line = cleaned.slice(0, m.index).split('\n').length
      if (parsed) literal.push({ file: rel, line, keys: parsed.keys })
      else {
        const sites = dynamic.get(rel) ?? []
        sites.push(`${rel}:${line}`)
        dynamic.set(rel, sites)
      }
    }
  }
  return { literal, dynamic }
}

test('every literal t() key exists in en.json (plural suffixes accepted)', () => {
  const { literal, dynamic } = scan()
  const missing = new Map<string, string[]>()
  for (const site of literal) {
    for (const key of site.keys) {
      if (!keyExists(key)) {
        const at = missing.get(key) ?? []
        if (at.length < 3) at.push(`${site.file}:${site.line}`)
        missing.set(key, [...at])
      }
    }
  }
  const lines = [...missing.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([key, at]) => `  ${key}  ←  ${at.join(', ')}`)
  const dynNote = dynamic.size > 0 ? `\n  (${dynamic.size} file(s) also have dynamic t() calls — see the allowlist test)` : ''
  assert.equal(lines.length, 0, `missing i18n keys in src/i18n/en.json:\n${lines.join('\n')}${dynNote}`)
})

test('files with dynamic t() first arguments match DYNAMIC_ALLOWLIST exactly', () => {
  const { dynamic } = scan()
  const found = [...dynamic.keys()].sort()
  const listed = Object.keys(DYNAMIC_ALLOWLIST).sort()
  const unlisted = found.filter(f => !DYNAMIC_ALLOWLIST[f])
  const stale = listed.filter(f => !dynamic.has(f))
  const detail = [
    ...unlisted.map(f => `  not allowlisted: ${f}\n    call sites: ${(dynamic.get(f) ?? []).join(', ')}\n    → add an entry to DYNAMIC_ALLOWLIST (or make the keys literal)`),
    ...stale.map(f => `  stale allowlist entry: ${f} — ${DYNAMIC_ALLOWLIST[f]}\n    → remove the entry (the file no longer has dynamic t() calls)`),
  ]
  assert.equal(detail.length, 0, `DYNAMIC_ALLOWLIST out of sync:\n${detail.join('\n')}`)
})

// ---------------------------------------------------------------------------
// Cross-locale parity gate.
//
// The tests above prove that src references resolve in en.json; they say
// nothing about the seven resource locales — which is exactly how
// prompts.reloadConflict/versionConflict/versionRequired drifted (en gained
// the keys, the translations never followed, and no gate noticed).
//
// `en` is the canonical bundle: every leaf key in en.json must resolve in each
// resource locale, MODULO i18next v4 CLDR plural categories. A plural family
// (`<base>_<suffix>`) only needs ONE variant present per locale — ja/ko/id
// have no "one" category, es/pt-BR additionally have "many", ar carries the
// full zero/one/two/few/many/other set — so a raw key-set diff would
// false-fail on ~10–50 keys per locale. A non-plural key must exist exactly.
// Extra locale-side variants with no en counterpart (e.g. ar `_few` where en
// has only `_other`) are CLDR-legal and are not checked.
//
// The second test rejects the structural residue class the audit surfaced:
// a top-level key that duplicates a `<ns>.<key>` name inside an existing
// namespace group (the stray top-level `routingMap` copies were exactly
// this — dead, yet inflating the canonical key set and poisoning
// every naive parity diff, which hid the real key drift behind pure
// noise). Top-level scalars belong in a namespace; bare copies are residue.

const PARITY_LOCALES = ['ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar'] as const

// Keep in sync with LOCALES in ./index.ts: every resource locale on disk must
// be covered here, and every name here must have a <locale>.json resource.
const DISK_BUNDLES = readdirSync(new URL('.', import.meta.url), { withFileTypes: true })
  .map(e => e.name)
  .filter(n => n.endsWith('.json'))
  .map(n => n.slice(0, -'.json'.length))
  .sort()

function loadBundleFor(loc: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(`../i18n/${loc}.json`, import.meta.url), 'utf8'))
}

// Dotted leaf paths of a nested bundle (all leaves; every value is a string).
function flattenLeaves(obj: unknown, prefix = ''): string[] {
  const out: string[] = []
  if (obj !== null && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out.push(...flattenLeaves(v, prefix ? `${prefix}.${k}` : k))
    }
  } else {
    out.push(prefix)
  }
  return out
}

test('parity gate covers exactly the locale bundles on disk (en + 7 resources)', () => {
  const expected = ['en', ...PARITY_LOCALES].sort()
  assert.deepEqual(
    DISK_BUNDLES,
    expected,
    'i18n/*.json files and the parity locale list diverged — update PARITY_LOCALES (and ./index.ts) together',
  )
})

test('every en.json key resolves in each resource locale (modulo CLDR plural categories)', () => {
  const enKeys = flattenLeaves(EN)
  const lines: string[] = []
  for (const loc of PARITY_LOCALES) {
    const have = new Set(flattenLeaves(loadBundleFor(loc)))
    for (const key of enKeys) {
      const fam = key.match(/_(zero|one|two|few|many|other)$/)
      const ok = fam
        ? PLURAL_SUFFIXES.some(s => have.has(`${key.slice(0, -fam[0].length)}_${s}`))
        : have.has(key)
      if (!ok) lines.push(`  ${loc}: ${key}`)
    }
  }
  assert.equal(
    lines.length,
    0,
    `resource locales are missing keys present in en.json:\n${lines.join('\n')}`,
  )
})

test('no locale has a top-level key that duplicates a namespaced key (residue guard)', () => {
  const lines: string[] = []
  for (const loc of ['en', ...PARITY_LOCALES] as const) {
    const leaves = flattenLeaves(loadBundleFor(loc))
    const namespaced = leaves.filter(k => k.includes('.'))
    for (const top of leaves.filter(k => !k.includes('.'))) {
      const dupes = namespaced.filter(k => k.endsWith(`.${top}`))
      if (dupes.length > 0) lines.push(`  ${loc}: "${top}" also exists as ${dupes.join(', ')}`)
    }
  }
  assert.equal(
    lines.length,
    0,
    `top-level keys duplicating namespace-group keys (translate under the namespace, delete the bare copy):\n${lines.join('\n')}`,
  )
})
