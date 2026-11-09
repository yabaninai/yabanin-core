// node strip-types harness — the GuardrailsPage.test.ts way). What must
// stay pinned:
//
//   1. YAML editing happens through a textarea whose validation is
//      SERVER-SIDE: the page surfaces the 400 body verbatim (role=alert)
//      and adds no local YAML opinion;
//   2. every mutation rides the single PUT verb through api/policyPipelines
//      — activate/rollback send { active_version } (the only "version
//      field" the API has), draft saves send { yaml };
//   3. the stale-edit guard runs before the PUTs (baseline re-read +
//      field-scoped compare) and blocks with an explicit refresh action;
//   4. the confirm dialog names the target version (was → becomes);
//   5. the preview points at the decisions log filtered by this policy
//      (deep link carries org + policy params);
//   6. every policyEditor.* copy key exists in all eight locales;
//   7. STRICT VALIDATE BEFORE SAVE (owner decision 2026-11-04 (a)): both
//      mutation paths (draft save, create) call the validate endpoint
//      FIRST and skip the mutation on any validation failure — an
//      unparseable document never reaches the store, fail-closed;
//   8. the org drift report is SHOWN (owner decision 2026-11-04 (b)):
//      a drift panel with per-policy status and a refresh, refreshed after
//      mutations so a UI edit past git flips its row immediately.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = join(here, '..')
const pageSource = readFileSync(join(srcDir, 'pages', 'PolicyEditorPage.tsx'), 'utf8')
const decisionsSource = readFileSync(join(srcDir, 'pages', 'PolicyDecisionsPage.tsx'), 'utf8')
const appSource = readFileSync(join(srcDir, 'App.tsx'), 'utf8')

describe('editor structure (R070-02)', () => {
  it('YAML editing is a textarea; validation errors surface verbatim', () => {
    assert.ok(pageSource.includes('data-testid="policy-editor-yaml-input"'), 'the textarea exists')
    assert.match(pageSource, /<textarea[^>]*[\s\S]*?rows=/, 'a real multiline editing surface')
    assert.ok(pageSource.includes('role="alert"') && pageSource.includes('policyValidationErrorText'),
      'the server 400 body renders at the block through the validation helper')
    for (const banned of ['kind: Policy\'', 'apiVersion', 'steps:', 'js-yaml', 'yaml.parse']) {
      assert.ok(!pageSource.includes(banned), `the editor must not add a local YAML opinion ("${banned}")`)
    }
  })

  it('N16-P01-T02 (a): strict validate runs BEFORE the draft save and the create', () => {
    // The arbiter endpoint is the SAME validation the store path runs — a
    // draft save validates first and skips the PUT on failure (fail-closed:
    // a transport failure also blocks, with an explicit message).
    const save = pageSource.match(/const saveDraft = useCallback\(\(\) => \{[\s\S]*?\n {2}\}, \[[^\]]*\]\)/)
    assert.ok(save, 'saveDraft is locatable')
    assert.ok(save[0].includes('await validatePolicyDoc(org, yamlText)'), 'the draft save validates the buffer first')
    assert.ok(save[0].indexOf('validatePolicyDoc') < save[0].indexOf('updatePolicy'), 'validate precedes the PUT')
    assert.ok(save[0].includes("setValidationError(serverMessage || t('policyEditor.validateFailed')"),
      'a validation failure (server text or transport) blocks the save with a message')
    const create = pageSource.match(/const submitCreate = useCallback\(\(e: React\.FormEvent\) => \{[\s\S]*?\n {2}\}, \[[^\]]*\]\)/)
    assert.ok(create, 'submitCreate is locatable')
    assert.ok(create[0].includes('await validatePolicyDoc(org, newYaml)'), 'the create validates the new yaml first')
    assert.ok(create[0].indexOf('validatePolicyDoc') < create[0].indexOf('createPolicy'), 'validate precedes the create call')
  })

  it('N16-P01-T02 (b): the org drift report is shown and refreshed after mutations', () => {
    assert.ok(pageSource.includes('getPolicyDrift'), 'the drift report is fetched')
    assert.ok(pageSource.includes('data-testid="policy-editor-drift"'), 'the drift panel exists')
    assert.ok(pageSource.includes('data-testid="policy-editor-drift-summary"'), 'the org drift count renders')
    assert.ok(pageSource.includes('data-testid="policy-editor-drift-refresh"'), 'drift has an explicit refresh')
    // All three server statuses get a label; the drift one renders danger.
    for (const key of ['policyEditor.driftStatusManaged', 'policyEditor.driftStatusDrift', 'policyEditor.driftStatusUnmanaged']) {
      assert.ok(pageSource.includes(`t('${key}')`), `${key} must render`)
    }
    assert.match(pageSource, /entry\.status === 'drift'[\s\S]*?var\(--astra-danger\)/,
      'the drift status is styled as an incident, not as a healthy state')
    // Refreshed after save/activate/toggle so a UI edit flips its row.
    const driftCalls = pageSource.match(/void loadDrift\(\)/g) ?? []
    assert.ok(driftCalls.length >= 3, 'drift refreshes after the draft save and both confirm actions')
  })

  it('activate/rollback and draft saves ride the single PUT verb', () => {
    assert.ok(pageSource.includes("from '../api/policyPipelines'"))
    assert.ok(pageSource.includes('active_version: version, version:'), 'activate/rollback PUT the target + the concurrency token')
    assert.ok(pageSource.includes('yaml: yamlText, version:'), 'a draft save PUTs the yaml + the concurrency token')
    assert.ok(pageSource.includes('enabled: !enabled, version:'), 'the mode toggle PUTs the enabled field + the token')
    assert.ok(pageSource.includes('baseline?.activeVersion ?? 0'),
      'the token is the loaded current_version — 0 (never activated) is a REAL token, never dropped')
    assert.ok(!pageSource.includes("'PATCH'"), 'no PATCH — the policy surface is GET/POST/PUT/DELETE only')
  })

  it('the server 409 backstop: a stale token flips the stale state, never a silent overwrite', () => {
    assert.ok(pageSource.includes('policyConflictCurrent'), 'the 409 body is parsed for the live current_version')
    assert.ok(pageSource.includes('handleMutationError'), 'every mutation routes its error through the conflict check')
    assert.ok(pageSource.includes('policyEditor.staleConflict'),
      'a server-side conflict renders the version-aware stale copy')
    assert.ok(pageSource.includes('setStaleBlocked(true)'), 'the conflict lands in the same stale state as the client guard')
    assert.ok(pageSource.includes('policyValidationErrorText'), 'non-conflict failures still surface their server text')
  })

  it('the stale-edit guard re-reads the baseline before the PUTs', () => {
    assert.ok(pageSource.includes('passStaleGuard'), 'the guard helper exists')
    assert.ok(pageSource.includes("passStaleGuard('yaml')") && pageSource.includes("passStaleGuard('activate')"),
      'both mutation shapes are guarded')
    assert.ok(pageSource.includes('isStaleForYaml') && pageSource.includes('isStaleForActivate'),
      'the field-scoped compare rules are used, not a blanket check')
    assert.ok(pageSource.includes('data-testid="policy-editor-stale"') && pageSource.includes('policyEditor.staleRefresh'),
      'a blocked edit shows the stale notice with an explicit refresh')
  })

  it('the confirm dialog names the target version (was → becomes)', () => {
    assert.ok(pageSource.includes('was: `@v${active}`'), 'the dialog shows the active version')
    assert.ok(pageSource.includes('becomes: `@v${version}`'), 'the dialog names the target')
    assert.ok(pageSource.includes('rollbackConfirm') && pageSource.includes('activateConfirm'),
      'rollback and activate carry their own confirm labels')
  })

  it('the preview deep-links the decisions log with org+policy params', () => {
    assert.ok(pageSource.includes('#policy-decisions?org='), 'the pointer carries the org scope')
    assert.ok(pageSource.includes('&policy='), 'the pointer filters by this policy')
    assert.ok(decisionsSource.includes("useHashParam('policy')"), 'the decisions page reads the policy param')
    assert.ok(decisionsSource.includes("useHashParam('org')"), 'the decisions page reads the org param')
  })

  it('CORE-TRACE-03: the editor links the affected requests (roll-up view of the same log)', () => {
    assert.ok(pageSource.includes('data-testid="policy-editor-preview-requests"'),
      'the affected-requests pointer exists beside the decisions pointer')
    const hrefRe = /href=\{`#policy-decisions\?org=\$\{encodeURIComponent\(org\)\}&policy=\$\{encodeURIComponent\(policyId\)\}&view=requests`\}/
    assert.match(pageSource, hrefRe,
      'the pointer must land on the decisions page requests view for the same org+policy')
    assert.ok(decisionsSource.includes("useHashParam('view')"), 'the decisions page reads the view param')
    assert.ok(decisionsSource.includes('listPolicyDecisionRequests'), 'the requests view fetches the roll-up entity')
  })

  it('the versions list shows labels and activate/rollback controls', () => {
    for (const needle of ['policy-editor-versions', 'policyEditor.activeChip', 'policyEditor.activateTo', 'policyEditor.rollbackTo']) {
      assert.ok(pageSource.includes(needle), `${needle} missing`)
    }
    assert.ok(pageSource.includes('diffLines('), 'the diff view is computed client-side')
  })
})

describe('nav registration (mirrors the audited gate map)', () => {
  it('the policy-editor entry sits in NAV_SECTIONS under policies.manage', () => {
    const re = new RegExp(String.raw`\{ id: 'policy-editor', labelKey: 'app\.navPolicyEditor', icon: <\w+ size=\{16\} \/>,
? access: \{ anyOrg: \['policies\.manage'\] \} \},`)
    assert.match(appSource, re,
      'the nav line must match the pinned gate exactly (App.navGates.test.ts holds the same table)')
  })
})

describe('policyEditor copy exists in all eight locales (same key set)', () => {
  const locales = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar']

  function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
    return Object.entries(obj).flatMap(([k, v]) =>
      v !== null && typeof v === 'object'
        ? flatKeys(v as Record<string, unknown>, prefix ? `${prefix}.${k}` : k)
        : [prefix ? `${prefix}.${k}` : k],
    )
  }

  it('every locale carries the en policyEditor key set and the nav label', () => {
    const en = JSON.parse(readFileSync(join(srcDir, 'i18n', 'en.json'), 'utf8'))
    const enKeys = flatKeys(en.policyEditor as Record<string, unknown>, 'policyEditor').sort()
    assert.ok(enKeys.length >= 40, `expected the policyEditor key family, found ${enKeys.length}`)
    for (const locale of locales) {
      const bundle = JSON.parse(readFileSync(join(srcDir, 'i18n', `${locale}.json`), 'utf8'))
      const keys = flatKeys(bundle.policyEditor as Record<string, unknown> ?? {}, 'policyEditor').sort()
      assert.deepEqual(keys, enKeys, `${locale}.policyEditor key set drifted from en.json`)
      assert.equal(typeof bundle.app?.navPolicyEditor, 'string', `${locale}.app.navPolicyEditor missing`)
      assert.notEqual(bundle.app?.navPolicyEditor, '', `${locale}.app.navPolicyEditor empty`)
      for (const k of keys) {
        const v = k.split('.').slice(1).reduce<unknown>((acc, part) => (acc as Record<string, unknown>)?.[part], bundle.policyEditor)
        assert.equal(typeof v, 'string', `${locale} ${k} must be a string`)
        assert.notEqual(v, '', `${locale} ${k} must not be empty`)
      }
    }
  })
})

// Pins for the review
// findings on this card's surfaces. Source-level by harness necessity (the
// node runner cannot render .tsx — GuardrailsPage.test.ts way); each pin
// targets the exact review finding so it cannot silently regress.
describe('CORE-TRACE-03 review fixes (IMP-TRACE03 review 2026-11-02)', () => {
  const explorerSource = readFileSync(join(srcDir, 'pages', 'RequestExplorerPage.tsx'), 'utf8')

  it('F2: a decision row without request_id renders a bare dash — never an empty link', () => {
    // The decisions entity serves request_id: '' rows (legacy pre-instrumented
    // traffic); only the requests roll-up filters them out server-side
    // (request_id <> '' in pkg/adminstore/policydecisions.go). The guard pins
    // the exact shape: empty id → the dash text node; requestLink (the only
    // <a> producer for this column) reachable solely through the truthy arm —
    // an empty, focusable link with a broken tooltip must not come back.
    assert.ok(!decisionsSource.includes('requestLink((d as PolicyDecision).request_id)'),
      'the unguarded decisions-view render is gone')
    assert.match(decisionsSource, /const id = \(d as PolicyDecision\)\.request_id\s*\n\s*return id \? requestLink\(id\) : '—'/,
      'empty request_id renders the bare dash — no <a>, nothing focusable')
    assert.match(decisionsSource, /render: d => requestLink\(\(d as PolicyDecisionRequestSummary\)\.request_id\)/,
      'the requests roll-up keeps the direct link (server guarantees a non-empty id there)')
  })

  it('F3: the drawer retry rides the same generation guard as the effect — a late retry response is a no-op', () => {
    // The fetch block's guard must be a shared generation ref, not the
    // effect-only closure flag: the retry button calls the callback OUTSIDE
    // the effect, so a closure flag was never invalidated by cleanup and a
    // late retry response could land rows/state from a previous scope after
    // an org switch or close/reopen (AC «смена org не показывает stale
    // данные» hole the review named). The pin is structural by harness
    // necessity — every invocation must take a token from ONE shared
    // counter, and BOTH settle branches must compare it.
    const block = explorerSource.match(/const genInspectDecisions = useRef\(0\)[\s\S]*?useEffect\(\(\) => loadInspectDecisions\(\)/)
    assert.ok(block, 'the drawer decisions fetch block carries its generation ref')
    assert.ok(block[0].includes('const g = ++genInspectDecisions.current'),
      'every fetch (effect body or retry click) takes a fresh generation token')
    assert.match(block[0], /\.then\(res => \{ if \(genInspectDecisions\.current === g\) \{ setInspectDecisions\(res\.rows\); setInspectDecisionsState\('ready'\) \} \}\)/,
      'a superseded retry success cannot land rows from the old scope')
    assert.match(block[0], /\.catch\(\(\) => \{ if \(genInspectDecisions\.current === g\) setInspectDecisionsState\('failed'\) \}\)/,
      'a superseded retry failure cannot clobber the newer scope\'s state')
    assert.ok(!block[0].includes('let cancelled'),
      'the closure flag is gone — it never guarded the unregistered retry closure')
    assert.ok(block[0].includes('++genInspectDecisions.current; setInspectDecisions(null)'),
      'the idle branch (close / empty scope) also invalidates anything in flight')
    assert.match(explorerSource, /data-testid="inspector-decisions-failed"[\s\S]*?onClick=\{loadInspectDecisions\}/,
      'the retry button re-enters the SAME guarded callback — no second, unguarded fetch path')
  })

  it('F4: a scope change flips loading in the same tick — the debounce window cannot render a false empty', () => {
    // Rows drop and loading flips together in the scope-change effect; the
    // debounced fetch itself is untouched. Without the synchronous flip the
    // per-view «empty» notice (empty vs emptyRequests) would state «no rows
    // for this scope» while the scope's fetch had not even started.
    const block = decisionsSource.match(/useEffect\(\(\) => \{\s*\n\s*setPage\(1\)[\s\S]*?\}, \[reload, org\]\)/)
    assert.ok(block, 'the scope-change effect exists with org in its deps')
    assert.match(block[0], /setRows\(\[\]\)\s*\n\s*if \(org\.trim\(\)\) setLoading\(true\)/,
      'rows drop AND loading flips synchronously — no empty-notice flash for the debounce window')
    assert.ok(block[0].includes('const timer = setTimeout(() => reload(1), 400)'),
      'the debounced fetch is unchanged (F4 touches the state flip only)')
  })
})
