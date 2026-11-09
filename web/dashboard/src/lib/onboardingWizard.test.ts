//
// The wizard is a UI composition over EXISTING root-only endpoints (residency
// PUT, policy-packs PUT, tool-policy preset POST — see the contract
// pinned is therefore DATA and STRUCTURE, the GuardrailsPage.test.ts way:
//
//   1. the plan derivation (which writes a selection produces, and which
//      selections produce none — «no change» is a plan outcome, not a bug);
//   2. the live-state truth table (unknown never reads as done; a preset
//      with any tool policies present is UNKNOWN, not applied — any preset
//      or hand-written policy may have created those rows);
//   3. the preset/pack vocabulary is the SERVER's, pinned to the Go sources
//      (pkg/toolpolicy/presets.go and defaultPackID in
//      services/admin/handlers/policy_pack_handlers.go) so the wizard can
//      never offer an id the backend would reject;
//   4. the page keeps the original 3 steps and adds exactly profiles →
//      policy defaults → review-before-apply, applying through the existing
//      api functions and never marking the org completed on partial failure
//      (the completed mark still rides the live allStepsDone effect);
//   5. every wizard copy key exists in all eight locales (same key set).

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  DEFAULT_WIZARD_SELECTION, REGION_PACK_IDS, WIZARD_SECURITY_PRESETS,
  wizardAppliedPackRegions, wizardItemDisplayState, wizardItemLiveState,
  wizardPlan, wizardPlanDone, wizardPlanItemKey, wizardPresetFromRegion,
  type WizardSelection, type WizardSignals,
} from './onboarding.ts'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..', '..', '..', '..')
const pageSource = readFileSync(join(here, '..', 'pages', 'OnboardingPage.tsx'), 'utf8')

const UNKNOWN: WizardSignals = { residencyRegion: null, toolPolicyCount: null, packRegions: null }

describe('wizard plan derivation (R066-02)', () => {
  it('the default selection changes nothing (empty plan)', () => {
    assert.deepEqual(wizardPlan(DEFAULT_WIZARD_SELECTION), [])
    assert.equal(wizardPlanDone([], UNKNOWN), true, 'an empty plan is trivially done')
  })

  it('a residency selection produces residency + pack writes, in that order', () => {
    const sel: WizardSelection = { ...DEFAULT_WIZARD_SELECTION, residency: 'SG' }
    assert.deepEqual(wizardPlan(sel), [
      { kind: 'residency', id: 'SG' },
      { kind: 'pack', id: 'SG' },
    ])
  })

  it('a security selection produces exactly one preset write', () => {
    const sel: WizardSelection = { ...DEFAULT_WIZARD_SELECTION, security: 'network-off' }
    assert.deepEqual(wizardPlan(sel), [{ kind: 'preset', id: 'network-off' }])
  })

  it('a full selection produces all three writes (residency, pack, preset)', () => {
    const sel: WizardSelection = { residency: 'IN', security: 'internal-only', deployment: 'helm' }
    assert.deepEqual(wizardPlan(sel).map(wizardPlanItemKey), ['residency:IN', 'pack:IN', 'preset:internal-only'])
  })
})

describe('wizard live-state truth table (resume safety)', () => {
  it('unknown signals never read as done', () => {
    for (const item of wizardPlan({ ...DEFAULT_WIZARD_SELECTION, residency: 'SG', security: 'network-off' })) {
      assert.equal(wizardItemLiveState(item, UNKNOWN), null)
    }
    assert.equal(wizardPlanDone(wizardPlan({ ...DEFAULT_WIZARD_SELECTION, residency: 'SG' }), UNKNOWN), null)
  })

  it('residency items are answered exactly by the live region', () => {
    const [residency] = wizardPlan({ ...DEFAULT_WIZARD_SELECTION, residency: 'SG' })
    assert.equal(wizardItemLiveState(residency, { residencyRegion: 'SG', toolPolicyCount: 0, packRegions: [] }), true)
    assert.equal(wizardItemLiveState(residency, { residencyRegion: 'IN', toolPolicyCount: 0, packRegions: [] }), false)
    assert.equal(wizardItemLiveState(residency, { ...UNKNOWN, residencyRegion: null }), null)
  })

  it('pack items are answered ONLY by the dedicated pack read — never by residency (AUDIT-P1-05)', () => {
    const [, pack] = wizardPlan({ ...DEFAULT_WIZARD_SELECTION, residency: 'SG' })
    // The residency match MUST NOT prove the pack applied: this is the
    // exact audit probe (successful residency PUT + failed pack PUT leaves
    // the live region at SG while no pack row exists).
    assert.equal(
      wizardItemLiveState(pack, { residencyRegion: 'SG', toolPolicyCount: null, packRegions: [] }), false,
      'a residency match with a confirming empty pack read is NOT applied — confirmed missing',
    )
    assert.equal(
      wizardItemLiveState(pack, { residencyRegion: 'SG', toolPolicyCount: null, packRegions: null }), null,
      'without the dedicated pack read the pack state stays unknown, never inferred',
    )
    assert.equal(
      wizardItemLiveState(pack, { residencyRegion: '', toolPolicyCount: null, packRegions: ['SG'] }), true,
      'the dedicated pack read alone answers the pack question',
    )
    assert.equal(
      wizardItemLiveState(pack, { residencyRegion: 'IN', toolPolicyCount: null, packRegions: ['IN'] }), false,
      'pack states are per region and independent of every other signal',
    )
  })

  it('wizardAppliedPackRegions proves only canonical enabled rows (server vocabulary)', () => {
    // Canonical + enabled = applied.
    assert.deepEqual(
      wizardAppliedPackRegions([{ region: 'SG', pack_id: 'sg_pdpa_mas', enabled: true }]),
      ['SG'],
    )
    // Explicitly disabled, foreign pack_id, or unknown region never prove it.
    assert.deepEqual(
      wizardAppliedPackRegions([
        { region: 'SG', pack_id: 'sg_pdpa_mas', enabled: false },
        { region: 'IN', pack_id: 'sg_pdpa_mas', enabled: true },
        { region: 'EU', pack_id: 'eu_whatever', enabled: true },
      ]),
      [],
    )
    // Malformed rows cannot prove application.
    assert.deepEqual(wizardAppliedPackRegions([{}, { region: 'SG' }, { pack_id: 'sg_pdpa_mas' }]), [])
    assert.deepEqual(wizardAppliedPackRegions(null), [])
    assert.deepEqual(wizardAppliedPackRegions(undefined), [])
  })

  it('wizardItemDisplayState: a failed outcome is NEVER promoted by any live signal (AUDIT-P1-05)', () => {
    // The audit probe sequence: explicit pack-PUT failure + an indirect
    // live signal reading applied must stay a visible failure.
    assert.deepEqual(
      wizardItemDisplayState({ ok: false, detail: '500' }, true),
      { ok: false, failed: true },
      'indirect live=true cannot mask an explicit failed write',
    )
    assert.deepEqual(
      wizardItemDisplayState({ ok: false }, null),
      { ok: false, failed: true },
      'unknown live state cannot mask an explicit failed write either',
    )
    // The explicit outcome is authoritative in the success direction too.
    assert.deepEqual(
      wizardItemDisplayState({ ok: true }, false),
      { ok: true, failed: false },
      'an explicit 2xx stands even if a stale read disagrees',
    )
    // Without an outcome the live signals drive the resume display.
    assert.deepEqual(wizardItemDisplayState(undefined, true), { ok: true, failed: false })
    assert.deepEqual(wizardItemDisplayState(undefined, false), { ok: false, failed: true })
    assert.deepEqual(wizardItemDisplayState(undefined, null), { ok: false, failed: false })
  })

  it('the failed-pack PUT audit scenario propagates: plan not done, retry stays available', () => {
    // Residency PUT succeeded, pack PUT failed → region live 'SG', the
    // dedicated pack read confirms no pack row.
    const signals: WizardSignals = { residencyRegion: 'SG', toolPolicyCount: null, packRegions: [] }
    const plan = wizardPlan({ ...DEFAULT_WIZARD_SELECTION, residency: 'SG' })
    assert.equal(wizardPlanDone(plan, signals), false,
      'a confirmed-missing pack keeps the plan explicitly not done — Apply stays enabled')
    // residency row: explicit ok; pack row: explicit failure despite the
    // residency match in the live signals.
    assert.deepEqual(
      plan.map(item => wizardItemDisplayState(
        item.kind === 'pack' ? { ok: false, detail: '500' } : undefined,
        wizardItemLiveState(item, signals),
      )),
      [
        { ok: true, failed: false },
        { ok: false, failed: true },
      ],
    )
  })

  it('a preset with zero tool policies is provably missing; any rows leave attribution UNKNOWN', () => {
    const preset = wizardPlan({ ...DEFAULT_WIZARD_SELECTION, security: 'network-off' })[0]
    assert.equal(wizardItemLiveState(preset, { residencyRegion: '', toolPolicyCount: 0, packRegions: [] }), false)
    assert.equal(wizardItemLiveState(preset, { residencyRegion: '', toolPolicyCount: 7, packRegions: [] }), null,
      'rows may come from any preset or hand-written policy — never claim this preset applied')
  })

  it('the region maps back onto the privacy radio; junk degrades to none', () => {
    assert.equal(wizardPresetFromRegion(''), 'none')
    assert.equal(wizardPresetFromRegion('SG'), 'SG')
    assert.equal(wizardPresetFromRegion('EU'), 'none')
  })
})

describe('wizard vocabulary is the server vocabulary', () => {
  it('security preset ids match pkg/toolpolicy/presets.go exactly', () => {
    const go = readFileSync(join(repoRoot, 'pkg', 'toolpolicy', 'presets.go'), 'utf8')
    const serverIds = [...go.matchAll(/Preset(\w+) = "([\w-]+)"/g)].map(m => m[2])
    assert.deepEqual(
      [...WIZARD_SECURITY_PRESETS].filter(id => id !== 'open').sort(),
      [...serverIds].sort(),
      'the wizard radio must offer exactly the server preset ids (plus the no-op "open")',
    )
  })

  it('REGION_PACK_IDS matches defaultPackID in policy_pack_handlers.go', () => {
    const go = readFileSync(join(repoRoot, 'services', 'admin', 'handlers', 'policy_pack_handlers.go'), 'utf8')
    for (const [region, pack] of Object.entries(REGION_PACK_IDS)) {
      const re = new RegExp(`case "${region}":\\s*\\n\\s*return "${pack}"`)
      assert.match(go, re, `${region} must map to the server's canonical pack id`)
    }
  })
})

describe('OnboardingPage structure (source-level pins)', () => {
  it('keeps the original three steps and adds profiles, defaults, review', () => {
    for (const id of ['welcome-step-provider', 'welcome-step-gateway', 'welcome-step-client']) {
      assert.ok(pageSource.includes(`data-testid="${id}"`), `${id} must stay`)
    }
    for (const id of ['welcome-step-profiles', 'welcome-step-defaults', 'welcome-step-review']) {
      assert.ok(pageSource.includes(`data-testid="${id}"`), `${id} missing`)
    }
  })

  it('applies only through the existing api modules (no new endpoint surface)', () => {
    assert.ok(pageSource.includes('applyToolPolicyPreset'), 'preset apply must reuse api/toolPolicy')
    assert.ok(pageSource.includes('updateOrgResidency'), 'residency apply must reuse api/orgSettings')
    assert.ok(pageSource.includes('upsertPolicyPack'), 'pack apply must reuse api/orgSettings')
    // pkfix1 follow-up: the wire body must satisfy the strict-decode +
    // required-config contract ({} alone is a 400 on the fixed handler).
    assert.ok(
      pageSource.includes("upsertPolicyPack(org, item.id, { pack_id: REGION_PACK_IDS[item.id as 'SG' | 'IN' | 'ID'], config: {} })"),
      'wizard pack apply must send the explicit canonical pack_id and a non-null config document',
    )
  })

  it('pack state is verified by the dedicated GET, never inferred from residency (AUDIT-P1-05)', () => {
    // Both wizard-signal reads include the dedicated policy-pack GET, and a
    // failed read stays null (unknown), never a residency-derived answer.
    const refreshBlock = pageSource.match(/const refreshWizardSignals =[\s\S]*?\n\s*\},\s*\[\]\)/)?.[0] ?? ''
    assert.ok(refreshBlock.includes('listPolicyPacks(orgId)'), 'refresh must re-read GET /policy-packs')
    assert.ok(refreshBlock.includes('wizardAppliedPackRegions(packs.value)'), 'pack signal = canonical applied rows')
    const initialBlock = pageSource.match(/const \[residency, presetList, policies, packs\] =[\s\S]*?\n\s*\}\)\(\)/)?.[0] ?? ''
    assert.ok(initialBlock.includes('listPolicyPacks(org)'), 'the initial per-org load must include the pack read too')
    // Every wizard-signals construction carries the pack signal.
    for (const m of pageSource.matchAll(/setWizardSignals\(\{[\s\S]*?\}\)/g)) {
      assert.ok(m[0].includes('packRegions'), 'each wizard-signals write must state the pack signal explicitly')
    }
    // The masked-override that let a residency match promote a failed pack
    // PUT to ✓ must be gone from the page, and the residency-implies-pack
    // inference must be gone from the lib helper.
    assert.ok(!pageSource.includes('outcome?.ok === true || live === true'),
      'the indirect override that produced the false success is removed')
    const libSource = readFileSync(join(here, 'onboarding.ts'), 'utf8')
    assert.ok(!libSource.includes("item.kind === 'residency' || item.kind === 'pack'"),
      'the residency-implies-pack inference is removed from the live-state helper')
    assert.ok(libSource.includes('wizardItemDisplayState'),
      'the outcome-authoritative row state lives in the tested lib, not inline in the page')
  })

  it('an explicit failed outcome renders through the outcome-authoritative helper (AUDIT-P1-05 wiring)', () => {
    assert.ok(pageSource.includes('wizardItemDisplayState(outcome, live)'),
      'the apply-list rows must derive ok/failed through the outcome-authoritative helper')
  })

  it('review-before-apply: the Apply control exists and partial failure keeps retry', () => {
    assert.ok(pageSource.includes('data-testid="wizard-apply"'))
    assert.ok(pageSource.includes('data-testid="wizard-review-summary"'), 'the summary must render before Apply')
    assert.ok(pageSource.includes('wizardApplyPartial'), 'a partial failure must surface its notice + retry')
    // The org completed mark must stay bound to the LIVE 3-signal effect —
    // exactly one completed:true call site, inside allStepsDone gating.
    assert.equal((pageSource.match(/markOrgOnboarding\(org, \{ completed: true \}\)/g) ?? []).length, 1,
      'the only completed:true mark must be the allStepsDone effect')
    assert.ok(pageSource.includes('allStepsDone(signals)'), 'completion stays derived from the live signals')
  })

  // scenario — a failed write is named, classified and retryable on its
  // own; completed items stay applied; partial never reads as success.
  it('a failed apply item carries an honest failure state and its own retry', () => {
    assert.ok(pageSource.includes('wizardItemFailed'), 'the failed chip renders per item')
    assert.ok(pageSource.includes('welcome.wizardRetryItem'), 'per-item retry copy exists')
    assert.ok(pageSource.includes('-retry`'), 'each failed item gets its own retry testid')
    // The per-item retry rides the SAME apply path: already-ok items are
    // skipped ("if (next[key]?.ok) continue"), so retry = exactly the
    // failed write, never a full re-run that could clobber completed parts.
    assert.ok(pageSource.includes('if (next[key]?.ok) continue'),
      'apply skips completed items — retry re-runs only the failed ones')
    // The failure detail names the server status class (never a silent
    // {ok:false}); a network failure is classified as such.
    assert.ok(pageSource.includes("'network'"), 'a network failure is classified honestly')
    assert.ok(pageSource.includes('detail: status'), 'the server status rides the outcome detail')
  })

  it('non-root callers get the honest partial note, not the flow', () => {
    assert.ok(pageSource.includes('wizardRootOnly'))
    assert.ok(pageSource.includes('wizardRootBlocked'), 'the gate variable must drive the steps')
  })
})

// The state matrix every N15-P02 card must keep (design/wizard §3 keep/extend
// contract): done/todo/unknown stay distinguishable everywhere, unknown is
// never styled as done or failed, and a confirmed to-do never borrows the
// unknown word. Color is never the only carrier — glyph + word + sr-only chip.
describe('state matrix (design/wizard §3)', () => {
  function block(startMarker: string, endMarker: string): string {
    const start = pageSource.indexOf(startMarker)
    assert.ok(start >= 0, `${startMarker} must exist`)
    const end = pageSource.indexOf(endMarker, start)
    assert.ok(end > start, `${endMarker} must follow ${startMarker}`)
    return pageSource.slice(start, end)
  }

  it('steps 1–3 state lines are honest 3-way: done sentence / To do word / Checking… word', () => {
    const steps = [
      { state: 'welcome-step-provider-state', done: 'welcome.stepProviderDone' },
      { state: 'welcome-step-gateway-state', done: 'welcome.stepGatewayDone' },
      { state: 'welcome-step-client-state', done: 'welcome.stepClientDone' },
    ] as const
    for (const { state, done } of steps) {
      const line = block(`data-testid="${state}"`, '</p>')
      const at = (needle: string): number => {
        const i = line.indexOf(needle)
        assert.ok(i >= 0, `${state}: missing ${needle}`)
        return i
      }
      assert.ok(at(done) < at("welcome.wizardStateTodo'"), `${state}: true branch must come first`)
      assert.ok(
        at("welcome.wizardStateTodo'") < at("welcome.stateChecking'"),
        `${state}: confirmed false must render the To do word, not the Checking… unknown word`,
      )
    }
  })

  it('badges: ✓ glyph only when truly done, the step number otherwise (never a spinner-only lie)', () => {
    assert.ok(pageSource.includes("{doneState === true ? '✓' : index}"),
      'the badge shows the number for to-do AND unknown — only a confirmed done gets the ✓')
    assert.ok(pageSource.includes("doneState === true ? 'text-[color:var(--astra-text-muted)]' : 'text-[color:var(--astra-ink)]'"),
      'the step title de-emphasizes only when done')
    assert.ok(pageSource.includes('{doneState === true && <span className="sr-only">'),
      'a done title carries the sr-only done chip (color is never the only carrier)')
  })

  it('the review summary names unknown with the state words, never as success', () => {
    assert.ok(pageSource.includes(
      "state === true ? t('welcome.wizardStateDone') : state === false ? t('welcome.wizardStateTodo') : t('welcome.wizardStateUnknown')",
    ), 'stepStateWord maps true/false/null onto Done/To do/Unknown in that order')
  })

  it('root-block: exactly steps 4–6 bodies are gated, steps 1–3 stay visible for everyone', () => {
    assert.equal((pageSource.match(/wizardRootBlocked \?/g) ?? []).length, 3,
      'the profiles, defaults and review bodies are the only gated steps')
    assert.equal((pageSource.match(/<StateNotice state="partial" message=\{t\('welcome\.wizardRootOnly'\)\} \/>/g) ?? []).length, 3,
      'each gated step renders the honest partial note (never a hidden step)')
    const firstThree = block('data-testid="welcome-step-provider"', 'data-testid="welcome-step-profiles"')
    assert.ok(!firstThree.includes('wizardRootBlocked'),
      'steps 1–3 are org-scoped reads — they must render for non-root operators too')
  })

  it('partial failure (apply): an error notice with a global retry, and completed items stay done', () => {
    const notice = block('Object.values(applyOutcomes).some(o => !o.ok)', '/>')
    assert.ok(notice.includes('state="error"'), 'the partial failure notice is an error state, never success')
    assert.ok(notice.includes('welcome.wizardApplyPartial'), 'the notice names what failed')
    assert.ok(notice.includes("label: t('common.retry')"), 'the notice carries the global retry action')
    assert.ok(pageSource.includes('if (next[key]?.ok) continue'),
      'retry skips completed items (they stay visibly done)')
  })

  it('flag unavailable and previously-skipped render honest partial notices above the steps', () => {
    const unavailable = block("flagState === 'unavailable'", '/>')
    assert.ok(unavailable.includes('state="partial"') && unavailable.includes('welcome.flagUnavailable'),
      'a 501-only deployment keeps working with a partial note')
    const skipped = block('previouslySkipped && !alreadyCompleted', '/>')
    assert.ok(skipped.includes('state="partial"') && skipped.includes('welcome.skippedNote'),
      'the skip redirect skips; the truth still renders, muted')
  })
})

describe('state-word vocabulary is the design/wizard §6 fixed set (en)', () => {
  const en = JSON.parse(readFileSync(join(here, '..', 'i18n', 'en.json'), 'utf8')) as {
    welcome: Record<string, string>
  }

  it('the same word never means two states', () => {
    // design/wizard §6: Done, To do, Unknown, Checking…, Applying…, Failed.
    assert.equal(en.welcome.wizardStateDone, 'Done')
    assert.equal(en.welcome.wizardStateTodo, 'To do')
    assert.equal(en.welcome.wizardStateUnknown, 'Unknown')
    assert.equal(en.welcome.stateChecking, 'Checking…')
    assert.equal(en.welcome.wizardApplying, 'Applying…')
    assert.equal(en.welcome.wizardItemFailed, 'Failed')
  })

  it('an unknown is named, never paraphrased into a success or a zero', () => {
    for (const key of ['wizardStateUnknown', 'stateChecking', 'wizardDefaultsUnavailable', 'flagUnavailable']) {
      assert.ok(!/no (keys|presets|data)/i.test(en.welcome[key] ?? ''),
        `welcome.${key} must not paraphrase unknown into a zero`)
    }
  })
})

describe('wizard copy exists in all eight locales (same key set)', () => {
  const locales = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar']

  function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
    return Object.entries(obj).flatMap(([k, v]) =>
      v !== null && typeof v === 'object'
        ? flatKeys(v as Record<string, unknown>, prefix ? `${prefix}.${k}` : k)
        : [prefix ? `${prefix}.${k}` : k],
    )
  }

  it('every locale carries the en wizard key set', () => {
    const en = JSON.parse(readFileSync(join(here, '..', 'i18n', 'en.json'), 'utf8'))
    const enKeys = flatKeys(en.welcome as Record<string, unknown>, 'welcome')
      .filter(k => k.includes('.wizard'))
      .sort()
    assert.ok(enKeys.length >= 40, `expected the wizard key family, found ${enKeys.length}`)
    for (const locale of locales) {
      const bundle = JSON.parse(readFileSync(join(here, '..', 'i18n', `${locale}.json`), 'utf8'))
      const keys = flatKeys(bundle.welcome as Record<string, unknown> ?? {}, 'welcome')
        .filter(k => k.includes('.wizard'))
        .sort()
      assert.deepEqual(keys, enKeys, `${locale}.welcome wizard key set drifted from en.json`)
      for (const k of keys) {
        const v = k.split('.').reduce<unknown>((acc, part) => (acc as Record<string, unknown>)?.[part], bundle)
        assert.equal(typeof v, 'string', `${locale} ${k} must be a string`)
        assert.notEqual(v, '', `${locale} ${k} must not be empty`)
      }
    }
  })
})
