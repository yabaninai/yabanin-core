import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { applyToolPolicyPreset, listToolPolicies, listToolPolicyPresets, type ToolPolicyPreset } from '../../api/toolPolicy'
import { getOrgResidency, listPolicyPacks, updateOrgResidency, upsertPolicyPack } from '../../api/orgSettings'
import {
  DEFAULT_WIZARD_SELECTION, REGION_PACK_IDS, wizardAppliedPackRegions, wizardPlan, wizardPlanDone,
  wizardPlanItemKey, wizardPresetFromRegion,
  type WizardApplyOutcome, type WizardPlanItem, type WizardResidencyPreset, type WizardSelection, type WizardSignals,
} from '../../lib/onboarding'

type Translate = ReturnType<typeof useTranslation>['t']

// The honest per-item failure classification: which write failed and the
// server's status class (never a silent skip; never success). A network
// failure is classified as such.
function errorStatusClass(err: unknown): string {
  return typeof err === 'object' && err !== null && 'status' in err
    ? String((err as { status?: unknown }).status)
    : 'network'
}

// One plan item's write, through the existing api modules only (no new
// endpoint surface). pkfix1 contract (review 98613b94): `config` is
// required non-null JSON — {} = the pack's built-in rules, no overrides.
// pack_id is sent explicitly so the wire body matches the pack the
// review summary just showed the operator.
async function applyOneWizardItem(org: string, item: WizardPlanItem, t: Translate): Promise<WizardApplyOutcome> {
  if (item.kind === 'residency') {
    await updateOrgResidency(org, item.id)
    return { ok: true }
  }
  if (item.kind === 'pack') {
    await upsertPolicyPack(org, item.id, { pack_id: REGION_PACK_IDS[item.id as 'SG' | 'IN' | 'ID'], config: {} })
    return { ok: true }
  }
  const res = await applyToolPolicyPreset(org, item.id)
  return {
    ok: true,
    detail: t('welcome.wizardAppliedCounts', { created: res.created, skipped: res.skipped_existing }),
  }
}

// The profiles/defaults/review wizard state machine: live wizard signals
// (residency / tool policies / a dedicated pack read — AUDIT-P1-05: the
// pack signal is NEVER derived from residency), the presets list, the
// derived plan and its per-item outcomes.
export function useOnboardingWizard(org: string, isRoot: boolean): {
  wizard: WizardSelection
  setWizard: (updater: (w: WizardSelection) => WizardSelection) => void
  onResidencyChange: (v: WizardResidencyPreset) => void
  wizardSignals: WizardSignals
  presets: ToolPolicyPreset[] | null
  applyOutcomes: Record<string, WizardApplyOutcome>
  applyingWizard: boolean
  wizardPlanItems: WizardPlanItem[]
  reviewDone: boolean | null
  profilesDone: boolean | null
  presetHint: (id: 'network-readonly' | 'network-off' | 'internal-only') => string
  applyWizardPlan: () => void
} {
  const { t } = useTranslation()
  const [wizard, setWizardState] = useState<WizardSelection>(DEFAULT_WIZARD_SELECTION)
  const [wizardSignals, setWizardSignals] = useState<WizardSignals>({ residencyRegion: null, toolPolicyCount: null, packRegions: null })
  const [presets, setPresets] = useState<ToolPolicyPreset[] | null>(null)
  const [applyOutcomes, setApplyOutcomes] = useState<Record<string, WizardApplyOutcome>>({})
  const [applyingWizard, setApplyingWizard] = useState(false)
  // Residency radio follows the live region until the operator touches it
  // (re-open resumes to the derived state, not a stale local choice).
  const wizardTouchedResidency = useRef(false)

  const setWizard = useCallback((updater: (w: WizardSelection) => WizardSelection) => setWizardState(updater), [])
  const onResidencyChange = useCallback((v: WizardResidencyPreset) => {
    wizardTouchedResidency.current = true
    setWizardState(w => ({ ...w, residency: v }))
  }, [])

  // The pack signal is its own dedicated read (GET /policy-packs) — it is
  // NEVER derived from residency (AUDIT-P1-05: a residency match is not
  // proof the pack applied).
  const refreshWizardSignals = useCallback(async (orgId: string) => {
    const [residency, policies, packs] = await Promise.allSettled([
      getOrgResidency(orgId),
      listToolPolicies(orgId),
      listPolicyPacks(orgId),
    ])
    setWizardSignals({
      residencyRegion: residency.status === 'fulfilled' ? (residency.value.residency_region ?? '') : null,
      toolPolicyCount: policies.status === 'fulfilled' ? policies.value.length : null,
      packRegions: packs.status === 'fulfilled' ? wizardAppliedPackRegions(packs.value) : null,
    })
  }, [])

  useEffect(() => {
    if (!org || !isRoot) return
    let cancelled = false
    setWizardSignals({ residencyRegion: null, toolPolicyCount: null, packRegions: null })
    setPresets(null)
    setApplyOutcomes({})
    wizardTouchedResidency.current = false
    void (async () => {
      const [residency, presetList, policies, packs] = await Promise.allSettled([
        getOrgResidency(org),
        listToolPolicyPresets(org),
        listToolPolicies(org),
        listPolicyPacks(org),
      ])
      if (cancelled) return
      setWizardSignals({
        residencyRegion: residency.status === 'fulfilled' ? (residency.value.residency_region ?? '') : null,
        toolPolicyCount: policies.status === 'fulfilled' ? policies.value.length : null,
        packRegions: packs.status === 'fulfilled' ? wizardAppliedPackRegions(packs.value) : null,
      })
      if (presetList.status === 'fulfilled') setPresets(presetList.value)
    })()
    return () => { cancelled = true }
  }, [org, isRoot])

  // Sync the privacy radio to the live region once per org (before touch).
  useEffect(() => {
    if (wizardTouchedResidency.current) return
    if (wizardSignals.residencyRegion === null) return
    setWizardState(w => ({ ...w, residency: wizardPresetFromRegion(wizardSignals.residencyRegion as string) }))
  }, [wizardSignals.residencyRegion])

  const wizardPlanItems = wizardPlan(wizard)
  const reviewDone = wizardPlanDone(wizardPlanItems, wizardSignals)

  // Security radio hints: the server preset description when the presets
  // endpoint answered, the short local fallback otherwise (the ids are the
  // server's; only the fallback prose is ours).
  const presetHint = useCallback((id: 'network-readonly' | 'network-off' | 'internal-only'): string => {
    const fromServer = (presets ?? []).find(p => p.ID === id)?.Description
    if (fromServer) return fromServer
    return id === 'network-readonly' ? t('welcome.wizardSecurityReadonlyHint')
      : id === 'network-off' ? t('welcome.wizardSecurityOffHint')
      : t('welcome.wizardSecurityInternalHint')
  }, [presets, t])

  const profilesDone = (() => {
    if (wizardSignals.residencyRegion === null) return null
    const residencyMatches = wizardSignals.residencyRegion === (wizard.residency === 'none' ? '' : wizard.residency)
    if (wizard.security === 'open') return residencyMatches
    if (wizardSignals.toolPolicyCount === null) return null
    return residencyMatches && wizardSignals.toolPolicyCount > 0
  })()

  // Apply runs the plan items in order; each item reports its own explicit
  // outcome, a failed item leaves the completed ones visible and retryable
  // (the «частичная ошибка» scenario) — and the org completed flag is NOT
  // touched here: it only flips through the live allStepsDone effect.
  // After the run the wizard signals refresh with a dedicated pack read, so
  // the review step re-derives from direct evidence, never from residency
  // inference (AUDIT-P1-05).
  const applyWizardPlan = useCallback(() => {
    if (!org || applyingWizard) return
    setApplyingWizard(true)
    void (async () => {
      const next = { ...applyOutcomes }
      for (const item of wizardPlan(wizard)) {
        const key = wizardPlanItemKey(item)
        if (next[key]?.ok) continue
        try {
          next[key] = await applyOneWizardItem(org, item, t)
        } catch (err) {
          const status = errorStatusClass(err)
          next[key] = { ok: false, detail: status }
        }
        setApplyOutcomes({ ...next })
      }
      setApplyingWizard(false)
      void refreshWizardSignals(org)
    })()
  }, [org, wizard, applyingWizard, applyOutcomes, refreshWizardSignals, t])

  return {
    wizard, setWizard, onResidencyChange, wizardSignals, presets, applyOutcomes, applyingWizard,
    wizardPlanItems, reviewDone, profilesDone, presetHint, applyWizardPlan,
  }
}
