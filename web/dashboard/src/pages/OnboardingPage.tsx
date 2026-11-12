import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listAPIKeys } from '../api/keys'
import { getOrgOnboarding, markOrgOnboarding, type OrgOnboarding } from '../api/onboarding'
import { listProviderCredentials } from '../api/providerCredentials'
import { requestStats } from '../api/requests'
import { applyToolPolicyPreset, listToolPolicies, listToolPolicyPresets, type ToolPolicyPreset } from '../api/toolPolicy'
import { getOrgResidency, listPolicyPacks, updateOrgResidency, upsertPolicyPack } from '../api/orgSettings'
import { CopyBlock } from '../components/CopyBlock'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useHashParam } from '../hooks/useHashParam'
import { usePermissions } from '../hooks/usePermissions'
import {
  ONBOARDING_CLIENTS, REGION_PACK_IDS, allStepsDone, clientConfigBlock, dashboardHomeLink,
  firstRequestState, gatewayKeyState, gatewayKeysLink, providerKeyState, providerKeysLink,
  DEFAULT_WIZARD_SELECTION, wizardAppliedPackRegions, wizardItemDisplayState, wizardItemLiveState, wizardPlan, wizardPlanDone, wizardPlanItemKey, wizardPresetFromRegion,
  type OnboardingClient, type OnboardingSignals,
  type WizardApplyOutcome, type WizardDeploymentPreset, type WizardResidencyPreset, type WizardSelection, type WizardSignals,
} from '../lib/onboarding'

// The 3-step welcome flow — (1) connect a provider key (BYOK,
// deep link to the provider-keys tab of organization settings), (2) create a
// gateway key (deep link to the API-keys screen), (3) point the client at
// the gateway (copy blocks verbatim from docs/clients/{opencode,claude-code,
// codex}.md).
//
// Contract facts this screen is built on:
//  - step completion is DERIVED LIVE (provider-credentials list, api-keys
//    list, org request stats) — the org flag (api/onboarding.ts) only stores
//    completed/skipped marks, so a step cannot lie because a stale flag says
//    so; unknown/loading/error never read as done (OnboardingCard);
//  - when every step confirms true the flow marks the org completed
//    (POST /api/me/onboarding, best-effort: a 501-only deployment keeps
//    working, the mark retries on the operator's next visit);
//  - skip persists the skipped flag and seats the operator on their landing
//    page; an explicitly opened #onboarding still renders (with a muted
//    "previously skipped" note) — the redirect is what skips, not the truth;
//  - the gateway address in the copy blocks is the docs placeholder: the
//    console cannot know the deployment's gateway origin, and no invented
//    URL is ever shown as if it were live (design-skill honesty rule).

type FlagState = 'loading' | 'ready' | 'unavailable'

function RadioGroup<V extends string>({ name, legend, value, onChange, options }: {
  name: string
  legend: string
  value: V
  onChange: (v: V) => void
  options: { value: V; label: string; hint?: string }[]
}) {
  return (
    <fieldset className="flex flex-col gap-1">
      <legend className="mb-1 text-sm font-medium text-[color:var(--astra-ink)]">{legend}</legend>
      {options.map(o => (
        <label
          key={o.value}
          data-testid={`wizard-${name}-${o.value}`}
          className={`flex min-h-[44px] cursor-pointer items-start gap-2 rounded-[length:var(--astra-radius-control)] border px-3 py-2 ${
            value === o.value
              ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)]'
              : 'border-[color:var(--astra-rule)] hover:bg-[color:var(--astra-surface-muted)]'
          }`}
        >
          <input
            type="radio"
            name={`wizard-${name}`}
            value={o.value}
            checked={value === o.value}
            onChange={() => onChange(o.value)}
            className="mt-1 accent-[color:var(--astra-action)]"
          />
          <span className="flex flex-col gap-0.5">
            <span className="text-sm text-[color:var(--astra-ink)]">{o.label}</span>
            {o.hint && <span className="text-xs text-[color:var(--astra-text-muted)]">{o.hint}</span>}
          </span>
        </label>
      ))}
    </fieldset>
  )
}

export function OnboardingPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const org = orgId.trim()
  const perms = usePermissions(org || undefined)
  const isRoot = perms.isRoot

  const [flag, setFlag] = useState<OrgOnboarding | null>(null)
  const [flagState, setFlagState] = useState<FlagState>('loading')
  const [signals, setSignals] = useState<OnboardingSignals>({ providerKey: null, gatewayKey: null, firstRequest: null })
  const [client, setClient] = useState<OnboardingClient>('opencode')
  const [skipping, setSkipping] = useState(false)
  // The auto-complete mark fires at most once per org (a ref, not state:
  // re-renders from the detection settles must not re-post).
  const completedMarkedFor = useRef('')

  // The wizard's reads/writes are the MustBeRoot app-config surfaces
  // (residency/policy-packs: router_orgs.go mountOrgsRoot; tool-policy
  // presets: router_mcp.go mountMCP), so the whole flow renders for root
  // and degrades to an honest note for everyone else — the server
  // arbitrates either way.
  const permsLoading = perms.loading
  const wizardRootBlocked = !permsLoading && perms.me !== null && !isRoot
  const [wizard, setWizard] = useState<WizardSelection>(DEFAULT_WIZARD_SELECTION)
  const [wizardSignals, setWizardSignals] = useState<WizardSignals>({ residencyRegion: null, toolPolicyCount: null, packRegions: null })
  const [presets, setPresets] = useState<ToolPolicyPreset[] | null>(null)
  const [applyOutcomes, setApplyOutcomes] = useState<Record<string, WizardApplyOutcome>>({})
  const [applyingWizard, setApplyingWizard] = useState(false)
  // Residency radio follows the live region until the operator touches it
  // (re-open resumes to the derived state, not a stale local choice).
  const wizardTouchedResidency = useRef(false)

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
    setWizard(w => ({ ...w, residency: wizardPresetFromRegion(wizardSignals.residencyRegion as string) }))
  }, [wizardSignals.residencyRegion])

  const wizardPlanItems = wizardPlan(wizard)
  const reviewDone = wizardPlanDone(wizardPlanItems, wizardSignals)

  // Security radio hints: the server preset description when the presets
  // endpoint answered, the short local fallback otherwise (the ids are the
  // server's; only the fallback prose is ours).
  const presetHint = (id: 'network-readonly' | 'network-off' | 'internal-only'): string => {
    const fromServer = (presets ?? []).find(p => p.ID === id)?.Description
    if (fromServer) return fromServer
    return id === 'network-readonly' ? t('welcome.wizardSecurityReadonlyHint')
      : id === 'network-off' ? t('welcome.wizardSecurityOffHint')
      : t('welcome.wizardSecurityInternalHint')
  }

  const profilesDone = (() => {
    if (wizardSignals.residencyRegion === null) return null
    const residencyMatches = wizardSignals.residencyRegion === (wizard.residency === 'none' ? '' : wizard.residency)
    if (wizard.security === 'open') return residencyMatches
    if (wizardSignals.toolPolicyCount === null) return null
    return residencyMatches && wizardSignals.toolPolicyCount > 0
  })()

  const stepStateWord = (state: boolean | null): string =>
    state === true ? t('welcome.wizardStateDone') : state === false ? t('welcome.wizardStateTodo') : t('welcome.wizardStateUnknown')

  // Apply runs the plan items in order; each item reports its own explicit
  // outcome, a failed item leaves the completed ones visible and retryable
  // (the «частичная ошибка» scenario) — and the org completed flag is NOT
  // touched here: it only flips through the live allStepsDone effect above.
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
          if (item.kind === 'residency') {
            await updateOrgResidency(org, item.id)
            next[key] = { ok: true }
          } else if (item.kind === 'pack') {
            // pkfix1 contract (review 98613b94): `config` is required
            // non-null JSON — {} = the pack's built-in rules, no overrides.
            // pack_id is sent explicitly so the wire body matches the pack
            // the review summary just showed the operator.
            await upsertPolicyPack(org, item.id, { pack_id: REGION_PACK_IDS[item.id as 'SG' | 'IN' | 'ID'], config: {} })
            next[key] = { ok: true }
          } else {
            const res = await applyToolPolicyPreset(org, item.id)
            next[key] = {
              ok: true,
              detail: t('welcome.wizardAppliedCounts', { created: res.created, skipped: res.skipped_existing }),
            }
          }
        } catch (err) {
          // The honest per-item failure state: which write failed and the
          // server's status class (never a silent skip; never success).
          const status = typeof err === 'object' && err !== null && 'status' in err
            ? String((err as { status?: unknown }).status)
            : 'network'
          next[key] = { ok: false, detail: status }
        }
        setApplyOutcomes({ ...next })
      }
      setApplyingWizard(false)
      void refreshWizardSignals(org)
    })()
  }, [org, wizard, applyingWizard, applyOutcomes, refreshWizardSignals, t])

  // ----- org flag (completed / skipped) -----
  useEffect(() => {
    if (!org) return
    let cancelled = false
    setFlag(null)
    setFlagState('loading')
    void (async () => {
      const state = await getOrgOnboarding(org)
      if (cancelled) return
      if (state === null) {
        setFlagState('unavailable') // old backend / capability off / failed read
      } else {
        setFlag(state)
        setFlagState('ready')
      }
    })()
    return () => { cancelled = true }
  }, [org])

  // ----- step detection (live, per org; TP-06 scope epoch discipline) -----
  useEffect(() => {
    setSignals({ providerKey: null, gatewayKey: null, firstRequest: null })
    completedMarkedFor.current = ''
    if (!org) return
    let cancelled = false
    void (async () => {
      const [creds, keys, stats] = await Promise.allSettled([
        listProviderCredentials(org),
        listAPIKeys(org, 1),
        requestStats({ orgId: org }),
      ])
      if (cancelled) return
      setSignals({
        providerKey: providerKeyState(creds),
        gatewayKey: gatewayKeyState(keys),
        firstRequest: firstRequestState(stats),
      })
    })()
    return () => { cancelled = true }
  }, [org])

  // ----- auto-complete: every step confirmed true → persist the mark -----
  useEffect(() => {
    if (!org || flagState !== 'ready' || !flag || flag.completed || flag.skipped) return
    if (!allStepsDone(signals)) return
    if (completedMarkedFor.current === org) return
    completedMarkedFor.current = org
    void (async () => {
      const ok = await markOrgOnboarding(org, { completed: true })
      if (ok) setFlag(prev => (prev ? { ...prev, completed: true } : prev))
    })()
  }, [org, flag, flagState, signals])

  const skip = useCallback(() => {
    if (!org || skipping) return
    setSkipping(true)
    void (async () => {
      await markOrgOnboarding(org, { skipped: true })
      // Degrade honestly: whether or not the mark persisted, the operator
      // asked to move on. An unpersisted skip resurfaces next login.
      window.location.hash = dashboardHomeLink(isRoot)
    })()
  }, [isRoot, org, skipping])

  if (!org) {
    return (
      <div className="space-y-6">
        <PageHeader title={t('welcome.title')} purpose={t('welcome.purpose')} />
        <div className="flex flex-wrap gap-3 items-end">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.orgId')}</span>
            <OrgSelect value={orgId} onChange={setOrgId} autoSelect className="sm:w-72" manualAriaLabel={t('orgSettings.orgUuid')} />
          </label>
        </div>
        <StateNotice state="not-loaded" message={t('orgSettings.notLoaded')} />
      </div>
    )
  }

  const alreadyCompleted = flagState === 'ready' && flag?.completed === true
  const previouslySkipped = flagState === 'ready' && flag?.skipped === true

  const stepHeader = (testid: string, doneState: boolean | null, index: number, title: string) => (
    <div className="flex items-center gap-3">
      <span
        aria-hidden="true"
        className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold"
        style={{
          borderColor: doneState === true ? 'var(--astra-success)' : 'var(--astra-rule-strong)',
          color: doneState === true ? 'var(--astra-success)' : 'var(--astra-text-muted)',
        }}
      >
        {doneState === true ? '✓' : index}
      </span>
      <h2
        data-testid={testid}
        className={`text-base font-semibold ${doneState === true ? 'text-[color:var(--astra-text-muted)]' : 'text-[color:var(--astra-ink)]'}`}
      >
        {title}
        {doneState === true && <span className="sr-only"> {t('onboarding.doneChip')}</span>}
      </h2>
    </div>
  )

  return (
    <div className="space-y-6" data-testid="welcome-flow">
      <PageHeader
        title={t('welcome.title')}
        purpose={t('welcome.purpose')}
        appliedScope={org}
        primaryAction={{ label: t('welcome.skip'), onClick: skip, disabled: skipping }}
      />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.orgId')}</span>
          <OrgSelect value={orgId} onChange={setOrgId} autoSelect className="sm:w-72" manualAriaLabel={t('orgSettings.orgUuid')} />
        </label>
      </div>

      {flagState === 'unavailable' && (
        <StateNotice state="partial" message={t('welcome.flagUnavailable')} />
      )}
      {previouslySkipped && !alreadyCompleted && (
        <StateNotice state="partial" message={t('welcome.skippedNote')} />
      )}

      {alreadyCompleted ? (
        <div className="astra-panel flex flex-col gap-2 p-4" data-testid="welcome-allset">
          <p className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-ink)]">
            <span aria-hidden="true" style={{ color: 'var(--astra-success)' }}>✓</span>
            {t('welcome.allSet')}
          </p>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.allSetHint')}</p>
          <a href={dashboardHomeLink(isRoot)} className="btn-primary mt-1 w-fit min-h-[44px]">
            {t('welcome.goDashboard')}
          </a>
        </div>
      ) : (
        <ol className="space-y-4" aria-label={t('welcome.title')}>
          {/* Step 1 — provider key (BYOK): deep link to the provider-keys tab. */}
          <li className="card space-y-2 p-4" data-testid="welcome-step-provider">
            {stepHeader('welcome-step-provider-title', signals.providerKey, 1, t('welcome.stepProvider'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepProviderDesc')}</p>
            <p className="text-sm" data-testid="welcome-step-provider-state">
              {/* False and null are different states (design/wizard §3):
                  confirmed to-do shows the To do word; "Checking…" stays the
                  in-flight/unknown word only — one word never means two. */}
              {signals.providerKey === true
                ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepProviderDone')}</span>
                : signals.providerKey === false
                  ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
                  : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
            </p>
            {signals.providerKey !== true && (
              <div>
                <a href={providerKeysLink(org)} className="btn-secondary min-h-[44px] w-fit" data-testid="welcome-open-provider-keys">
                  {t('welcome.stepProviderOpen')}
                </a>
              </div>
            )}
          </li>

          {/* Step 2 — gateway key: deep link to the API-keys screen. */}
          <li className="card space-y-2 p-4" data-testid="welcome-step-gateway">
            {stepHeader('welcome-step-gateway-title', signals.gatewayKey, 2, t('welcome.stepGateway'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepGatewayDesc')}</p>
            <p className="text-sm" data-testid="welcome-step-gateway-state">
              {signals.gatewayKey === true
                ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepGatewayDone')}</span>
                : signals.gatewayKey === false
                  ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
                  : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
            </p>
            {signals.gatewayKey !== true && (
              <div>
                <a href={gatewayKeysLink(org)} className="btn-secondary min-h-[44px] w-fit" data-testid="welcome-open-keys">
                  {t('welcome.stepGatewayOpen')}
                </a>
              </div>
            )}
          </li>

          {/* Step 3 — point the client at the gateway (copy blocks); the step
              confirms itself via the first-successful-request signal. */}
          <li className="card space-y-3 p-4" data-testid="welcome-step-client">
            {stepHeader('welcome-step-client-title', signals.firstRequest, 3, t('welcome.stepClient'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepClientDesc')}</p>
            <p className="text-sm" data-testid="welcome-step-client-state">
              {signals.firstRequest === true
                ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepClientDone')}</span>
                : signals.firstRequest === false
                  ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
                  : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
            </p>

            <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('welcome.clientTabs')}>
              {ONBOARDING_CLIENTS.map(id => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={client === id}
                  onClick={() => setClient(id)}
                  data-testid={`welcome-tab-${id}`}
                  className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${
                    client === id
                      ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
                      : 'border-[color:var(--astra-rule-strong)] hover:bg-[color:var(--astra-surface-muted)]'
                  }`}
                >
                  {id === 'opencode' && t('welcome.clientOpencode')}
                  {id === 'claude-code' && t('welcome.clientClaudeCode')}
                  {id === 'codex' && t('welcome.clientCodex')}
                </button>
              ))}
            </div>

            <CopyBlock
              id={client}
              text={clientConfigBlock(client)}
              copyLabel={t('welcome.copyAria', {
                client:
                  client === 'opencode' ? t('welcome.clientOpencode')
                  : client === 'claude-code' ? t('welcome.clientClaudeCode')
                  : t('welcome.clientCodex'),
              })}
            />
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('welcome.baseUrlNote')}</p>
          </li>

          {/* Step 4 — profiles: sequential privacy / security /
              deployment radio presets. Privacy maps to the residency
              endpoints, security to the tool-policy preset endpoint,
              deployment is checklist-only (infra is not dashboard-mutable,
              ratified D1). No writes happen on this step. */}
          <li className="card space-y-3 p-4" data-testid="welcome-step-profiles">
            {stepHeader('welcome-step-profiles-title', profilesDone, 4, t('welcome.wizardStepProfiles'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.wizardStepProfilesDesc')}</p>
            {wizardRootBlocked ? (
              <StateNotice state="partial" message={t('welcome.wizardRootOnly')} />
            ) : (
              <div className="grid gap-4 md:grid-cols-3">
                <RadioGroup<WizardResidencyPreset>
                  name="residency"
                  legend={t('welcome.wizardPrivacyLegend')}
                  value={wizard.residency}
                  onChange={v => { wizardTouchedResidency.current = true; setWizard(w => ({ ...w, residency: v })) }}
                  options={[
                    { value: 'none', label: t('welcome.wizardPrivacyNone'), hint: t('welcome.wizardPrivacyNoneHint') },
                    { value: 'SG', label: t('welcome.wizardPrivacySG'), hint: `${t('welcome.wizardPackPrefix')} ${REGION_PACK_IDS.SG}` },
                    { value: 'IN', label: t('welcome.wizardPrivacyIN'), hint: `${t('welcome.wizardPackPrefix')} ${REGION_PACK_IDS.IN}` },
                    { value: 'ID', label: t('welcome.wizardPrivacyID'), hint: `${t('welcome.wizardPackPrefix')} ${REGION_PACK_IDS.ID}` },
                  ]}
                />
                <RadioGroup
                  name="security"
                  legend={t('welcome.wizardSecurityLegend')}
                  value={wizard.security}
                  onChange={v => setWizard(w => ({ ...w, security: v }))}
                  options={[
                    { value: 'open', label: t('welcome.wizardSecurityOpen'), hint: t('welcome.wizardSecurityOpenHint') },
                    { value: 'network-readonly', label: t('welcome.wizardSecurityReadonly'), hint: presetHint('network-readonly') },
                    { value: 'network-off', label: t('welcome.wizardSecurityOff'), hint: presetHint('network-off') },
                    { value: 'internal-only', label: t('welcome.wizardSecurityInternal'), hint: presetHint('internal-only') },
                  ]}
                />
                <RadioGroup<WizardDeploymentPreset>
                  name="deployment"
                  legend={t('welcome.wizardDeploymentLegend')}
                  value={wizard.deployment}
                  onChange={v => setWizard(w => ({ ...w, deployment: v }))}
                  options={[
                    { value: 'compose', label: t('welcome.wizardDeployCompose') },
                    { value: 'helm', label: t('welcome.wizardDeployHelm') },
                    { value: 'managed', label: t('welcome.wizardDeployManaged') },
                  ]}
                />
              </div>
            )}
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('welcome.wizardDeployNote')}</p>
          </li>

          {/* Step 5 — policy defaults: the concrete preset/pack the
              chosen profile implies, straight from the existing presets
              endpoints (server descriptions, canonical pack ids). */}
          <li className="card space-y-3 p-4" data-testid="welcome-step-defaults">
            {stepHeader('welcome-step-defaults-title', presets !== null, 5, t('welcome.wizardStepDefaults'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.wizardStepDefaultsDesc')}</p>
            {wizardRootBlocked ? (
              <StateNotice state="partial" message={t('welcome.wizardRootOnly')} />
            ) : (
              <>
                {presets === null ? (
                  <StateNotice state="partial" message={t('welcome.wizardDefaultsUnavailable')} />
                ) : (
                  <ul className="flex flex-col gap-1" data-testid="wizard-preset-list">
                    {presets.map(p => (
                      <li
                        key={p.ID}
                        data-testid={`wizard-preset-${p.ID}`}
                        className={`rounded-[length:var(--astra-radius-control)] border px-3 py-2 text-sm ${
                          wizard.security === p.ID
                            ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)]'
                            : 'border-[color:var(--astra-rule)]'
                        }`}
                      >
                        <span style={{ fontFamily: 'var(--astra-font-code)' }}>{p.ID}</span>
                        <span className="text-[color:var(--astra-text-muted)]"> — {p.Description}</span>
                        {wizard.security === p.ID && (
                          <span className="ml-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-1.5 py-0.5 text-xs text-[color:var(--astra-text-muted)]">
                            {t('welcome.wizardPresetSelected')}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                {wizard.residency !== 'none' && (
                  <p className="text-sm" data-testid="wizard-pack-line">
                    {t('welcome.wizardPackLine', {
                      region: wizard.residency,
                      pack: REGION_PACK_IDS[wizard.residency],
                    })}
                  </p>
                )}
                <p className="text-xs text-[color:var(--astra-text-muted)]">{t('welcome.wizardDefaultsHint')}</p>
              </>
            )}
          </li>

          {/* Step 6 — review before apply: the full configuration
              visible before anything mutates; Apply runs the plan items in
              order with per-item outcomes and retry (a partial failure
              leaves completed parts done and never marks the org
              completed). */}
          <li className="card space-y-3 p-4" data-testid="welcome-step-review">
            {stepHeader('welcome-step-review-title', reviewDone, 6, t('welcome.wizardStepReview'))}
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.wizardStepReviewDesc')}</p>
            {wizardRootBlocked ? (
              <StateNotice state="partial" message={t('welcome.wizardRootOnly')} />
            ) : (
              <>
                <dl className="grid gap-2 text-sm md:grid-cols-2" data-testid="wizard-review-summary">
                  <div className="flex flex-col gap-0.5">
                    <dt className="font-medium text-[color:var(--astra-ink)]">{t('welcome.wizardReviewPrivacy')}</dt>
                    <dd className="text-[color:var(--astra-text-muted)]" data-testid="wizard-review-privacy">
                      {wizard.residency === 'none'
                        ? t('welcome.wizardNoChange')
                        : t('welcome.wizardReviewPrivacyValue', { region: wizard.residency, pack: REGION_PACK_IDS[wizard.residency] })}
                    </dd>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    <dt className="font-medium text-[color:var(--astra-ink)]">{t('welcome.wizardReviewSecurity')}</dt>
                    <dd className="text-[color:var(--astra-text-muted)]" data-testid="wizard-review-security">
                      {wizard.security === 'open' ? t('welcome.wizardNoChange') : wizard.security}
                    </dd>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    <dt className="font-medium text-[color:var(--astra-ink)]">{t('welcome.wizardReviewDeployment')}</dt>
                    <dd className="text-[color:var(--astra-text-muted)]" data-testid="wizard-review-deployment">
                      {wizard.deployment === 'compose' ? t('welcome.wizardDeployCompose')
                        : wizard.deployment === 'helm' ? t('welcome.wizardDeployHelm')
                        : t('welcome.wizardDeployManaged')}
                    </dd>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    <dt className="font-medium text-[color:var(--astra-ink)]">{t('welcome.wizardReviewKeys')}</dt>
                    <dd className="text-[color:var(--astra-text-muted)]" data-testid="wizard-review-keys">
                      {t('welcome.wizardReviewKeysState', {
                        provider: stepStateWord(signals.providerKey),
                        gateway: stepStateWord(signals.gatewayKey),
                        request: stepStateWord(signals.firstRequest),
                      })}
                    </dd>
                  </div>
                </dl>
                <p className="text-xs text-[color:var(--astra-text-muted)]">{t('welcome.wizardDeployChecklistNote')}</p>

                {wizardPlanItems.length === 0 ? (
                  <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="wizard-no-changes">
                    {t('welcome.wizardNoChanges')}
                  </p>
                ) : (
                  <>
                    <ul className="flex flex-col gap-1" data-testid="wizard-apply-list">
                      {wizardPlanItems.map(item => {
                        const key = wizardPlanItemKey(item)
                        const outcome = applyOutcomes[key]
                        const live = wizardItemLiveState(item, wizardSignals)
                        // AUDIT-P1-05: an explicit mutation outcome is the
                        // only evidence that can render this session's write
                        // applied. The removed indirect ok/failed OR-override
                        // let a residency match promote a failed pack PUT to
                        // ✓; the row recovers only through retry, and live
                        // signals answer only before any outcome exists.
                        const { ok, failed } = wizardItemDisplayState(outcome, live)
                        return (
                          <li
                            key={key}
                            data-testid={`wizard-apply-${key.replace(':', '-')}`}
                            className="flex flex-wrap items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 py-2 text-sm"
                          >
                            <span
                              aria-hidden="true"
                              style={{ color: ok ? 'var(--astra-success)' : failed ? 'var(--astra-danger)' : 'var(--astra-text-muted)' }}
                            >
                              {ok ? '✓' : failed ? '✕' : '○'}
                            </span>
                            <span style={{ fontFamily: 'var(--astra-font-code)' }}>
                              {item.kind === 'residency' ? t('welcome.wizardItemResidency', { region: item.id })
                                : item.kind === 'pack' ? t('welcome.wizardItemPack', { pack: REGION_PACK_IDS[item.id as 'SG' | 'IN' | 'ID'] })
                                : t('welcome.wizardItemPreset', { preset: item.id })}
                            </span>
                            {ok && outcome?.detail && (
                              <span className="text-xs text-[color:var(--astra-text-muted)]" data-testid={`wizard-apply-${key.replace(':', '-')}-detail`}>
                                {outcome.detail}
                              </span>
                            )}
                            {failed && !ok && (
                              <>
                                <span
                                  className="text-xs"
                                  style={{ color: 'var(--astra-danger)' }}
                                  data-testid={`wizard-apply-${key.replace(':', '-')}-failed`}
                                >
                                  {t('welcome.wizardItemFailed')}{outcome?.detail ? ` (${outcome.detail})` : ''}
                                </span>
                                {/* Per-item retry: the same apply
                                    path — already-ok items are skipped, so
                                    this retries exactly the failed write. */}
                                <button
                                  type="button"
                                  onClick={applyWizardPlan}
                                  disabled={applyingWizard}
                                  className="btn-secondary ml-auto min-h-[36px] px-2 text-xs"
                                  data-testid={`wizard-apply-${key.replace(':', '-')}-retry`}
                                >
                                  {t('welcome.wizardRetryItem')}
                                </button>
                              </>
                            )}
                            {ok && <span className="sr-only"> {t('onboarding.doneChip')}</span>}
                          </li>
                        )
                      })}
                    </ul>
                    <div>
                      <button
                        type="button"
                        onClick={applyWizardPlan}
                        disabled={applyingWizard || reviewDone === true}
                        className="btn-primary min-h-[44px] w-fit"
                        data-testid="wizard-apply"
                      >
                        {applyingWizard ? t('welcome.wizardApplying') : t('welcome.wizardApply')}
                      </button>
                    </div>
                    {Object.values(applyOutcomes).some(o => !o.ok) && (
                      <StateNotice
                        state="error"
                        message={t('welcome.wizardApplyPartial')}
                        action={{ label: t('common.retry'), onClick: applyWizardPlan }}
                      />
                    )}
                  </>
                )}
              </>
            )}
          </li>
        </ol>
      )}
    </div>
  )
}
