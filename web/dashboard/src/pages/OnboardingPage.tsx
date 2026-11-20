import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listAPIKeys } from '../api/keys'
import { getOrgOnboarding, markOrgOnboarding, type OrgOnboarding } from '../api/onboarding'
import { listProviderCredentials } from '../api/providerCredentials'
import { requestStats } from '../api/requests'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useHashParam } from '../hooks/useHashParam'
import { usePermissions } from '../hooks/usePermissions'
import {
  allStepsDone, dashboardHomeLink, firstRequestState, gatewayKeyState, providerKeyState,
  type OnboardingClient, type OnboardingSignals,
} from '../lib/onboarding'
import { AllSetPanel } from './onboarding/AllSetPanel'
import { OnboardingSteps } from './onboarding/OnboardingSteps'
import { SetupRequestEvidence } from './onboarding/SetupRequestEvidence'
import { WizardDefaultsStep, WizardProfilesStep, WizardReviewStep } from './onboarding/WizardSteps'
import { useOnboardingWizard } from './onboarding/useOnboardingWizard'
import { useSetupRequestEvidence } from './onboarding/useSetupRequestEvidence'

// The 3-step welcome flow — (1) connect a provider key (BYOK,
// deep link to the provider-keys tab of organization settings), (2) create a
// gateway key (deep link to the API-keys screen), (3) point the client at
// the gateway (copy blocks verbatim from docs/clients/{opencode,claude-code,
// codex}.md). Steps 4–6 extend it with the profiles/defaults/review wizard.
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
//
// The step views, the shared setup-request evidence control, the completed
// panel and the wizard state machine live in ./onboarding/* — this page
// composes them and owns the org scope, the flag and the live step signals.

type FlagState = 'loading' | 'ready' | 'unavailable'

export function OnboardingPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const org = orgId.trim()
  // The setup-request identity (see useSetupRequestEvidence): URL param,
  // supplied by the operator through the wizard's own entry control below.
  const [requestIdParam, setRequestIdParam] = useHashParam('request')
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

  const evidenceIdentity = useSetupRequestEvidence(org, requestIdParam)

  // The wizard's reads/writes are the MustBeRoot app-config surfaces
  // (residency/policy-packs: router_orgs.go mountOrgsRoot; tool-policy
  // presets: router_mcp.go mountMCP), so the whole flow renders for root
  // and degrades to an honest note for everyone else — the server
  // arbitrates either way.
  const wizardRootBlocked = !perms.loading && perms.me !== null && !isRoot
  const wizard = useOnboardingWizard(org, isRoot)

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

  const evidence = (
    <SetupRequestEvidence
      org={org}
      evidenceRequest={evidenceIdentity.evidenceRequest}
      requestEntry={evidenceIdentity.requestEntry}
      setRequestEntry={evidenceIdentity.setRequestEntry}
      entryState={evidenceIdentity.entryState}
      setRequestIdParam={setRequestIdParam}
    />
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
        <AllSetPanel isRoot={isRoot} evidence={evidence} />
      ) : (
        <ol className="space-y-4" aria-label={t('welcome.title')}>
          <OnboardingSteps org={org} signals={signals} evidence={evidence} client={client} setClient={setClient} />
          <WizardProfilesStep
            wizardRootBlocked={wizardRootBlocked}
            profilesDone={wizard.profilesDone}
            wizard={wizard.wizard}
            setWizard={wizard.setWizard}
            onResidencyChange={wizard.onResidencyChange}
            presetHint={wizard.presetHint}
          />
          <WizardDefaultsStep wizardRootBlocked={wizardRootBlocked} presets={wizard.presets} wizard={wizard.wizard} />
          <WizardReviewStep
            wizardRootBlocked={wizardRootBlocked}
            wizard={wizard.wizard}
            signals={signals}
            wizardSignals={wizard.wizardSignals}
            wizardPlanItems={wizard.wizardPlanItems}
            reviewDone={wizard.reviewDone}
            applyOutcomes={wizard.applyOutcomes}
            applyingWizard={wizard.applyingWizard}
            applyWizardPlan={wizard.applyWizardPlan}
          />
        </ol>
      )}
    </div>
  )
}
