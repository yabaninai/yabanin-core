import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { StateNotice } from '../../components/astra/StateNotice'
import {
  REGION_PACK_IDS,
  type OnboardingSignals, type WizardApplyOutcome, type WizardDeploymentPreset, type WizardPlanItem,
  type WizardResidencyPreset, type WizardSelection, type WizardSignals,
  wizardItemDisplayState, wizardItemLiveState, wizardPlanItemKey,
} from '../../lib/onboarding'
import { StepHeader } from './StepHeader'

type Translate = ReturnType<typeof useTranslation>['t']

function stepStateWord(t: Translate, state: boolean | null): string {
  return state === true ? t('welcome.wizardStateDone') : state === false ? t('welcome.wizardStateTodo') : t('welcome.wizardStateUnknown')
}

function RadioGroup<V extends string>({ name, legend, value, onChange, options }: {
  name: string
  legend: string
  value: V
  onChange: (v: V) => void
  options: { value: V; label: string; hint?: string }[]
}): ReactNode {
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

// Step 4 — profiles: sequential privacy / security / deployment radio
// presets. Privacy maps to the residency endpoints, security to the
// tool-policy preset endpoint, deployment is checklist-only (infra is
// not dashboard-mutable, ratified D1). No writes happen on this step.
export function WizardProfilesStep({ wizardRootBlocked, profilesDone, wizard, setWizard, onResidencyChange, presetHint }: {
  wizardRootBlocked: boolean
  profilesDone: boolean | null
  wizard: WizardSelection
  setWizard: (updater: (w: WizardSelection) => WizardSelection) => void
  onResidencyChange: (v: WizardResidencyPreset) => void
  presetHint: (id: 'network-readonly' | 'network-off' | 'internal-only') => string
}): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-3 p-4" data-testid="welcome-step-profiles">
      <StepHeader testid="welcome-step-profiles-title" doneState={profilesDone} index={4} title={t('welcome.wizardStepProfiles')} />
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.wizardStepProfilesDesc')}</p>
      {wizardRootBlocked ? (
        <StateNotice state="partial" message={t('welcome.wizardRootOnly')} />
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          <RadioGroup<WizardResidencyPreset>
            name="residency"
            legend={t('welcome.wizardPrivacyLegend')}
            value={wizard.residency}
            onChange={onResidencyChange}
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
  )
}

// Step 5 — policy defaults: the concrete preset/pack the chosen profile
// implies, straight from the existing presets endpoints (server
// descriptions, canonical pack ids).
export function WizardDefaultsStep({ wizardRootBlocked, presets, wizard }: {
  wizardRootBlocked: boolean
  presets: { ID: string; Description: string }[] | null
  wizard: WizardSelection
}): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-3 p-4" data-testid="welcome-step-defaults">
      <StepHeader testid="welcome-step-defaults-title" doneState={presets !== null} index={5} title={t('welcome.wizardStepDefaults')} />
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
  )
}

// Single source for the apply-row state glyph: one place pairs the
// ok/failed/unknown glyph with its color token.
function glyphFor(ok: boolean, failed: boolean): { glyph: string; color: string } {
  return {
    glyph: ok ? '✓' : failed ? '✕' : '○',
    color: ok ? 'var(--astra-success)' : failed ? 'var(--astra-danger)' : 'var(--astra-text-muted)',
  }
}

// One apply-list row. AUDIT-P1-05: an explicit mutation outcome is the
// only evidence that can render this session's write applied. The
// removed indirect ok/failed OR-override let a residency match promote
// a failed pack PUT to ✓; the row recovers only through retry, and live
// signals answer only before any outcome exists.
function WizardApplyItem({ item, outcome, live, onRetry, retryDisabled }: {
  item: WizardPlanItem
  outcome: WizardApplyOutcome | undefined
  live: boolean | null
  onRetry: () => void
  retryDisabled: boolean
}): ReactNode {
  const { t } = useTranslation()
  const key = wizardPlanItemKey(item)
  const { ok, failed } = wizardItemDisplayState(outcome, live)
  const { glyph, color } = glyphFor(ok, failed)
  const idBase = `wizard-apply-${key.replace(':', '-')}`
  return (
    <li
      data-testid={idBase}
      className="flex flex-wrap items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 py-2 text-sm"
    >
      <span aria-hidden="true" style={{ color }}>{glyph}</span>
      <span style={{ fontFamily: 'var(--astra-font-code)' }}>
        {item.kind === 'residency' ? t('welcome.wizardItemResidency', { region: item.id })
          : item.kind === 'pack' ? t('welcome.wizardItemPack', { pack: REGION_PACK_IDS[item.id as 'SG' | 'IN' | 'ID'] })
          : t('welcome.wizardItemPreset', { preset: item.id })}
      </span>
      {ok && outcome?.detail && (
        <span className="text-xs text-[color:var(--astra-text-muted)]" data-testid={`${idBase}-detail`}>
          {outcome.detail}
        </span>
      )}
      {failed && !ok && (
        <>
          <span
            className="text-xs"
            style={{ color: 'var(--astra-danger)' }}
            data-testid={`${idBase}-failed`}
          >
            {t('welcome.wizardItemFailed')}{outcome?.detail ? ` (${outcome.detail})` : ''}
          </span>
          {/* Per-item retry: the same apply path — already-ok items are
              skipped, so this retries exactly the failed write. */}
          <button
            type="button"
            onClick={onRetry}
            disabled={retryDisabled}
            className="btn-secondary ml-auto min-h-[36px] px-2 text-xs"
            data-testid={`${idBase}-retry`}
          >
            {t('welcome.wizardRetryItem')}
          </button>
        </>
      )}
      {ok && <span className="sr-only"> {t('onboarding.doneChip')}</span>}
    </li>
  )
}

// The review summary shown before anything mutates.
function WizardReviewSummary({ wizard, signals }: { wizard: WizardSelection; signals: OnboardingSignals }): ReactNode {
  const { t } = useTranslation()
  return (
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
            provider: stepStateWord(t, signals.providerKey),
            gateway: stepStateWord(t, signals.gatewayKey),
            request: stepStateWord(t, signals.firstRequest),
          })}
        </dd>
      </div>
    </dl>
  )
}

// Step 6 — review before apply: the full configuration visible before
// anything mutates; Apply runs the plan items in order with per-item
// outcomes and retry (a partial failure leaves completed parts done and
// never marks the org completed).
export function WizardReviewStep({ wizardRootBlocked, wizard, signals, wizardPlanItems, reviewDone, applyOutcomes, applyingWizard, applyWizardPlan, wizardSignals }: {
  wizardRootBlocked: boolean
  wizard: WizardSelection
  signals: OnboardingSignals
  wizardSignals: WizardSignals
  wizardPlanItems: WizardPlanItem[]
  reviewDone: boolean | null
  applyOutcomes: Record<string, WizardApplyOutcome>
  applyingWizard: boolean
  applyWizardPlan: () => void
}): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-3 p-4" data-testid="welcome-step-review">
      <StepHeader testid="welcome-step-review-title" doneState={reviewDone} index={6} title={t('welcome.wizardStepReview')} />
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.wizardStepReviewDesc')}</p>
      {wizardRootBlocked ? (
        <StateNotice state="partial" message={t('welcome.wizardRootOnly')} />
      ) : (
        <>
          <WizardReviewSummary wizard={wizard} signals={signals} />
          <p className="text-xs text-[color:var(--astra-text-muted)]">{t('welcome.wizardDeployChecklistNote')}</p>

          {wizardPlanItems.length === 0 ? (
            <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="wizard-no-changes">
              {t('welcome.wizardNoChanges')}
            </p>
          ) : (
            <>
              <ul className="flex flex-col gap-1" data-testid="wizard-apply-list">
                {wizardPlanItems.map(item => (
                  <WizardApplyItem
                    key={wizardPlanItemKey(item)}
                    item={item}
                    outcome={applyOutcomes[wizardPlanItemKey(item)]}
                    live={wizardItemLiveState(item, wizardSignals)}
                    onRetry={applyWizardPlan}
                    retryDisabled={applyingWizard}
                  />
                ))}
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
  )
}
