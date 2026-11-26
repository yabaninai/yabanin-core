import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { CopyBlock } from '../../components/CopyBlock'
import {
  ONBOARDING_CLIENTS, budgetsLink, clientConfigBlock, gatewayKeysLink, providerKeysLink,
  type OnboardingClient, type OnboardingSignals,
} from '../../lib/onboarding'
import { FirstTeamBudget } from '../budgets/FirstTeamBudget.tsx'
import { StepHeader } from './StepHeader'

// The first three welcome steps (org-scoped reads, visible to every
// operator): (1) provider key BYOK deep link, (2) gateway key deep link,
// (3) point the client at the gateway + the shared setup-request evidence
// control (CUI-02).

function ProviderKeyStep({ org, state }: { org: string; state: boolean | null }): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-2 p-4" data-testid="welcome-step-provider">
      {/* Step 1 — provider key (BYOK): deep link to the provider-keys tab. */}
      <StepHeader testid="welcome-step-provider-title" doneState={state} index={1} title={t('welcome.stepProvider')} />
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepProviderDesc')}</p>
      <p className="text-sm" data-testid="welcome-step-provider-state">
        {/* False and null are different states (design/wizard §3):
            confirmed to-do shows the To do word; "Checking…" stays the
            in-flight/unknown word only — one word never means two. */}
        {state === true
          ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepProviderDone')}</span>
          : state === false
            ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
            : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
      </p>
      {state !== true && (
        <div>
          <a href={providerKeysLink(org)} className="btn-secondary min-h-[44px] w-fit" data-testid="welcome-open-provider-keys">
            {t('welcome.stepProviderOpen')}
          </a>
        </div>
      )}
    </li>
  )
}

function GatewayKeyStep({ org, state }: { org: string; state: boolean | null }): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-2 p-4" data-testid="welcome-step-gateway">
      {/* Step 2 — gateway key: deep link to the API-keys screen. */}
      <StepHeader testid="welcome-step-gateway-title" doneState={state} index={2} title={t('welcome.stepGateway')} />
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepGatewayDesc')}</p>
      <p className="text-sm" data-testid="welcome-step-gateway-state">
        {state === true
          ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepGatewayDone')}</span>
          : state === false
            ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
            : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
      </p>
      {state !== true && (
        <div>
          <a href={gatewayKeysLink(org)} className="btn-secondary min-h-[44px] w-fit" data-testid="welcome-open-keys">
            {t('welcome.stepGatewayOpen')}
          </a>
        </div>
      )}
    </li>
  )
}

function ClientTabs({ client, setClient }: { client: OnboardingClient; setClient: (c: OnboardingClient) => void }): ReactNode {
  const { t } = useTranslation()
  return (
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
  )
}

// Step 3 — point the client at the gateway (copy blocks); the step
// confirms itself via the first-successful-request signal. The selected
// client is page-level state so it survives a completed/pending view
// flip exactly as before the split.
export function ClientSetupStep({ org, state, evidence, client, setClient }: {
  org: string
  state: boolean | null
  evidence: ReactNode
  client: OnboardingClient
  setClient: (c: OnboardingClient) => void
}): ReactNode {
  const { t } = useTranslation()
  return (
    <li className="card space-y-3 p-4" data-testid="welcome-step-client">
      <StepHeader testid="welcome-step-client-title" doneState={state} index={3} title={t('welcome.stepClient')} />
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.stepClientDesc')}</p>
      <p className="text-sm" data-testid="welcome-step-client-state">
        {state === true
          ? <span style={{ color: 'var(--astra-success)' }}>{t('welcome.stepClientDone')}</span>
          : state === false
            ? <span className="text-[color:var(--astra-text-muted)]">{t('welcome.wizardStateTodo')}</span>
            : <span className="text-[color:var(--astra-text-muted)]">{t('welcome.stateChecking')}</span>}
      </p>
      {/* CUI-02: the shared operator entry control (defined once with
          the completed view — same input, same validation action). */}
      {evidence}
      <ClientTabs client={client} setClient={setClient} />
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
      {/* CUI-02: without a team budget the first request is rejected 403
          budget_not_configured — say so up front and deep-link the fix. */}
      <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="welcome-step-budget-note">
        {t('welcome.budgetNote')}{' '}
        <a href={budgetsLink(org)} className="underline" data-testid="welcome-open-budgets">{t('welcome.openBudgets')}</a>
      </p>
      {/* The missing first-budget path itself: the write binds to the
          setup key's server-set team, explicitly confirmed (see
          pages/budgets/FirstTeamBudget.tsx). */}
      <FirstTeamBudget org={org} />
    </li>
  )
}

// Steps 1–3 as one <li> run inside the welcome <ol> (org-scoped reads —
// these render for every operator, root or not).
export function OnboardingSteps({ org, signals, evidence, client, setClient }: {
  org: string
  signals: OnboardingSignals
  evidence: ReactNode
  client: OnboardingClient
  setClient: (c: OnboardingClient) => void
}): ReactNode {
  return (
    <>
      <ProviderKeyStep org={org} state={signals.providerKey} />
      <GatewayKeyStep org={org} state={signals.gatewayKey} />
      <ClientSetupStep org={org} state={signals.firstRequest} evidence={evidence} client={client} setClient={setClient} />
    </>
  )
}
