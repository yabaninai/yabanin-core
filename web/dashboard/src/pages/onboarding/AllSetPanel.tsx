import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { dashboardHomeLink } from '../../lib/onboarding'

interface AllSetPanelProps {
  isRoot: boolean
  /** The shared setup-request entry/evidence control (same action as the pending view). */
  evidence: ReactNode
}

// The completed view of the welcome flow. The evidence control stays
// available here: a plain reopen of a completed org can still attach or
// correct its setup-request identity (the verified link renders when the
// entered id validates).
export function AllSetPanel(props: AllSetPanelProps): ReactNode {
  const { t } = useTranslation()
  return (
    <div className="astra-panel flex flex-col gap-2 p-4" data-testid="welcome-allset">
      <p className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-ink)]">
        <span aria-hidden="true" style={{ color: 'var(--astra-success)' }}>✓</span>
        {t('welcome.allSet')}
      </p>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('welcome.allSetHint')}</p>
      {/* Same entry/validation action as the pending view: a completed
          org can still attach or correct its setup-request identity on
          a plain reopen (the verified link below stays when present). */}
      {props.evidence}
      <a href={dashboardHomeLink(props.isRoot)} className="btn-primary w-fit min-h-[44px]">
        {t('welcome.goDashboard')}
      </a>
    </div>
  )
}
