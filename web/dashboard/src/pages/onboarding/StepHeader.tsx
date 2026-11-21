import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

export function StepHeader({ testid, doneState, index, title }: {
  testid: string
  doneState: boolean | null
  index: number
  title: string
}): ReactNode {
  const { t } = useTranslation()
  return (
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
}
