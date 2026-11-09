import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { OrgSelect } from './OrgSelect'
import { applyOrgFallback, useGlobalScope } from '../lib/globalScope'
import { GLOBAL_PRESETS } from '../lib/globalScope'
import type { PeriodPreset } from '../lib/analyticsQuery'

export { GLOBAL_PRESETS }

// AUX-08: the shared GlobalScope control (plan «Анатомия страницы данных» —
// "GlobalScope org · период · timezone, общий для всех страниц, в URL"). The
// state lives in the scope store (lib/globalScope.ts: hash + memory), so the
// operator picks org and period once and every scoped screen follows; a deep
// link with explicit params always wins over the remembered values.
//
// AUX-04 honesty: `fields` decides which controls render — a field a screen's
// endpoints ignore is never shown (e.g. the requests list takes no tz).

export type GlobalScopeField = 'org' | 'period' | 'tz'

export function GlobalScopeBar({ fields, orgLabel }: { fields: GlobalScopeField[]; /** Label override (e.g. a screen's established "Organization ID" wording). */ orgLabel?: string }) {
  const { t } = useTranslation()
  const scope = useGlobalScope()
  const showOrg = fields.includes('org')
  const showPeriod = fields.includes('period')
  const showTz = fields.includes('tz')
  // The tz input commits on blur/Enter (the ScopeBar draft contract) — every
  // keystroke would otherwise refetch the screen's data.
  const [tzDraft, setTzDraft] = useState(scope.tz)
  useEffect(() => { setTzDraft(scope.tz) }, [scope.tz])
  // 'custom' is a state, not a choice: it appears in the list only when the
  // applied window was pinned by hand or by a deep link (never a no-op item).
  const periodOptions: PeriodPreset[] = scope.period === 'custom'
    ? [...GLOBAL_PRESETS, 'custom']
    : [...GLOBAL_PRESETS]
  return (
    <>
      {showOrg && (
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{orgLabel ?? t('scope.organization')}</span>
          <OrgSelect
            value={scope.org}
            onChange={scope.setOrg}
            onAutoSelect={applyOrgFallback}
            autoSelect
            className="w-64"
          />
        </label>
      )}
      {showPeriod && (
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('scope.period')}</span>
          <select
            value={scope.period}
            aria-label={t('scope.period')}
            onChange={e => { if (e.target.value !== 'custom') scope.setPeriod(e.target.value as Exclude<PeriodPreset, 'custom'>) }}
            className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3"
          >
            {periodOptions.map(p => (
              <option key={p} value={p}>{t(`analytics.preset.${p}`)}</option>
            ))}
          </select>
        </label>
      )}
      {showTz && (
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('scope.timezone')}</span>
          <input
            value={tzDraft}
            onChange={e => setTzDraft(e.target.value)}
            onBlur={() => { if (tzDraft.trim() !== scope.tz) scope.setTz(tzDraft.trim()) }}
            onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
            placeholder={t('scope.utc')}
            className="control sm:w-28"
          />
        </label>
      )}
    </>
  )
}
