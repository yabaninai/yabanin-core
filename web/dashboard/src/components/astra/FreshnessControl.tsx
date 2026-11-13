import { useTranslation } from 'react-i18next'
import { AUTO_REFRESH_OPTIONS, formatAsOfTime } from '../../lib/freshness'
import { uiLocale } from '../../i18n/format'

// Astra companion for the data screens: «данные на ЧЧ:ММ» + a manual
// refresh button + the auto-refresh selector. Rendered inside PageHeader's
// freshness slot, next to the page actions. The time label is honest by
// construction: it is set by the screen on every SUCCESSFUL load and gains
// the explicit "refresh failed" marker when a refresh errored (the last good
// data stays on screen — it is not wiped by the failure).

export interface FreshnessControlProps {
  /** Epoch ms of the last successful load; null = nothing loaded yet. */
  asOf: number | null
  /** True when the last refresh (manual or auto) failed — honest stale marker. */
  stale?: boolean
  /** True while a load is in flight — the refresh button is disabled. */
  loading?: boolean
  /** True when refreshing is impossible (e.g. no org selected on Requests). */
  disabled?: boolean
  onRefresh: () => void
  intervalMs: number
  onIntervalChange: (ms: number) => void
}

export function FreshnessControl({
  asOf,
  stale = false,
  loading = false,
  disabled = false,
  onRefresh,
  intervalMs,
  onIntervalChange,
}: FreshnessControlProps) {
  const { t } = useTranslation()
  return (
    <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
      {asOf != null && (
        // The label can wrap inside the header instead of
        // growing the document past the viewport at 360px.
        <span
          role="status"
          data-testid="freshness-asof"
          className="overflow-wrap-anywhere min-w-0 text-sm text-[color:var(--astra-text-muted)]"
          style={{ font: '11px/1.4 var(--astra-font-code)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
        >
          {t('freshness.asOf', { time: formatAsOfTime(asOf, uiLocale()) })}
          {stale ? ` · ${t('freshness.stale')}` : ''}
        </span>
      )}
      <button
        type="button"
        className="btn-secondary"
        onClick={onRefresh}
        disabled={disabled || loading}
        aria-label={t('freshness.refresh')}
        title={t('freshness.refresh')}
      >
        ⟳
      </button>
      <label className="flex min-w-0 items-center gap-1 text-sm">
        <span className="overflow-wrap-anywhere text-[color:var(--astra-text-muted)]">{t('freshness.auto')}</span>
        <select
          value={String(intervalMs)}
          onChange={e => onIntervalChange(Number(e.target.value))}
          aria-label={t('freshness.auto')}
          className="control max-w-full"
        >
          {AUTO_REFRESH_OPTIONS.map(o => (
            <option key={o.ms} value={String(o.ms)}>{t(o.labelKey)}</option>
          ))}
        </select>
      </label>
    </div>
  )
}
