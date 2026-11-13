import { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { MetricHint } from './MetricHint'

// Astra primitive: MetricStrip (standards/design.md "Components and contracts").
// One horizontal band of summary metrics: value, unit, source/baseline,
// coverage/as-of, state. Unknown renders as the word "Unknown" — never as 0 —
// so a missing baseline can never masquerade as a measured one. Values are
// tabular (mono) numerals; the band is a polite live region.
//
// A metric can carry a glossary `description` (from the
// lib/analyticsQuery.ts registry); it renders as a hover/focus tooltip
// through the shared MetricHint primitive.

export type MetricState = 'ok' | 'warning' | 'error' | 'unknown' | 'loading'

export interface Metric {
  label: string
  /** Preformatted value. Pass the string "Unknown" when not measured. */
  value: ReactNode
  /** Unit shown in the label line ("USD", "req/s") — not repeated per value. */
  unit?: string
  /** Where the number comes from (baseline, price table, as-of). */
  source?: ReactNode
  /** Coverage such as "3 of 4 requests priced". */
  coverage?: ReactNode
  /** Glossary text for the "what does this mean" tooltip. */
  description?: ReactNode
  state?: MetricState
}

const stateStyles: Record<MetricState, { value: string; badge: string; glyph: string }> = {
  ok: { value: 'var(--astra-ink)', badge: 'var(--astra-success)', glyph: '●' },
  warning: { value: 'var(--astra-warning)', badge: 'var(--astra-warning)', glyph: '▲' },
  error: { value: 'var(--astra-danger)', badge: 'var(--astra-danger)', glyph: '✕' },
  unknown: { value: 'var(--astra-text-muted)', badge: 'var(--astra-text-muted)', glyph: '○' },
  loading: { value: 'var(--astra-text-muted)', badge: 'var(--astra-text-muted)', glyph: '…' },
}

export function MetricStrip({ metrics, 'aria-label': ariaLabel }: { metrics: Metric[]; 'aria-label'?: string }) {
  const { t } = useTranslation()
  return (
    // Porcelain composition: metrics are separate white cards (thin rule,
    // small radius) on the paper ground — not a divided band.
    <div
      role="group"
      aria-label={ariaLabel}
      aria-live="polite"
      className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4"
    >
      {metrics.map(m => {
        const st = m.state ?? 'ok'
        const s = stateStyles[st]
        return (
          <div key={m.label} className="astra-panel flex min-w-0 flex-col gap-1 px-4 py-4">
            <span
              className="text-[color:var(--astra-text-muted)]"
              style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)', letterSpacing: '0.04em', textTransform: 'uppercase' }}
            >
              {m.label}
              {m.unit ? <span className="font-normal normal-case"> · {m.unit}</span> : null}
              {m.description ? (
                <span className="ms-1 inline-flex translate-y-px align-middle font-normal normal-case">
                  <MetricHint label={typeof m.label === 'string' ? m.label : undefined} description={m.description} />
                </span>
              ) : null}
            </span>
            <span
              title={typeof m.value === 'string' ? m.value : undefined}
              className="overflow-wrap-anywhere min-w-0 text-2xl"
              style={{
                color: s.value,
                fontFamily: 'var(--astra-font-code)',
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {st === 'loading' ? (
                // Motion-safe so prefers-reduced-motion users
                // get a static ellipsis instead of the pulse.
                <span aria-label={t('states.loading')} className="inline-block motion-safe:animate-pulse">
                  …
                </span>
              ) : (
                <>
                  <span aria-hidden="true" className="me-1 text-sm align-middle" style={{ color: s.badge }}>
                    {s.glyph}
                  </span>
                  {m.value}
                </>
              )}
            </span>
            {(m.source || m.coverage) && (
              // fragments — they wrap, never widen the document.
              <small className="overflow-wrap-anywhere min-w-0 text-[color:var(--astra-text-muted)]" style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)' }}>
                {m.source}
                {m.source && m.coverage ? ' · ' : ''}
                {m.coverage}
              </small>
            )}
          </div>
        )
      })}
    </div>
  )
}
