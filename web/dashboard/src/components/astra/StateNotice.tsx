import { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

// Astra primitive: StateNotice (standards/design.md "Components and contracts").
// not loaded / loading / empty / stale / partial / error — each with an exact
// next action, no false success. Color is never the only carrier: every state
// has a shape glyph AND a text label.

export type NoticeState = 'not-loaded' | 'loading' | 'empty' | 'stale' | 'partial' | 'error' | 'warning'

export interface StateNoticeProps {
  state: NoticeState
  /** Short label; defaults to the state name. */
  title?: string
  /** What exactly happened / what is (not) shown. */
  message?: ReactNode
  /** The one useful next action, if any. */
  action?: { label: string; onClick?: () => void }
  /** Additional detail lines (e.g. which part is missing in `partial`). */
  details?: ReactNode
}

const defaults: Record<NoticeState, { glyph: string; titleKey: string; color: string }> = {
  'not-loaded': { glyph: '○', titleKey: 'states.notLoaded', color: 'var(--astra-text-muted)' },
  loading: { glyph: '…', titleKey: 'states.loading', color: 'var(--astra-text-muted)' },
  empty: { glyph: '∅', titleKey: 'states.noData', color: 'var(--astra-text-muted)' },
  stale: { glyph: '△', titleKey: 'states.outdated', color: 'var(--astra-warning)' },
  warning: { glyph: '△', titleKey: 'states.attention', color: 'var(--astra-warning)' },
  partial: { glyph: '◐', titleKey: 'states.partialData', color: 'var(--astra-info)' },
  error: { glyph: '✕', titleKey: 'states.failedToLoad', color: 'var(--astra-danger)' },
}

export function StateNotice({ state, title, message, action, details }: StateNoticeProps) {
  const { t } = useTranslation()
  const d = defaults[state]
  // Porcelain treatment: solid white panel; semantic states carry an
  // additional left bar in the state color (never the only carrier — the
  // glyph and the text label remain).
  const bar = state === 'stale' || state === 'warning' || state === 'partial' || state === 'error'
  return (
    <div
      role="status"
      className="astra-panel flex flex-col gap-1 px-4 py-5"
      style={bar ? { borderLeft: `3px solid ${d.color}` } : undefined}
    >
      <span className="flex items-center gap-2 text-sm font-medium text-[color:var(--astra-ink)]">
        <span aria-hidden="true" style={{ color: d.color }}>
          {d.glyph}
        </span>
        {title ?? t(d.titleKey)}
      </span>
      {message && <p className="text-sm text-[color:var(--astra-text-muted)]">{message}</p>}
      {details && <div className="text-[color:var(--astra-text-muted)]" style={{ font: 'var(--astra-font-small)/1.4 var(--astra-font-ui)' }}>{details}</div>}
      {action && (
        <button
          type="button"
          onClick={action.onClick}
          className="btn-secondary mt-1 w-fit"
        >
          {action.label}
        </button>
      )}
    </div>
  )
}
