import { ReactNode } from 'react'

// Astra primitive: PageHeader (standards/design.md "Components and contracts").
// Title, purpose, applied scope and usually one primary action. Sans UI,
// title 28-36px/1.15, mono for the applied-scope line. Never used inside
// tables or cards.
//
// …» entry point (it opens a FormDrawer) — always the single filled button,
// rendered before any secondary actions. The applied-scope line is mono but
// NOT uppercased: it carries identifiers (org names, ids, periods) and
// uppercasing both misreads them and breaks copy fidelity.

export interface PageHeaderAction {
  label: string
  onClick?: () => void
  /** Marks the single primary action (filled). At most one should be primary. */
  primary?: boolean
  disabled?: boolean
}

export interface PageHeaderProps {
  title: string
  /** One line: what this page is for. Muted, optional. */
  purpose?: string
  /** The applied scope (org / environment / period / timezone) as text. */
  appliedScope?: ReactNode
  /** The single primary action (v2: «Создать …», opens a FormDrawer). */
  primaryAction?: PageHeaderAction
  actions?: PageHeaderAction[]
  /** Freshness slot: «данные на ЧЧ:ММ» · ⟳ · auto-refresh selector
      (FreshnessControl). Sits before the action buttons in the action group. */
  freshness?: ReactNode
}

export function PageHeader({ title, purpose, appliedScope, primaryAction, actions = [], freshness }: PageHeaderProps) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4 border-b border-[color:var(--astra-rule)] pb-4">
      <div className="min-w-0">
        <h1
          className="text-3xl font-semibold tracking-tight text-[color:var(--astra-ink)]"
          style={{ lineHeight: 1.15 }}
        >
          {title}
        </h1>
        {purpose && (
          <p className="mt-1 text-sm text-[color:var(--astra-text-muted)]">{purpose}</p>
        )}
        {appliedScope != null && appliedScope !== '' && (
          // Text-enlarge safe: overflow-wrap so long scope strings
          // (org ids, key versions) break instead of pushing the header wider.
          // Mono, letter-spaced, but verbatim case — no uppercase for IDs.
          <p
            className="mt-2 overflow-wrap-anywhere text-[color:var(--astra-text-muted)]"
            style={{
              font: '11px/1.4 var(--astra-font-code)',
              letterSpacing: '0.04em',
            }}
          >
            {appliedScope}
          </p>
        )}
      </div>
      {(primaryAction != null || actions.length > 0 || freshness != null) && (
        // Text-enlarge safe: min-w-0 + max-w-full (not shrink-0) so the
        // action group wraps to its own line and the buttons wrap inside it
        // instead of growing the header — and the document — past the viewport
        // when the root font is enlarged.
        <div className="flex min-w-0 max-w-full flex-wrap items-center gap-3">
          {freshness}
          {primaryAction && (
            <button
              type="button"
              onClick={primaryAction.onClick}
              disabled={primaryAction.disabled}
              className="btn-primary"
            >
              {primaryAction.label}
            </button>
          )}
          {actions.map(a => (
            <button
              key={a.label}
              type="button"
              onClick={a.onClick}
              disabled={a.disabled}
              className={a.primary ? 'btn-primary' : 'btn-secondary'}
            >
              {a.label}
            </button>
          ))}
        </div>
      )}
    </header>
  )
}
