import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useDisclosureDismiss } from './disclosure'

// at most one primary action in the row, everything else lives here).
//
// Contract:
//   * items carry a risk level (the AUX-12 ActionRisk vocabulary): `high`
//     renders in the danger token (destructive/irreversible), `medium`
//     gets a warning glyph; the risk decision itself (dialog, type-the-name,
//     reason) stays with the page's useAction/ActionDialog flow;
//   * the disclosure follows the shared AUX-06 dismissal pattern
//     (useDisclosureDismiss): Escape closes and refocuses the «⋯» toggle,
//     an outside click closes while letting that click land;
//   * plain buttons in a disclosure (no menu roving) — the same ARIA shape
//     as the Table settings / Views menus, so keyboard parity is identical.

export type RowActionRisk = 'low' | 'medium' | 'high'

export interface RowActionItem {
  /** Stable item id (the React key). */
  id: string
  label: string
  /** Risk level for styling; default 'low'. */
  risk?: RowActionRisk
  disabled?: boolean
  onSelect: () => void
}

export function RowActions({ items, label }: { items: RowActionItem[]; label?: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const toggleRef = useRef<HTMLButtonElement>(null)
  useDisclosureDismiss(open, rootRef, toggleRef, () => setOpen(false))

  const closeAndRun = (item: RowActionItem) => {
    setOpen(false)
    toggleRef.current?.focus()
    item.onSelect()
  }

  if (items.length === 0) return null

  return (
    <div className="relative" ref={rootRef}>
      <button
        type="button"
        ref={toggleRef}
        aria-label={label ?? t('common.actions')}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="inline-flex h-9 w-9 items-center justify-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] text-base text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
      >
        <span aria-hidden="true">⋯</span>
      </button>
      {open && (
        <div
          role="menu"
          aria-label={label ?? t('common.actions')}
          className="astra-menu-pop flex w-56 max-w-[calc(100vw-2rem)] flex-col gap-0.5 !p-1"
        >
          {items.map(item => {
            const risk = item.risk ?? 'low'
            return (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                disabled={item.disabled}
                onClick={() => closeAndRun(item)}
                className={`inline-flex min-h-[36px] items-center gap-2 rounded-[length:var(--astra-radius-control)] px-2 text-start text-sm hover:bg-[color:var(--astra-surface-muted)] disabled:cursor-not-allowed disabled:text-[color:var(--astra-text-muted)] ${
                  risk === 'high' ? 'text-[color:var(--astra-danger)]' : 'text-[color:var(--astra-ink)]'
                }`}
              >
                {risk === 'medium' && <span aria-hidden="true" className="text-[color:var(--astra-text-muted)]">⚠</span>}
                <span className="min-w-0 truncate">{item.label}</span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
