import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useDisclosureDismiss } from './disclosure'
import type { TableDensity } from '../../lib/tablePrefs'

// AUX-22 — the per-table «Table settings» disclosure: column visibility
// (checkboxes), row density (compact/comfortable) and the "Reset to default"
// action. Pure controlled UI — the state and its localStorage persistence
// live with the page via lib/tablePrefs (useTablePrefs), so the same hidden
// list also drives the page's CSV exports.
//
// Contract: Escape closes and returns focus to the toggle; a click outside
// closes (useDisclosureDismiss — the AUX-06 disclosure pattern, generalized
// to close on click so the first click on an outside control still lands).
// The last visible column cannot be hidden — an empty table is never a state
// the operator can reach by accident.

export interface TableColumnOption {
  key: string
  header: string
}

export interface TableSettingsMenuProps {
  columns: TableColumnOption[]
  hiddenColumnIds: ReadonlyArray<string>
  onHiddenChange: (next: string[]) => void
  density: TableDensity
  onDensityChange: (density: TableDensity) => void
  /** Clears every stored pref for the table (visibility + density). */
  onReset: () => void
}

export function TableSettingsMenu({
  columns, hiddenColumnIds, onHiddenChange, density, onDensityChange, onReset,
}: TableSettingsMenuProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const toggleRef = useRef<HTMLButtonElement>(null)
  useDisclosureDismiss(open, menuRef, toggleRef, () => setOpen(false))

  const hidden = new Set(hiddenColumnIds)
  const toggleColumn = (key: string) => {
    if (hidden.has(key)) {
      onHiddenChange(hiddenColumnIds.filter(k => k !== key))
      return
    }
    // The last visible column stays: hiding it would blank the table.
    if (columns.length - hidden.size <= 1) return
    onHiddenChange([...hiddenColumnIds, key])
  }

  const menuId = 'table-settings-menu'
  const densityName = 'table-density'
  const lastVisible = columns.length - hidden.size <= 1

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        ref={toggleRef}
        className="btn-secondary min-h-[44px]"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen(o => !o)}
      >
        {t('table.settingsMenu')} ▾
      </button>
      {open && (
        <div
          id={menuId}
          className="astra-menu-pop flex max-h-[70vh] w-72 max-w-[calc(100vw-2rem)] flex-col gap-3 overflow-auto"
        >
          <fieldset className="flex flex-col gap-1">
            <legend className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('table.columns')}</legend>
            {columns.map(c => {
              const visible = !hidden.has(c.key)
              return (
                <label key={c.key} className="inline-flex min-h-[36px] items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={visible}
                    onChange={() => toggleColumn(c.key)}
                    disabled={visible && lastVisible}
                  />
                  <span className={visible ? undefined : 'text-[color:var(--astra-text-muted)]'}>{c.header}</span>
                </label>
              )
            })}
            {lastVisible && (
              <p className="text-xs text-[color:var(--astra-text-muted)]">{t('table.lastColumn')}</p>
            )}
          </fieldset>
          <hr className="border-[color:var(--astra-rule)]" />
          <fieldset className="flex flex-col gap-1">
            <legend className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('table.density')}</legend>
            <label className="inline-flex min-h-[36px] items-center gap-2 text-sm">
              <input
                type="radio"
                name={densityName}
                value="comfortable"
                checked={density === 'comfortable'}
                onChange={() => onDensityChange('comfortable')}
              />
              <span>{t('table.densityComfortable')}</span>
            </label>
            <label className="inline-flex min-h-[36px] items-center gap-2 text-sm">
              <input
                type="radio"
                name={densityName}
                value="compact"
                checked={density === 'compact'}
                onChange={() => onDensityChange('compact')}
              />
              <span>{t('table.densityCompact')}</span>
            </label>
          </fieldset>
          <hr className="border-[color:var(--astra-rule)]" />
          <button
            type="button"
            className="btn-secondary min-h-[44px]"
            onClick={() => {
              onReset()
              setOpen(false)
              toggleRef.current?.focus()
            }}
          >
            {t('table.resetToDefault')}
          </button>
        </div>
      )}
    </div>
  )
}
