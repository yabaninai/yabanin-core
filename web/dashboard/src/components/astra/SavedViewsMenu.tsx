import { useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useAction } from './ActionDialog'
import { useDisclosureDismiss } from './disclosure'

// AUX-22 — the general «Виды ▾» saved-views menu (the AUX-06 Analytics
// disclosure, generalized into the shared contract component). One UI, two
// storage backends (lib/savedViews.ts):
//   * Analytics passes its SERVER views (shareable, audited) — the reason
//     input stays on its dialogs via `collectReason`;
//   * other data pages pass the localStorage registry operations.
// Rename runs as a medium-risk AUX-12 dialog (prefilled name input), delete
// as a high-risk one (type-the-name confirmation) — the AUX-12 dialogs, no
// legacy browser popups. Escape closes and returns focus to the toggle; a
// click outside closes (useDisclosureDismiss).

export interface SavedViewMenuItem {
  id: string
  name: string
  /** Full display label (defaults to the name; Analytics decorates shared views). */
  label?: ReactNode
}

export interface SavedViewsMenuLabels {
  /** Toggle button (defaults to t('views.menu')). */
  menu?: ReactNode
  /** Accessible name of the disclosure region (defaults to t('views.menuLabel')). */
  menuLabel?: string
  section?: ReactNode
  empty?: ReactNode
  /** Name-input label (plain string — it labels the dialog input too). */
  name?: string
  save?: ReactNode
  /** Dialog titles + per-view action buttons (plain strings). */
  rename?: string
  delete?: string
  /** Delete-dialog impact line; defaults to t('views.deleteConfirm', {name}). */
  deleteImpact?: (name: string) => ReactNode
}

export interface SavedViewsMenuProps {
  menuId: string
  views: SavedViewMenuItem[]
  onApply: (view: SavedViewMenuItem) => void
  /** Resolves when the view is stored; rejections are surfaced by the caller. */
  onSave: (name: string) => void | Promise<void>
  /** `reason` carries the optional operator reason (X-Audit-Reason) when `collectReason` is on. */
  onRename: (id: string, name: string, reason: string) => void | Promise<void>
  onDelete: (id: string, reason: string) => void | Promise<void>
  /** Caller-side save gate (e.g. no applied scope yet). */
  saveDisabled?: boolean
  /** Extra controls rendered under the name input (Analytics: shared flag). */
  saveHint?: ReactNode
  /** AUX-14b: collect an optional operator reason in the AUX-12 dialogs. */
  collectReason?: boolean
  /** Action-descriptor ids for the rename/delete dialogs. */
  actionIds?: { rename: string; delete: string }
  labels?: SavedViewsMenuLabels
}

export function SavedViewsMenu({
  menuId, views, onApply, onSave, onRename, onDelete,
  saveDisabled, saveHint, collectReason, actionIds, labels,
}: SavedViewsMenuProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const toggleRef = useRef<HTMLButtonElement>(null)
  const close = () => setOpen(false)
  useDisclosureDismiss(open, menuRef, toggleRef, close)

  const ids = actionIds ?? { rename: 'views.rename', delete: 'views.delete' }
  const confirmRename = labels?.rename ?? t('views.rename')
  const confirmDelete = labels?.delete ?? t('views.delete')

  // AUX-12 contract, same risk routing the Analytics page used before the
  // menu was generalized: rename medium (reversible), delete high.
  const renameAction = useAction({ id: ids.rename, risk: 'medium', reversible: true })
  const deleteAction = useAction({ id: ids.delete, risk: 'high', reversible: false })

  const renameView = (id: string, current: string) => {
    renameAction.run({
      confirmLabel: confirmRename,
      was: current,
      input: { label: labels?.name ?? t('views.name'), initial: current },
      reason: collectReason ? {} : undefined,
      execute: async ({ value, reason }) => {
        const next = value.trim()
        if (!next || next === current) return
        await onRename(id, next, reason)
      },
    })
  }

  const deleteView = (id: string, current: string) => {
    deleteAction.run({
      entity: current,
      impact: labels?.deleteImpact
        ? labels.deleteImpact(current)
        : t('views.deleteConfirm', { name: current }),
      confirmLabel: confirmDelete,
      reason: collectReason ? {} : undefined,
      execute: async ({ reason }) => {
        await onDelete(id, reason)
      },
    })
  }

  const saveView = async () => {
    const trimmed = name.trim()
    if (!trimmed || busy) return
    setBusy(true)
    try {
      await onSave(trimmed)
      setName('')
    } catch {
      // The caller owns error surfacing; the input stays for a retry.
    } finally {
      setBusy(false)
    }
  }

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
        {labels?.menu ?? t('views.menu')} ▾
      </button>
      {open && (
        <div
          id={menuId}
          role="region"
          aria-label={labels?.menuLabel ?? t('views.menuLabel')}
          className="astra-menu-pop flex max-h-[70vh] w-80 max-w-[calc(100vw-2rem)] flex-col gap-3 overflow-auto"
        >
          <div className="flex flex-col gap-2">
            <span className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">
              {labels?.section ?? t('views.section')}
            </span>
            {views.length === 0 && (
              <p className="text-sm text-[color:var(--astra-text-muted)]">{labels?.empty ?? t('views.empty')}</p>
            )}
            <ul className="flex flex-col gap-1">
              {views.map(view => (
                <li key={view.id} className="flex flex-wrap items-center gap-1 text-sm">
                  <button
                    type="button"
                    className="min-h-[44px] grow text-start underline"
                    onClick={() => { onApply(view); setOpen(false) }}
                  >
                    {view.label ?? view.name}
                  </button>
                  <button type="button" className="btn-secondary min-h-[44px] px-2" onClick={() => renameView(view.id, view.name)}>
                    {confirmRename}
                  </button>
                  <button type="button" className="btn-secondary min-h-[44px] px-2" onClick={() => deleteView(view.id, view.name)}>
                    {confirmDelete}
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <hr className="border-[color:var(--astra-rule)]" />
          <div className="flex flex-col gap-2">
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{labels?.name ?? t('views.name')}</span>
              <input value={name} onChange={e => setName(e.target.value)} className="control" />
            </label>
            {saveHint}
            <button
              type="button"
              onClick={() => void saveView()}
              disabled={busy || saveDisabled || !name.trim()}
              className="btn-primary min-h-[44px]"
            >
              {labels?.save ?? t('views.save')}
            </button>
          </div>
        </div>
      )}
      {renameAction.ui}
      {deleteAction.ui}
    </div>
  )
}
