// Bulk selection bar + honest per-row report.
//
// The page owns the selection state (DataTable `selection` spec); this
// component renders the sticky action bar for the current selection and,
// after a mutating run, the per-row result report (success or error for
// EVERY selected row — rows rejected e.g. for missing permission are shown
// with their 403 text, never hidden). There are no bulk endpoints: the
// action is applied row by row through the existing single-row APIs, so a
// partial failure is the normal honest outcome, reported as such.
//
// Mutating actions run through the shared action contract: an ActionDialog
// (medium risk) collects an optional operator reason that rides to every
// row call as X-Audit-Reason. Reversible runs offer an Undo that inverts
// exactly the rows that succeeded. Instant actions (CSV export, add to
// filter) run without a dialog.
//
// This file must stay free of any org/root authorization logic — the page
// disables action items via its own permission gates.
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAction } from './ActionDialog'

/** Hard cap for one selection batch (stated explicitly in the bar). */
export const BULK_SELECTION_LIMIT = 100

export interface BulkRowResult {
  id: string
  label: string
  ok: boolean
  error?: string
}

interface BulkRunState<T> {
  kind: 'run' | 'undo'
  results: BulkRowResult[]
  /** Rows whose call succeeded — the exact target set for Undo. */
  succeededRows: T[]
  revertRow?: (row: T, reason: string) => Promise<void>
}

export interface BulkActionItem<T> {
  id: string
  label: string
  /**
   * Per-row call for a mutating action. Throw to mark the row failed with
   * the error message. Requires `dialog` on the component.
   */
  applyRow?: (row: T, reason: string) => Promise<void>
  /** Inverse per-row call powering the report's Undo affordance. */
  revertRow?: (row: T, reason: string) => Promise<void>
  /** Instant, dialog-free action (export, add to filter). */
  instant?: (rows: T[]) => void
  disabled?: boolean
  title?: string
}

export function BulkActions<T>({
  rows,
  getRowId,
  getRowLabel,
  selectedIds,
  onSelectionChange,
  limit = BULK_SELECTION_LIMIT,
  actions,
  dialog,
  onChanged,
}: {
  rows: T[]
  getRowId: (row: T) => string
  getRowLabel: (row: T) => string
  selectedIds: ReadonlyArray<string>
  onSelectionChange: (next: string[]) => void
  limit?: number
  actions: Array<BulkActionItem<T>>
  /** Carries the confirm dialog for mutating items. */
  dialog?: ReturnType<typeof useAction>
  /** Refetch after a mutating run (or its undo). */
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const [report, setReport] = useState<BulkRunState<T> | null>(null)
  const [undoBusy, setUndoBusy] = useState(false)

  const selectedSet = new Set(selectedIds)
  const selectedRows = rows.filter(r => selectedSet.has(getRowId(r)))

  // Sequential by design: no batch endpoint exists, and the report
  // must reflect each row's real outcome in order.
  const runRows = useCallback(
    async (targets: T[], apply: (row: T, reason: string) => Promise<void>, reason: string): Promise<BulkRowResult[]> => {
      const results: BulkRowResult[] = []
      for (const row of targets) {
        try {
          await apply(row, reason)
          results.push({ id: getRowId(row), label: getRowLabel(row), ok: true })
        } catch (err) {
          results.push({
            id: getRowId(row),
            label: getRowLabel(row),
            ok: false,
            error: err instanceof Error && err.message ? err.message : String(err),
          })
        }
      }
      return results
    },
    [getRowId, getRowLabel],
  )

  const runItem = (item: BulkActionItem<T>) => {
    if (selectedRows.length === 0) return
    if (item.instant) {
      item.instant(selectedRows)
      return
    }
    if (!item.applyRow || !dialog) return
    const applyRow = item.applyRow
    dialog.run({
      confirmLabel: item.label,
      reason: {},
      impact: <span>{t('bulk.impact', { count: selectedRows.length })}</span>,
      execute: async ({ reason }) => {
        const results = await runRows(selectedRows, applyRow, reason)
        // Never throw for a partial failure: the run DID happen and the
        // report below is its honest outcome.
        setReport({ kind: 'run', results, succeededRows: selectedRows.filter((_, i) => results[i]?.ok), revertRow: item.revertRow })
      },
      onDone: () => onChanged?.(),
    })
  }

  const undo = async () => {
    if (!report || report.kind !== 'run' || !report.revertRow || undoBusy) return
    setUndoBusy(true)
    try {
      const results = await runRows(report.succeededRows, report.revertRow, '')
      setReport({ kind: 'undo', results, succeededRows: [] })
      onChanged?.()
    } finally {
      setUndoBusy(false)
    }
  }

  const done = report ? report.results.filter(r => r.ok).length : 0

  return (
    <>
      {selectedIds.length > 0 && (
        <div
          role="toolbar"
          aria-label={t('bulk.barAria')}
          className="astra-panel sticky bottom-2 z-20 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] p-3 text-sm"
        >
          <span className="font-medium">
            {t('bulk.selected', { count: selectedIds.length })}
            {limit != null && (
              <span className="ms-2 font-normal text-[color:var(--astra-text-muted)]">
                {t('bulk.limitNote', { limit })}
              </span>
            )}
          </span>
          {actions.map(item => (
            <button
              key={item.id}
              type="button"
              className="btn-secondary"
              disabled={item.disabled}
              title={item.title}
              onClick={() => runItem(item)}
            >
              {item.label}
            </button>
          ))}
          <button type="button" className="btn-secondary" onClick={() => onSelectionChange([])}>
            {t('bulk.clear')}
          </button>
        </div>
      )}
      {report && (
        <div
          role="region"
          aria-label={t('bulk.reportAria')}
          className="astra-panel flex flex-col gap-2 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] p-3 text-sm"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium">
              {report.kind === 'run'
                ? t('bulk.reportTitle', { done, total: report.results.length })
                : t('bulk.undoReport', { done, total: report.results.length })}
            </span>
            <span className="flex gap-2">
              {report.kind === 'run' && report.revertRow && report.succeededRows.length > 0 && (
                <button type="button" className="btn-secondary" disabled={undoBusy} onClick={() => void undo()}>
                  {undoBusy ? t('bulk.undoing') : t('actions.undo')}
                </button>
              )}
              <button type="button" className="btn-secondary" onClick={() => setReport(null)}>
                {t('common.close')}
              </button>
            </span>
          </div>
          <ul className="flex flex-col gap-1">
            {report.results.map(r => (
              <li key={r.id} className="flex flex-wrap items-baseline gap-2">
                <span className="font-medium">{r.label}</span>
                {r.ok ? (
                  <span className="text-[color:var(--astra-success)]">
                    <span aria-hidden="true">✓</span> {t('bulk.ok')}
                  </span>
                ) : (
                  <span className="text-[color:var(--astra-danger)]">
                    <span aria-hidden="true">✗</span> {t('bulk.failed')}
                    {r.error ? `: ${r.error}` : ''}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {dialog?.ui}
    </>
  )
}
