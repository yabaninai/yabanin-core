import { Fragment, useMemo, useRef, useState, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { StateNotice } from './StateNotice'
import {
  compareSortState, nextSortState,
  type ColumnSortType, type SortState, type SortValue,
} from '../../lib/tableSort'
import type { TableDensity } from '../../lib/tablePrefs'
import {
  FORMAT_MONO, FORMAT_SORT_TYPE, formatCellByFormat,
  type ColumnFormatOptions, type ColumnFormatType,
} from '../../lib/columnFormat'

// Astra primitive: DataTable (standards/design.md "Components and contracts").
// Stable row keys, semantic th/td, per-column sort, client-side pagination
// over the fetched (server-scoped) rows, loading/empty/error via StateNotice.
// The sticky header lives INSIDE the designated scroll container only.
//
// DataTable v2 contract:
//  - every column declares `type` (+ `unit` metadata); `sortable` defaults to
//    true and `getSortValue` stays as a value override;
//  - ordering goes through the typed comparator in lib/tableSort (numbers,
//    money, dates, numeric-aware text, missing values last in BOTH
//    directions, current-locale collation);
//  - sorting is controllable: `sort` / `onSortChange` (controlled) or
//    `defaultSort` (internal state), with `sortMode` — 'client' reorders the
//    fetched rows locally, 'server' never reorders or re-pages locally and
//    only reports header clicks to `onSortChange` (the backend owns order);
//  - `pagination: 'external'` hides the built-in prev/next when the page
//    renders its own <Pagination>;
//  - `selection` renders a leading checkbox column: per-row toggles
//    (Shift-click extends from the last clicked row within the current page),
//    a header "select all on this page" checkbox (indeterminate when partial),
//    all capped at `selection.limit`. The page owns the bulk action bar
//    (components/astra/BulkActions.tsx); `hiddenColumnIds` excludes columns
//    from render, sort, aria-colcount and the consumer's CSV exports (the
//    Columns menu and per-table localStorage prefs live in
//    lib/tablePrefs);
//  - `density` switches row spacing between 'compact' (default; pages
//    with per-table prefs pass their own value, which always wins) and
//    'comfortable';
//    date/code/duration/percent get the built-in formatters from
//    lib/columnFormat (2-decimal money with the "<$0.01" sub-cent bound and
//    the exact value in the cell hint; tokens as "input / output"), plus
//    the implied mono/tabular or nowrap styling and a default sort type
//    (an explicit `type` still wins). A column with `render` keeps full
//    control of its cell.

export interface DataTableColumn<T> {
  key: string
  header: string
  /** Glossary text shown as the header's native title hint. */
  headerHint?: string
  /** Cell content; defaults to String(row[key]). */
  render?: (row: T) => ReactNode
  /** Comparator semantics of the column's values; default 'text'. */
  type?: ColumnSortType
  /**
   * Display semantic of the column; with no `render` the matching built-in
   * formatter renders the cell. Implies a default sort `type`
   * unless one is set explicitly.
   */
  format?: ColumnFormatType
  /** Formatter knobs (locale override, money currency, date timezone, …). */
  formatOptions?: ColumnFormatOptions
  /** Measurement unit of the values (currency code, ms, …); header metadata. */
  unit?: string
  /** Header-click sorting enabled; default true. */
  sortable?: boolean
  /** Overrides the compared value; defaults to the raw row[key]. */
  getSortValue?: (row: T) => SortValue
  align?: 'left' | 'right'
  /** Cell renders mono/tabular content (IDs, amounts). */
  mono?: boolean
}

/** Row-selection state owned by the page (see BulkActions.tsx). */
export interface DataTableSelectionSpec<T> {
  selectedRowIds?: ReadonlyArray<string>
  onSelectionChange?: (next: string[]) => void
  /** Hard cap for one selection batch. */
  limit?: number
  /** Human row name for the checkbox's aria-label; defaults to the row id. */
  rowLabel?: (row: T) => string
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[]
  rows: T[]
  /** Stable row identity (never the array index). */
  getRowId: (row: T) => string
  loading?: boolean
  error?: ReactNode
  empty?: ReactNode
  /** Label for the empty state's next action. */
  emptyAction?: { label: string; onClick?: () => void }
  /** Server-provided honest total; omit when the API does not return one. */
  serverTotal?: number
  /** What was capped server-side, e.g. "server limit 50". */
  scopeNote?: string
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  /** 'external' hides the built-in prev/next (the page renders <Pagination>). */
  pagination?: 'built-in' | 'external'
  caption?: string
  selectedId?: string
  /** Row actions cell (copy-ID, inspect, …). */
  renderActions?: (row: T) => ReactNode
  /**
   * Click a row to drill somewhere (the request explorer). Pointer
   * convenience only — keyboard parity stays with the row's action buttons.
   */
  onRowClick?: (row: T) => void
  /**
   * Optional full-width row rendered directly under its data row
   * (e.g. an inline per-row editor). It belongs to the row visually but
   * participates in neither sort nor pagination.
   */
  renderExpanded?: (row: T) => ReactNode
  /** 'client' (default) sorts fetched rows locally; 'server' keeps the order the backend sent. */
  sortMode?: 'client' | 'server'
  /** Controlled sort state; omit to let the table manage it internally. */
  sort?: SortState | null
  onSortChange?: (next: SortState | null) => void
  /** Sort assumed when none is active (and the third click's return target). */
  defaultSort?: SortState | null
  /** Leading checkbox column + select-all-on-page (bar lives in the page). */
  selection?: DataTableSelectionSpec<T>
  /** Columns excluded from render, sort and aria-colcount. */
  hiddenColumnIds?: ReadonlyArray<string>
  /** Row spacing; 'compact' (default) or 'comfortable'. */
  density?: TableDensity
}

const cellValue = (row: unknown, key: string): SortValue => {
  const v = (row as Record<string, unknown>)[key]
  if (typeof v === 'string' || typeof v === 'number') return v
  if (v == null) return null
  return String(v)
}

// Built-in formatting applies only to columns without an explicit
// `render`. The raw value goes through the pure formatter; the optional
// exact-value hint (sub-cent money) rides on a title span.
function formattedCell<T>(col: DataTableColumn<T>, row: T, locale: string): ReactNode {
  if (!col.format) return String(cellValue(row, col.key) ?? '')
  const raw = (row as Record<string, unknown>)[col.key]
  const cell = formatCellByFormat(col.format, raw, {
    ...col.formatOptions,
    locale: col.formatOptions?.locale ?? locale,
  })
  return cell.title != null ? <span title={cell.title}>{cell.text}</span> : cell.text
}

export function DataTable<T>({
  columns, rows, getRowId, loading, error, empty, emptyAction,
  serverTotal, scopeNote, page, pageSize, onPageChange,
  pagination = 'built-in', caption, selectedId, renderActions, renderExpanded, onRowClick,
  sortMode = 'client', sort: sortProp, onSortChange, defaultSort,
  selection, hiddenColumnIds, density = 'compact',
}: DataTableProps<T>) {
  const { t, i18n } = useTranslation()
  const [internalSort, setInternalSort] = useState<SortState | null>(defaultSort ?? null)
  const controlled = sortProp !== undefined
  const sort = controlled ? sortProp : internalSort
  const clientSort = sortMode === 'client'

  // Selection: controlled via selection.selectedRowIds when provided,
  // otherwise an internal fallback so simple consumers still get checkboxes.
  // Memoized identity: the controlled array is a page-owned prop that may be
  // a fresh literal each render, which would invalidate the Set below.
  const controlledSelection = selection?.selectedRowIds !== undefined
  const [internalSelection, setInternalSelection] = useState<ReadonlyArray<string>>([])
  const selectedRowIds = useMemo(
    () => (controlledSelection ? (selection?.selectedRowIds ?? []) : internalSelection),
    [controlledSelection, selection?.selectedRowIds, internalSelection],
  )
  const selectedSet = useMemo(() => new Set(selectedRowIds), [selectedRowIds])
  const lastClickedIdRef = useRef<string | null>(null)

  const visibleColumns = useMemo(
    () => (hiddenColumnIds && hiddenColumnIds.length > 0
      ? columns.filter(c => !hiddenColumnIds.includes(c.key))
      : columns),
    [columns, hiddenColumnIds],
  )

  // Client mode only: apply the typed comparator. Server mode renders the
  // rows exactly as the backend ordered and paged them.
  const ordered = useMemo(() => {
    if (!clientSort || !sort) return rows
    const col = visibleColumns.find(c => c.key === sort.key && c.sortable !== false)
    if (!col) return rows
    const type: ColumnSortType = col.type ?? (col.format ? FORMAT_SORT_TYPE[col.format] : 'text')
    const pick = col.getSortValue ?? ((row: T) => cellValue(row, col.key))
    return [...rows].sort((a, b) => compareSortState(pick(a), pick(b), type, sort.dir, i18n.language))
  }, [rows, sort, clientSort, visibleColumns, i18n.language])

  if (loading) {
    return <StateNotice state="loading" message={t('table.fetchingScope')} />
  }
  if (error) {
    return <StateNotice state="error" message={error} />
  }
  if (rows.length === 0) {
    return <StateNotice state="empty" message={empty ?? t('table.noRecordsScope')} action={emptyAction} />
  }

  // Server mode: the fetched rows ARE the requested page — never re-paged or
  // re-sliced locally; the count line reports the server page as-is.
  const pageRows = clientSort
    ? ordered.slice((page - 1) * pageSize, (page - 1) * pageSize + pageSize)
    : ordered
  const rowCount = ordered.length
  const pageCount = Math.max(1, Math.ceil(rowCount / pageSize))
  const safePage = Math.min(Math.max(1, page), pageCount)
  const start = clientSort
    ? (safePage - 1) * pageSize
    : (Math.max(1, page) - 1) * pageSize
  const shownTo = clientSort
    ? Math.min(start + pageSize, rowCount)
    : Math.min(page * pageSize, serverTotal ?? rowCount)

  const toggleSort = (key: string) => {
    const next = nextSortState(sort, key, defaultSort ?? null)
    if (controlled) onSortChange?.(next)
    else setInternalSort(next)
    // A re-sorted client view invalidates the local page; in server mode the
    // consumer's onSortChange handler owns the refetch (and page reset).
    if (clientSort) onPageChange(1)
  }

  // ----- Selection (checkbox column; the bulk bar lives in the page) -----
  const pageIds = pageRows.map(getRowId)
  const emitSelection = (next: ReadonlyArray<string>) => {
    const limit = selection?.limit
    const capped = limit != null && next.length > limit ? next.slice(0, limit) : next
    if (controlledSelection) selection?.onSelectionChange?.([...capped])
    else setInternalSelection([...capped])
  }
  const toggleRowSelection = (id: string, shift: boolean) => {
    if (shift && lastClickedIdRef.current != null) {
      const from = pageIds.indexOf(lastClickedIdRef.current)
      const to = pageIds.indexOf(id)
      if (from !== -1 && to !== -1) {
        // Shift extends from the last clicked row within the current page,
        // merging into (never clearing) the existing selection.
        const [lo, hi] = from <= to ? [from, to] : [to, from]
        const range = new Set(pageIds.slice(lo, hi + 1))
        emitSelection(pageIds.filter(pid => range.has(pid) || selectedSet.has(pid)))
        lastClickedIdRef.current = id
        return
      }
    }
    emitSelection(selectedSet.has(id) ? selectedRowIds.filter(x => x !== id) : [...selectedRowIds, id])
    lastClickedIdRef.current = id
  }
  const pageIdSet = new Set(pageIds)
  const selectedOnPage = pageIds.filter(id => selectedSet.has(id)).length
  const allOnPage = pageIds.length > 0 && selectedOnPage === pageIds.length
  const someOnPage = selectedOnPage > 0 && !allOnPage
  const toggleAllOnPage = () => {
    if (allOnPage) emitSelection(selectedRowIds.filter(id => !pageIdSet.has(id)))
    else emitSelection([...selectedRowIds, ...pageIds.filter(id => !selectedSet.has(id))])
    lastClickedIdRef.current = null
  }
  const selectColCount = visibleColumns.length + (renderActions ? 1 : 0) + (selection ? 1 : 0)

  // Row spacing by density. 'compact' is the primitive default; pages
  // with per-table prefs pass their own value, which always wins.
  // The sort button keeps its 36px target in
  // both densities — only the cell breathing room changes.
  const rowPad = density === 'compact' ? 'py-1' : 'py-2'
  const headPad = density === 'compact' ? 'py-1.5' : 'py-2'
  const thCls = `whitespace-nowrap border-b border-[color:var(--astra-rule-strong)] px-3 ${headPad} text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]`
  const tdBase = `border-b border-[color:var(--astra-rule)] px-3 ${rowPad} align-top text-sm text-[color:var(--astra-ink)]`

  // The sticky lead column (the first data column) stays visible during
  // horizontal scrolling. The
  // separation edge is an inset shadow — a collapsed-table border would
  // scroll away with the sticky cell. Opaque backgrounds keep scrolled
  // content from showing through; selected rows carry the accent surface.
  const stickyShadow = 'shadow-[inset_-1px_0_0_0_var(--astra-rule-strong)]'
  const stickyTd = (selected: boolean) =>
    `sticky z-[1] ${stickyShadow} ${selected ? 'bg-[color:var(--astra-accent-surface)]' : 'bg-[color:var(--astra-surface)]'}`
  const stickyTh = `sticky z-[2] bg-[color:var(--astra-surface)] ${stickyShadow}`

  return (
    // Text-enlarge safe: min-w-0 + max-w-full on the wrapper and the
    // scroll region so a wide table scrolls inside its container (bounded to
    // the viewport) instead of pushing the document wider when the root font
    // is enlarged. The table keeps its intrinsic width and scrolls locally.
    <div className="flex min-w-0 max-w-full flex-col gap-2">
      <div
        role="region"
        aria-label={caption ? t('table.scrollableCaption', { caption }) : t('table.scrollableDefault')}
        tabIndex={0}
        // relative: the scroll region becomes the containing block for
        // abs-pos descendants (sr-only labels), keeping their overflow local.
        className="relative max-h-[70vh] w-full min-w-0 overflow-auto rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)]"
      >
        <table
          className="w-full border-collapse"
          // Hidden columns do not count — aria-colcount mirrors what
          // is actually rendered (+ selection/actions columns when present).
          aria-colcount={selectColCount}
        >
          {caption && <caption className="sr-only">{caption}</caption>}
          <thead className="sticky top-0 z-10 bg-[color:var(--astra-surface)]">
            <tr>
              {selection && (
                <th scope="col" className={`${thCls} w-10 ${stickyTh} sticky left-0`}>
                  <input
                    type="checkbox"
                    aria-label={t('table.selectAllPage')}
                    checked={allOnPage}
                    ref={el => { if (el) el.indeterminate = someOnPage }}
                    onChange={toggleAllOnPage}
                    className="h-4 w-4 accent-[color:var(--astra-accent)]"
                  />
                </th>
              )}
              {visibleColumns.map((c, colIdx) => {
                const sortable = c.sortable !== false
                // The first data column sticks too — right after the
                // selection column when one leads the row (w-10 = left-10).
                const isLead = colIdx === 0
                const leadLeft = selection ? 'left-10' : 'left-0'
                return (
                  <th
                    key={c.key}
                    scope="col"
                    title={c.headerHint}
                    aria-sort={
                      sortable
                        ? sort?.key === c.key
                          ? sort.dir === 'asc' ? 'ascending' : 'descending'
                          : 'none'
                        : undefined
                    }
                    className={`${thCls} ${c.align === 'right' ? 'text-right' : ''} ${isLead ? `${stickyTh} sticky ${leadLeft}` : ''}`}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(c.key)}
                        // 36px compact sort target (desktop density).
                        className="inline-flex min-h-[36px] items-center gap-1 uppercase tracking-wide hover:text-[color:var(--astra-ink)]"
                      >
                        {c.header}
                        <span aria-hidden="true">{sort?.key === c.key ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'}</span>
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                )
              })}
              {renderActions && <th scope="col" className={thCls}><span className="sr-only">{t('common.actions')}</span></th>}
            </tr>
          </thead>
          <tbody>
            {pageRows.map(row => {
              const id = getRowId(row)
              const selected = selectedId === id
              const cells = (
                <>
                  {selection && (
                    <td
                      className={`${tdBase} ${stickyTd(selected)} sticky left-0`}
                      onClick={e => e.stopPropagation()}
                    >
                      <input
                        type="checkbox"
                        aria-label={t('table.selectRow', { row: selection?.rowLabel?.(row) ?? id })}
                        checked={selectedSet.has(id)}
                        // preventDefault keeps React's state the single source
                        // of truth; the click handler owns shift-range logic.
                        onClick={e => { e.preventDefault(); toggleRowSelection(id, e.shiftKey) }}
                        onChange={() => { /* handled in onClick */ }}
                        className="h-4 w-4 accent-[color:var(--astra-accent)]"
                      />
                    </td>
                  )}
                  {visibleColumns.map((c, colIdx) => {
                    const isLead = colIdx === 0
                    const leadLeft = selection ? 'left-10' : 'left-0'
                    // Built-in formats imply mono (and a nowrap cell for
                    // date/code); an explicit `mono` wins.
                    const effMono = c.mono ?? (c.format ? FORMAT_MONO[c.format] : false)
                    const nowrap = effMono || c.format === 'date'
                    // Numeric formats read better right-aligned; explicit
                    // `align` wins.
                    const effAlign = c.align ?? (c.format === 'money' || c.format === 'number' || c.format === 'tokens' || c.format === 'duration' || c.format === 'percent' ? 'right' : 'left')
                    return (
                      <td
                        key={c.key}
                        className={`${tdBase} ${effAlign === 'right' ? 'text-right' : ''} ${nowrap ? 'whitespace-nowrap' : ''} ${isLead ? `${stickyTd(selected)} sticky ${leadLeft}` : ''}`}
                        style={effMono ? { fontFamily: 'var(--astra-font-code)', fontVariantNumeric: 'tabular-nums' } : undefined}
                      >
                        {c.render ? c.render(row) : formattedCell(c, row, i18n.language)}
                      </td>
                    )
                  })}
                  {renderActions && <td className={tdBase}>{renderActions(row)}</td>}
                </>
              )
              if (!renderExpanded) {
                return (
                  <tr
                    key={id}
                    aria-selected={selected || undefined}
                    className={`${selected ? 'bg-[color:var(--astra-accent-surface)]' : ''} ${onRowClick ? 'cursor-pointer' : ''}`}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                  >
                    {cells}
                  </tr>
                )
              }
              return (
                <Fragment key={id}>
                  <tr
                    aria-selected={selected || undefined}
                    className={`${selected ? 'bg-[color:var(--astra-accent-surface)]' : ''} ${onRowClick ? 'cursor-pointer' : ''}`}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                  >
                    {cells}
                  </tr>
                  <tr>
                    <td colSpan={selectColCount} className={tdBase}>
                      {renderExpanded(row)}
                    </td>
                  </tr>
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-[color:var(--astra-text-muted)]">
        <span>
          {t('table.showing', { from: start + 1, to: shownTo, total: serverTotal ?? rowCount })}
          {serverTotal != null && serverTotal !== rowCount ? t('table.fetched', { fetched: rowCount }) : ''}
          {scopeNote ? ` · ${scopeNote}` : ''}
        </span>
        {pagination === 'built-in' && (
          <span className="flex gap-2">
            <button
              type="button"
              onClick={() => onPageChange(safePage - 1)}
              disabled={safePage <= 1}
              className="btn-secondary"
            >
              {t('table.prev')}
            </button>
            <button
              type="button"
              onClick={() => onPageChange(safePage + 1)}
              disabled={safePage >= pageCount}
              className="btn-secondary"
            >
              {t('table.next')}
            </button>
          </span>
        )}
      </div>
    </div>
  )
}
