import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

// U02: shared pagination for the control-plane list pages (Orgs, Models,
// Keys, Rules). The current page is mirrored into the URL (?page=N) so a
// paginated view is shareable and survives a reload; changing the page calls
// onChange, which the page uses to fetch that page.
//
// States handled by the page (not this component): loading (skeleton/Loading…),
// empty (no rows), error (banner), and the pending state shown here while a
// page change is in flight.

export interface PaginationProps {
  page: number
  pageSize: number
  total: number
  totalPages: number
  loading: boolean
  onChange: (page: number) => void
}

// readPageFromURL returns the ?page= param (>=1) or 1 when absent/invalid.
function readPageFromURL(): number {
  try {
    const raw = new URLSearchParams(window.location.search).get('page')
    const n = raw ? parseInt(raw, 10) : 1
    return Number.isFinite(n) && n >= 1 ? n : 1
  } catch {
    return 1
  }
}

// writePageToURL mirrors ?page=N into the address bar without a full
// navigation (pushState when leaving page 1, replaceState otherwise).
function writePageToURL(page: number) {
  try {
    const url = new URL(window.location.href)
    if (page <= 1) {
      url.searchParams.delete('page')
    } else {
      url.searchParams.set('page', String(page))
    }
    window.history.pushState(null, '', url.toString())
  } catch {
    // Non-browser environment (tests) — URL sync is best-effort.
  }
}

export function Pagination({ page, pageSize, total, totalPages, loading, onChange }: PaginationProps) {
  const { t } = useTranslation()
  const [pending, setPending] = useState(false)

  // On mount, adopt the page from the URL and tell the page to load it.
  useEffect(() => {
    const fromURL = readPageFromURL()
    if (fromURL !== page) {
      onChange(fromURL)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Keep the URL in sync when the page changes from anywhere.
  useEffect(() => {
    writePageToURL(page)
  }, [page])

  const go = useCallback(
    (next: number) => {
      if (loading || pending) return
      if (next < 1 || next > totalPages || next === page) return
      setPending(true)
      onChange(next)
    },
    [loading, pending, totalPages, page, onChange],
  )

  // Clear the pending flag whenever a fetch settles (loading toggles).
  useEffect(() => {
    if (!loading) setPending(false)
  }, [loading])

  const busy = loading || pending
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)

  // AVR-07 (F09): 44px target floor + Astra tokens (this legacy pagination
  // served the request explorer's Prev/Next at 26px).
  const btnCls = 'btn-secondary px-3 text-xs disabled:opacity-40'
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[color:var(--astra-rule)] px-3 py-2 text-xs text-[color:var(--astra-text-muted)]">
      <span aria-live="polite">
        {total === 0
          ? t('pagination.noRecords')
          : t('pagination.range', { from, to, total })}
        {busy && <span className="ms-2 text-[color:var(--astra-text-muted)]">…</span>}
      </span>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => go(page - 1)}
          disabled={busy || page <= 1}
          className={btnCls}
        >
          {t('common.prev')}
        </button>
        <span className="px-2 tabular-nums">
          {t('pagination.pageOf', { page, totalPages: Math.max(totalPages, 1) })}
        </span>
        <button
          type="button"
          onClick={() => go(page + 1)}
          disabled={busy || page >= totalPages}
          className={btnCls}
        >
          {t('common.next')}
        </button>
      </div>
    </div>
  )
}
