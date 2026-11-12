import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listFeedback, feedbackExportUrl, type FeedbackEntry, type FeedbackPage } from '../api/feedback'
import { Pagination } from '../components/Pagination'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { formatDateTime } from '../i18n/format'

// The handler serves 50 rows by default (feedback.ListDefaultPageSize); the
// export ignores pagination and always returns the full filtered set.
const PAGE_SIZE = 50

const RATINGS = ['thumbs_up', 'thumbs_down', 'regenerate'] as const

// W-FEED: the owner (root-only) listing of POST /v1/feedback records with
// org/rating filters and a CSV export of the same filtered set. The server
// stays the arbiter (root-only routes); this screen only mirrors the gates.
export function FeedbackPage() {
  const { t } = useTranslation()
  // The org filter is applied on Enter/Apply — a per-keystroke refetch would
  // spam the root-only endpoint while typing a long org id.
  const [orgDraft, setOrgDraft] = useState('')
  const [orgId, setOrgId] = useState('')
  const [rating, setRating] = useState('')
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<FeedbackPage | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadAbort = useRef<AbortController | null>(null)
  const load = useCallback(async (p: number, org: string, rate: string) => {
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    try {
      const d = await listFeedback({ orgId: org, rating: rate, page: p, pageSize: PAGE_SIZE }, { signal: ctrl.signal })
      setResult(d)
      setPage(p)
    } catch (e: unknown) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load(1, orgId, rating)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const applyFilters = (nextOrg: string, nextRating: string) => {
    setOrgDraft(nextOrg)
    setOrgId(nextOrg)
    setRating(nextRating)
    setPage(1)
    void load(1, nextOrg, nextRating)
  }

  // Enter in the org field or the Apply button commits the draft filter.
  const submitOrg = () => applyFilters(orgDraft.trim(), rating)

  const total = result?.total ?? 0
  const pageSize = result?.page_size || PAGE_SIZE
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  const entries = result?.feedback ?? []
  const empty = !loading && entries.length === 0

  const columns: DataTableColumn<FeedbackEntry>[] = [
    { key: 'created_at', header: t('feedback.colWhen'), type: 'date', mono: true, render: e => formatDateTime(e.created_at) },
    { key: 'org_id', header: t('feedback.colOrg'), type: 'text', mono: true },
    { key: 'request_id', header: t('feedback.colRequest'), type: 'text', mono: true },
    { key: 'original_class', header: t('feedback.colClass'), type: 'text' },
    {
      key: 'action',
      header: t('feedback.colRating'),
      type: 'text',
      render: e => t(`feedback.rating_${e.action}`),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title={t('feedback.title')} purpose={t('feedback.purpose')} />

      <div className="flex flex-wrap items-end gap-3">
        <form
          className="flex flex-col gap-1 text-sm"
          onSubmit={e => {
            e.preventDefault()
            submitOrg()
          }}
        >
          <label htmlFor="feedback-org-filter" className="text-[color:var(--astra-text-muted)]">{t('feedback.filterOrg')}</label>
          <div className="flex gap-2">
            <input
              id="feedback-org-filter"
              type="text"
              value={orgDraft}
              onChange={e => setOrgDraft(e.target.value)}
              placeholder={t('feedback.filterOrgPlaceholder')}
              className="control sm:w-72"
              spellCheck={false}
            />
            <button type="submit" className="btn-secondary">{t('feedback.apply')}</button>
          </div>
        </form>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('feedback.filterRating')}</span>
          <select
            value={rating}
            onChange={e => applyFilters(orgId, e.target.value)}
            className="control sm:w-44"
          >            <option value="">{t('feedback.ratingAll')}</option>
            {RATINGS.map(r => (
              <option key={r} value={r}>{t(`feedback.rating_${r}`)}</option>
            ))}
          </select>
        </label>
        <a
          className="btn-secondary"
          href={feedbackExportUrl({ orgId: orgId || undefined, rating: rating || undefined })}
          download
        >
          {t('feedback.exportCsv')}
        </a>
      </div>

      {/* a failed load is ONLY the error notice (server text + retry).
          Unknown is not empty: the card yields until a load settles, so a
          failure can never read as a successful «No feedback recorded yet…». */}
      {error ? (
        <StateNotice
          state="error"
          message={error}
          action={{ label: t('common.retry'), onClick: () => void load(page, orgId, rating) }}
        />
      ) : (
        <div className="card overflow-x-auto">
          {loading && entries.length === 0 ? (
            <StateNotice state="loading" message={t('feedback.fetching')} />
          ) : empty ? (
            <StateNotice state="empty" message={t('feedback.empty')} />
          ) : (
            <DataTable
              columns={columns}
              rows={entries}
              getRowId={e => String(e.id)}
              page={page}
              pageSize={pageSize}
              onPageChange={p => {
                setPage(p)
                void load(p, orgId, rating)
              }}
              pagination="external"
              serverTotal={total}
              caption={t('feedback.title')}
            />
          )}
          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            totalPages={totalPages}
            loading={loading}
            onChange={p => {
              setPage(p)
              void load(p, orgId, rating)
            }}
          />
        </div>
      )}
    </div>
  )
}
