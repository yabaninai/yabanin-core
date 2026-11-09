import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { executeRollback, listAuditLogs, rollbackConflictCurrent, type AuditLogEntry } from '../api/client'
import { Pagination } from '../components/Pagination'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { formatDateTime } from '../i18n/format'
import { entityId, rollbackPlan, type RollbackCall } from '../lib/rollbackPlan'
import type { SortState } from '../lib/tableSort'

// The handler serves page_size=50 by default; it also accepts page_size from
// makes that explicit). Until then the constant mirrors the server default.
const PAGE_SIZE = 50

// AUX-14a: the audit resource string maps to an existing list page when one
// exists — a simple cross-link (the per-entity drawer is AUX-17, a parallel
// models_pricing never links as a model. Unmapped resources stay plain text:
// never a link to a page that cannot show the entity.
const RESOURCE_PAGES: Record<string, string> = {
  organization: 'orgs',
  api_key: 'keys',
  agent_key: 'keys',
  model: 'models',
  model_alias: 'models',
  routing_rule: 'rules',
  tool_policy: 'tool-policy',
  label_policy: 'label-policy',
  analytics_view: 'analytics',
}

function resourcePage(resource: string): string | null {
  return RESOURCE_PAGES[resource.split(':')[0]] ?? null
}

// SnapshotBlock renders one side of the diff as pretty-printed JSON — text
// nodes only (no HTML injection), fixed height with its own scroll.
function SnapshotBlock({ label, value }: { label: string; value: unknown }) {
  if (value == null) return null
  return (
    <div className="mt-2">
      <div className="text-xs font-medium" style={{ color: 'var(--astra-text-muted)' }}>{label}</div>
      <pre
        className="mt-1 max-h-48 overflow-auto rounded p-2"
        style={{ background: 'var(--astra-surface-muted)', fontFamily: 'var(--astra-font-code)', fontSize: '0.75rem' }}
      >
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  )
}

export function AuditLogPage() {
  const { t } = useTranslation()
  const [entries, setEntries] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  // served (echoed in the response), not a local constant.
  const [pageSize, setPageSize] = useState(PAGE_SIZE)
  // AUX-14a: page + sort live in the URL; the server owns the row order
  // (AUX-02 allowlist) and 400 invalid_sort surfaces as an error. The journal
  // defaults to newest first (server insertion order is chronological asc).
  const { page, setPage, sort, setSort } = useTableUrlState('audit', {
    defaultSort: { key: 'timestamp', dir: 'desc' },
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Stale-fetch safety (U07): every load aborts the previous in-flight one so
  // a slow response cannot clobber a newer page.
  const loadAbort = useRef<AbortController | null>(null)
  const loadSafe = useCallback(async (p: number, s: SortState | null) => {
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    try {
      const resp = await listAuditLogs(p, { signal: ctrl.signal, sort: s?.key, dir: s?.dir, pageSize: PAGE_SIZE })
      setEntries(resp.audit_logs ?? [])
      setTotal(resp.total ?? 0)
      // total + served page_size (this envelope carries no total_pages).
      const lastPage = Math.max(1, Math.ceil((resp.total ?? 0) / Math.max(1, resp.page_size || PAGE_SIZE)))
      setTotalPages(lastPage)
      setPageSize(resp.page_size || PAGE_SIZE)
      // The server's page count is the only page truth — a stale or
      // URL-restored page beyond it steps back to the served last page
      // (the fetch effect follows the change).
      if (p > lastPage) setPage(lastPage)
    } catch (e: unknown) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setLoading(false)
    }
  }, [setPage])

  useEffect(() => {
    void loadSafe(page, sort)
    return () => loadAbort.current?.abort()
  }, [loadSafe, page, sort])

  // AUX-03 contract: a header click in server mode re-asks the backend; the
  // sort change resets the page to 1 (the view is a new ordering).
  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  // Same hash-query contract as the shell's goto(): the scope/locale query
  // survives the jump to the entity's list page.
  const openEntityPage = (target: string) => {
    const prevQuery = window.location.hash.split('?')[1]
    window.location.hash = target + (prevQuery ? `?${prevQuery}` : '')
  }

  // AUX-14b: the rollback dialog (medium risk, reason required). The reverse
  // call goes to the existing mutation route — no rollback endpoint exists —
  // and lands in the journal as its own entry, which the refetch shows.
  // AF-09: the plan carries the recorded after state as a precondition; the
  // server compares it atomically and answers 409 with the CURRENT state —
  // surfaced verbatim instead of pretending the rollback happened.
  const rollbackAction = useAction({ id: 'audit.rollback', risk: 'medium', reversible: true })
  const openRollback = (e: AuditLogEntry, plan: RollbackCall) => {
    rollbackAction.run({
      confirmLabel: t('auditLog.rollback'),
      impact: t('auditLog.rollbackImpact', { action: e.action }),
      reason: { required: true },
      execute: async ({ reason }) => {
        try {
          await executeRollback(plan, auditReasonOpts(reason))
        } catch (err) {
          const conflict = rollbackConflictCurrent(err)
          if (conflict) {
            throw new Error(
              t('auditLog.rollbackConflict', { current: JSON.stringify(conflict.current ?? null) }),
            )
          }
          throw err
        }
      },
      onDone: () => void loadSafe(page, sort),
      onError: () => {},
    })
  }

  const empty = !loading && entries.length === 0

  // AUX-14a: who/when/what/entity. Every column except the free-form details
  // maps to the AUX-02 server allowlist, so headers sort server-side; details
  // is honestly not sortable (not in the allowlist).
  const columns: DataTableColumn<AuditLogEntry>[] = [
    {
      key: 'timestamp',
      header: t('auditLog.colWhen'),
      type: 'date',
      mono: true,
      render: e => formatDateTime(e.timestamp),
    },
    {
      key: 'admin_name',
      header: t('auditLog.colWho'),
      type: 'text',
      render: e => (e.admin_name !== '' ? e.admin_name : t('common.unknown')),
    },
    {
      key: 'action',
      header: t('auditLog.colAction'),
      type: 'text',
      mono: true,
    },
    {
      key: 'resource',
      header: t('auditLog.colResource'),
      type: 'text',
      render: e => {
        const target = resourcePage(e.resource)
        // resource + id: the id rides in the resource ("api_key:<id>") or in
        // the details; show the pair as one label, never invent a bare id.
        const id = entityId(e)
        const label = id != null && !e.resource.includes(':') ? `${e.resource}:${id}` : e.resource
        if (!target) return label
        return (
          <a
            href={`#${target}`}
            onClick={ev => {
              ev.preventDefault()
              openEntityPage(target)
            }}
            title={t('auditLog.openEntityPage')}
            className="text-[color:var(--astra-accent)] underline-offset-2 hover:underline"
          >
            {label}
          </a>
        )
      },
    },
    {
      key: 'details',
      header: t('auditLog.colDetails'),
      sortable: false,
      render: e => {
        // AUX-14b: entries recorded with snapshots/reason expand into a diff
        // (before/after JSON, server-sanitized) plus the reason; safe families
        // also get a rollback button driven by the recorded before state.
        const hasReason = (e.reason ?? '') !== ''
        const hasDiff = e.before != null || e.after != null
        const plan = rollbackPlan(e)
        return (
          <div>
            {e.details ? (
              <span className="overflow-wrap-anywhere" style={{ fontFamily: 'var(--astra-font-code)' }}>
                {e.details}
              </span>
            ) : null}
            {(hasDiff || hasReason) && (
              <details className="mt-1">
                <summary className="cursor-pointer text-sm" style={{ color: 'var(--astra-accent)' }}>
                  {t('auditLog.changes')}
                </summary>
                {hasReason && (
                  <p className="mt-2 text-sm">
                    <span style={{ color: 'var(--astra-text-muted)' }}>{t('auditLog.reason')}: </span>
                    <span className="overflow-wrap-anywhere">{e.reason}</span>
                  </p>
                )}
                <SnapshotBlock label={t('auditLog.before')} value={e.before} />
                <SnapshotBlock label={t('auditLog.after')} value={e.after} />
                {plan && (
                  <button type="button" className="btn-secondary mt-2" onClick={() => openRollback(e, plan)}>
                    {t('auditLog.rollback')}
                  </button>
                )}
              </details>
            )}
          </div>
        )
      },
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title={t('auditLog.title')} purpose={t('auditLog.purpose')} />

      {rollbackAction.ui}

      {error && <StateNotice state="error" message={error} />}

      <div className="card overflow-x-auto">
        {loading && entries.length === 0 ? (
          <StateNotice state="loading" message={t('auditLog.fetching')} />
        ) : empty ? (
          <StateNotice state="empty" message={t('auditLog.empty')} />
        ) : (
          <DataTable
            columns={columns}
            rows={entries}
            getRowId={e => e.id}
            page={page}
            pageSize={pageSize}
            onPageChange={setPage}
            pagination="external"
            serverTotal={total}
            scopeNote={t('auditLog.scopeNote')}
            sortMode="server"
            sort={sort}
            onSortChange={handleSortChange}
            defaultSort={{ key: 'timestamp', dir: 'desc' }}
            caption={t('auditLog.title')}
          />
        )}
        <Pagination
          page={page}
          pageSize={pageSize}
          total={total}
          totalPages={totalPages}
          loading={loading}
          onChange={p => setPage(p)}
        />
      </div>
    </div>
  )
}
