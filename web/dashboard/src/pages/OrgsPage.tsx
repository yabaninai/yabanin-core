import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listOrganizations, createOrganization, updateOrganization, deleteOrganization,
  type Organization,
} from '../api/client'
import { Pagination } from '../components/Pagination'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { EntityDrawer } from '../components/astra/EntityDrawer'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { useInspectParam } from '../hooks/useInspectParam'
import { currentHashQuery, relatedListHref } from '../lib/inspectUrl'
import type { SortState } from '../lib/tableSort'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'

const PAGE_SIZE = 25

export function OrgsPage() {
  const { t } = useTranslation()
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  // served (echoed in pagination), not a local constant — until the list
  const [pageSize, setPageSize] = useState(PAGE_SIZE)
  // AUX-03 (server sort): page + sort live in the URL (#orgs?orgs__sort=name:asc)
  // and the server owns the row order (allowlisted columns, 400 invalid_sort
  // otherwise); the fetched page renders exactly as the backend sent it.
  const { page, setPage, sort, setSort } = useTableUrlState('orgs')
  // AUX-17: the entity inspector — opened by an entity-name click and by the
  // ?inspect=<id> deep link (read once at mount, removed from the hash on
  // close). The row itself carries every field the card shows; there is no
  // per-org activity data on this page, so the drawer shows no activity yet.
  const [inspectId, setInspectId] = useInspectParam()
  const inspected = useMemo(
    () => orgs.find(o => o.id === inspectId) ?? null,
    [orgs, inspectId],
  )
  // Honest not-found state only once a fetch has completed — the first paint
  // (before the effect fires) must not flash "not found" for a deep link.
  const [orgsLoaded, setOrgsLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [creating, setCreating] = useState(false)
  // UI-VF-1: row-level mutations — inline edit (name/slug/currency/timezone,
  // matching PUT /api/organizations/{id}) and destructive delete. Deletion
  // cascades to keys/rules server-side, so it always asks for confirmation.
  const [busyOrgId, setBusyOrgId] = useState('')
  const [editingId, setEditingId] = useState('')
  const [editName, setEditName] = useState('')
  const [editSlug, setEditSlug] = useState('')
  const [editCurrency, setEditCurrency] = useState('')
  const [editTimezone, setEditTimezone] = useState('')
  const [editIssue, setEditIssue] = useState('')

  // Stale-fetch safety (U07): a newer page load aborts the previous one.
  const loadAbort = useRef<AbortController | null>(null)
  const load = useCallback(async (p: number, s: SortState | null) => {
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    try {
      const resp = await listOrganizations(p, { signal: ctrl.signal, sort: s?.key, dir: s?.dir, pageSize: PAGE_SIZE })
      setOrgs(resp.data ?? [])
      const pg = resp.pagination
      setTotal(pg?.total ?? resp.data?.length ?? 0)
      setPageSize(pg?.page_size ?? PAGE_SIZE)
      const lastPage = Math.max(1, pg?.total_pages ?? 1)
      setTotalPages(lastPage)
      // stale or URL-restored page beyond it steps back to the served last
      // page (the fetch effect follows the change).
      if (p > lastPage) setPage(lastPage)
      setOrgsLoaded(true)
    } catch (e: unknown) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setLoading(false)
    }
  }, [setPage])

  useEffect(() => {
    void load(page, sort)
    return () => loadAbort.current?.abort()
  }, [load, page, sort])

  // AUX-12 contract: a header click in server mode re-asks the backend; the
  // sort change resets the page to 1 (the view is a new ordering).
  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setError('')
    try {
      await createOrganization(name.trim(), slug.trim() || name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-'))
      setName('')
      setSlug('')
      // New org lands on page 1; the effect refetches when the page changes,
      // an explicit load covers the already-on-page-1 case.
      if (page === 1) await load(1, sort)
      else setPage(1)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setCreating(false)
    }
  }

  // UI-VF-1: refetch the current page after a row mutation so pagination and
  // totals stay consistent (unlike the create flow, which resets to page 1).
  const refresh = () => void load(page, sort)

  const startEdit = (o: Organization) => {
    setEditingId(o.id)
    setEditName(o.name)
    setEditSlug(o.slug)
    // Empty values render as placeholders (USD / UTC); prefill those defaults
    // so saving an untouched row is a no-op rather than a surprise write.
    setEditCurrency(o.currency || 'USD')
    setEditTimezone(o.timezone || 'UTC')
    setEditIssue(o.issue_url_template || '')
  }

  const handleSaveEdit = async (id: string) => {
    if (!editName.trim() || !editSlug.trim()) return
    setBusyOrgId(id)
    setError('')
    try {
      await updateOrganization(id, {
        name: editName.trim(),
        slug: editSlug.trim(),
        currency: editCurrency.trim().toUpperCase(),
        timezone: editTimezone.trim(),
        ...(editIssue.trim() ? { issue_url_template: editIssue.trim() } : {}),
      })
      setEditingId('')
      refresh()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusyOrgId('')
    }
  }

  // AUX-12: org deletion is high risk (cascades to keys/rules server-side) —
  // dialog with consequences, name confirmation and a required reason.
  const deleteOrgAction = useAction({
    id: 'orgs.delete', risk: 'high', reversible: false, impact: t('orgs.deleteConfirm'),
  })
  const handleDeleteOrg = (o: Organization) => {
    setError('')
    deleteOrgAction.run({
      entity: o.name,
      confirmLabel: t('common.delete'),
      reason: {},
      execute: async ({ reason }) => {
        await deleteOrganization(o.id, auditReasonOpts(reason))
      },
      onDone: () => {
        // refetched server pagination (the step-back clamp in load) — not by
        // a local remaining-rows counter.
        void load(page, sort)
      },
    })
  }

  const empty = !loading && orgs.length === 0

  // AUX-03: DataTable v2 columns. Every column declares its sort semantic;
  // `issue_url_template` is not in the AUX-02 server allowlist, so its header
  // is honestly not sortable (server keeps the fixed default order for it).
  const columns: DataTableColumn<Organization>[] = [
    {
      key: 'id',
      header: t('orgs.id'),
      type: 'text',
      mono: true,
      render: o => o.id,
    },
    {
      key: 'name',
      header: t('orgs.nameHeader'),
      type: 'text',
      render: o => editingId === o.id ? (
        <input
          value={editName}
          onChange={e => setEditName(e.target.value)}
          aria-label={t('orgs.name')}
          className="control min-w-0 max-w-full sm:w-40"
        />
      ) : (
        // AUX-17: the name opens the entity inspector (read-only).
        <button
          type="button"
          onClick={() => setInspectId(o.id)}
          title={t('drawer.inspectHint')}
          className="inline-flex min-h-[36px] items-center text-start font-medium text-[color:var(--astra-ink)] hover:underline"
        >
          {o.name}
        </button>
      ),
    },
    {
      key: 'slug',
      header: t('orgs.slug'),
      type: 'text',
      render: o => editingId === o.id ? (
        <input
          value={editSlug}
          onChange={e => setEditSlug(e.target.value)}
          aria-label={t('orgs.slug')}
          className="control min-w-0 max-w-full font-mono text-xs sm:w-32"
        />
      ) : o.slug,
    },
    {
      key: 'currency',
      header: t('orgs.currency'),
      type: 'text',
      render: o => editingId === o.id ? (
        <input
          value={editCurrency}
          onChange={e => setEditCurrency(e.target.value)}
          aria-label={t('orgs.currency')}
          className="control font-mono text-xs sm:w-20"
        />
      ) : <span className="font-mono text-xs">{o.currency || 'USD'}</span>,
    },
    {
      key: 'timezone',
      header: t('orgs.timezone'),
      type: 'text',
      render: o => editingId === o.id ? (
        <input
          value={editTimezone}
          onChange={e => setEditTimezone(e.target.value)}
          aria-label={t('orgs.timezone')}
          className="control min-w-0 max-w-full font-mono text-xs sm:w-36"
        />
      ) : <span className="font-mono text-xs">{o.timezone || 'UTC'}</span>,
    },
    {
      key: 'issue_url_template',
      header: t('orgs.issueTemplate'),
      type: 'text',
      sortable: false,
      render: o => editingId === o.id ? (
        <input
          value={editIssue}
          onChange={e => setEditIssue(e.target.value)}
          aria-label={t('orgs.issueTemplate')}
          className="control min-w-0 max-w-full font-mono text-xs sm:w-48"
        />
      ) : <span className="block max-w-[12rem] truncate font-mono text-xs">{o.issue_url_template || '—'}</span>,
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('orgs.title')}
        purpose={t('orgs.purpose')}
      />

      {/* AUX-12 action surface (dialog), fixed-position. */}
      {deleteOrgAction.ui}

      {error && <StateNotice state="error" message={error} />}

      <form onSubmit={handleCreate} className="card flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgs.name')}</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder={t('orgs.acmeInc')}
            className="control sm:w-56"
            required
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgs.slugOptional')}</span>
          <input
            value={slug}
            onChange={e => setSlug(e.target.value)}
            placeholder={t('orgs.acme')}
            className="control sm:w-40"
          />
        </label>
        <button
          type="submit"
          disabled={creating || !name.trim()}
          className="btn-primary"
        >
          {creating ? t('orgs.creating') : t('orgs.createOrganization')}
        </button>
      </form>

      <div className="card overflow-x-auto">
        {loading && orgs.length === 0 ? (
          <StateNotice state="loading" message={t('orgs.fetching')} />
        ) : empty ? (
          <StateNotice state="empty" message={t('orgs.empty')} />
        ) : (
          <DataTable
            columns={columns}
            rows={orgs}
            getRowId={o => o.id}
            page={page}
            pageSize={pageSize}
            onPageChange={setPage}
            pagination="external"
            serverTotal={total}
            sortMode="server"
            sort={sort}
            onSortChange={handleSortChange}
            caption={t('orgs.title')}
            renderActions={o => editingId === o.id ? (
              <span className="inline-flex flex-wrap justify-end gap-2">
                <button
                  onClick={() => handleSaveEdit(o.id)}
                  disabled={busyOrgId !== '' || !editName.trim() || !editSlug.trim()}
                  className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-1 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50"
                >
                  {busyOrgId === o.id ? '…' : t('common.save')}
                </button>
                <button
                  onClick={() => setEditingId('')}
                  disabled={busyOrgId !== ''}
                  className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 py-1 text-xs font-medium text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)] disabled:opacity-50"
                >
                  {t('common.cancel')}
                </button>
              </span>
            ) : (
              // UI-VF-1: edit is reversible (no confirm); delete cascades
              // server-side and always asks.
              <span className="inline-flex flex-wrap justify-end gap-2">
                <button
                  onClick={() => startEdit(o)}
                  disabled={busyOrgId !== ''}
                  className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-1 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50"
                >
                  {t('common.edit')}
                </button>
                <button
                  onClick={() => handleDeleteOrg(o)}
                  disabled={busyOrgId !== ''}
                  className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 py-1 text-xs font-medium text-[color:var(--astra-danger)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50"
                >
                  {t('common.delete')}
                </button>
              </span>
            )}
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

      {/* AUX-17: the org inspector card. Fields come from the loaded row
          (the list response carries the full record); links navigate to the
          related lists with the scope params kept and ?inspect dropped. */}
      {(inspected || (inspectId && orgsLoaded && !loading)) && (
        <EntityDrawer
          kind={t('orgs.title')}
          title={inspected ? inspected.name : inspectId}
          onClose={() => setInspectId(null)}
          missing={!inspected}
          ids={inspected ? [{ label: t('drawer.id'), value: inspected.id }] : []}
          fields={inspected ? [
            { label: t('orgs.name'), value: inspected.name },
            { label: t('orgs.slug'), value: inspected.slug, mono: true },
            { label: t('orgs.currency'), value: inspected.currency || 'USD', mono: true },
            { label: t('orgs.timezone'), value: inspected.timezone || 'UTC', mono: true },
            { label: t('orgs.issueTemplate'), value: inspected.issue_url_template || '—', mono: true },
            { label: t('drawer.created'), value: inspected.created_at ?? t('common.notRecorded'), mono: true },
          ] : []}
          links={inspected ? [
            { label: t('app.navRequestsExplorer'), href: relatedListHref('requests-explorer', currentHashQuery(), { org: inspected.id }) },
            { label: t('app.navApiKeys'), href: relatedListHref('keys', currentHashQuery()) },
            { label: t('app.navRoutingRules'), href: relatedListHref('rules', currentHashQuery()) },
          ] : []}
        />
      )}
    </div>
  )
}
