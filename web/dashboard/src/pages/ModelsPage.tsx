import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listModels, getModel, createModel, updateModel, deleteModel, setModelEnabled,
  listModelAliases, createModelAlias, deleteModelAlias,
  MODEL_TIERS, type ModelEntry, type ModelFormValues, type ModelAlias,
} from '../api/client'
import { Pagination } from '../components/Pagination'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { EntityDrawer } from '../components/astra/EntityDrawer'
import { useAction } from '../components/astra/ActionDialog'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { useInspectParam } from '../hooks/useInspectParam'
import { currentHashQuery, relatedListHref } from '../lib/inspectUrl'
import type { SortState } from '../lib/tableSort'

const PAGE_SIZE = 25

// ASTR-07 + PO-03: pending is tracked PER MODEL and per action kind (a slow
// mutation on one row must not block other rows); a ref-based in-flight set
// guards double-clicks ahead of re-render. Full CRUD: create, edit (dialog),
// delete (typed confirmation), enable/disable. upstream_api_key is write-only
// — the form shows a placeholder, never a value (the server never returns it).

type ActionKind = 'enable' | 'disable' | 'update' | 'delete'

const emptyForm: ModelFormValues = {
  model_name: '',
  display_name: '',
  tier: 'easy',
  provider: '',
  upstream_url: '',
  upstream_api_key: '',
  fallback_model: '',
  failover_models: '',
  tier_pool: '',
  upstream_timeout_ms: '',
  enabled: true,
}

function toForm(m: ModelEntry): ModelFormValues {
  return {
    model_name: m.model_name,
    display_name: m.display_name ?? '',
    tier: m.tier || 'easy',
    provider: m.provider ?? '',
    upstream_url: m.upstream_url ?? '',
    upstream_api_key: '',
    fallback_model: m.fallback_model ?? '',
    failover_models: (m.failover_models ?? []).join(', '),
    tier_pool: (m.tier_pool ?? []).join(', '),
    upstream_timeout_ms: m.upstream_timeout_ms != null ? String(m.upstream_timeout_ms) : '',
    enabled: m.enabled,
  }
}

export function ModelsPage() {
  const { t } = useTranslation()
  const [models, setModels] = useState<ModelEntry[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  // served (echoed in pagination), not a local constant — until the list
  const [pageSize, setPageSize] = useState(PAGE_SIZE)
  // AUX-03 (server sort): page + sort live in the URL; the server owns the
  // row order (AUX-02 allowlist) and 400 invalid_sort surfaces as an error.
  const { page, setPage, sort, setSort } = useTableUrlState('models')
  // AUX-17: the model inspector — opened from an entity-name click and from
  // the ?inspect=<model_name> deep link. The list row is a projection, so
  // the card re-reads the EXISTING detail GET (getModel) for the full field
  // set and falls back to the row when that fetch fails.
  const [inspectId, setInspectId] = useInspectParam()
  const inspected = useMemo(
    () => models.find(m => m.model_name === inspectId) ?? null,
    [models, inspectId],
  )
  const [inspectedDetail, setInspectedDetail] = useState<ModelEntry | null>(null)
  const [detailError, setDetailError] = useState('')
  const [modelsLoaded, setModelsLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  // The detail record wins over the list-row projection when it arrives.
  const inspectedFull = inspected ? inspectedDetail ?? inspected : null
  const [pending, setPending] = useState<Record<string, ActionKind>>({})
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<ModelEntry | null>(null)
  const [form, setForm] = useState<ModelFormValues>(emptyForm)
  const [formError, setFormError] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<ModelEntry | null>(null)
  const [confirmDisable, setConfirmDisable] = useState<ModelEntry | null>(null)
  const [confirmText, setConfirmText] = useState('')
  const inFlight = useRef<Set<string>>(new Set())
  const dialogRef = useRef<HTMLDivElement>(null)
  const disableDialogRef = useRef<HTMLDivElement>(null)
  const lastFocused = useRef<HTMLElement | null>(null)

  // AUX-16: model aliases (existing /api/model-aliases routes, root-only like
  // the models CRUD). The list endpoint returns a plain array; a non-array
  // body (older stub/backend) honestly renders as an empty table. Create is a
  // form (target picks from the loaded registry with a free-text escape),
  // delete goes through a high ActionDialog with the typed alias.
  const [aliases, setAliases] = useState<ModelAlias[]>([])
  const [aliasesLoaded, setAliasesLoaded] = useState(false)
  const [aliasError, setAliasError] = useState('')
  const [aliasFormError, setAliasFormError] = useState('')
  const [aliasName, setAliasName] = useState('')
  const [aliasTarget, setAliasTarget] = useState('')
  const [aliasBusy, setAliasBusy] = useState(false)
  const [aliasNotice, setAliasNotice] = useState('')

  const aliasRemove = useAction({
    id: 'models.alias.delete', risk: 'high', reversible: false,
    impact: t('aliases.removeImpact'),
  })

  const loadAliases = useCallback(async () => {
    setAliasError('')
    try {
      const rows = await listModelAliases()
      setAliases(rows)
      setAliasesLoaded(true)
    } catch (e: unknown) {
      setAliasError(e instanceof Error ? e.message : String(e))
      setAliasesLoaded(true)
    }
  }, [])

  useEffect(() => {
    void loadAliases()
  }, [loadAliases])

  const handleCreateAlias = async (e: React.FormEvent) => {
    e.preventDefault()
    const alias = aliasName.trim()
    const target = aliasTarget.trim()
    if (!alias || !target || aliasBusy) return
    setAliasBusy(true)
    setAliasFormError(''); setAliasNotice('')
    try {
      await createModelAlias(alias, target)
      setAliasName(''); setAliasTarget('')
      setAliasNotice(t('aliases.created', { alias }))
      await loadAliases()
    } catch (err: unknown) {
      setAliasFormError(err instanceof Error ? err.message : String(err))
    } finally {
      setAliasBusy(false)
    }
  }

  const handleRemoveAlias = (a: ModelAlias) => {
    setAliasNotice('')
    aliasRemove.run({
      entity: a.alias,
      confirmLabel: t('aliases.remove'),
      execute: async () => {
        await deleteModelAlias(a.alias)
      },
      onDone: () => {
        setAliasNotice(t('aliases.removed', { alias: a.alias }))
        void loadAliases()
      },
    })
  }

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
      const resp = await listModels(p, { signal: ctrl.signal, sort: s?.key, dir: s?.dir, pageSize: PAGE_SIZE })
      setModels(resp.data ?? [])
      const pg = resp.pagination
      setTotal(pg?.total ?? resp.data?.length ?? 0)
      setPageSize(pg?.page_size ?? PAGE_SIZE)
      const lastPage = Math.max(1, pg?.total_pages ?? 1)
      setTotalPages(lastPage)
      // stale or URL-restored page beyond it steps back to the served last
      // page (the fetch effect follows the change).
      if (p > lastPage) setPage(lastPage)
      setModelsLoaded(true)
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

  // AUX-17: refresh the inspector's detail projection when the inspected
  // model changes (existing detail endpoint; the drawer merges it over the
  // list row and shows an honest error notice when it fails).
  useEffect(() => {
    if (!inspected) { setInspectedDetail(null); setDetailError(''); return }
    let alive = true
    setInspectedDetail(null)
    setDetailError('')
    getModel(inspected.model_name)
      .then(full => { if (alive) setInspectedDetail(full) })
      .catch((e: unknown) => {
        if (alive) setDetailError(e instanceof Error ? e.message : String(e))
      })
    return () => { alive = false }
  }, [inspected])

  // AUX-12 contract: a header click in server mode re-asks the backend; the
  // sort change resets the page to 1 (the view is a new ordering).
  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  const beginPending = (name: string, kind: ActionKind) => {
    inFlight.current.add(`${name}:${kind}`)
    setPending(prev => ({ ...prev, [name]: kind }))
  }
  const endPending = (name: string, kind: ActionKind) => {
    inFlight.current.delete(`${name}:${kind}`)
    setPending(prev => {
      if (prev[name] !== kind) return prev
      const { [name]: _removed, ...rest } = prev
      return rest
    })
  }

  const applyToggle = async (m: ModelEntry) => {
    const name = m.model_name
    const next: ActionKind = m.enabled ? 'disable' : 'enable'
    if (inFlight.current.has(`${name}:${next}`)) return
    beginPending(name, next)
    setError(''); setNotice('')
    try {
      await setModelEnabled(name, next === 'enable')
      await loadSafe(page, sort)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(t('models.toggleFailed', { action: next, name, message: msg }))
    } finally {
      endPending(name, next)
    }
  }

  // UI-contract #8: disabling is reversible but changes routing eligibility —
  // confirm first with a registry-level impact preview (fallback/failover
  // dependents among the loaded models; org-scoped rules are honestly noted
  // as not visible here). Enabling is immediate.
  const toggle = (m: ModelEntry) => {
    if (m.enabled) {
      setConfirmDisable(m)
      return
    }
    void applyToggle(m)
  }

  const confirmDisableSubmit = () => {
    const m = confirmDisable
    setConfirmDisable(null)
    if (m) void applyToggle(m)
  }

  const openCreate = () => {
    lastFocused.current = document.activeElement as HTMLElement | null
    setEditing(null)
    setForm(emptyForm)
    setFormError('')
    setFormOpen(true)
  }
  const openEdit = async (m: ModelEntry) => {
    if (inFlight.current.has(`${m.model_name}:update`)) return
    lastFocused.current = document.activeElement as HTMLElement | null
    setEditing(m)
    setForm(toForm(m))
    setFormError('')
    setFormOpen(true)
    // Fresh fetch: the list row is a projection; the detail endpoint carries
    // the full field set (upstream_url, failover lists, timeout).
    try {
      const full = await getModel(m.model_name)
      setForm(toForm(full))
    } catch (e: unknown) {
      setFormError(e instanceof Error ? e.message : String(e))
    }
  }

  const closeForm = () => {
    setFormOpen(false)
    setFormError('')
    lastFocused.current?.focus()
  }

  // Dialog focus contract: move focus in on open, Escape closes with focus
  // returned to the trigger (same contract as RequestInspector).
  useEffect(() => {
    if (!formOpen) return
    const first = dialogRef.current?.querySelector<HTMLElement>('input, select, button')
    first?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeForm()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [formOpen])

  // Disable-impact dialog: same focus/Escape contract as the other dialogs.
  useEffect(() => {
    if (!confirmDisable) return
    disableDialogRef.current?.querySelector<HTMLElement>('button')?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setConfirmDisable(null)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [confirmDisable])

  const setField = (k: keyof ModelFormValues, v: string | boolean) =>
    setForm(prev => ({ ...prev, [k]: v }))

  const submitForm = async () => {
    const creating = editing == null
    if (creating && !form.model_name.trim()) {
      setFormError(t('models.nameRequired'))
      return
    }
    const name = creating ? form.model_name : editing!.model_name
    if (inFlight.current.has(`${name}:update`)) return
    beginPending(name, 'update')
    setFormError(''); setError(''); setNotice('')
    try {
      if (creating) {
        await createModel(form)
        setNotice(t('models.created', { name }))
      } else {
        await updateModel(editing!.model_name, form)
        setNotice(t('models.updated', { name }))
      }
      setFormOpen(false)
      lastFocused.current?.focus()
      // New models land on page 1; an explicit load covers the
      // already-on-page-1 case (the effect only refires on a state change).
      if (creating && page === 1) await loadSafe(1, sort)
      else if (creating) setPage(1)
      else await loadSafe(page, sort)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setFormError(t('models.saveFailed', { message: msg }))
    } finally {
      endPending(name, 'update')
    }
  }

  const confirmDeleteSubmit = async () => {
    const m = confirmDelete
    if (!m || confirmText.trim() !== m.model_name) return
    if (inFlight.current.has(`${m.model_name}:delete`)) return
    beginPending(m.model_name, 'delete')
    setError(''); setNotice('')
    try {
      await deleteModel(m.model_name)
      setNotice(t('models.deleted', { name: m.model_name }))
      setConfirmDelete(null)
      setConfirmText('')
      await loadSafe(page, sort)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(t('models.deleteFailed', { name: m.model_name, message: msg }))
    } finally {
      endPending(m.model_name, 'delete')
    }
  }

  const empty = !loading && models.length === 0

  // AUX-03: DataTable v2 columns. Every column maps to an AUX-02 server
  // allowlist entry (model_name/display_name/tier/enabled), so each header
  // sorts server-side; type/unit metadata drives the typed comparator.
  const columns: DataTableColumn<ModelEntry>[] = [
    {
      key: 'model_name',
      header: t('models.model'),
      type: 'text',
      mono: true,
      render: m => (
        // AUX-17: the model name opens the entity inspector (read-only).
        <button
          type="button"
          onClick={() => setInspectId(m.model_name)}
          title={t('drawer.inspectHint')}
          className="inline-flex min-h-[36px] items-center text-start hover:underline"
          style={{ fontFamily: 'var(--astra-font-code)' }}
        >
          {m.model_name}
        </button>
      ),
    },
    {
      key: 'display_name',
      header: t('models.displayName'),
      type: 'text',
      render: m => m.display_name,
    },
    {
      key: 'tier',
      header: t('models.tier'),
      type: 'text',
      render: m => m.tier,
    },
    {
      key: 'enabled',
      header: t('models.status'),
      type: 'text',
      getSortValue: m => (m.enabled ? 1 : 0),
      render: m => {
        const action = pending[m.model_name]
        const isPending = action != null
        if (isPending) {
          return (
            <span className="whitespace-nowrap text-xs font-medium" style={{ color: 'var(--astra-warning)' }}>
              <span aria-hidden="true">◐ </span>{t('models.pendingAction', { action })}
            </span>
          )
        }
        return m.enabled ? (
          <span className="whitespace-nowrap text-xs" style={{ color: 'var(--astra-success)' }}>
            <span aria-hidden="true">● </span>{t('models.enabled')}
          </span>
        ) : (
          <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">
            <span aria-hidden="true">○ </span>{t('models.disabled')}
          </span>
        )
      },
    },
  ]

  // PO-03: Astra control surfaces (token-driven; see standards/design.md).
  const baseBorder = 'border border-[color:var(--astra-rule-strong)]'
  const baseSurface = 'bg-[color:var(--astra-surface)]'
  const baseRadius = 'rounded-[length:var(--astra-radius-control)]'
  const baseInk = 'text-[color:var(--astra-ink)]'
  const baseHover = 'hover:bg-[color:var(--astra-surface-muted)]'
  const baseDisabled = 'disabled:opacity-50'
  const fieldCls =
    `${baseRadius} ${baseBorder} ${baseSurface} ${baseInk} w-full px-3 py-1.5 text-sm`
  const labelCls = 'mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]'
  const rowBtnCls =
    `${baseRadius} ${baseBorder} ${baseSurface} ${baseInk} ${baseHover} ${baseDisabled} px-3 py-1 text-xs font-medium`

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('models.title')}
        purpose={t('models.purpose')}
        actions={[{ label: t('models.create'), onClick: openCreate, primary: true }]}
      />

      {/* StateNotice has no success state (honest visual vocabulary): the
          confirmation line is a plain muted note, not a status banner. */}
      {notice && <p className="text-xs text-[color:var(--astra-success)]">{notice}</p>}
      {error && <StateNotice state="error" message={error} />}

      <div className="card overflow-x-auto">
        {loading && models.length === 0 ? (
          <StateNotice state="loading" message={t('models.fetching')} />
        ) : empty ? (
          <StateNotice state="empty" message={t('models.empty')} />
        ) : (
          <DataTable
            columns={columns}
            rows={models}
            getRowId={m => m.model_name}
            page={page}
            pageSize={pageSize}
            onPageChange={setPage}
            pagination="external"
            serverTotal={total}
            sortMode="server"
            sort={sort}
            onSortChange={handleSortChange}
            caption={t('models.title')}
            renderActions={m => {
              const action = pending[m.model_name]
              const isPending = action != null
              return (
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => openEdit(m)}
                    disabled={isPending}
                    className={rowBtnCls}
                  >
                    {t('models.edit')}
                  </button>
                  <button
                    onClick={() => toggle(m)}
                    disabled={isPending}
                    className={rowBtnCls}
                  >
                    {isPending && (action === 'enable' || action === 'disable')
                      ? (action === 'enable' ? t('models.enabling') : t('models.disabling'))
                      : m.enabled ? t('models.disable') : t('models.enable')}
                  </button>
                  <button
                    onClick={() => { setConfirmDelete(m); setConfirmText('') }}
                    disabled={isPending}
                    className={`${rowBtnCls} !text-[color:var(--astra-danger)]`}
                  >
                    {t('models.delete')}
                  </button>
                </div>
              )
            }}
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

      <p className="text-xs text-[color:var(--astra-text-muted)]">
        {t('models.impact')}
      </p>

      {/* AUX-16: model aliases — one registry-level name → target mapping
          table over the existing /api/model-aliases routes. */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('aliases.section')}
        </h2>
        {aliasRemove.ui}
        {aliasNotice && <p className="text-xs text-[color:var(--astra-success)]">{aliasNotice}</p>}
        {aliasFormError && <StateNotice state="error" message={aliasFormError} />}

        <form onSubmit={handleCreateAlias} className="card flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('aliases.alias')}</span>
            <input
              value={aliasName}
              onChange={e => setAliasName(e.target.value)}
              disabled={aliasBusy}
              className="control w-56 font-[family-name:var(--astra-font-code)]"
              placeholder="fast"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('aliases.target')}</span>
            <input
              value={aliasTarget}
              onChange={e => setAliasTarget(e.target.value)}
              disabled={aliasBusy}
              list="alias-target-options"
              className="control w-64 font-[family-name:var(--astra-font-code)]"
              placeholder="glm-5.3-flash"
            />
            <datalist id="alias-target-options">
              {models.map(m => <option key={m.model_name} value={m.model_name} />)}
            </datalist>
          </label>
          <button type="submit" disabled={aliasBusy || !aliasName.trim() || !aliasTarget.trim()} className="btn-primary">
            {t('aliases.add')}
          </button>
        </form>

        <div className="card overflow-x-auto">
          {aliasError ? (
            <StateNotice state="error" message={aliasError} />
          ) : !aliasesLoaded ? (
            <StateNotice state="loading" message={t('aliases.fetching')} />
          ) : aliases.length === 0 ? (
            <StateNotice state="empty" message={t('aliases.empty')} />
          ) : (
            <DataTable
              columns={[
                { key: 'alias', header: t('aliases.alias'), type: 'text', mono: true, render: a => a.alias },
                { key: 'target_model', header: t('aliases.target'), type: 'text', mono: true, render: a => a.target_model },
              ]}
              rows={aliases}
              getRowId={a => a.alias}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              sortMode="client"
              caption={t('aliases.section')}
              renderActions={a => (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => handleRemoveAlias(a)}
                    className={`${rowBtnCls} !text-[color:var(--astra-danger)]`}
                  >
                    {t('aliases.remove')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      {formOpen && (
        <div
          ref={dialogRef}
          role="dialog"
          aria-modal="true"
          aria-label={t(editing ? 'models.editTitle' : 'models.createTitle')}
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
        >
          <div aria-hidden="true" className="fixed inset-0" style={{ background: 'var(--astra-ink)', opacity: 0.4 }} />
          <div className="card relative max-h-[90vh] w-full max-w-xl overflow-y-auto space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">
                {t(editing ? 'models.editTitle' : 'models.createTitle')}
              </h2>
              <button type="button" onClick={closeForm} aria-label={t('common.close')} className={rowBtnCls}>✕</button>
            </div>

            {formError && <StateNotice state="error" message={formError} />}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className={labelCls} htmlFor="mf-name">{t('models.model')}</label>
                <input
                  id="mf-name"
                  className={fieldCls}
                  value={form.model_name}
                  disabled={!!editing}
                  onChange={e => setField('model_name', e.target.value)}
                  placeholder="gpt-4"
                  style={{ fontFamily: 'var(--astra-font-code)' }}
                />
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-display">{t('models.displayName')}</label>
                <input id="mf-display" className={fieldCls} value={form.display_name}
                  onChange={e => setField('display_name', e.target.value)} />
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-tier">{t('models.tier')}</label>
                <select id="mf-tier" className={fieldCls} value={form.tier}
                  onChange={e => setField('tier', e.target.value)}>
                  {MODEL_TIERS.map(tier => <option key={tier} value={tier}>{tier}</option>)}
                </select>
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-provider">{t('models.provider')}</label>
                <input id="mf-provider" className={fieldCls} value={form.provider}
                  onChange={e => setField('provider', e.target.value)} placeholder="openai-compat" />
              </div>
              <div className="sm:col-span-2">
                <label className={labelCls} htmlFor="mf-url">{t('models.upstreamUrl')}</label>
                <input id="mf-url" className={fieldCls} value={form.upstream_url}
                  onChange={e => setField('upstream_url', e.target.value)} placeholder={t('models.phUrl')} />
              </div>
              <div className="sm:col-span-2">
                <label className={labelCls} htmlFor="mf-key">{t('models.upstreamKey')}</label>
                <input
                  id="mf-key"
                  type="password"
                  className={fieldCls}
                  value={form.upstream_api_key}
                  onChange={e => setField('upstream_api_key', e.target.value)}
                  placeholder={t('models.keyPlaceholder')}
                  autoComplete="new-password"
                />
                <p className="mt-1 text-[11px] text-[color:var(--astra-text-muted)]">{t('models.keyNote')}</p>
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-fallback">{t('models.fallbackModel')}</label>
                <input id="mf-fallback" className={fieldCls} value={form.fallback_model}
                  onChange={e => setField('fallback_model', e.target.value)} style={{ fontFamily: 'var(--astra-font-code)' }} />
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-timeout">{t('models.timeout')}</label>
                <input id="mf-timeout" className={fieldCls} value={form.upstream_timeout_ms}
                  onChange={e => setField('upstream_timeout_ms', e.target.value)} inputMode="numeric" placeholder="30000" />
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-failover">{t('models.failover')}</label>
                <input id="mf-failover" className={fieldCls} value={form.failover_models}
                  onChange={e => setField('failover_models', e.target.value)} placeholder={t('models.phFailover')} style={{ fontFamily: 'var(--astra-font-code)' }} />
              </div>
              <div>
                <label className={labelCls} htmlFor="mf-pool">{t('models.tierPool')}</label>
                <input id="mf-pool" className={fieldCls} value={form.tier_pool}
                  onChange={e => setField('tier_pool', e.target.value)} placeholder={t('models.phPool')} style={{ fontFamily: 'var(--astra-font-code)' }} />
              </div>
            </div>

            {editing && (
              <label className="flex items-center gap-2 text-sm text-[color:var(--astra-ink)]">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={e => setField('enabled', e.target.checked)}
                />
                {t('models.enabled')}
              </label>
            )}

            <div className="flex justify-end gap-2 border-t border-[color:var(--astra-rule)] pt-3">
              <button type="button" onClick={closeForm} className={rowBtnCls}>
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={submitForm}
                className={`${rowBtnCls} border-[color:var(--astra-accent)] bg-[color:var(--astra-accent)] text-white hover:opacity-90`}
              >
                {t(editing ? 'models.save' : 'models.create')}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmDelete && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={t('models.deleteTitle', { name: confirmDelete.model_name })}
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
        >
          <div aria-hidden="true" className="fixed inset-0" style={{ background: 'var(--astra-ink)', opacity: 0.4 }} />
          <div className="card relative w-full max-w-md space-y-4">
            <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">
              {t('models.deleteTitle', { name: confirmDelete.model_name })}
            </h2>
            <p className="text-sm text-[color:var(--astra-text-muted)]">
              {t('models.deleteConfirm', { name: confirmDelete.model_name })}
            </p>
            <input
              className={fieldCls}
              value={confirmText}
              onChange={e => setConfirmText(e.target.value)}
              placeholder={confirmDelete.model_name}
              aria-label={t('models.deleteConfirmInput')}
              style={{ fontFamily: 'var(--astra-font-code)' }}
            />
            <div className="flex justify-end gap-2 border-t border-[color:var(--astra-rule)] pt-3">
              <button type="button" onClick={() => { setConfirmDelete(null); setConfirmText('') }} className={rowBtnCls}>
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={confirmDeleteSubmit}
                disabled={confirmText.trim() !== confirmDelete.model_name}
                className={`${rowBtnCls} border-[color:var(--astra-danger)] text-[color:var(--astra-danger)]`}
              >
                {t('models.delete')}
              </button>
            </div>
          </div>
        </div>
      )}

      {confirmDisable && (() => {
        const name = confirmDisable.model_name
        const fallbackDependents = models.filter(m => m.fallback_model === name)
        const failoverDependents = models.filter(m => (m.failover_models ?? []).includes(name))
        return (
          <div
            ref={disableDialogRef}
            role="dialog"
            aria-modal="true"
            aria-label={t('models.disableTitle', { name })}
            className="fixed inset-0 z-40 flex items-center justify-center p-4"
          >
            <div aria-hidden="true" className="fixed inset-0" style={{ background: 'var(--astra-ink)', opacity: 0.4 }} />
            <div className="card relative w-full max-w-md space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">
                  {t('models.disableTitle', { name })}
                </h2>
                <button type="button" onClick={() => setConfirmDisable(null)} aria-label={t('common.close')} className={rowBtnCls}>✕</button>
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">
                {t('models.disableConfirm')}
              </p>
              <div>
                <p className="text-xs font-semibold text-[color:var(--astra-ink)]">{t('models.disableDependsOnIt')}</p>
                <ul className="mt-1 space-y-1 text-sm text-[color:var(--astra-text-muted)]">
                  {fallbackDependents.length > 0 && (
                    <li>{t('models.disableDependentsFallback', { count: fallbackDependents.length, name })}</li>
                  )}
                  {failoverDependents.length > 0 && (
                    <li>{t('models.disableDependentsFailover', { count: failoverDependents.length, name })}</li>
                  )}
                  {fallbackDependents.length === 0 && failoverDependents.length === 0 && (
                    <li>{t('models.disableDependentsNone', { name })}</li>
                  )}
                </ul>
              </div>
              <div className="flex justify-end gap-2 border-t border-[color:var(--astra-rule)] pt-3">
                <button type="button" onClick={() => setConfirmDisable(null)} className={rowBtnCls}>
                  {t('common.cancel')}
                </button>
                <button
                  type="button"
                  onClick={confirmDisableSubmit}
                  className={`${rowBtnCls} border-[color:var(--astra-danger)] text-[color:var(--astra-danger)]`}
                >
                  {t('models.disableAction')}
                </button>
              </div>
            </div>
          </div>
        )
      })()}

      {/* AUX-17: the model inspector card. Detail GET first, row as the
          fallback; upstream_api_key is write-only and is never shown. */}
      {(inspected || (inspectId && modelsLoaded && !loading)) && (
        <EntityDrawer
          kind={t('models.title')}
          title={inspectedFull ? inspectedFull.model_name : inspectId}
          onClose={() => setInspectId(null)}
          missing={!inspectedFull}
          ids={inspectedFull ? [{ label: t('models.model'), value: inspectedFull.model_name }] : []}
          fields={inspectedFull ? [
            { label: t('models.displayName'), value: inspectedFull.display_name || '—' },
            { label: t('models.tier'), value: inspectedFull.tier || '—' },
            { label: t('models.status'), value: inspectedFull.enabled ? t('models.enabled') : t('models.disabled') },
            { label: t('models.provider'), value: inspectedFull.provider || '—', mono: true },
            { label: t('models.upstreamUrl'), value: inspectedFull.upstream_url || '—', mono: true },
            { label: t('models.timeout'), value: inspectedFull.upstream_timeout_ms != null ? `${inspectedFull.upstream_timeout_ms} ms` : '—' },
            { label: t('models.fallbackModel'), value: inspectedFull.fallback_model || '—', mono: true },
            {
              label: t('models.failover'),
              value: (inspectedFull.failover_models ?? []).length > 0 ? inspectedFull.failover_models!.join(', ') : '—',
              mono: true,
            },
            {
              label: t('models.tierPool'),
              value: (inspectedFull.tier_pool ?? []).length > 0 ? inspectedFull.tier_pool!.join(', ') : '—',
              mono: true,
            },
          ] : []}
          links={inspectedFull ? [
            { label: t('app.navRequestsExplorer'), href: relatedListHref('requests-explorer', currentHashQuery(), { model: inspectedFull.model_name }) },
            { label: t('app.navRoutingRules'), href: relatedListHref('rules', currentHashQuery()) },
          ] : []}
        >
          {detailError && <StateNotice state="error" message={t('drawer.detailFailed', { message: detailError })} />}
        </EntityDrawer>
      )}
    </div>
  )
}
