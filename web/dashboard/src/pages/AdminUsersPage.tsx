import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listAdminUsers, createAdminUser, updateAdminUser, deleteAdminUser,
  type AdminUser,
} from '../api/client'
import { Pagination } from '../components/Pagination'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { formatDateTime } from '../i18n/format'
import { useAction } from '../components/astra/ActionDialog'
import type { SortState } from '../lib/tableSort'

const PAGE_SIZE = 50

// AUX-16: platform administrators (root-only CRUD over the existing
// /api/admin-users endpoints). Server sort + pagination (AUX-02 allowlist:
// id/email/display_name/is_root/active/created_at), same contract as Orgs.
// The create form never echoes the password; `active` is display-only (no
// update endpoint carries it). Grants/revocations of root and deletions go
// through ActionDialog (medium / high with typed confirmation).

export function AdminUsersPage() {
  const { t } = useTranslation()
  const [users, setUsers] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  // served (echoed in pagination), not a local constant.
  const [pageSize, setPageSize] = useState(PAGE_SIZE)
  const { page, setPage, sort, setSort } = useTableUrlState('admin-users', {
    defaultSort: { key: 'created_at', dir: 'desc' },
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  // Create form (the password is sent once and never stored client-side).
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [isRoot, setIsRoot] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const loadAbort = useRef<AbortController | null>(null)
  const loadSafe = useCallback(async (p: number, s: SortState | null) => {
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    try {
      const resp = await listAdminUsers(p, { signal: ctrl.signal, sort: s?.key, dir: s?.dir, pageSize: PAGE_SIZE })
      setUsers(resp.data ?? [])
      const pg = resp.pagination
      setTotal(pg?.total ?? resp.data?.length ?? 0)
      setPageSize(pg?.page_size ?? PAGE_SIZE)
      const lastPage = Math.max(1, pg?.total_pages ?? 1)
      setTotalPages(lastPage)
      // stale or URL-restored page beyond it steps back to the served last
      // page (the fetch effect follows the change).
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

  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password || creating) return
    setCreating(true)
    setCreateError(''); setNotice('')
    try {
      const created = await createAdminUser({
        email: email.trim(),
        password,
        name: name.trim(),
        is_root: isRoot,
      })
      setEmail(''); setName(''); setPassword(''); setIsRoot(false)
      setNotice(t('adminUsers.created', { email: created.email ?? email.trim() }))
      if (page === 1) await loadSafe(1, sort)
      else setPage(1)
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : String(err))
    } finally {
      setCreating(false)
    }
  }

  // Medium dialog: rename (was → becomes via the input's initial value).
  const renameAction = useAction({
    id: 'adminUsers.rename', risk: 'medium', reversible: false,
  })
  const handleRename = (u: AdminUser) => {
    setNotice('')
    renameAction.run({
      input: { label: t('adminUsers.colName'), initial: u.display_name },
      confirmLabel: t('common.save'),
      was: u.display_name || '—',
      execute: async ({ value }) => {
        await updateAdminUser(u.id, { name: value.trim() })
      },
      onDone: () => {
        setNotice(t('adminUsers.updated', { email: u.email }))
        void loadSafe(page, sort)
      },
    })
  }

  // Medium dialog: grant/revoke root (was → becomes).
  const rootAction = useAction({
    id: 'adminUsers.root', risk: 'medium', reversible: true,
  })
  const handleToggleRoot = (u: AdminUser) => {
    setNotice('')
    const next = !u.is_root
    rootAction.run({
      confirmLabel: next ? t('adminUsers.grantRoot') : t('adminUsers.revokeRoot'),
      was: u.is_root ? t('adminUsers.root') : t('adminUsers.notRoot'),
      becomes: next ? t('adminUsers.root') : t('adminUsers.notRoot'),
      execute: async () => {
        await updateAdminUser(u.id, { is_root: next })
      },
      onDone: () => {
        setNotice(t('adminUsers.updated', { email: u.email }))
        void loadSafe(page, sort)
      },
    })
  }

  // High dialog: delete the administrator (typed email confirmation).
  const removeAction = useAction({
    id: 'adminUsers.remove', risk: 'high', reversible: false,
    impact: t('adminUsers.removeImpact'),
  })
  const handleRemove = (u: AdminUser) => {
    setNotice('')
    removeAction.run({
      entity: u.email,
      confirmLabel: t('common.delete'),
      execute: async () => {
        await deleteAdminUser(u.id)
      },
      onDone: () => {
        setNotice(t('adminUsers.deleted', { email: u.email }))
        // refetched server pagination (the step-back clamp in loadSafe) —
        // not by a local remaining-rows counter.
        void loadSafe(page, sort)
      },
    })
  }

  const empty = !loading && users.length === 0

  // Every column maps to the AUX-02 server allowlist, so headers sort
  // server-side (same contract as Orgs/AuditLog).
  const columns: DataTableColumn<AdminUser>[] = [
    { key: 'email', header: t('adminUsers.colEmail'), type: 'text', mono: true, render: u => u.email },
    { key: 'display_name', header: t('adminUsers.colName'), type: 'text', render: u => u.display_name || '—' },
    {
      key: 'is_root', header: t('adminUsers.colRoot'), type: 'text',
      getSortValue: u => (u.is_root ? 1 : 0),
      render: u => (u.is_root
        ? <span className="whitespace-nowrap text-xs font-medium">● {t('adminUsers.root')}</span>
        : <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">○ {t('adminUsers.notRoot')}</span>),
    },
    {
      key: 'active', header: t('adminUsers.colActive'), type: 'text',
      getSortValue: u => (u.active ? 1 : 0),
      render: u => (u.active ? t('models.enabled') : t('models.disabled')),
    },
    {
      key: 'created_at', header: t('adminUsers.colCreated'), type: 'date', mono: true,
      render: u => (u.created_at ? formatDateTime(u.created_at) : '—'),
    },
  ]

  const rowBtnCls = 'btn-secondary px-3 py-1 text-xs font-medium'

  return (
    <div className="space-y-6">
      <PageHeader title={t('adminUsers.title')} purpose={t('adminUsers.purpose')} />

      {renameAction.ui}
      {rootAction.ui}
      {removeAction.ui}

      {notice && <p className="text-xs text-[color:var(--astra-success)]">{notice}</p>}
      {error && <StateNotice state="error" message={error} />}

      <form onSubmit={handleCreate} className="card flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('adminUsers.colEmail')}</span>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            disabled={creating}
            required
            className="control w-56"
            placeholder={t('adminUsers.phEmail')}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('adminUsers.colName')}</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={creating}
            className="control w-44"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('adminUsers.password')}</span>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            disabled={creating}
            required
            autoComplete="new-password"
            className="control w-44"
          />
        </label>
        <label className="flex min-h-[44px] items-center gap-2 text-sm text-[color:var(--astra-ink)]">
          <input
            type="checkbox"
            checked={isRoot}
            onChange={e => setIsRoot(e.target.checked)}
            disabled={creating}
          />
          {t('adminUsers.root')}
        </label>
        <button type="submit" disabled={creating || !email.trim() || !password} className="btn-primary">
          {t('adminUsers.add')}
        </button>
      </form>
      {createError && <StateNotice state="error" message={createError} />}

      <div className="card overflow-x-auto">
        {loading && users.length === 0 ? (
          <StateNotice state="loading" message={t('adminUsers.fetching')} />
        ) : empty ? (
          <StateNotice state="empty" message={t('adminUsers.empty')} />
        ) : (
          <DataTable
            columns={columns}
            rows={users}
            getRowId={u => u.id}
            page={page}
            pageSize={pageSize}
            onPageChange={setPage}
            pagination="external"
            serverTotal={total}
            sortMode="server"
            sort={sort}
            onSortChange={handleSortChange}
            defaultSort={{ key: 'created_at', dir: 'desc' }}
            caption={t('adminUsers.title')}
            renderActions={u => (
              <div className="flex justify-end gap-2">
                <button type="button" onClick={() => handleRename(u)} className={rowBtnCls}>
                  {t('common.edit')}
                </button>
                <button type="button" onClick={() => handleToggleRoot(u)} className={rowBtnCls}>
                  {u.is_root ? t('adminUsers.revokeRoot') : t('adminUsers.grantRoot')}
                </button>
                <button
                  type="button"
                  onClick={() => handleRemove(u)}
                  className={`${rowBtnCls} !text-[color:var(--astra-danger)]`}
                >
                  {t('common.delete')}
                </button>
              </div>
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
    </div>
  )
}
