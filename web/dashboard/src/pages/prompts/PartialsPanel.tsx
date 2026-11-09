import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createPartial, deletePartial, listPartials, updatePartial, type PromptPartial } from '../../api/prompts'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { RowActions } from '../../components/astra/RowActions'
import { useAction } from '../../components/astra/ActionDialog'
import { templatePreview } from '../../lib/promptRender'

// {{partials.name}}. PUT bumps the version; DELETE never checks references
// (the server does not block), so the delete dialog carries the honest
// warning: templates referencing the partial will fail to render.

export function PartialsPanel({
  org, canManage, manageHint,
}: {
  org: string
  canManage: boolean
  manageHint?: string
}) {
  const { t } = useTranslation()
  const [actionError, setActionError] = useState('')

  const listFetcher = useCallback(async (signal: AbortSignal) => listPartials(org, { signal }), [org])
  const list = useScopedQuery<PromptPartial[]>({
    key: `partials|${org}`,
    org,
    fetcher: listFetcher,
  })
  const rows = useMemo(() => list.data ?? [], [list.data])

  // create / edit share one drawer (edit pre-fills the body)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<PromptPartial | null>(null)
  const [draftName, setDraftName] = useState('')
  const [draftBody, setDraftBody] = useState('')

  const openCreate = () => {
    setEditing(null)
    setDraftName('')
    setDraftBody('')
    setActionError('')
    setDrawerOpen(true)
  }
  const openEdit = (partial: PromptPartial) => {
    setEditing(partial)
    setDraftName(partial.name)
    setDraftBody(partial.body)
    setActionError('')
    setDrawerOpen(true)
  }

  const submitDrawer = async () => {
    if (editing) {
      try {
        await updatePartial(org, editing.name, draftBody, editing.version)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        if (message.includes('409') || message.includes('428')) {
          setActionError(message.includes('428')
            ? `${t('prompts.versionRequired')}. ${t('prompts.reloadConflict')}`
            : `${t('prompts.versionConflict')}. ${t('prompts.reloadConflict')}`)
          void list.load({ refresh: true })
        }
        throw error
      }
    } else {
      await createPartial(org, { name: draftName.trim(), body: draftBody })
    }
    setDrawerOpen(false)
    list.load({ refresh: true })
  }

  const deleteAction = useAction({
    id: 'prompts.deletePartial',
    risk: 'high',
    reversible: false,
    impact: t('prompts.partialDeleteImpact'),
  })
  const handleDelete = (partial: PromptPartial) => {
    setActionError('')
    deleteAction.run({
      entity: partial.name,
      confirmLabel: t('prompts.partialDelete'),
      execute: async () => {
        await deletePartial(org, partial.name)
        list.load({ refresh: true })
      },
      onError: message => {
        setActionError(message.includes('428')
          ? `${t('prompts.versionRequired')}. ${t('prompts.reloadConflict')}`
          : message.includes('409')
            ? `${t('prompts.versionConflict')}. ${t('prompts.reloadConflict')}`
            : message)
        if (message.includes('409') || message.includes('428')) list.load({ refresh: true })
      },
    })
  }

  // AUX-23: a failed refresh keeps the last good data — surface the honest
  // stale marker instead of pretending nothing happened.
  useEffect(() => {
    if (list.error) setActionError(list.error)
  }, [list.error])

  const columns: DataTableColumn<PromptPartial>[] = [
    { key: 'name', header: t('prompts.partialColName'), type: 'text', mono: true },
    {
      key: 'body', header: t('prompts.partialColBody'), type: 'text', sortable: false,
      render: p => <span className="font-mono text-xs">{templatePreview(p.body, 120)}</span>,
    },
    { key: 'version', header: t('prompts.partialColVersion'), type: 'number', mono: true, align: 'right' },
    { key: 'updated_at', header: t('prompts.colUpdated'), format: 'date', render: p => p.updated_at },
    {
      key: 'row-actions', header: t('common.actions'), sortable: false,
      render: p => (
        <RowActions
          label={t('prompts.partialRowActionsAria', { name: p.name })}
          items={[
            { id: 'edit', label: t('common.edit'), disabled: !canManage, onSelect: () => openEdit(p) },
            { id: 'delete', label: t('common.delete'), risk: 'high', disabled: !canManage, onSelect: () => handleDelete(p) },
          ]}
        />
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="btn-primary" onClick={openCreate} disabled={!canManage}>
          {t('prompts.partialNew')}
        </button>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('prompts.partialHint')}</p>
        {manageHint && <p className="text-sm text-[color:var(--astra-text-muted)]">{manageHint}</p>}
      </div>

      {actionError && <StateNotice state="error" message={actionError} />}
      {list.refreshStale && <StateNotice state="stale" message={t('prompts.staleData')} />}

      <div className="card overflow-x-auto">
        <DataTable
          columns={columns}
          rows={rows}
          getRowId={p => p.id}
          loading={list.loading}
          empty={t('prompts.partialEmpty')}
          page={1}
          pageSize={Math.max(1, rows.length)}
          onPageChange={() => {}}
          serverTotal={rows.length}
          sortMode="client"
          caption={t('prompts.tabPartials')}
        />
      </div>

      <FormDrawer
        open={drawerOpen}
        kind={t('prompts.tabPartials')}
        title={editing ? t('prompts.partialEditTitle', { name: editing.name }) : t('prompts.partialCreateTitle')}
        submitLabel={t('common.save')}
        onClose={() => setDrawerOpen(false)}
        onSubmit={submitDrawer}
      >
        {!editing && (
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.partialFieldName')}</span>
            <input
              className="control w-full font-mono"
              value={draftName}
              onChange={e => setDraftName(e.target.value)}
              maxLength={256}
              required
              autoFocus
              spellCheck={false}
              aria-label={t('prompts.partialFieldName')}
            />
            <span className="text-xs text-[color:var(--astra-text-muted)]">{t('prompts.partialFieldNameHint')}</span>
          </label>
        )}
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('prompts.partialFieldBody')}</span>
          <textarea
            className="control min-h-[160px] w-full font-mono"
            value={draftBody}
            onChange={e => setDraftBody(e.target.value)}
            required
            autoFocus={editing !== null}
            spellCheck={false}
            aria-label={t('prompts.partialFieldBody')}
          />
          {editing && (
            <span className="text-xs text-[color:var(--astra-text-muted)]">
              {t('prompts.partialEditVersionNote', { version: editing.version + 1 })}
            </span>
          )}
        </label>
      </FormDrawer>

      {deleteAction.ui}
    </div>
  )
}
