import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createPrompt, deletePrompt, getPrompt, listPrompts, type Prompt, type PromptLabelName } from '../../api/prompts'
import { useShellScope } from '../../hooks/useGlobalScope'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { usePermissions } from '../../hooks/usePermissions'
import { PageHeader } from '../../components/astra/PageHeader'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { RowActions } from '../../components/astra/RowActions'
import { useAction } from '../../components/astra/ActionDialog'
import { parseParamsObject } from '../../lib/promptRender'
import { LabelChips } from './LabelChips'
import { PromptDetail } from './PromptDetail'
import { PartialsPanel } from './PartialsPanel'
import { PlaygroundPanel } from './PlaygroundPanel'

// versioning, labels, partials and a client-side playground over the frozen
// policies.manage server-side; root passes). The shell OrgSwitcher owns the
// organization (same scope contract as RulesPage); every read rides
// useScopedQuery so a scope switch aborts the in-flight load.
//
// Honesty notes:
// - The list endpoint returns plain rows (no labels) — label chips load
//   best-effort per prompt and stay empty on failure (never an error state).
// - The playground renders TEMPLATES CLIENT-SIDE ONLY (no model call): the
//   screen is labeled preview-only next to the render output.
// - Saving a template APPENDS a version (immutable history): the confirm
//   dialog states the next version number before the PUT fires.

type StudioTab = 'prompts' | 'partials' | 'playground'

export function PromptsPage() {
  const { t } = useTranslation()
  const gs = useShellScope()
  const org = gs.org
  const perms = usePermissions(org || undefined)
  const canManage = perms.isRoot || perms.can('policies.manage')
  const manageHint = canManage ? undefined : t('perms.required', { permission: 'policies.manage' })

  const [tab, setTab] = useState<StudioTab>('prompts')
  const [selectedId, setSelectedId] = useState('')

  // ===== org prompt library =====
  const listFetcher = useCallback(async (signal: AbortSignal) => listPrompts(org, { signal }), [org])
  const list = useScopedQuery<Prompt[]>({
    key: `prompts|${org}`,
    org,
    enabled: org !== '',
    fetcher: listFetcher,
  })
  const rows = useMemo(() => list.data ?? [], [list.data])

  // Label chips: the list rows carry no labels, so each prompt's labels load
  // best-effort (prompt libraries are small). A failure leaves the chips
  // empty instead of flagging the screen — the detail view is authoritative.
  const [labelMap, setLabelMap] = useState<Record<string, PromptLabelName[]>>({})
  useEffect(() => {
    if (org === '' || rows.length === 0) {
      setLabelMap({})
      return
    }
    let alive = true
    const ac = new AbortController()
    void Promise.all(
      rows.map(p =>
        getPrompt(org, p.id, { signal: ac.signal })
          .then(d => [p.id, (d.labels ?? []).map(l => l.label)] as const)
          .catch(() => [p.id, [] as PromptLabelName[]] as const),
      ),
    ).then(entries => {
      if (alive) setLabelMap(Object.fromEntries(entries))
    })
    return () => {
      alive = false
      ac.abort()
    }
  }, [org, rows])

  // ===== create / delete =====
  const [createOpen, setCreateOpen] = useState(false)
  const [draftName, setDraftName] = useState('')
  const [draftDescription, setDraftDescription] = useState('')
  const [draftTemplate, setDraftTemplate] = useState('')
  const [draftParams, setDraftParams] = useState('')
  const [actionError, setActionError] = useState('')
  const draftParamsCheck = useMemo(() => parseParamsObject(draftParams), [draftParams])
  const deleteAction = useAction({
    id: 'prompts.delete',
    risk: 'high',
    reversible: false,
    impact: t('prompts.deleteImpact'),
  })

  const openCreate = () => {
    setDraftName('')
    setDraftDescription('')
    setDraftTemplate('')
    setDraftParams('')
    setActionError('')
    setCreateOpen(true)
  }

  const submitCreate = async () => {
    if (!draftParamsCheck.ok) throw new Error(t('prompts.paramsInvalid'))
    const detail = await createPrompt(org, {
      name: draftName.trim(),
      description: draftDescription.trim() || undefined,
      template: draftTemplate,
      params: draftParamsCheck.value,
    })
    setCreateOpen(false)
    list.load({ refresh: true })
    setSelectedId(detail.prompt.id)
  }

  const handleDelete = (prompt: Prompt) => {
    setActionError('')
    deleteAction.run({
      entity: prompt.name,
      confirmLabel: t('prompts.deletePrompt'),
      execute: async () => {
        await deletePrompt(org, prompt.id)
        if (selectedId === prompt.id) setSelectedId('')
        list.load({ refresh: true })
      },
      onError: message => setActionError(message),
    })
  }

  const selected = useMemo(() => rows.find(p => p.id === selectedId) ?? null, [rows, selectedId])

  const columns: DataTableColumn<Prompt>[] = [
    {
      key: 'name', header: t('prompts.colName'), type: 'text', mono: true,
      render: p => (
        <button
          type="button"
          onClick={() => setSelectedId(p.id)}
          className="inline-flex min-h-[36px] items-center gap-1 text-start font-medium text-[color:var(--astra-ink)] underline decoration-[color:var(--astra-rule-strong)] underline-offset-2 hover:decoration-[color:var(--astra-accent)]"
        >
          {p.name}
        </button>
      ),
    },
    {
      key: 'description', header: t('prompts.colDescription'), type: 'text', sortable: false,
      render: p => p.description || '—',
    },
    {
      key: 'labels', header: t('prompts.colLabels'), type: 'text', sortable: false,
      render: p => <LabelChips labels={labelMap[p.id] ?? []} />,
    },
    { key: 'updated_at', header: t('prompts.colUpdated'), format: 'date', render: p => p.updated_at },
    {
      key: 'row-actions', header: t('common.actions'), sortable: false,
      render: p => (
        <RowActions
          label={t('prompts.rowActionsAria', { name: p.name })}
          items={[
            { id: 'open', label: t('prompts.openDetail'), onSelect: () => setSelectedId(p.id) },
            { id: 'delete', label: t('common.delete'), risk: 'high', disabled: !canManage, onSelect: () => handleDelete(p) },
          ]}
        />
      ),
    },
  ]

  const tabBtn = (id: StudioTab, label: string) => (
    <button
      key={id}
      type="button"
      role="tab"
      aria-selected={tab === id}
      onClick={() => setTab(id)}
      className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${
        tab === id
          ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
          : 'border-[color:var(--astra-rule-strong)] hover:bg-[color:var(--astra-surface-muted)]'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t('prompts.title')} purpose={t('prompts.purpose')} />

      {org === '' && <StateNotice state="not-loaded" message={t('prompts.createOrgFirst')} />}

      <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('prompts.title')}>
        {tabBtn('prompts', t('prompts.tabPrompts'))}
        {tabBtn('partials', t('prompts.tabPartials'))}
        {tabBtn('playground', t('prompts.tabPlayground'))}
      </div>

      {tab === 'prompts' && selected && org !== '' && (
        <PromptDetail
          org={org}
          promptId={selected.id}
          canManage={canManage}
          manageHint={manageHint}
          onBack={() => setSelectedId('')}
          onChanged={() => list.load({ refresh: true })}
        />
      )}

      {tab === 'prompts' && !selected && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className="btn-primary" onClick={openCreate} disabled={org === '' || !canManage}>
              {t('prompts.newPrompt')}
            </button>
            {manageHint && <p className="text-sm text-[color:var(--astra-text-muted)]">{manageHint}</p>}
          </div>

          {actionError && <StateNotice state="error" message={actionError} />}
          {org !== '' && (
            <div className="card overflow-x-auto">
              <DataTable
                columns={columns}
                rows={rows}
                getRowId={p => p.id}
                loading={list.loading}
                // DataTable error branch preempts the empty row). The
                // previous standalone notice left the table claiming «No
                // prompts … yet» under the error — a failure reading as a
                // successful empty library.
                error={list.error}
                empty={t('prompts.empty')}
                page={1}
                pageSize={Math.max(1, rows.length)}
                onPageChange={() => {}}
                serverTotal={rows.length}
                sortMode="client"
                caption={t('prompts.title')}
              />
            </div>
          )}
        </>
      )}

      {tab === 'partials' && org !== '' && <PartialsPanel org={org} canManage={canManage} manageHint={manageHint} />}

      {tab === 'playground' && org !== '' && <PlaygroundPanel org={org} prompts={rows} />}

      <FormDrawer
        open={createOpen}
        kind={t('prompts.title')}
        title={t('prompts.createTitle')}
        submitLabel={t('prompts.createSubmit')}
        onClose={() => setCreateOpen(false)}
        onSubmit={submitCreate}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldName')}</span>
          <input
            className="control w-full"
            value={draftName}
            onChange={e => setDraftName(e.target.value)}
            maxLength={256}
            required
            autoFocus
            spellCheck={false}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldDescription')}</span>
          <input
            className="control w-full"
            value={draftDescription}
            onChange={e => setDraftDescription(e.target.value)}
            maxLength={1024}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldTemplate')}</span>
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('prompts.fieldTemplateHint')}</span>
          <textarea
            className="control min-h-[160px] w-full font-mono"
            value={draftTemplate}
            onChange={e => setDraftTemplate(e.target.value)}
            required
            spellCheck={false}
            aria-label={t('prompts.fieldTemplate')}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldParams')}</span>
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('prompts.fieldParamsHint')}</span>
          <textarea
            className="control min-h-[72px] w-full font-mono"
            value={draftParams}
            onChange={e => setDraftParams(e.target.value)}
            spellCheck={false}
            aria-label={t('prompts.fieldParams')}
            aria-invalid={!draftParamsCheck.ok || undefined}
          />
          {!draftParamsCheck.ok && (
            <span role="alert" className="text-xs" style={{ color: 'var(--astra-danger)' }}>
              {t('prompts.paramsInvalid')}
            </span>
          )}
        </label>
      </FormDrawer>

      {deleteAction.ui}
    </div>
  )
}
