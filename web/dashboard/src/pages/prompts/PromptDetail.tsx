import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  deletePrompt, getPrompt, promotePromptLabel, updatePrompt,
  PROMPT_LABEL_NAMES, type PromptDetail as PromptDetailData, type PromptLabelName, type PromptVersion,
} from '../../api/prompts'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { useAction } from '../../components/astra/ActionDialog'
import { parseParamsObject, templatePreview } from '../../lib/promptRender'
import { LabelChips } from './LabelChips'

// immutable (the PUT appends: the editor's confirm dialog names the next
// version before it fires); labels are movable pointers (promote = upsert
// with a confirm dialog — the active label drives gateway behavior).
// All mutations sit behind policies.manage server-side; the client only
// pre-disables what /api/me already denies.

type DetailTab = 'versions' | 'labels' | 'editor'

export function PromptDetail({
  org, promptId, canManage, manageHint, onBack, onChanged,
}: {
  org: string
  promptId: string
  canManage: boolean
  manageHint?: string
  onBack: () => void
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<DetailTab>('versions')
  const [actionError, setActionError] = useState('')

  const fetcher = useCallback(
    async (signal: AbortSignal) => getPrompt(org, promptId, { signal }),
    [org, promptId],
  )
  const detail = useScopedQuery<PromptDetailData>({
    key: `prompt|${org}|${promptId}`,
    org,
    fetcher,
  })
  const data = detail.data
  const versions = useMemo(() => data?.versions ?? [], [data])
  const latest = versions[0] ?? null
  const nextVersion = (latest?.version ?? 0) + 1
  const maxVersion = latest?.version ?? 0

  // ===== editor (appends a version) =====
  const [editorTemplate, setEditorTemplate] = useState('')
  const [editorParams, setEditorParams] = useState('')
  const editorParamsCheck = useMemo(() => parseParamsObject(editorParams), [editorParams])
  useEffect(() => {
    if (!latest) return
    setEditorTemplate(latest.template)
    setEditorParams(latest.params == null ? '' : JSON.stringify(latest.params, null, 2))
  }, [latest])

  const saveAction = useAction({
    id: 'prompts.saveVersion',
    risk: 'medium',
    reversible: false,
    impact: t('prompts.saveVersionImpact', { version: nextVersion }),
  })
  const handleSave = () => {
    setActionError('')
    saveAction.run({
      confirmLabel: t('prompts.saveNewVersion'),
      execute: async () => {
        if (!editorParamsCheck.ok) throw new Error(t('prompts.paramsInvalid'))
        await updatePrompt(org, promptId, {
          version: latest?.version ?? 0,
          template: editorTemplate,
          params: editorParamsCheck.value,
        })
        await detail.load()
        onChanged()
      },
      onError: message => {
        setActionError(message.includes('428')
          ? `${t('prompts.versionRequired')}. ${t('prompts.reloadConflict')}`
          : message.includes('409')
            ? `${t('prompts.versionConflict')}. ${t('prompts.reloadConflict')}`
            : message)
        if (message.includes('409') || message.includes('428')) void detail.load({ refresh: true })
      },
    })
  }

  // ===== labels (movable pointers) =====
  const [labelVersions, setLabelVersions] = useState<Record<string, number>>({})
  const labels = useMemo(() => data?.labels ?? [], [data])
  const boundOf = (label: PromptLabelName): number | null =>
    labels.find(l => l.label === label)?.version ?? null
  const versionOptions = useMemo(
    () => Array.from({ length: Math.max(1, maxVersion) }, (_, i) => maxVersion - i),
    [maxVersion],
  )
  const selectedVersionOf = (label: PromptLabelName): number => {
    const chosen = labelVersions[label]
    if (chosen !== undefined) return chosen
    return boundOf(label) ?? Math.max(1, maxVersion)
  }
  const promoteAction = useAction({
    id: 'prompts.promote',
    risk: 'medium',
    reversible: true,
    impact: t('prompts.promoteImpact'),
  })
  const handlePromote = (label: PromptLabelName) => {
    setActionError('')
    const version = selectedVersionOf(label)
    promoteAction.run({
      confirmLabel: t('prompts.promoteConfirm', { label, version }),
      execute: async () => {
        await promotePromptLabel(org, promptId, label, version)
        detail.load()
        onChanged()
      },
      onError: message => setActionError(message),
    })
  }

  // ===== delete =====
  const deleteAction = useAction({
    id: 'prompts.deleteDetail',
    risk: 'high',
    reversible: false,
    impact: t('prompts.deleteImpact'),
  })
  const handleDelete = () => {
    if (!data) return
    setActionError('')
    deleteAction.run({
      entity: data.prompt.name,
      confirmLabel: t('prompts.deletePrompt'),
      execute: async () => {
        await deletePrompt(org, promptId)
        onBack()
        onChanged()
      },
      onError: message => setActionError(message),
    })
  }

  const versionColumns: DataTableColumn<PromptVersion>[] = [
    { key: 'version', header: t('prompts.colVersion'), type: 'number', mono: true, align: 'right' },
    {
      key: 'template', header: t('prompts.colTemplatePreview'), type: 'text', sortable: false,
      render: v => <span className="font-mono text-xs">{templatePreview(v.template)}</span>,
    },
    { key: 'created_by', header: t('prompts.colCreatedBy'), type: 'text', sortable: false,
      render: v => v.created_by || '—' },
    { key: 'created_at', header: t('prompts.colCreated'), format: 'date', render: v => v.created_at },
  ]

  const tabBtn = (id: DetailTab, label: string) => (
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
    <div className="card flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <button type="button" className="btn-secondary" onClick={onBack}>
            ← {t('prompts.backToList')}
          </button>
          <h2 className="mt-2 break-all text-lg font-semibold text-[color:var(--astra-ink)]">
            {data?.prompt.name ?? promptId}
          </h2>
          {data && data.prompt.description && (
            <p className="text-sm text-[color:var(--astra-text-muted)]">{data.prompt.description}</p>
          )}
          {data && <div className="mt-1"><LabelChips labels={labels.map(l => l.label)} /></div>}
        </div>
        <button type="button" className="btn-secondary" onClick={handleDelete} disabled={!canManage}>
          {t('prompts.deletePrompt')}
        </button>
      </div>

      {manageHint && <p className="text-sm text-[color:var(--astra-text-muted)]">{manageHint}</p>}
      {detail.error && <StateNotice state="error" message={detail.error} />}
      {detail.refreshStale && <StateNotice state="stale" message={t('prompts.staleData')} />}

      <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('prompts.detailTabs')}>
        {tabBtn('versions', t('prompts.detailVersions'))}
        {tabBtn('labels', t('prompts.detailLabels'))}
        {tabBtn('editor', t('prompts.detailEditor'))}
      </div>

      {actionError && <StateNotice state="error" message={actionError} />}

      {tab === 'versions' && versions.length > 0 && (
        <div className="overflow-x-auto">
          <DataTable
            columns={versionColumns}
            rows={versions}
            getRowId={v => v.id}
            page={1}
            pageSize={Math.max(1, versions.length)}
            onPageChange={() => {}}
            serverTotal={versions.length}
            sortMode="client"
            caption={t('prompts.detailVersions')}
          />
        </div>
      )}
      {tab === 'versions' && versions.length === 0 && !detail.loading && (
        <StateNotice state="empty" message={t('prompts.versionsEmpty')} />
      )}

      {tab === 'labels' && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">{t('prompts.detailLabels')}</caption>
            <thead>
              <tr>
                <th scope="col" className="border-b border-[color:var(--astra-rule-strong)] px-3 py-1.5 text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('prompts.colLabel')}</th>
                <th scope="col" className="border-b border-[color:var(--astra-rule-strong)] px-3 py-1.5 text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('prompts.colBoundVersion')}</th>
                <th scope="col" className="border-b border-[color:var(--astra-rule-strong)] px-3 py-1.5 text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('prompts.colLabelUpdated')}</th>
                <th scope="col" className="border-b border-[color:var(--astra-rule-strong)] px-3 py-1.5 text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('prompts.colPromoteTo')}</th>
                <th scope="col" className="border-b border-[color:var(--astra-rule-strong)] px-3 py-1.5 text-start text-[length:12px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {PROMPT_LABEL_NAMES.map(label => {
                const bound = boundOf(label)
                const updated = labels.find(l => l.label === label)?.updated_at
                return (
                  <tr key={label}>
                    <td className="border-b border-[color:var(--astra-rule)] px-3 py-1 font-mono text-[color:var(--astra-ink)]">{label}</td>
                    <td className="border-b border-[color:var(--astra-rule)] px-3 py-1 text-[color:var(--astra-ink)]">
                      {bound ?? <span className="text-[color:var(--astra-text-muted)]">—</span>}
                    </td>
                    <td className="border-b border-[color:var(--astra-rule)] px-3 py-1 text-[color:var(--astra-text-muted)]">
                      {updated ?? '—'}
                    </td>
                    <td className="border-b border-[color:var(--astra-rule)] px-3 py-1">
                      <label className="sr-only" htmlFor={`promote-version-${label}`}>
                        {t('prompts.colPromoteTo')}
                      </label>
                      <select
                        id={`promote-version-${label}`}
                        className="control w-24"
                        value={selectedVersionOf(label)}
                        onChange={e => setLabelVersions(prev => ({ ...prev, [label]: Number(e.target.value) }))}
                      >
                        {versionOptions.map(v => <option key={v} value={v}>v{v}</option>)}
                      </select>
                    </td>
                    <td className="border-b border-[color:var(--astra-rule)] px-3 py-1">
                      <button
                        type="button"
                        className="btn-secondary"
                        disabled={!canManage || maxVersion < 1}
                        onClick={() => handlePromote(label)}
                      >
                        {t('prompts.promote')}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'editor' && (
        <div className="flex flex-col gap-3">
          {latest && (
            <p className="text-sm text-[color:var(--astra-text-muted)]">
              {t('prompts.editorLatest', { version: latest.version })}
            </p>
          )}
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldTemplate')}</span>
            <textarea
              className="control min-h-[240px] w-full font-mono"
              value={editorTemplate}
              onChange={e => setEditorTemplate(e.target.value)}
              spellCheck={false}
              aria-label={t('prompts.fieldTemplate')}
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('prompts.fieldParams')}</span>
            <textarea
              className="control min-h-[96px] w-full font-mono"
              value={editorParams}
              onChange={e => setEditorParams(e.target.value)}
              spellCheck={false}
              aria-invalid={!editorParamsCheck.ok || undefined}
            />
            {!editorParamsCheck.ok && (
              <span role="alert" className="text-xs" style={{ color: 'var(--astra-danger)' }}>
                {t('prompts.paramsInvalid')}
              </span>
            )}
          </label>
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="btn-primary"
              disabled={!canManage || editorTemplate.trim() === '' || !editorParamsCheck.ok}
              onClick={handleSave}
            >
              {t('prompts.saveNewVersion')}
            </button>
            <span className="text-sm text-[color:var(--astra-text-muted)]">
              {t('prompts.saveCreatesVersion', { version: nextVersion })}
            </span>
          </div>
        </div>
      )}

      {saveAction.ui}
      {promoteAction.ui}
      {deleteAction.ui}
    </div>
  )
}
