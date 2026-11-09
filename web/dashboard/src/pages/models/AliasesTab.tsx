import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  createModelAlias, deleteModelAlias, listModelAliases, type ModelAlias,
} from '../../api/aliases'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { DataTable } from '../../components/astra/DataTable'
import { RowActions } from '../../components/astra/RowActions'
import { StateNotice } from '../../components/astra/StateNotice'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { useAction } from '../../components/astra/ActionDialog'
import { chainTargetStatus } from './helpers'

// existing /api/model-aliases routes, moved out of the page body into a tab.
// Creation is a FormDrawer (v2 checklist item 3); the target must be an
// existing registry model (the server stays the source of truth); removal
// keeps the high-risk typed confirmation.

export function AliasesTab({ knownModels }: { knownModels: ReadonlyMap<string, boolean> }) {
  const { t } = useTranslation()

  const list = useScopedQuery<ModelAlias[]>({
    key: 'model-aliases',
    fetcher: signal => listModelAliases({ signal }),
  })

  const aliasRemove = useAction({
    id: 'models.alias.delete', risk: 'high', reversible: false,
    impact: t('aliases.removeImpact'),
  })

  const targetStatus = (name: string) => chainTargetStatus(name, knownModels)

  const remove = (a: ModelAlias) => {
    aliasRemove.run({
      entity: a.alias,
      confirmLabel: t('aliases.remove'),
      execute: async () => {
        await deleteModelAlias(a.alias)
      },
      onDone: () => {
        list.load({ refresh: true })
      },
    })
  }

  return (
    <section aria-label={t('aliases.section')} className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('aliases.section')}</h2>
        <CreateAliasDrawer knownModels={knownModels} onCreated={() => list.load({ refresh: true })} />
      </div>

      {aliasRemove.ui}

      {list.error ? (
        <StateNotice
          state="error"
          message={list.error}
          action={{ label: t('common.retry'), onClick: () => list.load() }}
        />
      ) : !list.data ? (
        <StateNotice state="loading" message={t('aliases.fetching')} />
      ) : list.data.length === 0 ? (
        <StateNotice state="empty" message={t('aliases.empty')} />
      ) : (
        <DataTable
          columns={[
            { key: 'alias', header: t('aliases.alias'), type: 'text', mono: true, render: a => a.alias },
            {
              key: 'target_model',
              header: t('aliases.target'),
              type: 'text',
              mono: true,
              render: a => {
                const status = targetStatus(a.target_model)
                if (status === 'ok') return a.target_model
                return (
                  <span
                    title={status === 'unknown'
                      ? t('models.tagUnknown', { name: a.target_model })
                      : t('models.tagDisabled', { name: a.target_model })}
                    style={{ color: status === 'unknown' ? 'var(--astra-danger)' : 'var(--astra-warning)' }}
                  >
                    <span aria-hidden="true">▲ </span>{a.target_model}
                  </span>
                )
              },
            },
          ]}
          rows={list.data}
          getRowId={a => a.alias}
          page={1}
          pageSize={Math.max(1, list.data.length)}
          onPageChange={() => {}}
          sortMode="client"
          caption={t('aliases.section')}
          renderActions={a => (
            <RowActions
              label={t('common.actions')}
              items={[
                {
                  id: 'remove',
                  label: t('aliases.remove'),
                  risk: 'high',
                  onSelect: () => remove(a),
                },
              ]}
            />
          )}
        />
      )}
    </section>
  )
}

// ----- creation drawer ------------------------------------------------------

function CreateAliasDrawer({ knownModels, onCreated }: {
  knownModels: ReadonlyMap<string, boolean>
  onCreated: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [alias, setAlias] = useState('')
  const [target, setTarget] = useState('')

  const suggestions = useMemo(() => [...knownModels.keys()].sort(), [knownModels])

  const trimmedTarget = target.trim()
  const targetProblem = trimmedTarget && chainTargetStatus(trimmedTarget, knownModels) === 'unknown'
    ? t('aliases.targetUnknown')
    : null
  const targetWarning = trimmedTarget && !targetProblem
    && chainTargetStatus(trimmedTarget, knownModels) === 'disabled'
    ? t('aliases.targetDisabledWarn')
    : null

  const submit = async () => {
    if (!alias.trim() || !trimmedTarget) return
    if (targetProblem) throw new Error(targetProblem)
    await createModelAlias(alias.trim(), trimmedTarget)
    setAlias('')
    setTarget('')
    onCreated()
  }

  return (
    <>
      <button type="button" className="btn-primary" onClick={() => setOpen(true)}>
        {t('aliases.add')}
      </button>
      <FormDrawer
        open={open}
        kind={t('aliases.section')}
        title={t('aliases.addTitle')}
        submitLabel={t('aliases.add')}
        onClose={() => setOpen(false)}
        onSubmit={submit}
      >
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="alias-name">
            {t('aliases.alias')}
          </label>
          <input
            id="alias-name"
            className="control w-full"
            value={alias}
            onChange={e => setAlias(e.target.value)}
            placeholder="fast"
            style={{ fontFamily: 'var(--astra-font-code)' }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="alias-target">
            {t('aliases.target')}
          </label>
          <input
            id="alias-target"
            className="control w-full"
            value={target}
            onChange={e => setTarget(e.target.value)}
            list="alias-target-options"
            placeholder="glm-5.3-flash"
            style={{ fontFamily: 'var(--astra-font-code)' }}
          />
          <datalist id="alias-target-options">
            {suggestions.map(name => <option key={name} value={name} />)}
          </datalist>
          {targetProblem && (
            <p className="mt-1 text-[11px]" style={{ color: 'var(--astra-danger)' }}>{targetProblem}</p>
          )}
          {!targetProblem && targetWarning && (
            <p className="mt-1 text-[11px]" style={{ color: 'var(--astra-warning)' }}>{targetWarning}</p>
          )}
        </div>
      </FormDrawer>
    </>
  )
}
