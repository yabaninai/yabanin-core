import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  createModel, getModel, updateModel, MODEL_TIERS,
  type ModelEntry, type ModelFormValues,
} from '../../api/models'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { StateNotice } from '../../components/astra/StateNotice'
import { parseNameList, validateChainTargets, validateTierPool } from './helpers'
import { TagField } from './TagField'

// FormDrawer replaces the self-written dialogs). Contract carried over from
//   * editing opens with a fresh detail GET (the list row is a projection);
//   * upstream_api_key is write-only: the field starts empty, the placeholder
//     says "leave empty to keep", and the stored key is only ever represented
//     by its status (has_key) plus an explicit clear switch;
//   * chain targets (fallback / failover / tier pool) are validated against
//     the loaded registry slice — unknown or disabled targets block the save
//     (the server re-checks and stays the source of truth).

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

export interface ModelFormDrawerProps {
  open: boolean
  /** The model being edited; null = create. */
  editing: ModelEntry | null
  /** Registry slice for autocomplete + target validation (name → enabled). */
  knownModels: ReadonlyMap<string, boolean>
  onClose: () => void
  /** Called after a successful create/update (the page reloads the list). */
  onSaved: (name: string, created: boolean) => void
}

export function ModelFormDrawer({ open, editing, knownModels, onClose, onSaved }: ModelFormDrawerProps) {
  const { t } = useTranslation()
  const [form, setForm] = useState<ModelFormValues>(emptyForm)
  const [clearKey, setClearKey] = useState(false)
  const [detailError, setDetailError] = useState('')
  // The fetched detail entry: the list row is a projection, so has_key (key
  // status) and the optional fields come from here when it arrives.
  const [detail, setDetail] = useState<ModelEntry | null>(null)
  const keySource = detail ?? editing

  // Fresh detail per open: the list row lacks the optional fields (provider,
  // upstream_url, failover lists, timeout, has_key). A failed detail fetch
  // keeps the row projection and shows the honest error.
  useEffect(() => {
    if (!open) return
    setClearKey(false)
    setDetailError('')
    setDetail(null)
    if (!editing) {
      setForm(emptyForm)
      return
    }
    setForm(toForm(editing))
    let alive = true
    getModel(editing.model_name)
      .then(full => {
        if (!alive) return
        setDetail(full)
        setForm(toForm(full))
      })
      .catch((e: unknown) => {
        if (alive) setDetailError(e instanceof Error ? e.message : String(e))
      })
    return () => { alive = false }
  }, [open, editing])

  const setField = (k: keyof ModelFormValues, v: string | boolean) =>
    setForm(prev => ({ ...prev, [k]: v }))

  const suggestions = useMemo(
    () => [...knownModels.keys()].filter(name => name !== form.model_name).sort(),
    [knownModels, form.model_name],
  )

  const tagState = (name: string) => {
    const enabled = knownModels.get(name)
    if (enabled === undefined) return 'unknown' as const
    return enabled ? ('ok' as const) : ('disabled' as const)
  }
  const tagTitle = (name: string) => {
    const state = tagState(name)
    if (state === 'unknown') return t('models.tagUnknown', { name })
    if (state === 'disabled') return t('models.tagDisabled', { name })
    return name
  }
  // tier_pool holds TIER names (pkg/router buckets pools by classifier
  // class), so its validation is the tier vocabulary, not model existence.
  const tierPoolState = (name: string) =>
    (MODEL_TIERS as readonly string[]).includes(name) ? ('ok' as const) : ('unknown' as const)
  const tierPoolTitle = (name: string) =>
    tierPoolState(name) === 'unknown' ? t('models.tagUnknownTier', { name }) : name

  // disabled model, and the tier pool cannot carry entries outside the tier
  // vocabulary — the thrown message renders inline (role=alert) and keeps
  // the drawer open; the server re-checks on save and stays the truth.
  const chainProblem = useMemo(() => {
    if (!open) return null
    const chainCheck = validateChainTargets(
      [...parseNameList(form.fallback_model), ...parseNameList(form.failover_models)],
      knownModels,
    )
    if (!chainCheck.ok) {
      const names = [...chainCheck.unknown, ...chainCheck.disabled].join(', ')
      return t('models.chainInvalid', { names })
    }
    const poolCheck = validateTierPool(parseNameList(form.tier_pool), MODEL_TIERS)
    if (!poolCheck.ok) {
      return t('models.tierPoolInvalid', { names: poolCheck.unknown.join(', ') })
    }
    return null
  }, [open, form.fallback_model, form.failover_models, form.tier_pool, knownModels, t])

  const submit = async () => {
    const creating = editing == null
    if (creating && !form.model_name.trim()) {
      throw new Error(t('models.nameRequired'))
    }
    // saved — the thrown message renders inline (role=alert) and keeps the
    // drawer open with the fields intact; the server re-checks on save.
    if (chainProblem) throw new Error(chainProblem)
    const values: ModelFormValues = { ...form, clear_upstream_key: clearKey }
    if (creating) {
      await createModel(values)
      // The notice carries the name the operator typed — the 201 body is the
      // server's projection and is not echoed into the UI text.
      onSaved(values.model_name.trim(), true)
    } else {
      await updateModel(editing!.model_name, values)
      onSaved(editing!.model_name, false)
    }
  }

  return (
    <FormDrawer
      open={open}
      kind={t('models.title')}
      title={editing ? t('models.editTitle') : t('models.createTitle')}
      submitLabel={editing ? t('models.save') : t('models.create')}
      onClose={onClose}
      onSubmit={submit}
    >
      {detailError && <StateNotice state="warning" message={t('drawer.detailFailed', { message: detailError })} />}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-name">
            {t('models.model')}
          </label>
          <input
            id="mf-name"
            className="control w-full"
            value={form.model_name}
            disabled={!!editing}
            onChange={e => setField('model_name', e.target.value)}
            placeholder="gpt-4"
            style={{ fontFamily: 'var(--astra-font-code)' }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-display">
            {t('models.displayName')}
          </label>
          <input id="mf-display" className="control w-full" value={form.display_name}
            onChange={e => setField('display_name', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-tier">
            {t('models.tier')}
          </label>
          <select id="mf-tier" className="control w-full" value={form.tier}
            onChange={e => setField('tier', e.target.value)}>
            {MODEL_TIERS.map(tier => <option key={tier} value={tier}>{tier}</option>)}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-provider">
            {t('models.provider')}
          </label>
          <input id="mf-provider" className="control w-full" value={form.provider}
            onChange={e => setField('provider', e.target.value)} placeholder="openai-compat" />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-url">
            {t('models.upstreamUrl')}
          </label>
          <input id="mf-url" className="control w-full" value={form.upstream_url}
            onChange={e => setField('upstream_url', e.target.value)} placeholder={t('models.phUrl')} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-key">
            {t('models.upstreamKey')}
          </label>
          {keySource?.has_key && (
            <p className="mb-1 text-xs" style={{ color: 'var(--astra-success)' }}>
              <span aria-hidden="true">● </span>{t('models.keySet')}
            </p>
          )}
          <input
            id="mf-key"
            type="password"
            className="control w-full"
            value={form.upstream_api_key}
            onChange={e => setField('upstream_api_key', e.target.value)}
            placeholder={t('models.keyPlaceholder')}
            autoComplete="new-password"
          />
          <p className="mt-1 text-[11px] text-[color:var(--astra-text-muted)]">{t('models.keyNote')}</p>
          {keySource?.has_key && (
            <div className="mt-1">
              <label className="flex items-center gap-2 text-sm text-[color:var(--astra-ink)]">
                <input
                  type="checkbox"
                  checked={clearKey}
                  onChange={e => setClearKey(e.target.checked)}
                  disabled={form.upstream_api_key.trim() !== ''}
                />
                {t('models.clearKey')}
              </label>
              {clearKey && (
                <p className="mt-1 text-[11px] text-[color:var(--astra-warning)]">{t('models.clearKeyNote')}</p>
              )}
            </div>
          )}
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-fallback">
            {t('models.fallbackModel')}
          </label>
          <input
            id="mf-fallback" className="control w-full" value={form.fallback_model}
            onChange={e => setField('fallback_model', e.target.value)}
            list="mf-model-options"
            style={{ fontFamily: 'var(--astra-font-code)' }}
          />
          <datalist id="mf-model-options">
            {suggestions.map(s => <option key={s} value={s} />)}
          </datalist>
          {form.fallback_model.trim() && tagState(form.fallback_model.trim()) !== 'ok' && (
            <p className="mt-1 text-[11px]" style={{ color: 'var(--astra-warning)' }}>
              {tagTitle(form.fallback_model.trim())}
            </p>
          )}
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="mf-timeout">
            {t('models.timeout')}
          </label>
          <input id="mf-timeout" className="control w-full" value={form.upstream_timeout_ms}
            onChange={e => setField('upstream_timeout_ms', e.target.value)} inputMode="numeric" placeholder="30000" />
        </div>
        <div className="sm:col-span-2">
          <TagField
            id="mf-failover"
            label={t('models.failoverTags')}
            hint={t('models.tagsHint')}
            placeholder={t('models.tagPlaceholder')}
            value={parseNameList(form.failover_models)}
            onChange={names => setField('failover_models', names.join(', '))}
            suggestions={suggestions}
            datalistId="mf-failover-options"
            tagState={tagState}
            tagTitle={tagTitle}
            removeLabel={name => t('models.tagRemove', { name })}
          />
        </div>
        <div className="sm:col-span-2">
          <TagField
            id="mf-pool"
            label={t('models.tierPoolTags')}
            hint={t('models.tiersHint')}
            placeholder={t('models.tagPlaceholderTier')}
            value={parseNameList(form.tier_pool)}
            onChange={names => setField('tier_pool', names.join(', '))}
            suggestions={[...MODEL_TIERS]}
            datalistId="mf-pool-options"
            tagState={tierPoolState}
            tagTitle={tierPoolTitle}
            removeLabel={name => t('models.tagRemove', { name })}
          />
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
    </FormDrawer>
  )
}
