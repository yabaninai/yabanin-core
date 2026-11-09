import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  createProviderCredential, deleteProviderCredential, listProviderCredentialModels,
  listProviderCredentials, testProviderCredential, updateProviderCredential,
  type ProviderCredential,
} from '../../api/providerCredentials'
import { listAllModels, type ModelEntry } from '../../api/models'
import { formatDateTimeIn } from '../../i18n/date'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { RowActions } from '../../components/astra/RowActions'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import {
  crossCheckCatalog, PROVIDER_OPTIONS, buildCreateInput, buildUpdatePatch,
  catalogStateFromError, catalogStateFromResult, editDraftOf, emptyDraft,
  maskKeyLast4, registryLoadState, testStateFromError, testStateFromResult,
  withCheckedAt,
  type CredentialCatalogState, type CredentialDraft, type CredentialEditDraft,
  type CredentialTestState,
} from './providerKeysHelpers'
import {
  stateBadgeColor, stateBadgeGlyph, stateBadgeShell,
  type ModelDisplayState, type ModelState, type UnavailableReason,
} from '../models/helpers'

// W-BYOK (card W-BYOK-UI): the «Provider keys» tab of the organization
// settings screen. BYOK credentials per the frozen W-BYOK-API contract:
// the list shows the masked key fragment only ("••••1234"); the raw key is
// typed into a password field, serialized into the POST/PUT body once, and
// cleared from state the moment the request is sent — it is never kept in
// component state after sending and never touches localStorage.
//
// Honesty rules:
//  - «Test connection» fires the contract POST …/test per credential; the
//    result {ok, status?, error?} is rendered as an indicator in the table.
//    The server does not persist a test history, so the column reflects only
//    this browser session's runs (untested stays "not recorded", never OK),
//    re-probe exists; the buttons are the only probes and they share the
//    server's 1/min/org budget, whose throttle surfaces as an honest error);
//  - a delayed test completion is dropped when the org scope changed or a
//    newer run for the same credential superseded it (TP-06 async scope);
//    the same async-scope rules: verified is always false — a snapshot is
//    NOT a usability mark, nothing is saved, and manual model entry stays
//    the fallback (refusals render their machine reason honestly);
//    through the shared modelDisplayState matrix — discovered / configured /
//    verified / unavailable + reason, derived over the facts only; probes
//    never mutate state (D-2), an id the registry does not know renders
//    "discovered" with the manual-register hint, and a registry outage
//    suspends the states instead of reading models as missing;
//  - deletion runs through the AUX-12 high-risk dialog (type-the-name);
//  - every mutating action carries the AUX-14b X-Audit-Reason.

const rowBtnCls =
  'inline-flex min-h-[36px] items-center whitespace-nowrap rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:cursor-not-allowed disabled:opacity-50'

export function ProviderKeysSection({ org }: { org: string }) {
  const { t, i18n } = useTranslation()
  const locale = i18n.language

  const fetchCredentials = useCallback(
    (signal: AbortSignal) => listProviderCredentials(org, { signal }),
    [org],
  )
  const query = useScopedQuery({
    key: `provider-credentials|${org}`,
    org,
    fetcher: fetchCredentials,
  })
  const creds = query.data ?? []
  const [page, setPage] = useState(1)

  const [error, setError] = useState('')
  const [addOpen, setAddOpen] = useState(false)
  const [createDraft, setCreateDraft] = useState<CredentialDraft>(emptyDraft)
  const [editCred, setEditCred] = useState<ProviderCredential | null>(null)
  const [editDraft, setEditDraft] = useState<CredentialEditDraft>(() => editDraftOf({ name: '', base_url: '', enabled: true }))

  // Connection tests: per-credential client-side state; a new run for the
  // same credential or an org switch discards stale completions.
  const [testStates, setTestStates] = useState<Record<string, CredentialTestState>>({})
  const testSeq = useRef(0)
  // last snapshot (per credential) lives only in this session; the panel
  // shows the most recent run.
  const [modelStates, setModelStates] = useState<Record<string, CredentialCatalogState>>({})
  const [modelsCred, setModelsCred] = useState<ProviderCredential | null>(null)
  const modelSeq = useRef(0)
  // (a plain read — no probe, D-4 is untouched by it). The registry is
  // global; the candidate rows are filtered to the credential's provider at
  // render time.
  const registryFetcher = useCallback((signal: AbortSignal) => listAllModels({ signal }), [])
  const registryIndex = useScopedQuery<ModelEntry[]>({
    key: 'provider-keys-registry-index',
    fetcher: registryFetcher,
  })
  // Provider → (model name → enabled). Rows without a provider can never
  // match a credential, so they stay out; an EMPTY inner map is a real
  // "nothing registered for this provider" (→ every id reads discovered),
  // while registryIndex.data being null is the outage/loading suspension.
  const registryByProvider = useMemo(() => {
    const byProvider = new Map<string, Map<string, boolean>>()
    for (const m of registryIndex.data ?? []) {
      const key = m.provider ?? ''
      if (!key) continue
      let inner = byProvider.get(key)
      if (!inner) { inner = new Map<string, boolean>(); byProvider.set(key, inner) }
      inner.set(m.model_name, m.enabled)
    }
    return byProvider
  }, [registryIndex.data])
  // The credential's last test verdict — the only usability evidence a BYOK
  // credential carries (undefined while running or never run).
  const testVerdict = (credId: string): boolean | undefined => {
    const s = testStates[credId]
    if (!s || s.phase === 'running') return undefined
    return s.phase === 'ok'
  }
  const orgRef = useRef(org)
  orgRef.current = org
  useEffect(() => {
    setTestStates({})
    setModelStates({})
    setModelsCred(null)
    setError('')
    setAddOpen(false)
    setCreateDraft(emptyDraft())
  }, [org])

  const submitCreate = async () => {
    setError('')
    const parsed = buildCreateInput(createDraft)
    if (!parsed.ok) {
      const missing = parsed.missing
      if (missing.includes('name')) throw new Error(t('providerKeys.errNameRequired'))
      if (missing.includes('provider')) throw new Error(t('providerKeys.errProviderRequired'))
      if (missing.includes('baseUrl')) throw new Error(t('providerKeys.errBaseUrlRequired'))
      throw new Error(t('providerKeys.errKeyRequired'))
    }
    const payload = parsed.input
    // The key leaves state the moment the request goes out. A failed create
    // is retried by re-entering it — the failed attempt's key is never kept.
    setCreateDraft(d => ({ ...d, key: '' }))
    await createProviderCredential(org, payload)
    setCreateDraft(emptyDraft())
    query.load()
  }

  const openEdit = (cred: ProviderCredential) => {
    setError('')
    setEditCred(cred)
    setEditDraft(editDraftOf(cred))
  }
  const closeEdit = useCallback(() => setEditCred(null), [])

  const submitEdit = async () => {
    if (!editCred) return
    setError('')
    const patch = buildUpdatePatch(editCred, editDraft)
    if (Object.keys(patch).length === 0) {
      closeEdit()
      return
    }
    // Same secret rule as create: a typed key is wiped as soon as it is sent.
    setEditDraft(d => ({ ...d, key: '' }))
    await updateProviderCredential(org, editCred.id, patch)
    closeEdit()
    query.load()
  }

  const deleteAction = useAction({
    id: 'providerKeys.delete', risk: 'high', reversible: false,
    impact: <span>{t('providerKeys.deleteImpact')}</span>,
  })
  const handleDelete = (cred: ProviderCredential) => {
    setError('')
    deleteAction.run({
      entity: cred.name,
      confirmLabel: t('providerKeys.deleteConfirm'),
      reason: {},
      execute: async ({ reason }) => {
        await deleteProviderCredential(org, cred.id, auditReasonOpts(reason))
      },
      onDone: () => query.load(),
      onError: (message) => setError(message),
    })
  }

  const runTest = (cred: ProviderCredential) => {
    setError('')
    const run = ++testSeq.current
    const seenOrg = org
    setTestStates(m => ({ ...m, [cred.id]: { phase: 'running' } }))
    void (async () => {
      try {
        const result = await testProviderCredential(org, cred.id)
        if (orgRef.current !== seenOrg || testSeq.current !== run) return
        // D-4: the completion time is the "checked at" badge — session
        // evidence only, never a stored or background-refreshed state.
        setTestStates(m => ({ ...m, [cred.id]: withCheckedAt(testStateFromResult(result), new Date().toISOString()) }))
      } catch (err: unknown) {
        if (orgRef.current !== seenOrg || testSeq.current !== run) return
        setTestStates(m => ({ ...m, [cred.id]: withCheckedAt(testStateFromError(err), new Date().toISOString()) }))
      }
    })()
  }

  // async-scope discipline as runTest: a stale completion (org switched or
  // a newer run started) is dropped. The snapshot is display-only here —
  // this component never writes the models anywhere (D-3 display-only).
  const runModels = (cred: ProviderCredential) => {
    setError('')
    const run = ++modelSeq.current
    const seenOrg = org
    setModelsCred(cred)
    setModelStates(m => ({ ...m, [cred.id]: { phase: 'running' } }))
    void (async () => {
      try {
        const result = await listProviderCredentialModels(org, cred.id)
        if (orgRef.current !== seenOrg || modelSeq.current !== run) return
        setModelStates(m => ({ ...m, [cred.id]: withCheckedAt(catalogStateFromResult(result), new Date().toISOString()) }))
      } catch (err: unknown) {
        if (orgRef.current !== seenOrg || modelSeq.current !== run) return
        setModelStates(m => ({ ...m, [cred.id]: withCheckedAt(catalogStateFromError(err), new Date().toISOString()) }))
      }
    })()
  }

  const columns: DataTableColumn<ProviderCredential>[] = useMemo(() => [
    {
      key: 'name',
      header: t('providerKeys.colName'),
      type: 'text',
      render: c => <span className="font-medium">{c.name}</span>,
    },
    {
      key: 'provider',
      header: t('providerKeys.colProvider'),
      type: 'text',
      render: c => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{c.provider}</span>,
    },
    {
      key: 'base_url',
      header: t('providerKeys.colBaseUrl'),
      type: 'text',
      render: c => <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{c.base_url}</span>,
    },
    {
      key: 'key_last4',
      header: t('providerKeys.colKey'),
      type: 'text',
      sortable: false,
      render: c => {
        const mask = maskKeyLast4(c.key_last4)
        return mask
          ? <span style={{ fontFamily: 'var(--astra-font-code)' }}>{mask}</span>
          : <span className="text-[color:var(--astra-text-muted)]">—</span>
      },
    },
    {
      key: 'enabled',
      header: t('providerKeys.colEnabled'),
      type: 'text',
      getSortValue: c => (c.enabled ? '1' : '0'),
      render: c => (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span aria-hidden="true" style={{ color: c.enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {c.enabled ? '●' : '○'}
          </span>
          {c.enabled ? t('orgSettings.on') : t('orgSettings.off')}
        </span>
      ),
    },
    {
      key: 'last_test',
      header: t('providerKeys.colTest'),
      type: 'text',
      sortable: false,
      render: c => {
        const state = testStates[c.id]
        if (!state) {
          return <span className="text-xs text-[color:var(--astra-text-muted)]">{t('common.notRecorded')}</span>
        }
        if (state.phase === 'running') {
          return <span className="text-xs text-[color:var(--astra-text-muted)]" aria-busy="true">{t('providerKeys.testRunning')}</span>
        }
        const checkedAt = state.checkedAt
          ? (
            <span className="text-xs text-[color:var(--astra-text-muted)]">
              {t('providerKeys.checkedAt', { time: formatDateTimeIn(locale, state.checkedAt) })}
            </span>
          )
          : null
        if (state.phase === 'ok') {
          return (
            <span className="flex flex-col items-start gap-0.5">
              <span className="whitespace-nowrap text-xs">
                <span aria-hidden="true" style={{ color: 'var(--astra-success)' }}>✓</span>{' '}
                {state.status !== undefined
                  ? t('providerKeys.testOkStatus', { status: String(state.status) })
                  : t('providerKeys.testOk')}
              </span>
              {checkedAt}
            </span>
          )
        }
        return (
          <span className="flex flex-col items-start gap-0.5">
            <span className="block max-w-[240px] truncate text-xs" title={state.error ?? ''}>
              <span aria-hidden="true" style={{ color: 'var(--astra-danger)' }}>✕</span>{' '}
              {state.error ?? t('providerKeys.testFail')}
            </span>
            {checkedAt}
          </span>
        )
      },
    },
  ], [t, testStates, locale])

  // Honest refusal rendering: the server's machine reason becomes a
  // diagnosis and the matching next step — never "success", never empty.
  const catalogReasonMessage = (state: CredentialCatalogState): string => {
    switch (state.reason) {
      case 'models_list_unavailable': return t('providerKeys.reasonListUnavailable')
      case 'key_forbidden': return t('providerKeys.reasonKeyForbidden')
      case 'key_unauthorized': return t('providerKeys.reasonKeyUnauthorized')
      case 'key_unavailable': return t('providerKeys.reasonKeyUnavailable')
      case 'transport_error': return t('providerKeys.reasonTransport', { error: state.error ?? '' })
      default: return state.error || t('providerKeys.modelsFail')
    }
  }

  // and the fix are always visible; nothing unavailable renders as working).
  const stateLabel = (state: ModelDisplayState): string => {
    switch (state) {
      case 'verified': return t('providerKeys.stateVerified')
      case 'configured': return t('providerKeys.stateConfigured')
      case 'discovered': return t('providerKeys.stateDiscovered')
      case 'unavailable': return t('providerKeys.stateUnavailable')
    }
  }
  const unavailableHint = (reason: UnavailableReason): string => {
    switch (reason) {
      case 'operator_disabled': return t('providerKeys.reasonOperatorDisabled')
      case 'check_failed': return t('providerKeys.reasonCheckFailed')
      case 'not_registered': return t('providerKeys.reasonNotRegistered')
      case 'absent_from_snapshot': return t('providerKeys.reasonAbsentFromSnapshot')
    }
  }
  const renderStateBadge = (state: ModelState) => (
    <span
      className={stateBadgeShell}
      style={{ color: stateBadgeColor(state.state) }}
      title={state.state === 'unavailable' && state.reason ? unavailableHint(state.reason) : undefined}
    >
      <span aria-hidden="true">{stateBadgeGlyph(state.state)}</span>
      {stateLabel(state.state)}
    </span>
  )
  // Per-row hint text under a badge: the fix, per D-6.
  const rowHint = (state: ModelState): string | null => {
    if (state.state === 'discovered') return t('providerKeys.hintRegisterManual')
    if (state.state === 'unavailable' && state.reason) return unavailableHint(state.reason)
    return null
  }

  return (
    <section aria-labelledby="orgsettings-providerkeys-title" className="flex flex-col gap-3">
      <h2 id="orgsettings-providerkeys-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('providerKeys.title')}</h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('providerKeys.note')}</p>

      {deleteAction.ui}

      {(error !== '' || query.error !== '') && (
        <StateNotice state="error" message={error !== '' ? error : query.error} action={{ label: t('common.retry'), onClick: () => query.load({ refresh: true }) }} />
      )}

      <div>
        <button type="button" className="btn-primary" onClick={() => setAddOpen(true)}>{t('providerKeys.addTitle')}</button>
      </div>

      <DataTable
        columns={columns}
        rows={creds}
        getRowId={c => c.id}
        loading={query.loading && creds.length === 0}
        empty={t('providerKeys.empty')}
        page={page}
        pageSize={50}
        onPageChange={setPage}
        caption={t('providerKeys.caption')}
        renderActions={c => (
          <span className="flex items-center gap-1.5">
            <button
              type="button"
              className={rowBtnCls}
              disabled={modelStates[c.id]?.phase === 'running' || testStates[c.id]?.phase === 'running'}
              onClick={() => runModels(c)}
            >
              {t('providerKeys.modelsButton')}
            </button>
            <button
              type="button"
              className={rowBtnCls}
              disabled={testStates[c.id]?.phase === 'running' || modelStates[c.id]?.phase === 'running'}
              onClick={() => runTest(c)}
            >
              {t('providerKeys.testButton')}
            </button>
            <RowActions
              label={t('common.actions')}
              items={[
                { id: 'edit', label: t('common.edit'), onSelect: () => openEdit(c) },
                { id: 'delete', label: t('common.delete'), risk: 'high', onSelect: () => handleDelete(c) },
              ]}
            />
          </span>
        )}
      />
      <p className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.testNote')}</p>

      {/* The discovery panel shows the most recent catalog run, display-only
          and session-scoped — the server keeps no history either. Each snapshot
          id carries its derived display state over the facts
          (registry row + last test verdict); nothing here writes anywhere. */}
      {modelsCred && modelStates[modelsCred.id] && (() => {
        const state = modelStates[modelsCred.id]
        // and a true outage both suspend the states, but only the outage
        // earns failure copy (review finding 2: loading ≠ outage).
        const registryLoad = registryLoadState({
          hasData: registryIndex.data != null,
          loading: registryIndex.loading,
          error: registryIndex.error,
        })
        const registry = registryLoad.kind === 'ready'
          ? (registryByProvider.get(modelsCred.provider) ?? new Map<string, boolean>())
          : null
        const suspendedLabel = registryLoad.kind === 'loading'
          ? t('providerKeys.stateSuspendedLoading')
          : t('providerKeys.stateSuspended')
        const check = crossCheckCatalog({
          snapshot: state.models,
          testOk: testVerdict(modelsCred.id),
          registry,
        })
        const checkedAtBadge = state.checkedAt ? (
          <span className="text-xs text-[color:var(--astra-text-muted)]">
            {t('providerKeys.checkedAt', { time: formatDateTimeIn(locale, state.checkedAt) })}
          </span>
        ) : null
        return (
          <div
            className="flex flex-col gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-3 text-sm"
            aria-live="polite"
          >
            <div className="flex items-center gap-2">
              <span className="font-medium">{modelsCred.name}</span>
              <span className="text-xs text-[color:var(--astra-text-muted)]" style={{ fontFamily: 'var(--astra-font-code)' }}>{modelsCred.provider}</span>
            </div>
            {state.phase === 'running' && (
              <span className="text-xs text-[color:var(--astra-text-muted)]" aria-busy="true">{t('providerKeys.modelsRunning')}</span>
            )}
            {state.phase === 'ok' && (
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  {checkedAtBadge}
                  {registryLoad.kind === 'outage' && (
                    <span className="text-xs" style={{ color: 'var(--astra-warning)' }}>{t('providerKeys.registryOutage')}</span>
                  )}
                  {registryLoad.kind === 'loading' && (
                    <span className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.registryLoading')}</span>
                  )}
                </div>
                {check.snapshotRows.length === 0 ? (
                  <span className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.modelsSnapshotEmpty')}</span>
                ) : (
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-medium text-[color:var(--astra-text-muted)]">
                      {t('providerKeys.snapshotSectionTitle', { count: check.snapshotRows.length })}
                    </span>
                    <ul className="flex flex-col gap-1">
                      {check.snapshotRows.map(row => (
                        <li key={row.model} className="flex flex-wrap items-center gap-2">
                          <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{row.model}</span>
                          {row.state === null
                            ? <span className="text-xs text-[color:var(--astra-text-muted)]">{suspendedLabel}</span>
                            : renderStateBadge(row.state)}
                          {row.state && rowHint(row.state) && (
                            <span className="text-xs text-[color:var(--astra-text-muted)]">{rowHint(row.state)}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {check.absentRows.length > 0 && (
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-medium text-[color:var(--astra-text-muted)]">
                      {t('providerKeys.absentSectionTitle', { count: check.absentRows.length })}
                    </span>
                    <ul className="flex flex-col gap-1">
                      {check.absentRows.map(row => row.state ? (
                        <li key={row.model} className="flex flex-wrap items-center gap-2">
                          <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{row.model}</span>
                          {renderStateBadge(row.state)}
                          {rowHint(row.state) && (
                            <span className="text-xs text-[color:var(--astra-text-muted)]">{rowHint(row.state)}</span>
                          )}
                        </li>
                      ) : null)}
                    </ul>
                  </div>
                )}
                <span className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.modelsHonestNote')}</span>
              </div>
            )}
            {state.phase === 'fail' && (
              <span className="text-xs" style={{ color: 'var(--astra-danger)' }}>{catalogReasonMessage(state)}</span>
            )}
          </div>
        )
      })()}

      <p className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.recheckNote')}</p>

      {/* Create: the key is a one-time secret — password field, sent once. */}
      <FormDrawer
        open={addOpen}
        kind={t('providerKeys.title')}
        title={t('providerKeys.addTitle')}
        submitLabel={t('providerKeys.addSubmit')}
        onClose={() => setAddOpen(false)}
        onSubmit={() => submitCreate()}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.name')}</span>
          <input
            value={createDraft.name}
            onChange={e => setCreateDraft(d => ({ ...d, name: e.target.value }))}
            placeholder={t('providerKeys.namePlaceholder')}
            className="control"
            required
            autoComplete="off"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.provider')}</span>
          <select
            value={createDraft.provider}
            onChange={e => setCreateDraft(d => ({ ...d, provider: e.target.value }))}
            className="control"
          >
            {PROVIDER_OPTIONS.map(p => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.baseUrl')}</span>
          <input
            value={createDraft.baseUrl}
            onChange={e => setCreateDraft(d => ({ ...d, baseUrl: e.target.value }))}
            placeholder={t('providerKeys.baseUrlPlaceholder')}
            className="control"
            required
            autoComplete="off"
            inputMode="url"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.key')}</span>
          <input
            type="password"
            value={createDraft.key}
            onChange={e => setCreateDraft(d => ({ ...d, key: e.target.value }))}
            placeholder={t('providerKeys.keyPlaceholder')}
            className="control"
            required
            autoComplete="new-password"
          />
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.keyHint')}</span>
        </label>
      </FormDrawer>

      {/* Edit: an empty key field keeps the stored key (omitted from the PUT). */}
      <FormDrawer
        open={editCred !== null}
        kind={t('providerKeys.title')}
        title={t('providerKeys.editTitle')}
        submitLabel={t('common.save')}
        onClose={closeEdit}
        onSubmit={() => submitEdit()}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.name')}</span>
          <input
            value={editDraft.name}
            onChange={e => setEditDraft(d => ({ ...d, name: e.target.value }))}
            className="control"
            required
            autoComplete="off"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.baseUrl')}</span>
          <input
            value={editDraft.baseUrl}
            onChange={e => setEditDraft(d => ({ ...d, baseUrl: e.target.value }))}
            className="control"
            required
            autoComplete="off"
            inputMode="url"
          />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={editDraft.enabled}
            onChange={e => setEditDraft(d => ({ ...d, enabled: e.target.checked }))}
            className="h-4 w-4"
          />
          <span>{t('providerKeys.enabled')}</span>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('providerKeys.keyReplace')}</span>
          <input
            type="password"
            value={editDraft.key}
            onChange={e => setEditDraft(d => ({ ...d, key: e.target.value }))}
            className="control"
            autoComplete="new-password"
          />
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('providerKeys.keyReplaceHint')}</span>
        </label>
      </FormDrawer>
    </section>
  )
}
