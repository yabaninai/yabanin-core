import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  createPolicy, getPolicy, getPolicyDrift, listPolicies, policyConflictCurrent, policyValidationErrorText,
  updatePolicy, validatePolicyDoc,
  type PolicyDetail, type PolicyDriftEntry, type PolicyDriftReport, type PolicyPipeline,
} from '../api/policyPipelines'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useAction } from '../components/astra/ActionDialog'
import { useHashParam } from '../hooks/useHashParam'
import { diffLines, diffSummary } from '../lib/policyDiff'
import {
  activeVersionDetail, baselineFromDetail, defaultDiffPair, isRollback, isStaleForActivate, isStaleForYaml,
  newestVersion, type PolicyBaseline,
} from '../lib/policyEditor'

// validation is SERVER-SIDE and runs BEFORE every mutation (owner decision
// 2026-11-04 (a), STRICT EVERYWHERE FAIL-CLOSED): the editor calls
// POST /policies/validate — the same pkg/pipeline.ParsePolicy the save and
// the gateway compile run — and only an UNREJECTABLE document reaches
// create/update; the editor surfaces the verbatim 400 text at the block and
// stores nothing on error. The page also shows the org's drift report
// (owner decision 2026-11-04 (b): the dashboard shows drift, managed /
// drift — edited past git after a reconcile / unmanaged), refreshed after
// every mutation so a UI-authored edit flips its policy to drift
// immediately. Version history with a client-side diff view, and
// activate/rollback through PUT active_version (the only mutation verb the
// API has).
//
// Stale-edit guard (negative scenario «stale edit»), two layers with the
// server as the arbiter:
//  - client fast-path (lib/policyEditor.ts): before every PUT the editor
//    re-reads the detail and blocks when the baseline moved — a moved
//    latest version blocks a draft save, a moved active version blocks an
//    activate/rollback;
//    `version` = the loaded current_version; a stale token makes the server
//    apply NOTHING and answer 409 {error, current} — the editor flips to
//    the stale notice with the refresh-and-rebase action, never a silent
//    overwrite. The token is the pipeline's current_version: a concurrent
//    ACTIVATION is the lost-update the guard exists to catch; concurrent
//    draft appends stay allowed (versions are immutable append-only rows
//    and the editor re-reads after every save).
//
// Preview before activate (criterion «пользователь понимает эффект до
// сохранения»): the diff summary of the editing buffer against the ACTIVE
// version plus the pointer to the decisions log filtered by this policy —
// the runtime keeps evaluating @v(active) until activate flips it.

type DetailState = 'loading' | 'ready' | 'error'

const controlCls = 'min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-[color:var(--astra-ink)]'

export function PolicyEditorPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const org = orgId.trim()
  const [policyId, setPolicyId] = useHashParam('policy')

  const [policies, setPolicies] = useState<PolicyPipeline[] | null>(null)
  const [listFailed, setListFailed] = useState(false)
  const [detail, setDetail] = useState<PolicyDetail | null>(null)
  const [detailState, setDetailState] = useState<DetailState>('loading')
  const [baseline, setBaseline] = useState<PolicyBaseline | null>(null)
  const [yamlText, setYamlText] = useState('')
  const [dirty, setDirty] = useState(false)
  const [saveBusy, setSaveBusy] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [savedVersion, setSavedVersion] = useState<number | null>(null)
  const [staleBlocked, setStaleBlocked] = useState(false)
  const [mutateError, setMutateError] = useState('')
  const [diffA, setDiffA] = useState<number | null>(null)
  const [diffB, setDiffB] = useState<number | null>(null)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [newYaml, setNewYaml] = useState('')
  const [createError, setCreateError] = useState('')
  const [drift, setDrift] = useState<PolicyDriftReport | null>(null)
  const [driftFailed, setDriftFailed] = useState(false)
  const gen = useRef(0)

  const activateAction = useAction({ id: 'policy.activate', risk: 'medium', reversible: true })
  const toggleAction = useAction({ id: 'policy.enabled', risk: 'medium', reversible: true })

  // ----- list (org-scoped; 403/404 for foreign orgs surfaces as failure) -----
  useEffect(() => {
    setPolicies(null)
    setListFailed(false)
    if (!org) return
    let cancelled = false
    void (async () => {
      try {
        const rows = await listPolicies(org)
        if (!cancelled) setPolicies(rows)
      } catch {
        if (!cancelled) setListFailed(true)
      }
    })()
    return () => { cancelled = true }
  }, [org])

  const loadDetail = useCallback(async (targetPolicy: string, opts?: { rebase?: boolean }): Promise<PolicyDetail | null> => {
    const rebase = opts?.rebase !== false
    const g = ++gen.current
    setDetailState('loading')
    setValidationError('')
    setStaleBlocked(false)
    setConflictCurrent(null)
    setSavedVersion(null)
    setMutateError('')
    try {
      const d = await getPolicy(org, targetPolicy)
      if (gen.current !== g) return null
      setDetail(d)
      setBaseline(baselineFromDetail(d))
      setDetailState('ready')
      if (rebase) {
        setYamlText(newestVersion(d)?.yaml ?? '')
        setDirty(false)
      }
      const pair = defaultDiffPair(d.versions ?? [])
      setDiffA(pair?.a ?? null)
      setDiffB(pair?.b ?? null)
      return d
    } catch {
      if (gen.current !== g) return null
      setDetail(null)
      setDetailState('error')
      return null
    }
  }, [org])

  // ----- detail (policy-scoped; the hash param makes it deep-linkable) -----
  useEffect(() => {
    setDetail(null)
    setBaseline(null)
    setYamlText('')
    setDirty(false)
    setValidationError('')
    setStaleBlocked(false)
    if (!org || !policyId) {
      setDetailState('loading')
      return
    }
    void loadDetail(policyId)
  }, [org, policyId, loadDetail])

  // ----- drift (org-wide; refreshed after mutations, owner decision (b)) -----
  const loadDrift = useCallback(async () => {
    if (!org) return
    try {
      const report = await getPolicyDrift(org)
      setDrift(report)
      setDriftFailed(false)
    } catch {
      setDriftFailed(true)
    }
  }, [org])

  useEffect(() => {
    setDrift(null)
    setDriftFailed(false)
    void loadDrift()
  }, [org, policyId, loadDrift])

  const driftStatusLabel = useCallback((status: string) => {
    if (status === 'drift') return t('policyEditor.driftStatusDrift')
    if (status === 'managed') return t('policyEditor.driftStatusManaged')
    return t('policyEditor.driftStatusUnmanaged')
  }, [t])

  // ----- stale-edit guard: re-read + baseline compare before every PUT -----
  const passStaleGuard = useCallback(async (mode: 'yaml' | 'activate'): Promise<boolean> => {
    if (!baseline || !org || !policyId) return false
    try {
      const current = baselineFromDetail(await getPolicy(org, policyId))
      const stale = mode === 'yaml' ? isStaleForYaml(baseline, current) : isStaleForActivate(baseline, current)
      if (stale) {
        setStaleBlocked(true)
        return false
      }
      return true
    } catch {
      // The guard read itself failed — let the PUT through; the server's
      // version token stays the arbiter and a 409 surfaces normally.
      return true
    }
  }, [baseline, org, policyId])

  // Server-409 backstop: a stale version token flips the editor into the
  // stale state (refresh-and-rebase offer). The live current_version from
  // the conflict body is kept for the operator-facing hint.
  const [conflictCurrent, setConflictCurrent] = useState<number | null>(null)
  const handleMutationError = useCallback((err: unknown): boolean => {
    const live = policyConflictCurrent(err)
    if (live !== null) {
      setConflictCurrent(live)
      setStaleBlocked(true)
      return true
    }
    return false
  }, [])

  const saveDraft = useCallback(() => {
    if (!org || !policyId || saveBusy || !dirty) return
    setSaveBusy(true)
    setValidationError('')
    setSavedVersion(null)
    void (async () => {
      // STRICT VALIDATE FIRST (owner decision 2026-11-04 (a)): the same
      // parser the store path runs; an unparseable draft never reaches the
      // store, and a validation transport failure also blocks the save
      // (fail-closed — "could not validate" is not "valid").
      try {
        await validatePolicyDoc(org, yamlText)
      } catch (err) {
        const serverMessage = policyValidationErrorText(err)
        setValidationError(serverMessage || t('policyEditor.validateFailed'))
        setSaveBusy(false)
        return
      }
      if (!(await passStaleGuard('yaml'))) {
        setSaveBusy(false)
        return
      }
      try {
        await updatePolicy(org, policyId, { yaml: yamlText, version: baseline?.activeVersion ?? 0 })
        // Rebase onto the appended draft; the saved hint names the new @v.
        const d = await loadDetail(policyId)
        setSavedVersion(d?.versions?.[0]?.version ?? null)
        void loadDrift() // a UI-authored edit flips this policy to drift
      } catch (err) {
        if (handleMutationError(err)) {
          // Stale token: the server applied nothing; the stale notice with
          // the refresh-and-rebase action takes over.
        } else {
          const serverMessage = policyValidationErrorText(err)
          if (serverMessage) setValidationError(serverMessage)
          else setValidationError(t('policyEditor.saveFailed'))
        }
      } finally {
        setSaveBusy(false)
      }
    })()
  }, [org, policyId, saveBusy, dirty, yamlText, baseline, passStaleGuard, loadDetail, handleMutationError, loadDrift, t])

  const runActivate = useCallback((version: number) => {
    if (!org || !policyId || !detail) return
    const active = detail.policy.current_version
    setMutateError('')
    void (async () => {
      if (!(await passStaleGuard('activate'))) return
      activateAction.run({
        entity: detail.policy.name,
        was: `@v${active}`,
        becomes: `@v${version}`,
        confirmLabel: isRollback(version, active)
          ? t('policyEditor.rollbackConfirm', { version })
          : t('policyEditor.activateConfirm', { version }),
        execute: async () => {
          try {
            await updatePolicy(org, policyId, { active_version: version, version: baseline?.activeVersion ?? 0 })
          } catch (err) {
            if (handleMutationError(err)) return // stale notice takes over
            throw err
          }
        },
        onDone: () => { void loadDetail(policyId, { rebase: false }); void loadDrift() },
        onError: () => setMutateError(t('policyEditor.activateFailed')),
      })
    })()
  }, [org, policyId, detail, baseline, passStaleGuard, activateAction, loadDetail, handleMutationError, loadDrift, t])

  const runToggle = useCallback(() => {
    if (!org || !policyId || !detail) return
    const enabled = detail.policy.enabled
    setMutateError('')
    toggleAction.run({
      entity: detail.policy.name,
      was: enabled ? t('policyEditor.stateEnabled') : t('policyEditor.stateDisabled'),
      becomes: enabled ? t('policyEditor.stateDisabled') : t('policyEditor.stateEnabled'),
      confirmLabel: enabled ? t('policyEditor.detachConfirm') : t('policyEditor.enableConfirm'),
      execute: async () => {
        try {
          await updatePolicy(org, policyId, { enabled: !enabled, version: baseline?.activeVersion ?? 0 })
        } catch (err) {
          if (handleMutationError(err)) return // stale notice takes over
          throw err
        }
      },
      onDone: () => { void loadDetail(policyId, { rebase: false }); void loadDrift() },
      onError: () => setMutateError(t('policyEditor.activateFailed')),
    })
  }, [org, policyId, detail, baseline, toggleAction, loadDetail, handleMutationError, loadDrift, t])

  const submitCreate = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    if (!org || creating) return
    setCreating(true)
    setCreateError('')
    void (async () => {
      // STRICT VALIDATE FIRST (owner decision 2026-11-04 (a)): an
      // unparseable draft is rejected before the create call — nothing
      // stores; the verbatim server text lands at the form.
      try {
        await validatePolicyDoc(org, newYaml)
      } catch (err) {
        const serverMessage = policyValidationErrorText(err)
        setCreating(false)
        setCreateError(serverMessage || t('policyEditor.validateFailed'))
        return
      }
      try {
        const d = await createPolicy(org, { name: newName.trim(), yaml: newYaml })
        setCreating(false)
        setNewName('')
        setNewYaml('')
        setPolicyId(d.policy.id)
      } catch (err) {
        setCreating(false)
        const serverMessage = policyValidationErrorText(err)
        setCreateError(serverMessage || t('policyEditor.createFailed'))
      }
    })()
  }, [org, creating, newName, newYaml, setPolicyId, t])

  // ----- derived: preview (active ↔ editing buffer) and diff view -----
  const activeV = detail ? activeVersionDetail(detail) : null
  const activeYaml = activeV?.yaml ?? ''
  const previewDiff = yamlText !== activeYaml ? diffLines(activeYaml, yamlText) : []
  const previewSummary = diffSummary(previewDiff)

  const versionByNumber = new Map((detail?.versions ?? []).map(v => [v.version, v]))
  const diffLinesView = diffA !== null && diffB !== null && versionByNumber.has(diffA) && versionByNumber.has(diffB)
    ? diffLines(versionByNumber.get(diffA)!.yaml, versionByNumber.get(diffB)!.yaml)
    : []
  const diffViewSummary = diffSummary(diffLinesView)

  return (
    <div className="space-y-6" data-testid="policy-editor">
      <PageHeader title={t('policyEditor.title')} purpose={t('policyEditor.purpose')} appliedScope={org || undefined} />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.orgId')}</span>
          <OrgSelect value={orgId} onChange={setOrgId} autoSelect className="sm:w-72" manualAriaLabel={t('orgSettings.orgUuid')} />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyEditor.selectPolicy')}</span>
          <select
            value={policyId}
            onChange={e => setPolicyId(e.target.value)}
            className={`sm:w-72 ${controlCls}`}
            data-testid="policy-editor-select"
            disabled={!policies || policies.length === 0}
          >
            <option value="">—</option>
            {(policies ?? []).map(p => (
              <option key={p.id} value={p.id}>
                {p.name} (@v{p.current_version}{p.enabled ? '' : `, ${t('policyEditor.stateDisabled')}`})
              </option>
            ))}
          </select>
        </label>
      </div>

      {!org && <StateNotice state="not-loaded" message={t('policyEditor.notLoaded')} />}
      {org && listFailed && <StateNotice state="error" message={t('policyEditor.loadFailed')} />}
      {org && !listFailed && policies !== null && policies.length === 0 && !policyId && (
        <StateNotice state="empty" message={t('policyEditor.emptyList')} />
      )}

      {org && policies !== null && !policyId && (
        <form onSubmit={submitCreate} className="card flex flex-col gap-3 p-4" data-testid="policy-editor-create">
          <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('policyEditor.createTitle')}</h2>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('policyEditor.createName')}</span>
            <input value={newName} onChange={e => setNewName(e.target.value)} required maxLength={256}
              className={`sm:w-72 ${controlCls}`} data-testid="policy-editor-create-name" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('policyEditor.createYaml')}</span>
            <textarea value={newYaml} onChange={e => setNewYaml(e.target.value)} required rows={8} spellCheck={false}
              className={`${controlCls} font-mono text-xs`} style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="policy-editor-create-yaml" />
          </label>
          {createError && (
            <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }} data-testid="policy-editor-create-error">
              {createError}
            </p>
          )}
          <div>
            <button type="submit" disabled={creating} className="btn-primary min-h-[44px] w-fit" data-testid="policy-editor-create-submit">
              {creating ? t('policyEditor.creating') : t('policyEditor.createSubmit')}
            </button>
          </div>
        </form>
      )}

      {org && policyId && detailState === 'loading' && <StateNotice state="loading" message={t('states.loading')} />}
      {org && policyId && detailState === 'error' && (
        <StateNotice state="error" message={t('policyEditor.detailError')}
          action={{ label: t('common.retry'), onClick: () => void loadDetail(policyId) }} />
      )}
      {org && policyId && detailState === 'ready' && detail && (
        <>
          {/* Meta + mode toggle. */}
          <section className="card flex flex-wrap items-center gap-3 p-4" data-testid="policy-editor-meta">
            <h2 className="text-base font-semibold text-[color:var(--astra-ink)]" style={{ fontFamily: 'var(--astra-font-code)' }}>
              {detail.policy.name}
            </h2>
            <span className="text-sm text-[color:var(--astra-text-muted)]" data-testid="policy-editor-active">
              {t('policyEditor.activeAt', { version: detail.policy.current_version })}
            </span>
            <span
              className="rounded-[length:var(--astra-radius-control)] border px-2 py-0.5 text-xs"
              style={{
                borderColor: detail.policy.enabled ? 'var(--astra-success)' : 'var(--astra-rule-strong)',
                color: detail.policy.enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)',
              }}
              data-testid="policy-editor-enabled"
            >
              {detail.policy.enabled ? t('policyEditor.stateEnabled') : t('policyEditor.stateDisabled')}
            </span>
            <button type="button" onClick={runToggle} className="btn-secondary min-h-[44px]" data-testid="policy-editor-toggle">
              {detail.policy.enabled ? t('policyEditor.toggleDetach') : t('policyEditor.toggleEnable')}
            </button>
          </section>

          {/* Drift report (owner decision 2026-11-04 (b)): the dashboard
              SHOWS drift — managed / drift / unmanaged per policy, with the
              org drift count; refreshed after every mutation so a UI edit
              past git flips the row immediately. */}
          <section className="card flex flex-col gap-2 p-4" data-testid="policy-editor-drift">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('policyEditor.driftTitle')}</h2>
              <button type="button" onClick={() => void loadDrift()} className="btn-secondary min-h-[44px]" data-testid="policy-editor-drift-refresh">
                {t('policyEditor.driftRefresh')}
              </button>
            </div>
            {driftFailed && <StateNotice state="error" message={t('policyEditor.driftLoadFailed')}
              action={{ label: t('common.retry'), onClick: () => void loadDrift() }} />}
            {drift && (
              <>
                <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="policy-editor-drift-summary">
                  {t('policyEditor.driftSummary', { count: drift.drift_count, total: drift.count })}
                </p>
                {drift.data.length > 0 && (
                  <ul className="flex flex-col gap-1">
                    {drift.data.map((entry: PolicyDriftEntry) => {
                      const isDrift = entry.status === 'drift'
                      const statusColor = isDrift
                        ? 'var(--astra-danger)'
                        : entry.status === 'managed' ? 'var(--astra-success)' : 'var(--astra-text-muted)'
                      return (
                        <li
                          key={entry.policy_id}
                          data-testid={`policy-editor-drift-row-${entry.policy_id}`}
                          className="flex flex-wrap items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 py-2 text-sm"
                        >
                          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{entry.name}</span>
                          <span
                            className="rounded-[length:var(--astra-radius-control)] border px-1.5 py-0.5 text-xs"
                            style={{ color: statusColor, borderColor: isDrift ? 'var(--astra-danger)' : 'var(--astra-rule-strong)' }}
                            data-testid={`policy-editor-drift-status-${entry.policy_id}`}
                          >
                            {driftStatusLabel(entry.status)}
                          </span>
                          <span className="text-xs text-[color:var(--astra-text-muted)]">
                            @v{entry.current_version}{entry.latest_version > 0 && entry.latest_version !== entry.current_version
                              ? ` → @v${entry.latest_version}` : ''}
                          </span>
                          <span className="ml-auto text-xs text-[color:var(--astra-text-muted)]">{entry.latest_edited_at}</span>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </>
            )}
          </section>

          {staleBlocked && (
            <div data-testid="policy-editor-stale">
              <StateNotice
                state="stale"
                message={conflictCurrent !== null
                  ? t('policyEditor.staleConflict', { version: conflictCurrent })
                  : t('policyEditor.staleMessage')}
                action={{ label: t('policyEditor.staleRefresh'), onClick: () => void loadDetail(policyId) }}
              />
            </div>
          )}
          {mutateError && <StateNotice state="error" message={mutateError} />}

          {/* YAML editor: server-side validation; nothing stores on error. */}
          <section className="card flex flex-col gap-3 p-4" data-testid="policy-editor-yaml">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('policyEditor.editorTitle')}</h2>
              {dirty && <span className="text-xs text-[color:var(--astra-text-muted)]">{t('policyEditor.dirty')}</span>}
            </div>
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('policyEditor.editorHint')}</p>
            <label className="sr-only" htmlFor="policy-editor-yaml-input">{t('policyEditor.editorTitle')}</label>
            <textarea
              id="policy-editor-yaml-input"
              value={yamlText}
              onChange={e => { setYamlText(e.target.value); setDirty(true); setValidationError(''); setSavedVersion(null) }}
              rows={14}
              spellCheck={false}
              className={`${controlCls} text-xs`}
              style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="policy-editor-yaml-input"
            />
            {validationError && (
              <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }} data-testid="policy-editor-validation">
                {t('policyEditor.validationErrorTitle')}: {validationError}
              </p>
            )}
            {savedVersion !== null && !validationError && (
              <p className="text-sm" style={{ color: 'var(--astra-success)' }} data-testid="policy-editor-saved">
                {t('policyEditor.saved', { version: savedVersion })}
              </p>
            )}
            <div>
              <button
                type="button"
                onClick={saveDraft}
                disabled={saveBusy || !dirty || staleBlocked}
                className="btn-primary min-h-[44px] w-fit"
                data-testid="policy-editor-save"
              >
                {saveBusy ? t('policyEditor.saving') : t('policyEditor.saveDraft')}
              </button>
            </div>
          </section>

          {/* Preview: the effect of activating the buffer, before saving it. */}
          <section className="card flex flex-col gap-2 p-4" data-testid="policy-editor-preview">
            <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('policyEditor.previewTitle')}</h2>
            <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="policy-editor-preview-active">
              {activeV
                ? t('policyEditor.previewActive', { version: activeV.version })
                : t('policyEditor.previewNoActive')}
            </p>
            {previewDiff.length > 0 ? (
              <p className="text-sm" data-testid="policy-editor-preview-diff">
                {t('policyEditor.previewChanges', {
                  added: previewSummary.added,
                  removed: previewSummary.removed,
                  version: activeV?.version ?? 0,
                })}
              </p>
            ) : (
              <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="policy-editor-preview-diff">
                {t('policyEditor.previewNoChange')}
              </p>
            )}
            <a
              href={`#policy-decisions?org=${encodeURIComponent(org)}&policy=${encodeURIComponent(policyId)}`}
              className="text-sm underline w-fit"
              data-testid="policy-editor-preview-decisions"
            >
              {t('policyEditor.previewDecisions')}
            </a>
            {/* CORE-TRACE-03: the other half of the same log — the
              per-request roll-up. `view=requests` lands the decision log on
              its requests view filtered to this pipeline. */}
            <a
              href={`#policy-decisions?org=${encodeURIComponent(org)}&policy=${encodeURIComponent(policyId)}&view=requests`}
              className="text-sm underline w-fit"
              data-testid="policy-editor-preview-requests"
            >
              {t('policyEditor.previewRequests')}
            </a>
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('policyEditor.previewNote')}</p>
          </section>

          {/* Version history + diff + activate/rollback. */}
          <section className="card flex flex-col gap-3 p-4" data-testid="policy-editor-versions">
            <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('policyEditor.versionsTitle')}</h2>
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('policyEditor.versionsHint')}</p>
            <div className="flex flex-wrap items-end gap-3" data-testid="policy-editor-diff-select">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('policyEditor.diffFrom')}</span>
                <select value={diffA ?? ''} onChange={e => setDiffA(e.target.value ? Number(e.target.value) : null)} className={`w-28 ${controlCls}`}>
                  {(detail.versions ?? []).map(v => <option key={v.version} value={v.version}>@v{v.version}</option>)}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('policyEditor.diffTo')}</span>
                <select value={diffB ?? ''} onChange={e => setDiffB(e.target.value ? Number(e.target.value) : null)} className={`w-28 ${controlCls}`}>
                  {(detail.versions ?? []).map(v => <option key={v.version} value={v.version}>@v{v.version}</option>)}
                </select>
              </label>
              {diffLinesView.length > 0 && (
                <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="policy-editor-diff-summary">
                  {t('policyEditor.diffSummary', { added: diffViewSummary.added, removed: diffViewSummary.removed })}
                </p>
              )}
            </div>
            {diffLinesView.length > 0 && (
              <pre
                aria-label={t('policyEditor.diffTitle')}
                className="overflow-x-auto rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface)] p-3 text-xs leading-relaxed"
                style={{ fontFamily: 'var(--astra-font-code)' }}
                data-testid="policy-editor-diff-view"
              >
                {diffLinesView.map((l, idx) => (
                  <span
                    key={idx}
                    aria-hidden={false}
                    style={{
                      display: 'block',
                      color: l.type === 'add' ? 'var(--astra-success)' : l.type === 'del' ? 'var(--astra-danger)' : 'var(--astra-text-muted)',
                    }}
                  >
                    {l.type === 'add' ? '+ ' : l.type === 'del' ? '- ' : '  '}{l.text}
                  </span>
                ))}
              </pre>
            )}
            {diffA !== null && diffB !== null && diffA === diffB && (
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('policyEditor.diffEmpty')}</p>
            )}
            <ul className="flex flex-col gap-1">
              {(detail.versions ?? []).map(v => {
                const isActive = v.version === detail.policy.current_version
                return (
                  <li
                    key={v.id}
                    data-testid={`policy-editor-version-${v.version}`}
                    className="flex flex-wrap items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 py-2 text-sm"
                  >
                    <span style={{ fontFamily: 'var(--astra-font-code)' }}>@v{v.version}</span>
                    <span className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-1.5 py-0.5 text-xs text-[color:var(--astra-text-muted)]">
                      {v.label}
                    </span>
                    {isActive && (
                      <span className="text-xs" style={{ color: 'var(--astra-success)' }} data-testid={`policy-editor-version-${v.version}-active`}>
                        {t('policyEditor.activeChip')}
                      </span>
                    )}
                    <span className="text-xs text-[color:var(--astra-text-muted)]">
                      {v.created_by ? `${v.created_by} · ` : ''}{v.created_at}
                    </span>
                    {!isActive && (
                      <button
                        type="button"
                        onClick={() => runActivate(v.version)}
                        className="btn-secondary ml-auto min-h-[44px]"
                        data-testid={`policy-editor-activate-${v.version}`}
                      >
                        {isRollback(v.version, detail.policy.current_version)
                          ? t('policyEditor.rollbackTo', { version: v.version })
                          : t('policyEditor.activateTo', { version: v.version })}
                      </button>
                    )}
                  </li>
                )
              })}
            </ul>
          </section>
        </>
      )}

      {activateAction.ui}
      {toggleAction.ui}
    </div>
  )
}
