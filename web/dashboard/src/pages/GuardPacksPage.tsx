import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import {
  activateGuardPack, guardPackStatus, listGuardPacks, rollbackGuardPack,
  simulateGuardPack, validateGuardPack,
  type GuardPackList, type GuardPackRow, type GuardPackSimulation, type GuardPackValidation,
} from '../api/guardPacks.ts'
import { listAuditLogs, type AuditLogEntry } from '../api/audit.ts'
import { ApiError } from '../api/transport.ts'
import {
  activePackDir, durableVersionLabel, filterGuardPackJournal, guardPackErrorView,
  packRows, statusView, type GuardPackErrorView, type GuardPackStatusView,
} from './guardPacksModel.ts'

// N02-P08 (T02/T06): the guard detector-pack lifecycle screen — the free
// BYO cycle end to end, no paywall vocabulary, no invented telemetry.
//
// Chain (each stage is a distinct network call the e2e spec asserts):
//   edit      the operator authors pack files under the server's pack root
//             (documented honestly in the empty state — the UI has no pack
//             upload by design: writing operator files from a browser is a
//             separate, unapproved surface);
//   validate  POST /api/guard-packs/validate (dry-run loader, stages nothing);
//   simulate  POST /api/guard-packs/simulate (detect-only preview);
//   activate  POST /api/guard-packs/activate (durable CAS);
//   runtime   GET  /api/guard-packs/status (durable state + load check);
//   audit     GET  /api/audit-logs page 1, client-filtered to guard_pack
//             (the endpoint has no resource filter; labeled as first page).
//
// Negative states are first-class: 404 unknown pack/version, 409 with the
// server's LIVE durable state, 409 verification failure, 500 store failure,
// 503 unwired surface — every one renders the server's own message.

type MutationOutcome =
  | { kind: 'activated'; activeVersion: string; previousVersion: string }
  | { kind: 'rolledBack'; activeVersion: string; previousVersion: string }
  | { kind: 'error'; view: GuardPackErrorView }

export function GuardPacksPage() {
  const { t } = useTranslation()

  // ----- data: list + status (one load, refreshed after mutations) -----
  const [list, setList] = useState<GuardPackList | null>(null)
  const [status, setStatus] = useState<GuardPackStatusView | null>(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(true)
  const genRef = useRef(0)

  const refresh = useCallback(async () => {
    const gen = ++genRef.current
    setLoading(true)
    setLoadError('')
    try {
      const [nextList, nextStatus] = await Promise.all([listGuardPacks(), guardPackStatus()])
      if (gen !== genRef.current) return
      setList(nextList)
      setStatus(statusView(nextStatus))
    } catch (err) {
      if (gen !== genRef.current) return
      setList(null)
      setStatus(null)
      setLoadError(err instanceof ApiError ? err.message : String(err))
    } finally {
      if (gen === genRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  // ----- per-row dry-run results -----
  const [validation, setValidation] = useState<Record<string, GuardPackValidation | { error: string }>>({})
  const [busyRow, setBusyRow] = useState('')

  // ----- simulate form -----
  const [sample, setSample] = useState('')
  const [simulation, setSimulation] = useState<GuardPackSimulation | null>(null)
  const [simulateError, setSimulateError] = useState('')
  const [simulating, setSimulating] = useState(false)

  // ----- activate / rollback -----
  const [outcome, setOutcome] = useState<MutationOutcome | null>(null)
  const [activating, setActivating] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)

  // ----- journal (first page, client-filtered) -----
  const [journal, setJournal] = useState<AuditLogEntry[] | null>(null)
  useEffect(() => {
    let alive = true
    listAuditLogs(1)
      .then(body => { if (alive) setJournal(filterGuardPackJournal(body.audit_logs ?? [])) })
      .catch(() => { if (alive) setJournal(null) })
    return () => { alive = false }
  }, [outcome])

  const rows = packRows(list?.packs)

  const runValidate = async (row: GuardPackRow) => {
    const key = rowKey(row)
    setBusyRow(key)
    try {
      const result = await validateGuardPack(row.pack_id ?? row.dir, row.pack_version ?? '')
      setValidation(prev => ({ ...prev, [key]: result }))
    } catch (err) {
      setValidation(prev => ({ ...prev, [key]: { error: err instanceof ApiError ? err.message : String(err) } }))
    } finally {
      setBusyRow('')
    }
  }

  const runActivate = async (row: GuardPackRow) => {
    setActivating(true)
    setOutcome(null)
    try {
      const result = await activateGuardPack(row.pack_id ?? row.dir, row.pack_version ?? '')
      setOutcome({ kind: 'activated', activeVersion: result.active_version, previousVersion: result.previous_version })
      await refresh()
    } catch (err) {
      setOutcome({ kind: 'error', view: guardPackErrorView(err) })
    } finally {
      setActivating(false)
    }
  }

  const runRollback = async () => {
    setRollingBack(true)
    setOutcome(null)
    try {
      const result = await rollbackGuardPack()
      setOutcome({ kind: 'rolledBack', activeVersion: result.active_version, previousVersion: result.previous_version })
      await refresh()
    } catch (err) {
      setOutcome({ kind: 'error', view: guardPackErrorView(err) })
    } finally {
      setRollingBack(false)
    }
  }

  const runSimulate = async (row: GuardPackRow) => {
    setSimulating(true)
    setSimulateError('')
    setSimulation(null)
    try {
      const result = await simulateGuardPack(row.pack_id ?? row.dir, row.pack_version ?? '', sample)
      setSimulation(result)
    } catch (err) {
      setSimulateError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setSimulating(false)
    }
  }

  const [selected, setSelected] = useState<GuardPackRow | null>(null)
  const healthy = rows.filter(r => !r.error)
  const selectedRow = selected ?? healthy[0] ?? null

  return (
    <div className="space-y-6">
      <PageHeader title={t('guardPacks.title')} purpose={t('guardPacks.purpose')} />

      <p className="max-w-3xl text-sm text-[color:var(--astra-text-muted)]">{t('guardPacks.intro')}</p>

      {/* Runtime status strip: durable requested state + honest load check.
          No applied version and no failure count are fabricated here — the
          gateway's per-replica telemetry lives in its /metrics and logs. */}
      <section aria-labelledby="guardpacks-status" data-testid="guardpacks-status" className="space-y-2">
        <h2 id="guardpacks-status" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardPacks.statusTitle')}
        </h2>
        {loading && <StateNotice state="loading" message={t('table.fetchingScope')} />}
        {!loading && loadError && <StateNotice state="error" message={loadError} />}
        {!loading && !loadError && status && (
          <div className="astra-panel grid gap-3 px-4 py-3 text-sm sm:grid-cols-2 lg:grid-cols-4" data-testid="guardpacks-status-values">
            <StatusCell label={t('guardPacks.statusActive')} value={status.activeVersion} testId="guardpacks-status-active" />
            <StatusCell label={t('guardPacks.statusPrevious')} value={status.previousVersion} testId="guardpacks-status-previous" />
            <StatusCell label={t('guardPacks.statusStaged')} value={status.stagedVersion === '' ? '—' : status.stagedVersion} testId="guardpacks-status-staged" />
            <div className="min-w-0">
              <p className="text-[12px] uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('guardPacks.statusLoadCheck')}</p>
              {status.activePackLoadable ? (
                <p className="font-medium text-[color:var(--astra-ink)]" data-testid="guardpacks-status-loadable">{t('guardPacks.statusLoadOk')}</p>
              ) : (
                <p className="font-medium text-[color:var(--astra-ink)]" data-testid="guardpacks-status-load-error" title={status.loadError ?? ''}>
                  {t('guardPacks.statusLoadFailed')}
                </p>
              )}
            </div>
            <p className="text-[12px] text-[color:var(--astra-text-muted)] sm:col-span-2 lg:col-span-4">{status.check}</p>
            {!status.activePackLoadable && status.loadError && (
              <p className="text-[12px] text-[color:var(--astra-ink)] sm:col-span-2 lg:col-span-4" data-testid="guardpacks-status-load-error-detail">{status.loadError}</p>
            )}
          </div>
        )}
      </section>

      {/* Pack inventory */}
      <section aria-labelledby="guardpacks-packs" data-testid="guardpacks-packs" className="space-y-3">
        <h2 id="guardpacks-packs" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardPacks.packsTitle')}
        </h2>
        {!loading && !loadError && rows.length === 0 && (
          <StateNotice state="empty" message={t('guardPacks.emptyPacks')} />
        )}
        {!loading && !loadError && rows.length > 0 && (
          <DataTable
            columns={packColumns(t, list?.active_version ?? '')}
            rows={rows}
            getRowId={rowKey}
            page={1}
            pageSize={Math.max(rows.length, 1)}
            onPageChange={() => { /* single-page inventory: the walk is unpaginated */ }}
            caption={t('guardPacks.packsCaption')}
            renderActions={row => {
              const key = rowKey(row)
              const disabled = row.error !== undefined && row.error !== '' || busyRow === key
              return (
                <span className="flex flex-wrap gap-1">
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={disabled}
                    data-testid={`guardpacks-validate-${key}`}
                    onClick={() => void runValidate(row)}
                  >
                    {t('guardPacks.validate')}
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={disabled || activating}
                    data-testid={`guardpacks-activate-${key}`}
                    onClick={() => void runActivate(row)}
                  >
                    {t('guardPacks.activate')}
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    data-testid={`guardpacks-simulate-pick-${key}`}
                    onClick={() => setSelected(row)}
                  >
                    {t('guardPacks.simulatePick')}
                  </button>
                </span>
              )
            }}
          />
        )}
        {/* Per-row validation verdicts (server's own words, never rewritten). */}
        {Object.entries(validation).map(([key, result]) => (
          <p key={key} className="text-sm" data-testid={`guardpacks-validation-${key}`}>
            {('error' in result)
              ? <span className="text-[color:var(--astra-ink)]">{t('guardPacks.validationFailed', { message: result.error })}</span>
              : <span className="text-[color:var(--astra-ink)]">{t('guardPacks.validationOk', { pack: result.pack_id, version: result.pack_version, detectors: result.detectors })}</span>}
          </p>
        ))}
      </section>

      {/* Simulate (detect-only preview) */}
      <section aria-labelledby="guardpacks-simulate" data-testid="guardpacks-simulate" className="space-y-3">
        <h2 id="guardpacks-simulate" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardPacks.simulateTitle')}
        </h2>
        <p className="max-w-3xl text-sm text-[color:var(--astra-text-muted)]">{t('guardPacks.simulateIntro')}</p>
        {selectedRow ? (
          <div className="astra-panel space-y-3 px-4 py-4">
            <p className="text-sm font-medium text-[color:var(--astra-ink)]" data-testid="guardpacks-simulate-pack">
              {t('guardPacks.simulatePack', { pack: selectedRow.pack_id ?? selectedRow.dir, version: selectedRow.pack_version ?? '—' })}
            </p>
            <label className="block text-sm text-[color:var(--astra-ink)]" htmlFor="guardpacks-sample">
              {t('guardPacks.sampleLabel')}
            </label>
            <textarea
              id="guardpacks-sample"
              className="w-full rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-sm text-[color:var(--astra-ink)]"
              rows={4}
              value={sample}
              onChange={e => setSample(e.target.value)}
              data-testid="guardpacks-sample-input"
            />
            <button
              type="button"
              className="btn-primary"
              disabled={simulating}
              data-testid="guardpacks-simulate-run"
              onClick={() => void runSimulate(selectedRow)}
            >
              {t('guardPacks.simulateRun')}
            </button>
            {simulateError && <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-simulate-error">{simulateError}</p>}
            {simulation && (
              <div className="space-y-2" data-testid="guardpacks-simulation">
                <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-simulation-total">
                  {simulation.truncated
                    ? t('guardPacks.simulationTruncated', { total: simulation.total_findings })
                    : t('guardPacks.simulationTotal', { total: simulation.total_findings })}
                </p>
                {simulation.categories && simulation.categories.length > 0 && (
                  <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-simulation-categories">
                    {t('guardPacks.simulationCategories', { categories: simulation.categories.join(', ') })}
                  </p>
                )}
                {simulation.findings.length > 0 && (
                  <ul className="space-y-1 text-sm" data-testid="guardpacks-simulation-findings">
                    {simulation.findings.map((f, i) => (
                      <li key={`${f.detector}:${f.start}:${i}`} className="text-[color:var(--astra-ink)]">
                        <span className="font-[family-name:var(--astra-font-code)]">{f.detector}</span>
                        {' · '}{f.category}{' · '}[{f.start}, {f.end})
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        ) : (
          <StateNotice state="empty" message={t('guardPacks.simulateNoPack')} />
        )}
      </section>

      {/* Activate / rollback outcomes (honest failure states) */}
      <section aria-labelledby="guardpacks-mutations" data-testid="guardpacks-mutations" className="space-y-3">
        <h2 id="guardpacks-mutations" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardPacks.mutationsTitle')}
        </h2>
        <button
          type="button"
          className="btn-secondary"
          disabled={rollingBack}
          data-testid="guardpacks-rollback"
          onClick={() => void runRollback()}
        >
          {t('guardPacks.rollback')}
        </button>
        {outcome?.kind === 'activated' && (
          <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-outcome-activated">
            {t('guardPacks.activated', { active: outcome.activeVersion, previous: outcome.previousVersion })}
          </p>
        )}
        {outcome?.kind === 'rolledBack' && (
          <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-outcome-rolled-back">
            {t('guardPacks.rolledBack', { active: outcome.activeVersion, previous: outcome.previousVersion })}
          </p>
        )}
        {outcome?.kind === 'error' && (() => {
          // Literal keys only — the i18n static-scan gate (keys.test.ts)
          // verifies every t('…') call site against en.json.
          const kindLabel: Record<GuardPackErrorView['kind'], string> = {
            notFound: t('guardPacks.errorKind.notFound'),
            conflict: t('guardPacks.errorKind.conflict'),
            conflictState: t('guardPacks.errorKind.conflictState'),
            storeFailure: t('guardPacks.errorKind.storeFailure'),
            unwired: t('guardPacks.errorKind.unwired'),
            http: t('guardPacks.errorKind.http'),
          }
          return (
            <div className="astra-panel space-y-1 px-4 py-3" data-testid="guardpacks-outcome-error">
              <p className="text-sm font-semibold text-[color:var(--astra-ink)]">{kindLabel[outcome.view.kind]}</p>
              <p className="text-sm text-[color:var(--astra-ink)]">{outcome.view.serverMessage}</p>
              {outcome.view.conflict && (
                <p className="text-sm text-[color:var(--astra-ink)]" data-testid="guardpacks-outcome-conflict-state">
                  {t('guardPacks.conflictLiveState', {
                    active: durableVersionLabel(outcome.view.conflict.active_version ?? ''),
                    previous: durableVersionLabel(outcome.view.conflict.previous_version ?? ''),
                  })}
                </p>
              )}
            </div>
          )
        })()}
      </section>

      {/* Audit trail: the guard_pack slice of the journal's first page. */}
      <section aria-labelledby="guardpacks-journal" data-testid="guardpacks-journal" className="space-y-3">
        <h2 id="guardpacks-journal" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardPacks.journalTitle')}
        </h2>
        <p className="max-w-3xl text-sm text-[color:var(--astra-text-muted)]">{t('guardPacks.journalIntro')}</p>
        {journal === null
          ? <StateNotice state="error" message={t('guardPacks.journalUnavailable')} />
          : journal.length === 0
            ? <StateNotice state="empty" message={t('guardPacks.journalEmpty')} />
            : (
              <ul className="space-y-1 text-sm" data-testid="guardpacks-journal-entries">
                {journal.map(e => (
                  <li key={e.id} className="text-[color:var(--astra-ink)]">
                    <span className="font-[family-name:var(--astra-font-code)]">{e.action}</span>
                    {' · '}{e.details ?? ''}{' · '}{e.admin_name}{' · '}{e.timestamp}
                  </li>
                ))}
              </ul>
            )}
        <a href="#audit-log" className="text-sm font-medium text-[color:var(--astra-ink)] underline" data-testid="guardpacks-journal-link">
          {t('guardPacks.journalLink')}
        </a>
      </section>
    </div>
  )
}

function StatusCell(props: { label: string; value: string; testId: string }) {
  return (
    <div className="min-w-0">
      <p className="text-[12px] uppercase tracking-wide text-[color:var(--astra-text-muted)]">{props.label}</p>
      <p className="truncate font-medium text-[color:var(--astra-ink)]" data-testid={props.testId} title={props.value}>{props.value}</p>
    </div>
  )
}

function rowKey(row: GuardPackRow): string {
  return row.dir
}

type TFunc = (key: string, params?: Record<string, unknown>) => string

function packColumns(t: TFunc, activeVersion: string): Array<DataTableColumn<GuardPackRow>> {
  const activeDir = activePackDir(activeVersion)
  return [
    { key: 'dir', header: t('guardPacks.colPack'), mono: true, sortable: false },
    { key: 'pack_version', header: t('guardPacks.colVersion'), mono: true, sortable: false },
    {
      key: 'signature_declared',
      header: t('guardPacks.colSignature'),
      sortable: false,
      render: row => t(row.signature_declared ? 'guardPacks.signatureDeclared' : 'guardPacks.signatureUnsigned'),
    },
    {
      key: 'state',
      header: t('guardPacks.colState'),
      sortable: false,
      render: row => (row.dir === activeDir ? t('guardPacks.stateActive') : '—'),
    },
    { key: 'error', header: t('guardPacks.colLoadError'), sortable: false, render: row => row.error ?? '' },
  ]
}
