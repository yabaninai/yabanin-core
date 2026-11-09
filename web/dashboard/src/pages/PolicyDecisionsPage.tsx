import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useHashParam } from '../hooks/useHashParam'
import {
  listPolicyDecisions,
  listPolicyDecisionRequests,
  type PolicyDecision,
  type PolicyDecisionEntity,
  type PolicyDecisionRequestSummary,
} from '../api/client'
import { PageHeader } from '../components/astra/PageHeader'
import { OrgSelect } from '../components/OrgSelect'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { Pagination } from '../components/Pagination'
import { DEFAULT_PAGE_SIZE } from '../api/http.ts'
import { currentHashQuery, relatedListHref } from '../lib/inspectUrl'

// OP-9: the policy decision log — read-only view of what the org's policy
// pipeline did (shadow vs enforce), one row per evaluation the gateway
// attached to a request event. Findings show detector categories only (the
// log is content-free by contract); retention is 90 days.
//
// CORE-TRACE-03: the log has two views over the same frozen API. `decisions`
// keeps the per-evaluation rows (now with the request id and a reverse link
// into the request explorer); `requests` shows the per-request roll-up the
// policy editor's affected-requests link lands on. `view`, `verdict`, `mode`
// and `request` all ride the hash query, so org switches, deep links and
// reloads preserve the full scope. A shadow evaluation never renders as an
// applied verdict: the cell says explicitly what WOULD have happened.
type DecisionRow = PolicyDecision | PolicyDecisionRequestSummary

export function PolicyDecisionsPage() {
  const { t } = useTranslation()
  // &policy=…) so the policy editor's preview can deep-link the log for the
  // exact pipeline; the controls keep working exactly as before.
  const [org, setOrg] = useHashParam('org')
  const [verdict, setVerdict] = useHashParam('verdict')
  const [mode, setMode] = useHashParam('mode')
  const [policyId, setPolicyId] = useHashParam('policy')
  const [viewParam, setView] = useHashParam('view')
  const [requestId, setRequestId] = useHashParam('request')
  // Unknown/absent view params degrade to the per-evaluation log.
  const view: PolicyDecisionEntity = viewParam === 'requests' ? 'requests' : 'decisions'
  const [rows, setRows] = useState<DecisionRow[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(0)
  const [page, setPage] = useState(1)
  const [failed, setFailed] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const gen = useRef(0)

  const reload = useCallback((targetPage: number) => {
    if (!org.trim()) return
    const g = ++gen.current
    setLoading(true)
    const filters = {
      verdict: verdict || undefined,
      mode: mode || undefined,
      policyId: policyId.trim() || undefined,
      requestId: requestId.trim() || undefined,
    }
    const pending = view === 'requests'
      ? listPolicyDecisionRequests(org.trim(), targetPage, filters, DEFAULT_PAGE_SIZE)
      : listPolicyDecisions(org.trim(), targetPage, filters, DEFAULT_PAGE_SIZE)
    pending
      .then(res => {
        if (gen.current !== g) return
        setRows(res.rows); setTotal(res.total); setTotalPages(res.totalPages)
        setFailed(false)
      })
      // may flag the screen. The inverted `!==` never set `failed` for the
      // live load, so a 403/500 rendered the EMPTY notice (empty data
      // without diagnostics) while a superseded load's failure clobbered
      // the newer state. Failure of the current load drops the stale rows
      // (partial/unknown is never success) and names the failure + retry.
      .catch(() => { if (gen.current === g) { setFailed(true); setRows([]); setTotal(0) } })
      .finally(() => { if (gen.current === g) { setLoaded(true); setLoading(false) } })
  }, [org, verdict, mode, policyId, requestId, view])

  useEffect(() => {
    setPage(1)
    // View switches swap the column set: stale rows from the other entity
    // would render under the wrong headers until the debounce fires, so the
    // rows drop as soon as the scope changes (RequestExplorer pattern).
    // The loading flag flips in the same tick — the
    // rows are gone but the debounced fetch has not started yet, and with
    // `loading` still false the per-view «empty» notice (empty vs
    // emptyRequests) would flash a false statement for the whole 400 ms
    // debounce window on every filter edit / view toggle.
    setRows([])
    if (org.trim()) setLoading(true)
    const timer = setTimeout(() => reload(1), 400)
    return () => { clearTimeout(timer) }
  }, [reload, org])

  const requestLink = (id: string) => (
    // CORE-TRACE-03 AC3: a decision row names its request and leads back to
    // it — the explorer opens the inspector for `request:<id>` in the same
    // org scope. relatedListHref carries the current scope params along.
    <a
      className="text-[color:var(--astra-accent)] underline-offset-2 hover:underline"
      href={relatedListHref('requests-explorer', currentHashQuery(), { org: org.trim(), inspect: `request:${id}` })}
      title={t('policyDecisions.openRequest', { id })}
    >{id}</a>
  )

  const columns: DataTableColumn<DecisionRow>[] = view === 'requests' ? [
    { key: 'request_id', header: t('policyDecisions.colRequest'), type: 'text', mono: true, sortable: false,
      render: d => requestLink((d as PolicyDecisionRequestSummary).request_id) },
    { key: 'evaluations', header: t('policyDecisions.colEvaluations'), type: 'text', align: 'right', sortable: false },
    { key: 'first_seen_at', header: t('policyDecisions.colFirstSeen'), format: 'date', sortable: false },
    { key: 'last_seen_at', header: t('policyDecisions.colLastSeen'), format: 'date', sortable: false },
  ] : [
    { key: 'created_at', header: t('policyDecisions.colTime'), format: 'date', render: d => (d as PolicyDecision).created_at },
    { key: 'policy_id', header: t('policyDecisions.colPolicy'), type: 'text', mono: true,
      render: d => { const r = d as PolicyDecision; return r.policy_version > 0 ? `${r.policy_id} @v${r.policy_version}` : r.policy_id } },
    { key: 'mode', header: t('policyDecisions.colMode'), type: 'text' },
    { key: 'verdict', header: t('policyDecisions.colVerdict'), type: 'text',
      render: d => {
        const r = d as PolicyDecision
        return r.mode === 'shadow'
          ? t('policyDecisions.verdictShadow', { verdict: r.verdict })
          : r.verdict
      } },
    { key: 'findings', header: t('policyDecisions.colFindings'), type: 'text', sortable: false,
      render: d => (d as PolicyDecision).findings
        .map(f => (f.step ? `${f.step}: ${f.category}` : f.category))
        .filter(Boolean).join(', ') },
    { key: 'request_id', header: t('policyDecisions.colRequest'), type: 'text', mono: true, sortable: false,
      render: d => {
        // Legacy rows (pre-instrumented traffic) serve
        // request_id: '' on the decisions entity (the requests roll-up filters
        // them out server-side). An empty id must not render an <a>: an empty,
        // keyboard-focusable link with a broken tooltip, whose blank inspect
        // param the explorer drops anyway. A bare dash — no link.
        const id = (d as PolicyDecision).request_id
        return id ? requestLink(id) : '—'
      } },
    { key: 'duration_ms', header: t('policyDecisions.colDuration'), format: 'duration', unit: 'ms', align: 'right' },
  ]

  const controlCls = 'min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-[color:var(--astra-ink)]'

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t('policyDecisions.title')} purpose={t('policyDecisions.purpose')} />
      <form className="card flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault() }}>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('explorer.organizationId')}</span>
          <OrgSelect
            value={org}
            onChange={v => { setOrg(v); setLoaded(false) }}
            autoSelect
            className="w-64"
            manualAriaLabel={t('explorer.orgUuid')}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyDecisions.viewLabel')}</span>
          <select value={view} onChange={e => setView(e.target.value)} className={`w-44 ${controlCls}`}>
            <option value="decisions">{t('policyDecisions.viewEvaluations')}</option>
            <option value="requests">{t('policyDecisions.viewRequests')}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyDecisions.filterVerdict')}</span>
          <select value={verdict} onChange={e => setVerdict(e.target.value)} className={`w-32 ${controlCls}`}>
            <option value="">{t('policyDecisions.filterAll')}</option>
            <option value="allow">allow</option>
            <option value="flag">flag</option>
            <option value="mask">mask</option>
            <option value="deny">deny</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyDecisions.filterMode')}</span>
          <select value={mode} onChange={e => setMode(e.target.value)} className={`w-32 ${controlCls}`}>
            <option value="">{t('policyDecisions.filterAll')}</option>
            <option value="shadow">shadow</option>
            <option value="enforce">enforce</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyDecisions.filterPolicy')}</span>
          <input value={policyId} onChange={e => setPolicyId(e.target.value)}
            placeholder="*" spellCheck={false} className={`w-56 ${controlCls}`}
            style={{ fontFamily: 'var(--astra-font-code)' }} />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('policyDecisions.filterRequest')}</span>
          <input value={requestId} onChange={e => setRequestId(e.target.value)}
            placeholder="*" spellCheck={false} className={`w-56 ${controlCls}`}
            style={{ fontFamily: 'var(--astra-font-code)' }} />
        </label>
      </form>

      {!org.trim() && !loaded && <StateNotice state="not-loaded" message={t('policyDecisions.notLoaded')} />}
      {loaded && failed && <StateNotice state="error" message={t('policyDecisions.loadFailed')} action={{ label: t('common.retry'), onClick: () => reload(page) }} />}

      {org.trim() && loaded && !failed && (rows.length === 0 && !loading ? (
        <StateNotice state="empty" message={view === 'requests' ? t('policyDecisions.emptyRequests') : t('policyDecisions.empty')} />
      ) : (
        <div className="card overflow-x-auto">
          <DataTable
            columns={columns}
            rows={rows}
            getRowId={d => ('id' in d ? d.id : d.request_id)}
            loading={loading}
            page={page}
            pageSize={DEFAULT_PAGE_SIZE}
            onPageChange={p => { setPage(p); reload(p) }}
            pagination="external"
            serverTotal={total}
            sortMode="server"
            caption={t('policyDecisions.title')}
          />
          <Pagination
            page={page}
            pageSize={DEFAULT_PAGE_SIZE}
            total={total}
            totalPages={totalPages}
            loading={loading}
            onChange={p => { setPage(p); reload(p) }}
          />
        </div>
      ))}
    </div>
  )
}
