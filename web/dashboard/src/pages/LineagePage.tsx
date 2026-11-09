import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useHashParam } from '../hooks/useHashParam'
import {
  getLineage, verifyLineage, listLineageByOrg,
  type LineageRecord, type LineageAttestation,
} from '../api/client'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { useTablePrefs } from '../hooks/useTablePrefs'
import { TableSettingsMenu } from '../components/astra/TableSettingsMenu'
import { SavedViewsMenu } from '../components/astra/SavedViewsMenu'
import {
  currentHashQuery, deleteSavedView, listSavedViews, parseViewQuery,
  renameSavedView, saveSavedView, type SavedViewRecord,
} from '../lib/savedViews'
import { readTableUrlState } from '../lib/tableUrl'
import { RequestInspector } from '../components/astra/RequestInspector'
import { CopyIdButton } from '../components/astra/CopyIdButton'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'

// ASTR-04 adapter: the Lineage page on Astra primitives.
//  - org-scoped record list (DataTable): stable row ids, scoped client-side
//    pagination over the server-capped set, per-column sort, copy-ID;
//  - point lookup by request ID (as before) rendered via RequestInspector;
//  - inspect dialog with focus return + Escape close.

const PAGE_SIZE = 20
const SERVER_LIMIT = 50

const EVIDENCE_KEYS: Record<string, string> = {
  endpoint_pinned: 'lineage.evidenceEndpointPinned',
  header_observed: 'lineage.evidenceHeaderObserved',
  provider_attested: 'lineage.evidenceProviderAttested',
  provider_declared: 'lineage.evidenceProviderDeclared',
}

const evidenceText = (tier: unknown, t: (k: string) => string): string => {
  const key = typeof tier === 'string' ? EVIDENCE_KEYS[tier] : undefined
  return key ? t(key) : t('lineage.evidenceUnknown')
}

function toInspector(raw: Partial<LineageAttestation> & { request_id?: string }, t: (k: string) => string) {
  return {
    id: raw.request_id,
    model: typeof raw.model_used === 'string' ? raw.model_used : undefined,
    regionClaim: typeof raw.inference_region === 'string' ? raw.inference_region : undefined,
    timing: typeof raw.timestamp === 'string' ? raw.timestamp : undefined,
    evidence: {
      tier: typeof raw.region_evidence === 'string' && raw.region_evidence ? raw.region_evidence : 'provider_declared',
      explanation: evidenceText(raw.region_evidence, t),
    },
    raw,
  }
}

export function LineagePage() {
  const { t } = useTranslation()
  // Org-scoped list state.
  // UI-contract #1: the org scope is part of the URL (#page?org=…) — a
  // filtered view is a shareable link and survives reload/back-forward.
  const [urlOrg, setUrlOrg] = useHashParam('org')
  const [orgInput, setOrgInputInner] = useState(urlOrg)
  const setOrgInput = (v: string) => { setOrgInputInner(v); setUrlOrg(v.trim()) }
  const [orgScope, setOrgScope] = useState('')
  const [rows, setRows] = useState<LineageAttestation[]>([])
  const [listLoading, setListLoading] = useState(false)
  const [listError, setListError] = useState('')
  const [listLoaded, setListLoaded] = useState(false)
  // AUX-01: sort + page live in the URL (#lineage?lineage__sort=…:…) — a
  // sorted view is a shareable link and survives reload.
  const { page, setPage, sort, setSort } = useTableUrlState('lineage')
  // AUX-22: per-table personalization (hidden columns + density) and the
  // local saved-views registry, both keyed by the table id in localStorage.
  const prefs = useTablePrefs('lineage')
  const [views, setViews] = useState<SavedViewRecord[]>(() => listSavedViews('lineage'))
  const [selected, setSelected] = useState<LineageAttestation | null>(null)
  const listGen = useRef(0)
  const prevListOrg = useRef('')

  // Point-lookup state (kept from the pre-Astra page).
  // UI-contract #9: drill-down from the request explorer (#lineage?req=…)
  // pre-fills the lookup; submitting verifies as usual.
  const [urlReq, setUrlReq] = useHashParam('req')
  const [requestId, setRequestIdInner] = useState(urlReq)
  const setRequestId = (v: string) => { setRequestIdInner(v); setUrlReq(v.trim()) }
  const [record, setRecord] = useState<LineageRecord | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean } | null>(null)
  const [lookupError, setLookupError] = useState('')
  const lookupGen = useRef(0)

  // UX-03: auto-load the records list when a non-empty org is entered (300ms
  // debounce so typing the UUID doesn't fire a request per keystroke).
  useEffect(() => {
    if (!orgInput.trim()) return
    const timer = setTimeout(() => { void loadList() }, 300)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgInput])

  const loadList = async () => {
    const org = orgInput.trim()
    if (!org) return
    const gen = ++listGen.current
    setOrgScope(org)
    setListLoading(true)
    setListError('')
    setRows([])
    // A different org has a different row set — reset the page; reloading the
    // SAME org (e.g. the manual reload action) keeps a URL-restored page.
    if (prevListOrg.current !== org) {
      prevListOrg.current = org
      setPage(1)
    }
    setSelected(null)
    try {
      const result = await listLineageByOrg(org, SERVER_LIMIT)
      if (listGen.current === gen) setRows(result)
    } catch (err: unknown) {
      if (listGen.current === gen) setListError(err instanceof Error ? err.message : String(err))
    } finally {
      if (listGen.current === gen) {
        setListLoading(false)
        setListLoaded(true)
      }
    }
  }

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!requestId.trim()) return
    const gen = ++lookupGen.current
    setLookupLoading(true)
    setLookupError('')
    setRecord(null)
    setVerifyResult(null)
    try {
      const result = await getLineage(requestId.trim())
      if (lookupGen.current === gen) setRecord(result)
    } catch (err: unknown) {
      if (lookupGen.current === gen) setLookupError(err instanceof Error ? err.message : String(err))
    } finally {
      if (lookupGen.current === gen) setLookupLoading(false)
    }
  }

  const handleVerify = async (id?: string) => {
    const target = id ?? (typeof record?.request_id === 'string' ? record.request_id : '')
    if (!target) return
    const gen = lookupGen.current
    setVerifying(true)
    setVerifyResult(null)
    try {
      const result = await verifyLineage(target)
      if (lookupGen.current === gen) setVerifyResult(result)
    } catch (err: unknown) {
      if (lookupGen.current === gen) setLookupError(err instanceof Error ? err.message : String(err))
    } finally {
      if (lookupGen.current === gen) setVerifying(false)
    }
  }

  const columns: DataTableColumn<LineageAttestation>[] = [
    {
      key: 'request_id',
      header: t('lineage.headerRequestId'),
      mono: true,
      render: r => r.request_id ? <span className="break-all">{r.request_id}</span> : <span className="text-[color:var(--astra-text-muted)]">{t('common.unavailable')}</span>,
    },
    {
      key: 'timestamp',
      header: t('lineage.headerRecordedAt'),
      type: 'date',
      render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{typeof r.timestamp === 'string' ? r.timestamp : '—'}</span>,
    },
    {
      key: 'model_used',
      header: t('lineage.headerModelActual'),
      render: r => (typeof r.model_used === 'string' && r.model_used) || '—',
    },
    {
      key: 'region_evidence',
      header: t('lineage.headerEvidence'),
      render: r => (typeof r.region_evidence === 'string' && r.region_evidence) || t('lineage.notRecorded'),
    },
    {
      key: 'inference_region',
      header: t('lineage.headerRegionClaim'),
    },
  ]

  // AUX-22: saved views over the page's URL state. A view snapshot is the
  // hash query at save time; applying restores the keys the page understands
  // (org, point-lookup prefill, table sort/page) through the same setters the
  // controls use — a missing key leaves that part of the state alone.
  const refreshViews = () => setViews(listSavedViews('lineage'))
  const saveView = (name: string) => {
    saveSavedView('lineage', name, currentHashQuery())
    refreshViews()
  }
  const renameView = (id: string, name: string) => {
    renameSavedView('lineage', id, name)
    refreshViews()
  }
  const deleteView = (id: string) => {
    deleteSavedView('lineage', id)
    refreshViews()
  }
  const applyView = (item: { id: string }) => {
    const view = views.find(v => v.id === item.id)
    if (!view) return
    const snapshot = parseViewQuery(view.query)
    const org = snapshot.get('org')
    if (org !== null && org !== orgInput) setOrgInput(org)
    const req = snapshot.get('req')
    if (req !== null && req !== requestId) setRequestId(req)
    const table = readTableUrlState(snapshot, 'lineage')
    setPage(table.page)
    setSort(table.sort)
  }

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={t('lineage.title')}
        purpose={t('lineage.purpose')}
      />

      {/* Org-scoped list (GET /api/organizations/{id}/lineage — root-only). */}
      <section className="flex flex-col gap-3" aria-labelledby="lineage-list-title">
        <h2 id="lineage-list-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('lineage.orgRecords')}</h2>
        {/* UX-03: the org records list auto-loads after a 300ms debounce on the
            org input (the single-record lookup below stays an explicit form —
            a lookup is a deliberate query, not a scope). */}
        <form
          className="card flex flex-wrap items-end gap-3"
          onSubmit={e => { e.preventDefault() }}
        >
          <label className="flex flex-1 flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('lineage.organizationId')}</span>
            {/* UI-VF-1: shared OrgSelect picker (dropdown + manual escape
                hatch) instead of a hand-copied UUID; autoSelect pre-commits
                the last-used or first org so the list loads on arrival. */}
            <OrgSelect
              value={orgInput}
              onChange={v => { setOrgInput(v); setListLoaded(false) }}
              autoSelect
              className="w-full max-w-md"
              manualAriaLabel={t('lineage.orgUuid')}
            />
          </label>
        </form>

        {!listLoaded && !listLoading && (
          <StateNotice state="not-loaded" message={t('lineage.notLoaded')} />
        )}
        {listLoaded && !listLoading && !listError && rows.length === 0 && (
          <StateNotice state="empty" message={t('lineage.emptyOrg', { org: orgScope })} action={{ label: t('lineage.loadAgain') }} />
        )}
        {rows.length > 0 && (
          <>
            {/* AUX-22: saved views + table personalization for this table. */}
            <div className="flex flex-wrap items-center justify-end gap-2">
              <SavedViewsMenu
                menuId="lineage-views-menu"
                views={views.map(v => ({ id: v.id, name: v.name }))}
                onApply={applyView}
                onSave={saveView}
                onRename={renameView}
                onDelete={deleteView}
              />
              <TableSettingsMenu
                columns={columns.map(c => ({ key: c.key, header: c.header }))}
                hiddenColumnIds={prefs.hiddenColumnIds}
                onHiddenChange={prefs.setHiddenColumnIds}
                density={prefs.density}
                onDensityChange={prefs.setDensity}
                onReset={prefs.reset}
              />
            </div>
            <DataTable
              columns={columns}
              rows={rows}
              getRowId={r => String(r.request_id ?? JSON.stringify(r).slice(0, 64))}
              page={page}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
              sort={sort}
              onSortChange={setSort}
              hiddenColumnIds={prefs.hiddenColumnIds}
              density={prefs.density}
              scopeNote={t('lineage.scopeNoteLimit', { limit: SERVER_LIMIT, org: orgScope })}
              caption={t('lineage.captionOrgRecords')}
              selectedId={selected?.request_id}
              renderActions={r => (
                <span className="flex flex-wrap gap-2">
                  <CopyIdButton value={String(r.request_id ?? '')} label="request" />
                  <button
                    type="button"
                    onClick={() => setSelected(r)}
                    className="inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]"
                  >
                    {t('common.inspector')}
                  </button>
                </span>
              )}
            />
          </>
        )}
      </section>
      {/* Point lookup by request ID. */}
      <section className="flex flex-col gap-3" aria-labelledby="lineage-lookup-title">
        <h2 id="lineage-lookup-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('lineage.lookupTitle')}</h2>
        <form onSubmit={handleLookup} className="card flex flex-wrap items-end gap-3">
          <label className="flex flex-1 flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('lineage.requestId')}</span>
            <input
              value={requestId}
              onChange={e => { lookupGen.current++; setRequestId(e.target.value); setRecord(null); setVerifyResult(null); setLookupLoading(false); setVerifying(false); setLookupError('') }}
              placeholder={t('lineage.requestIdPlaceholder')}
              className="w-full max-w-md rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-[color:var(--astra-ink)] placeholder:text-[color:var(--astra-text-muted)]"
              style={{ fontFamily: 'var(--astra-font-code)' }}
              required
            />
          </label>
          <button
            type="submit"
            disabled={lookupLoading || verifying || !requestId.trim()}
            className="btn-primary"
          >
            {lookupLoading ? t('lineage.lookingUp') : t('lineage.lookup')}
          </button>
          <button
            type="button"
            onClick={() => void handleVerify()}
            disabled={lookupLoading || verifying || !record?.request_id}
            className="btn-secondary"
          >
            {verifying ? t('lineage.verifying') : t('lineage.verifySignature')}
          </button>
        </form>

        {lookupError && <StateNotice state="error" message={lookupError} action={{ label: t('common.retry') }} />}
        {verifyResult && (
          <StateNotice
            state={verifyResult.valid ? 'partial' : 'error'}
            title={verifyResult.valid ? t('lineage.signatureVerified') : t('lineage.verificationFailed')}
            message={verifyResult.valid
              ? t('lineage.verifiedMessage')
              : t('lineage.untrustedMessage')}
          />
        )}

          <RequestInspector
            dialog
            record={selected ? toInspector(selected, t) : null}
            onClose={() => setSelected(null)}
          />
        {!selected && (record || lookupLoading) && (
          <RequestInspector
            loading={lookupLoading}
            record={record ? {
              id: typeof record.request_id === 'string' ? record.request_id : undefined,
              model: typeof record.model_used === 'string' ? record.model_used : (typeof record.model === 'string' ? record.model : undefined),
              regionClaim: typeof record.inference_region === 'string' ? record.inference_region : (typeof record.region === 'string' ? record.region : undefined),
              evidence: {
                tier: typeof record.region_evidence === 'string' && record.region_evidence ? record.region_evidence : 'provider_declared',
                explanation: evidenceText(record.region_evidence, t),
              },
              raw: record,
            } : null}
            verify={{
              status: verifyResult ? (verifyResult.valid ? 'valid' : 'invalid') : 'unverified',
              onVerify: () => void handleVerify(),
              verifying,
            }}
          />
        )        }
      </section>
    </div>
  )
}
