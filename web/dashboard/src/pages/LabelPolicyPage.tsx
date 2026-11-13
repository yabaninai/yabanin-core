import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  fetchLabelPolicy, saveLabelPolicy, resetLabelPolicy, testLabelPolicy,
  type LabelPolicy, type LabelPolicyTestResult,
} from '../api/client'
import { PageHeader } from '../components/astra/PageHeader'
import { OrgSelect } from '../components/OrgSelect'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'

const emptyPolicy = (): LabelPolicy => ({
  allowed_keys: [], denied_keys: [], required_keys: [],
  on_invalid: 'drop', on_missing: 'allow', aliases: {}, derive: [],
  rollup_keys: [], max_labels: 32, value_max_len: 128,
})

export function LabelPolicyPage() {
  const { t } = useTranslation()
  const [org, setOrg] = useState('')
  const [policy, setPolicy] = useState<LabelPolicy>(emptyPolicy())
  // The on_missing value as last loaded from the server: the "was" side of
  // the medium-risk save dialog must show the committed state, not the draft.
  const [savedOnMissing, setSavedOnMissing] = useState<LabelPolicy['on_missing']>('allow')
  const [isDefault, setIsDefault] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [failed, setFailed] = useState(false)
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [headerSample, setHeaderSample] = useState('')
  const [testResult, setTestResult] = useState<LabelPolicyTestResult | null>(null)

  useEffect(() => {
    if (!org.trim()) return
    let live = true
    setLoaded(false)
    fetchLabelPolicy(org.trim())
      .then(res => {
        if (!live) return
        setPolicy(normalize(res.policy))
        setSavedOnMissing(normalize(res.policy).on_missing)
        setIsDefault(res.is_default)
        setFailed(false)
      })
      .catch(() => { if (live) setFailed(true) })
      .finally(() => { if (live) setLoaded(true) })
    return () => { live = false }
  }, [org])

  // ActionDialog contract: saving with on_missing=reject is medium risk —
  // the dialog shows was -> becomes and consequences. Reset is high risk
  // (drops the whole policy) with a name confirmation. Both dialogs
  // collect an operator reason and send it as X-Audit-Reason (the journal
  // stores and shows it).
  const saveAction = useAction({
    id: 'label-policy.save', risk: 'medium', reversible: true,
    impact: t('labelPolicy.confirmReject'),
  })
  const resetAction = useAction({
    id: 'label-policy.reset', risk: 'high', reversible: false,
    impact: t('labelPolicy.confirmReset'),
  })

  const applySave = async (reason: string) => {
    const res = await saveLabelPolicy(org.trim(), policy, auditReasonOpts(reason))
    setPolicy(normalize(res.policy))
    setIsDefault(false)
    setNotice(t('labelPolicy.saved'))
  }

  const save = () => {
    if (!org.trim() || busy) return
    setNotice('')
    if (policy.on_missing === 'reject') {
      // Medium risk: the dialog owns progress/errors; the page busy flag
      // stays untouched so a cancelled dialog cannot wedge the Save button.
      saveAction.run({
        confirmLabel: t('labelPolicy.save'),
        was: savedOnMissing === 'warn' ? t('labelPolicy.warn') : savedOnMissing === 'reject' ? t('labelPolicy.rejectMissing') : t('labelPolicy.allow'),
        becomes: t('labelPolicy.rejectMissing'),
        reason: {},
        execute: ({ reason }) => applySave(reason),
      })
      return
    }
    setBusy(true)
    applySave('')
      .catch(err => setNotice(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(false))
  }

  const reset = () => {
    if (!org.trim()) return
    setNotice('')
    resetAction.run({
      entity: org.trim(),
      confirmLabel: t('labelPolicy.reset'),
      reason: {},
      execute: async ({ reason }) => {
        const res = await resetLabelPolicy(org.trim(), auditReasonOpts(reason))
        setPolicy(normalize(res.policy))
        setIsDefault(true)
        setNotice(t('labelPolicy.resetDone'))
      },
    })
  }

  const runTest = () => {
    if (!org.trim()) return
    testLabelPolicy(org.trim(), {
      policy,
      headers: headerSample.trim() ? { 'X-Yabanin-Labels': headerSample.trim() } : {},
    })
      .then(setTestResult)
      .catch(err => setNotice(err instanceof Error ? err.message : String(err)))
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('labelPolicy.title')} purpose={t('labelPolicy.purpose')} />

      {/* ActionDialog surfaces (dialogs), fixed-position. */}
      {saveAction.ui}
      {resetAction.ui}
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-[color:var(--astra-text-muted)]">{t('explorer.organizationId')}</span>
        <OrgSelect value={org} onChange={setOrg} autoSelect />
      </label>
      {!org.trim() && <StateNotice state="not-loaded" message={t('labelPolicy.notLoaded')} />}
      {org.trim() && !loaded && <StateNotice state="loading" message={t('states.loading')} />}
      {loaded && failed && <StateNotice state="error" message={t('labelPolicy.loadFailed')} />}
      {loaded && !failed && org.trim() && (
        <div className="space-y-6">
          {isDefault && <StateNotice state="empty" message={t('labelPolicy.defaultPolicy')} />}
          {notice && <p role="status">{notice}</p>}
          <Chips label={t('labelPolicy.allowed')} hint={t('labelPolicy.patternHint')} values={policy.allowed_keys} onChange={v => setPolicy({ ...policy, allowed_keys: v })} />
          <Chips label={t('labelPolicy.denied')} hint={t('labelPolicy.patternHint')} values={policy.denied_keys} onChange={v => setPolicy({ ...policy, denied_keys: v })} />
          <Chips label={t('labelPolicy.required')} hint={t('labelPolicy.requiredHint')} values={policy.required_keys} onChange={v => setPolicy({ ...policy, required_keys: v })} />
          <label className="block">
            <span>{t('labelPolicy.onInvalid')}</span>
            <select className="mt-1 block" value={policy.on_invalid} onChange={e => setPolicy({ ...policy, on_invalid: e.target.value })}>
              <option value="drop">{t('labelPolicy.drop')}</option>
              <option value="reject">{t('labelPolicy.reject')}</option>
            </select>
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('labelPolicy.onInvalidHint')}</p>
          </label>
          <label className="block">
            <span>{t('labelPolicy.onMissing')}</span>
            <select className="mt-1 block" value={policy.on_missing} onChange={e => setPolicy({ ...policy, on_missing: e.target.value })}>
              <option value="allow">{t('labelPolicy.allow')}</option>
              <option value="warn">{t('labelPolicy.warn')}</option>
              <option value="reject">{t('labelPolicy.rejectMissing')}</option>
            </select>
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('labelPolicy.onMissingHint')}</p>
          </label>
          <AliasTable policy={policy} onChange={setPolicy} />
          <DeriveTable policy={policy} onChange={setPolicy} sample={headerSample} onSample={setHeaderSample} onTest={runTest} result={testResult} />
          <Chips label={t('labelPolicy.rollup')} hint={t('labelPolicy.rollupHint')} values={policy.rollup_keys} onChange={v => setPolicy({ ...policy, rollup_keys: v.slice(0, 40) })} />
          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={save} disabled={busy}>{busy ? t('states.loading') : t('labelPolicy.save')}</button>
            <button type="button" onClick={reset}>{t('labelPolicy.reset')}</button>
          </div>
        </div>
      )}
    </div>
  )
}

function normalize(p: LabelPolicy): LabelPolicy {
  return {
    ...emptyPolicy(),
    ...p,
    allowed_keys: p.allowed_keys ?? [],
    denied_keys: p.denied_keys ?? [],
    required_keys: p.required_keys ?? [],
    aliases: p.aliases ?? {},
    derive: p.derive ?? [],
    rollup_keys: p.rollup_keys ?? [],
  }
}

function Chips({ label, hint, values, onChange }: { label: string; hint: string; values: string[]; onChange: (v: string[]) => void }) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState('')
  return (
    <div>
      <h2 className="text-base font-semibold">{label}</h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{hint}</p>
      <ul className="mt-2 flex flex-wrap gap-2">
        {values.map(v => (
          <li key={v}>
            <button type="button" onClick={() => onChange(values.filter(x => x !== v))}>{v} {t('labelPolicy.remove')}</button>
          </li>
        ))}
      </ul>
      <div className="mt-2 flex gap-2">
        <input value={draft} onChange={e => setDraft(e.target.value)} aria-label={label} />
        <button type="button" onClick={() => { const next = draft.trim(); if (!next) return; onChange([...values, next]); setDraft('') }}>{t('labelPolicy.add')}</button>
      </div>
    </div>
  )
}

function AliasTable({ policy, onChange }: { policy: LabelPolicy; onChange: (p: LabelPolicy) => void }) {
  const { t } = useTranslation()
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [page, setPage] = useState(1)
  const rows = Object.entries(policy.aliases).map(([src, dst]) => ({ src, dst }))
  // DataTable v2, client mode. The edit-list keeps its insertion
  // order by default (no default sort); headers still sort on click.
  const columns: DataTableColumn<{ src: string; dst: string }>[] = [
    { key: 'src', header: t('labelPolicy.from'), type: 'text', mono: true, render: r => r.src },
    { key: 'dst', header: t('labelPolicy.to'), type: 'text', mono: true, render: r => r.dst },
  ]
  return (
    <div>
      <h2 className="text-base font-semibold">{t('labelPolicy.aliases')}</h2>
      {rows.length > 0 && (
        <div className="mt-2">
          <DataTable
            columns={columns}
            rows={rows}
            getRowId={r => r.src}
            page={page}
            pageSize={50}
            onPageChange={setPage}
            caption={t('labelPolicy.aliases')}
            renderActions={r => (
              <button type="button" onClick={() => {
                const aliases = { ...policy.aliases }
                delete aliases[r.src]
                onChange({ ...policy, aliases })
              }}>{t('labelPolicy.remove')}</button>
            )}
          />
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        <input aria-label={t('labelPolicy.from')} value={from} onChange={e => setFrom(e.target.value)} />
        <input aria-label={t('labelPolicy.to')} value={to} onChange={e => setTo(e.target.value)} />
        <button type="button" onClick={() => {
          if (!from.trim() || !to.trim()) return
          onChange({ ...policy, aliases: { ...policy.aliases, [from.trim()]: to.trim() } })
          setFrom(''); setTo('')
        }}>{t('labelPolicy.add')}</button>
      </div>
    </div>
  )
}

function DeriveTable({ policy, onChange, sample, onSample, onTest, result }: {
  policy: LabelPolicy
  onChange: (p: LabelPolicy) => void
  sample: string
  onSample: (v: string) => void
  onTest: () => void
  result: LabelPolicyTestResult | null
}) {
  const { t } = useTranslation()
  const [row, setRow] = useState({ from: '', regex: '', to: '', template: '' })
  const [page, setPage] = useState(1)
  // DataTable v2, client mode; insertion order by default.
  const columns: DataTableColumn<LabelPolicy['derive'][number] & { __idx: number }>[] = [
    { key: 'from', header: t('labelPolicy.from'), type: 'text', mono: true, render: d => d.from },
    { key: 'regex', header: t('labelPolicy.regex'), type: 'text', mono: true, render: d => d.regex },
    { key: 'to', header: t('labelPolicy.to'), type: 'text', mono: true, render: d => d.to },
    { key: 'template', header: t('labelPolicy.template'), type: 'text', mono: true, render: d => d.template },
  ]
  const rows = policy.derive.map((d, i) => ({ ...d, __idx: i }))
  return (
    <div>
      <h2 className="text-base font-semibold">{t('labelPolicy.derive')}</h2>
      {rows.length > 0 && (
        <div className="mt-2">
          <DataTable
            columns={columns}
            rows={rows}
            getRowId={r => `${r.from}-${r.__idx}`}
            page={page}
            pageSize={50}
            onPageChange={setPage}
            caption={t('labelPolicy.derive')}
            renderActions={r => (
              <button type="button" onClick={() => onChange({ ...policy, derive: policy.derive.filter((_, j) => j !== r.__idx) })}>{t('labelPolicy.remove')}</button>
            )}
          />
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        <input aria-label={t('labelPolicy.from')} value={row.from} onChange={e => setRow({ ...row, from: e.target.value })} />
        <input aria-label={t('labelPolicy.regex')} value={row.regex} onChange={e => setRow({ ...row, regex: e.target.value })} />
        <input aria-label={t('labelPolicy.to')} value={row.to} onChange={e => setRow({ ...row, to: e.target.value })} />
        <input aria-label={t('labelPolicy.template')} value={row.template} onChange={e => setRow({ ...row, template: e.target.value })} />
        <button type="button" onClick={() => {
          if (!row.from.trim() || !row.to.trim()) return
          onChange({ ...policy, derive: [...policy.derive, { from: row.from, regex: row.regex, to: row.to, template: row.template }] })
          setRow({ from: '', regex: '', to: '', template: '' })
        }}>{t('labelPolicy.add')}</button>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <input aria-label={t('labelPolicy.testSample')} value={sample} onChange={e => onSample(e.target.value)} />
        <button type="button" onClick={onTest}>{t('labelPolicy.test')}</button>
      </div>
      {result && (
        <p role="status">
          {t('labelPolicy.testResult', {
            rejected: String(result.rejected),
            missing: (result.missing ?? []).join(',') || t('labelPolicy.none'),
          })}
        </p>
      )}
    </div>
  )
}
