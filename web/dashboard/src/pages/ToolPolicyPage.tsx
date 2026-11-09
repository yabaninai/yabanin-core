import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listToolPolicies, createToolPolicy, updateToolPolicy, deleteToolPolicy,
  listToolPolicyPresets, applyToolPolicyPreset,
  type ToolPolicy, type ToolPolicyPreset,
} from '../api/client'
import { PageHeader } from '../components/astra/PageHeader'
import { OrgSelect } from '../components/OrgSelect'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'

// TOOL-01/04: the per-org tool-call policy registry. Policies gate MCP/A2A
// invokes, the built-in server-side executors (yabanin:*) and the tool_calls
// the model declares in its response — an org with no rows allows all (the
// documented default). Presets apply starter policy sets the admin then
// edits; applying is idempotent per row name.
export function ToolPolicyPage() {
  const { t } = useTranslation()
  const [org, setOrg] = useState('')
  const [policies, setPolicies] = useState<ToolPolicy[]>([])
  const [presets, setPresets] = useState<ToolPolicyPreset[]>([])
  const [failed, setFailed] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [notice, setNotice] = useState('')
  const gen = useRef(0)

  const reload = (orgId: string) => {
    const g = ++gen.current
    Promise.all([listToolPolicies(orgId), listToolPolicyPresets(orgId)])
      .then(([rows, ps]) => {
        if (gen.current !== g) return
        setPolicies(rows); setPresets(ps); setFailed(false)
      })
      .catch(() => { if (gen.current !== g) { setFailed(true); setPolicies([]) } })
      .finally(() => { if (gen.current === g) setLoaded(true) })
  }

  useEffect(() => {
    if (!org.trim()) return
    const g = gen.current
    const timer = setTimeout(() => reload(org.trim()), 400)
    return () => { clearTimeout(timer); void g }
  }, [org])

  // ---- create form state
  const [name, setName] = useState('')
  const [subject, setSubject] = useState('*')
  const [tool, setTool] = useState('')
  const [action, setAction] = useState('deny')
  const [priority, setPriority] = useState(100)
  const [busy, setBusy] = useState(false)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!org.trim() || busy) return
    setBusy(true); setNotice('')
    createToolPolicy({
      org_id: org.trim(), name: name.trim(), subject: subject.trim() || '*',
      tool: tool.trim() || '*', action, priority, enabled: true,
    })
      .then(() => { setName(''); setTool(''); reload(org.trim()); setNotice(t('toolPolicy.created')) })
      .catch(err => setNotice(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(false))
  }

  const toggle = (p: ToolPolicy) => {
    updateToolPolicy(org.trim(), p.name, { enabled: !p.enabled })
      .then(() => reload(org.trim()))
      .catch(err => setNotice(err instanceof Error ? err.message : String(err)))
  }

  // AUX-12 (13th action point): policy deletion used to fire with no
  // confirmation at all. It is high risk and irreversible — dialog with
  // consequences and a name confirmation. Toggle stays a low-risk no-dialog
  // action (no inverse call exists today, so no undo toast yet).
  const removeAction = useAction({
    id: 'tool-policy.delete', risk: 'high', reversible: false,
    impact: t('toolPolicy.deleteConfirm'),
  })

  const remove = (p: ToolPolicy) => {
    setNotice('')
    removeAction.run({
      entity: p.name,
      confirmLabel: t('toolPolicy.delete'),
      reason: {},
      execute: async ({ reason }) => {
        await deleteToolPolicy(org.trim(), p.name, auditReasonOpts(reason))
      },
      onDone: () => reload(org.trim()),
      onError: (message) => setNotice(message),
    })
  }

  const applyPreset = (id: string) => {
    applyToolPolicyPreset(org.trim(), id)
      .then(res => { reload(org.trim()); setNotice(t('toolPolicy.presetApplied', { created: res.created, skipped: res.skipped_existing })) })
      .catch(err => setNotice(err instanceof Error ? err.message : String(err)))
  }

  const inputCls = 'min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-[color:var(--astra-ink)]'

  // AUX-03: DataTable v2, client mode. Priority sorts numerically, the
  // enabled flag by its boolean sort value; toggle/delete live in
  // renderActions (the AUX-12 delete dialog stays wired through `remove`).
  const [policiesPage, setPoliciesPage] = useState(1)
  const policyColumns: DataTableColumn<ToolPolicy>[] = [
    { key: 'name', header: t('toolPolicy.name'), type: 'text', mono: true, render: p => p.name },
    { key: 'subject', header: t('toolPolicy.subject'), type: 'text', mono: true, render: p => p.subject },
    { key: 'tool', header: t('toolPolicy.tool'), type: 'text', mono: true, render: p => p.tool },
    { key: 'action', header: t('toolPolicy.action'), type: 'text', render: p => p.action },
    { key: 'priority', header: t('toolPolicy.priority'), type: 'number', unit: 'count', render: p => p.priority },
    {
      key: 'enabled',
      header: t('toolPolicy.status'),
      type: 'number',
      getSortValue: p => (p.enabled ? 1 : 0),
      render: p => (p.enabled ? t('toolPolicy.enabled') : t('toolPolicy.disabled')),
    },
  ]

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t('toolPolicy.title')} purpose={t('toolPolicy.purpose')} />
      {/* AUX-12 action surface (dialog), fixed-position. */}
      {removeAction.ui}
      <form className="card flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault() }}>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('explorer.organizationId')}</span>
          {/* UI-VF-1: OrgSelect picker instead of a hand-copied UUID;
              autoSelect pre-commits the last-used or first org. */}
          <OrgSelect
            value={org}
            onChange={v => { setOrg(v); setLoaded(false) }}
            autoSelect
            className="w-64"
            manualAriaLabel={t('explorer.orgUuid')}
          />
        </label>
      </form>

      {!org.trim() && !loaded && <StateNotice state="not-loaded" message={t('toolPolicy.notLoaded')} />}
      {loaded && failed && <StateNotice state="error" message={t('toolPolicy.loadFailed')} />}
      {notice && <p role="status" className="card px-4 py-3 text-sm">{notice}</p>}

      {loaded && !failed && (
        <>
          <section className="card p-4">
            <h2 className="mb-3 text-base font-semibold">{t('toolPolicy.presetsTitle')}</h2>
            <div className="flex flex-wrap gap-3">
              {presets.map(p => (
                <button key={p.ID} type="button" onClick={() => applyPreset(p.ID)}
                  className={`${inputCls} min-w-[180px] text-sm`} title={p.Description}>
                  {p.ID}
                </button>
              ))}
            </div>
            <p className="mt-2 text-sm text-[color:var(--astra-text-muted)]">{t('toolPolicy.presetsHint')}</p>
          </section>

          <form className="card flex flex-wrap items-end gap-3" onSubmit={submit}>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('toolPolicy.name')}</span>
              <input value={name} onChange={e => setName(e.target.value)} required
                placeholder="deny-web" spellCheck={false} className={`w-40 ${inputCls}`}
                style={{ fontFamily: 'var(--astra-font-code)' }} />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('toolPolicy.subject')}</span>
              <input value={subject} onChange={e => setSubject(e.target.value)}
                placeholder={t('toolPolicy.subjectPlaceholder')} spellCheck={false} className={`w-36 ${inputCls}`}
                style={{ fontFamily: 'var(--astra-font-code)' }} />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('toolPolicy.tool')}</span>
              <input value={tool} onChange={e => setTool(e.target.value)}
                placeholder={t('toolPolicy.toolPlaceholder')} spellCheck={false} className={`w-40 ${inputCls}`}
                style={{ fontFamily: 'var(--astra-font-code)' }} />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('toolPolicy.action')}</span>
              <select value={action} onChange={e => setAction(e.target.value)} className={`w-28 ${inputCls}`}>
                <option value="deny">deny</option>
                <option value="allow">allow</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('toolPolicy.priority')}</span>
              <input type="number" min={0} max={1000} value={priority}
                onChange={e => setPriority(Number(e.target.value))} className={`w-24 ${inputCls}`} />
            </label>
            <button type="submit" disabled={busy}
              className={`${inputCls} min-w-[120px] bg-[color:var(--astra-accent)] px-4 text-sm font-semibold text-white disabled:opacity-50`}>
              {busy ? '…' : t('toolPolicy.create')}
            </button>
          </form>

          {policies.length === 0 ? (
            <StateNotice state="empty" message={t('toolPolicy.empty')} />
          ) : (
            <div className="card overflow-x-auto">
              <DataTable
                columns={policyColumns}
                rows={policies}
                getRowId={p => p.id}
                page={policiesPage}
                pageSize={50}
                onPageChange={setPoliciesPage}
                caption={t('toolPolicy.title')}
                renderActions={p => (
                  <span className="flex justify-end gap-2">
                    <button type="button" onClick={() => toggle(p)} className="mr-2 text-sm underline">
                      {p.enabled ? t('toolPolicy.disable') : t('toolPolicy.enable')}
                    </button>
                    <button type="button" onClick={() => remove(p)} className="text-sm underline">
                      {t('toolPolicy.delete')}
                    </button>
                  </span>
                )}
              />
            </div>
          )}
        </>
      )}
    </div>
  )
}
