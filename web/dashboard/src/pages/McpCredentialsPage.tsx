import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  beginMcpUserOAuth, deleteMcpGrant, deleteMcpServerCredential, deleteMcpUserCredential,
  getMcpServerCredential, listMcpGrants, listMcpServers, listMcpUserCredentials,
  putMcpServerCredential, submitMcpUserHeaders,
  type McpCredKind, type McpGrant, type McpServer, type McpServerCredential,
  type McpUserCredential, type McpUserCredStatus,
} from '../api/mcpCredentials.ts'
import { ApiError } from '../api/transport.ts'
import { OrgSelect } from '../components/OrgSelect'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'
import { useFocusTrap } from '../components/astra/useFocusTrap'
import { usePermissions } from '../hooks/usePermissions'
import { useHashParam } from '../hooks/useHashParam'
import { formatDateTime } from '../i18n/format'
import {
  buildHeadersPayload, buildOauthPayload, maskSecretLast4, statusLabelKey, statusTone,
  type HeaderPairDraft, type OauthDraft,
} from './mcpcreds/mcpCredsHelpers'

// MC-4 (MCP-CREDENTIALS-PLAN-2026-10-05): the «MCP credentials» screen —
// the lifecycle UI over the org's MCP server credentials, per-agent grants
// and per-user credential rows.
//
// Contract honesty (verified against the handlers before this screen was
//   - Server-level credentials + grants are real admin-plane surfaces
//     (router_mcp.go) — every action here works against the live backend.
//   - Per-user rows come from GET …/mcp/user-credentials, an MC-4 PROPOSAL:
//     the store method exists but the current backend does not mount the
//     route, so the client answers null and this screen says exactly that
//     (an explicit unavailable notice — never a fake empty table).
//   - The per-row flow actions (submit headers, begin oauth, revoke) target
//     the documented gateway surfaces; a deployment where the dashboard
//     origin cannot reach them shows the backend's error verbatim.
//
// Secret hygiene: value dialogs keep their drafts in local state ONLY while
// open; a submit serializes the values into one request body and the dialog
// unmounts (drafts gone). No module state, no storage, no logs. Reads are
// masked (has_secret + last4) — a response can never echo a secret back.

type T = ReturnType<typeof useTranslation>['t']

function errorOf(e: unknown): string {
  if (e instanceof ApiError) return e.message
  return e instanceof Error ? e.message : String(e)
}

function CredStatusChip({ status, t }: { status: McpUserCredStatus; t: T }) {
  const tone = statusTone(status)
  const color = tone === 'success' ? 'var(--astra-success)'
    : tone === 'warning' ? 'var(--astra-warning)'
    : tone === 'danger' ? 'var(--astra-danger)'
    : 'var(--astra-text-muted)'
  const glyph = tone === 'success' ? '●' : tone === 'muted' ? '○' : '△'
  return (
    <span className="inline-flex items-center gap-1 text-sm" style={{ color }}>
      <span aria-hidden="true">{glyph}</span>
      {t(statusLabelKey(status))}
    </span>
  )
}

function EnabledChip({ enabled, t }: { enabled: boolean; t: T }) {
  const color = enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)'
  return (
    <span className="inline-flex items-center gap-1 text-sm" style={{ color }}>
      <span aria-hidden="true">{enabled ? '●' : '○'}</span>
      {t(enabled ? 'mcpCreds.on' : 'mcpCreds.off')}
    </span>
  )
}

// -----
// The one-time values dialog: password inputs for every secret field, drafts
// live only while mounted, the payload leaves exactly once via onSubmit.
// -----

const EMPTY_OAUTH: OauthDraft = { clientId: '', clientSecret: '', authUrl: '', tokenUrl: '', scopes: '' }

function CredValuesDialog({
  heading, impact, kindLocked, busy, error, onSubmit, onCancel,
}: {
  heading: string
  impact: string
  /** true = the kind is fixed to headers (per-user flow); no switcher. */
  kindLocked: boolean
  busy: boolean
  error: string
  onSubmit: (kind: McpCredKind, payload: Record<string, string>) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const panelRef = useRef<HTMLDivElement | null>(null)
  useFocusTrap(panelRef, onCancel)
  const [kind, setKind] = useState<McpCredKind>('headers')
  const [pairs, setPairs] = useState<HeaderPairDraft[]>([{ name: '', value: '' }])
  const [oauth, setOauth] = useState<OauthDraft>(EMPTY_OAUTH)
  const [problem, setProblem] = useState('')

  const setPair = (idx: number, patch: Partial<HeaderPairDraft>) => {
    setPairs(prev => prev.map((p, i) => (i === idx ? { ...p, ...patch } : p)))
  }

  const submit = () => {
    if (kind === 'headers') {
      const result = buildHeadersPayload(pairs)
      if (!result.ok) {
        setProblem(t(`mcpCreds.problem.${result.problem}`))
        return
      }
      onSubmit('headers', result.payload)
      return
    }
    const result = buildOauthPayload(oauth)
    if (!result.ok) {
      setProblem(t(`mcpCreds.problem.${result.problem}`))
      return
    }
    onSubmit('oauth', result.payload)
  }

  const inputCls = 'control w-full'
  const labelCls = 'mb-1 block text-sm text-[color:var(--astra-text-muted)]'

  return (
    <div className="astra-overlay">
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={heading}
        className="card astra-dialog"
      >
        <h2 className="text-lg font-medium">{heading}</h2>
        <p className="mt-2 text-sm text-[color:var(--astra-text-muted)]">{impact}</p>

        {!kindLocked && (
          <fieldset className="mt-3">
            <legend className={labelCls}>{t('mcpCreds.kindLabel')}</legend>
            <div className="flex gap-4 text-sm">
              <label className="inline-flex items-center gap-1">
                <input type="radio" name="mcp-cred-kind" checked={kind === 'headers'} onChange={() => setKind('headers')} />
                {t('mcpCreds.kindHeaders')}
              </label>
              <label className="inline-flex items-center gap-1">
                <input type="radio" name="mcp-cred-kind" checked={kind === 'oauth'} onChange={() => setKind('oauth')} />
                {t('mcpCreds.kindOauth')}
              </label>
            </div>
          </fieldset>
        )}

        {kind === 'headers' ? (
          <div className="mt-3 flex flex-col gap-2">
            <span className={labelCls}>{t('mcpCreds.headersHint')}</span>
            {pairs.map((pair, idx) => (
              <div key={idx} className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
                <div>
                  <label className={labelCls} htmlFor={`mcp-hdr-name-${idx}`}>{t('mcpCreds.headerName')}</label>
                  <input
                    id={`mcp-hdr-name-${idx}`}
                    className={inputCls}
                    value={pair.name}
                    onChange={e => setPair(idx, { name: e.target.value })}
                    autoComplete="off"
                    spellCheck={false}
                  />
                </div>
                <div>
                  <label className={labelCls} htmlFor={`mcp-hdr-value-${idx}`}>{t('mcpCreds.headerValue')}</label>
                  <input
                    id={`mcp-hdr-value-${idx}`}
                    type="password"
                    className={inputCls}
                    value={pair.value}
                    onChange={e => setPair(idx, { value: e.target.value })}
                    autoComplete="new-password"
                    spellCheck={false}
                  />
                </div>
              </div>
            ))}
            <button type="button" className="btn-secondary w-fit" onClick={() => setPairs(prev => [...prev, { name: '', value: '' }])}>
              {t('mcpCreds.addHeader')}
            </button>
          </div>
        ) : (
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <label className={labelCls} htmlFor="mcp-oauth-client-id">{t('mcpCreds.oauthClientId')}</label>
              <input id="mcp-oauth-client-id" className={inputCls} value={oauth.clientId} onChange={e => setOauth({ ...oauth, clientId: e.target.value })} autoComplete="off" spellCheck={false} />
            </div>
            <div>
              <label className={labelCls} htmlFor="mcp-oauth-client-secret">{t('mcpCreds.oauthClientSecret')}</label>
              <input id="mcp-oauth-client-secret" type="password" className={inputCls} value={oauth.clientSecret} onChange={e => setOauth({ ...oauth, clientSecret: e.target.value })} autoComplete="new-password" spellCheck={false} />
            </div>
            <div>
              <label className={labelCls} htmlFor="mcp-oauth-auth-url">{t('mcpCreds.oauthAuthUrl')}</label>
              <input id="mcp-oauth-auth-url" className={inputCls} value={oauth.authUrl} onChange={e => setOauth({ ...oauth, authUrl: e.target.value })} autoComplete="off" spellCheck={false} placeholder="https://…" />
            </div>
            <div>
              <label className={labelCls} htmlFor="mcp-oauth-token-url">{t('mcpCreds.oauthTokenUrl')}</label>
              <input id="mcp-oauth-token-url" className={inputCls} value={oauth.tokenUrl} onChange={e => setOauth({ ...oauth, tokenUrl: e.target.value })} autoComplete="off" spellCheck={false} placeholder="https://…" />
            </div>
            <div className="sm:col-span-2">
              <label className={labelCls} htmlFor="mcp-oauth-scopes">{t('mcpCreds.oauthScopes')}</label>
              <input id="mcp-oauth-scopes" className={inputCls} value={oauth.scopes} onChange={e => setOauth({ ...oauth, scopes: e.target.value })} autoComplete="off" spellCheck={false} />
            </div>
          </div>
        )}

        {(problem || error) && (
          <p role="alert" className="mt-3 text-sm" style={{ color: 'var(--astra-danger)' }}>
            {t('actions.errorLabel')}: {problem || error}
          </p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onCancel} disabled={busy}>{t('common.cancel')}</button>
          <button type="button" className="btn-primary" onClick={submit} disabled={busy}>{t('mcpCreds.submitOnce')}</button>
        </div>
      </div>
    </div>
  )
}

interface BeginInfo {
  server: string
  url: string
  redirect: string
}

/** Server-level connect/rotate dialog wrapper — keeps the rotate/connect
 * heading choice on a plain identifier so the i18n keys gate can verify both
 * branches statically. */
function ServerCredDialog({
  server, cred, busy, error, onSubmit, onCancel,
}: {
  server: McpServer
  cred: McpServerCredential | null
  busy: boolean
  error: string
  onSubmit: (kind: McpCredKind, payload: Record<string, string>) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const rotating = cred !== null
  return (
    <CredValuesDialog
      heading={t(rotating ? 'mcpCreds.rotateTitle' : 'mcpCreds.connectTitle', { name: server.name })}
      impact={t('mcpCreds.valuesImpact')}
      kindLocked={false}
      busy={busy}
      error={error}
      onSubmit={onSubmit}
      onCancel={onCancel}
    />
  )
}

export function McpCredentialsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const perms = usePermissions(orgId.trim() || undefined)
  const isRoot = perms.isRoot

  const [servers, setServers] = useState<McpServer[] | null>(null)
  const [creds, setCreds] = useState<Record<string, McpServerCredential | null>>({})
  const [grants, setGrants] = useState<Record<string, McpGrant[]>>({})
  const [userCreds, setUserCreds] = useState<McpUserCredential[] | null>(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(false)

  const [credDialog, setCredDialog] = useState<{ server: McpServer } | null>(null)
  const [userDialog, setUserDialog] = useState<{ row: McpUserCredential } | null>(null)
  const [credBusy, setCredBusy] = useState(false)
  const [credError, setCredError] = useState('')
  const [begin, setBegin] = useState<BeginInfo | null>(null)

  // Org-scope epoch (TP-06): a delayed response can never land in another org.
  const orgEpoch = useRef(0)
  const orgRef = useRef('')
  useEffect(() => {
    orgEpoch.current++
    orgRef.current = orgId
  }, [orgId])
  const abortRef = useRef<AbortController | null>(null)

  const org = orgId.trim()

  const load = useCallback(async () => {
    const seenOrg = orgRef.current
    if (!seenOrg) return
    // Fail-closed: every surface here is root-only server-side (router_mcp.go).
    if (perms.loading || !perms.isRoot) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const opts = { signal: ctrl.signal }
    setLoading(true)
    try {
      const serverRows = await listMcpServers(seenOrg, opts)
      const [credEntries, grantEntries, userRows] = await Promise.all([
        Promise.all(serverRows.map(async s => [s.name, await getMcpServerCredential(seenOrg, s.name, opts)] as const)),
        Promise.all(serverRows.map(async s => [s.name, await listMcpGrants(seenOrg, s.name, opts)] as const)),
        listMcpUserCredentials(seenOrg, opts).catch(() => null),
      ])
      if (orgRef.current !== seenOrg || ctrl.signal.aborted) return
      setServers(serverRows)
      setCreds(Object.fromEntries(credEntries))
      setGrants(Object.fromEntries(grantEntries))
      setUserCreds(userRows)
      setLoadError('')
    } catch (e: unknown) {
      if (ctrl.signal.aborted || orgRef.current !== seenOrg) return
      setServers(null)
      setLoadError(errorOf(e))
    } finally {
      if (!ctrl.signal.aborted && orgRef.current === seenOrg) setLoading(false)
    }
  }, [perms.loading, perms.isRoot])

  useEffect(() => {
    if (!org) return
    const timer = setTimeout(() => { void load() }, 300)
    return () => { clearTimeout(timer); abortRef.current?.abort() }
  }, [load, org])

  // ----- server-level credential actions (real admin surfaces) -----

  const openConnect = useCallback((server: McpServer) => {
    setCredError('')
    setCredDialog({ server })
  }, [])

  const submitCred = useCallback(async (kind: McpCredKind, payload: Record<string, string>) => {
    if (!credDialog) return
    const server = credDialog.server
    setCredBusy(true)
    setCredError('')
    try {
      const cred = await putMcpServerCredential(org, server.name, { kind, secret: payload })
      setCreds(prev => ({ ...prev, [server.name]: cred }))
      setCredDialog(null) // unmount clears the drafts — the values are gone
    } catch (e: unknown) {
      setCredError(errorOf(e))
    } finally {
      setCredBusy(false)
    }
  }, [credDialog, org])

  const deleteCredAction = useAction({ id: 'mcpCreds.serverCred.delete', risk: 'high', reversible: false })
  const confirmDeleteCred = useCallback((server: McpServer) => {
    deleteCredAction.run({
      entity: server.name,
      confirmLabel: t('mcpCreds.deleteCredConfirm', { name: server.name }),
      impact: <span>{t('mcpCreds.deleteCredImpact')}</span>,
      execute: async () => {
        await deleteMcpServerCredential(org, server.name)
        setCreds(prev => ({ ...prev, [server.name]: null }))
      },
      onDone: () => void load(),
    })
  }, [deleteCredAction, load, org, t])

  // ----- grant actions (real admin surfaces; revoke → server-side orphaning) -----

  const revokeGrantAction = useAction({ id: 'mcpCreds.grant.revoke', risk: 'high', reversible: false })
  const confirmRevokeGrant = useCallback((server: McpServer, grant: McpGrant) => {
    revokeGrantAction.run({
      entity: grant.agent_id,
      confirmLabel: t('mcpCreds.revokeGrantConfirm', { agent: grant.agent_id, name: server.name }),
      impact: <span>{t('mcpCreds.revokeGrantImpact')}</span>,
      reason: {},
      execute: async ({ reason }) => {
        await deleteMcpGrant(org, server.name, grant.agent_id, auditReasonOpts(reason))
        setGrants(prev => ({
          ...prev,
          [server.name]: (prev[server.name] ?? []).filter(g => g.id !== grant.id),
        }))
      },
      onDone: () => void load(),
    })
  }, [org, revokeGrantAction, load, t])

  // ----- per-user row actions (documented gateway surfaces; errors stay honest) -----

  const submitUserHeaders = useCallback(async (row: McpUserCredential, payload: Record<string, string>) => {
    setCredBusy(true)
    setCredError('')
    try {
      await submitMcpUserHeaders(org, row.server_name, payload)
      setUserDialog(null)
      await load()
    } catch (e: unknown) {
      setCredError(errorOf(e))
    } finally {
      setCredBusy(false)
    }
  }, [load, org])

  const startUserOAuth = useCallback(async (row: McpUserCredential) => {
    setCredBusy(true)
    setCredError('')
    try {
      const result = await beginMcpUserOAuth(org, row.server_name)
      setBegin({ server: row.server_name, url: result.url, redirect: result.redirect })
    } catch (e: unknown) {
      setCredError(errorOf(e))
    } finally {
      setCredBusy(false)
    }
  }, [org])

  const revokeUserCredAction = useAction({ id: 'mcpCreds.userCred.revoke', risk: 'high', reversible: false })
  const confirmRevokeUserCred = useCallback((row: McpUserCredential) => {
    const entity = `${row.server_name}/${row.agent_key_id}`
    revokeUserCredAction.run({
      entity,
      confirmLabel: t('mcpCreds.revokeUserConfirm', { entity }),
      impact: <span>{t('mcpCreds.revokeUserImpact')}</span>,
      execute: async () => {
        await deleteMcpUserCredential(org, row.server_name, row.agent_key_id)
      },
      onDone: () => void load(),
    })
  }, [org, revokeUserCredAction, load, t])

  // ----- tables -----

  const serverRows = useMemo(() => (servers ?? []).map(server => ({ server, cred: creds[server.name] ?? null })), [servers, creds])

  const serverColumns: DataTableColumn<{ server: McpServer; cred: McpServerCredential | null }>[] = [
    {
      key: 'name', header: t('mcpCreds.colServer'), type: 'text', getSortValue: r => r.server.name,
      render: r => (
        <span className="flex flex-col">
          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.server.name}</span>
          {r.server.display_name && r.server.display_name !== r.server.name && (
            <span className="text-xs text-[color:var(--astra-text-muted)]">{r.server.display_name}</span>
          )}
        </span>
      ),
    },
    { key: 'kind', header: t('mcpCreds.colKind'), type: 'text', getSortValue: r => r.cred?.kind ?? '', render: r => r.cred?.kind ?? '—' },
    {
      key: 'secret', header: t('mcpCreds.colSecret'), type: 'text', getSortValue: r => r.cred?.secret_last4 ?? '',
      render: r => (r.cred?.has_secret
        ? <span style={{ fontFamily: 'var(--astra-font-code)' }}>{maskSecretLast4(r.cred.secret_last4)}</span>
        : <span className="text-[color:var(--astra-text-muted)]">{t('mcpCreds.noSecret')}</span>),
    },
    {
      key: 'enabled', header: t('mcpCreds.colEnabled'), type: 'text', getSortValue: r => (r.cred?.enabled ? '1' : '0'),
      render: r => (r.cred ? <EnabledChip enabled={r.cred.enabled} t={t} /> : '—'),
    },
    {
      key: 'updated_at', header: t('mcpCreds.colUpdated'), type: 'text', getSortValue: r => r.cred?.updated_at ?? '',
      render: r => (r.cred
        ? <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(r.cred.updated_at)}</span>
        : '—'),
    },
  ]

  const grantRows = useMemo(() => (servers ?? []).flatMap(server => (grants[server.name] ?? []).map(grant => ({ server, grant }))), [servers, grants])

  const grantColumns: DataTableColumn<{ server: McpServer; grant: McpGrant }>[] = [
    { key: 'server', header: t('mcpCreds.colServer'), type: 'text', getSortValue: r => r.server.name, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.server.name}</span> },
    { key: 'agent', header: t('mcpCreds.colAgent'), type: 'text', getSortValue: r => r.grant.agent_id, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.grant.agent_id}</span> },
    { key: 'enabled', header: t('mcpCreds.colEnabled'), type: 'text', getSortValue: r => (r.grant.enabled ? '1' : '0'), render: r => <EnabledChip enabled={r.grant.enabled} t={t} /> },
    { key: 'tools', header: t('mcpCreds.colTools'), type: 'number', align: 'right', getSortValue: r => r.grant.allowed_tools.length, render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.grant.allowed_tools.length}</span> },
    { key: 'updated', header: t('mcpCreds.colUpdated'), type: 'text', getSortValue: r => r.grant.updated_at, render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(r.grant.updated_at)}</span> },
  ]

  const userColumns: DataTableColumn<McpUserCredential>[] = [
    { key: 'server', header: t('mcpCreds.colServer'), type: 'text', getSortValue: r => r.server_name, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.server_name}</span> },
    { key: 'agent', header: t('mcpCreds.colAgent'), type: 'text', getSortValue: r => r.agent_key_id, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.agent_key_id}</span> },
    { key: 'status', header: t('mcpCreds.colStatus'), type: 'text', getSortValue: r => r.status, render: r => <CredStatusChip status={r.status} t={t} /> },
    { key: 'kind', header: t('mcpCreds.colKind'), type: 'text', getSortValue: r => r.kind },
    {
      key: 'secret', header: t('mcpCreds.colSecret'), type: 'text', getSortValue: r => r.secret_last4,
      render: r => (r.has_secret
        ? <span style={{ fontFamily: 'var(--astra-font-code)' }}>{maskSecretLast4(r.secret_last4)}</span>
        : <span className="text-[color:var(--astra-text-muted)]">{t('mcpCreds.noSecret')}</span>),
    },
    { key: 'updated', header: t('mcpCreds.colUpdated'), type: 'text', getSortValue: r => r.updated_at, render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(r.updated_at)}</span> },
  ]

  const rowBtnCls = 'btn-secondary text-xs'

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('mcpCreds.title')}
        purpose={t('mcpCreds.purpose')}
        appliedScope={org || undefined}
      />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('mcpCreds.orgId')}</span>
          <OrgSelect
            value={orgId}
            onChange={setOrgId}
            autoSelect
            className="sm:w-72"
            manualAriaLabel={t('mcpCreds.orgUuid')}
          />
        </label>
      </div>

      {!org && <StateNotice state="not-loaded" message={t('mcpCreds.notLoaded')} />}
      {org && perms.loading && <StateNotice state="loading" message={t('mcpCreds.checkingRights')} />}
      {org && !perms.loading && !isRoot && <StateNotice state="empty" message={t('mcpCreds.noAccess')} />}

      {org && !perms.loading && isRoot && (
        <>
          {loadError ? (
            <StateNotice state="error" message={loadError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : (
            <>
              {/* ===== Server-level credentials ===== */}
              <section aria-labelledby="mcp-creds-servers-title" className="flex flex-col gap-3">
                <h2 id="mcp-creds-servers-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('mcpCreds.serversTitle')}</h2>
                <p className="text-sm text-[color:var(--astra-text-muted)]">{t('mcpCreds.serversAbout')}</p>
                <DataTable
                  columns={serverColumns}
                  rows={serverRows}
                  getRowId={r => r.server.id || r.server.name}
                  loading={servers === null && loading}
                  empty={t('mcpCreds.serversEmpty')}
                  page={1}
                  pageSize={50}
                  onPageChange={() => {}}
                  caption={t('mcpCreds.serversCaption')}
                  renderActions={r => (
                    r.cred ? (
                      <span className="flex gap-2">
                        <button type="button" className={rowBtnCls} onClick={() => openConnect(r.server)}>{t('mcpCreds.rotate')}</button>
                        <button type="button" className={rowBtnCls} onClick={() => confirmDeleteCred(r.server)}>{t('common.delete')}</button>
                      </span>
                    ) : (
                      <button type="button" className="btn-primary text-xs" onClick={() => openConnect(r.server)}>{t('mcpCreds.connect')}</button>
                    )
                  )}
                />
              </section>

              {/* ===== Agent grants (revoking a grant orphans the agent's credentials) ===== */}
              <section aria-labelledby="mcp-creds-grants-title" className="flex flex-col gap-3">
                <h2 id="mcp-creds-grants-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('mcpCreds.grantsTitle')}</h2>
                <p className="text-sm text-[color:var(--astra-text-muted)]">{t('mcpCreds.grantsAbout')}</p>
                <DataTable
                  columns={grantColumns}
                  rows={grantRows}
                  getRowId={r => r.grant.id}
                  loading={servers === null && loading}
                  empty={t('mcpCreds.grantsEmpty')}
                  page={1}
                  pageSize={50}
                  onPageChange={() => {}}
                  caption={t('mcpCreds.grantsCaption')}
                  renderActions={r => (
                    <button type="button" className={rowBtnCls} onClick={() => confirmRevokeGrant(r.server, r.grant)}>{t('mcpCreds.revoke')}</button>
                  )}
                />
              </section>

              {/* ===== Per-user credential rows ===== */}
              <section aria-labelledby="mcp-creds-user-title" className="flex flex-col gap-3">
                <h2 id="mcp-creds-user-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('mcpCreds.userTitle')}</h2>
                <p className="text-sm text-[color:var(--astra-text-muted)]">{t('mcpCreds.userAbout')}</p>
                {userCreds === null ? (
                  <StateNotice
                    state="not-loaded"
                    message={t('mcpCreds.userUnavailable')}
                    details={t('mcpCreds.userUnavailableDetails')}
                  />
                ) : (
                  <DataTable
                    columns={userColumns}
                    rows={userCreds}
                    getRowId={r => r.id}
                    loading={loading && userCreds.length === 0}
                    empty={t('mcpCreds.userEmpty')}
                    page={1}
                    pageSize={50}
                    onPageChange={() => {}}
                    caption={t('mcpCreds.userCaption')}
                    renderActions={r => (
                      <span className="flex gap-2">
                        {r.kind === 'oauth' ? (
                          <button type="button" className={rowBtnCls} onClick={() => void startUserOAuth(r)}>
                            {t(r.status === 'needs_reauth' ? 'mcpCreds.reauth' : 'mcpCreds.beginOauth')}
                          </button>
                        ) : (
                          <button type="button" className={rowBtnCls} onClick={() => setUserDialog({ row: r })}>
                            {t(r.status === 'needs_reauth' ? 'mcpCreds.reauth' : 'mcpCreds.submitValues')}
                          </button>
                        )}
                        <button type="button" className={rowBtnCls} onClick={() => confirmRevokeUserCred(r)}>{t('mcpCreds.revoke')}</button>
                      </span>
                    )}
                  />
                )}
              </section>
            </>
          )}
        </>
      )}

      {credError && !credDialog && !userDialog && (
        <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }}>{credError}</p>
      )}

      {begin && (
        <div className="astra-panel flex flex-col gap-2 p-4" data-testid="mcp-oauth-begin">
          <p className="text-sm font-medium text-[color:var(--astra-ink)]">{t('mcpCreds.beginTitle', { name: begin.server })}</p>
          <a className="btn-primary w-fit" href={begin.url} target="_blank" rel="noreferrer">{t('mcpCreds.beginOpen')}</a>
          <p className="break-all text-xs text-[color:var(--astra-text-muted)]">
            {t('mcpCreds.beginRedirect')}: <span style={{ fontFamily: 'var(--astra-font-code)' }}>{begin.redirect}</span>
          </p>
          <p className="text-xs text-[color:var(--astra-text-muted)]">{t('mcpCreds.beginNote')}</p>
          <div className="flex gap-2">
            <button type="button" className={rowBtnCls} onClick={() => void load()}>{t('mcpCreds.beginRefresh')}</button>
            <button type="button" className={rowBtnCls} onClick={() => setBegin(null)}>{t('common.dismiss')}</button>
          </div>
        </div>
      )}

      {credDialog && (
        <ServerCredDialog
          server={credDialog.server}
          cred={creds[credDialog.server.name] ?? null}
          busy={credBusy}
          error={credError}
          onSubmit={(kind, payload) => { void submitCred(kind, payload) }}
          onCancel={() => setCredDialog(null)}
        />
      )}

      {userDialog && (
        <CredValuesDialog
          heading={t('mcpCreds.userValuesTitle', { name: userDialog.row.server_name, agent: userDialog.row.agent_key_id })}
          impact={t('mcpCreds.userValuesImpact')}
          kindLocked
          busy={credBusy}
          error={credError}
          onSubmit={(_kind, payload) => { void submitUserHeaders(userDialog.row, payload) }}
          onCancel={() => setUserDialog(null)}
        />
      )}

      {deleteCredAction.ui}
      {revokeGrantAction.ui}
      {revokeUserCredAction.ui}
    </div>
  )
}
