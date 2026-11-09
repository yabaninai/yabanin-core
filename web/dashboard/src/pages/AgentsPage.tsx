import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  GUIDED_AGENTS, agentCopyBlock, agentTestAuth, agentTestURL, getClientConfig, isGuidedAgent,
  type ClientConfigResult, type GuidedAgent,
} from '../api/clientConfig'
import { listAPIKeys } from '../api/keys'
import { CopyBlock } from '../components/CopyBlock'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useHashParam } from '../hooks/useHashParam'
import { gatewayKeysLink } from '../lib/onboarding'

// config → copy → test the first request.
//
// Contract facts this screen is built on (internal product contract;
//  - config generation is SERVER-SIDE (D2, owner ratified 2026-10-18):
//    GET /api/client-config/{agent} renders through pkg/clientconfig — the
//    console renders whatever the server says; format drift is impossible
//    by construction, and an unknown agent 404s instead of inventing a
//    config;
//  - the API key itself is never embedded (env names only) and never sent
//    to the admin API: the test-connection action calls the operator-entered
//    gateway URL directly from the browser with the operator-pasted key,
//    exactly the docs/clients «Check» curl;
//  - the console cannot know the deployment's gateway origin — the base URL
//    field starts EMPTY and no invented URL is ever shown as if it were
//    live (same honesty rule as the welcome flow's docs placeholders);
//  - negatives surface as actionable guidance: wrong env var (Claude Code
//    reads ANTHROPIC_AUTH_TOKEN, not ANTHROPIC_API_KEY), wrong URL (missing
//    /v1 or http/https), revoked key (401) and unreachable/CORS-blocked
//    gateways (the curl check in docs/clients remains the fallback); a
//    failed render (400 invalid input, 404 old backend, 5xx degraded)
//    renders the server's reason with a retry — never a made-up block.

type TestOutcome = 'ok' | 'auth' | 'not-found' | 'unreachable'

const TEST_TIMEOUT_MS = 10_000

export function AgentsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const org = orgId.trim()

  const [agent, setAgent] = useState<GuidedAgent>('claude-code')
  const [baseURL, setBaseURL] = useState('')
  const [model, setModel] = useState('')
  const [keyEnv, setKeyEnv] = useState('YABANIN_API_KEY')
  const [activeKeys, setActiveKeys] = useState<number | null>(null)
  const [testKey, setTestKey] = useState('')
  const [testing, setTesting] = useState(false)
  const [outcome, setOutcome] = useState<TestOutcome | null>(null)
  // Server-side render state (the generate step is a fetch, not a local
  // template): result, the honest pending flag, and the failure surface.
  const [genResult, setGenResult] = useState<ClientConfigResult | null>(null)
  const [genGenerating, setGenGenerating] = useState(false)
  const [genError, setGenError] = useState('')
  const gen = useRef(0)

  // Best-effort hint: how many ACTIVE gateway keys this org already has
  // (revoked-only does not count — same semantics as the welcome flow).
  // A 403 (no keys.manage) just hides the hint; the server arbitrates.
  useEffect(() => {
    setActiveKeys(null)
    if (!org) return
    let cancelled = false
    void (async () => {
      try {
        const res = await listAPIKeys(org, 1)
        if (!cancelled) setActiveKeys((res.data ?? []).filter(k => k.active === true).length)
      } catch {
        if (!cancelled) setActiveKeys(null)
      }
    })()
    return () => { cancelled = true }
  }, [org])

  const switchAgent = useCallback((id: string) => {
    if (isGuidedAgent(id)) setAgent(id)
    setOutcome(null)
  }, [])

  const urlValid = /^https?:\/\/.+/.test(baseURL.trim())

  // Generate = fetch the server render whenever the inputs are valid. The
  // generation guard (gen.current) keeps only the last request's answer;
  // failures surface verbatim (the 400 body names the offending param, a
  // 404/5xx gets the honest degraded notice with a retry).
  const genKey = `${agent}|${baseURL.trim()}|${keyEnv.trim()}|${model.trim()}`
  useEffect(() => {
    setGenResult(null)
    setGenError('')
    if (!urlValid) return
    const g = ++gen.current
    setGenGenerating(true)
    void (async () => {
      try {
        const result = await getClientConfig(agent, {
          baseURL: baseURL.trim(),
          keyEnv: keyEnv.trim() || undefined,
          model: model.trim() || undefined,
        })
        if (gen.current !== g) return
        setGenResult(result)
      } catch (err) {
        if (gen.current !== g) return
        const message = err instanceof Error && err.message ? err.message : ''
        setGenError(message || 'failed')
      } finally {
        if (gen.current === g) setGenGenerating(false)
      }
    })()
    // genKey carries the exact inputs; the guard ref is stable.
  }, [genKey, agent, urlValid, baseURL, keyEnv, model])

  const retryGenerate = useCallback(() => {
    setGenError('')
    const g = ++gen.current
    setGenGenerating(true)
    void (async () => {
      try {
        const result = await getClientConfig(agent, {
          baseURL: baseURL.trim(),
          keyEnv: keyEnv.trim() || undefined,
          model: model.trim() || undefined,
        })
        if (gen.current !== g) return
        setGenResult(result)
      } catch (err) {
        if (gen.current !== g) return
        const message = err instanceof Error && err.message ? err.message : ''
        setGenError(message || 'failed')
      } finally {
        if (gen.current === g) setGenGenerating(false)
      }
    })()
  }, [agent, baseURL, keyEnv, model])

  const runTest = useCallback(() => {
    if (!urlValid || !testKey.trim() || testing) return
    const g = ++gen.current
    setTesting(true)
    setOutcome(null)
    void (async () => {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), TEST_TIMEOUT_MS)
      try {
        const auth = agentTestAuth(agent)
        const headers: Record<string, string> = { ...auth.extra }
        if (auth.header === 'x-api-key') headers['x-api-key'] = testKey.trim()
        else headers.Authorization = `Bearer ${testKey.trim()}`
        const res = await fetch(agentTestURL(baseURL), { method: 'GET', headers, signal: controller.signal, mode: 'cors' })
        if (gen.current !== g) return
        if (res.ok) setOutcome('ok')
        else if (res.status === 401 || res.status === 403) setOutcome('auth')
        else if (res.status === 404) setOutcome('not-found')
        else setOutcome('auth')
      } catch {
        // Network failure, CORS block or abort — indistinguishable from the
        // browser; the honest outcome is "could not verify from here".
        if (gen.current !== g) return
        setOutcome('unreachable')
      } finally {
        clearTimeout(timer)
        if (gen.current === g) setTesting(false)
      }
    })()
  }, [agent, baseURL, testKey, testing, urlValid])

  const controlCls = 'min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2 text-[color:var(--astra-ink)]'

  const agentLabel = (id: GuidedAgent): string =>
    id === 'claude-code' ? t('agents.clientClaudeCode')
    : id === 'codex' ? t('agents.clientCodex')
    : id === 'opencode' ? t('agents.clientOpencode')
    : id === 'continue' ? t('agents.clientContinue')
    : id === 'cline' ? t('agents.clientCline')
    : t('agents.clientAider')

  return (
    <div className="space-y-6" data-testid="agents-flow">
      <PageHeader title={t('agents.title')} purpose={t('agents.purpose')} appliedScope={org || undefined} />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.orgId')}</span>
          <OrgSelect value={orgId} onChange={setOrgId} autoSelect className="sm:w-72" manualAriaLabel={t('orgSettings.orgUuid')} />
        </label>
        {activeKeys !== null && (
          <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="agents-active-keys">
            {t('agents.keysHint', { count: activeKeys })}{' '}
            <a href={gatewayKeysLink(org)} className="underline" data-testid="agents-open-keys">{t('agents.keysOpen')}</a>
          </p>
        )}
      </div>

      {/* Step 1 — select the agent (first wave: claude-code / codex / opencode). */}
      <section className="card space-y-3 p-4" data-testid="agents-step-select">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('agents.stepSelect')}</h2>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('agents.stepSelectDesc')}</p>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('agents.stepSelect')}>
          {GUIDED_AGENTS.map(id => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={agent === id}
              onClick={() => switchAgent(id)}
              data-testid={`agents-tab-${id}`}
              className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${
                agent === id
                  ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
                  : 'border-[color:var(--astra-rule-strong)] hover:bg-[color:var(--astra-surface-muted)]'
              }`}
            >
              {agentLabel(id)}
            </button>
          ))}
        </div>
      </section>

      {/* Step 2 — generate the scoped config from the entered gateway origin. */}
      <section className="card space-y-3 p-4" data-testid="agents-step-generate">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('agents.stepGenerate')}</h2>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('agents.stepGenerateDesc')}</p>
        <div className="grid gap-3 md:grid-cols-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('agents.baseUrlLabel')}</span>
            <input
              value={baseURL}
              onChange={e => { setBaseURL(e.target.value); setOutcome(null) }}
              placeholder={t('agents.baseUrlPlaceholder')}
              spellCheck={false}
              className={`sm:w-80 ${controlCls}`}
              style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="agents-base-url"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('agents.modelLabel')}</span>
            <input
              value={model}
              onChange={e => setModel(e.target.value)}
              placeholder={t('agents.modelPlaceholder')}
              spellCheck={false}
              className={`sm:w-48 ${controlCls}`}
              style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="agents-model"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('agents.keyEnvLabel')}</span>
            <input
              value={keyEnv}
              onChange={e => setKeyEnv(e.target.value)}
              spellCheck={false}
              className={`sm:w-48 ${controlCls}`}
              style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="agents-key-env"
            />
          </label>
        </div>
        {!urlValid && baseURL.trim() !== '' && (
          <StateNotice state="warning" message={t('agents.baseUrlInvalid')} />
        )}
        {urlValid && genGenerating && (
          <div data-testid="agents-generating">
            <StateNotice state="loading" message={t('states.loading')} />
          </div>
        )}
        {urlValid && !genGenerating && genError && (
          <StateNotice
            state="error"
            message={t('agents.generateFailed')}
            details={genError}
            action={{ label: t('common.retry'), onClick: retryGenerate }}
          />
        )}
        {urlValid && !genGenerating && !genError && genResult && (
          <>
            <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="agents-config-path">
              {t('agents.configPath', { path: genResult.path })}
            </p>
            <CopyBlock id={agent} text={agentCopyBlock(genResult)} copyLabel={t('agents.copyBlockAria', { client: agentLabel(agent) })} />
            {genResult.dropped_labels && genResult.dropped_labels.length > 0 && (
              <p className="text-xs" style={{ color: 'var(--astra-warning, var(--astra-danger))' }} data-testid="agents-dropped-labels">
                {t('agents.droppedLabels', { count: genResult.dropped_labels.length })}
              </p>
            )}
            <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="agents-key-note">
              {agent === 'claude-code' ? t('agents.keyNoteClaudeCode')
                : agent === 'codex' ? t('agents.keyNoteCodex')
                : agent === 'opencode' ? t('agents.keyNoteOpencode')
                : agent === 'continue' ? t('agents.keyNoteContinue')
                : agent === 'cline' ? t('agents.keyNoteCline')
                : t('agents.keyNoteAider')}
            </p>
          </>
        )}
        {urlValid && !genGenerating && !genError && !genResult && (
          <StateNotice state="not-loaded" message={t('agents.needBaseUrl')} />
        )}
      </section>

      {/* Step 3 — test the first request with a just-created key. */}
      <section className="card space-y-3 p-4" data-testid="agents-step-test">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('agents.stepTest')}</h2>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('agents.stepTestDesc')}</p>
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('agents.testKeyLabel')}</span>
            <input
              type="password"
              value={testKey}
              onChange={e => { setTestKey(e.target.value); setOutcome(null) }}
              placeholder="yb_…"
              autoComplete="off"
              spellCheck={false}
              className={`sm:w-80 ${controlCls}`}
              style={{ fontFamily: 'var(--astra-font-code)' }}
              data-testid="agents-test-key"
            />
          </label>
          <button
            type="button"
            onClick={runTest}
            disabled={!urlValid || !testKey.trim() || testing}
            className="btn-primary min-h-[44px]"
            data-testid="agents-test-run"
          >
            {testing ? t('agents.testing') : t('agents.testRun')}
          </button>
        </div>
        <p className="text-xs text-[color:var(--astra-text-muted)]">{t('agents.testKeyNote')}</p>

        {outcome === 'ok' && (
          <p className="flex items-center gap-2 text-sm font-medium" data-testid="agents-test-ok" style={{ color: 'var(--astra-success)' }}>
            <span aria-hidden="true">✓</span>
            {t('agents.testOk')}
          </p>
        )}
        {outcome === 'auth' && (
          <StateNotice
            state="error"
            message={t('agents.testAuth')}
            details={
              agent === 'claude-code' ? t('agents.keyNoteClaudeCode')
              : agent === 'codex' ? t('agents.keyNoteCodex')
              : agent === 'opencode' ? t('agents.keyNoteOpencode')
              : agent === 'continue' ? t('agents.keyNoteContinue')
              : agent === 'cline' ? t('agents.keyNoteCline')
              : t('agents.keyNoteAider')
            }
          />
        )}
        {outcome === 'not-found' && (
          <StateNotice state="warning" message={t('agents.testNotFound')} details={t('agents.testNotFoundHint')} />
        )}
        {outcome === 'unreachable' && (
          <StateNotice state="warning" message={t('agents.testUnreachable')} details={t('agents.testUnreachableHint')} />
        )}
      </section>
    </div>
  )
}
