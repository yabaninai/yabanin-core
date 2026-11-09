// the REAL consumer chain — the dashboard's own API modules over the real
// transport (fetch stubbed at the module boundary, the dashboard-suite analog
// of the e2e installApiStubs pattern; e2e/** itself is shared-edit and
// untouched) — composed exactly the way ProviderKeysSection derives what it
// renders: registryLoadState → provider-scoped slice → testVerdict →
// crossCheckCatalog → badge/hint/copy keys, resolved against every locale.
//
// reason and fix are visible, and «model absent from the provider / became
// unavailable» goes through the same boundary. Public-core only: every import
// lives under web/dashboard/src — no proprietary modules, no entitlement.

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  catalogStateFromError, catalogStateFromResult, crossCheckCatalog,
  registryLoadState, testStateFromError, testStateFromResult, withCheckedAt,
  type CredentialCatalogState, type CredentialTestState,
} from './providerKeysHelpers.ts'
import type { CatalogModelRow } from './providerKeysHelpers.ts'
import { listAllModels, type ModelEntry } from '../../api/models.ts'
import {
  listProviderCredentialModels, listProviderCredentials, testProviderCredential,
  type ProviderCredential,
} from '../../api/providerCredentials.ts'
import { ApiError, resetCsrf } from '../../api/transport.ts'

// ---------------------------------------------------------------------------
// The stub: one fetch boundary serving wire shapes per (method, url prefix).
// ---------------------------------------------------------------------------

interface RecordedCall { url: string, method: string, csrf: string | null }

interface Stub {
  calls: RecordedCall[]
  restore: () => void
}

function installFetchStubs(
  routes: Array<{
    match: (url: string, method: string) => boolean
    respond: (url: string) => { status: number, body?: unknown } | Promise<{ status: number, body?: unknown }>
  }>,
): Stub {
  const calls: RecordedCall[] = []
  const real = globalThis.fetch
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url)
    const method = init?.method ?? 'GET'
    const csrf = init?.headers instanceof Headers ? init.headers.get('X-CSRF-Token') : null
    calls.push({ url: href, method, csrf })
    const route = routes.find(r => r.match(href, method))
    if (!route) throw new Error(`stub: no route for ${method} ${href}`)
    const { status, body } = await route.respond(href)
    return new Response(body === undefined ? undefined : JSON.stringify(body), { status })
  }) as typeof fetch
  return {
    calls,
    restore: () => { globalThis.fetch = real },
  }
}

const json = (body: unknown) => ({ status: 200, body })

// Shared synthetic fixtures (no real provider data): one credential, a
// three-row registry slice, a two-id snapshot.
const REGISTRY_ROWS: ModelEntry[] = [
  { model_name: 'glm-x', display_name: 'GLM X', tier: 'medium', enabled: true, provider: 'openai-compat' },
  { model_name: 'qwen-x', display_name: 'Qwen X', tier: 'easy', enabled: false, provider: 'openai-compat' },
  { model_name: 'gone-x', display_name: 'Gone X', tier: 'easy', enabled: true, provider: 'openai-compat' },
]

function registryRoute() {
  return {
    match: (url: string, method: string) => method === 'GET' && url.startsWith('/api/models?'),
    respond: () => json({
      data: REGISTRY_ROWS,
      pagination: { page: 1, page_size: 100, total: REGISTRY_ROWS.length, total_pages: 1 },
    }),
  }
}

const CRED: ProviderCredential = {
  id: 'c1', org_id: 'acme', name: 'prod-compat', provider: 'openai-compat',
  base_url: 'https://api.example-llm.dev/v1', key_last4: '1234', enabled: true,
  key_version: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}

function credsRoute() {
  return {
    match: (url: string, method: string) =>
      method === 'GET' && url.startsWith('/api/orgs/acme/provider-credentials') && !url.includes('/test') && !url.includes('/models'),
    respond: () => json([CRED]),
  }
}

const csrfRoute = {
  match: (url: string, method: string) => url.startsWith('/auth/csrf') && method === 'GET',
  respond: () => json({ csrf_token: 'stub-csrf-token' }),
}

// ---------------------------------------------------------------------------
// The panel derivation, mirrored from ProviderKeysSection.tsx (the exact
// calls and order the component makes per render) — the consumer entry point
// under test minus the JSX binding itself.
// ---------------------------------------------------------------------------

function registrySliceByProvider(rows: ModelEntry[] | null): Map<string, Map<string, boolean>> | null {
  if (rows === null) return null
  const byProvider = new Map<string, Map<string, boolean>>()
  for (const m of rows) {
    const key = m.provider ?? ''
    if (!key) continue
    let inner = byProvider.get(key)
    if (!inner) { inner = new Map<string, boolean>(); byProvider.set(key, inner) }
    inner.set(m.model_name, m.enabled)
  }
  return byProvider
}

function testVerdict(states: Record<string, CredentialTestState>): boolean | undefined {
  const s = states[CRED.id]
  if (!s || s.phase === 'running') return undefined
  return s.phase === 'ok'
}

function composePanel(o: {
  registryRows: ModelEntry[] | null
  registryError: string
  registryLoading: boolean
  testState?: CredentialTestState
  catalogState?: CredentialCatalogState
}): {
  rows: CatalogModelRow[]
  absent: CatalogModelRow[]
  loadKind: string
  copyKeys: string[]
} {
  const load = registryLoadState({
    hasData: o.registryRows != null,
    loading: o.registryLoading,
    error: o.registryError,
  })
  const slice = load.kind === 'ready' ? registrySliceByProvider(o.registryRows)?.get(CRED.provider) : undefined
  const registry = load.kind === 'ready' ? (slice ?? new Map<string, boolean>()) : null
  const check = crossCheckCatalog({
    snapshot: o.catalogState?.models,
    testOk: testVerdict(o.testState ? { [CRED.id]: o.testState } : {}),
    registry,
  })
  const copyKeys: string[] = []
  if (load.kind === 'outage') copyKeys.push('registryOutage')
  if (load.kind === 'loading') copyKeys.push('registryLoading')
  for (const row of [...check.snapshotRows, ...check.absentRows]) {
    if (row.state === null) { copyKeys.push(load.kind === 'loading' ? 'stateSuspendedLoading' : 'stateSuspended'); continue }
    copyKeys.push('state' + row.state.state[0].toUpperCase() + row.state.state.slice(1))
    if (row.state.state === 'discovered') copyKeys.push('hintRegisterManual')
    if (row.state.state === 'unavailable' && row.state.reason) {
      copyKeys.push(
        row.state.reason === 'operator_disabled' ? 'reasonOperatorDisabled'
          : row.state.reason === 'check_failed' ? 'reasonCheckFailed'
            : row.state.reason === 'not_registered' ? 'reasonNotRegistered'
              : 'reasonAbsentFromSnapshot',
      )
    }
  }
  return { rows: check.snapshotRows, absent: check.absentRows, loadKind: load.kind, copyKeys }
}

function allLocaleProviderKeys(): Array<{ locale: string, keys: Record<string, unknown> }> {
  const i18nDir = fileURLToPath(new URL('../../i18n/', import.meta.url))
  return readdirSync(i18nDir).filter(f => f.endsWith('.json')).map(locale => ({
    locale,
    keys: (JSON.parse(readFileSync(`${i18nDir}${locale}`, 'utf8')) as {
      providerKeys?: Record<string, unknown>
    }).providerKeys ?? {},
  }))
}

// ---------------------------------------------------------------------------
// Scenarios — every probe below is a stubbed HTTP round trip through the
// real API module; nothing here touches e2e/** or a live stand.
// ---------------------------------------------------------------------------

let stub: Stub | null = null

beforeEach(() => { resetCsrf() })
afterEach(() => { stub?.restore(); stub = null })

test('integration: the happy surface — registry + creds + PASSED probe + snapshot compose D-1 states', async () => {
  stub = installFetchStubs([
    registryRoute(),
    credsRoute(),
    csrfRoute,
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/test'),
      respond: () => json({ ok: true, status: 200 }),
    },
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/models'),
      respond: () => json({
        provider: 'openai-compat', base_url: CRED.base_url, count: 2,
        data: ['glm-x', 'fresh-model'], discovered: true, verified: false,
      }),
    },
  ])

  // The reads, through the real modules (pagination walk included).
  const [registryRows, creds] = await Promise.all([listAllModels(), listProviderCredentials('acme')])
  assert.equal(creds.length, 1)
  assert.deepEqual(registryRows.map(m => [m.model_name, m.enabled]), [
    ['glm-x', true], ['qwen-x', false], ['gone-x', true],
  ])

  // The probes, through the real mutation transport (CSRF load included).
  const testState = withCheckedAt(
    testStateFromResult(await testProviderCredential('acme', CRED.id)), '2026-10-14T10:00:00.000Z',
  )
  const catalogState = withCheckedAt(
    catalogStateFromResult(await listProviderCredentialModels('acme', CRED.id)), '2026-10-14T10:01:00.000Z',
  )
  assert.deepEqual(testState, { phase: 'ok', status: 200, checkedAt: '2026-10-14T10:00:00.000Z' })
  assert.deepEqual(catalogState, { phase: 'ok', models: ['glm-x', 'fresh-model'], count: 2, checkedAt: '2026-10-14T10:01:00.000Z' })

  const panel = composePanel({
    registryRows, registryError: '', registryLoading: false, testState, catalogState,
  })
  // D-1 over the facts: registered+enabled+PASSED → verified; unknown id →
  // discovered (no test credit); disabled → operator_disabled; enabled but
  // absent from the list → absent_from_snapshot. Nothing reads working
  // without evidence.
  assert.deepEqual(panel.rows, [
    { model: 'glm-x', state: { state: 'verified' } },
    { model: 'fresh-model', state: { state: 'discovered' } },
  ])
  assert.deepEqual(panel.absent, [
    { model: 'qwen-x', state: { state: 'unavailable', reason: 'operator_disabled' } },
    { model: 'gone-x', state: { state: 'unavailable', reason: 'absent_from_snapshot' } },
  ])
  assert.equal(panel.loadKind, 'ready')

  // D-5 boundary: only the four ratified display states ever leave the
  // composition (agent-facing fallback semantics live in pkg/resolver, not
  // in this surface).
  for (const row of [...panel.rows, ...panel.absent]) {
    assert.ok(
      row.state === null || ['verified', 'configured', 'discovered', 'unavailable'].includes(row.state.state),
    )
  }

  // D-2/D-3: the probes stayed render-only — no registry mutation was sent.
  const mutations = stub.calls.filter(c => c.method !== 'GET')
  assert.deepEqual(
    mutations.map(c => `${c.method} ${c.url}`),
    [
      'POST /api/orgs/acme/provider-credentials/c1/test',
      'POST /api/orgs/acme/provider-credentials/c1/models',
    ],
    'exactly the probe POSTs — no PUT/POST against /api/models',
  )
  assert.ok(
    stub.calls.some(c => c.url.startsWith('/auth/csrf')),
    'the CSRF token load went through the real transport',
  )
  for (const m of mutations) {
    assert.equal(m.csrf, 'stub-csrf-token', `probe carries the CSRF header: ${m.url}`)
  }

  // D-6: every state and hint the surface would render exists, non-empty,
  // in every locale.
  for (const { locale, keys } of allLocaleProviderKeys()) {
    for (const key of [...panel.copyKeys, 'checkedAt', 'snapshotSectionTitle', 'absentSectionTitle', 'modelsHonestNote']) {
      const v = keys[key]
      assert.equal(typeof v, 'string', `${locale}: providerKeys.${key} must exist for the composed surface`)
      assert.ok((v as string).length > 0, `${locale}: providerKeys.${key} must be non-empty`)
    }
  }
})

test('integration: the probe budget 429 arrives through the real transport as an honest fail', async () => {
  stub = installFetchStubs([
    registryRoute(),
    credsRoute(),
    csrfRoute,
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/test'),
      respond: () => ({
        status: 429,
        body: { error: 'credential test rate limit exceeded (1 per minute per organization)' },
      }),
    },
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/models'),
      respond: () => ({
        status: 429,
        body: { error: 'credential test rate limit exceeded (1 per minute per organization)' },
      }),
    },
  ])

  await assert.rejects(
    testProviderCredential('acme', CRED.id),
    (err: unknown) => {
      assert.ok(err instanceof ApiError)
      assert.equal((err as ApiError).status, 429)
      assert.equal(
        (err as ApiError).message,
        'API error 429: credential test rate limit exceeded (1 per minute per organization)',
      )
      const state = testStateFromError(err)
      assert.equal(state.phase, 'fail')
      assert.match(state.error ?? '', /rate limit exceeded/)
      return true
    },
  )
  // Same boundary for the discovery probe: fail, no invented taxonomy reason.
  await assert.rejects(
    listProviderCredentialModels('acme', CRED.id),
    (err: unknown) => {
      const state = catalogStateFromError(err)
      assert.equal(state.phase, 'fail')
      assert.equal(state.reason, undefined, 'the throttle is never disguised as a catalog reason')
      assert.match(state.error ?? '', /429/)
      return true
    },
  )
})

test('integration: a registry outage through the real GET suspends the surface — states not missing', async () => {
  stub = installFetchStubs([
    {
      match: (url, method) => method === 'GET' && url.startsWith('/api/models?'),
      respond: () => ({ status: 503, body: { error: 'model registry unavailable' } }),
    },
    credsRoute(),
    csrfRoute,
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/models'),
      respond: () => json({
        provider: 'openai-compat', count: 1, data: ['glm-x'], discovered: true, verified: false,
      }),
    },
  ])

  const catalogState = catalogStateFromResult(await listProviderCredentialModels('acme', CRED.id))
  await assert.rejects(listAllModels(), (err: unknown) => {
    assert.ok(err instanceof ApiError)
    assert.equal((err as ApiError).status, 503)
    assert.match((err as ApiError).message, /model registry unavailable/)
    return true
  })

  // The component maps the failed read to load-state outage → suspension
  // with the OUTAGE copy (not the transient note, never «missing»).
  const panel = composePanel({
    registryRows: null, registryError: 'API error 503: model registry unavailable',
    registryLoading: false, catalogState,
  })
  assert.equal(panel.loadKind, 'outage')
  assert.deepEqual(panel.rows, [{ model: 'glm-x', state: null }])
  assert.deepEqual(panel.absent, [], 'no absence claims without the slice')
  assert.ok(panel.copyKeys.includes('registryOutage'))
  assert.ok(!panel.copyKeys.includes('registryLoading'), 'an outage must not render the transient note')
})

test('integration: a transient registry load keeps failure copy off the surface', async () => {
  // The response is withheld until the test releases it — the read genuinely
  // stays in flight (and is completed at the end so no timer lingers).
  let release: (r: { status: number, body: unknown }) => void = () => {}
  stub = installFetchStubs([
    {
      match: (url: string, method: string) => method === 'GET' && url.startsWith('/api/models?'),
      respond: () => new Promise(resolve => { release = resolve }),
    },
  ])
  let settled = false
  void listAllModels().then(
    () => { settled = true },
    () => { settled = true },
  )
  await new Promise(r => setTimeout(r, 10))
  assert.equal(settled, false, 'the read is still in flight')
  const panel = composePanel({
    registryRows: null, registryError: '', registryLoading: true,
    catalogState: catalogStateFromResult({ provider: 'openai-compat', count: 1, data: ['glm-x'], discovered: true }),
  })
  assert.equal(panel.loadKind, 'loading')
  assert.deepEqual(panel.rows, [{ model: 'glm-x', state: null }])
  assert.ok(panel.copyKeys.includes('registryLoading'))
  assert.ok(!panel.copyKeys.includes('registryOutage'), 'a transient load never earns failure copy')
  // The load completes → the same derivation flips to ready (recovery).
  release({ status: 200, body: { data: REGISTRY_ROWS, pagination: { page: 1, page_size: 100, total: REGISTRY_ROWS.length, total_pages: 1 } } })
  await new Promise(r => setTimeout(r, 10))
  assert.equal(settled, true, 'the load completes once the response arrives')
  stub.restore()
})

test('integration: a malformed discovery payload through the real POST never renders as a snapshot', async () => {
  stub = installFetchStubs([
    registryRoute(),
    credsRoute(),
    csrfRoute,
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/models'),
      respond: () => json({
        provider: 'openai-compat', count: 2, discovered: true, data: 'glm-x,fresh-model',
      }),
    },
  ])
  const state = catalogStateFromResult(await listProviderCredentialModels('acme', CRED.id))
  assert.equal(state.phase, 'fail')
  assert.match(state.error ?? '', /malformed catalog payload/)
  assert.equal(state.reason, undefined)
  // The panel renders the diagnosable error text (the default refusal copy
  // branch), and no row claims anything.
  const panel = composePanel({ registryRows: null, registryError: '', registryLoading: false, catalogState: state })
  assert.deepEqual(panel.rows, [])
  assert.deepEqual(panel.absent, [])
})

test('integration: the 5-reason refusal taxonomy arrives through the real POST and keeps its hint key', async () => {
  stub = installFetchStubs([
    registryRoute(),
    credsRoute(),
    csrfRoute,
    {
      match: (url, method) => method === 'POST' && url.startsWith('/api/orgs/acme/provider-credentials/c1/models'),
      respond: () => json({
        provider: 'openai-compat', count: 0, discovered: false, reason: 'key_unauthorized', status: 401,
      }),
    },
  ])
  const state = catalogStateFromResult(await listProviderCredentialModels('acme', CRED.id))
  assert.deepEqual(state, { phase: 'fail', reason: 'key_unauthorized', status: 401, error: undefined })
  // The reason passes through UNRENAMED to the render copy (reuse, not
  // redefinition): every locale carries the matching hint.
  for (const { locale, keys } of allLocaleProviderKeys()) {
    const hint = keys.reasonKeyUnauthorized
    assert.equal(typeof hint, 'string', `${locale}: reasonKeyUnauthorized must exist`)
    assert.ok((hint as string).length > 0)
  }
})
