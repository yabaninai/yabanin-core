// Pure helpers for the Provider keys settings
// section. Kept side-effect free so the contract logic (mask, PATCH diffing,
// test-result shaping) is unit-testable without a DOM — the section renders,
// these decide.
//
// Provider options mirror the server's adapter registry
// (pkg/provider/factory.go New(): "" / openai / openai-compat / anthropic /
// sovereign PB4.2-PB4.3 / local PB3.5 / zai-coding). They are adapter keys —
// data tokens, not UI copy — so they are not translated.

import type { CreateProviderCredentialInput, ProviderCredentialTestResult, ProviderModelCatalog, UpdateProviderCredentialInput } from '../../api/providerCredentials'
// The .ts extension is required here: node --test loads this module directly.
import { modelDisplayState, type ModelState } from '../models/helpers.ts'

export const PROVIDER_OPTIONS: readonly string[] = [
  'openai',
  'openai-compat',
  'anthropic',
  'zai-coding',
  'sakana',
  'sarvam',
  'krutrim',
  'naver',
  'falcon',
  'jais',
  'mistral',
  'yandex',
  'sber',
  'vllm',
  'ollama',
  'tgi',
  'llamacpp',
]

/** "1234" → "••••1234"; a missing fragment stays unknown (never invented). */
export function maskKeyLast4(last4: string | undefined | null): string {
  const digits = (last4 ?? '').trim()
  return digits ? `••••${digits}` : ''
}

export interface CredentialDraft {
  name: string
  provider: string
  baseUrl: string
  key: string
}

export function emptyDraft(): CredentialDraft {
  return { name: '', provider: PROVIDER_OPTIONS[0] ?? '', baseUrl: '', key: '' }
}

/** The contract fields whose absence blocks a create. */
export type CreateField = 'name' | 'provider' | 'baseUrl' | 'key'

type CreateParsed =
  | { ok: true; input: CreateProviderCredentialInput }
  | { ok: false; missing: CreateField[] }

/** POST body per the API contract: {name, provider, base_url, key}. */
export function buildCreateInput(draft: CredentialDraft): CreateParsed {
  const name = draft.name.trim()
  const provider = draft.provider.trim()
  const baseUrl = draft.baseUrl.trim()
  const key = draft.key.trim()
  const missing: CreateField[] = []
  if (!name) missing.push('name')
  if (!provider) missing.push('provider')
  if (!baseUrl) missing.push('baseUrl')
  if (!key) missing.push('key')
  if (missing.length > 0) return { ok: false, missing }
  return { ok: true, input: { name, provider, base_url: baseUrl, key } }
}

export interface CredentialEditDraft {
  name: string
  baseUrl: string
  enabled: boolean
  /** Empty = keep the stored key (omitted from the PUT body). */
  key: string
}

export function editDraftOf(cred: { name: string; base_url: string; enabled: boolean }): CredentialEditDraft {
  return { name: cred.name, baseUrl: cred.base_url, enabled: cred.enabled, key: '' }
}

/**
 * PUT body per the frozen contract: only the fields the operator actually
 * changed; `key` only when a new one was typed (empty never overwrites).
 * An empty patch means "nothing changed — skip the PUT".
 */
export function buildUpdatePatch(
  cred: Pick<ProviderCredentialFields, 'name' | 'base_url' | 'enabled'>,
  draft: CredentialEditDraft,
): UpdateProviderCredentialInput {
  const patch: UpdateProviderCredentialInput = {}
  const name = draft.name.trim()
  const baseUrl = draft.baseUrl.trim()
  const key = draft.key.trim()
  if (name && name !== cred.name) patch.name = name
  if (baseUrl && baseUrl !== cred.base_url) patch.base_url = baseUrl
  if (draft.enabled !== cred.enabled) patch.enabled = draft.enabled
  if (key) patch.key = key
  return patch
}

// The update diff only ever reads these three response fields.
interface ProviderCredentialFields {
  name: string
  base_url: string
  enabled: boolean
}

export type TestPhase = 'running' | 'ok' | 'fail'

export interface CredentialTestState {
  phase: TestPhase
  status?: number | string
  error?: string
  /** When this run completed (ISO, client clock). Absent = not checked this session. */
  checkedAt?: string
}

/**
 * R068 D-4: stamps the completion time onto a rendered probe state. The
 * badge "checked at <ts>" is session evidence only — no background re-probe
 * exists, so a state without checkedAt has simply never run.
 */
export function withCheckedAt<S extends { checkedAt?: string }>(state: S, checkedAt: string): S {
  return { ...state, checkedAt }
}

/** Shapes a contract response {ok, status?, error?} (or a thrown failure). */
export function testStateFromResult(result: ProviderCredentialTestResult): CredentialTestState {
  return result.ok
    ? { phase: 'ok', status: result.status }
    : { phase: 'fail', status: result.status, error: result.error }
}

export function testStateFromError(err: unknown): CredentialTestState {
  return { phase: 'fail', error: err instanceof Error && err.message ? err.message : String(err) }
}

// snapshot and a diagnosable refusal, so the phase is decided by
// `discovered`, not by the HTTP call alone. A snapshot is display-only
// evidence (verified=false) — never a "credential works" mark.
export type CatalogPhase = 'running' | 'ok' | 'fail'

/** The machine-readable refusal reasons the server derives (contract §5). */
export type CatalogReason =
  | 'models_list_unavailable'
  | 'key_forbidden'
  | 'key_unauthorized'
  | 'key_unavailable'
  | 'transport_error'

export interface CredentialCatalogState {
  phase: CatalogPhase
  models?: string[]
  count?: number
  reason?: CatalogReason
  status?: number | string
  error?: string
  /** When this run completed (ISO, client clock). Absent = not checked this session. */
  checkedAt?: string
}

/**
 * Shapes the contract response (or a thrown failure) into render state.
 * R068-03: the wire is untrusted — only a strictly boolean-parsed snapshot
 * (`discovered === true`) whose `data` is a list of non-empty id strings may
 * render as ok; a malformed payload is an honest, diagnosable fail WITHOUT a
 * taxonomy reason (the 5-reason catalog taxonomy stays server-derived, it is
 * never invented client-side) and without leaking the garbage ids.
 */
export function catalogStateFromResult(result: ProviderModelCatalog): CredentialCatalogState {
  if (result.discovered === true) {
    if (!isSnapshotIdList(result.data)) {
      return { phase: 'fail', error: 'malformed catalog payload: data is not a list of model ids' }
    }
    return { phase: 'ok', models: result.data ?? [], count: result.count }
  }
  return {
    phase: 'fail',
    reason: isCatalogReason(result.reason) ? result.reason : undefined,
    status: result.status,
    error: result.error,
  }
}

/** `data` is optional on a snapshot; when present it must be real id strings. */
function isSnapshotIdList(data: unknown): boolean {
  return data === undefined || (
    Array.isArray(data) && data.every(id => typeof id === 'string' && id.trim() !== '')
  )
}

export function catalogStateFromError(err: unknown): CredentialCatalogState {
  return { phase: 'fail', error: err instanceof Error && err.message ? err.message : String(err) }
}

function isCatalogReason(reason: string | undefined): reason is CatalogReason {
  return (
    reason === 'models_list_unavailable' ||
    reason === 'key_forbidden' ||
    reason === 'key_unauthorized' ||
    reason === 'key_unavailable' ||
    reason === 'transport_error'
  )
}

// ---------------------------------------------------------------------------
// registry slice meet in the shared modelDisplayState matrix. Display-only
// on both sides (D-3): the result never mutates the registry or the
// credential — it only decides which badge the operator sees.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// cross-check slice hangs off the registry query's three facts; while the
// slice is merely loading the panel must show the transient note, and only a
// real outage earns the failure copy — the two must never share a rendering.
// ---------------------------------------------------------------------------

/** The registry slice's load state: ready, transient loading, or true outage. */
export type RegistryLoadState =
  | { kind: 'ready' }
  | { kind: 'loading' }
  | { kind: 'outage' }

/**
 * Derives the registry load state: present data wins (a failed refresh keeps
 * the last good slice), an error without data is
 * the true outage, and everything else (first load in flight, not yet
 * loaded) is the transient loading state — suspended, but never failure copy.
 */
export function registryLoadState(o: {
  hasData: boolean
  loading: boolean
  error: string
}): RegistryLoadState {
  if (o.hasData) return { kind: 'ready' }
  if (o.error !== '') return { kind: 'outage' }
  return { kind: 'loading' }
}

/** One cross-checked row of the discovery panel. */
export interface CatalogModelRow {
  model: string
  /**
   * null = the registry slice could not be loaded (registry outage): the
   * display state is SUSPENDED, never invented — the panel shows the distinct
   * outage note instead of reading the model as missing (contract example 3).
   */
  state: ModelState | null
}

export interface CatalogCrossCheck {
  /** The snapshot's model ids with their display states. */
  snapshotRows: CatalogModelRow[]
  /** Registry rows (of this credential's provider) absent from the parsed snapshot. */
  absentRows: CatalogModelRow[]
}

/**
 * Cross-check one parsed snapshot against the registry slice.
 *
 * `registry` maps model name → enabled for the candidate rows the caller
 * already scoped to this credential's provider; null means the slice is
 * unavailable (outage or still loading) and every state is suspended.
 * `testOk` is the credential's last connection-test verdict — the only
 * usability evidence a BYOK credential carries — applied to the registered
 * rows only: a snapshot-only id stays "discovered" (register it manually)
 * no matter how the test went.
 */
export function crossCheckCatalog(o: {
  snapshot: readonly string[] | undefined
  testOk?: boolean
  registry: ReadonlyMap<string, boolean> | null
}): CatalogCrossCheck {
  const registry = o.registry
  // parse gate) is not evidence — it claims nothing and lists nothing.
  const snapshot: readonly string[] | undefined = Array.isArray(o.snapshot) ? o.snapshot : undefined
  const snapshotRows: CatalogModelRow[] = (snapshot ?? []).map(model => {
    if (registry === null) return { model, state: null }
    const registered = registry.has(model)
    return {
      model,
      state: modelDisplayState({
        registered,
        enabled: registry.get(model) ?? false,
        testOk: registered ? o.testOk : undefined,
        discovered: true,
      }),
    }
  })
  const absentRows: CatalogModelRow[] = []
  if (snapshot !== undefined && registry !== null) {
    for (const [name, enabled] of registry) {
      if (snapshot.includes(name)) continue
      absentRows.push({
        model: name,
        state: modelDisplayState({
          registered: true,
          enabled,
          testOk: o.testOk,
          discovered: false,
        }),
      })
    }
  }
  return { snapshotRows, absentRows }
}
