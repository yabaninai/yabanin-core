// Pure model behind GuardPacksPage.tsx so the fail-closed ordering, payload
// shapes and honest error mapping stay executable under the node strip-types
// harness (the GuardrailsPage/guardrailsModel precedent: JSX cannot render in
// the node harness, so every decision the page makes lives here).
//
// What the model owns (each pinned by guardPacksModel.test.ts):
//   1. the exact wire payloads (simulate/activate bodies) the browser test
//      asserts on the network;
//   2. the durable-version identity parsing (the gateway's strings.Cut
//      semantics: FIRST '@' splits pack dir from version; a joined
//      multi-pack identity has no single row);
//   3. the honest ApiError mapping (404 vs 409-conflict-with-live-state vs
//      store failure vs unwired) — the UI never invents a success;
//   4. the audit-journal client-side filter (the /api/audit-logs endpoint
//      has no resource filter — documented in api/audit.ts; the page labels
//      the result "first page" and links to the full journal);
//   5. status normalization (a zero/absent updated_at renders as unknown,
//      never as a zero date).

import type { AuditLogEntry } from '../api/audit.ts'

export type { RequestOptions } from '../api/http.ts'

// ----- 1. wire payloads -----------------------------------------------------

/** The exact POST /api/guard-packs/simulate body. */
export function simulateRequestBody(packId: string, version: string, sample: string): { pack_id: string; version: string; sample: string } {
  return { pack_id: packId, version, sample }
}

/** The exact POST /api/guard-packs/activate body. */
export function activateRequestBody(packId: string, version: string): { pack_id: string; version: string } {
  return { pack_id: packId, version }
}

// ----- 2. durable identity parsing (gateway Cut semantics) ------------------

/**
 * Splits one "pack@version" identity part at the FIRST '@' (the same
 * strings.Cut the runtime materialization uses). Returns null for a
 * malformed part.
 */
export function parseIdentityPart(part: string): { packId: string; version: string } | null {
  const at = part.indexOf('@')
  if (at <= 0 || at === part.length - 1) return null
  return { packId: part.slice(0, at), version: part.slice(at + 1) }
}

/**
 * The pack directory the durable active version names — null for the
 * built-in chain ('' or 'core') and for a joined multi-pack identity, where
 * no single row is "the active one".
 */
export function activePackDir(activeVersion: string): string | null {
  const trimmed = activeVersion.trim()
  if (trimmed === '' || trimmed === 'core') return null
  if (trimmed.includes(',')) return null
  return parseIdentityPart(trimmed)?.packId ?? null
}

/** Human label for a durable version: the built-in chain is named, not blank. */
export function durableVersionLabel(activeVersion: string): string {
  return activeVersion.trim() === '' ? 'core' : activeVersion.trim()
}

// ----- 3. honest error mapping ----------------------------------------------

export interface GuardPackErrorView {
  /** Stable machine kind the page maps to copy. */
  kind: 'notFound' | 'conflict' | 'conflictState' | 'storeFailure' | 'unwired' | 'http'
  /** The server's own error text (verbatim; never rewritten by the UI). */
  serverMessage: string
  /** The LIVE durable state a 409 conflict envelope carries (AF-09 parity). */
  conflict?: { active_version?: string; previous_version?: string }
}

/**
 * Maps the transport's ApiError to the honest view. The serverMessage is the
 * API's own text: an unknown version stays "guard pack version not found",
 * a CAS loser shows the winner's live state, a store failure never reads as
 * "nothing happened" (the UI labels it a store failure with state unchanged).
 */
export function guardPackErrorView(err: unknown): GuardPackErrorView {
  const apiErr = err as { status?: number; body?: string; message?: string }
  const status = typeof apiErr?.status === 'number' ? apiErr.status : 0
  const serverMessage = typeof apiErr?.message === 'string' && apiErr.message ? apiErr.message : String(err)
  if (status === 404) return { kind: 'notFound', serverMessage }
  if (status === 409) {
    try {
      const parsed = JSON.parse(apiErr?.body ?? '') as { error?: string; current?: { active_version?: string; previous_version?: string } }
      if (parsed?.error === 'conflict' && parsed.current) {
        return { kind: 'conflictState', serverMessage, conflict: parsed.current }
      }
    } catch {
      // not the conflict envelope — a plain 409 (e.g. verification failure)
    }
    return { kind: 'conflict', serverMessage }
  }
  if (status === 500) return { kind: 'storeFailure', serverMessage }
  if (status === 503) return { kind: 'unwired', serverMessage }
  return { kind: 'http', serverMessage }
}

// ----- 4. audit journal filter ----------------------------------------------

/**
 * The guard_pack slice of one audit page. The endpoint has no resource
 * filter (api/audit.ts documents: "none are invented here"), so the page
 * filters the fetched page client-side and labels it as the first page —
 * honest scoping, not a fabricated complete history.
 */
export function filterGuardPackJournal(entries: AuditLogEntry[]): AuditLogEntry[] {
  return entries.filter(e => e.resource === 'guard_pack')
}

// ----- 5. status normalization -----------------------------------------------

export interface GuardPackStatusView {
  activeVersion: string
  previousVersion: string
  updatedBy: string | null
  /** Null when no durable activation was ever recorded (never a zero date). */
  updatedAt: string | null
  stagedVersion: string
  activePackLoadable: boolean
  loadError: string | null
  check: string
}

/**
 * Normalizes the raw status body. Defensive against a degraded/stub body
 * (missing runtime object) by falling to the honest unknown state rather
 * than crashing or claiming health.
 */
export function statusView(raw: Partial<{
  active_version: string
  previous_version: string
  updated_by?: string
  updated_at?: string
  staged_version: string
  runtime: { active_pack_loadable?: boolean; load_error?: string; check?: string }
}> | null | undefined): GuardPackStatusView {
  const runtime = raw?.runtime ?? {}
  const updatedAt = typeof raw?.updated_at === 'string' && raw.updated_at !== '' ? raw.updated_at : null
  return {
    activeVersion: durableVersionLabel(raw?.active_version ?? ''),
    previousVersion: durableVersionLabel(raw?.previous_version ?? ''),
    updatedBy: typeof raw?.updated_by === 'string' && raw.updated_by !== '' ? raw.updated_by : null,
    updatedAt,
    stagedVersion: typeof raw?.staged_version === 'string' ? raw.staged_version : '',
    activePackLoadable: runtime.active_pack_loadable === true,
    loadError: typeof runtime.load_error === 'string' && runtime.load_error !== '' ? runtime.load_error : null,
    check: typeof runtime.check === 'string' ? runtime.check : '',
  }
}

/** Defensive list normalization (degraded/stub body → the honest empty list). */
export function packRows(raw: unknown): Array<{ dir: string; pack_id?: string; pack_version?: string; files?: number; signature_declared?: boolean; error?: string }> {
  if (!Array.isArray(raw)) return []
  return raw.filter((row): row is NonNullable<typeof row> =>
    typeof row === 'object' && row !== null && typeof (row as { dir?: unknown }).dir === 'string',
  )
}
