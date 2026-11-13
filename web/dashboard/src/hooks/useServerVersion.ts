import { useEffect, useState } from 'react'
// The transport is imported directly (not via ../api/client): client.ts is a
// loadable by node --test (the unit tests import the pure decision logic).
import { ApiError, readJSON } from '../api/transport.ts'

// GET /api/version, mounted for an authenticated session):
//   { version: string, commit: string, api_level: number, migration: number }
//
// The dashboard is compiled against an expected admin API level. When the
// server reports a LOWER level (an older admin build) or the endpoint is
// this newer dashboard may not work against it; App shows a persistent yellow
// banner (VersionBanner) instead of failing screens one by one with 404s.
//
// Honesty rules:
// - Only the two card triggers raise the banner: a parsed api_level below the
//   expectation, or a 404. Anything else that leaves the level unknown (a
//   network drop, a 5xx, an unauthenticated 401, a malformed body) is NOT
//   "older" — unknown is not a claim, and the affected screens already show
//   their own error states. A stub fallback that answers 200 with an empty
//   body therefore stays banner-free.
// - The answer is cached for the browser session (module-level, same pattern
//   as the /api/me cache in usePermissions): a build identity cannot change
//   under a running dashboard, and a page reload refetches. A negative answer
//   (including 404) is cached too — remounting consumers must not refire the
//   request.

/** The admin API contract level this dashboard build is compiled against
 * (mirrors the server's `AdminAPILevel` const, currently 1). */
export const EXPECTED_API_LEVEL = 1

export interface ServerVersionInfo {
  version: string
  commit: string
  api_level: number
  migration?: number
}

export type ServerVersionState =
  | { kind: 'loading' }
  /** Parsed answer with api_level >= EXPECTED_API_LEVEL. */
  | { kind: 'compatible'; server: ServerVersionInfo }
  /** Parsed answer with api_level < EXPECTED_API_LEVEL — banner. */
  | { kind: 'older'; server: ServerVersionInfo }
  /** The endpoint does not exist (404) — banner. */
  | { kind: 'unavailable' }
  /** Level unknown (network/5xx/401/malformed) — no banner, screens fail honestly. */
  | { kind: 'unknown' }

/** The banner decision as a pure function (unit-tested): null = no banner. */
export interface VersionBannerInfo {
  /** Present when the server answered with a too-old api_level. */
  server?: ServerVersionInfo
}

export function versionBanner(state: ServerVersionState): VersionBannerInfo | null {
  if (state.kind === 'older') return { server: state.server }
  if (state.kind === 'unavailable') return {}
  return null
}

/** Validates the /api/version payload shape; a body without a usable numeric
 * api_level is 'unknown' (never guessed into 'older'). */
function normalize(raw: unknown): ServerVersionState {
  if (typeof raw !== 'object' || raw === null) return { kind: 'unknown' }
  const v = raw as Partial<Record<keyof ServerVersionInfo, unknown>>
  if (typeof v.api_level !== 'number' || !Number.isFinite(v.api_level)) return { kind: 'unknown' }
  const server: ServerVersionInfo = {
    version: typeof v.version === 'string' ? v.version : '',
    commit: typeof v.commit === 'string' ? v.commit : '',
    api_level: v.api_level,
    migration: typeof v.migration === 'number' ? v.migration : undefined,
  }
  if (server.api_level < EXPECTED_API_LEVEL) return { kind: 'older', server }
  return { kind: 'compatible', server }
}

function classifyError(error: unknown): ServerVersionState {
  // 404 is the handshake's "endpoint predates the dashboard" signal (the card's
  // second trigger). Every other failure leaves compatibility unknown.
  if (error instanceof ApiError && error.status === 404) return { kind: 'unavailable' }
  return { kind: 'unknown' }
}

let cachedState: ServerVersionState | null = null
let inflight: Promise<ServerVersionState> | null = null

function requestVersion(): Promise<ServerVersionState> {
  if (cachedState) return Promise.resolve(cachedState)
  if (!inflight) {
    inflight = readJSON<unknown>('/api/version')
      .then(raw => {
        cachedState = normalize(raw)
        return cachedState
      })
      .catch((error: unknown) => {
        cachedState = classifyError(error)
        return cachedState
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

export function useServerVersion(): ServerVersionState {
  const [state, setState] = useState<ServerVersionState>(() => cachedState ?? { kind: 'loading' })
  useEffect(() => {
    let alive = true
    void requestVersion().then(result => {
      // Adopt the single-flight result even if this instance mounted while the
      // request was in flight (same reasoning as usePermissions: without the
      // unconditional set such an instance stays stuck on 'loading').
      if (!alive) return
      setState(result)
    })
    return () => {
      alive = false
    }
  }, [])
  return state
}
