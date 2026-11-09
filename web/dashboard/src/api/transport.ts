// AF-08: the single owner of the dashboard's HTTP transport lifecycle.
//
// Every request goes through exactly one of the two entry points:
// - readJSON:     fetch → status/error parse → JSON body parse → cleanup
// - sendMutation: CSRF prep → fetch → status/error parse → body parse →
//                 cleanup, plus the single safe replay after a CSRF
//                 403 "forbidden".
//
// Cancellation covers the full lifecycle, not just the fetch:
// - Reads carry the documented default 30s read timeout even when the caller
//   passes no options (`timeoutMs: 0` disables it). Mutations arm no timer by
//   default — a client-side timeout there would leave the server-side outcome
//   unknown — only an explicit caller `timeoutMs` applies.
// - The caller's AbortSignal stays connected until body parsing finished: an
//   abort during a response-body read (or an error-body read) still cancels
//   the operation. Timers and abort listeners are released in a finally after
//   parsing, so cleanup never leaks either.
// - CSRF token loading is deduplicated across concurrent callers, and one
//   cancelled caller only cancels its own await — the shared token fetch
//   keeps going so the other callers still get the token.
// - Mutations are NEVER resent after a network timeout or abort (the server
//   may have accepted them — the outcome is unknown). The only resend is the
//   documented single replay when the server answered 403 "forbidden": the
//   CSRF token was stale, the mutation itself was never accepted.

export class ApiError extends Error {
  readonly status: number
  readonly code?: string
  readonly body?: string

  constructor(status: number, message: string, code?: string, body?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
  }
}

// requestOpts: `signal` is the caller's AbortSignal (cancellation only — no
// auto-retry semantics), `timeoutMs` is a per-request timeout that aborts
// automatically (undefined → default 30s for reads, none for mutations;
// 0 disables the timer). `headers` (AUX-14b) carries extra request headers,
// e.g. X-Audit-Reason; the CSRF token is still set by the client and cannot
// be overridden here.
export interface RequestOptions {
  signal?: AbortSignal
  timeoutMs?: number
  headers?: Record<string, string>
}

/** Documented default read timeout — armed even when no options are passed. */
export const DEFAULT_READ_TIMEOUT_MS = 30_000

async function toApiError(res: Response): Promise<ApiError> {
  // Outside the guard: a failed body read (caller abort, network drop) must
  // propagate as the transport error — it is not a "non-JSON body".
  const body = await res.text()
  let message = `API error: ${res.status} ${res.statusText}`
  let code: string | undefined
  try {
    if (body) {
      const parsed = JSON.parse(body) as { error?: string }
      if (typeof parsed.error === 'string' && parsed.error) {
        message = `API error ${res.status}: ${parsed.error}`
        code = parsed.error
      }
    }
  } catch {
    // non-JSON body — keep the status-line message
  }
  // mutation replay (the first attempt and every read/CSRF path throw
  // unauthorized() before this point) — notify so no real 401 stays unseen.
  if (res.status === 401) notifyUnauthorized()
  return new ApiError(res.status, message, code, body)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// Fired exactly once per response the transport classifies as 401: the shared
// unauthorized() path (reads, the CSRF token load, the first mutation
// attempt) and the final-response parse of a replayed mutation (toApiError).
// Non-401 failures never fire. The session gate subscribes and swaps the
// whole shell for the sign-in screen.
export type UnauthorizedListener = () => void

const unauthorizedListeners = new Set<UnauthorizedListener>()

/** Subscribes to 401 notifications; returns the unsubscribe function. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener)
  return () => {
    unauthorizedListeners.delete(listener)
  }
}

function notifyUnauthorized(): void {
  for (const listener of [...unauthorizedListeners]) listener()
}

// the full deep link (path + query + hash, e.g. "/#keys?org=acme") so the
// login flow returns the operator to the exact screen. Same shape the server
// accepts: relative, starts with "/", never scheme-relative ("//" or "/\"),
// no scheme — anything else falls back to "/". Encoded exactly once.
export function loginNextUrl(loc: { pathname: string; search: string; hash: string }): string {
  const next = `${loc.pathname}${loc.search}${loc.hash}`
  const safe = next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/'
  return `/auth/login?next=${encodeURIComponent(safe)}`
}

// ---------------------------------------------------------------------------
// CSRF token (shared across concurrent callers)
// ---------------------------------------------------------------------------

let csrfToken: string | null = null
let csrfInflight: Promise<string> | null = null

/** Clears the cached CSRF token (after a 401 / CSRF rejection; also for tests). */
export function resetCsrf(): void {
  csrfToken = null
}

function unauthorized(): ApiError {
  resetCsrf()
  notifyUnauthorized()
  return new ApiError(401, 'Unauthorized (401) — log in to the admin panel first')
}

// Shared in-flight token load: one fetch serves every concurrent caller. It is
// bounded by the default read timeout but deliberately carries NO caller's
// abort signal — one cancelled caller must not cancel the token for all.
function loadCsrfToken(): Promise<string> {
  return (async () => {
    const scope = createScope(undefined, DEFAULT_READ_TIMEOUT_MS)
    try {
      const res = await fetch('/auth/csrf', { credentials: 'include', signal: scope.signal })
      if (res.status === 401) throw unauthorized()
      if (!res.ok) throw await toApiError(res)
      const parsed = (await res.json()) as { csrf_token?: string }
      if (!parsed.csrf_token) throw new ApiError(res.status, 'CSRF token missing')
      csrfToken = parsed.csrf_token
      return csrfToken
    } finally {
      scope.dispose()
    }
  })()
}

function ensureCsrf(signal?: AbortSignal): Promise<string> {
  if (csrfToken) return Promise.resolve(csrfToken)
  if (!csrfInflight) {
    const flight = loadCsrfToken()
    csrfInflight = flight
    const settled = (): void => {
      if (csrfInflight === flight) csrfInflight = null
    }
    flight.then(settled, settled)
  }
  // A caller that aborts only cuts short its own await (isolateCallerAbort);
  // the shared load keeps running and the token stays cached for the others.
  return isolateCallerAbort(csrfInflight, signal)
}

// Rejects the caller's await when its signal fires, without influencing the
// underlying promise (or the fetch behind it).
function isolateCallerAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(signal.reason ?? new DOMException('Aborted', 'AbortError'))
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason ?? new DOMException('Aborted', 'AbortError'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      error => {
        signal.removeEventListener('abort', onAbort)
        reject(error)
      },
    )
  })
}

// ---------------------------------------------------------------------------
// Cancellation scope: caller signal + optional timeout, merged
// ---------------------------------------------------------------------------

interface LifecycleScope {
  signal?: AbortSignal
  dispose: () => void
}

// Merges the caller signal with an optional timeout into a single signal
// without taking ownership of either (callers still own their
// AbortController). dispose() runs only after body parsing so an abort stays
// connected through the whole response read; it is idempotent and releases
// every listener/timer the scope armed.
function createScope(signal: AbortSignal | undefined, timeoutMs: number | undefined): LifecycleScope {
  if (!signal && !(timeoutMs && timeoutMs > 0)) return { signal: undefined, dispose: () => {} }
  const controller = new AbortController()
  const onAbort = (): void => controller.abort(signal?.reason)
  if (signal) {
    if (signal.aborted) controller.abort(signal.reason)
    else signal.addEventListener('abort', onAbort, { once: true })
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  if (timeoutMs && timeoutMs > 0) {
    timer = setTimeout(() => controller.abort(new DOMException('timeout', 'TimeoutError')), timeoutMs)
  }
  return {
    signal: controller.signal,
    dispose: () => {
      signal?.removeEventListener('abort', onAbort)
      if (timer !== undefined) {
        clearTimeout(timer)
        timer = undefined
      }
    },
  }
}

// Reads: undefined → the documented default; 0 (or negative) explicitly
// disables the timer. Mutations: always undefined unless the caller asked.
function readTimeout(opts?: RequestOptions): number | undefined {
  if (opts?.timeoutMs === undefined) return DEFAULT_READ_TIMEOUT_MS
  return opts.timeoutMs > 0 ? opts.timeoutMs : undefined
}

function mutationTimeout(opts?: RequestOptions): number | undefined {
  return opts?.timeoutMs !== undefined && opts.timeoutMs > 0 ? opts.timeoutMs : undefined
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

export async function readJSON<T>(url: string, opts?: RequestOptions): Promise<T> {
  const scope = createScope(opts?.signal, readTimeout(opts))
  try {
    const res = await fetch(url, { credentials: 'include', headers: opts?.headers, signal: scope.signal })
    if (res.status === 401) throw unauthorized()
    if (!res.ok) throw await toApiError(res)
    return (await res.json()) as T
  } finally {
    scope.dispose()
  }
}

export type MutationResult<T> =
  | { ok: true; status: number; body?: T }
  | { ok: false; status: number; error: ApiError }

async function mutationAttempt<T>(
  url: string, init: RequestInit, opts: RequestOptions | undefined, firstAttempt: boolean,
): Promise<MutationResult<T>> {
  const token = await ensureCsrf(opts?.signal)
  const headers = new Headers(init.headers)
  for (const [name, value] of Object.entries(opts?.headers ?? {})) {
    headers.set(name, value)
  }
  // Set last: callers cannot override the CSRF header.
  headers.set('X-CSRF-Token', token)
  const scope = createScope(opts?.signal, mutationTimeout(opts))
  try {
    const res = await fetch(url, { ...init, credentials: 'include', headers, signal: scope.signal })
    // First attempt only: a replayed 401 is reported as a plain error like
    // every other non-2xx of the final response (the historical contract).
    if (res.status === 401 && firstAttempt) throw unauthorized()
    if (!res.ok) return { ok: false, status: res.status, error: await toApiError(res) }
    if (res.status === 204) return { ok: true, status: res.status }
    return { ok: true, status: res.status, body: (await res.json()) as T }
  } finally {
    scope.dispose()
  }
}

function csrfForbidden(err: ApiError): boolean {
  return err.status === 403 && (err.body ?? '').trim() === 'forbidden'
}

export async function sendMutation<T = unknown>(
  url: string, init: RequestInit, opts?: RequestOptions,
): Promise<MutationResult<T>> {
  let outcome = await mutationAttempt<T>(url, init, opts, true)
  if (!outcome.ok && outcome.status === 403 && csrfForbidden(outcome.error)) {
    // Single safe replay (documented contract): the server rejected the CSRF
    // token, not the mutation — the request was never accepted, so resending
    // cannot duplicate anything. A second rejection is reported as-is.
    resetCsrf()
    outcome = await mutationAttempt<T>(url, init, opts, false)
  }
  return outcome
}
