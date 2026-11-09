// client.ts unchanged — behavior-preserving split into domain modules).
//
// U07: unified API errors + cancellation.
//
// - ApiError is the single typed error for every HTTP failure: status, the
//   server `error` code/message when the body is JSON, and the raw body text.
// - `signal` is an optional AbortSignal on every request (readonly parameter —
//   the client NEVER creates or aborts on its own; callers own the
//   AbortController). AF-08: the transport keeps it connected until body
//   parsing finished, so an abort during a response-body read still cancels.
// - AF-08: the documented default 30s read timeout is really armed (even with
//   no options; `timeoutMs: 0` disables it). Mutations arm no timer unless the
//   caller passes one — a client-side timeout there would leave the
//   server-side outcome unknown.
// - There is NO automatic retry for POST/PUT — a mutation must not fire twice
//   (double key creation, double top-up), and that includes after a network
//   timeout or abort, where the outcome is unknown. The only exception is a
//   single replay after a CSRF 403 "forbidden", which refreshes the token and
//   does not duplicate a request the server accepted. GETs are retry-safe but
//   we still do not retry: the UI decides.
//
// AF-08: the HTTP lifecycle itself (CSRF preparation, fetch, error parsing,
// body parsing, cancellation scope and cleanup) lives in ./transport — one
// owner for every request. The domain modules (./orgs, ./keys, …) are the
// endpoint surface; ./client re-exports everything for compatibility.

import { readJSON, sendMutation, type RequestOptions } from './transport.ts'

export { ApiError } from './transport.ts'
export type { RequestOptions } from './transport.ts'

export async function fetchJSON<T>(url: string, opts?: RequestOptions): Promise<T> {
  return readJSON<T>(`/api${url}`, opts)
}

export async function postJSON<T>(url: string, body: unknown, method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' = 'POST', opts?: RequestOptions): Promise<T> {
  const outcome = await sendMutation<T>(`/api${url}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, opts)
  if (!outcome.ok) throw outcome.error
  return outcome.body as T
}

// ===== Control-plane API (I9) =====

export interface Paginated<T> {
  data: T[]
  pagination: { page: number; page_size: number; total: number; total_pages: number }
}

// AUX-03 (server-side sort, AUX-02 contract): allowlisted `sort` column +
// `dir`; an unknown column is rejected by the server with 400 invalid_sort,
// which callers surface as an error state (never silently ignored).
export interface ListSortParams {
  sort?: string
  dir?: 'asc' | 'desc'
}

// server must slice exactly what the page labels promise. Without it the
// server serves its own default (50) while pages assume their PAGE_SIZE.
export const DEFAULT_PAGE_SIZE = 50

export function listQuery(page: number, pageSize: number, sort?: string, dir?: 'asc' | 'desc'): string {
  const q = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  if (sort) q.set('sort', sort)
  if (dir) q.set('dir', dir)
  return q.toString()
}
