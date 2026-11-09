// AUX-17 (EntityDrawer): the inspect deep-link — `?inspect=<id>` in the
// page-hash query. Pure parse/serialize so node:test can cover it without a
// DOM, mirroring lib/tableUrl.ts. The dashboard routes via the hash
// (#page?params): the inspect param rides next to the scope params (org,
// locale, sort) and is removed again when the drawer closes, so a shared
// link opens exactly one inspector and a plain URL stays a plain URL.

export const INSPECT_PARAM = 'inspect'

/** The current hash query (best-effort; empty outside the browser). */
export function currentHashQuery(): URLSearchParams {
  try {
    const q = window.location.hash.split('?')[1] ?? ''
    return new URLSearchParams(q)
  } catch {
    return new URLSearchParams()
  }
}

/** The inspect id encoded in the query, or null when absent/blank. */
export function readInspectParam(query: URLSearchParams | string): string | null {
  const params = typeof query === 'string' ? new URLSearchParams(query) : query
  const raw = params.get(INSPECT_PARAM)?.trim() ?? ''
  return raw === '' ? null : raw
}

/** Sets (id) or removes (null) the inspect param; other params untouched. */
export function writeInspectParam(params: URLSearchParams, id: string | null): void {
  if (id && id.trim() !== '') params.set(INSPECT_PARAM, id.trim())
  else params.delete(INSPECT_PARAM)
}

/**
 * Hash for navigating to a related list page from the drawer: the current
 * query minus this page's inspect param (a stale id must not leak into the
 * next page and open a ghost inspector there), plus explicit extra params
 * (e.g. the entity's org for the requests explorer). Blank extras are
 * skipped so absent org ids never encode as `org=`.
 */
export function relatedListHref(
  target: string,
  query: URLSearchParams | string,
  extra: Record<string, string> = {},
): string {
  const params = new URLSearchParams(typeof query === 'string' ? query : query)
  params.delete(INSPECT_PARAM)
  for (const [key, value] of Object.entries(extra)) {
    if (value.trim() !== '') params.set(key, value.trim())
  }
  const qs = params.toString()
  return `#${target}${qs ? `?${qs}` : ''}`
}
