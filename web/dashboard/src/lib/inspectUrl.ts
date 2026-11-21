// AUX-17 (EntityDrawer): the inspect deep-link — `?inspect=<id>` in the
// page-hash query. Pure parse/serialize so node:test can cover it without a
// DOM, mirroring lib/tableUrl.ts. The dashboard routes via the hash
// (#page?params): the inspect param rides next to the scope params (org,
// locale, sort) and is removed again when the drawer closes, so a shared
// link opens exactly one inspector and a plain URL stays a plain URL.

export const INSPECT_PARAM = 'inspect'
// 0028: the inspect target's physical row selector. `inspect` names the
// correlation (request_id); `row_key` names the one physical request_logs
// row the user clicked out of the possibly-many sharing that correlation.
// Decimal string on the wire (see api/requests.ts RequestRow.row_key).
export const INSPECT_ROW_PARAM = 'row_key'

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
 * The row selector's raw values, or null when the URL carries no row_key at
 * all. Deliberately NOT collapsed: a duplicated selector (row_key=1&row_key=2)
 * must surface as two values for the caller to forward — collapsing to the
 * first sibling (URLSearchParams.get) would silently inspect a row the URL
 * never named. Blank-present is [''] (presence is intent); policy belongs to
 * the server's strict validation, not to this parser.
 */
export function readInspectRowKeys(query: URLSearchParams | string): string[] | null {
  const params = typeof query === 'string' ? new URLSearchParams(query) : query
  const all = params.getAll(INSPECT_ROW_PARAM)
  return all.length === 0 ? null : all
}

/**
 * Hash for navigating to a related list page from the drawer: the current
 * query minus this page's inspect param (a stale id must not leak into the
 * next page and open a ghost inspector there) and its row selector (same
 * leak rule: the key belongs to this correlation only), plus explicit extra
 * params (e.g. the entity's org for the requests explorer). Blank extras
 * are skipped so absent org ids never encode as `org=`.
 */
export function relatedListHref(
  target: string,
  query: URLSearchParams | string,
  extra: Record<string, string> = {},
): string {
  const params = new URLSearchParams(typeof query === 'string' ? new URLSearchParams(query) : query)
  params.delete(INSPECT_PARAM)
  params.delete(INSPECT_ROW_PARAM)
  for (const [key, value] of Object.entries(extra)) {
    if (value.trim() !== '') params.set(key, value.trim())
  }
  const qs = params.toString()
  return `#${target}${qs ? `?${qs}` : ''}`
}
