// AUX-22 — Table personalization, part 2: the general saved-views contract.
//
// A saved view is a named SNAPSHOT OF THE PAGE'S URL STATE (the hash query).
// The contract has two storage backends sharing one UI
// (components/astra/SavedViewsMenu.tsx):
//   * Analytics — the existing SERVER registry (GET/POST/PATCH/DELETE
//     /api/analytics/views, shareable across operators). Untouched here.
//   * Every other data page — THIS localStorage registry, keyed per page
//     (per-browser by nature; server-side sharing is a separate card).
//
// Applying a view is the page's job (the pages read their hash params at
// mount and own adoption logic — the same pattern as the Analytics openView):
// the snapshot round-trips through URLSearchParams, so lib/tableUrl state
// (<tableId>__sort/__page) and scope params (org, …) restore exactly.
//
// Persistence rules mirror lib/tablePrefs.ts: one key per page, untrusted
// JSON re-validated on read, best-effort writes.

export interface SavedViewRecord {
  id: string
  name: string
  /** Serialized hash-query snapshot (URLSearchParams-encoded). */
  query: string
}

const KEY_PREFIX = 'yabanin.savedViews.v1:'
const MAX_VIEWS = 50
const MAX_NAME_LENGTH = 120
const MAX_QUERY_LENGTH = 2048

export function savedViewsKey(pageId: string): string {
  return `${KEY_PREFIX}${pageId}`
}

/** Validates an untrusted parsed-JSON value into a clean view list. */
export function parseSavedViews(raw: unknown): SavedViewRecord[] {
  if (!Array.isArray(raw)) return []
  const out: SavedViewRecord[] = []
  for (const entry of raw.slice(0, MAX_VIEWS)) {
    if (typeof entry !== 'object' || entry === null) continue
    const v = entry as Partial<SavedViewRecord>
    if (typeof v.id !== 'string' || v.id.trim() === '' || v.id.length > 64) continue
    if (typeof v.name !== 'string' || v.name.trim() === '' || v.name.length > MAX_NAME_LENGTH) continue
    if (typeof v.query !== 'string' || v.query.length > MAX_QUERY_LENGTH) continue
    out.push({ id: v.id, name: v.name, query: v.query })
  }
  return out
}

export function listSavedViews(pageId: string): SavedViewRecord[] {
  try {
    const raw = localStorage.getItem(savedViewsKey(pageId))
    if (!raw) return []
    return parseSavedViews(JSON.parse(raw))
  } catch {
    return []
  }
}

function writeViews(pageId: string, views: SavedViewRecord[]): void {
  try {
    localStorage.setItem(savedViewsKey(pageId), JSON.stringify(views.slice(0, MAX_VIEWS)))
  } catch {
    // Private mode / tests — persistence is best-effort.
  }
}

function newViewId(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  } catch {
    // Fall through to the manual id.
  }
  return `view-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}

/** Saves a named snapshot of `query`; returns the stored record. */
export function saveSavedView(pageId: string, name: string, query: string): SavedViewRecord {
  const record: SavedViewRecord = {
    id: newViewId(),
    name: name.trim().slice(0, MAX_NAME_LENGTH),
    query: query.slice(0, MAX_QUERY_LENGTH),
  }
  writeViews(pageId, [...listSavedViews(pageId), record])
  return record
}

export function renameSavedView(pageId: string, id: string, name: string): void {
  const next = name.trim().slice(0, MAX_NAME_LENGTH)
  if (!next) return
  writeViews(pageId, listSavedViews(pageId).map(v => (v.id === id ? { ...v, name: next } : v)))
}

export function deleteSavedView(pageId: string, id: string): void {
  writeViews(pageId, listSavedViews(pageId).filter(v => v.id !== id))
}

/** The current page's hash-query snapshot (the part after '?', may be ''). */
export function currentHashQuery(): string {
  if (typeof window === 'undefined') return ''
  return window.location.hash.split('?')[1] ?? ''
}

/**
 * Decodes a snapshot into a clean param record: keys and values stay
 * strings, control pairs are dropped, and the encoded form stays stable for
 * comparisons.
 */
export function parseViewQuery(query: string): URLSearchParams {
  return new URLSearchParams(query)
}
