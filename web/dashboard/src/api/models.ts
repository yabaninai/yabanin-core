
import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type Paginated, type ListSortParams, type RequestOptions } from './http.ts'

export interface ModelEntry {
  model_name: string
  display_name: string
  tier: string
  enabled: boolean
  version?: number
  upstream_url?: string
  provider?: string
  fallback_model?: string
  failover_models?: string[]
  tier_pool?: string[]
  upstream_timeout_ms?: number
  // set (has_key). The UI shows the status, never a value.
  has_key?: boolean
}

// PO-03: upstream_api_key is write-only — the server never returns it, so the
// entry type has no key field and the edit form shows a placeholder, not a
// server 400s when it is combined with a new key).
export interface ModelFormValues {
  model_name: string
  display_name: string
  tier: string
  provider: string
  upstream_url: string
  upstream_api_key: string
  clear_upstream_key?: boolean
  fallback_model: string
  failover_models: string
  tier_pool: string
  upstream_timeout_ms: string
  enabled: boolean
}

export const MODEL_TIERS = ['easy', 'medium', 'hard', 'premium'] as const

export async function listModels(page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<Paginated<ModelEntry>> {
  return fetchJSON(`/models?${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

// autocomplete. The server caps page_size at 100, so this walks the remaining
// pages (capped at 10 — registries beyond 1000 models stop growing the index;
// the server stays the source of truth on save either way).
const INDEX_PAGE_SIZE = 100
const INDEX_MAX_PAGES = 10

export async function listAllModels(opts?: RequestOptions): Promise<ModelEntry[]> {
  const first = await listModels(1, { ...opts, pageSize: INDEX_PAGE_SIZE })
  const rows = [...(first.data ?? [])]
  const totalPages = Math.min(Math.max(1, first.pagination?.total_pages ?? 1), INDEX_MAX_PAGES)
  for (let p = 2; p <= totalPages; p++) {
    const next = await listModels(p, { ...opts, pageSize: INDEX_PAGE_SIZE })
    rows.push(...(next.data ?? []))
  }
  return rows
}

export async function setModelEnabled(modelName: string, enabled: boolean, opts?: RequestOptions): Promise<void> {
  await postJSON(`/models/${encodeURIComponent(modelName)}`, { enabled }, 'PUT', opts)
}

export async function getModel(modelName: string, opts?: RequestOptions): Promise<ModelEntry> {
  return fetchJSON(`/models/${encodeURIComponent(modelName)}`, opts)
}

export async function createModel(values: ModelFormValues, opts?: RequestOptions): Promise<ModelEntry> {
  const body: Record<string, unknown> = {
    model_name: values.model_name.trim(),
    display_name: values.display_name.trim(),
    tier: values.tier,
  }
  if (values.provider.trim()) body.provider = values.provider.trim()
  if (values.upstream_url.trim()) body.upstream_url = values.upstream_url.trim()
  if (values.upstream_api_key.trim()) body.upstream_api_key = values.upstream_api_key.trim()
  if (values.fallback_model.trim()) body.fallback_model = values.fallback_model.trim()
  if (values.failover_models.trim()) body.failover_models = splitList(values.failover_models)
  if (values.tier_pool.trim()) body.tier_pool = splitList(values.tier_pool)
  if (values.upstream_timeout_ms.trim()) {
    const n = Number(values.upstream_timeout_ms)
    if (!Number.isInteger(n) || n <= 0) throw new Error('upstream_timeout_ms must be a positive integer')
    body.upstream_timeout_ms = n
  }
  return postJSON('/models', body, 'POST', opts)
}

export async function updateModel(modelName: string, values: ModelFormValues, opts?: RequestOptions): Promise<void> {
  const body: Record<string, unknown> = {
    display_name: values.display_name.trim(),
    tier: values.tier,
    enabled: values.enabled,
  }
  if (values.provider.trim()) body.provider = values.provider.trim()
  if (values.upstream_url.trim()) body.upstream_url = values.upstream_url.trim()
  // Empty means "unchanged" — the server treats an absent upstream_api_key as
  // explicit clear flag removes the stored key (mutually exclusive with a new
  // key; the server 400s on the combination).
  if (values.upstream_api_key.trim()) body.upstream_api_key = values.upstream_api_key.trim()
  else if (values.clear_upstream_key) body.clear_upstream_key = true
  if (values.fallback_model.trim()) body.fallback_model = values.fallback_model.trim()
  if (values.failover_models.trim()) body.failover_models = splitList(values.failover_models)
  if (values.tier_pool.trim()) body.tier_pool = splitList(values.tier_pool)
  if (values.upstream_timeout_ms.trim()) {
    const n = Number(values.upstream_timeout_ms)
    if (!Number.isInteger(n) || n <= 0) throw new Error('upstream_timeout_ms must be a positive integer')
    body.upstream_timeout_ms = n
  }
  await postJSON(`/models/${encodeURIComponent(modelName)}`, body, 'PUT', opts)
}

export async function deleteModel(modelName: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/models/${encodeURIComponent(modelName)}`, {}, 'DELETE', opts)
}

function splitList(s: string): string[] {
  return s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)
}
