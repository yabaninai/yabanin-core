// unchanged).

import { sendMutation, type RequestOptions } from './transport.ts'
import { fetchJSON, postJSON } from './http.ts'

// Pricing (root-only CRUD; list supports provider/model filters, no paging).
export interface PricingEntry {
  id: number
  provider: string
  model: string
  input_per_m: number
  output_per_m: number
  cache_write_per_m: number
  cache_read_per_m: number
  source?: string
  source_ref?: string
  updated_by?: string
  effective_from: string
  effective_to?: string | null
}

export async function listPricing(
  opts?: RequestOptions & { provider?: string; model?: string },
): Promise<PricingEntry[]> {
  const q = new URLSearchParams()
  if (opts?.provider) q.set('provider', opts.provider)
  if (opts?.model) q.set('model', opts.model)
  const rows = await fetchJSON<PricingEntry[] | null>(`/pricing?${q.toString()}`, opts)
  return Array.isArray(rows) ? rows : []
}

export interface PricingCreateBody {
  provider: string
  model: string
  input_per_m: number
  output_per_m: number
  cache_write_per_m: number
  cache_read_per_m: number
}

export async function createPricingEntry(body: PricingCreateBody, opts?: RequestOptions): Promise<PricingEntry> {
  return postJSON<PricingEntry>('/pricing', body, 'POST', opts)
}

/** PUT /api/pricing/{id} — partial update; only the provided fields change. */
export async function updatePricingEntry(
  id: number, patch: Partial<Pick<PricingEntry, 'input_per_m' | 'output_per_m' | 'cache_write_per_m' | 'cache_read_per_m'>>, opts?: RequestOptions,
): Promise<PricingEntry> {
  return postJSON<PricingEntry>(`/pricing/${encodeURIComponent(String(id))}`, patch, 'PUT', opts)
}

export async function deletePricingEntry(id: number, opts?: RequestOptions): Promise<void> {
  const outcome = await sendMutation(
    `/api/pricing/${encodeURIComponent(String(id))}`, { method: 'DELETE' }, opts)
  if (!outcome.ok) throw outcome.error
}

/** Plain link target (root-only CSV export); fetched by the browser, not the client. */
export function pricingExportCsvUrl(): string {
  return '/api/pricing/export.csv'
}
