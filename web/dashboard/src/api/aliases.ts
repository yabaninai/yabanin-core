
import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

export interface ModelAlias {
  alias: string
  target_model: string
  created_at?: string
  updated_at?: string
}

// Plain-array endpoint (no pagination envelope); a non-array body (unknown
// stub/older backend) honestly renders as an empty list.
export async function listModelAliases(opts?: RequestOptions): Promise<ModelAlias[]> {
  const rows = await fetchJSON<ModelAlias[] | null>('/model-aliases', opts)
  return Array.isArray(rows) ? rows : []
}

export async function createModelAlias(alias: string, targetModel: string, opts?: RequestOptions): Promise<ModelAlias> {
  return postJSON<ModelAlias>('/model-aliases', { alias, target_model: targetModel }, 'POST', opts)
}

export async function deleteModelAlias(alias: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/model-aliases/${encodeURIComponent(alias)}`, {}, 'DELETE', opts)
}
