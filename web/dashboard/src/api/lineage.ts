
import { ApiError } from './transport.ts'
import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

export interface LineageRecord {
  request_id?: string
  model?: string
  region?: string
  [k: string]: unknown
}

export async function getLineage(requestId: string, opts?: RequestOptions): Promise<LineageRecord> {
  return fetchJSON(`/lineage/${encodeURIComponent(requestId)}`, opts)
}

export async function verifyLineage(requestId: string, opts?: RequestOptions): Promise<{ valid: boolean; request_id: string }> {
  const result = await postJSON<{ valid: boolean; request_id: string }>(`/lineage/${encodeURIComponent(requestId)}/verify`, {}, 'POST', opts)
  if (typeof result.valid !== 'boolean' || result.request_id !== requestId) {
    throw new ApiError(0, 'Verification result unavailable or does not match the request')
  }
  return result
}

// ASTR-04: org-scoped lineage list (GET /api/organizations/{id}/lineage).
// The API returns a plain array capped by `limit` (no total, no cursor) —
// the UI must present pagination honestly against the fetched set.
export interface LineageAttestation {
  request_id?: string
  org_id?: string
  timestamp?: string
  model_used?: string
  inference_region?: string
  model_origin_country?: string
  log_storage_region?: string
  provider_entity_jurisdiction?: string
  region_evidence?: string
  [k: string]: unknown
}

export async function listLineageByOrg(orgId: string, limit = 50, opts?: RequestOptions): Promise<LineageAttestation[]> {
  const result = await fetchJSON<LineageAttestation[]>(
    `/organizations/${encodeURIComponent(orgId)}/lineage?limit=${limit}`,
    opts,
  )
  return Array.isArray(result) ? result : []
}
