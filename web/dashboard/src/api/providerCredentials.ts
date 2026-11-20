// Org provider credentials — the BYOK
// client module, written against the frozen API contract:
//
//   GET    /api/orgs/{orgId}/provider-credentials
//   POST   /api/orgs/{orgId}/provider-credentials                    body {name, provider, base_url, api_key}
//   PUT    /api/orgs/{orgId}/provider-credentials/{credId}           body {name?, base_url?, enabled?, api_key?}
//   DELETE /api/orgs/{orgId}/provider-credentials/{credId}
//   POST   /api/orgs/{orgId}/provider-credentials/{credId}/test      → {ok, status?, error?}
//
// One credential reads back as:
//   {id, org_id, name, provider, base_url, key_last4, enabled, key_version,
//    created_at, updated_at}
// where key_last4 is the display fragment ("1234") — the UI renders it as
// "••••1234". The raw key is write-only: it is serialized into the POST/PUT
// body once and NEVER kept by this module (no module state, no storage);
// no response ever carries it back. On the wire the server strict-decodes
// `api_key` and rejects unknown fields (no alias exists server-side), so
// this module maps the UI-facing `key` property to `api_key` at the
// request boundary — create AND update — and never emits a `key` field.

import { fetchJSON, postJSON } from './http.ts'
import type { RequestOptions } from './transport.ts'

export interface ProviderCredential {
  id: string
  org_id: string
  name: string
  provider: string
  base_url: string
  /** Last four digits only ("1234"); displayed as "••••1234", never more. */
  key_last4: string
  enabled: boolean
  key_version: number
  created_at: string
  updated_at: string
}

export interface CreateProviderCredentialInput {
  name: string
  provider: string
  base_url: string
  /** Serialized as the server's api_key wire field; a literal `key` never leaves this module. */
  key: string
}

export interface UpdateProviderCredentialInput {
  name?: string
  base_url?: string
  enabled?: boolean
  /** Omit to keep the stored key; when present it replaces it (key_version bumps). Serialized as api_key. */
  key?: string
}

export interface ProviderCredentialTestResult {
  ok: boolean
  /** Upstream-reported status; the server decides the type — kept loose. */
  status?: number | string
  error?: string
}

// provider's OpenAI-compatible /models list, fetched server-side with the
// stored key. The catalog is discovery-only: verified is always false and
// nothing is written to any registry — manual model entry stays the
// fallback. Refusals carry a machine-readable reason instead of data.
export interface ProviderModelCatalog {
  provider: string
  base_url?: string
  count: number
  /** Model ids from the snapshot; absent on refusals and on empty catalogs. */
  data?: string[]
  /** true only on a parsed snapshot. */
  discovered?: boolean
  /** Always false on a snapshot: discovery does not mean verified usability. */
  verified?: boolean
  /** "models_list_unavailable" | "key_forbidden" | "key_unauthorized" | "key_unavailable" | "transport_error". */
  reason?: string
  status?: number | string
  error?: string
}

export async function listProviderCredentials(orgId: string, opts?: RequestOptions): Promise<ProviderCredential[]> {
  const result = await fetchJSON<ProviderCredential[] | { data?: ProviderCredential[] }>(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials`, opts,
  )
  if (Array.isArray(result)) return result
  return Array.isArray(result?.data) ? result.data : []
}

// Wire boundary: the admin API strict-decodes `api_key` (org_credentials.go
// rejects unknown fields — a literal `key` field is a 400). The UI keeps the
// friendlier `key` property; it is renamed exactly here, for create AND
// update, and the mapped body goes straight to the wire (never stored).
function createWireBody(input: CreateProviderCredentialInput): {
  name: string; provider: string; base_url: string; api_key: string
} {
  return { name: input.name, provider: input.provider, base_url: input.base_url, api_key: input.key }
}

function updateWireBody(input: UpdateProviderCredentialInput): {
  name?: string; base_url?: string; enabled?: boolean; api_key?: string
} {
  const body: { name?: string; base_url?: string; enabled?: boolean; api_key?: string } = {}
  if (input.name !== undefined) body.name = input.name
  if (input.base_url !== undefined) body.base_url = input.base_url
  if (input.enabled !== undefined) body.enabled = input.enabled
  if (input.key !== undefined) body.api_key = input.key
  return body
}

export async function createProviderCredential(
  orgId: string, input: CreateProviderCredentialInput, opts?: RequestOptions,
): Promise<ProviderCredential> {
  return postJSON<ProviderCredential>(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials`, createWireBody(input), 'POST', opts,
  )
}

export async function updateProviderCredential(
  orgId: string, credId: string, input: UpdateProviderCredentialInput, opts?: RequestOptions,
): Promise<ProviderCredential> {
  return postJSON<ProviderCredential>(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials/${encodeURIComponent(credId)}`, updateWireBody(input), 'PUT', opts,
  )
}

export async function deleteProviderCredential(orgId: string, credId: string, opts?: RequestOptions): Promise<void> {
  await postJSON(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials/${encodeURIComponent(credId)}`, {}, 'DELETE', opts,
  )
}

export async function testProviderCredential(
  orgId: string, credId: string, opts?: RequestOptions,
): Promise<ProviderCredentialTestResult> {
  return postJSON<ProviderCredentialTestResult>(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials/${encodeURIComponent(credId)}/test`, {}, 'POST', opts,
  )
}

export async function listProviderCredentialModels(
  orgId: string, credId: string, opts?: RequestOptions,
): Promise<ProviderModelCatalog> {
  return postJSON<ProviderModelCatalog>(
    `/orgs/${encodeURIComponent(orgId)}/provider-credentials/${encodeURIComponent(credId)}/models`, {}, 'POST', opts,
  )
}
