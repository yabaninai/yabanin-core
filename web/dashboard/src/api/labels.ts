
import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

export interface LabelPolicy {
  allowed_keys: string[]
  denied_keys: string[]
  required_keys: string[]
  on_invalid: string
  on_missing: string
  aliases: Record<string, string>
  derive: { from: string; regex: string; to: string; template: string }[]
  rollup_keys: string[]
  max_labels: number
  value_max_len: number
}

export interface LabelPolicyResponse {
  policy: LabelPolicy
  is_default: boolean
  updated_at: string
  updated_by: string
}

export interface LabelPolicyTestResult {
  labels: Record<string, string>
  dropped: { key: string; reason: string }[]
  missing: string[]
  rejected: boolean
}

export async function fetchLabelPolicy(orgId: string, opts?: RequestOptions): Promise<LabelPolicyResponse> {
  return fetchJSON<LabelPolicyResponse>(`/label-policy?org_id=${encodeURIComponent(orgId)}`, opts)
}

export async function saveLabelPolicy(orgId: string, policy: LabelPolicy, opts?: RequestOptions): Promise<LabelPolicyResponse> {
  return postJSON<LabelPolicyResponse>(`/label-policy?org_id=${encodeURIComponent(orgId)}`, policy, 'PUT', opts)
}

export async function resetLabelPolicy(orgId: string, opts?: RequestOptions): Promise<LabelPolicyResponse> {
  return postJSON<LabelPolicyResponse>(`/label-policy?org_id=${encodeURIComponent(orgId)}`, {}, 'DELETE', opts)
}

export async function testLabelPolicy(orgId: string, body: {
  policy?: LabelPolicy
  headers?: Record<string, string>
  key_labels?: Record<string, string>
  key_locked?: boolean
}, opts?: RequestOptions): Promise<LabelPolicyTestResult> {
  return postJSON<LabelPolicyTestResult>(`/label-policy/test?org_id=${encodeURIComponent(orgId)}`, body, 'POST', opts)
}
