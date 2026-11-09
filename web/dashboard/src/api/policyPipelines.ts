// surface — services/admin/handlers/policy_pipelines.go, mounted under
// RequireOrgPermissionPoliciesManage (policies.manage; root passes; a
// foreign org is 404, a member without the permission 403).
//
// Contract notes that shape this module:
//  - GET detail returns { policy, versions (newest first), attachments };
//  - PUT is the ONLY mutation verb: yaml (append a NEW draft version),
//    enabled (mode flag), active_version (activate/rollback),
//    attachments (replace-all). The server 400s unknown fields
//    (DisallowUnknownFields) and a body with no recognized field ("nothing
//    to update"). git_sha is NOT a UI field (owner decision 2026-11-04, G3):
//    the API rejects any caller-supplied value — git authorship is
//    reconcile-managed, UI versions carry git_sha="" so drift attribution
//    stays unspoofable;
//  - validation is SERVER-SIDE and STRICT (owner decision 2026-11-04 (a)):
//    every save passes pkg/pipeline.ParsePolicy + Policy.Validate — the
//    SAME parser the gateway compiles at load time; an unparseable policy
//    is never stored. The editor calls POST /policies/validate (the same
//    validation) BEFORE the mutation, so invalid drafts never reach the
//    store; a 400 body {error} surfaces verbatim to the editor; this
//    client adds no local YAML opinion;
//    token: the policy.current_version the caller loaded. Stale → the
//    server applies NOTHING and answers 409 {"error","current":{policy}};
//    policyConflictCurrent unwraps the live current_version for the
//    refresh-and-rebase offer.

import { fetchJSON, postJSON, type RequestOptions } from './http.ts'
import { ApiError } from './transport.ts'

/** One org-scoped policy pipeline (adminstore.PolicyPipeline). */
export interface PolicyPipeline {
  id: string
  org_id: string
  name: string
  /** false = detached (kill-switch), true = attached; shadow/enforce lives in the YAML. */
  enabled: boolean
  /** The version attachments resolve to (0 = none yet). */
  current_version: number
  created_at: string
  updated_at: string
}

/** One immutable YAML version (adminstore.PolicyVersion). */
export interface PolicyVersion {
  id: string
  policy_id: string
  org_id: string
  version: number
  yaml: string
  git_sha: string
  label: 'draft' | 'active' | 'canary' | string
  created_by: string
  created_at: string
}

/** Pipeline → (key label, model pattern, endpoint) binding. */
export interface PolicyAttachment {
  id: string
  policy_id: string
  org_id: string
  key_label: string
  model_pattern: string
  endpoint: string
  priority: number
}

/** GET single-policy payload: versions newest first, attachments priority-first. */
export interface PolicyDetail {
  policy: PolicyPipeline
  versions: PolicyVersion[]
  attachments: PolicyAttachment[]
}

export async function listPolicies(orgId: string, opts?: RequestOptions): Promise<PolicyPipeline[]> {
  const body = await fetchJSON<{ data: PolicyPipeline[] | null; count: number } | null>(
    `/organizations/${encodeURIComponent(orgId)}/policies`, opts)
  return body?.data ?? []
}

export async function getPolicy(orgId: string, policyId: string, opts?: RequestOptions): Promise<PolicyDetail> {
  return fetchJSON<PolicyDetail>(
    `/organizations/${encodeURIComponent(orgId)}/policies/${encodeURIComponent(policyId)}`, opts)
}

export async function createPolicy(orgId: string, input: {
  name: string
  yaml: string
  enabled?: boolean
}, opts?: RequestOptions): Promise<PolicyDetail> {
  return postJSON<PolicyDetail>(
    `/organizations/${encodeURIComponent(orgId)}/policies`,
    { name: input.name, yaml: input.yaml, ...(input.enabled !== undefined ? { enabled: input.enabled } : {}) },
    'POST', opts)
}

/** POST /policies/validate payload: the parsed identity echoes back so the
 * editor can show WHAT the document declares (name/mode) before saving. */
export interface PolicyValidateOk {
  valid: true
  name: string
  mode: string
}

/** The save-time arbiter (owner decision 2026-11-04 (a)): runs EXACTLY the
 * strict validation the create/update path runs (one parser, one message),
 * never touches the store. A 200 here means the same bytes would store;
 * a 400 answers with the exact save-error text (ApiError, code = message).
 * Throws on invalid — callers decide how to surface it. */
export async function validatePolicyDoc(orgId: string, yaml: string, opts?: RequestOptions): Promise<PolicyValidateOk> {
  return postJSON<PolicyValidateOk>(
    `/organizations/${encodeURIComponent(orgId)}/policies/validate`,
    { yaml },
    'POST', opts)
}

/** PUT patch — exactly the fields the server's update body accepts; omit
    everything you do not want to change (unknown fields 400). `version` is
    the optimistic-concurrency token (R070 D2, owner 2026-10-18): the
    policy.current_version the editor loaded — present → the server applies
    the whole body atomically or answers 409 with the live row. */
export interface PolicyUpdatePatch {
  yaml?: string
  enabled?: boolean
  active_version?: number
  version?: number
}

export async function updatePolicy(
  orgId: string, policyId: string, patch: PolicyUpdatePatch, opts?: RequestOptions,
): Promise<PolicyDetail> {
  const body: Record<string, unknown> = {}
  if (patch.yaml !== undefined) body.yaml = patch.yaml
  if (patch.enabled !== undefined) body.enabled = patch.enabled
  if (patch.active_version !== undefined) body.active_version = patch.active_version
  if (patch.version !== undefined) body.version = patch.version
  return postJSON<PolicyDetail>(
    `/organizations/${encodeURIComponent(orgId)}/policies/${encodeURIComponent(policyId)}`,
    body, 'PUT', opts)
}

/** The server 409 body: the live pipeline row a stale PUT must rebase on.
 * Shape: {"error": "…", "current": {"policy": {"current_version": N, …}}}. */
export interface PolicyConflictBody {
  current?: { policy?: { current_version?: number } }
}

/** True when the error is the server's stale-version rejection (409). */
export function isPolicyConflictError(err: unknown): err is ApiError {
  return err instanceof ApiError && err.status === 409
}

/** The live current_version from a 409 body (null when absent/not a
 * conflict) — the number the editor rebases on. */
export function policyConflictCurrent(err: unknown): number | null {
  if (!isPolicyConflictError(err)) return null
  try {
    const body = JSON.parse(err.body ?? '') as PolicyConflictBody
    const current = body?.current?.policy?.current_version
    return typeof current === 'number' ? current : null
  } catch {
    return null
  }
}

/** True when the error is the server's YAML validation rejection (400 with
    a body message) — the editor renders `errorText` inline at the block. */
export function isPolicyValidationError(err: unknown): err is ApiError {
  return err instanceof ApiError && err.status === 400 && !!err.code
}

/** The server's validation message ("" when not a validation rejection). */
export function policyValidationErrorText(err: unknown): string {
  return isPolicyValidationError(err) ? String(err.code) : ''
}

// --- Drift (GET /policies/drift, services/admin/handlers/policy_reconcile.go)

/** DB-side drift classification of one policy (owner decision 2026-11-04
 * (b): the dashboard SHOWS drift, it does not hide it):
 *  - managed: the newest version was authored by a git reconcile;
 *  - drift:   edited past git after a reconcile (authored outside git,
 *             but git history exists) — the incident state;
 *  - unmanaged: never reconciled (UI/API-native; informational). */
export type PolicyDriftStatus = 'managed' | 'drift' | 'unmanaged'

/** One policy row of the drift report (adminstore.PolicyDriftEntry). */
export interface PolicyDriftEntry {
  policy_id: string
  name: string
  status: PolicyDriftStatus | string
  enabled: boolean
  current_version: number
  latest_version: number
  latest_git_sha: string
  latest_created_by: string
  latest_edited_at: string
}

/** GET drift payload — oldest policy first (deterministic for dashboards). */
export interface PolicyDriftReport {
  org_id: string
  count: number
  drift_count: number
  data: PolicyDriftEntry[]
}

export async function getPolicyDrift(orgId: string, opts?: RequestOptions): Promise<PolicyDriftReport> {
  return fetchJSON<PolicyDriftReport>(
    `/organizations/${encodeURIComponent(orgId)}/policies/drift`, opts)
}
