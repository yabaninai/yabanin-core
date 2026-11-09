// N02-P08 (T02/T06): the guard detector-pack surface client.
//
// Every shape mirrors the Go handlers exactly (services/admin/handlers/
// guardpacks.go + guardpacks_read.go). The chain this client serves:
// edit (operator picks a pack@version + authors on disk) → validate (dry-run
// loader) → simulate (detect-only preview) → activate/rollback (durable CAS)
// → runtime status (durable state + load check) → audit journal.
//
// Honesty contract: nothing here invents fields. The status response carries
// the DURABLE requested versions and the pack load check — never a gateway
// replica's applied version or a watch-failure count (those live in the
// gateway process; see guardpacks_read.go).

import { fetchJSON, postJSON, type RequestOptions } from './http.ts'
import { simulateRequestBody } from '../pages/guardPacksModel.ts'

/** One on-disk pack directory (GET /api/guard-packs). */
export interface GuardPackRow {
  /** Directory name under the pack root (always present). */
  dir: string
  pack_id?: string
  pack_version?: string
  files?: number
  signature_declared?: boolean
  /** Reason the directory is not loadable (empty = healthy). */
  error?: string
}

export interface GuardPackList {
  packs: GuardPackRow[]
  active_version: string
  previous_version: string
}

export interface GuardPackRuntimeStatus {
  active_pack_loadable: boolean
  load_error?: string
  /** What the check verified (server-provided, quoted verbatim by the UI). */
  check: string
}

export interface GuardPackStatus {
  active_version: string
  previous_version: string
  updated_by?: string
  /** RFC3339; absent when no durable activation was ever recorded. */
  updated_at?: string
  staged_version: string
  runtime: GuardPackRuntimeStatus
}

export interface GuardPackValidation {
  status: 'valid'
  pack_id: string
  pack_version: string
  digest: string
  detectors: number
}

export interface GuardPackFinding {
  detector: string
  category: string
  start: number
  end: number
  confidence: number
}

export interface GuardPackSimulation {
  status: 'simulated'
  pack_id: string
  pack_version: string
  digest: string
  total_findings: number
  truncated: boolean
  findings: GuardPackFinding[]
  /** Scan-threshold categories (Hook.Scan parity) — what runtime would act on. */
  categories?: string[]
}

export interface GuardPackMutationResult {
  status: string
  active_version: string
  previous_version: string
}

export async function listGuardPacks(opts?: RequestOptions): Promise<GuardPackList> {
  return fetchJSON<GuardPackList>('/guard-packs', opts)
}

export async function guardPackStatus(opts?: RequestOptions): Promise<GuardPackStatus> {
  return fetchJSON<GuardPackStatus>('/guard-packs/status', opts)
}

/** Dry-run the loader (SHA-256 verification + compile); stages nothing. */
export async function validateGuardPack(packId: string, version: string, opts?: RequestOptions): Promise<GuardPackValidation> {
  return postJSON<GuardPackValidation>('/guard-packs/validate', { pack_id: packId, version }, 'POST', opts)
}

/**
 * Detect-only preview: the combined built-in + pack evaluator over the
 * sample. Audit-only semantics — findings only, no action, no state change.
 */
export async function simulateGuardPack(packId: string, version: string, sample: string, opts?: RequestOptions): Promise<GuardPackSimulation> {
  return postJSON<GuardPackSimulation>('/guard-packs/simulate', simulateRequestBody(packId, version, sample), 'POST', opts)
}

export async function activateGuardPack(packId: string, version: string, opts?: RequestOptions): Promise<GuardPackMutationResult> {
  return postJSON<GuardPackMutationResult>('/guard-packs/activate', { pack_id: packId, version }, 'POST', opts)
}

export async function rollbackGuardPack(opts?: RequestOptions): Promise<GuardPackMutationResult> {
  return postJSON<GuardPackMutationResult>('/guard-packs/rollback', {}, 'POST', opts)
}
