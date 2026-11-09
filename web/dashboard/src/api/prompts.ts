// (services/admin/handlers/prompt_studio.go) as a typed module.
//
// Base path is /api/organizations/{orgId}; every route sits behind the
// policies.manage org gate (root passes). Shapes mirror the Go payloads
// exactly:
//   Prompt        — adminstore.Prompt (id, org_id, name, description, timestamps)
//   PromptVersion — immutable template version (params is the raw JSON object)
//   PromptLabel   — movable label→version binding (draft|active|canary|custom)
//   PromptPartial — org-scoped partial body (version bumps on every PUT)
//   PromptDetail  — { prompt, versions (newest first), labels (may be null) }
// Errors are { error }; duplicate names 409, foreign/missing ids 404, an
// unwired store 503 — all surface through ApiError like every other domain.
//
// NOTE: the type is PromptPartial (not `Partial`) — the TS utility type must
// stay shadow-free in consumer files.

import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

export type PromptLabelName = 'draft' | 'active' | 'canary' | 'custom'

/** The closed label set (mirrors the 0010 CHECK constraint). */
export const PROMPT_LABEL_NAMES: readonly PromptLabelName[] = ['draft', 'active', 'canary', 'custom']

export interface Prompt {
  id: string
  org_id: string
  name: string
  description: string
  created_at: string
  updated_at: string
}

export interface PromptVersion {
  id: string
  prompt_id: string
  org_id: string
  version: number
  /** Raw text with {{var}} / {{partials.name}} placeholders. */
  template: string
  /** Raw JSON object carried next to the template (model, temperature, …). */
  params: unknown
  created_by: string
  created_at: string
}

export interface PromptLabel {
  prompt_id: string
  org_id: string
  label: PromptLabelName
  version: number
  updated_at: string
}

export interface PromptPartial {
  id: string
  org_id: string
  name: string
  body: string
  version: number
  created_at: string
  updated_at: string
}

export interface PromptDetail {
  prompt: Prompt
  versions: PromptVersion[]
  labels: PromptLabel[] | null
}

export interface PromptCreateInput {
  name: string
  description?: string
  template: string
  params?: Record<string, unknown>
}

export interface PromptUpdateInput {
  version: number
  template: string
  params?: Record<string, unknown>
}

const orgBase = (orgId: string): string => `/organizations/${encodeURIComponent(orgId)}`

/** GET /prompts — the org prompt list (plain rows; labels ride the detail). */
export async function listPrompts(orgId: string, opts?: RequestOptions): Promise<Prompt[]> {
  const body = await fetchJSON<{ data?: Prompt[]; count?: number }>(`${orgBase(orgId)}/prompts`, opts)
  return body.data ?? []
}

/** POST /prompts — creates the prompt with version 1 + the draft binding. */
export function createPrompt(orgId: string, input: PromptCreateInput, opts?: RequestOptions): Promise<PromptDetail> {
  return postJSON<PromptDetail>(`${orgBase(orgId)}/prompts`, input, 'POST', opts)
}

/** GET /prompts/{promptId} — prompt + versions (newest first) + labels. */
export function getPrompt(orgId: string, promptId: string, opts?: RequestOptions): Promise<PromptDetail> {
  return fetchJSON<PromptDetail>(`${orgBase(orgId)}/prompts/${encodeURIComponent(promptId)}`, opts)
}

/** PUT /prompts/{promptId} — APPENDS a version (never an in-place edit). */
export function updatePrompt(orgId: string, promptId: string, input: PromptUpdateInput, opts?: RequestOptions): Promise<PromptDetail> {
  return postJSON<PromptDetail>(`${orgBase(orgId)}/prompts/${encodeURIComponent(promptId)}`, input, 'PUT', opts)
}

/** POST /prompts/{promptId}/labels — upsert binding {label, version}. */
export function promotePromptLabel(
  orgId: string, promptId: string, label: PromptLabelName, version: number, opts?: RequestOptions,
): Promise<{ label: PromptLabel }> {
  return postJSON<{ label: PromptLabel }>(
    `${orgBase(orgId)}/prompts/${encodeURIComponent(promptId)}/labels`, { label, version }, 'POST', opts)
}

/** DELETE /prompts/{promptId} — the server does not block on references. */
export function deletePrompt(orgId: string, promptId: string, opts?: RequestOptions): Promise<{ status: string }> {
  return postJSON<{ status: string }>(`${orgBase(orgId)}/prompts/${encodeURIComponent(promptId)}`, undefined, 'DELETE', opts)
}

/** GET /partials — the org partial list. */
export async function listPartials(orgId: string, opts?: RequestOptions): Promise<PromptPartial[]> {
  const body = await fetchJSON<{ data?: PromptPartial[]; count?: number }>(`${orgBase(orgId)}/partials`, opts)
  return body.data ?? []
}

/** POST /partials — creates a partial (version 1). */
export function createPartial(orgId: string, input: { name: string; body: string }, opts?: RequestOptions): Promise<{ partial: PromptPartial }> {
  return postJSON<{ partial: PromptPartial }>(`${orgBase(orgId)}/partials`, input, 'POST', opts)
}

/** PUT /partials/{name} — replaces the body, version +1. */
export function updatePartial(orgId: string, name: string, body: string, version: number, opts?: RequestOptions): Promise<{ partial: PromptPartial }> {
  return postJSON<{ partial: PromptPartial }>(
    `${orgBase(orgId)}/partials/${encodeURIComponent(name)}`, { body, version }, 'PUT', opts)
}

/** DELETE /partials/{name} — the server does not block on references. */
export function deletePartial(orgId: string, name: string, opts?: RequestOptions): Promise<{ status: string }> {
  return postJSON<{ status: string }>(`${orgBase(orgId)}/partials/${encodeURIComponent(name)}`, undefined, 'DELETE', opts)
}
