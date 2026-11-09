// W-CAPS: org caps — the beta limits surface (RPM / TPM / hard monthly
// returns the effective block (beta defaults merged with the org's
// overrides) plus the measured month-to-date spend; the PUT sends the full
// sextuple with a MANDATORY operator reason (the server 400s an empty one)
// and answers the re-read effective block.
//
// AF-01 honesty rule: null means "beta default" — never "unlimited" — for
// rpm/tpm/budget (the server applies 60 RPM / 200k TPM / $50 month). The
// key_tokens_per_min) have NO beta default: null = OFF (0 = no window; the
// aggregate TPM default keeps applying). A partial PUT never disables a cap.

import { readJSON, sendMutation } from './transport.ts'
import type { RequestOptions } from './transport.ts'

export const ORG_CAPS_MIN_VALUE = 1
export const ORG_CAPS_MAX_VALUE = 10_000_000
export const ORG_CAPS_MIN_BUDGET_CENTS = 1
export const ORG_CAPS_MAX_BUDGET_CENTS = 1_000_000_000

/** A settable rpm/tpm override: null (beta default) or [1..10_000_000]. */
export function isValidOrgCapsValue(v: number | null): boolean {
  if (v === null) return true
  return Number.isInteger(v) && v >= ORG_CAPS_MIN_VALUE && v <= ORG_CAPS_MAX_VALUE
}

/** A settable monthly budget override in cents: null (beta default) or [1..$10M]. */
export function isValidOrgCapsBudgetCents(v: number | null): boolean {
  if (v === null) return true
  return Number.isInteger(v) && v >= ORG_CAPS_MIN_BUDGET_CENTS && v <= ORG_CAPS_MAX_BUDGET_CENTS
}

export interface OrgCaps {
  org_id: string
  /** Effective requests-per-minute cap (override or beta default). */
  rpm: number
  /** Effective tokens-per-minute cap (override or beta default). */
  tpm: number
  /** Effective hard monthly budget, USD cents. */
  monthly_budget_cents: number
  input_tokens_per_min: number
  output_tokens_per_min: number
  key_tokens_per_min: number
  /** Measured month-to-date spend, USD cents (server-computed). */
  month_spend_cents: number
  /** True when the measured spend has reached the hard budget. */
  budget_exceeded: boolean
  /** null = no override — the beta default applies. */
  rpm_override: number | null
  tpm_override: number | null
  monthly_budget_override_cents: number | null
  input_tokens_per_min_override: number | null
  output_tokens_per_min_override: number | null
  key_tokens_per_min_override: number | null
}

export interface OrgCapsPatch {
  rpm: number | null
  tpm: number | null
  monthly_budget_cents: number | null
  input_tokens_per_min: number | null
  output_tokens_per_min: number | null
  key_tokens_per_min: number | null
  reason: string
}

export async function getOrgCaps(orgId: string, opts?: RequestOptions): Promise<OrgCaps> {
  return readJSON<OrgCaps>(`/api/orgs/${encodeURIComponent(orgId)}/caps`, opts)
}

export async function updateOrgCaps(orgId: string, patch: OrgCapsPatch, opts?: RequestOptions): Promise<OrgCaps> {
  const outcome = await sendMutation<OrgCaps>(
    `/api/orgs/${encodeURIComponent(orgId)}/caps`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Audit-Reason': patch.reason },
      body: JSON.stringify(patch),
    },
    opts,
  )
  if (!outcome.ok) throw outcome.error
  return outcome.body as OrgCaps
}
