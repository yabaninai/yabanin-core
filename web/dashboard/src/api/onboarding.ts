// Client module for the org onboarding progress flag —
// GET/POST /api/me/onboarding (contract: services/admin/handlers/me.go, the
// org target rides the ?org_id= query string on BOTH verbs).
//
// Degradation contract (honesty): the flag is a UI-progress hint, so
// this module never throws. GET answers null when the state is unknown (old
// backend 404, store without the capability → 501, network failure) — the
// flow still renders, it just cannot persist. POST answers false when the
// mark did not persist; the caller keeps the flow's local state and the mark
// is simply retried on the operator's next visit. The server stays the
// arbiter of authorization (org membership gate); a 403 surfaces as null /
// false like any other failure.

import { fetchJSON, postJSON } from './http.ts'
import type { RequestOptions } from './transport.ts'

export interface OrgOnboarding {
  org_id: string
  completed: boolean
  skipped: boolean
}

export type OnboardingMark = { completed: true; skipped?: false } | { skipped: true; completed?: false }

/** null = state unknown (persistence unavailable or the read failed). */
export async function getOrgOnboarding(orgId: string, opts?: RequestOptions): Promise<OrgOnboarding | null> {
  try {
    const state = await fetchJSON<OrgOnboarding>(`/me/onboarding?org_id=${encodeURIComponent(orgId)}`, opts)
    if (typeof state?.completed !== 'boolean' || typeof state?.skipped !== 'boolean') return null
    return state
  } catch {
    return null
  }
}

/** true = the mark persisted; false = it did not (the caller degrades honestly). */
export async function markOrgOnboarding(orgId: string, mark: OnboardingMark, opts?: RequestOptions): Promise<boolean> {
  try {
    await postJSON(
      `/me/onboarding?org_id=${encodeURIComponent(orgId)}`,
      { completed: mark.completed === true, skipped: mark.skipped === true },
      'POST', opts,
    )
    return true
  } catch {
    return false
  }
}
