// GuardrailsPage.tsx so the fail-closed / fail-open ordering is executable
// under the node strip-types unit harness (the .tsx page itself cannot run
// there). The decisions pinned here:
//
//   1. While /api/me is in flight (latency) the caller's rights are UNKNOWN:
//      every card reports locked — a root answer that would open everything
//      must never flash open for the request duration (no flicker-to-open).
//   2. When /api/me FAILED (endpoint unavailable) the cards open (documented
//     fail-open): rights unknown is not denial, the server stays the arbiter
//      behind every link and 403s what the caller cannot use.
//   3. The loading guard is checked BEFORE the fail-open branch — the exact
//      ordering that makes (1) and (2) compose correctly while the request
//      is pending.
//
// The locked-card vocabulary is data, not copy: the reason keys resolve

export interface GuardrailsAccess {
  rootOnly?: boolean
  anyOrg?: string[]
}

/** The slice of the usePermissions result the card gate reads. */
export interface GuardrailsPermsView {
  /** True while the first /api/me answer is still pending. */
  loading: boolean
  /** True once a /api/me payload landed; false while loading or when the endpoint failed. */
  hasIdentity: boolean
  isRoot: boolean
  canAnyOrg: (...permissions: string[]) => boolean
}

export function guardrailsCardOpenable(access: GuardrailsAccess, perms: GuardrailsPermsView): boolean {
  if (perms.loading) return false // unknown yet — locked cards persist, never a flash of links that would 403
  if (!perms.hasIdentity) return true // endpoint unavailable — server stays the arbiter
  if (perms.isRoot) return true
  if (access.rootOnly) return false
  return perms.canAnyOrg(...(access.anyOrg ?? []))
}

export type GuardrailsLockReasonKey = 'guardrails.requiresRoot' | 'guardrails.requiresPerm'

export function guardrailsLockReasonKey(access: GuardrailsAccess): GuardrailsLockReasonKey {
  return access.rootOnly ? 'guardrails.requiresRoot' : 'guardrails.requiresPerm'
}

export function guardrailsLockReasonParams(access: GuardrailsAccess): Record<string, string> {
  return access.rootOnly ? {} : { permission: (access.anyOrg ?? []).join(', ') }
}
