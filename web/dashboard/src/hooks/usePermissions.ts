import { useEffect, useState } from 'react'
import { fetchJSON } from '../api/client.ts'

// AUX-13: UI-side permission hints from the console GET /api/me.
//
// The server remains the sole arbiter — every mutation can still 403. This
// hook only feeds convenience: disabling buttons with a "requires permission
// X" hint and hiding nav entries the caller has no path to use.
//
// Honesty rules:
// - While /api/me has not answered yet the caller's rights are UNKNOWN:
//   capability checks report false (fail-closed) so a restricted admin never
//   sees a flash of clickable buttons that would only produce 403s. Nav uses
//   `loading` to keep the current show-all behavior until the answer lands.
// - If /api/me fails outright (old backend, portal shadowing, network), the
//   payload stays null and checks report true (fail-open): rights unknown is
//   not denial, the UI degrades to today's behavior instead of bricking the
//   console, and the server still 403s anything unauthorized.

export interface MeOrganization {
  id: string
  name: string
  role: string
  permissions: string[]
}

export interface Me {
  id: string
  name: string
  email?: string
  is_root: boolean
  organizations?: MeOrganization[]
}

// Module-level cache: one /api/me request per browser session (the same
// pattern as the org-list cache in useOrgPresentation). The payload changes
// only when roles change — a page reload refetches.
//
// network) is remembered for the session too — remounting consumers (page
// navigation mounts another usePermissions) must not refire /api/me after
// the endpoint already answered with an error. The failed state keeps the
// same fail-open semantics as before: me stays null, checks report true.
let cachedMe: Me | null = null
let meUnavailable = false
let inflight: Promise<Me | null> | null = null

function requestMe(): Promise<Me | null> {
  if (cachedMe) return Promise.resolve(cachedMe)
  if (meUnavailable) return Promise.resolve(null)
  if (!inflight) {
    inflight = fetchJSON<Me>('/me')
      .then(me => {
        cachedMe = me
        return me
      })
      .catch(() => {
        meUnavailable = true // null = endpoint unavailable (distinct from a payload)
        return null
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

// payload (and any in-flight request) must not survive into the signed-out
// state or a remount. Mirrors the org-list cache invalidation precedent.
// the previous session must not shadow the next login's /api/me (the new
// identity would stay unknown forever, silently fail-open). resetMeCache is
// only called on a confirmed sign-out, so clearing here cannot re-introduce
// resets.
export function resetMeCache(): void {
  cachedMe = null
  meUnavailable = false
  inflight = null
}

// the caching/single-flight contract is module-level, not per component.
export { requestMe }

export interface Permissions {
  /** The /api/me payload; null while loading or when the endpoint is unavailable. */
  me: Me | null
  /** True while the first /api/me answer is pending. */
  loading: boolean
  /** Platform administrator: every capability (server bypasses membership too). */
  isRoot: boolean
  /** Org-scoped check for the orgId passed to usePermissions. */
  can: (permission: string) => boolean
  /** True when ANY of the caller's organizations grants one of the permissions. */
  canAnyOrg: (...permissions: string[]) => boolean
}

export function usePermissions(orgId?: string): Permissions {
  const [me, setMe] = useState<Me | null>(() => cachedMe)
  const [loading, setLoading] = useState(() => cachedMe === null)

  useEffect(() => {
    let alive = true
    void requestMe().then(result => {
      // Adopt the single-flight result even if this instance mounted while
      // another consumer's request was in flight — including the window where
      // the promise resolved between this component's render (initializer
      // read a then-null cache) and this effect. Without the unconditional
      // set, such an instance would stay stuck on the empty state forever.
      if (!alive) return
      setMe(result)
      setLoading(false)
    })
    return () => {
      alive = false
    }
  }, [])

  const isRoot = me?.is_root === true
  const org = orgId ? me?.organizations?.find(o => o.id === orgId) : undefined

  const can = (permission: string): boolean => {
    if (loading) return false // unknown yet — never advertise rights we don't have
    if (me === null) return true // endpoint unavailable — server stays the arbiter
    if (isRoot) return true
    return org?.permissions?.includes(permission) ?? false
  }

  const canAnyOrg = (...permissions: string[]): boolean => {
    if (loading) return false
    if (me === null) return true
    if (isRoot) return true
    return (me.organizations ?? []).some(o =>
      permissions.some(p => o.permissions?.includes(p)),
    )
  }

  return { me, loading, isRoot, can, canAnyOrg }
}
