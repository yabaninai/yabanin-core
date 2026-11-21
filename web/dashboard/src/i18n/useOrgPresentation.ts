// Org presentation (currency + timezone) for any screen. A member's orgs —
// with presentation — come from /api/me alone; the root-only
// /api/organizations directory is fetched only when the caller may list it
// (root, or /api/me unavailable = fail-open) and never while the identity is
// still unknown, so a reader never fires the doomed directory 403. Root may
// resolve an org beyond directory page 1 through the supported single-org
// GET instead of defaulting. Display-only: the ledger stays USD (no FX).

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getOrganization, listOrganizations, type Organization } from '../api/client.ts'
import { requestMe, resetMeCache, type Me } from '../hooks/usePermissions.ts'
import { DEFAULT_CURRENCY, DEFAULT_TIMEZONE } from './defaults.ts'

export interface OrgPresentation {
  currency: string
  timezone: string
}

const EMPTY: OrgPresentation = { currency: DEFAULT_CURRENCY, timezone: DEFAULT_TIMEZONE }

/** Identity a cached org pool belongs to ('' = /api/me unavailable, fail-open). */
export function identityKey(me: Me | null): string {
  return me === null ? '' : me.id
}

/** Directory may be requested only once the identity is known (root or unavailable). */
export function wantDirectory(meLoading: boolean, me: Me | null): boolean {
  return !meLoading && (me === null || me.is_root)
}

/** Root-only single-org fallback may run only for a confirmed root identity. */
export function mayResolveDetail(meLoading: boolean, me: Me | null): boolean {
  return !meLoading && me !== null && me.is_root
}

// Identity-scoped, generation-guarded directory cache:
//   * rows/singles belong to one identity key; another identity never
//     reuses them;
//   * every commit checks identity AND generation, so a late completion
//     after a reset/identity switch is discarded, never written over the
//     new owner (mirrors the meGeneration guard in usePermissions);
//   * extra holds page-2+ singles resolved by id for a confirmed root.
interface DirectoryState {
  identity: string | null
  rows: Organization[] | null
  promise: Promise<Organization[]> | null
  extra: Map<string, Organization>
  // Shared in-flight single-org lookups: every concurrent consumer awaits
  // the SAME promise (a Set marker would hand later callers a resolved
  // null and hide the successful completion from their re-render).
  extraInflight: Map<string, Promise<Organization | null>>
}
let dirState: DirectoryState = { identity: null, rows: null, promise: null, extra: new Map(), extraInflight: new Map() }
let dirGeneration = 0

function freshDirectory(identity: string | null): DirectoryState {
  return { identity, rows: null, promise: null, extra: new Map(), extraInflight: new Map() }
}

/** Test seam: the committed directory state. */
export function directorySnapshot(): { identity: string | null; rows: Organization[] | null } {
  return { identity: dirState.identity, rows: dirState.rows }
}

/** Drop the listing + singles and retire every in-flight commit. */
export function resetDirectory(): void {
  dirGeneration++
  dirState = freshDirectory(null)
}

/** Fetch (or reuse) the identity-scoped directory listing. Test seam. */
export function beginDirectory(me: Me | null): Promise<Organization[]> {
  const identity = identityKey(me)
  const generation = dirGeneration
  if (dirState.identity !== identity) dirState = freshDirectory(identity)
  if (dirState.rows) return Promise.resolve(dirState.rows)
  if (dirState.promise) return dirState.promise
  const promise = listOrganizations(1)
    .then((r) => {
      const rows = r.data ?? []
      if (dirState.identity === identity && dirGeneration === generation) dirState.rows = rows
      return rows
    })
    .catch(() => {
      if (dirState.identity === identity && dirGeneration === generation) dirState.promise = null
      return []
    })
  dirState.promise = promise
  return promise
}

/** Committed single-org lookup for the identity owning the cache, by id or
 *  slug. Another identity (a member, a different root) never reads it. */
export function directoryExtraFor(me: Me, orgId: string): Organization | null {
  if (dirState.identity !== identityKey(me)) return null
  for (const org of dirState.extra.values()) {
    if (org.id === orgId || org.slug === orgId) return org
  }
  return null
}

/** Find an org in a pool by id or slug. */
export function findPoolOrg(orgs: Organization[] | null, orgId?: string): Organization | undefined {
  if (!orgId || !orgs) return undefined
  return orgs.find((o) => o.id === orgId || o.slug === orgId)
}

/**
 * Root-only authoritative fallback for an org the page-1 listing lacks: the
 * supported GET /api/organizations/{id}. Concurrent consumers share one
 * in-flight promise; commits only while identity/generation still match;
 * retired flights resolve null (no commit, no adoption); failures clear the
 * entry so a later attempt may retry. Test seam.
 */
export function beginOrgDetail(me: Me, orgId: string): Promise<Organization | null> {
  const identity = identityKey(me)
  const generation = dirGeneration
  if (dirState.identity !== identity) dirState = freshDirectory(identity)
  const known = directoryExtraFor(me, orgId)
  if (known) return Promise.resolve(known)
  const shared = dirState.extraInflight.get(orgId)
  if (shared) return shared
  const promise: Promise<Organization | null> = getOrganization(orgId)
    .then((org) => {
      // Retired flight: no commit, no adoption — mirrors requestMe.
      if (dirState.identity !== identity || dirGeneration !== generation) return null
      if (org?.id) dirState.extra.set(org.id, org)
      return org?.id ? org : null
    })
    .catch(() => null)
    .finally(() => {
      // Delete only our own entry: after a reset the whole state was
      // discarded, and after a retry a newer entry may already exist.
      if (dirState.identity === identity && dirGeneration === generation) {
        if (dirState.extraInflight.get(orgId) === promise) dirState.extraInflight.delete(orgId)
      }
    })
  dirState.extraInflight.set(orgId, promise)
  return promise
}

/** A member's own orgs mapped straight from the /api/me payload. */
export function memberOrgs(me: Me): Organization[] {
  return (me.organizations ?? []).map((o) => ({
    id: o.id,
    name: o.name,
    slug: o.slug ?? '',
    currency: o.currency,
    timezone: o.timezone,
  }))
}

/** Pure presentation resolution: pool hit with normalized authoritative
 *  values; USD/UTC defaults for unknown/unset. Test seam. */
export function resolveOrgPresentation(orgs: Organization[] | null, orgId?: string): OrgPresentation {
  const org = findPoolOrg(orgs, orgId)
  if (!org) return EMPTY
  return {
    currency: org.currency && org.currency.length === 3 ? org.currency.toUpperCase() : DEFAULT_CURRENCY,
    timezone: org.timezone && org.timezone.length > 0 ? org.timezone : DEFAULT_TIMEZONE,
  }
}

/** Pool the presentation memo resolves against: the loaded orgs plus (for
 *  the confirmed root identity that owns the cache) committed singles. */
export function presentationPool(orgs: Organization[] | null, me: Me | null, orgId?: string): Organization[] | null {
  if (!orgId || me === null || !me.is_root) return orgs
  const extra = directoryExtraFor(me, orgId)
  return extra ? [...(orgs ?? []), extra] : orgs
}

/**
 * Shared org-pool hook. Members: own orgs from /api/me. Root / unavailable:
 * the identity-scoped cached directory. `null` until loaded, `[]` on
 * failure/no memberships. Owns its /api/me state so reload refreshes a
 * mounted component's results (new memberships, fresh listing).
 */
function useOrgPoolCore(): { orgs: Organization[] | null; reload: () => void; me: Me | null; meLoading: boolean } {
  const [me, setMe] = useState<Me | null>(null)
  const [meLoading, setMeLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  // The committed listing carries its identity key; under any other key it
  // renders as not-yet-loaded (stale completions never surface).
  const [pool, setPool] = useState<{ key: string; rows: Organization[] | null }>({ key: '', rows: null })

  useEffect(() => {
    let alive = true
    void requestMe().then((result) => {
      if (!alive) return
      setMe(result)
      setMeLoading(false)
    })
    return () => {
      alive = false
    }
  }, [nonce])

  const key = identityKey(me)
  const wantList = wantDirectory(meLoading, me)

  useEffect(() => {
    if (!wantList) return
    let alive = true
    void beginDirectory(me).then((rows) => {
      if (alive) setPool({ key, rows })
    })
    return () => {
      alive = false
    }
  }, [wantList, key, me, nonce])

  const listed = pool.key === key ? pool.rows : null
  const orgs = useMemo(
    () => (me === null || me.is_root ? listed : memberOrgs(me)),
    [me, listed],
  )

  // New orgs created elsewhere are invisible to the caches; `reload` drops
  // both (with in-flight retirement) and refetches for the current identity.
  const reload = useCallback(() => {
    resetMeCache()
    resetDirectory()
    setMe(null)
    setMeLoading(true)
    setPool({ key: '', rows: null })
    setNonce((n) => n + 1)
  }, [])

  return { orgs, reload, me, meLoading }
}

/**
 * Returns the presentation settings for `orgId` (or defaults when `orgId` is
 * empty/unknown). Re-renders on UI-locale change so a locale switch
 * re-formats everything.
 */
export function useOrgPresentation(orgId?: string): OrgPresentation {
  const { i18n } = useTranslation()
  const { orgs, me, meLoading } = useOrgPoolCore()
  const [detailsVersion, setDetailsVersion] = useState(0)

  void i18n

  // Root-only page-2+ fallback: when the loaded pool cannot answer, resolve
  // the actual org record via the supported single-org GET instead of
  // defaulting. Members never fetch here (the detail route is root-only).
  useEffect(() => {
    const root = mayResolveDetail(meLoading, me) ? me : null
    if (!orgId || !root) return
    if (findPoolOrg(orgs, orgId) || directoryExtraFor(root, orgId)) return
    let alive = true
    void beginOrgDetail(root, orgId).then((org) => {
      if (alive && org) setDetailsVersion((v) => v + 1)
    })
    return () => {
      alive = false
    }
  }, [orgId, me, meLoading, orgs])

  return useMemo(() => {
    // detailsVersion re-computes when a shared single-org lookup commits.
    return resolveOrgPresentation(presentationPool(orgs, me, orgId), orgId)
  }, [orgs, me, orgId, detailsVersion])
}

/**
 * Shared org-list hook for scope pickers. Members list their own orgs;
 * root lists the directory. One request per source per session.
 */
export function useOrgs(): { orgs: Organization[] | null; reload: () => void } {
  const { orgs, reload } = useOrgPoolCore()
  return { orgs, reload }
}
