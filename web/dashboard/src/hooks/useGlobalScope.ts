// (lib/globalScope.ts) to the operator's identity (/api/me) and the org list.
//
// The Topbar OrgSwitcher renders THIS controller; every data screen keeps
// reading the same store via `useGlobalScope()` (re-exported here as the
// single future import for page cards). Behavior contract:
//   * The scope org/period still live in the hash (?org=&period=) — deep
//     links with an explicit ?org= always win and are never rewritten by the
//     auto-selection below.
//   * A member (non-root) is pinned to their own organizations: "All
//     organizations" is a root-only view, and an org the caller lost access
//     to falls back to their first membership.
//   * The only org is selected automatically (member: first membership; root:
//     when the directory lists exactly one org).
//   * The last committed org is remembered by lib/orgScope and adopted by the
//     store when the URL carries none.
//   * A root remembered org that resolves nowhere anymore (demo DB re-created)
//     is re-anchored once the directory is loaded: the single listed org, else
//     the "All organizations" view — instead of 404-ing every scoped request.
//
// The /api/organizations directory is fetched only when the caller may
// actually list it (root, or /api/me unavailable = fail-open). A member's
// options come from /api/me alone — no doomed directory request, no 403 noise.

import { useEffect, useMemo, useState } from 'react'
import { useGlobalScope as useScopeStore, type GlobalScopeApi } from '../lib/globalScope.ts'
import { listOrganizations, type Organization } from '../api/orgs.ts'
import { usePermissions } from './usePermissions.ts'

export { useGlobalScope } from '../lib/globalScope.ts'

export interface ScopeOrgOption {
  id: string
  name: string
}

function toOption(o: Pick<Organization, 'id' | 'name'>): ScopeOrgOption {
  return { id: o.id, name: o.name }
}

/**
 * Which org the shell should apply, given the scope, identity and URL.
 * Pure decision — unit-tested in useGlobalScope.test.ts.
 */
export function resolveScopeOrg(input: {
  /** ?org= present in the arriving URL (deep-link priority). */
  explicitInUrl: boolean
  /** Current store org (already includes the last-org memory fallback). */
  currentOrg: string
  /** /api/me has answered with a payload (not loading, not unavailable). */
  identityKnown: boolean
  isRoot: boolean
  /** The caller's own organizations from /api/me. */
  memberships: ScopeOrgOption[]
  /** The root directory listing (null = not loaded / not listable). */
  listedOrgs: ScopeOrgOption[] | null
}): string {
  if (input.explicitInUrl || !input.identityKnown) return input.currentOrg
  if (!input.isRoot) {
    if (input.memberships.length === 0) return input.currentOrg
    const ids = new Set(input.memberships.map(o => o.id))
    return ids.has(input.currentOrg) ? input.currentOrg : input.memberships[0]!.id
  }
  if (input.currentOrg) {
    // The remembered org survives only while it still resolves somewhere.
    // A LOADED directory (plus memberships) that lacks it — e.g. the demo
    // DB was re-created — must not leave root 404-storming: re-anchor to
    // the single listed org, else "All organizations". An unloaded
    // directory never guesses (no flicker while /api/organizations runs).
    const known = new Set([...input.memberships, ...(input.listedOrgs ?? [])].map(o => o.id))
    if (!known.has(input.currentOrg) && input.listedOrgs !== null && input.listedOrgs.length > 0) {
      return input.listedOrgs.length === 1 ? input.listedOrgs[0]!.id : ''
    }
    return input.currentOrg
  }
  if (input.listedOrgs && input.listedOrgs.length === 1) return input.listedOrgs[0]!.id
  return input.currentOrg
}

/** True when the current hash query carries an explicit ?org= param. */
export function orgParamInHash(): boolean {
  if (typeof window === 'undefined') return false
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q).has('org')
}

// Module-level directory cache — the same session-cache pattern as the org
// list in i18n/useOrgPresentation.ts (one request per session; a reload
// refetches). Read-only data: no invalidation beyond the module lifetime.
let orgList: ScopeOrgOption[] | null = null
let orgListPromise: Promise<ScopeOrgOption[]> | null = null

function loadOrgList(): Promise<ScopeOrgOption[]> {
  if (orgList) return Promise.resolve(orgList)
  if (!orgListPromise) {
    orgListPromise = listOrganizations(1)
      .then(r => {
        orgList = (r.data ?? []).map(toOption)
        return orgList
      })
      .catch(() => {
        orgListPromise = null // allow retry on transient failure
        return []
      })
  }
  return orgListPromise
}

export interface ShellScopeController extends GlobalScopeApi {
  /** Options for the OrgSwitcher (root: directory; member: own orgs). */
  options: ScopeOrgOption[]
  /** "All organizations" is offered only to root (fail-open without /api/me). */
  canAllOrgs: boolean
  /** Resolved display name of the current org ('' = all orgs / unknown). */
  orgName: string
  /** True when the current org id resolves to a known name. */
  orgKnown: boolean
  /** True while the option list is still loading. */
  orgsLoading: boolean
  isRoot: boolean
}

export function useShellScope(): ShellScopeController {
  const scope = useScopeStore()
  const perms = usePermissions()
  const identityKnown = !perms.loading && perms.me !== null
  // Stable identity for the effect deps: only the id/name pairs matter.
  const membershipsKey = (perms.me?.organizations ?? []).map(o => `${o.id}\u0000${o.name}`).join('\u0001')
  const memberships = useMemo<ScopeOrgOption[]>(
    () => (perms.me?.organizations ?? []).map(toOption),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [membershipsKey],
  )

  // The directory is requested only when the caller may list it at all —
  // a member's client never fires the root-only /api/organizations request.
  const wantList = !perms.loading && (perms.me === null || perms.isRoot)
  const [listed, setListed] = useState<ScopeOrgOption[] | null>(orgList)
  useEffect(() => {
    if (!wantList) return
    let alive = true
    void loadOrgList().then(rows => {
      if (alive) setListed(rows)
    })
    return () => {
      alive = false
    }
  }, [wantList])

  // Auto-selection (see resolveScopeOrg): commits at most once per input
  // change — the guard `target !== scope.org` makes the effect a no-op after
  // the store caught up.
  useEffect(() => {
    const target = resolveScopeOrg({
      explicitInUrl: orgParamInHash(),
      currentOrg: scope.org,
      identityKnown,
      isRoot: perms.isRoot,
      memberships,
      listedOrgs: wantList ? listed : null,
    })
    if (target !== scope.org) scope.setOrg(target)
  }, [identityKnown, perms.isRoot, memberships, wantList, listed, scope])

  const canAllOrgs = perms.me === null || perms.isRoot
  const options = useMemo<ScopeOrgOption[]>(() => {
    if (canAllOrgs) return listed ?? []
    return memberships
  }, [canAllOrgs, listed, memberships])

  const orgName = useMemo(() => {
    if (!scope.org) return ''
    const pool = [...memberships, ...(listed ?? [])]
    const hit = pool.find(o => o.id === scope.org)
    return hit?.name ?? ''
  }, [scope.org, memberships, listed])

  return {
    ...scope,
    options,
    canAllOrgs,
    orgName,
    orgKnown: Boolean(scope.org) && orgName !== '',
    orgsLoading: perms.loading || (canAllOrgs && listed === null),
    isRoot: perms.isRoot,
  }
}
