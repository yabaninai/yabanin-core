// Resolve the applied org's presentation settings (currency +
// timezone) so any screen can render amounts/dates in the org's currency and
// timezone. The org list is fetched once and cached; passing no `orgId`
// yields the safe defaults (USD / UTC / current UI locale).

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listOrganizations, type Organization } from '../api/client'
// The hook returns raw currency/timezone strings; the page's
// formatMoney/formatNumber consume them.
import { DEFAULT_CURRENCY, DEFAULT_TIMEZONE } from './format'

export interface OrgPresentation {
  currency: string
  timezone: string
}

const EMPTY: OrgPresentation = { currency: DEFAULT_CURRENCY, timezone: DEFAULT_TIMEZONE }

// Module-level cache so the (lightweight) org list is fetched at most once per
// session across the many screens that resolve presentation.
let orgCache: Organization[] | null = null
let orgCachePromise: Promise<Organization[]> | null = null

function loadOrgs(): Promise<Organization[]> {
  if (orgCache) return Promise.resolve(orgCache)
  if (!orgCachePromise) {
    orgCachePromise = listOrganizations(1)
      .then((r) => {
        orgCache = r.data ?? []
        return orgCache
      })
      .catch(() => {
        orgCachePromise = null // allow retry on transient failure
        return []
      })
  }
  return orgCachePromise
}

/**
 * Returns the presentation settings for `orgId` (or defaults when `orgId` is
 * empty/unknown). Also re-renders on UI-locale change so a locale switch
 * re-formats everything.
 */
export function useOrgPresentation(orgId?: string): OrgPresentation {
  const { i18n } = useTranslation()
  const [orgs, setOrgs] = useState<Organization[] | null>(orgCache)

  useEffect(() => {
    let live = true
    loadOrgs().then((rows) => {
      if (live) setOrgs(rows)
    })
    return () => {
      live = false
    }
  }, [])

  // useTranslation() re-renders the caller on locale change, so the returned
  // presentation is recomputed for the active UI locale automatically; the
  // values themselves (currency/timezone) are locale-independent, so no extra
  // dependency is needed.
  void i18n

  return useMemo(() => {
    if (!orgId || !orgs) return EMPTY
    const org = orgs.find((o) => o.id === orgId || o.slug === orgId)
    if (!org) return EMPTY
    return {
      currency: org.currency && org.currency.length === 3 ? org.currency.toUpperCase() : DEFAULT_CURRENCY,
      timezone: org.timezone && org.timezone.length > 0 ? org.timezone : DEFAULT_TIMEZONE,
    }
  }, [orgId, orgs])
}

/**
 * Shared org-list hook for scope pickers. Backed by the same
 * module-level cache as useOrgPresentation, so mounting several pickers on
 * one screen still costs a single request. Returns `null` until loaded and
 * `[]` on failure; callers render their fallback (manual UUID input) then.
 */
export function useOrgs(): { orgs: Organization[] | null; reload: () => void } {
  const [orgs, setOrgs] = useState<Organization[] | null>(orgCache)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let live = true
    loadOrgs().then((rows) => {
      if (live) setOrgs(rows)
    })
    return () => {
      live = false
    }
  }, [nonce])

  // New orgs created elsewhere in the session are invisible to the module
  // cache; `reload` lets the caller force a refetch after mutations.
  const reload = useCallback(() => {
    orgCache = null
    orgCachePromise = null
    setNonce((n) => n + 1)
  }, [])

  return { orgs, reload }
}
