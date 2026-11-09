import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  createPricingEntry, deletePolicyPack, deletePricingEntry, getOrgCacheSettings, getOrgOriginalRetention,
  getOrgRegion, getOrgResidency, getOrgRoutingSettings, listA2aAgents,
  listMcpServers, listPolicyPacks, listPricing, updateA2aAgent, updateMcpServer,
  updateOrgCacheSettings, updateOrgOriginalRetention, updateOrgRegion, updateOrgResidency,
  updateOrgRoutingSettings, updatePricingEntry, upsertPolicyPack,
  pricingExportCsvUrl,
  type A2aAgent, type McpServer, type OrgCacheSettings, type OrgPolicyPack,
  type OrgOriginalRetention, type OrgRegionAssignment, type OrgResidency, type OrgRoutingSettings,
  type PricingEntry,
} from '../api/client'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'
import { useHashParam } from '../hooks/useHashParam'
import { usePermissions } from '../hooks/usePermissions'
import { formatDateTime } from '../i18n/format'
import { ProviderKeysSection } from './orgsettings/ProviderKeysSection'
import {
  CACHE_MODES, RESIDENCY_REGIONS, ROUTING_MODES, isCacheMode, isResidencyRegion,
  isRoutingMode, isRoutingThreshold, pricingPatch, type PricingDraft,
} from '../lib/orgSettings'

// AUX-24: organization settings as ONE screen with tabs over the EXISTING
// root-only APIs. Route facts this screen is built on (services/admin/
// handlers/router.go): cache-settings, routing, residency/policy-packs,
// region, MCP/A2A and pricing all sit under MustBeRoot, so the whole screen —
// nav entry included — is root-gated (AUX-13 semantics: UI convenience, the
// server stays the arbiter; when /api/me is unavailable the screen degrades
// to today's show-and-let-403 behavior).
//
// Honesty rules:
//  - every tab reads its own endpoints with loading/error/empty states; a
//    503 from a not-configured store or a 404 from an unmounted region
//    handler is surfaced as such, never hidden;
//  - the two overwriting PATCH contracts (cache-settings, routing) always
//    send the FULL pair — see client.ts;
//  - every mutating action runs through useAction/ActionDialog (AUX-12) and
//    dialogs collect an operator reason (AUX-14b) sent as X-Audit-Reason;
//  - the org spend alert is NOT duplicated here: it is managed on the
//    Budgets & alerts screen (AUX-15), so the Alerts tab is an honest pointer.
//
// FIX-06 (CA-07): the whole settings body below is mounted under key={org}.
// An org switch unmounts EVERYTHING scope-bound — per-endpoint data, action
// closures, open dialogs, the undo toast, form drafts — aborts the in-flight
// reads, and mounts a fresh body that fetches the new org before anything is
// actionable. The screen can therefore never submit one organization's
// settings to another: pre-fix, org A's panel stayed actionable while org B's
// data was in flight, and a click in that window PATCHed org A's values to
// org B (the TP-06 epoch guard only dropped the late response, not the stale
// state that was still being submitted).

type TabId = 'cache' | 'originals' | 'routing' | 'residency' | 'alerts' | 'integrations' | 'provider-keys' | 'pricing'

const TAB_IDS: TabId[] = ['cache', 'originals', 'routing', 'residency', 'alerts', 'integrations', 'provider-keys', 'pricing']

const TAB_LABEL_KEYS: Record<TabId, string> = {
  cache: 'orgSettings.tabCache',
  originals: 'orgSettings.tabOriginals',
  routing: 'orgSettings.tabRouting',
  residency: 'orgSettings.tabResidency',
  alerts: 'orgSettings.tabAlerts',
  integrations: 'orgSettings.tabIntegrations',
  'provider-keys': 'orgSettings.tabProviderKeys',
  pricing: 'orgSettings.tabPricing',
}

function errorOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Toggle chip: enabled state is shape + text + color, never color alone. */
function EnabledChip({ enabled, onLabel, offLabel }: { enabled: boolean; onLabel: string; offLabel: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden="true" style={{ color: enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
        {enabled ? '●' : '○'}
      </span>
      {enabled ? onLabel : offLabel}
    </span>
  )
}

export function OrgSettingsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const [tab, setTab] = useHashParam('tab')
  const org = orgId.trim()
  const perms = usePermissions(org || undefined)
  const isRoot = perms.isRoot
  // Fail-open (AUX-13): /api/me unavailable ≠ denial — render the tabs and
  // let the server arbitrate. While loading, stay fail-closed and quiet.
  const allowed = isRoot || perms.me === null
  const ready = !perms.loading && allowed
  const activeTab: TabId = (TAB_IDS as string[]).includes(tab) ? (tab as TabId) : 'cache'

  return (
    <div className="space-y-6">
      <PageHeader title={t('orgSettings.title')} purpose={t('orgSettings.purpose')} appliedScope={org || undefined} />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.orgId')}</span>
          <OrgSelect
            value={orgId}
            onChange={setOrgId}
            autoSelect
            className="sm:w-72"
            manualAriaLabel={t('orgSettings.orgUuid')}
          />
        </label>
      </div>

      {!org && <StateNotice state="not-loaded" message={t('orgSettings.notLoaded')} />}

      {org && perms.loading && <StateNotice state="loading" message={t('orgSettings.checkingRights')} />}

      {org && !perms.loading && !allowed && (
        <StateNotice state="empty" message={t('orgSettings.noAccess')} />
      )}

      {org && ready && <OrgSettingsBody key={org} org={org} activeTab={activeTab} onTab={setTab} />}
    </div>
  )
}

/**
 * One organization per mount (see the FIX-06 note above): `org` is a
 * constructor constant for this component — an org switch builds a fresh
 * instance, so no state or closure here can ever mix two organizations.
 */
function OrgSettingsBody({ org, activeTab, onTab }: { org: string; activeTab: TabId; onTab: (tab: string) => void }) {
  const { t } = useTranslation()

  // ----- per-endpoint data (null = not loaded / skipped) -----
  const [cache, setCache] = useState<OrgCacheSettings | null>(null)
  const [cacheError, setCacheError] = useState('')
  const [originalRetention, setOriginalRetention] = useState<OrgOriginalRetention | null>(null)
  const [originalRetentionError, setOriginalRetentionError] = useState('')
  const [routing, setRouting] = useState<OrgRoutingSettings | null>(null)
  const [routingError, setRoutingError] = useState('')
  const [residency, setResidency] = useState<OrgResidency | null>(null)
  const [residencyError, setResidencyError] = useState('')
  const [packs, setPacks] = useState<OrgPolicyPack[] | null>(null)
  const [packsError, setPacksError] = useState('')
  const [region, setRegion] = useState<OrgRegionAssignment | null>(null)
  const [regionError, setRegionError] = useState('')
  const [regionUnavailable, setRegionUnavailable] = useState(false)
  const [mcp, setMcp] = useState<McpServer[] | null>(null)
  const [mcpError, setMcpError] = useState('')
  const [a2a, setA2a] = useState<A2aAgent[] | null>(null)
  const [a2aError, setA2aError] = useState('')
  const [pricing, setPricing] = useState<PricingEntry[] | null>(null)
  const [pricingError, setPricingError] = useState('')
  const [loading, setLoading] = useState(false)

  // FIX-06 (CA-07): org binding is structural (the key={org} mount), so the
  // old TP-06 cross-org epoch is subsumed — an org switch unmounts this body
  // and aborts its reads. loadSeq only supersedes a slower earlier read of
  // the SAME org (a tab switch or a retry racing a slow response); the
  // aborted call's late answer must not overwrite the newer one.
  const loadSeq = useRef(0)
  const abortRef = useRef<AbortController | null>(null)

  const load = useCallback(async (which: TabId) => {
    if (!org) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const opts = { signal: ctrl.signal }
    loadSeq.current++
    const seen = { epoch: loadSeq.current }
    const live = () => loadSeq.current === seen.epoch
    setLoading(true)
    const runs: Array<Promise<void>> = []
    if (which === 'cache') {
      runs.push(
        getOrgCacheSettings(org, opts)
          .then(v => { if (live()) { setCache(v); setCacheError('') } })
          .catch((e: unknown) => { if (live()) { setCache(null); setCacheError(errorOf(e)) } }),
      )
    }
    if (which === 'originals') {
      runs.push(
        getOrgOriginalRetention(org, opts)
          .then(v => { if (live()) { setOriginalRetention(v); setOriginalRetentionError('') } })
          .catch((e: unknown) => { if (live()) { setOriginalRetention(null); setOriginalRetentionError(errorOf(e)) } }),
      )
    }
    if (which === 'routing') {
      runs.push(
        getOrgRoutingSettings(org, opts)
          .then(v => { if (live()) { setRouting(v); setRoutingError('') } })
          .catch((e: unknown) => { if (live()) { setRouting(null); setRoutingError(errorOf(e)) } }),
      )
    }
    if (which === 'residency') {
      runs.push(
        getOrgResidency(org, opts)
          .then(v => { if (live()) { setResidency(v); setResidencyError('') } })
          .catch((e: unknown) => { if (live()) { setResidency(null); setResidencyError(errorOf(e)) } }),
      )
      runs.push(
        listPolicyPacks(org, opts)
          .then(v => { if (live()) { setPacks(v); setPacksError('') } })
          .catch((e: unknown) => { if (live()) { setPacks(null); setPacksError(errorOf(e)) } }),
      )
      runs.push(
        getOrgRegion(org, opts)
          .then(v => { if (live()) { setRegion(v); setRegionError(''); setRegionUnavailable(false) } })
          .catch((e: unknown) => {
            if (!live()) return
            setRegion(null)
            // 404 = the region handler is not mounted on this deployment.
            setRegionUnavailable((e as { status?: number }).status === 404)
            setRegionError((e as { status?: number }).status === 404 ? '' : errorOf(e))
          }),
      )
    }
    if (which === 'integrations') {
      runs.push(
        listMcpServers(org, opts)
          .then(v => { if (live()) { setMcp(v); setMcpError('') } })
          .catch((e: unknown) => { if (live()) { setMcp(null); setMcpError(errorOf(e)) } }),
      )
      runs.push(
        listA2aAgents(org, opts)
          .then(v => { if (live()) { setA2a(v); setA2aError('') } })
          .catch((e: unknown) => { if (live()) { setA2a(null); setA2aError(errorOf(e)) } }),
      )
    }
    if (which === 'pricing') {
      runs.push(
        listPricing(opts)
          .then(v => { if (live()) { setPricing(v); setPricingError('') } })
          .catch((e: unknown) => { if (live()) { setPricing(null); setPricingError(errorOf(e)) } }),
      )
    }
    await Promise.allSettled(runs)
    if (live()) setLoading(false)
  }, [org])

  // Load the active tab on mount and re-load after org edits / tab switches
  // (org itself never changes within a mount — see key={org}).
  useEffect(() => {
    void load(activeTab)
    return () => { abortRef.current?.abort() }
  }, [activeTab, load])

  const reload = useCallback(() => { void load(activeTab) }, [activeTab, load])

  // ----- actions (AUX-12 contract; reasons ride X-Audit-Reason, AUX-14b) -----

  const cacheToggleAction = useAction({ id: 'orgSettings.cache.toggle', risk: 'low', reversible: true })
  const originalRetentionAction = useAction({ id: 'orgSettings.originalRetention.toggle', risk: 'high', reversible: true })
  const cacheModeAction = useAction({ id: 'orgSettings.cache.mode', risk: 'medium', reversible: true })
  const routeModeAction = useAction({ id: 'orgSettings.routing.mode', risk: 'medium', reversible: true })
  const routeThresholdAction = useAction({ id: 'orgSettings.routing.threshold', risk: 'medium', reversible: true })
  const residencyAction = useAction({ id: 'orgSettings.residency.set', risk: 'medium', reversible: true })
  const packToggleAction = useAction({ id: 'orgSettings.pack.toggle', risk: 'low', reversible: true })
  const packAddAction = useAction({ id: 'orgSettings.pack.add', risk: 'medium', reversible: true })
  const packRemoveAction = useAction({ id: 'orgSettings.pack.remove', risk: 'high', reversible: false })
  const regionHomeAction = useAction({ id: 'orgSettings.region.home', risk: 'medium', reversible: true })
  const regionPinAction = useAction({ id: 'orgSettings.region.pin', risk: 'low', reversible: true })
  const mcpToggleAction = useAction({ id: 'orgSettings.mcp.toggle', risk: 'low', reversible: true })
  const a2aToggleAction = useAction({ id: 'orgSettings.a2a.toggle', risk: 'low', reversible: true })
  const pricingDeleteAction = useAction({ id: 'orgSettings.pricing.delete', risk: 'high', reversible: false })

  const toggleCache = useCallback(() => {
    if (!cache) return
    const next = !cache.cache_enabled
    cacheToggleAction.run({
      confirmLabel: t(next ? 'orgSettings.cacheEnable' : 'orgSettings.cacheDisable'),
      execute: async () => {
        // The PATCH overwrites BOTH fields — the current mode rides along.
        await updateOrgCacheSettings(org, { cache_enabled: next, cache_mode: cache.cache_mode })
      },
      undo: async () => {
        await updateOrgCacheSettings(org, { cache_enabled: cache.cache_enabled, cache_mode: cache.cache_mode })
      },
      onDone: reload,
    })
  }, [cache, cacheToggleAction, org, reload, t])

  const toggleOriginalRetention = useCallback(() => {
    if (!originalRetention) return
    const next = !originalRetention.effective_enabled
    originalRetentionAction.run({
      confirmLabel: t(next ? 'orgSettings.originalsEnable' : 'orgSettings.originalsDisable'),
      execute: async () => { await updateOrgOriginalRetention(org, next) },
      undo: async () => { await updateOrgOriginalRetention(org, originalRetention.enabled) },
      onDone: reload,
    })
  }, [org, originalRetention, originalRetentionAction, reload, t])

  const openCacheMode = useCallback(() => {
    if (!cache) return
    cacheModeAction.run({
      confirmLabel: t('orgSettings.cacheSaveMode'),
      was: cache.cache_mode,
      input: { label: t('orgSettings.cacheModeInput'), initial: cache.cache_mode },
      reason: {},
      execute: async ({ value, reason }) => {
        const mode = value.trim().toLowerCase()
        if (!isCacheMode(mode)) throw new Error(t('orgSettings.invalidMode', { modes: CACHE_MODES.join(', ') }))
        await updateOrgCacheSettings(
          org, { cache_enabled: cache.cache_enabled, cache_mode: mode }, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [cache, cacheModeAction, org, reload, t])

  const openRouteMode = useCallback(() => {
    if (!routing) return
    routeModeAction.run({
      confirmLabel: t('orgSettings.routingSaveMode'),
      was: routing.routing_mode,
      input: { label: t('orgSettings.routingModeInput'), initial: routing.routing_mode },
      reason: {},
      execute: async ({ value, reason }) => {
        const mode = value.trim().toLowerCase()
        if (!isRoutingMode(mode)) throw new Error(t('orgSettings.invalidMode', { modes: ROUTING_MODES.join(', ') }))
        await updateOrgRoutingSettings(
          org, { routing_mode: mode, routing_threshold_confidence: routing.routing_threshold_confidence },
          auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, reload, routeModeAction, routing, t])

  const openRouteThreshold = useCallback(() => {
    if (!routing) return
    routeThresholdAction.run({
      confirmLabel: t('orgSettings.routingSaveThreshold'),
      was: String(routing.routing_threshold_confidence),
      input: { label: t('orgSettings.routingThresholdInput'), initial: String(routing.routing_threshold_confidence) },
      reason: {},
      execute: async ({ value, reason }) => {
        const v = Number(value.trim())
        if (!isRoutingThreshold(v)) throw new Error(t('orgSettings.invalidThreshold'))
        await updateOrgRoutingSettings(
          org, { routing_mode: routing.routing_mode, routing_threshold_confidence: v }, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, reload, routeThresholdAction, routing, t])

  const openResidency = useCallback(() => {
    if (!residency) return
    residencyAction.run({
      confirmLabel: t('orgSettings.residencySave'),
      was: residency.residency_region || t('orgSettings.residencyNone'),
      input: { label: t('orgSettings.residencyInput'), initial: residency.residency_region },
      reason: {},
      execute: async ({ value, reason }) => {
        const region = value.trim().toUpperCase()
        if (region !== '' && !isResidencyRegion(region)) {
          throw new Error(t('orgSettings.invalidResidency', { regions: RESIDENCY_REGIONS.join(', ') }))
        }
        await updateOrgResidency(org, region, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, reload, residency, residencyAction, t])

  const togglePack = useCallback((pack: OrgPolicyPack) => {
    const next = !pack.enabled
    packToggleAction.run({
      confirmLabel: t(next ? 'orgSettings.packEnable' : 'orgSettings.packDisable'),
      execute: async () => {
        await upsertPolicyPack(org, pack.region, { pack_id: pack.pack_id, config: pack.config ?? {}, enabled: next })
      },
      undo: async () => {
        await upsertPolicyPack(org, pack.region, { pack_id: pack.pack_id, config: pack.config ?? {}, enabled: pack.enabled })
      },
      onDone: reload,
    })
  }, [org, packToggleAction, reload, t])

  const openPackAdd = useCallback(() => {
    packAddAction.run({
      confirmLabel: t('orgSettings.packAddSave'),
      was: t('orgSettings.packNone'),
      input: { label: t('orgSettings.packRegionInput'), initial: '' },
      reason: {},
      execute: async ({ value, reason }) => {
        const region = value.trim().toUpperCase()
        if (!isResidencyRegion(region)) {
          throw new Error(t('orgSettings.invalidResidency', { regions: RESIDENCY_REGIONS.join(', ') }))
        }
        // pkfix1 contract (review 98613b94): config is required non-null
        // JSON — {} = the pack's built-in rules; the server still defaults
        // the pack id per region (the form deliberately has no pack input).
        await upsertPolicyPack(org, region, { config: {}, enabled: true }, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, packAddAction, reload, t])

  const openPackRemove = useCallback((pack: OrgPolicyPack) => {
    packRemoveAction.run({
      entity: pack.pack_id || pack.region,
      confirmLabel: t('orgSettings.packRemove'),
      impact: <span>{t('orgSettings.packRemoveImpact', { region: pack.region })}</span>,
      reason: { required: true },
      execute: async ({ reason }) => {
        const id = pack.id
        if (!id) throw new Error(t('orgSettings.packNoId'))
        await deletePolicyPack(org, id, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, packRemoveAction, reload, t])

  const removePack = openPackRemove

  const openRegionHome = useCallback(() => {
    if (!region) return
    regionHomeAction.run({
      confirmLabel: t('orgSettings.regionSaveHome'),
      was: region.home_region,
      input: { label: t('orgSettings.regionHomeInput'), initial: region.home_region },
      reason: {},
      execute: async ({ value, reason }) => {
        const home = value.trim().toLowerCase()
        if (!home) throw new Error(t('orgSettings.invalidHome'))
        await updateOrgRegion(
          org, { home_region: home, residency_pinned: region.residency_pinned }, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [org, region, regionHomeAction, reload, t])

  const toggleRegionPin = useCallback(() => {
    if (!region) return
    const next = !region.residency_pinned
    regionPinAction.run({
      confirmLabel: t(next ? 'orgSettings.regionPin' : 'orgSettings.regionUnpin'),
      execute: async () => {
        await updateOrgRegion(org, { home_region: region.home_region, residency_pinned: next })
      },
      undo: async () => {
        await updateOrgRegion(org, { home_region: region.home_region, residency_pinned: region.residency_pinned })
      },
      onDone: reload,
    })
  }, [org, region, regionPinAction, reload, t])

  const toggleMcp = useCallback((server: McpServer) => {
    const next = !server.enabled
    mcpToggleAction.run({
      confirmLabel: t(next ? 'orgSettings.mcpEnable' : 'orgSettings.mcpDisable', { name: server.name }),
      execute: async () => { await updateMcpServer(org, server.name, { enabled: next }) },
      undo: async () => { await updateMcpServer(org, server.name, { enabled: server.enabled }) },
      onDone: reload,
    })
  }, [mcpToggleAction, org, reload, t])

  const toggleA2a = useCallback((agent: A2aAgent) => {
    const next = !agent.enabled
    a2aToggleAction.run({
      confirmLabel: t(next ? 'orgSettings.a2aEnable' : 'orgSettings.a2aDisable', { name: agent.name }),
      execute: async () => { await updateA2aAgent(org, agent.name, { enabled: next }) },
      undo: async () => { await updateA2aAgent(org, agent.name, { enabled: agent.enabled }) },
      onDone: reload,
    })
  }, [a2aToggleAction, org, reload, t])

  const openPricingDelete = useCallback((entry: PricingEntry) => {
    pricingDeleteAction.run({
      entity: entry.model,
      confirmLabel: t('orgSettings.pricingDelete'),
      impact: <span>{t('orgSettings.pricingDeleteImpact', { model: entry.model, provider: entry.provider })}</span>,
      reason: { required: true },
      execute: async ({ reason }) => {
        await deletePricingEntry(entry.id, auditReasonOpts(reason))
      },
      onDone: reload,
    })
  }, [pricingDeleteAction, reload, t])

  // ----- pricing create + inline edit (plain forms, OrgsPage/RulesPage precedent) -----
  const [creating, setCreating] = useState(false)
  const [createForm, setCreateForm] = useState({ provider: '', model: '', input_per_m: '', output_per_m: '', cache_write_per_m: '', cache_read_per_m: '' })
  const [createError, setCreateError] = useState('')
  const [editingId, setEditingId] = useState<number | null>(null)
  const [editDraft, setEditDraft] = useState<PricingDraft>({ input_per_m: '', output_per_m: '', cache_write_per_m: '', cache_read_per_m: '' })
  const [editError, setEditError] = useState('')

  const submitCreate = useCallback(async () => {
    setCreateError('')
    const priceOf = (raw: string, label: string): number => {
      const v = Number(raw.trim())
      if (!Number.isFinite(v) || v < 0) throw new Error(t('orgSettings.invalidPrice', { field: label }))
      return v
    }
    try {
      const body = {
        provider: createForm.provider.trim(),
        model: createForm.model.trim(),
        input_per_m: priceOf(createForm.input_per_m, t('orgSettings.colInput')),
        output_per_m: priceOf(createForm.output_per_m, t('orgSettings.colOutput')),
        cache_write_per_m: priceOf(createForm.cache_write_per_m, t('orgSettings.colCacheW')),
        cache_read_per_m: priceOf(createForm.cache_read_per_m, t('orgSettings.colCacheR')),
      }
      if (!body.provider || !body.model) throw new Error(t('orgSettings.pricingProviderModelRequired'))
      setCreating(true)
      await createPricingEntry(body)
      setCreateForm({ provider: '', model: '', input_per_m: '', output_per_m: '', cache_write_per_m: '', cache_read_per_m: '' })
      reload()
    } catch (e: unknown) {
      setCreateError(errorOf(e))
    } finally {
      setCreating(false)
    }
  }, [createForm, reload, t])

  const startEdit = useCallback((entry: PricingEntry) => {
    setEditError('')
    setEditingId(entry.id)
    setEditDraft({
      input_per_m: String(entry.input_per_m),
      output_per_m: String(entry.output_per_m),
      cache_write_per_m: String(entry.cache_write_per_m),
      cache_read_per_m: String(entry.cache_read_per_m),
    })
  }, [])

  const submitEdit = useCallback(async (entry: PricingEntry) => {
    setEditError('')
    const parsed = pricingPatch(editDraft, entry)
    if (!parsed.ok) {
      setEditError(t('orgSettings.invalidPriceValues'))
      return
    }
    if (Object.keys(parsed.patch).length === 0) {
      setEditingId(null) // nothing changed — no PUT
      return
    }
    try {
      await updatePricingEntry(entry.id, parsed.patch)
      setEditingId(null)
      reload()
    } catch (e: unknown) {
      setEditError(errorOf(e))
    }
  }, [editDraft, reload, t])

  const editing = editingId != null

  // ----- tables -----

  const num = (v: number) => (
    <span style={{ fontVariantNumeric: 'tabular-nums' }}>{v.toFixed(6)}</span>
  )

  const pricingColumns: DataTableColumn<PricingEntry>[] = [
    { key: 'model', header: t('orgSettings.colModel'), type: 'text', getSortValue: r => r.model, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.model}</span> },
    { key: 'provider', header: t('orgSettings.colProvider'), type: 'text', getSortValue: r => r.provider },
    { key: 'input_per_m', header: t('orgSettings.colInput'), type: 'number', align: 'right', getSortValue: r => r.input_per_m, render: r => num(r.input_per_m) },
    { key: 'output_per_m', header: t('orgSettings.colOutput'), type: 'number', align: 'right', getSortValue: r => r.output_per_m, render: r => num(r.output_per_m) },
    { key: 'cache_write_per_m', header: t('orgSettings.colCacheW'), type: 'number', align: 'right', getSortValue: r => r.cache_write_per_m, render: r => num(r.cache_write_per_m) },
    { key: 'cache_read_per_m', header: t('orgSettings.colCacheR'), type: 'number', align: 'right', getSortValue: r => r.cache_read_per_m, render: r => num(r.cache_read_per_m) },
    {
      key: 'effective_from', header: t('orgSettings.colEffective'), type: 'text',
      getSortValue: r => r.effective_from,
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(r.effective_from)}</span>,
    },
  ]

  const mcpColumns: DataTableColumn<McpServer>[] = [
    { key: 'name', header: t('orgSettings.colName'), type: 'text', getSortValue: r => r.name, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.name}</span> },
    { key: 'url', header: 'URL', type: 'text', getSortValue: r => r.url, render: r => <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{r.url}</span> },
    { key: 'transport', header: t('orgSettings.colTransport'), type: 'text', getSortValue: r => r.transport },
    {
      key: 'tools', header: t('orgSettings.colTools'), type: 'number', align: 'right',
      getSortValue: r => r.allowed_tools?.length ?? 0,
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.allowed_tools?.length ?? 0}</span>,
    },
    {
      key: 'enabled', header: t('orgSettings.colEnabled'), type: 'text',
      getSortValue: r => (r.enabled ? '1' : '0'),
      render: r => <EnabledChip enabled={r.enabled} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />,
    },
  ]

  const a2aColumns: DataTableColumn<A2aAgent>[] = [
    { key: 'name', header: t('orgSettings.colName'), type: 'text', getSortValue: r => r.name, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.name}</span> },
    { key: 'url', header: 'URL', type: 'text', getSortValue: r => r.url, render: r => <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{r.url}</span> },
    {
      key: 'enabled', header: t('orgSettings.colEnabled'), type: 'text',
      getSortValue: r => (r.enabled ? '1' : '0'),
      render: r => <EnabledChip enabled={r.enabled} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />,
    },
  ]

  const packColumns: DataTableColumn<OrgPolicyPack>[] = [
    { key: 'region', header: t('orgSettings.colRegion'), type: 'text', getSortValue: r => r.region, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.region}</span> },
    { key: 'pack_id', header: t('orgSettings.colPack'), type: 'text', getSortValue: r => r.pack_id, render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.pack_id}</span> },
    { key: 'version', header: t('orgSettings.colVersion'), type: 'number', align: 'right', getSortValue: r => r.version ?? 0, render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.version ?? 0}</span> },
    {
      key: 'enabled', header: t('orgSettings.colEnabled'), type: 'text',
      getSortValue: r => (r.enabled ? '1' : '0'),
      render: r => <EnabledChip enabled={r.enabled} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />,
    },
  ]

  const rowBtnCls =
    'rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50'
  const rowBtnQuietCls =
    'rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)] disabled:opacity-50'

  const inputCls = 'control w-full min-w-0'

  // ----- render -----

  return (
    <>
      <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('orgSettings.title')}>
        {TAB_IDS.map(id => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={activeTab === id}
            onClick={() => onTab(id)}
            className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${
              activeTab === id
                ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
                : 'border-[color:var(--astra-rule-strong)] hover:bg-[color:var(--astra-surface-muted)]'
            }`}
          >
            {t(TAB_LABEL_KEYS[id])}
          </button>
        ))}
      </div>

      {/* ===== Cache ===== */}
      {activeTab === 'cache' && (
        <section aria-labelledby="orgsettings-cache-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-cache-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.cacheTitle')}</h2>
          {cacheError ? (
            <StateNotice state="error" message={cacheError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : cache ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.cacheEnabledLabel')}: </span>
                  <EnabledChip enabled={cache.cache_enabled} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.cacheModeLabel')}: </span>
                  <span style={{ fontFamily: 'var(--astra-font-code)' }}>{cache.cache_mode}</span>
                </span>
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.cacheNote')}</p>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={toggleCache}>
                  {t(cache.cache_enabled ? 'orgSettings.cacheDisable' : 'orgSettings.cacheEnable')}
                </button>
                <button type="button" className="btn-secondary" onClick={openCacheMode}>{t('orgSettings.cacheChangeMode')}</button>
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('orgSettings.cacheLoading')} />
          )}
        </section>
      )}

      {activeTab === 'originals' && (
        <section aria-labelledby="orgsettings-originals-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-originals-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.originalsTitle')}</h2>
          {originalRetentionError ? (
            <StateNotice state="error" message={originalRetentionError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : originalRetention ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.originalsState')}: </span>
                <EnabledChip enabled={originalRetention.effective_enabled} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />
                {originalRetention.inherited && <span className="ml-2 text-[color:var(--astra-text-muted)]">{t('orgSettings.originalsInherited')}</span>}
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.originalsNote')}</p>
              <button type="button" className="btn-secondary self-start" onClick={toggleOriginalRetention}>
                {t(originalRetention.effective_enabled ? 'orgSettings.originalsDisable' : 'orgSettings.originalsEnable')}
              </button>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('orgSettings.originalsLoading')} />
          )}
        </section>
      )}

      {/* ===== Routing ===== */}
      {activeTab === 'routing' && (
        <section aria-labelledby="orgsettings-routing-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-routing-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.routingTitle')}</h2>
          {routingError ? (
            <StateNotice state="error" message={routingError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : routing ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.routingModeLabel')}: </span>
                  <span style={{ fontFamily: 'var(--astra-font-code)' }}>{routing.routing_mode}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.routingThresholdLabel')}: </span>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>{routing.routing_threshold_confidence}</span>
                </span>
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.routingNote')}</p>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={openRouteMode}>{t('orgSettings.routingChangeMode')}</button>
                <button type="button" className="btn-secondary" onClick={openRouteThreshold}>{t('orgSettings.routingChangeThreshold')}</button>
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('orgSettings.routingLoading')} />
          )}
        </section>
      )}

      {/* ===== Residency & region ===== */}
      {activeTab === 'residency' && (
        <section aria-labelledby="orgsettings-residency-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-residency-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.residencyTitle')}</h2>
          {residencyError ? (
            <StateNotice state="error" message={residencyError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : residency ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.residencyLabel')}: </span>
                  {residency.residency_region
                    ? <span style={{ fontFamily: 'var(--astra-font-code)' }}>{residency.residency_region}</span>
                    : <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.residencyNone')}</span>}
                </span>
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.residencyNote')}</p>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={openResidency}>{t('orgSettings.residencyChange')}</button>
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('orgSettings.residencyLoading')} />
          )}

          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.packsTitle')}</h3>
          {packsError ? (
            <StateNotice state="error" message={packsError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : (
            <DataTable
              columns={packColumns}
              rows={packs ?? []}
              getRowId={r => r.id ?? `${r.region}:${r.pack_id}`}
              loading={packs === null && loading}
              empty={t('orgSettings.packsEmpty')}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              caption={t('orgSettings.packsCaption')}
              renderActions={r => (
                <span className="flex flex-wrap gap-1.5">
                  <button type="button" className={rowBtnCls} onClick={() => togglePack(r)}>
                    {t(r.enabled ? 'orgSettings.packDisable' : 'orgSettings.packEnable')}
                  </button>
                  <button type="button" className={rowBtnQuietCls} onClick={() => removePack(r)}>{t('orgSettings.packRemove')}</button>
                </span>
              )}
            />
          )}
          <div>
            <button type="button" className="btn-secondary" onClick={openPackAdd}>{t('orgSettings.packAdd')}</button>
          </div>

          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.regionTitle')}</h3>
          {regionError ? (
            <StateNotice state="error" message={regionError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : regionUnavailable ? (
            <StateNotice state="partial" message={t('orgSettings.regionUnavailable')} />
          ) : region ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.regionHomeLabel')}: </span>
                  <span style={{ fontFamily: 'var(--astra-font-code)' }}>{region.home_region}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.regionPinnedLabel')}: </span>
                  <EnabledChip enabled={region.residency_pinned} onLabel={t('orgSettings.on')} offLabel={t('orgSettings.off')} />
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={openRegionHome}>{t('orgSettings.regionChangeHome')}</button>
                <button type="button" className="btn-secondary" onClick={toggleRegionPin}>
                  {t(region.residency_pinned ? 'orgSettings.regionUnpin' : 'orgSettings.regionPin')}
                </button>
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('orgSettings.regionLoading')} />
          )}
        </section>
      )}

      {/* ===== Alerts (pointer — spend alert lives on Budgets & alerts) ===== */}
      {activeTab === 'alerts' && (
        <section aria-labelledby="orgsettings-alerts-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-alerts-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.alertsTitle')}</h2>
          <div className="astra-panel flex flex-col gap-3 p-4">
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.alertsNote')}</p>
            <a href={`#budgets?org=${encodeURIComponent(org)}`} className="btn-secondary w-fit">{t('orgSettings.alertsOpenBudgets')}</a>
          </div>
        </section>
      )}

      {/* ===== Integrations (MCP / A2A) ===== */}
      {activeTab === 'integrations' && (
        <section aria-labelledby="orgsettings-integrations-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-integrations-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.integrationsTitle')}</h2>

          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.mcpTitle')}</h3>
          {mcpError ? (
            <StateNotice state="error" message={mcpError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : (
            <DataTable
              columns={mcpColumns}
              rows={mcp ?? []}
              getRowId={r => r.id || r.name}
              loading={mcp === null && loading}
              empty={t('orgSettings.mcpEmpty')}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              caption={t('orgSettings.mcpCaption')}
              renderActions={r => (
                <button type="button" className={rowBtnCls} onClick={() => toggleMcp(r)}>
                  {t(r.enabled ? 'orgSettings.mcpDisable' : 'orgSettings.mcpEnable', { name: r.name })}
                </button>
              )}
            />
          )}

          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.a2aTitle')}</h3>
          {a2aError ? (
            <StateNotice state="error" message={a2aError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : (
            <DataTable
              columns={a2aColumns}
              rows={a2a ?? []}
              getRowId={r => r.id || r.name}
              loading={a2a === null && loading}
              empty={t('orgSettings.a2aEmpty')}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              caption={t('orgSettings.a2aCaption')}
              renderActions={r => (
                <button type="button" className={rowBtnCls} onClick={() => toggleA2a(r)}>
                  {t(r.enabled ? 'orgSettings.a2aDisable' : 'orgSettings.a2aEnable', { name: r.name })}
                </button>
              )}
            />
          )}
        </section>
      )}

      {/* ===== Provider keys (W-BYOK: org provider credentials) ===== */}
      {activeTab === 'provider-keys' && <ProviderKeysSection org={org} />}

      {/* ===== Pricing ===== */}
      {activeTab === 'pricing' && (
        <section aria-labelledby="orgsettings-pricing-title" className="flex flex-col gap-3">
          <h2 id="orgsettings-pricing-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.pricingTitle')}</h2>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('orgSettings.pricingNote')}</p>

          <div className="card flex flex-col gap-3 p-4">
            <h3 className="text-sm font-semibold text-[color:var(--astra-ink)]">{t('orgSettings.pricingCreate')}</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.colProvider')}</span>
                <input className={inputCls} value={createForm.provider} onChange={e => setCreateForm(f => ({ ...f, provider: e.target.value }))} autoComplete="off" />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('orgSettings.colModel')}</span>
                <input className={inputCls} value={createForm.model} onChange={e => setCreateForm(f => ({ ...f, model: e.target.value }))} autoComplete="off" />
              </label>
              {(['input_per_m', 'output_per_m', 'cache_write_per_m', 'cache_read_per_m'] as const).map((field, i) => (
                <label key={field} className="flex flex-col gap-1 text-sm">
                  <span className="text-[color:var(--astra-text-muted)]">{[t('orgSettings.colInput'), t('orgSettings.colOutput'), t('orgSettings.colCacheW'), t('orgSettings.colCacheR')][i]}</span>
                  <input
                    className={inputCls}
                    inputMode="decimal"
                    value={createForm[field]}
                    onChange={e => setCreateForm(f => ({ ...f, [field]: e.target.value }))}
                    autoComplete="off"
                  />
                </label>
              ))}
            </div>
            {createError && <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }}>{t('actions.errorLabel')}: {createError}</p>}
            <div>
              <button type="button" className="btn-primary" onClick={() => void submitCreate()} disabled={creating}>{t('orgSettings.pricingCreateSave')}</button>
            </div>
          </div>

          {pricingError ? (
            <StateNotice state="error" message={pricingError} action={{ label: t('common.retry'), onClick: reload }} />
          ) : (
            <DataTable
              columns={pricingColumns}
              rows={pricing ?? []}
              getRowId={r => String(r.id)}
              loading={pricing === null && loading}
              empty={t('orgSettings.pricingEmpty')}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              caption={t('orgSettings.pricingCaption')}
              renderExpanded={r => editingId === r.id && (
                <div className="flex flex-col gap-2 p-3">
                  <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                    {(['input_per_m', 'output_per_m', 'cache_write_per_m', 'cache_read_per_m'] as const).map((field, i) => (
                      <label key={field} className="flex flex-col gap-1 text-sm">
                        <span className="text-[color:var(--astra-text-muted)]">{[t('orgSettings.colInput'), t('orgSettings.colOutput'), t('orgSettings.colCacheW'), t('orgSettings.colCacheR')][i]}</span>
                        <input
                          className={inputCls}
                          inputMode="decimal"
                          value={editDraft[field]}
                          onChange={e => setEditDraft(d => ({ ...d, [field]: e.target.value }))}
                          autoComplete="off"
                        />
                      </label>
                    ))}
                  </div>
                  {editError && <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }}>{t('actions.errorLabel')}: {editError}</p>}
                  <div className="flex gap-2">
                    <button type="button" className="btn-primary" onClick={() => void submitEdit(r)}>{t('common.save')}</button>
                    <button type="button" className="btn-secondary" onClick={() => setEditingId(null)}>{t('common.cancel')}</button>
                  </div>
                </div>
              )}
              renderActions={r => (
                <span className="flex flex-wrap gap-1.5">
                  <button type="button" className={rowBtnCls} disabled={editing} onClick={() => startEdit(r)}>{t('common.edit')}</button>
                  <button type="button" className={rowBtnQuietCls} onClick={() => openPricingDelete(r)}>{t('orgSettings.pricingDelete')}</button>
                </span>
              )}
            />
          )}
          <div>
            <a href={pricingExportCsvUrl()} className="btn-secondary w-fit" download>{t('orgSettings.pricingExportCsv')}</a>
          </div>
        </section>
      )}

      {cacheToggleAction.ui}
      {cacheModeAction.ui}
      {routeModeAction.ui}
      {routeThresholdAction.ui}
      {residencyAction.ui}
      {packToggleAction.ui}
      {packAddAction.ui}
      {packRemoveAction.ui}
      {regionHomeAction.ui}
      {regionPinAction.ui}
      {mcpToggleAction.ui}
      {a2aToggleAction.ui}
      {pricingDeleteAction.ui}
    </>
  )
}
