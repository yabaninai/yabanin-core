// W-WELCOME: pure helpers for the 3-step welcome flow (no DOM, no fetch —
// the React side lives in pages/OnboardingPage.tsx, the client in
// api/onboarding.ts).
//
// Step detection is DERIVED LIVE from the existing org-scoped APIs and never
// stored: (1) an org provider credential exists (provider-credentials list),
// (2) an ACTIVE gateway key exists (api-keys list — a revoked-only set does
// not count, same semantics as the OnboardingCard), (3) the org has seen a
// successful request (requests/stats: total > 0 AND success_rate > 0 — a
// stream of 5xx is not onboarding progress). Unknown (null) never counts as
// done: partial data must not produce "all set" (OnboardingCard precedent).

export type StepState = boolean | null // null = not yet determined / failed

export interface OnboardingSignals {
  providerKey: StepState
  gatewayKey: StepState
  firstRequest: StepState
}

export const ONBOARDING_CLIENTS = ['opencode', 'claude-code', 'codex'] as const
export type OnboardingClient = (typeof ONBOARDING_CLIENTS)[number]

export function isOnboardingClient(v: string): v is OnboardingClient {
  return (ONBOARDING_CLIENTS as readonly string[]).includes(v)
}

// UI-contract #1: the org scope rides the hash query, so a deep link opens
// the target screen pre-scoped to the org being onboarded. Step 1 deep-links
// the provider-keys tab of organization settings (W-BYOK-UI surface).
export function providerKeysLink(orgId: string): string {
  return `#org-settings?tab=provider-keys&org=${encodeURIComponent(orgId)}`
}

export function gatewayKeysLink(orgId: string): string {
  return `#keys?org=${encodeURIComponent(orgId)}`
}

export function allStepsDone(s: OnboardingSignals): boolean {
  return s.providerKey === true && s.gatewayKey === true && s.firstRequest === true
}

// Step detection decisions (design/wizard §2/§3 keep-contract): the exact
// live-signal → StepState rules, extracted from OnboardingPage so the state
// matrix is REAL-testable (the page effect feeds these the settled arms of
// the same three org-scoped reads and nothing else). Each helper answers the
// design's honest tri-state: true = confirmed done, false = confirmed to-do,
// null = unknown (read failed, old backend, shape drift) — unknown never
// reads as done, and a confirmed negative stays distinguishable from unknown.

export function providerKeyState(
  creds: PromiseSettledResult<{ length: number }>,
): StepState {
  // One credential is enough: the BYOK list endpoint only answers the
  // applied org, so an answered empty list PROVES none connected (to-do),
  // while a rejected read stays unknown.
  return creds.status === 'fulfilled' ? creds.value.length > 0 : null
}

export function gatewayKeyState(
  keys: PromiseSettledResult<{ data?: { active?: boolean }[] }>,
): StepState {
  if (keys.status !== 'fulfilled') return null
  // Active keys only — a revoked-only registry is not a working setup
  // (same semantics as the OnboardingCard). An answered list with no
  // active key is confirmed to-do, never unknown.
  return (keys.value.data ?? []).some(k => k.active === true)
}

/** The minimal stats shape step 3 needs; shape drift degrades to unknown. */
export interface RequestStatsShape {
  total_requests: number
  success_rate: number
}

export function isRequestStats(v: unknown): v is RequestStatsShape {
  if (typeof v !== 'object' || v === null) return false
  const s = v as Record<string, unknown>
  return typeof s.total_requests === 'number' && typeof s.success_rate === 'number'
}

export function firstRequestState(
  stats: PromiseSettledResult<unknown>,
): StepState {
  if (stats.status !== 'fulfilled') return null
  // Shape drift degrades to unknown (design/wizard §2 «stats failed or shape
  // drifted»), never to a confirmed to-do: a payload that lost its fields
  // proves nothing either way. Traffic with a 0% success rate, in turn, is
  // a confirmed negative — not a working setup.
  if (!isRequestStats(stats.value)) return null
  return stats.value.total_requests > 0 && stats.value.success_rate > 0
}

/**
 * The config block copied into the operator's client, verbatim from
 * docs/clients/{opencode,claude-code,codex}.md. The gateway address and the
 * yb_… key are placeholders on purpose: the dashboard cannot know the
 * deployment's gateway origin, and the raw key is never displayed back.
 */
export function clientConfigBlock(client: OnboardingClient): string {
  switch (client) {
    case 'opencode':
      return [
        'baseURL: https://gateway.example.internal/v1',
        'apiKey: yb_…',
      ].join('\n')
    case 'claude-code':
      return [
        "export ANTHROPIC_BASE_URL='https://gateway.example.internal'",
        "export ANTHROPIC_AUTH_TOKEN='yb_…'",
      ].join('\n')
    case 'codex':
      return [
        '# ~/.codex/config.toml',
        '[model_providers.yabanin]',
        'name = "Yabanin"',
        'base_url = "https://gateway.example.internal/v1"',
        'env_key = "YABANIN_API_KEY"',
        'wire_api = "responses"',
        '',
        "# environment (not the config file)",
        "export YABANIN_API_KEY='yb_…'",
      ].join('\n')
  }
}

/** Where "skip" / "go to dashboard" lands after the flow closes. */
export function dashboardHomeLink(isRoot: boolean): string {
  // Root operators land on the root-only Overview aggregate; members are
  // seated on the requests explorer — the first entry their rights allow in
  // the common reader case (the server arbitrates; the sidebar carries them
  // anywhere else).
  return isRoot ? '#overview' : '#requests-explorer'
}

//
// D1 "app-config + checklist"): the wizard mutates ONLY app config through
// EXISTING endpoints —
//   - privacy  → PUT /api/organizations/{id}/residency (region) and
//                PUT /api/organizations/{id}/policy-packs/{region}
//                (server defaults the pack id per region);
//   - security → POST /api/organizations/{id}/tool-policies/presets/{preset}
//                (preset application is idempotent-shaped: existing rows are
//                skipped, so a re-run after an interrupted apply is safe —
//                the resume story of the negative scenario);
//   - deployment → NO mutation: infra (DB/Redis/env) is pkg/config +
//     compose/helm territory; the deployment preset only picks the read-only
//     checklist shown on the review step.
// Both write surfaces are MustBeRoot today (router_mcp.go mountMCP,
// router_orgs.go mountOrgsRoot): non-root callers get the honest partial
// note instead of the flow, and the server still arbitrates every call.
//
// Like the 3-step flow above, the wizard derives its state LIVE (residency
// region read + tool-policy rows count) — nothing about the wizard persists
// in the onboarding flag, so a closed wizard re-opens to the same derived
// state and previously applied parts show done.

export const WIZARD_RESIDENCY_PRESETS = ['none', 'SG', 'IN', 'ID'] as const
export const WIZARD_SECURITY_PRESETS = ['open', 'network-readonly', 'network-off', 'internal-only'] as const
export const WIZARD_DEPLOYMENT_PRESETS = ['compose', 'helm', 'managed'] as const

export type WizardResidencyPreset = (typeof WIZARD_RESIDENCY_PRESETS)[number]
export type WizardSecurityPreset = (typeof WIZARD_SECURITY_PRESETS)[number]
export type WizardDeploymentPreset = (typeof WIZARD_DEPLOYMENT_PRESETS)[number]

export interface WizardSelection {
  residency: WizardResidencyPreset
  security: WizardSecurityPreset
  deployment: WizardDeploymentPreset
}

// Live-derived wizard signals (root-only reads today; null = unknown — the
// read failed or was not attempted for the caller's role). The pack signal
// is its OWN read (GET /policy-packs): residency never answers pack
// questions (AUDIT-P1-05 — a residency match is not proof the pack
// applied, and a failed pack write must not be masked by one).
export interface WizardSignals {
  residencyRegion: string | null
  toolPolicyCount: number | null
  /** Regions whose policy pack is CONFIRMED applied by the dedicated
      GET /policy-packs read (canonical pack_id, pack enabled); null = the
      read failed or was not attempted. */
  packRegions: string[] | null
}

export const DEFAULT_WIZARD_SELECTION: WizardSelection = {
  residency: 'none',
  security: 'open',
  deployment: 'compose',
}

/** Canonical pack per region — pinned to defaultPackID in
    services/admin/handlers/policy_pack_handlers.go (the wizard displays it
    on the review summary; the server still chooses the pack). */
export const REGION_PACK_IDS: Record<'SG' | 'IN' | 'ID', string> = {
  SG: 'sg_pdpa_mas',
  IN: 'in_dpdp_rbi',
  ID: 'id_pdp',
}

/** The live region mapped back onto the privacy radio ('' → none). */
export function wizardPresetFromRegion(region: string): WizardResidencyPreset {
  return (WIZARD_RESIDENCY_PRESETS as readonly string[]).includes(region) && region !== 'none'
    ? region as WizardResidencyPreset
    : 'none'
}

/** Minimal structural shape of one GET /policy-packs row the pack
    derivation reads (mirrors api/orgSettings OrgPolicyPack; this lib stays
    fetch-free and dependency-free). */
export interface WizardPackRow {
  region?: unknown
  pack_id?: unknown
  enabled?: unknown
}

/** Regions whose policy-pack row matches the wizard's claim: a row exists
    for the region, its pack_id is the region's canonical pack (the one the
    review summary shows and the apply sends), and the pack is not disabled.
    Rows that cannot prove the claim (unknown region, foreign pack_id,
    explicit enabled:false, malformed shape) are skipped. Only an explicit
    enabled:false disables: the server always marshals a boolean enabled, so
    an undefined one means contract drift, and this derivation treats it as
    enabled like any other non-false value — drift cases recover through the
    explicit apply/retry outcome, not a guess. */
export function wizardAppliedPackRegions(rows: readonly WizardPackRow[] | null | undefined): string[] {
  const applied: string[] = []
  for (const row of rows ?? []) {
    if (typeof row.region !== 'string' || typeof row.pack_id !== 'string') continue
    const canonical = REGION_PACK_IDS[row.region as 'SG' | 'IN' | 'ID']
    if (canonical === undefined || canonical !== row.pack_id) continue
    if (row.enabled === false) continue
    applied.push(row.region)
  }
  return applied
}

/** One explicit per-item result of the wizard's own apply run. */
export interface WizardApplyOutcome {
  ok: boolean
  detail?: string
}

/** Which state one apply-list row renders. An explicit mutation outcome is
    the authoritative evidence for this session's write (AUDIT-P1-05): a
    failed write is NEVER promoted to success by an indirect live signal,
    even when live reads applied — the row recovers only through retry,
    which produces a new explicit outcome. Live signals answer only when no
    outcome exists yet (the fresh resume display). */
export function wizardItemDisplayState(
  outcome: WizardApplyOutcome | undefined,
  live: boolean | null,
): { ok: boolean; failed: boolean } {
  if (outcome) return { ok: outcome.ok === true, failed: outcome.ok !== true }
  return { ok: live === true, failed: live === false }
}

/** One concrete change the review step lists and Apply performs. */
export type WizardPlanItem = { kind: 'residency' | 'pack' | 'preset'; id: string }

export function wizardPlanItemKey(item: WizardPlanItem): string {
  return `${item.kind}:${item.id}`
}

/** The ordered apply plan: 'none'/'open' selections contribute no writes
    (that IS the outcome the summary must state — «no change»). */
export function wizardPlan(s: WizardSelection): WizardPlanItem[] {
  const items: WizardPlanItem[] = []
  if (s.residency !== 'none') {
    items.push({ kind: 'residency', id: s.residency })
    items.push({ kind: 'pack', id: s.residency })
  }
  if (s.security !== 'open') items.push({ kind: 'preset', id: s.security })
  return items
}

/** Live state of one plan item: true = confirmed applied, false = confirmed
    not applied, null = unknown from live signals alone.
    - residency: the live region answers it exactly;
    - pack: only the DEDICATED policy-pack read answers it — residency never
      implies the pack (a residency match while the pack PUT failed is
      exactly the false-success AUDIT-P1-05 closed);
    - preset: zero tool policies PROVES not-applied; any rows leave the
      attribution unknown (any preset/policy may have created them) — the
      honest answer is null, and the review step shows the apply response
      (created/skipped counts) for in-session confirmation instead. */
export function wizardItemLiveState(item: WizardPlanItem, signals: WizardSignals): boolean | null {
  if (item.kind === 'residency') {
    if (signals.residencyRegion === null) return null
    return signals.residencyRegion === item.id
  }
  if (item.kind === 'pack') {
    if (signals.packRegions === null) return null
    return signals.packRegions.includes(item.id)
  }
  if (signals.toolPolicyCount === null) return null
  return signals.toolPolicyCount === 0 ? false : null
}

/** The whole plan is confirmed applied (drives the review step's done chip).
    An empty plan is trivially done — «no change» is a valid outcome. Any
    item unknown → unknown; any item confirmed missing → false. */
export function wizardPlanDone(plan: WizardPlanItem[], signals: WizardSignals): boolean | null {
  if (plan.length === 0) return true
  let anyNull = false
  for (const item of plan) {
    const state = wizardItemLiveState(item, signals)
    if (state === null) anyNull = true
    else if (state === false) return false
  }
  return anyNull ? null : true
}
