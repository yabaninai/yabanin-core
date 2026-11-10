import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { SessionGate } from './components/astra/SessionGate'
import {
  LayoutDashboard, DollarSign, BarChart3, ShieldCheck, Shield, Wallet, Upload,
  Building2,   KeyRound, Boxes, GitBranch, FileSearch,
  GitCompareArrows, ListTodo, Wrench,   ShieldAlert, TrendingUp, LayoutGrid, Tags, History, PiggyBank,
  KeySquare, Users, UserCog, Settings, Waypoints, Route, ThumbsUp, ScrollText, FileCode2, Blocks, Bot, FileEdit, PackageSearch, ReceiptText,
  Fingerprint, Radar, Workflow, Settings2 } from 'lucide-react'
import { ChunkErrorBoundary } from './components/ChunkErrorBoundary'
import { CommandPalette } from './components/astra/CommandPalette'
import { usePermissions } from './hooks/usePermissions'
import { useShellScope } from './hooks/useGlobalScope'
import { Topbar } from './components/shell/Topbar'
import { Sidebar, SidebarNav, type NavSectionView } from './components/shell/Sidebar'
import { Breadcrumbs } from './components/shell/Breadcrumbs'
import { loginNextUrl } from './api/transport'
import { VersionBanner } from './components/astra/VersionBanner'
import { ERRORS_ONLY_YQL, actionHref, type CommandOption } from './lib/commandPalette'
import { getOrgOnboarding } from './api/onboarding'
import { listOrganizations } from './api/orgs'
import { readLastOrg } from './lib/orgScope'

const OverviewPage = lazy(() => import('./pages/OverviewPage').then(m => ({ default: m.OverviewPage })))
const ClassifierPage = lazy(() => import('./pages/ClassifierPage').then(m => ({ default: m.ClassifierPage })))
const CachePage = lazy(() => import('./pages/CachePage').then(m => ({ default: m.CachePage })))
const CreditsPage = lazy(() => import('./pages/CreditsPage').then(m => ({ default: m.CreditsPage })))
const OrgsPage = lazy(() => import('./pages/OrgsPage').then(m => ({ default: m.OrgsPage })))
const KeysPage = lazy(() => import('./pages/KeysPage').then(m => ({ default: m.KeysPage })))
const AgentsPage = lazy(() => import('./pages/AgentsPage').then(m => ({ default: m.AgentsPage })))
const ModelsPage = lazy(() => import('./pages/models/ModelsPage').then(m => ({ default: m.ModelsPage })))
const RulesPage = lazy(() => import('./pages/rules/RulesPage').then(m => ({ default: m.RulesPage })))
const LineagePage = lazy(() => import('./pages/LineagePage').then(m => ({ default: m.LineagePage })))
const CostDashboard = lazy(() => import('./pages/CostDashboard'))
const ComparePage = lazy(() => import('./pages/ComparePage').then(m => ({ default: m.ComparePage })))
const ToolCallsPage = lazy(() => import('./pages/ToolCallsPage').then(m => ({ default: m.ToolCallsPage })))
const RequestExplorerPage = lazy(() => import('./pages/RequestExplorerPage').then(m => ({ default: m.RequestExplorerPage })))
const AnalyticsExplorerPage = lazy(() => import('./pages/AnalyticsExplorerPage').then(m => ({ default: m.AnalyticsExplorerPage })))
const DashboardsPage = lazy(() => import('./pages/DashboardsPage').then(m => ({ default: m.DashboardsPage })))
const TasksPage = lazy(() => import('./pages/TasksPage').then(m => ({ default: m.TasksPage })))
const ToolPolicyPage = lazy(() => import('./pages/ToolPolicyPage').then(m => ({ default: m.ToolPolicyPage })))
// OP-9: the policy decision log (Shadow→Enforce observability).
const PolicyDecisionsPage = lazy(() => import('./pages/PolicyDecisionsPage').then(m => ({ default: m.PolicyDecisionsPage })))
const PolicyEditorPage = lazy(() => import('./pages/PolicyEditorPage').then(m => ({ default: m.PolicyEditorPage })))
const PromptsPage = lazy(() => import('./pages/prompts/PromptsPage').then(m => ({ default: m.PromptsPage })))
const LabelPolicyPage = lazy(() => import('./pages/LabelPolicyPage').then(m => ({ default: m.LabelPolicyPage })))
// screen over the existing policy screens (no new backend endpoints).
const GuardrailsPage = lazy(() => import('./pages/GuardrailsPage').then(m => ({ default: m.GuardrailsPage })))
// N02-P08: the guard detector-pack lifecycle (list/validate/simulate/
// activate/rollback/status/audit over the root-only guard-pack API).
const GuardPacksPage = lazy(() => import('./pages/GuardPacksPage').then(m => ({ default: m.GuardPacksPage })))
const AuditLogPage = lazy(() => import('./pages/AuditLogPage').then(m => ({ default: m.AuditLogPage })))
const ExportsPage = lazy(() => import('./pages/ExportsPage').then(m => ({ default: m.ExportsPage })))
const BudgetsPage = lazy(() => import('./pages/BudgetsPage').then(m => ({ default: m.BudgetsPage })))
const ModelAccessPage = lazy(() => import('./pages/ModelAccessPage').then(m => ({ default: m.ModelAccessPage })))
const MembersPage = lazy(() => import('./pages/MembersPage').then(m => ({ default: m.MembersPage })))
const AdminUsersPage = lazy(() => import('./pages/AdminUsersPage').then(m => ({ default: m.AdminUsersPage })))
const OrgSettingsPage = lazy(() => import('./pages/OrgSettingsPage').then(m => ({ default: m.OrgSettingsPage })))
const RoutingMapPage = lazy(() => import('./pages/RoutingMapPage').then(m => ({ default: m.RoutingMapPage })))
const OnboardingPage = lazy(() => import('./pages/OnboardingPage').then(m => ({ default: m.OnboardingPage })))
// W-FEED: the owner (root-only) classifier-feedback list.
const FeedbackPage = lazy(() => import('./pages/FeedbackPage').then(m => ({ default: m.FeedbackPage })))
// MC-4: the MCP credentials lifecycle screen (server creds, grants, per-user rows).
const McpCredentialsPage = lazy(() => import('./pages/McpCredentialsPage').then(m => ({ default: m.McpCredentialsPage })))
// Currencies slice 2: committed reference rates catalog (read-only, any admin session).
const RatesPage = lazy(() => import('./pages/RatesPage').then(m => ({ default: m.RatesPage })))

type Page =
  | 'overview' | 'cost' | 'compare' | 'credits' | 'classifier' | 'cache' | 'feedback'
  | 'orgs' | 'keys' | 'agents' | 'models' | 'rules' | 'lineage'
  | 'requests-explorer' | 'analytics' | 'dashboards' | 'tool-calls' | 'tasks' | 'tool-policy' | 'policy-editor' | 'policy-decisions' | 'label-policy' | 'prompts'
  | 'guardrails'
  | 'guard-packs'
  | 'audit-log' | 'budgets' | 'model-access' | 'members' | 'admin-users' | 'org-settings' | 'exports' | 'routing-map'
  | 'mcp-credentials'
  | 'rates'
  // W-WELCOME: the welcome flow is a real route (deep-linkable from the
  // first-login redirect) but deliberately NOT a sidebar entry — it closes
  // itself via complete/skip.
  | 'onboarding'

// AUX-13: the server-side gate each screen's data actually sits behind, so
// nav entries without a path are hidden. rootOnly = the endpoints are under
// MustBeRoot today; anyOrg = org-scoped under RequireOrgPermission (any one
// of the listed permissions unlocks the screen). This is UI convenience only:
// the server stays the arbiter, and a deep link to a hidden page still
// renders (the API 403s if the caller truly lacks the right).
type NavAccess = {
  rootOnly?: boolean
  anyOrg?: string[]
  anyOrgRole?: string[]
  /** Server gate = any authenticated admin session (currencies brief §1:
      GET /api/rates/catalog has no org gate and no store dependency). */
  anySession?: boolean
}

// I18N-01: nav labels are i18next keys; they are resolved at render time
// (useTranslation), so the table stays data-only. `access` mirrors the
// server-side gate (AUX-13) — see the NavAccess comment for the honest map.
//
  // AUX-08: sections follow the plan's navigation table (ADMIN_UX_2026-09-30,
  // "Навигация"): Обзор / Исследование / Оптимизация / Лимиты и доступ /
  // Маршрутизация и политики / Администрирование. The screens of cards not yet
  // delivered (budgets center AUX-15, teams & members + model access AUX-16,
  // audit log AUX-14a, admin users, pricing) slot into these sections when they
  // land; today only the shipped screens are listed. Access gates are carried
  // over from AUX-13 unchanged.
  //
  // AUX-21: the command palette reuses this same table (and the same
  // navVisible access filter), so its page entries inherit exactly the rights
  // the sidebar shows — a command without the rights never appears.
  const NAV_SECTIONS: { labelKey: string; items: { id: Page; labelKey: string; icon: React.ReactNode; access: NavAccess }[] }[] = [
  {
    labelKey: 'app.sectionOverview',
    items: [
      // Overview/Cost read the global (root-only) aggregates today.
      { id: 'overview', labelKey: 'app.navOverview', icon: <LayoutDashboard size={16} />, access: { rootOnly: true } },
      { id: 'cost', labelKey: 'app.navCost', icon: <DollarSign size={16} />, access: { rootOnly: true } },
      // W-CRED: the credits wallet reads moved to the org-permission surface
      // (budgets.manage on the target org; root keeps the operator view).
      { id: 'credits', labelKey: 'app.navCredits', icon: <Wallet size={16} />, access: { anyOrg: ['budgets.manage'] } },
    ],
  },
  {
    labelKey: 'app.sectionExplore',
    items: [
      { id: 'requests-explorer', labelKey: 'app.navRequestsExplorer', icon: <FileSearch size={16} />, access: { anyOrg: ['requests.read'] } },
      { id: 'analytics', labelKey: 'app.navAnalytics', icon: <TrendingUp size={16} />, access: { anyOrg: ['analytics.read'] } },
      // root-only today (MustBeRoot on GET /api/organizations/{id}) — the
      // gate is rootOnly so analytics.read members are not shown a screen
      // that 403s on load. AUX-13's honest wart, closed on the UI side; an
      // org-scoped aggregate stays a decision request (server unchanged).
      { id: 'dashboards', labelKey: 'app.navDashboards', icon: <LayoutGrid size={16} />, access: { rootOnly: true } },
      { id: 'tasks', labelKey: 'app.navTasks', icon: <ListTodo size={16} />, access: { anyOrg: ['analytics.read'] } },
      { id: 'tool-calls', labelKey: 'app.navToolCalls', icon: <Wrench size={16} />, access: { rootOnly: true } },
      // FileSearch — indistinguishable in the nav and the palette).
      { id: 'lineage', labelKey: 'app.navLineage', icon: <Waypoints size={16} />, access: { anyOrg: ['lineage.read'] } },
      { id: 'compare', labelKey: 'app.navCompare', icon: <GitCompareArrows size={16} />, access: { rootOnly: true } },
    ],
  },
  {
    labelKey: 'app.sectionOptimization',
    items: [
      { id: 'cache', labelKey: 'app.navCache', icon: <ShieldCheck size={16} />, access: { rootOnly: true } },
      { id: 'classifier', labelKey: 'app.navClassifier', icon: <BarChart3 size={16} />, access: { rootOnly: true } },
      // W-FEED: the owner list of /v1/feedback records (root-only routes).
      { id: 'feedback', labelKey: 'app.navFeedback', icon: <ThumbsUp size={16} />, access: { rootOnly: true } },
    ],
  },
  {
    labelKey: 'app.sectionAccess',
    items: [
      // Keys covers API keys + agent keys (two org permissions); profiles are
      // root-only. AUX-15 budgets / AUX-16 teams & model access land here.
      { id: 'keys', labelKey: 'app.navApiKeys', icon: <KeyRound size={16} />, access: { anyOrg: ['keys.manage', 'agent_keys.manage'] } },
      // hint) and deep-links key creation — the keys gate floor; the config
      // generation itself is local and the test call goes browser→gateway.
      { id: 'agents', labelKey: 'app.navAgents', icon: <Bot size={16} />, access: { anyOrg: ['keys.manage', 'agent_keys.manage'] } },
      // AUX-15: budgets & alerts center — team budgets under budgets.manage
      // (agent budgets additionally need agent_keys.manage; the spend-alert
      // and credits sections gate on root inside the page).
      { id: 'budgets', labelKey: 'app.navBudgets', icon: <PiggyBank size={16} />, access: { anyOrg: ['budgets.manage', 'agent_keys.manage', 'analytics.read'] } },
      { id: 'exports', labelKey: 'app.navExports', icon: <Upload size={16} />, access: { anyOrg: ['budgets.read'] } },
      // AUX-16: whitelist/aliases/teams-listing routes are MustBeRoot today;
      // members/developers sit under the org-scoped members.manage.
      { id: 'model-access', labelKey: 'app.navModelAccess', icon: <KeySquare size={16} />, access: { rootOnly: true } },
      { id: 'members', labelKey: 'app.navMembers', icon: <Users size={16} />, access: { anyOrg: ['members.manage'] } },
    ],
  },
  {
    labelKey: 'app.sectionRouting',
    items: [
      // to the policy surfaces (tool-policy, rules, label-policy). The gate
      // is the FLOOR of the linked screens' gates (label-policy's
      // analytics.read): whoever sees the summary can open at least one of
      // its cards, and a viewer who can open none never sees the entry. The
      // screen fetches nothing; the server stays the arbiter behind every
      // link (the page pins the same gate map per card).
      { id: 'guardrails', labelKey: 'app.navGuardrails', icon: <Shield size={16} />, access: { anyOrg: ['analytics.read'] } },
      // N02-P08: the detector-pack lifecycle screen. Every endpoint it reads
      // (list/status) and mutates (validate/simulate/activate/rollback) sits
      // on the root-only guard mount (guardpacks.go MustBeRoot group), so the
      // gate is rootOnly — the UI hides no more than the server forbids.
      { id: 'guard-packs', labelKey: 'app.navGuardPacks', icon: <PackageSearch size={16} />, access: { rootOnly: true } },
      { id: 'models', labelKey: 'app.navModels', icon: <Boxes size={16} />, access: { rootOnly: true } },
      { id: 'rules', labelKey: 'app.navRoutingRules', icon: <GitBranch size={16} />, access: { rootOnly: true } },
      // org-side; root passes) and GET /api/providers/health
      // (analytics.read) — the map is the screen's headline content.
      { id: 'routing-map', labelKey: 'app.navRoutingMap', icon: <Route size={16} />, access: { anyOrg: ['routing.manage'] } },
      { id: 'tool-policy', labelKey: 'app.navToolPolicy', icon: <ShieldAlert size={16} />, access: { rootOnly: true } },
      // (mountPolicyPipelines → RequireOrgPermissionPoliciesManage); same
      // gate as the decision log below.
      { id: 'policy-editor', labelKey: 'app.navPolicyEditor', icon: <FileEdit size={16} />, access: { anyOrg: ['policies.manage'] } },
      // OP-9: the decision log reads under the same policies.manage gate as
      // the policies themselves (decisions show what policies did).
      { id: 'policy-decisions', labelKey: 'app.navPolicyDecisions', icon: <ScrollText size={16} />, access: { anyOrg: ['policies.manage'] } },
      // routes sit behind policies.manage verbatim).
      { id: 'prompts', labelKey: 'app.navPrompts', icon: <FileCode2 size={16} />, access: { anyOrg: ['policies.manage'] } },
      // Reading label-policy sits under analytics.read (writes need policies.manage).
      { id: 'label-policy', labelKey: 'app.navLabelPolicy', icon: <Tags size={16} />, access: { anyOrg: ['analytics.read'] } },
    ],
  },
  {
    labelKey: 'app.sectionAdmin',
    items: [
      // AUX-14a audit log / AUX-16 admin users land here next to orgs.
      { id: 'orgs', labelKey: 'app.navOrganizations', icon: <Building2 size={16} />, access: { rootOnly: true } },
      // the security_auditor org role (roles_authz.go globalAuditRole). The
      // nav mirrors the server from the org roles /api/me already serves, so
      // the UI hides no more than the server forbids (navGates INV-1).
      { id: 'audit-log', labelKey: 'app.navAuditLog', icon: <History size={16} />, access: { anyOrgRole: ['security_auditor'] } },
      { id: 'admin-users', labelKey: 'app.navAdminUsers', icon: <UserCog size={16} />, access: { rootOnly: true } },
      // AUX-24: organization settings — every tab endpoint (cache-settings,
      // routing, residency/policy-packs, region, MCP/A2A, pricing) is a
      // MustBeRoot route today (router.go), so the whole screen is root-gated.
      { id: 'org-settings', labelKey: 'app.navOrgSettings', icon: <Settings size={16} />, access: { rootOnly: true } },
      // MC-4: MCP credentials lifecycle — the credential/grant surfaces live
      // on the root-only MCP mount (router_mcp.go), same posture as org-settings.
      { id: 'mcp-credentials', labelKey: 'app.navMcpCredentials', icon: <Blocks size={16} />, access: { rootOnly: true } },
      // Currencies slice 2: reference rates catalog — readable by ANY admin
      // session (handler gate), so the nav item is anySession, not rootOnly.
      { id: 'rates', labelKey: 'app.navRates', icon: <ReceiptText size={16} />, access: { anySession: true } },
    ],
  },
]

// D-UI-2 (owner decision 2026-11-06): the Enterprise nav section is STATIC
// in core v1 — every item is always rendered locked (grey + lock icon,
// never hidden) and points at the EE app root /ee/, which owns the real
// routing. Core never decides entitlement: there is deliberately NO runtime
// entitlement detection here (none may be added in core) — the EE app at
// /ee/ shows the live licensed state.
const EE_NAV_SECTION: NavSectionView = {
  labelKey: 'app.sectionEnterprise',
  items: [
    // Placeholder surfaces per the UI-BOUNDARY approach-A research (§2-A2 +
    // verdict: identity/access, threat posture, loop-exec runs, entitlement
    // admin/settings) — all resolve inside the EE app.
    { id: 'ee-identity', labelKey: 'app.navEeIdentity', icon: <Fingerprint size={16} />, href: '/ee/', locked: true },
    { id: 'ee-threat-posture', labelKey: 'app.navEeThreatPosture', icon: <Radar size={16} />, href: '/ee/', locked: true },
    { id: 'ee-loop-runs', labelKey: 'app.navEeLoopRuns', icon: <Workflow size={16} />, href: '/ee/', locked: true },
    { id: 'ee-settings', labelKey: 'app.navEeSettings', icon: <Settings2 size={16} />, href: '/ee/', locked: true },
  ],
}

function findNav(id: Page): { sectionKey: string; item: { id: Page; labelKey: string; icon: React.ReactNode } } | null {
  for (const s of NAV_SECTIONS) {
    const item = s.items.find(i => i.id === id)
    if (item) return { sectionKey: s.labelKey, item }
  }
  return null
}

// Astra v2 "Paper & Olive" shell (standards/design.md §7): a paper topbar
// (brand + service actions, thin bottom rule) and a calm paper sidebar with
// grouped navigation on lg+ (≥1024px). Active item = selection ground +
// on-selection ink + a short 2px marker + aria-current. Below lg the same
// sections collapse into the accessible disclosure panel under the topbar
// (aria-expanded/controls, Escape + focus return, closes on navigation).
// The full product navigation (all sections) stays reachable at every
// width.
//
// Nav item styles are shared by the sidebar and the mobile panel; only the
// width differs. The 2px active marker keeps its column reserved on inactive
// items (transparent border) so nothing shifts on selection.

function AppShell() {
  const { t } = useTranslation()
  // AUX-13: nav entries without a usable server-side path are hidden once the
  // caller's rights are known. While /api/me is pending the full nav renders
  // (hiding it would blank the sidebar on every load); the server still
  // arbitrates every request either way.
  const perms = usePermissions()
  // shared with every data screen.
  const scopeCtl = useShellScope()
  const navVisible = (access: NavAccess): boolean => {
    if (perms.loading) return true // rights unknown yet — keep today's nav
    if (perms.me === null) return true // endpoint unavailable — server arbitrates
    if (perms.isRoot) return true
    if (access.anySession) return true
    if (access.rootOnly) return false
    // role from the caller's org memberships, the only role source in the
    // store) mirror that server logic on the org roles /api/me already serves.
    if (access.anyOrgRole) {
      return (perms.me.organizations ?? []).some(o => access.anyOrgRole!.includes(o.role))
    }
    return perms.canAnyOrg(...(access.anyOrg ?? []))
  }
  const readPage = (): Page => {
    // Strip the locale query that may ride in the hash (#page?locale=pseudo).
    const id = window.location.hash.slice(1).split('?')[0]
    // W-WELCOME: the onboarding route is valid without being a nav entry.
    if (id === 'onboarding') return 'onboarding'
    return NAV_SECTIONS.some(s => s.items.some(i => i.id === id)) ? id as Page : 'overview'
  }
  const [page, setPage] = useState<Page>(readPage)
  const [navOpen, setNavOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [signedOut, setSignedOut] = useState(false)
  const toggleRef = useRef<HTMLButtonElement>(null)
  const paletteButtonRef = useRef<HTMLButtonElement>(null)
  // AUX-21: bumping the nonce remounts the current page. A palette action
  // that lands on the page ALREADY open must remount it — the pages read
  // their hash params once at mount (useHashParam/useInspectParam), so a
  // plain hash rewrite would update the URL without updating the screen.
  const [pageNonce, setPageNonce] = useState(0)
  useEffect(() => {
    const onHashChange = () => setPage(readPage())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const goto = (id: Page) => {
    // Preserve the hash query (org scope, locale) across navigation —
    // UI-contract #1: the scope is part of the location, not page state.
    const prevQuery = window.location.hash.split('?')[1]
    window.location.hash = id + (prevQuery ? `?${prevQuery}` : '')
    setPage(id)
    // Mobile disclosure: close after navigation and return focus to the toggle.
    if (navOpen) {
      setNavOpen(false)
      toggleRef.current?.focus()
    }
  }

  // page in the hash) is seated on the FIRST navigation entry their rights
  // allow — never on the root-only Overview default. Deep links (an explicit
  // #page) still render as-is: the server arbitrates the data behind them.
  //
  // W-WELCOME: before that seating, an org whose onboarding flag is neither
  // completed nor skipped routes to the welcome flow first. The org
  // candidate resolves cheapest-first (remembered scope → the member's first
  // org → root's first listed org); the flag GET is best-effort — an old
  // backend or a capability-off store answers null and today's landing
  // behavior applies unchanged.
  const landingDone = useRef(false)
  useEffect(() => {
    if (landingDone.current || perms.loading) return
    landingDone.current = true
    const me = perms.me
    if (me === null) return
    if (window.location.hash.split('?')[0].slice(1)) return // explicit deep link
    void (async () => {
      const seatMember = () => {
        if (perms.isRoot) return
        const first = NAV_SECTIONS.flatMap(s => s.items).find(i => navVisible(i.access))
        if (first) goto(first.id)
      }
      let orgCandidate = readLastOrg()
      if (!orgCandidate) orgCandidate = me.organizations?.[0]?.id ?? ''
      if (!orgCandidate && perms.isRoot) {
        try {
          const orgs = await listOrganizations(1)
          orgCandidate = orgs.data?.[0]?.id ?? ''
        } catch { /* org list unavailable — keep today's landing */ }
      }
      if (!orgCandidate) {
        seatMember()
        return
      }
      const flag = await getOrgOnboarding(orgCandidate)
      if (flag && !flag.completed && !flag.skipped) {
        goto('onboarding')
        return
      }
      seatMember()
    })()
  }, [perms.loading, perms.me, perms.isRoot]) // eslint-disable-line react-hooks/exhaustive-deps

  // disclosure and the palette from one computed view.
  const visibleSections = useMemo<NavSectionView[]>(
    () => [
      ...NAV_SECTIONS
        .map(s => ({ labelKey: s.labelKey, items: s.items.filter(i => navVisible(i.access)) }))
        .filter(s => s.items.length > 0),
      // D-UI-2: the static Enterprise section rides along unfiltered —
      // always visible, always locked; core never decides entitlement (the
      // items carry no access gate at all).
      EE_NAV_SECTION,
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [perms.loading, perms.me],
  )

  // AUX-21 palette commands: the visible pages (same access filter as the
  // sidebar) plus navigation-only actions. Labels resolve at render time —
  // locale switches and /api/me answers rebuild the list like the sidebar
  // does; App re-renders rarely enough that memoization buys nothing.
  const pageCommands: CommandOption[] = NAV_SECTIONS.flatMap(section =>
    section.items
      .filter(item => navVisible(item.access))
      .map(item => ({ id: item.id, label: t(item.labelKey), section: t(section.labelKey), keywords: [item.id] })),
  )
  const actionCommands: CommandOption[] = [
    // Requests with the errors-only YQL applied; same right as the page.
    ...(navVisible({ anyOrg: ['requests.read'] }) ? [{
      id: 'palette-requests-errors',
      label: t('palette.actionRequestsErrors'),
      section: t('palette.sectionActions'),
      href: actionHref('requests-explorer', { query: ERRORS_ONLY_YQL }),
    }] : []),
    // Creating a key happens on the keys screen; the right is narrower
    // than reading it (keys.manage vs the page's manage-any gate).
    ...(navVisible({ anyOrg: ['keys.manage'] }) ? [{
      id: 'palette-key-create',
      label: t('palette.actionNewKey'),
      section: t('palette.sectionActions'),
    }] : []),
  ]
  const commands = [...pageCommands, ...actionCommands]

  const runCommand = (id: string) => {
    const command = commands.find(c => c.id === id)
    if (!command) return
    if (command.href) {
      // Navigation action: land on the target with the prefilled params.
      const target = command.href.slice(1).split('?')[0]
      window.location.hash = command.href
      if (target === page) setPageNonce(n => n + 1)
      else setPage(readPage())
    } else {
      goto(id as Page)
    }
  }

  // AUX-21: ⌘K / Ctrl+K opens (and toggles) the palette, before the browser
  // can turn the shortcut into a location-bar focus.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && (event.key === 'k' || event.key === 'K')) {
        event.preventDefault()
        setPaletteOpen(open => !open)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  // Mobile disclosure: Escape closes and returns focus to the toggle.
  useEffect(() => {
    if (!navOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setNavOpen(false)
        toggleRef.current?.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [navOpen])

  const crumb = findNav(page)
  const navId = 'admin-nav'

  if (signedOut) {
    return <SignedOutNotice />
  }

  return (
    <div className="flex min-h-screen flex-col bg-[color:var(--astra-paper)]">
      <a href="#admin-content" onClick={e => { e.preventDefault(); document.getElementById('admin-content')?.focus() }} className="sr-only focus:not-sr-only">{t('app.skipToContent')}</a>

      {/* Topbar owns the period preset · version-banner slot · ⌘K · user menu; the disclosure toggle and the
          below-lg scope controls live inside the Topbar too. */}
      <Topbar
        scope={scopeCtl}
        navId={navId}
        navOpen={navOpen}
        onToggleNav={() => setNavOpen(o => !o)}
        navToggleRef={toggleRef}
        navSlot={<SidebarNav sections={visibleSections} page={page} onNavigate={id => goto(id as Page)} heading />}
        paletteOpen={paletteOpen}
        onTogglePalette={() => setPaletteOpen(true)}
        paletteButtonRef={paletteButtonRef}
        onSignedOut={() => setSignedOut(true)}
      />

      {/* VersionBanner decides its own visibility: hidden unless the build is stale
          (low api_level, or /api/version answered 404); persistent for the session. */}
      <VersionBanner />

      {/* Body: calm paper sidebar with grouped sections (lg+) beside the
          working column. Both scroll with the page; the document never gets
          a second independent scroll region on wide screens. */}
      <div className="mx-auto flex w-full max-w-[1600px] flex-1 items-stretch">
        <Sidebar sections={visibleSections} page={page} onNavigate={id => goto(id as Page)} />

        {/* Main content: breadcrumb (Раздел / Страница) first, then the page
            composition. */}
        <div className="min-w-0 flex-1">
          <Breadcrumbs
            sectionKey={crumb?.sectionKey ?? 'app.sectionOverview'}
            pageKey={crumb?.item.labelKey ?? 'app.navOverview'}
          />

          <main id="admin-content" tabIndex={-1} className="min-w-0 p-4 md:p-6">
            <Suspense fallback={<p role="status" className="text-sm text-[color:var(--astra-text-muted)]">{t('app.loadingPage')}</p>}>
              <ChunkErrorBoundary key={`${page}:${pageNonce}`}>
                {page === 'overview' && <OverviewPage />}
                {page === 'cost' && <CostDashboard />}
                {page === 'compare' && <ComparePage />}
                {page === 'tasks' && <TasksPage />}
                {page === 'credits' && <CreditsPage />}
                {page === 'classifier' && <ClassifierPage />}
                {page === 'feedback' && <FeedbackPage />}
                {page === 'cache' && <CachePage />}
                {page === 'orgs' && <OrgsPage />}
                {page === 'keys' && <KeysPage />}
                {page === 'agents' && <AgentsPage />}
                {page === 'budgets' && <BudgetsPage />}
                {page === 'models' && <ModelsPage />}
                {page === 'rules' && <RulesPage />}
                {page === 'routing-map' && <RoutingMapPage />}
                {page === 'lineage' && <LineagePage />}
                {page === 'requests-explorer' && <RequestExplorerPage />}
                {page === 'analytics' && <AnalyticsExplorerPage />}
                {page === 'dashboards' && <DashboardsPage />}
                {page === 'tool-calls' && <ToolCallsPage />}
                {page === 'tool-policy' && <ToolPolicyPage />}
                {page === 'policy-editor' && <PolicyEditorPage />}
                {page === 'policy-decisions' && <PolicyDecisionsPage />}
                {page === 'prompts' && <PromptsPage />}
                {page === 'label-policy' && <LabelPolicyPage />}
                {page === 'guardrails' && <GuardrailsPage />}
                {page === 'guard-packs' && <GuardPacksPage />}
                {page === 'audit-log' && <AuditLogPage />}
                {page === 'exports' && <ExportsPage />}
                {page === 'model-access' && <ModelAccessPage />}
                {page === 'members' && <MembersPage />}
                {page === 'admin-users' && <AdminUsersPage />}
                {page === 'org-settings' && <OrgSettingsPage />}
                {page === 'mcp-credentials' && <McpCredentialsPage />}
              {page === 'rates' && <RatesPage />}
                {page === 'onboarding' && <OnboardingPage />}
              </ChunkErrorBoundary>
            </Suspense>
          </main>
        </div>
      </div>

      {/* AUX-21: the ⌘K command palette (navigation-only commands). */}
      {paletteOpen && (
        <CommandPalette
          commands={commands}
          onRun={runCommand}
          onClose={() => setPaletteOpen(false)}
        />
      )}
    </div>
  )
}

// completed (the server cleared the session cookie). Same paper panel as the
// 401 SessionGate; the sign-in link preserves the deep link via `next`.
function SignedOutNotice() {
  const { t } = useTranslation()
  const signInRef = useRef<HTMLAnchorElement>(null)
  useEffect(() => {
    signInRef.current?.focus()
  }, [])
  return (
    <div
      role="alertdialog"
      aria-labelledby="signed-out-title"
      aria-describedby="signed-out-message"
      className="fixed inset-0 z-50 flex items-center justify-center bg-[color:var(--astra-paper)] px-4"
    >
      <div className="astra-panel flex w-full max-w-md flex-col gap-2 px-6 py-8">
        <span className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-ink)]">
          <span aria-hidden="true" className="text-[color:var(--astra-ink)]">○</span>
          <span id="signed-out-title">{t('userMenu.signedOutTitle')}</span>
        </span>
        <p id="signed-out-message" className="text-sm text-[color:var(--astra-text-muted)]">
          {t('userMenu.signedOutMessage')}
        </p>
        <a ref={signInRef} href={loginNextUrl(window.location)} className="btn-primary mt-2 w-fit" data-testid="signed-out-sign-in">
          {t('session.signIn')}
        </a>
      </div>
    </div>
  )
}

// session-expired gate; the sign-in link preserves the deep link via `next`.
export default function App() {
  return (
    <SessionGate>
      <AppShell />
    </SessionGate>
  )
}
