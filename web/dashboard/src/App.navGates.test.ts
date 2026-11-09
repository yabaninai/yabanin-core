import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// classes — the UI half of the contract's example D ("UI hides ⇄ API denies
// must stay aligned in BOTH directions: the server forbids everything the UI
// hides, and hides no more than the server forbids").
//
// Why source-level: App.tsx is a JSX component the node strip-types harness
// cannot execute (there is no React render tree here). The gate TABLE is
// data; this fixture pins that data exactly the way the golden route file
// pins server route guarding (testdata/routes_admin.golden). The gate LOGIC
// unavailable latch) is exercised by hooks/usePermissions.test.ts; the
// server half of every pair cited below is enforced by the Go deny tests in
// services/admin/handlers (TestPrivilegedRoutes_DenyWithoutRights,
// TestOrgRoutes_RoleMatrixSweep, TestTP01_DashboardAggregateIsRootOnly).
//
// If this test goes red, the nav table drifted from the audited gate map:
// either restore the gate or re-audit the server surface and update BOTH the
// table and the evidence comments below in the same change.

const here = dirname(fileURLToPath(import.meta.url))
const appSource = readFileSync(join(here, 'App.tsx'), 'utf8')

// The server-side permission universe (pkg/adminstore/permissions.go,
// AllPermissions). UI anyOrg gates may only name these — a permission the
// server does not define is dead UI vocabulary that silently gates nobody
// and drifts from /api/me's permissions array.
const SERVER_PERMISSIONS = [
  'analytics.read', 'requests.read', 'requests.read_payloads',
  'lineage.read', 'lineage.verify', 'audit.read',
  'keys.manage', 'agent_keys.manage', 'budgets.manage',
  'members.manage', 'routing.manage', 'policies.manage', 'org.update',
] as const

// "budgets.read", which no server permission defines. Today's behavior is
// fail-closed (false for every non-root identity, root bypasses), and the
// server surfaces behind the page (spend-alert webhook) are root-only — so
// INV-1 holds in both directions and only the NAME is fictitious. Renaming
// is a UI-workstream card, not a regression-stage change.
const DOCUMENTED_WARTS = ['budgets.read'] as const

type NavGate = { rootOnly?: boolean; anyOrg?: string[]; anyOrgRole?: string[]; anySession?: boolean }

// cites the server evidence for its class.
const EXPECTED_GATES: Record<string, NavGate> = {
  // Overview — reads the global (root-only) aggregates.
  overview: { rootOnly: true },           // GET / dashboard aggregate — TestTP01 + sweep (root)
  cost: { rootOnly: true },               // cost dashboard — root-only money surfaces
  credits: { anyOrg: ['budgets.manage'] },// RequireOrgPermissionCreditsRead — TestCreditsOrgView_AuthzMatrix
  // Explore.
  'requests-explorer': { anyOrg: ['requests.read'] },
  analytics: { anyOrg: ['analytics.read'] },
  // MustBeRoot route — so the old anyOrg:['analytics.read'] gate showed
  // members a page that 403s on load (the AUX-13 honest wart). rootOnly is
  // the fixed behavior this regression pins; the named case below is the
  // negative proof.
  dashboards: { rootOnly: true },
  tasks: { anyOrg: ['analytics.read'] },
  'tool-calls': { rootOnly: true },
  lineage: { anyOrg: ['lineage.read'] },
  compare: { rootOnly: true },
  // Optimization — root-only surfaces (cache, classifier, feedback owner list).
  cache: { rootOnly: true },
  classifier: { rootOnly: true },
  feedback: { rootOnly: true },
  // Access & limits.
  keys: { anyOrg: ['keys.manage', 'agent_keys.manage'] },
  // list hint (mountKeys group, PermKeysManage) plus the keys deep link;
  // the agent_keys.manage half mirrors the keys screen floor so both key
  // custodians see the setup. The config generation is local and the test
  // call goes browser→gateway (no admin route).
  agents: { anyOrg: ['keys.manage', 'agent_keys.manage'] },
  budgets: { anyOrg: ['budgets.manage'] },
  exports: { anyOrg: ['budgets.read'] },  // documented wart — see DOCUMENTED_WARTS
  'model-access': { rootOnly: true },     // whitelist/aliases/teams — MustBeRoot mounts
  members: { anyOrg: ['members.manage'] },// RequireOrgPermission(MembersManage) — role sweep
  // Routing & policies.
  models: { rootOnly: true },
  rules: { rootOnly: true },
  'routing-map': { anyOrg: ['routing.manage'] }, // requireOrgRead — TestRoutingMap_RightsMatrix
  'tool-policy': { rootOnly: true },
  // RequireOrgPermissionPoliciesManage (policies.manage; root passes) — the
  // same server gate as the decision log entry below.
  'policy-editor': { anyOrg: ['policies.manage'] },
  'policy-decisions': { anyOrg: ['policies.manage'] },
  prompts: { anyOrg: ['policies.manage'] },
  'label-policy': { anyOrg: ['analytics.read'] },
  // surface over tool-policy / rules / label-policy (it fetches nothing).
  // The gate is the FLOOR of the linked screens' gates (label-policy's
  // analytics.read; rootOnly targets admit root through anyOrg too): whoever
  // sees the entry can open at least one card, a viewer who can open none
  // never sees it. GuardrailsPage.test.ts pins the per-card gates to this
  // same table so the summary cannot drift from the screens it links.
  guardrails: { anyOrg: ['analytics.read'] },
  // N02-P08 detector-pack lifecycle: every endpoint (GET list/status, POST
  // validate/simulate/activate/rollback) sits on the root-only guard mount
  // (services/admin/handlers/guardpacks.go mountGuard → mountRootAdmin;
  // TestGuardPacksRead_RoutingContract pins anon 401 / non-root 403).
  'guard-packs': { rootOnly: true },
  // Administration — platform surfaces behind MustBeRoot.
  orgs: { rootOnly: true },
  // root plus the security_auditor org role, resolved from /api/me's
  // organizations[].role. Replacing this with rootOnly re-hides the journal
  // from a security_auditor the server admits (the F2 asymmetry this test
  // pins shut); naming any other role breaks the first assertion below.
  'audit-log': { anyOrgRole: ['security_auditor'] },
  'admin-users': { rootOnly: true },
  'org-settings': { rootOnly: true },     // every tab endpoint is MustBeRoot (AUX-24)
  'mcp-credentials': { rootOnly: true },  // root-only MCP mount (MC-4)
  // Currencies slice 2 (brief 2026-11-02 §6.1): GET /api/rates/catalog is
  // session-gated only (any authenticated admin session; no org store
  // dependency) — so the nav item is anySession, the same class the server
  // enforces. Not rootOnly: hiding a catalog any session may read would be
  // example-D drift in the opposite direction.
  rates: { anySession: true },
}

const navStart = appSource.indexOf('const NAV_SECTIONS')
const navEnd = appSource.indexOf('\n]', navStart)

// One NAV_SECTIONS item per line: id, labelKey, icon, access.
const ITEM_LINE = /^\s*\{ id: '([\w-]+)', labelKey: '[\w.]+', icon: <\w+ size=\{16\} \/>, access: (\{.+?\}) \},\s*$/

function parseNavTable(source: string): Record<string, NavGate> {
  const out: Record<string, NavGate> = {}
  for (const line of source.split('\n')) {
    const m = ITEM_LINE.exec(line)
    if (!m) continue
    const gate: NavGate = {}
    const access = m[2]
    if (/rootOnly: true/.test(access)) gate.rootOnly = true
    const anyOrg = /anyOrg: \[([^\]]*)\]/.exec(access)
    if (anyOrg) {
      gate.anyOrg = anyOrg[1].split(',').map(s => s.trim().replaceAll("'", '')).filter(Boolean)
    }
    const anyOrgRole = /anyOrgRole: \[([^\]]*)\]/.exec(access)
    if (anyOrgRole) {
      gate.anyOrgRole = anyOrgRole[1].split(',').map(s => s.trim().replaceAll("'", '')).filter(Boolean)
    }
    if (/anySession: true/.test(access)) gate.anySession = true
    out[m[1]] = gate
  }
  return out
}

describe('nav gate table vs server gates (R031-04 INV-1)', () => {
  const table = (() => {
    assert.ok(navStart > -1 && navEnd > navStart, 'NAV_SECTIONS table not found in App.tsx')
    const parsed = parseNavTable(appSource.slice(navStart, navEnd))
    // Floor guard: a formatting or extraction regression must not silently
    // shrink the pinned surface.
    assert.ok(Object.keys(parsed).length >= 20,
      `parsed only ${Object.keys(parsed).length} nav items — the extraction is broken`)
    return parsed
  })()

  it('the nav table is exactly the audited gate map', () => {
    assert.deepEqual(table, EXPECTED_GATES)
  })

  it('the R031-02 dashboards fix holds: rootOnly, not the broken analytics.read gate', () => {
    // Negative proof for the fixed defect (INV-1, UI side): under the broken
    // gate (anyOrg ['analytics.read']) an analytics reader was shown a
    // screen whose data route (GET /api/organizations/{id}) is MustBeRoot.
    // Flipping the gate back is the mutation demonstrated in
    // goes red.
    assert.deepEqual(table.dashboards, { rootOnly: true })
  })

  it('the R031-D1 audit-log gate mirrors RequireGlobalAuditRead', () => {
    // The server admits root plus the security_auditor org role
    // (roles_authz.go globalAuditRole → adminstore.CanReadGlobalAudit). The
    // security_auditor — a "server allows, UI hides" INV-1 violation found
    assert.deepEqual(table['audit-log'], { anyOrgRole: ['security_auditor'] })
  })

  it('every anyOrgRole gate names a role the server global-gates', () => {
    // adminstore.CanReadGlobalAudit admits exactly the security_auditor org
    // role for non-root callers (pkg/adminstore/permissions.go:57).
    const GLOBAL_ROLES = new Set(['security_auditor'])
    for (const [id, gate] of Object.entries(table)) {
      for (const role of gate.anyOrgRole ?? []) {
        assert.ok(GLOBAL_ROLES.has(role),
          `${id} gates on global role "${role}" which the server does not admit`)
      }
    }
  })

  it('every anyOrg permission exists on the server (or is a documented wart)', () => {
    const known = new Set<string>([...SERVER_PERMISSIONS, ...DOCUMENTED_WARTS])
    for (const [id, gate] of Object.entries(table)) {
      for (const perm of gate.anyOrg ?? []) {
        assert.ok(known.has(perm),
          `${id} gates on "${perm}" which is neither a server permission nor a documented wart`)
      }
    }
  })

  it('every pinned page is still in the table (no silent removals)', () => {
    for (const id of Object.keys(EXPECTED_GATES)) {
      assert.ok(id in table, `pinned nav item "${id}" disappeared from NAV_SECTIONS`)
    }
  })
})
