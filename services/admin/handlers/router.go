package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/clientip"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/rulestore"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/reireirei/yabanin/pkg/validation"
	"github.com/reireirei/yabanin/pkg/whitelist"
)

// GenerateSessionKey creates a random 32-byte hex key for HMAC signing.
func GenerateSessionKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate session key: %v", err))
	}
	return hex.EncodeToString(b)
}

// StoreInterface defines the methods used by handlers to access admin data.
type StoreInterface interface {
	Log() *slog.Logger
	InsertAuditLog(ctx context.Context, id, action, resource, details, adminID, adminName, ipAddr string) error
	CreateAdminUser(ctx context.Context, email, displayName, passwordHash string, isRoot bool) (*adminstore.AdminUser, error)
	GetAdminUserByID(ctx context.Context, id string) (*adminstore.AdminUser, error)
	GetAdminUserByEmailWithHash(ctx context.Context, email string) (*adminstore.AdminUserWithHash, error)
	ListAdminUsers(ctx context.Context, onlyActive bool, f adminstore.PageFilter) ([]*adminstore.AdminUser, int64, error)
	UpdateAdminUser(ctx context.Context, id string, displayName *string, isRoot *bool) error
	DeleteAdminUser(ctx context.Context, id string) error
	CreateOrganization(ctx context.Context, name, slug string) (*adminstore.Organization, error)
	GetOrganizationByID(ctx context.Context, id string) (*adminstore.Organization, error)
	ListOrganizations(ctx context.Context, f adminstore.PageFilter) ([]*adminstore.Organization, int64, error)
	UpdateOrganization(ctx context.Context, id, name, slug, currency, timezone string, issueURL *string) error
	DeleteOrganization(ctx context.Context, id string) error
	GetOrgCacheSettings(ctx context.Context, orgID string) (*adminstore.OrgCacheSettings, error)
	UpdateOrgCacheSettings(ctx context.Context, orgID string, enabled bool, mode string) error
	GetOrgRoutingSettings(ctx context.Context, orgID string) (*adminstore.OrgRoutingSettings, error)
	UpdateOrgRoutingSettings(ctx context.Context, orgID string, mode string, threshold float64) error
	BumpModelVersion(ctx context.Context, modelName string) error
	GetCacheAnalytics(ctx context.Context, orgID string, from, to time.Time) (*adminstore.CacheAnalytics, error)
	CreateTeam(ctx context.Context, orgID, name, slug string, parentTeamID *string) (*adminstore.Team, error)
	GetTeamByID(ctx context.Context, id string) (*adminstore.Team, error)
	GetDefaultTeam(ctx context.Context, orgID string) (*adminstore.Team, error)
	ListTeamsByOrg(ctx context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.Team, int64, error)
	UpdateTeam(ctx context.Context, id, name, slug string, parentTeamID *string) error
	DeleteTeam(ctx context.Context, id string) error
	CreateAPIKey(ctx context.Context, keyHash, name string, orgID *string, teamID *string) (*adminstore.APIKey, error)
	GetAPIKeyByID(ctx context.Context, id string) (*adminstore.APIKey, error)
	ListAPIKeys(ctx context.Context, orgID *string, f adminstore.PageFilter) ([]*adminstore.APIKey, int64, error)
	UpdateAPIKeyActive(ctx context.Context, id string, active bool) error
	RotateAPIKey(ctx context.Context, id, newHash string) error
	DeleteAPIKey(ctx context.Context, id string) error
	UpdateAPIKeyLabels(ctx context.Context, id string, labels map[string]string, locked, mint, usage bool) error
	RevokeSessionKeysByParent(ctx context.Context, parentID string) ([]string, error)
	// Agent principals (G1).
	CreateAgentKey(ctx context.Context, keyHash, name, orgID string) (*adminstore.AgentKey, error)
	// ADL-03 delegation: create a key with delegation fields (child of a parent).
	CreateAgentKeyDelegated(ctx context.Context, p adminstore.AgentKeyCreateParams) (*adminstore.AgentKey, error)
	GetAgentKeyByID(ctx context.Context, id string) (*adminstore.AgentKey, error)
	ListAgentKeys(ctx context.Context, orgID string) ([]*adminstore.AgentKey, error)
	RevokeAgentKey(ctx context.Context, id string) error
	GetAgentBudget(ctx context.Context, agentID string) (*adminstore.AgentBudget, error)
	UpsertAgentBudget(ctx context.Context, agentID string, dailyLimitCents int64) (*adminstore.AgentBudget, error)
	DeleteAgentBudget(ctx context.Context, agentID string) error
	CreateModel(ctx context.Context, modelName, displayName, tier string, upstreamURL, upstreamAPIKey *string) (*adminstore.ModelRegistry, error)
	CreateModelWithParams(ctx context.Context, p adminstore.CreateModelParams) (*adminstore.ModelRegistry, error)
	GetModelByName(ctx context.Context, modelName string) (*adminstore.ModelRegistry, error)
	ListModels(ctx context.Context, f adminstore.PageFilter) ([]*adminstore.ModelRegistry, int64, error)
	UpdateModel(ctx context.Context, modelName, displayName string, tier *string, upstreamURL *string, upstreamAPIKey *string, enabled *bool) error
	UpdateModelWithParams(ctx context.Context, p adminstore.UpdateModelParams) error
	UpdateModelEnabled(ctx context.Context, modelName string, enabled bool) error
	DeleteModel(ctx context.Context, modelName string) error
	CreateRoutingRule(ctx context.Context, orgID, matchExpr, targetModel string, priority int) (*adminstore.RoutingRule, error)
	GetRoutingRuleByID(ctx context.Context, id string) (*adminstore.RoutingRule, error)
	ListRoutingRulesByOrg(ctx context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.RoutingRule, int64, error)
	UpdateRoutingRule(ctx context.Context, id, matchExpr, targetModel string, priority *int) error
	UpdateRoutingRuleEnabled(ctx context.Context, id string, enabled bool) error
	DeleteRoutingRule(ctx context.Context, id string) error
	AddKeyWhitelist(ctx context.Context, apiKeyID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error)
	ListKeyWhitelist(ctx context.Context, apiKeyID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error)
	DeleteKeyWhitelist(ctx context.Context, apiKeyID, modelName string) error
	AddTeamWhitelist(ctx context.Context, teamID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error)
	ListTeamWhitelist(ctx context.Context, teamID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error)
	DeleteTeamWhitelist(ctx context.Context, teamID, modelName string) error
	GetRequestLogStats(ctx context.Context, orgID *string, since time.Time) (*adminstore.RequestLogStats, error)
	TopModels(ctx context.Context, orgID *string, limit int) ([]adminstore.TopModelCount, error)
	TopOrgs(ctx context.Context, limit int) ([]adminstore.TopOrgCount, error)
	RequestTimeSeries(ctx context.Context, orgID *string, since time.Time, interval string) ([]adminstore.TimeSeriesPoint, error)
	ErrorBreakdown(ctx context.Context, orgID *string, since time.Time) ([]adminstore.ErrorBreakdownEntry, error)
	LatencyPercentiles(ctx context.Context, orgID *string, since time.Time) (*adminstore.LatencyPercentile, error)
	RecentErrors(ctx context.Context, orgID *string, limit int) ([]adminstore.RecentErrorLog, error)
	GetCostAnalytics(ctx context.Context, orgID string, from, to time.Time, provider string) (*adminstore.CostReport, error)
	RequestStats(ctx context.Context, f adminstore.RequestListFilters) (*adminstore.RequestListStats, error)
	GetToolCallsReport(ctx context.Context, orgID string, days int) (*adminstore.ToolCallsReport, error)
	GetGlobalCostStats(ctx context.Context, from, to time.Time) (*adminstore.CostReport, error)
	// G4: CTOR/task cost analytics.
	GetTaskAnalytics(ctx context.Context, orgID string, from, to time.Time, groupBy string, limit int) (*adminstore.TaskAnalyticsReport, error)
	// Unified request explorer list.
	ListRequests(ctx context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error)
	// Full request detail (stored response snapshot + raw fields), org-scoped.
	GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error)
	GetSavingsReport(ctx context.Context, orgID string, days int, provider string) (*adminstore.SavingsReport, error)
	GetShadowComparison(ctx context.Context, orgID string, days int) (*adminstore.ShadowComparison, error)
	// ADL-04: quality closed-loop (evalgate verdicts → per-model / per-task-class
	// scores + a routing recommendation).
	GetQualityScores(ctx context.Context, orgID string, from, to time.Time) (*adminstore.QualityReport, error)
	RunAnalyticsQuery(ctx context.Context, q *adminstore.AnalyticsQuery) (*adminstore.AnalyticsResult, error)
	ListLabelKeys(ctx context.Context, orgID string, from, to time.Time) ([]adminstore.LabelKeyStat, error)
	// ADL-06: agent role profiles (reusable yag_ key-issuance templates).
	CreateAgentProfile(ctx context.Context, p adminstore.AgentProfileCreateParams) (*adminstore.AgentProfile, error)
	GetAgentProfile(ctx context.Context, id string) (*adminstore.AgentProfile, error)
	ListAgentProfiles(ctx context.Context, orgID string) ([]*adminstore.AgentProfile, error)
	UpdateAgentProfile(ctx context.Context, id string, p adminstore.AgentProfileUpdateParams) (*adminstore.AgentProfile, error)
	DeleteAgentProfile(ctx context.Context, id string) error
	// ENT-02: RBAC — org membership (role) management + role lookup.
	CreateOrgMembership(ctx context.Context, m adminstore.OrgMembership) (*adminstore.OrgMembership, error)
	SetOrgMembership(ctx context.Context, userID, orgID string, role adminstore.OrgRole) (*adminstore.OrgMembership, error)
	DeleteOrgMembership(ctx context.Context, userID, orgID string) error
	GetUserOrgRoles(ctx context.Context, userID string) (map[string]adminstore.OrgRole, error)
	ListOrgMembers(ctx context.Context, orgID string) ([]*adminstore.OrgMembership, error)
	CreatePricing(ctx context.Context, p adminstore.CreatePricingParams) (*adminstore.PricingEntry, error)
	UpdatePricing(ctx context.Context, p adminstore.UpdatePricingParams) (*adminstore.PricingEntry, error)
	DeletePricing(ctx context.Context, id int64) error
	ListPricing(ctx context.Context, opts adminstore.ListPricingOptions) ([]adminstore.PricingEntry, error)
	ImportCatalogPricing(ctx context.Context, catalog pricing.PriceFile, mappings []adminstore.CatalogPriceMap, onlyMapped, apply bool, updatedBy string) (adminstore.CatalogImportResult, error)
	ListModelAliases(ctx context.Context) ([]adminstore.ModelAlias, error)
	CreateModelAlias(ctx context.Context, alias, target string) (*adminstore.ModelAlias, error)
	DeleteModelAlias(ctx context.Context, alias string) error
	GetOrgSpendAlertSettings(ctx context.Context, orgID string) (*adminstore.OrgSpendAlertSettings, error)
	UpdateOrgSpendAlertSettings(ctx context.Context, orgID string, threshold *float64, webhookURL *string) error
	ListOrgsWithSpendAlerts(ctx context.Context) ([]adminstore.SpendAlertOrg, error)
	SpendToday(ctx context.Context, orgID string) (float64, error)
	UpdateLastAlertAt(ctx context.Context, orgID string, at time.Time) error
	GetTeamSpendSummary(ctx context.Context, teamID string) (*adminstore.TeamSpendSummary, error)
	UpsertTeamBudget(ctx context.Context, teamID string, monthlyLimit float64, hardLimit bool) error
	DeleteTeamBudget(ctx context.Context, teamID string) error
	ListTeamBudgetsByOrg(ctx context.Context, orgID string) ([]adminstore.TeamSpendSummary, error)
}

// CASStore is the narrow AF-09 capability interface: atomic preconditioned
// (compare-and-set) mutations for the audited rollback families. The
// expected CURRENT state is compared inside the same SQL statement as the
// write; a mismatch returns adminstore.ErrPreconditionFailed together with
// the row's current state. Stores that do not implement it simply never get
// a preconditioned call — the rollback handlers refuse (501) rather than
// silently degrade to a blind overwrite.
type CASStore interface {
	UpdateAPIKeyActivePreconditioned(ctx context.Context, id string, active bool, expectActive *bool) (*bool, error)
	UpdateRoutingRuleEnabledPreconditioned(ctx context.Context, id string, enabled bool, expectEnabled *bool) (*bool, error)
	UpdateAPIKeyLabelsPreconditioned(ctx context.Context, id string, labels map[string]string, locked, mint, usage bool, expect *adminstore.APIKeyLabelsState) (*adminstore.APIKeyLabelsState, error)
	UpsertTeamBudgetPreconditioned(ctx context.Context, teamID string, monthlyLimit float64, hardLimit bool, expect *adminstore.TeamBudgetExpectation) (*adminstore.TeamBudget, error)
	DeleteTeamBudgetPreconditioned(ctx context.Context, teamID string, expect adminstore.TeamBudgetExpectation) (bool, *adminstore.TeamBudget, error)
	UpsertAgentBudgetPreconditioned(ctx context.Context, agentID string, dailyLimitCents int64, expect *adminstore.AgentBudgetExpectation) (*adminstore.AgentBudget, error)
	DeleteAgentBudgetPreconditioned(ctx context.Context, agentID string, expectCents int64) (bool, *adminstore.AgentBudget, error)
	AddKeyWhitelistPreconditioned(ctx context.Context, apiKeyID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error)
	DeleteKeyWhitelistPreconditioned(ctx context.Context, apiKeyID, modelName string, expectAllowed bool) (bool, *adminstore.WhitelistEntry, error)
	AddTeamWhitelistPreconditioned(ctx context.Context, teamID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error)
	DeleteTeamWhitelistPreconditioned(ctx context.Context, teamID, modelName string, expectAllowed bool) (bool, *adminstore.WhitelistEntry, error)
}

// cas returns the store's CAS capability, or nil when unsupported.
func (h *AdminHandlers) cas() CASStore {
	cs, _ := h.store.(CASStore)
	return cs
}

// DelegationBudgetStore is the narrow AUDIT-P1-03 capability interface: the
// delegation-budget invariant (a child cap ≤ the parent's remaining
// headroom; the parent must have a budget row) enforced atomically at
// delegation time. The real adminstore implements it; other StoreInterface
// implementations are unaffected — the delegation-budget endpoints refuse
// (501) rather than silently degrade to an unchecked write.
type DelegationBudgetStore interface {
	// CreateAgentKeyDelegatedChecked inserts the child key AND its
	// agent_budgets row in one advisory-locked transaction after verifying
	// the cap against the parent headroom (adminstore.ErrParentBudgetMissing
	// / ErrDelegationHeadroomExceeded / ErrParentNotDelegable on refusal).
	CreateAgentKeyDelegatedChecked(ctx context.Context, p adminstore.AgentKeyCreateParams) (*adminstore.AgentKey, error)
	// UpsertAgentBudgetChecked updates the cap under the same invariant (a
	// delegated child only; roots follow the unconstrained legacy path).
	UpsertAgentBudgetChecked(ctx context.Context, agentID string, dailyLimitCents int64) (*adminstore.AgentBudget, error)
	// UpsertAgentBudgetPreconditionedChecked is the AF-09 CAS variant under
	// the same invariant (adminstore.ErrPreconditionFailed on a stale
	// expectation, carrying the current row).
	UpsertAgentBudgetPreconditionedChecked(ctx context.Context, agentID string, dailyLimitCents int64, expect *adminstore.AgentBudgetExpectation) (*adminstore.AgentBudget, error)
}

// delegationBudget returns the store's delegation-budget capability, or nil
// when unsupported.
func (h *AdminHandlers) delegationBudget() DelegationBudgetStore {
	ds, _ := h.store.(DelegationBudgetStore)
	return ds
}

// AuditJournalStore is the narrow AF-10 capability interface: the durable,
// DB-backed audit journal. The full sanitized entry (snapshots/reason) is
// persisted synchronously into the hash-chained table, the journal is read
// back from the DB (a restart or a second instance returns the same journal),
// and the outbox records a durable intent when the direct write fails.
// Type-asserted from StoreInterface (like CASStore); stores without the
// capability keep the legacy in-buffer behavior.
type AuditJournalStore interface {
	InsertAuditLogEntry(ctx context.Context, rec adminstore.AuditLogEntryRecord) error
	ListAuditLogEntries(ctx context.Context, q adminstore.AuditLogQuery) ([]adminstore.AuditLogEntry, int64, int64, error)
	EnqueueAuditOutbox(ctx context.Context, rec adminstore.AuditLogEntryRecord) error
	DrainAuditOutbox(ctx context.Context, limit int) (int, error)
}

// auditJournal returns the store's durable audit capability, or nil when
// unsupported.
func (h *AdminHandlers) auditJournal() AuditJournalStore {
	js, _ := h.store.(AuditJournalStore)
	return js
}

// struct): the OIDC client, the developer store and the provisioning
// policy. Wired as a unit by SetPortal.
type portalDeps struct {
	enabled      bool
	client       *adminauth.OIDCClient
	store        PortalStore
	provisioning string
	domains      map[string]struct{}
	defaultOrg   string
	defaultTeam  string
	maxKeys      int
	keyTTLDays   int
	gatewayURL   string
}

// billingDeps groups the reseller-billing dependencies (PR1): the credit
// wallet store, the resale-pricing DB pool and the handler structs
// constructed from them by initBillingHandlers.
type billingDeps struct {
	creditStore       *credits.Store
	resalePricingPool *pgxpool.Pool
	credit            *CreditHandlers
	lowBalance        http.HandlerFunc
	resale            *ResalePricingHandlers
}

// mcpDeps groups the external-tool registry dependencies — the MCP server
// registry (MCP-02), per-agent grants, the A2A agent registry (A2A-01) and
// the tool-policy registry (TOOL-01) — plus the shared SSRF guards: one
// operator-managed upstream allow-list and the DNS-resolution test seam.
type mcpDeps struct {
	store            *mcpagg.Store
	allowedUpstreams []string
	a2a              *a2aagg.Store
	toolPolicies     *toolpolicy.Store
	toolEngine       *toolpolicy.Engine
	// MC-1: the server-level MCP credential store (nil = the credential
	// routes answer 503) and the gateway cache-invalidation bumper (nil =
	// TTL-only staleness bound on the gateway side).
	credStore          MCPCredentialStore
	credsVersionBumper MCPCredsVersionBumper
	userCredLifecycle  MCPUserCredLifecycle
	// dnsResolver overrides SSRF-guard DNS resolution (QG2-D3 test seam,
	// same-package tests only; nil = bounded default resolver in production).
	dnsResolver func(ctx context.Context, host string) ([]net.IP, error)
}

// feedbackDeps groups the classifier-feedback dependencies: the collector
// (P5.13 POST /v1/feedback, with the API-key resolver for server-side org
// attribution), the exporter (PC3 admin export) and the owner-page lister
// (W-FEED root-only list + CSV export; nil = routes stay unmounted).
type feedbackDeps struct {
	collector *feedback.Collector
	resolver  *auth.Resolver
	exporter  *feedback.Exporter
	lister    FeedbackLister
}

// lineageDeps groups the PB1 lineage dependencies: the query store and the
// response verifier.
type lineageDeps struct {
	store    LineageStore
	verifier LineageVerifier
}

// analyticsDeps groups the analytics-adjacent stores: saved analytics views
// and the per-org label policy.
type analyticsDeps struct {
	views       AnalyticsViewStore
	labelPolicy LabelPolicyStore
}

// orgDeps groups the PA.6 org-governance stores: residency policy packs and
// the org residency-region.
type orgDeps struct {
	policyPacks PolicyPackStore
	residency   OrgResidencyStore
}

// AdminHandlers holds all admin handler state. Cross-cutting dependencies
// (store, session, limiters, audit, gateway cache hooks) sit on the top
// level; domain state lives in the dependency groups below — each mounted
// by its router_*.go file.
type AdminHandlers struct {
	store                 StoreInterface
	sessionRevocations    adminauth.RevocationStore
	resolverCache         ResolverCache // optional — revocation purge (S02); nil = TTL-only
	sessionSecret         string
	previousSessionSecret string
	sessionGraceStarted   time.Time
	sessionGrace          time.Duration
	internalServiceKey    string // optional /internal service API key (empty = not mounted)
	// eeInternalToken arms the D-UI-4 EE session-validation endpoint
	// (POST /auth/ee/session, X-EE-Internal guard; empty = not mounted,
	// feature-dark).
	eeInternalToken string
	domain          string
	logger          *slog.Logger
	rateLimiter     adminLimiter
	loginLimiter    adminLimiter
	ssoStartLimiter adminLimiter
	auditMu         sync.RWMutex
	auditLogBuffer  []AuditLogEntry
	// AF-10: entries that could not be made durable (direct append AND
	// outbox both failed). Memory-only, retried by the delivery loop and
	// surfaced via pending_audit_entries — never treated as durable.
	auditPending []AuditLogEntry
	// auditLoopOnce guards the one-time delivery-loop start (first audit
	// write); auditCancel stops it (guarded by auditMu).
	auditLoopOnce sync.Once
	// auditCancel stops the AF-10 audit delivery loop (nil = not running).
	auditCancel    context.CancelFunc
	trustedProxies []string
	inv            *cache.Invalidator // cache invalidation (nil if not configured)
	// ruleInv clears the gateway rule cache (RT-06) after routing-rule
	// create/update/delete; nil = TTL-only staleness bound.
	ruleInv      *rulestore.Store       // gateway rule-cache invalidation
	policyLoader *cache.PolicyCache     // gateway policy cache for invalidation
	experiments  *cache.ExperimentStore // A/B experiment store (nil = endpoints return 501)
	wlLoader     *whitelist.Loader      // whitelist cache invalidation (nil if not configured)
	dbPricer     *pricing.DBPricer      // database pricer (nil if not configured)
	// ratesCatalogStore is the full adminstore (with pool) backing the
	// durable rates-catalog promotion (AUDIT-P1-04): active-of-record GET
	// payload, durable promote with in-transaction materialization. nil =
	// legacy in-memory promotion only.
	ratesCatalogStore *adminstore.Store
	sovereignHandlers *SovereignHandlers      // PB4.9 sovereign model marketplace (nil if not configured)
	regionHandlers    *RegionHandlers         // PB2.7 region routing admin (nil if not configured)
	orgCreds          *OrgCredentialHandlers  // W-BYOK-API BYOK credential routes (nil = routes answer 503)
	policyPipes       *PolicyPipelineHandlers // OP-0b policy pipeline routes (nil = routes answer 503)
	canaryRollouts    *CanaryRolloutHandlers  // Canary rollout routes (nil = routes answer 503)
	policyDecisions   *PolicyDecisionHandlers // OP-9 policy decision log route (nil = route answers 503)
	promptStudio      *PromptStudioHandlers   // Prompt studio routes (nil = routes answer 503)
	verticalHandlers  *VerticalHandlers       // PC2 vertical pack admin (nil if not configured)
	templateHandlers  *PolicyTemplateHandlers // PC3 policy template admin (nil if not configured)
	retrainHandlers   *RetrainHandlers        // data flywheel retrain status (nil if not configured)
	guardPacks        *GuardPackHandlers      // N02-P04/P08 guard pack lifecycle (nil = routes answer 503)
	allowedOrigins    []string                // CORS origins for admin panel (nil = no CORS)
	oidcClient        *adminauth.OIDCClient   // ENT-01: OIDC SSO (nil = password flow only)
	// SAML 2.0 SSO (nil = not mounted; see auth_saml.go). Wired in
	// services/run when the IdP metadata URL env knob is present.
	samlSP *adminauth.SAMLSP
	// W-SECADM: optional /metrics bearer key (see SetMetricsBearerKey in
	// router_public.go). Empty keeps the legacy network-restriction-only
	// behavior documented in config.yaml.
	metricsBearerKey string
	reservationsGate budget.Mode
	// E01-P05 W04-C02: served-license diagnostics source (nil = the route
	// answers 503). The admin plane reads only this narrow interface —
	// pkg/license is never imported here (license_boundary_test.go).
	entitlementDiagnostics EntitlementDiagnosticsSource

	// Domain-scoped dependency groups.
	portal    portalDeps
	billing   billingDeps
	mcp       mcpDeps
	feedback  feedbackDeps
	lineage   lineageDeps
	analytics analyticsDeps
	org       orgDeps
	// E02-P01: observable asset registry (root-only, wired as a unit —
	// see router_inventory.go).
	inventory inventoryDeps
	// SCIM provisioning surface (bearer /scim/v2 + token management).
	scim scimDeps
}

// SetSessionSecretGrace enables bounded validation with the previous signing
// key. Newly created cookies continue to use sessionSecret.
func (h *AdminHandlers) SetSessionSecretGrace(previous string, started time.Time, grace time.Duration) {
	h.previousSessionSecret = previous
	h.sessionGraceStarted = started
	h.sessionGrace = grace
}

// SetReservationsGate configures the deployment rollout ceiling shown by
// org budget settings. It must match the gateway admission configuration.
func (h *AdminHandlers) SetReservationsGate(mode string) {
	h.reservationsGate = budget.ResolveMode(mode)
}

func (h *AdminHandlers) sessionAuthMiddleware() func(http.Handler) http.Handler {
	return adminauth.ChiAuthMiddlewareRotatingWithRevocation(h.sessionSecret, h.previousSessionSecret, h.sessionGraceStarted, h.sessionGrace, time.Now, func(r *http.Request, session *adminauth.AdminSession) {
		h.logger.Warn("admin session validated with previous signing secret", "user_id", session.UserID)
		ctx := context.WithValue(r.Context(), adminauth.ContextKeyUserID{}, session.UserID)
		ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, session.Email)
		ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, session.IsRoot)
		auditedRequest := r.WithContext(ctx)
		h.recordAudit(ctx, auditedRequest, "admin_session_previous_secret", "session", "session validated with previous signing secret", nil, nil)
	}, h.adminSessionsInvalidatedAt, h.sessionRevocations, h.adminSessionRevalidate)
}

// adminLimiter is the contract both rate limiter implementations satisfy:
// the in-memory one (rate_limiter.go) and the Redis-backed
type adminLimiter interface {
	allow(key string) bool
	Stop()
}

// redisLimiterAdapter adapts adminauth.RedisRateLimiter (exported Allow)
// to adminLimiter.
type redisLimiterAdapter struct{ *adminauth.RedisRateLimiter }

func (a redisLimiterAdapter) allow(key string) bool { return a.Allow(key) }

// SetSovereignHandlers attaches the sovereign model handlers and registers routes.
func (h *AdminHandlers) SetSovereignHandlers(sh *SovereignHandlers) {
	h.sovereignHandlers = sh
}

// SetRegionHandlers attaches the region routing handlers and registers routes.
func (h *AdminHandlers) SetRegionHandlers(rh *RegionHandlers) {
	h.regionHandlers = rh
}

// SetVerticalHandlers attaches the vertical pack admin handlers.
func (h *AdminHandlers) SetVerticalHandlers(vh *VerticalHandlers) {
	h.verticalHandlers = vh
}

// SetTemplateHandlers attaches the policy template admin handler.
func (h *AdminHandlers) SetTemplateHandlers(th *PolicyTemplateHandlers) {
	h.templateHandlers = th
}

// SetFeedbackExporter attaches the feedback exporter for admin export endpoints.
func (h *AdminHandlers) SetFeedbackExporter(e *feedback.Exporter) {
	h.feedback.exporter = e
}

// SetRetrainHandlers attaches the retrain status handler.
func (h *AdminHandlers) SetRetrainHandlers(rh *RetrainHandlers) {
	h.retrainHandlers = rh
}

// New creates a new AdminHandlers instance.

// ResolverCache invalidates org-resolver cache entries so a revoked key stops
// authenticating immediately instead of after the TTL (S02). *redis.Client
// satisfies it.
type ResolverCache interface {
	Del(ctx context.Context, keys ...string) error
}

// SetResolverCache wires the shared Redis (nil disables instant revocation —
// the documented TTL bound applies).
func (h *AdminHandlers) SetResolverCache(rc ResolverCache) { h.resolverCache = rc }

// purgeResolverKeys removes org:resolve:<hash> entries (fail-soft: a purge
// failure never fails the revocation itself — the TTL remains the bound).
func (h *AdminHandlers) purgeResolverKeys(ctx context.Context, keyHashes ...string) {
	if h.resolverCache == nil {
		return
	}
	keys := make([]string, 0, len(keyHashes))
	for _, hash := range keyHashes {
		if hash != "" {
			keys = append(keys, "org:resolve:"+hash)
		}
	}
	if len(keys) == 0 {
		return
	}
	if err := h.resolverCache.Del(ctx, keys...); err != nil {
		h.logger.Warn("resolver cache purge failed; TTL bound applies", "error", err)
	} else {
		h.logger.Info("resolver cache purged (revocation propagates immediately)", "keys", len(keys))
	}
}

// New starts a mock upstream server for tests.
// New.
func New(store StoreInterface, sessionSecret string, domain string, trustedProxies []string) *AdminHandlers {
	rl := newRateLimiter(1000, 1*time.Minute)
	ll := newRateLimiter(5, 15*time.Minute)
	sl := newRateLimiter(ssoStartLimit, 15*time.Minute)
	go rl.cleanup()
	go ll.cleanup()
	go sl.cleanup()
	h := &AdminHandlers{
		store:           store,
		sessionSecret:   sessionSecret,
		domain:          domain,
		logger:          slog.Default(),
		rateLimiter:     rl,
		loginLimiter:    ll,
		ssoStartLimiter: sl,
		trustedProxies:  trustedProxies,
		// SCIM-created users join the token org as readers unless the
		// deployment overrides the default role (SetScimDefaultRole).
		scim: scimDeps{defaultRole: adminstore.RoleReader},
	}
	if revocations, ok := store.(adminauth.RevocationStore); ok {
		h.sessionRevocations = revocations
	} else {
		h.logger.Warn("durable admin-session revocation store unavailable; using process-local fallback")
	}
	return h
}

// SetCacheInvalidator attaches the cache invalidator for flush operations.
func (h *AdminHandlers) SetCacheInvalidator(inv *cache.Invalidator) {
	h.inv = inv
}

// SetRuleCacheInvalidator attaches the gateway rule cache (RT-06): a
// cache-only rulestore over the shared Redis. After a routing-rule mutation
// the affected org's entry is deleted so gateway replicas observe new rules
// without waiting for the TTL.
func (h *AdminHandlers) SetRuleCacheInvalidator(ruleInv *rulestore.Store) {
	h.ruleInv = ruleInv
}

// invalidateRuleCache clears the rule cache for orgID (best-effort: an
// invalidation failure only bounds visibility at the TTL, never breaks the
// mutation itself).
func (h *AdminHandlers) invalidateRuleCache(r *http.Request, orgID string) {
	if h.ruleInv == nil || orgID == "" {
		return
	}
	h.ruleInv.Invalidate(r.Context(), orgID)
}

// SetPolicyLoader attaches the gateway policy cache for invalidation on settings change.
func (h *AdminHandlers) SetPolicyLoader(pl *cache.PolicyCache) {
	h.policyLoader = pl
}

// SetWhitelistLoader attaches the whitelist loader for cache invalidation on whitelist changes.
func (h *AdminHandlers) SetWhitelistLoader(wl *whitelist.Loader) {
	h.wlLoader = wl
}

// SetFeedbackCollector attaches the classifier feedback collector together
// with the API-key resolver used to attribute feedback server-side (F2).
func (h *AdminHandlers) SetFeedbackCollector(fc *feedback.Collector, resolver *auth.Resolver) {
	h.feedback.collector = fc
	h.feedback.resolver = resolver
}

// SetDBPricer attaches the database pricer.
func (h *AdminHandlers) SetDBPricer(p *pricing.DBPricer) {
	h.dbPricer = p
}

// SetRatesCatalogStore attaches the adminstore backing the durable rates
// promotion (active-of-record catalog GET, one-transaction promote +
// materialization). nil keeps the legacy in-memory promotion behavior.
func (h *AdminHandlers) SetRatesCatalogStore(s *adminstore.Store) {
	h.ratesCatalogStore = s
}

// SetCreditStore attaches the credits store for reseller billing.
func (h *AdminHandlers) SetCreditStore(cs *credits.Store, pool *pgxpool.Pool) {
	h.billing.creditStore = cs
	h.billing.resalePricingPool = pool
}

// SetToolPolicyStore wires the tool policy registry CRUD (nil when no DB
// pool — the routes then answer 503). The engine reference (may be nil)
// drops the org's cached decisions on every mutation.
func (h *AdminHandlers) SetToolPolicyStore(store *toolpolicy.Store, engine *toolpolicy.Engine) {
	h.mcp.toolPolicies = store
	h.mcp.toolEngine = engine
}

// SetOIDCClient enables the SSO login routes. Pass nil (or never call) to
// keep the console on the password flow — the default and a zero behavior
// change for deployments without the OIDC config tuple.
func (h *AdminHandlers) SetOIDCClient(c *adminauth.OIDCClient) {
	h.oidcClient = c
}

// SetA2AStore wires the A2A agent registry CRUD (nil when no DB pool — the
// routes then answer 503). The SSRF allow-list is shared with the MCP
// registry: one operator-managed deployment list covers both dial-out
// features.
func (h *AdminHandlers) SetA2AStore(store *a2aagg.Store) {
	h.mcp.a2a = store
}

// SetMCPStore attaches the MCP aggregator registry (MCP-02) for the
// /api/organizations/{id}/mcp/servers CRUD. store is nil when no DB pool is
// configured (the routes then answer 503). allowedUpstreams is the SSRF
// domain allow-list for server URLs (the deployment's gateway
// allowed_upstreams list; empty = no domain allowed, fail-closed).
func (h *AdminHandlers) SetMCPStore(store *mcpagg.Store, allowedUpstreams []string) {
	h.mcp.store = store
	h.mcp.allowedUpstreams = allowedUpstreams
}

// SetAllowedOrigins configures CORS origins for the admin panel.
func (h *AdminHandlers) SetAllowedOrigins(origins []string) {
	h.allowedOrigins = origins
}

// SetRateLimitRedis moves the admin-plane rate limiters onto the shared
// min) thresholds are unchanged, but the limit is now shared across
// replicas. Call only with a live Redis client; without it the in-memory
// limiters stay in place. Redis outages fail open with a metric and a
// throttled WARN (see adminauth.RedisRateLimiter).
func (h *AdminHandlers) SetRateLimitRedis(rdb adminauth.Scripter) {
	if h.rateLimiter != nil {
		h.rateLimiter.Stop()
	}
	if h.loginLimiter != nil {
		h.loginLimiter.Stop()
	}
	h.rateLimiter = redisLimiterAdapter{adminauth.NewRedisRateLimiter(rdb, "api", 1000, time.Minute, h.logger)}
	h.loginLimiter = redisLimiterAdapter{adminauth.NewRedisRateLimiter(rdb, "login", 5, 15*time.Minute, h.logger)}
	if h.ssoStartLimiter != nil {
		h.ssoStartLimiter.Stop()
	}
	h.ssoStartLimiter = redisLimiterAdapter{adminauth.NewRedisRateLimiter(rdb, "sso-start", ssoStartLimit, 15*time.Minute, h.logger)}
}

// SetupRouter builds the full chi router with all admin routes.
//
// own router_*.go file and owns exactly one domain's routes. The mount calls
// below follow the registration order of the pre-split monolith; each route
// keeps its original guard group (public | service | portal+portal-csrf |
func (h *AdminHandlers) SetupRouter() http.Handler {
	r := chi.NewRouter()

	// Per-request timeout — applied globally (30s default; wire via config struct when available)
	r.Use(httpmw.Timeout(30 * time.Second))

	// Body size limit — applies to all routes (1 MiB for admin API).
	// /api/rates/ carries full sealed operator pack envelopes, which can
	// exceed the small built-in reference pack — root-only routes get a
	// 16 MiB ceiling so a large promotion body passes (the
	// global 1 MiB ceiling refused them at the middleware; AUDIT-P1-04).
	r.Use(httpmw.MaxBodyByPrefix(1024*1024, 16*1024*1024, "/api/rates/"))

	// Security headers — applied globally
	r.Use(httpmw.SecurityHeaders())

	// Rate limiting middleware — global request limit
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.rateLimiter != nil {
				ip := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies)
				if !h.rateLimiter.allow(ip) {
					writeJSON(w, http.StatusTooManyRequests, apiError{Error: "rate limit exceeded"})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})

	h.mountPublic(r)        // /health, /metrics, /auth (login/logout/csrf/OIDC)
	h.mountSCIM(r)          // /scim/v2 provisioning server (bearer, NOT the admin session)
	h.mountPortal(r)        // developer portal (opt-in)
	h.initBillingHandlers() // PR1: construct credit/resale handlers (explicit deps)
	h.mountInternalAPI(r)   // read-only service API for CLI/automation (trcli)

	protected := h.protectedRouter()

	h.mountConsole(protected)                 // /api/me, /api/version, / dashboard
	h.mountAnalytics(protected)               // org-scoped analytics + label policy
	h.mountKeys(protected)                    // API keys + agent keys (org-permission groups)
	h.mountBilling(protected)                 // team budgets (org-permission group)
	h.mountOrgBudgetSettingsRoutes(protected) // NEXT-18f org budget settings (gates in the handlers)
	h.mountOrgCapsRoutes(protected)           // W-CAPS org caps: GET/PUT /api/orgs/{id}/caps (gates in the handlers)
	h.mountRoutingViews(protected)            // Provider health + routing map (org gates in the handlers)
	h.mountCurrenciesRoutes(protected)        // units spend + budgets + credits ledger + rates catalog (gates in the handlers)
	h.mountOrgs(protected)                    // members (+ developers when the portal is on)
	h.mountSCIMAdmin(protected)               // SCIM token issue/list/revoke (org:members.manage)
	h.mountOrgCredentials(protected)          // W-BYOK-API org provider credentials (org gates in the mount)
	h.mountPolicyPipelines(protected)         // OP-0b policy pipelines (org gates in the mount)
	h.mountCanaryRollouts(protected)          // Canary model rollouts (org gate in the mount)
	h.mountPolicyDecisions(protected)         // OP-9 policy decision log (org gate in the mount)
	h.mountPromptStudio(protected)            // Prompt studio (org gate in the mount)
	h.mountExplorer(protected)                // request explorer + lineage (org-permission groups)
	h.mountSecurityInbox(protected)           // E06-P01 security inbox reads (org:security.read)
	h.mountAudit(protected)                   // root-only audit journal + cross-org aggregates
	h.mountRootAdmin(protected)               // root-only CRUD, one mount per domain file
	h.mountFeedback(r)                        // classifier feedback (API-key auth, not admin-only)

	r.Mount("/", protected)

	return r
}

// protectedRouter builds the session-authenticated dashboard subrouter: the
// optional CORS middleware, the per-request session re-validation (TP-02),
// CSRF validation, and the JSON 404 for unknown /api/ paths. Domain mounts
// register their routes on top of it.
func (h *AdminHandlers) protectedRouter() chi.Router {
	protected := chi.NewRouter()

	// Wire CORS if configured
	if len(h.allowedOrigins) > 0 {
		protected.Use(validation.NewCORSMiddleware(validation.CORSConfig{
			AllowedOrigins:   h.allowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Request-ID", "Accept", "Origin", "X-CSRF-Token"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// TP-02: re-check the session user against the store on every request so a
	// deleted or demoted admin loses privileges when the DB says so, not when
	// the cookie expires. A lookup failure fails closed (401).
	protected.Use(h.sessionAuthMiddleware())
	protected.Use(adminauth.CSRFValidation())

	// JSON 404 for unknown API paths so API clients never fall through to the
	// plain-text chi 404 (or a browser-oriented response). Non-API paths keep
	// the default behavior.
	protected.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
			return
		}
		http.NotFound(w, r)
	})

	return protected
}

// mountRootAdmin registers the root-only CRUD surface. The single Group
// preserves the exact middleware chain of the pre-split router
// (MustBeRoot + OrgScopeMiddleware); each domain file mounts its slice onto
// the group router.
func (h *AdminHandlers) mountRootAdmin(protected chi.Router) {
	protected.Group(func(r chi.Router) {
		r.Use(adminauth.MustBeRoot())
		// S01: org dimension of the route×role×org authorization matrix.
		// Enforces X-Yabanin-Org-Id against the target org for org-scoped
		// mutations (403 on mismatch, 400 when the scope header is absent).
		// Runs inside the group, after MustBeRoot: root is an operator (any
		// org in scope); non-root currently 403s at MustBeRoot, so the scope
		// check is the future home for org-scoped admin roles.
		r.Use(OrgScopeMiddleware)

		h.mountOrgsRoot(r)               // router_orgs.go
		h.mountMCP(r)                    // router_mcp.go
		h.mountKeysRoot(r)               // router_keys.go
		h.mountModels(r)                 // router_models.go
		h.mountAnalyticsRoot(r)          // router_analytics.go
		h.mountBillingRoot(r)            // router_billing.go
		h.mountOps(r)                    // router_ops.go
		h.mountGuard(r)                  // router_guard (guardpacks.go): N02-P04/P08 guard pack lifecycle
		h.mountInventory(r)              // router_inventory.go: E02-P01 asset registry (root-only, wired unit)
		h.mountEntitlementDiagnostics(r) // entitlement_diagnostics_handlers.go: E01-P05 W04-C02
		h.mountFleet(r)                  // fleet_handlers.go: E03-P01 W04-C03 read-only fleet registry
	})
}

// Stop releases resources held by AdminHandlers (rate limiter goroutines,
// the audit delivery loop, etc).
func (h *AdminHandlers) Stop() {
	if h.rateLimiter != nil {
		h.rateLimiter.Stop()
	}
	if h.loginLimiter != nil {
		h.loginLimiter.Stop()
	}
	if h.ssoStartLimiter != nil {
		h.ssoStartLimiter.Stop()
	}
	h.auditMu.Lock()
	if h.auditCancel != nil {
		cancel := h.auditCancel
		h.auditCancel = nil
		h.auditMu.Unlock()
		cancel()
		return
	}
	h.auditMu.Unlock()
}

// ssoStartLimit is the per-IP budget for SSO flow STARTS (N04-P01 T10).
// Unlike the password login budget (5/15min — online credential guessing),
// a flow start carries no credential material: the cap exists to stop one
// address from minting unlimited state/PKCE flows and bouncing the console
// onto the IdP as a redirect amplifier. 30 per 15 min keeps multi-attempt
// resilience flows (lost cookies, interrupted logins) and small NAT offices
// working while cutting the amplification ceiling ~30x under the global
// per-IP limiter.
const ssoStartLimit = 30

// ssoStartRateLimitMiddleware enforces the SSO flow-start budget per client IP.
func (h *AdminHandlers) ssoStartRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.ssoStartLimiter == nil {
			next(w, r)
			return
		}
		ip := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies)
		if !h.ssoStartLimiter.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, apiError{Error: "too many login attempts, try again later"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loginRateLimitMiddleware enforces per-IP rate limiting on login attempts.
func (h *AdminHandlers) loginRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.loginLimiter == nil {
			next(w, r)
			return
		}
		ip := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), h.trustedProxies)
		if !h.loginLimiter.allow(ip) {
			writeJSON(w, http.StatusTooManyRequests, apiError{Error: "too many login attempts, try again later"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminSessionRevalidate feeds adminauth.ChiAuthMiddleware (TP-02): the
// current existence, active flag and root role come from the store on every
// request. Any lookup error is reported as such so the middleware can fail
// closed instead of trusting the cookie.
func (h *AdminHandlers) adminSessionRevalidate(ctx context.Context, userID string) (bool, bool, error) {
	u, err := h.store.GetAdminUserByID(ctx, userID)
	if err != nil {
		return false, false, err
	}
	return u.IsRoot, u.Active, nil
}
