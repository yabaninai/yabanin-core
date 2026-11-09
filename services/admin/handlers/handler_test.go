package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSON(t *testing.T) {
	rw := httptest.NewRecorder()
	writeJSON(rw, http.StatusOK, map[string]string{"key": "value"})

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(rw.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["key"] != "value" {
		t.Fatalf("expected key=value, got %q", result["key"])
	}
}

func TestWriteJSON_EmptyMap(t *testing.T) {
	rw := httptest.NewRecorder()
	writeJSON(rw, http.StatusCreated, map[string]interface{}{})

	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rw.Code)
	}
}

func TestWriteJSON_NilBody(t *testing.T) {
	rw := httptest.NewRecorder()
	defer func() { recover() }()
	writeJSON(rw, http.StatusOK, nil)
}

func TestHealthEndpoint(t *testing.T) {
	h := &AdminHandlers{}
	router := h.SetupRouter()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	router.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}
	if body := rw.Body.String(); body != "ok\n" && body != "ok" {
		t.Fatalf("expected 'ok', got %q", body)
	}
}

func TestSecurityHeadersApplied(t *testing.T) {
	h := &AdminHandlers{}
	router := h.SetupRouter()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	router.ServeHTTP(rw, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}
	for header, expected := range expectedHeaders {
		if got := rw.Header().Get(header); got != expected {
			t.Fatalf("expected %s=%q, got %q", header, expected, got)
		}
	}
}

func TestCSPHeaderApplied(t *testing.T) {
	h := &AdminHandlers{}
	router := h.SetupRouter()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	router.ServeHTTP(rw, req)

	csp := rw.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be set")
	}
	directives := []string{
		"default-src 'none'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"object-src 'none'",
	}
	for _, d := range directives {
		if !contains(csp, d) {
			t.Fatalf("expected CSP to contain %q, got %q", d, csp)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRateLimitMiddleware_Global(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	// Exhaust the rate limit for a single IP by sending many requests
	var lastRw *httptest.ResponseRecorder
	for i := 0; i < 1500; i++ {
		lastRw = httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		router.ServeHTTP(lastRw, req)
	}

	if lastRw.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after exhausting global limit, got %d", lastRw.Code)
	}

	// Another IP should still work
	rw2 := httptest.NewRecorder()
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	req2.RemoteAddr = "10.10.10.10:1234"
	router.ServeHTTP(rw2, req2)
	if rw2.Code != http.StatusOK {
		t.Fatalf("expected 200 for different IP, got %d", rw2.Code)
	}
}

func TestLoginRateLimitMiddleware(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	handler := h.loginRateLimitMiddleware(h.HandleLogin())

	// Send 6 login attempts from same IP (limit is 5 per 15min)
	for i := 0; i < 7; i++ {
		rw := httptest.NewRecorder()
		body := bytes.NewReader([]byte("email=test@test.com&password=password"))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", body)
		req.RemoteAddr = "2.2.2.2:1234"
		handler.ServeHTTP(rw, req)

		if i >= 5 && rw.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: expected 429 after exceeding login limit, got %d", i, rw.Code)
		}
	}
}

func TestLoginRateLimitMiddleware_DifferentIP(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	handler := h.loginRateLimitMiddleware(h.HandleLogin())

	// Exhaust IP 3.3.3.3
	for i := 0; i < 6; i++ {
		rw := httptest.NewRecorder()
		body := bytes.NewReader([]byte("email=x@x.com&password=p"))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", body)
		req.RemoteAddr = "3.3.3.3:1234"
		handler.ServeHTTP(rw, req)
	}

	// IP 4.4.4.4 should still be allowed
	rw := httptest.NewRecorder()
	body := bytes.NewReader([]byte("email=y@y.com&password=p"))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", body)
	req.RemoteAddr = "4.4.4.4:1234"
	handler.ServeHTTP(rw, req)

	// Should not be rate limited (may fail auth but not rate limit)
	if rw.Code == http.StatusTooManyRequests {
		t.Fatal("different IP should not be rate limited")
	}
}

func TestLoginRateLimitMiddleware_ForwardedFor(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	handler := h.loginRateLimitMiddleware(h.HandleLogin())

	// Send 6 requests with same X-Forwarded-For
	for i := 0; i < 7; i++ {
		rw := httptest.NewRecorder()
		body := bytes.NewReader([]byte("email=z@z.com&password=p"))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", body)
		req.Header.Set("X-Forwarded-For", "5.5.5.5")
		handler.ServeHTTP(rw, req)

		if i >= 5 && rw.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: expected 429 with X-Forwarded-For, got %d", i, rw.Code)
		}
	}
}

func TestLoginPage(t *testing.T) {
	h := &AdminHandlers{}
	handler := h.LoginPage()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/login", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for login page, got %d", rw.Code)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type text/html; charset=utf-8, got %q", ct)
	}
	body := rw.Body.String()
	if len(body) < 100 {
		t.Fatal("login page body seems too short")
	}
}

func TestLogout(t *testing.T) {
	h := &AdminHandlers{}
	handler := h.HandleLogout()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/logout", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect for logout, got %d", rw.Code)
	}
	location := rw.Header().Get("Location")
	if location != "/" && location != "" {
		t.Logf("logout redirects to %s", location)
	}
}

func TestSetupRouter_NilStore(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	router.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for health endpoint with nil store, got %d", rw.Code)
	}
}

func TestGenerateSessionKey(t *testing.T) {
	key1 := GenerateSessionKey()
	key2 := GenerateSessionKey()

	if len(key1) != 64 {
		t.Fatalf("expected 64-char hex key, got length %d", len(key1))
	}
	if key1 == key2 {
		t.Fatal("expected different session keys")
	}
}

func TestAdminHandlers_New(t *testing.T) {
	h := New(nil, "test-secret", "example.com", []string{})
	if h == nil {
		t.Fatal("expected non-nil AdminHandlers from New()")
	}
	if h.sessionSecret != "test-secret" {
		t.Fatalf("expected sessionSecret=test-secret, got %q", h.sessionSecret)
	}
	if h.domain != "example.com" {
		t.Fatalf("expected domain=example.com, got %q", h.domain)
	}
	if h.rateLimiter == nil {
		t.Fatal("expected rateLimiter to be initialized")
	}
	if h.loginLimiter == nil {
		t.Fatal("expected loginLimiter to be initialized")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := newRateLimiter(3, 100*time.Millisecond)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.allow("test-ip") {
			t.Fatalf("expected request %d to be allowed", i+1)
		}
	}

	if rl.allow("test-ip") {
		t.Fatal("expected 4th request to be denied")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := newRateLimiter(1, 100*time.Millisecond)
	defer rl.Stop()

	rl.allow("ip-1")
	if rl.allow("ip-1") {
		t.Fatal("expected ip-1 to be denied after limit")
	}
	if !rl.allow("ip-2") {
		t.Fatal("expected ip-2 to be allowed (different IP)")
	}
}

func TestRateLimiter_Expiry(t *testing.T) {
	rl := newRateLimiter(1, 50*time.Millisecond)
	defer rl.Stop()

	rl.allow("expire-ip")
	if rl.allow("expire-ip") {
		t.Fatal("expected request to be denied before expiry")
	}

	time.Sleep(60 * time.Millisecond)

	if !rl.allow("expire-ip") {
		t.Fatal("expected request to be allowed after expiry")
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := newRateLimiter(10, 1*time.Minute)

	done := make(chan struct{})
	go func() {
		// Verify cleanup goroutine is running by checking no deadlock
		time.Sleep(100 * time.Millisecond)
		close(done)
	}()
	<-done

	rl.Stop()

	// Double Stop should not panic
	rl.Stop()
}

func TestAdminHandlers_Stop(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})
	defer h.Stop()

	if h.rateLimiter == nil || h.loginLimiter == nil {
		t.Fatal("expected both limiters to be initialized")
	}

	h.Stop()
	h.Stop()
}

func TestAuditLogAction(t *testing.T) {
	h := New(nil, "test-secret-32-bytes-long-here!!", "", []string{})

	// Should not panic with nil store — uses in-memory buffer path
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, "admin-1")
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "Test Admin")
	h.auditLogAction(req.WithContext(ctx), "TEST_ACTION", "test-resource", "details")

	if len(h.auditLogBuffer) != 1 {
		t.Fatalf("expected 1 audit entry in buffer, got %d", len(h.auditLogBuffer))
	}
	if h.auditLogBuffer[0].AdminID != "admin-1" {
		t.Fatalf("expected admin_id=admin-1, got %q", h.auditLogBuffer[0].AdminID)
	}
}

func TestListAuditLogs_NilStore(t *testing.T) {
	h := &AdminHandlers{}
	handler := h.ListAuditLogs()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs?page=1&limit=50", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for audit logs with nil store, got %d", rw.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rw.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if data, ok := result["audit_logs"].([]interface{}); !ok || len(data) != 0 {
		t.Fatal("expected empty audit log list")
	}
	if total, ok := result["total"].(float64); !ok || total != 0 {
		t.Fatalf("expected total=0, got %v", total)
	}
}

func TestDashboard_NilStore(t *testing.T) {
	h := &AdminHandlers{}
	handler := h.dashboard()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for dashboard with nil store, got %d", rw.Code)
	}
}

func TestServeStatic(t *testing.T) {
	h := &AdminHandlers{}
	handler := h.serveStatic()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/nonexistent.html", nil)
	handler.ServeHTTP(rw, req)

	// Should return 404 since no static files exist
	if rw.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent static file, got %d", rw.Code)
	}
}

func TestAnalyticsEndpoints_NilStore(t *testing.T) {
	h := &AdminHandlers{}

	endpoints := map[string]func() http.HandlerFunc{
		"stats":         h.apiAnalyticsStats,
		"top-models":    h.apiTopModels,
		"top-orgs":      h.apiTopOrgs,
		"time-series":   h.apiTimeSeries,
		"errors":        h.apiErrorBreakdown,
		"latency":       h.apiLatency,
		"recent-errors": h.apiRecentErrors,
	}

	for name, fn := range endpoints {
		rw := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/an/"+name, nil)
		fn().ServeHTTP(rw, req)

		if rw.Code != http.StatusInternalServerError {
			t.Fatalf("analytics %s: expected 500 with nil store, got %d", name, rw.Code)
		}
	}
}

func TestAdminUsersEndpoints_NilStore(t *testing.T) {
	h := &AdminHandlers{}

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin-users", nil)
	h.ListAdminUsers().ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for ListAdminUsers with nil store, got %d", rw.Code)
	}
}

func TestCRUDEndpoints_List_NilStore(t *testing.T) {
	h := &AdminHandlers{}

	testCases := []struct {
		name string
		fn   func() http.HandlerFunc
	}{
		{"ListOrganizations", h.ListOrganizations},
		{"ListTeams", h.ListTeams},
		{"ListAPIKeys", h.ListAPIKeys},
		{"ListModels", h.ListModels},
	}

	for _, tc := range testCases {
		rw := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/"+tc.name, nil)
		tc.fn().ServeHTTP(rw, req)

		if rw.Code != http.StatusInternalServerError {
			t.Fatalf("%s: expected 500 with nil store, got %d", tc.name, rw.Code)
		}
	}
}

func TestCRUDCreate_InvalidJSON_NilStore(t *testing.T) {
	h := &AdminHandlers{}

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	h.CreateOrganization().ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for invalid JSON with nil store in CreateOrganization, got %d", rw.Code)
	}
}

func TestCRUDCreate_EmptyBody_NilStore(t *testing.T) {
	h := &AdminHandlers{}

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations", eofReader{})
	req.Header.Set("Content-Type", "application/json")
	h.CreateOrganization().ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for empty body with nil store in CreateOrganization, got %d", rw.Code)
	}
}

func TestAuditMiddleware_RequestID_NotPanic(t *testing.T) {
	logger := &mockAuditLogger{}
	mw := AuditMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}
	if rw.Header().Get("X-Request-Id") != "" {
		t.Fatal("expected no X-Request-Id header when requestID is not in context")
	}
}

func TestAuditMiddleware_RequestID_Set(t *testing.T) {
	logger := &mockAuditLogger{}
	mw := AuditMiddleware(logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), contextKey("requestID"), "req-abc-123")
	req = req.WithContext(ctx)

	handler.ServeHTTP(rw, req)

	if rw.Header().Get("X-Request-Id") != "req-abc-123" {
		t.Fatalf("expected X-Request-Id=req-abc-123, got %q", rw.Header().Get("X-Request-Id"))
	}
}

// mockAuditLogger is a minimal AuditLogger implementation for tests.
type mockAuditLogger struct{}

func (*mockAuditLogger) LogEntry(_ context.Context, _ AuditLogEntry) error { return nil }

// EOFReader implements io.Reader that always returns EOF
type eofReader struct{}

func (eofReader) Read(p []byte) (int, error) { return 0, io.EOF }

// ---- mockStore implementing StoreInterface for CRUD/Analytics/Whitelist tests ----

type mockStore struct {
	log            *slog.Logger
	adminUsers     map[string]*adminstore.AdminUser
	orgs           map[string]*adminstore.Organization
	teams          map[string]*adminstore.Team
	apiKeys        map[string]*adminstore.APIKey
	sessionHashes  map[string][]string
	revokedParents []string
	agentKeys      map[string]*adminstore.AgentKey
	agentProfiles  map[string]*adminstore.AgentProfile
	orgMembers     map[string]*adminstore.OrgMembership // key: userID/orgID (ENT-02)
	// N04-P01 SSO group→role mapping state (key: orgID|group|effect and
	// orgID|userID) so handler tests exercise the login-time sync end to end.
	ssoRules  map[string]*adminstore.SSOGroupRoleRule
	ssoGrants map[string]adminstore.OrgRole
	ssoErr    error // fails the next mapping store call (outage path)
	// ssoSetGrantErr / ssoSetMemberErr fail exactly one write of the grant
	// path (provenance / membership respectively), after the decision inputs
	// read fine — the split-failure knob for the convergence contract tests.
	ssoSetGrantErr  error
	ssoSetMemberErr error
	models          map[string]*adminstore.ModelRegistry
	rules           map[string]*adminstore.RoutingRule
	keyWhitelist    map[string][]*adminstore.WhitelistEntry
	teamWhitelist   map[string][]*adminstore.WhitelistEntry
	// AF-09: budget state the budget mocks read and write, so precondition
	// (CAS) semantics can be exercised at handler level. teamSpends carries
	// GetTeamSpendSummary (stored budget + spend; absent row fail-closed).
	teamBudgets  map[string]*adminstore.TeamBudget
	teamSpends   map[string]float64
	agentBudgets map[string]*adminstore.AgentBudget
	// AUDIT-P1-03: one-shot error for the checked delegation-budget calls.
	delegationErr error
	// AUTH-01: platform-level global roles (admin_users.global_role). The
	// global audit gate must consult ONLY this — never org memberships.
	globalRoles   map[string]string
	globalRoleErr error
	// team-budget mocks fail so handler outage paths are provable
	// (partial/unknown store states must never read as success).
	orgSettingsErr     error
	teamBudgetUpsert   error
	requestLogStats    *adminstore.RequestLogStats
	topModels          []adminstore.TopModelCount
	topOrgs            []adminstore.TopOrgCount
	timeSeries         []adminstore.TimeSeriesPoint
	errorBreakdown     []adminstore.ErrorBreakdownEntry
	latencyPercentiles *adminstore.LatencyPercentile
	recentErrors       []adminstore.RecentErrorLog
	// AF-10: durable audit capability state. insertAuditErr/enqueueOutboxErr
	// simulate store failures for the no-durable-success tests.
	auditMu            sync.Mutex
	auditRecords       []adminstore.AuditLogEntryRecord
	auditOutbox        []adminstore.AuditLogEntryRecord
	auditSeq           int64
	insertAuditErr     error
	enqueueOutboxErr   error
	err                error
	lastRequestFilters adminstore.RequestListFilters
	experiments        map[string]*cache.Experiment
	analytics          *adminstore.AnalyticsResult
	pricingImport      func(catalog pricing.PriceFile, mappings []adminstore.CatalogPriceMap, onlyMapped, apply bool, updatedBy string) (adminstore.CatalogImportResult, error)
}

func newMockStore() *mockStore {
	m := &mockStore{
		log:                slog.Default(),
		adminUsers:         make(map[string]*adminstore.AdminUser),
		orgs:               make(map[string]*adminstore.Organization),
		teams:              make(map[string]*adminstore.Team),
		apiKeys:            make(map[string]*adminstore.APIKey),
		agentKeys:          make(map[string]*adminstore.AgentKey),
		agentProfiles:      make(map[string]*adminstore.AgentProfile),
		orgMembers:         make(map[string]*adminstore.OrgMembership),
		ssoRules:           make(map[string]*adminstore.SSOGroupRoleRule),
		ssoGrants:          make(map[string]adminstore.OrgRole),
		teamBudgets:        make(map[string]*adminstore.TeamBudget),
		teamSpends:         make(map[string]float64),
		agentBudgets:       make(map[string]*adminstore.AgentBudget),
		globalRoles:        make(map[string]string),
		models:             make(map[string]*adminstore.ModelRegistry),
		rules:              make(map[string]*adminstore.RoutingRule),
		keyWhitelist:       make(map[string][]*adminstore.WhitelistEntry),
		teamWhitelist:      make(map[string][]*adminstore.WhitelistEntry),
		requestLogStats:    &adminstore.RequestLogStats{TotalRequests: 100, SuccessRate: 0.95, AvgDurationMs: 42.5},
		topModels:          []adminstore.TopModelCount{{ModelName: "gpt-4", Count: 50}, {ModelName: "claude-3", Count: 30}},
		topOrgs:            []adminstore.TopOrgCount{{OrgID: "org-1", Slug: "acme", Count: 80, TokensIn: 1000}},
		timeSeries:         []adminstore.TimeSeriesPoint{{Time: "2024-01-01T00:00:00Z", Value: 10}, {Time: "2024-01-01T01:00:00Z", Value: 20}},
		errorBreakdown:     []adminstore.ErrorBreakdownEntry{{Category: "server_error", Count: 5}, {Category: "client_error", Count: 10}},
		latencyPercentiles: &adminstore.LatencyPercentile{P50: 30.0, P90: 80.0, P95: 120.0, P99: 200.0},
		recentErrors:       []adminstore.RecentErrorLog{{ID: 1, OrgID: "org-1", ModelUsed: "gpt-4", StatusCode: 500, DurationMs: 100, Error: "timeout"}},
	}
	// TP-02: session revalidation resolves the cookie's user in the store, so
	// the fixture users referenced by makeSessionCookie must exist here.
	m.adminUsers["admin-root"] = &adminstore.AdminUser{ID: "admin-root", Email: "root@example.com", DisplayName: "Root", IsRoot: true, Active: true}
	m.adminUsers["admin-1"] = &adminstore.AdminUser{ID: "admin-1", Email: "test@example.com", DisplayName: "Admin", IsRoot: false, Active: true}
	return m
}

func (m *mockStore) Log() *slog.Logger                                                  { return m.log }
func (m *mockStore) InsertAuditLog(_ context.Context, _, _, _, _, _, _, _ string) error { return nil }

// ---- AF-10 durable audit capability (mockStore implements AuditJournalStore,
// so handler tests exercise the synchronous persisted path) ----

func (m *mockStore) InsertAuditLogEntry(_ context.Context, rec adminstore.AuditLogEntryRecord) error {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	if m.insertAuditErr != nil {
		return m.insertAuditErr
	}
	m.auditSeq++
	m.auditRecords = append(m.auditRecords, rec)
	return nil
}

func (m *mockStore) ListAuditLogEntries(_ context.Context, q adminstore.AuditLogQuery) ([]adminstore.AuditLogEntry, int64, int64, error) {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	total := int64(len(m.auditRecords))
	start := int64(q.Page-1) * int64(q.PageSize)
	if start < 0 || start >= int64(len(m.auditRecords)) {
		return nil, total, int64(len(m.auditOutbox)), nil
	}
	end := start + int64(q.PageSize)
	if end > int64(len(m.auditRecords)) {
		end = int64(len(m.auditRecords))
	}
	items := make([]adminstore.AuditLogEntry, 0, end-start)
	for _, rec := range m.auditRecords[start:end] {
		items = append(items, adminstore.AuditLogEntry{
			ID: rec.ID, Action: rec.Action, Resource: rec.Resource, Details: rec.Details,
			AdminID: rec.AdminID, AdminName: rec.AdminName, IPAddress: rec.IPAddress,
			Timestamp: rec.CreatedAt, Before: json.RawMessage(rec.Before), After: json.RawMessage(rec.After), Reason: rec.Reason,
		})
	}
	return items, total, int64(len(m.auditOutbox)), nil
}

func (m *mockStore) EnqueueAuditOutbox(_ context.Context, rec adminstore.AuditLogEntryRecord) error {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	if m.enqueueOutboxErr != nil {
		return m.enqueueOutboxErr
	}
	m.auditOutbox = append(m.auditOutbox, rec)
	return nil
}

func (m *mockStore) DrainAuditOutbox(_ context.Context, limit int) (int, error) {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	delivered := 0
	for len(m.auditOutbox) > 0 && delivered < limit {
		rec := m.auditOutbox[0]
		m.auditOutbox = m.auditOutbox[1:]
		m.auditSeq++
		m.auditRecords = append(m.auditRecords, rec)
		delivered++
	}
	return delivered, nil
}

// lastAuditRecord returns the most recently captured audit record.
func (m *mockStore) lastAuditRecord(t *testing.T) adminstore.AuditLogEntryRecord {
	t.Helper()
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	require.NotEmpty(t, m.auditRecords, "no audit records captured")
	return m.auditRecords[len(m.auditRecords)-1]
}

// auditRecordByIndex returns the captured audit record at the given
// insertion index.
func (m *mockStore) auditRecordByIndex(t *testing.T, i int) adminstore.AuditLogEntryRecord {
	t.Helper()
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	require.Less(t, i, len(m.auditRecords), "audit record index out of range")
	return m.auditRecords[i]
}

// auditRecordCount returns how many audit records have been captured.
func (m *mockStore) auditRecordCount() int {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	return len(m.auditRecords)
}
func (m *mockStore) CreateAdminUser(_ context.Context, email, displayName, passwordHash string, isRoot bool) (*adminstore.AdminUser, error) {
	u := &adminstore.AdminUser{ID: "admin-1", Email: email, DisplayName: displayName, IsRoot: isRoot, Active: true}
	m.adminUsers[u.ID] = u
	return u, nil
}
func (m *mockStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	u, ok := m.adminUsers[id]
	if !ok {
		return nil, fmt.Errorf("admin user not found")
	}
	return u, nil
}
func (m *mockStore) GetAdminUserByEmailWithHash(_ context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	for _, u := range m.adminUsers {
		if u.Email == email {
			return &adminstore.AdminUserWithHash{ID: u.ID, Email: u.Email, PasswordHash: "hash", DisplayName: u.DisplayName, IsRoot: u.IsRoot, Active: u.Active}, nil
		}
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListAdminUsers(_ context.Context, _ bool, f adminstore.PageFilter) ([]*adminstore.AdminUser, int64, error) {
	var result []*adminstore.AdminUser
	for _, u := range m.adminUsers {
		result = append(result, u)
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateAdminUser(_ context.Context, id string, displayName *string, isRoot *bool) error {
	u, ok := m.adminUsers[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	if displayName != nil {
		u.DisplayName = *displayName
	}
	if isRoot != nil {
		u.IsRoot = *isRoot
	}
	return nil
}
func (m *mockStore) DeleteAdminUser(_ context.Context, id string) error {
	if _, ok := m.adminUsers[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.adminUsers, id)
	return nil
}
func (m *mockStore) CreateOrganization(_ context.Context, name, slug string) (*adminstore.Organization, error) {
	o := &adminstore.Organization{ID: "org-1", Name: name, Slug: slug}
	m.orgs[o.ID] = o
	return o, nil
}
func (m *mockStore) GetOrganizationByID(_ context.Context, id string) (*adminstore.Organization, error) {
	o, ok := m.orgs[id]
	if !ok {
		return nil, fmt.Errorf("org not found")
	}
	return o, nil
}
func (m *mockStore) ListOrganizations(_ context.Context, f adminstore.PageFilter) ([]*adminstore.Organization, int64, error) {
	var result []*adminstore.Organization
	for _, o := range m.orgs {
		result = append(result, o)
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateOrganization(_ context.Context, id, name, slug, currency, timezone string, issueURL *string) error {
	o, ok := m.orgs[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	o.Name = name
	o.Slug = slug
	if currency != "" {
		o.Currency = currency
	}
	if timezone != "" {
		o.Timezone = timezone
	}
	if issueURL != nil {
		o.IssueURLTemplate = *issueURL
	}
	return nil
}
func (m *mockStore) DeleteOrganization(_ context.Context, id string) error {
	if _, ok := m.orgs[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.orgs, id)
	return nil
}
func (m *mockStore) GetOrgCacheSettings(_ context.Context, orgID string) (*adminstore.OrgCacheSettings, error) {
	if org, ok := m.orgs[orgID]; ok {
		return &adminstore.OrgCacheSettings{CacheEnabled: org.CacheEnabled, CacheMode: org.CacheMode}, nil
	}
	return nil, fmt.Errorf("organization not found")
}
func (m *mockStore) UpdateOrgCacheSettings(_ context.Context, orgID string, enabled bool, mode string) error {
	if org, ok := m.orgs[orgID]; ok {
		org.CacheEnabled = enabled
		org.CacheMode = mode
		return nil
	}
	return fmt.Errorf("organization not found")
}
func (m *mockStore) GetOrgRoutingSettings(_ context.Context, orgID string) (*adminstore.OrgRoutingSettings, error) {
	if org, ok := m.orgs[orgID]; ok {
		return &adminstore.OrgRoutingSettings{
			RoutingMode:                org.RoutingMode,
			RoutingThresholdConfidence: org.RoutingThresholdConfidence,
		}, nil
	}
	return nil, fmt.Errorf("organization not found")
}
func (m *mockStore) UpdateOrgRoutingSettings(_ context.Context, orgID string, mode string, threshold float64) error {
	if org, ok := m.orgs[orgID]; ok {
		org.RoutingMode = mode
		org.RoutingThresholdConfidence = threshold
		return nil
	}
	return fmt.Errorf("organization not found")
}
func (m *mockStore) BumpModelVersion(_ context.Context, modelName string) error {
	if _, ok := m.models[modelName]; !ok {
		return fmt.Errorf("model not found")
	}
	return nil
}
func (m *mockStore) GetCacheAnalytics(_ context.Context, orgID string, from, to time.Time) (*adminstore.CacheAnalytics, error) {
	return &adminstore.CacheAnalytics{
		TotalRequests:      100,
		HitsExact:          30,
		HitsSemantic:       20,
		Misses:             50,
		CacheHitRate:       0.5,
		SavingsUSD:         1.23,
		CounterfactualCost: 2.46,
		AvgSimilarity:      0.97,
	}, nil
}

// A/B experiment mock methods.
func (m *mockStore) CreateExperiment(_ context.Context, name, orgID string, trafficPct int) (*cache.Experiment, error) {
	return &cache.Experiment{ID: "exp-1", Name: name, OrgID: orgID, TrafficPct: trafficPct, Enabled: true}, nil
}
func (m *mockStore) GetExperiment(_ context.Context, id string) (*cache.Experiment, error) {
	if exp, ok := m.experiments[id]; ok {
		return exp, nil
	}
	return nil, fmt.Errorf("experiment not found")
}
func (m *mockStore) ListExperiments(_ context.Context, orgID string, onlyEnabled bool) ([]*cache.Experiment, error) {
	var results []*cache.Experiment
	for _, exp := range m.experiments {
		if orgID != "" && exp.OrgID != orgID {
			continue
		}
		if onlyEnabled && !exp.Enabled {
			continue
		}
		results = append(results, exp)
	}
	return results, nil
}
func (m *mockStore) UpdateExperiment(_ context.Context, id string, trafficPct *int, enabled *bool) error {
	if _, ok := m.experiments[id]; !ok {
		return fmt.Errorf("experiment not found")
	}
	return nil
}
func (m *mockStore) DeleteExperiment(_ context.Context, id string) error {
	if _, ok := m.experiments[id]; !ok {
		return fmt.Errorf("experiment not found")
	}
	delete(m.experiments, id)
	return nil
}
func (m *mockStore) GetCacheResults(_ context.Context, experimentID string) (map[string]float64, error) {
	return map[string]float64{
		"control_savings_usd":   0.5,
		"treatment_savings_usd": 1.2,
	}, nil
}

func (m *mockStore) CreateTeam(_ context.Context, orgID, name, slug string, parentTeamID *string) (*adminstore.Team, error) {
	t := &adminstore.Team{ID: "team-1", OrgID: orgID, Name: name, Slug: slug}
	if parentTeamID != nil {
		t.ParentTeam = parentTeamID
	}
	m.teams[t.ID] = t
	return t, nil
}

func (m *mockStore) GetDefaultTeam(_ context.Context, orgID string) (*adminstore.Team, error) {
	return &adminstore.Team{ID: "team-default", OrgID: orgID, Name: "Default", Slug: "default"}, nil
}

func (m *mockStore) GetTeamByID(_ context.Context, id string) (*adminstore.Team, error) {
	t, ok := m.teams[id]
	if !ok {
		return nil, fmt.Errorf("team not found")
	}
	return t, nil
}
func (m *mockStore) ListTeamsByOrg(_ context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.Team, int64, error) {
	var result []*adminstore.Team
	for _, t := range m.teams {
		if t.OrgID == orgID {
			result = append(result, t)
		}
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateTeam(_ context.Context, id, name, slug string, parentTeamID *string) error {
	t, ok := m.teams[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	if name != "" {
		t.Name = name
	}
	if slug != "" {
		t.Slug = slug
	}
	if parentTeamID != nil {
		t.ParentTeam = parentTeamID
	}
	return nil
}
func (m *mockStore) DeleteTeam(_ context.Context, id string) error {
	if _, ok := m.teams[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.teams, id)
	return nil
}
func (m *mockStore) CreateAPIKey(_ context.Context, keyHash, name string, orgID *string, teamID *string) (*adminstore.APIKey, error) {
	k := &adminstore.APIKey{ID: "key-1", KeyHash: keyHash, Name: name, Active: true}
	k.OrgID = orgID
	k.TeamID = teamID
	m.apiKeys[k.ID] = k
	return k, nil
}
func (m *mockStore) GetAPIKeyByID(_ context.Context, id string) (*adminstore.APIKey, error) {
	k, ok := m.apiKeys[id]
	if !ok {
		return nil, fmt.Errorf("api key not found")
	}
	return k, nil
}
func (m *mockStore) ListAPIKeys(_ context.Context, orgID *string, f adminstore.PageFilter) ([]*adminstore.APIKey, int64, error) {
	var result []*adminstore.APIKey
	for _, k := range m.apiKeys {
		if orgID == nil || (k.OrgID != nil && *k.OrgID == *orgID) {
			result = append(result, k)
		}
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateAPIKeyActive(_ context.Context, id string, active bool) error {
	k, ok := m.apiKeys[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	k.Active = active
	return nil
}

// AF-09: CAS semantics mirror the SQL statement — the expectation is checked
// against the stored row and only a matching row is mutated.
func (m *mockStore) UpdateAPIKeyActivePreconditioned(_ context.Context, id string, active bool, expectActive *bool) (*bool, error) {
	k, ok := m.apiKeys[id]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	current := k.Active
	if expectActive != nil && k.Active != *expectActive {
		return &current, adminstore.ErrPreconditionFailed
	}
	k.Active = active
	return &current, nil
}

func (m *mockStore) UpdateRoutingRuleEnabledPreconditioned(_ context.Context, id string, enabled bool, expectEnabled *bool) (*bool, error) {
	r, ok := m.rules[id]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	current := r.Enabled
	if expectEnabled != nil && r.Enabled != *expectEnabled {
		return &current, adminstore.ErrPreconditionFailed
	}
	r.Enabled = enabled
	return &current, nil
}

func (m *mockStore) UpdateAPIKeyLabelsPreconditioned(_ context.Context, id string, labels map[string]string, locked, mint, usage bool, expect *adminstore.APIKeyLabelsState) (*adminstore.APIKeyLabelsState, error) {
	k, ok := m.apiKeys[id]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	if labels == nil {
		labels = map[string]string{}
	}
	if expect != nil {
		expectLabels := expect.Labels
		if expectLabels == nil {
			expectLabels = map[string]string{}
		}
		if !maps.Equal(k.Labels, expectLabels) ||
			k.LabelsLocked != expect.LabelsLocked ||
			k.CanMintSessions != expect.CanMintSessions ||
			k.CanReadUsage != expect.CanReadUsage {
			current := &adminstore.APIKeyLabelsState{
				Labels:          k.Labels,
				LabelsLocked:    k.LabelsLocked,
				CanMintSessions: k.CanMintSessions,
				CanReadUsage:    k.CanReadUsage,
			}
			return current, adminstore.ErrPreconditionFailed
		}
	}
	k.Labels = labels
	k.LabelsLocked = locked
	k.CanMintSessions = mint
	k.CanReadUsage = usage
	return &adminstore.APIKeyLabelsState{Labels: labels, LabelsLocked: locked, CanMintSessions: mint, CanReadUsage: usage}, nil
}
func (m *mockStore) RotateAPIKey(_ context.Context, id, newHash string) error {
	k, ok := m.apiKeys[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	k.KeyHash = newHash
	return nil
}
func (m *mockStore) RevokeSessionKeysByParent(_ context.Context, parentID string) ([]string, error) {
	m.revokedParents = append(m.revokedParents, parentID)
	if m.sessionHashes == nil {
		return nil, nil
	}
	return m.sessionHashes[parentID], nil
}

func (m *mockStore) UpdateAPIKeyLabels(_ context.Context, id string, labels map[string]string, locked, mint, usage bool) error {
	k, ok := m.apiKeys[id]
	if !ok {
		return adminstore.ErrNotFound
	}
	if labels == nil {
		labels = map[string]string{}
	}
	k.Labels = labels
	k.LabelsLocked = locked
	k.CanMintSessions = mint
	k.CanReadUsage = usage
	return nil
}

func (m *mockStore) DeleteAPIKey(_ context.Context, id string) error {
	if _, ok := m.apiKeys[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.apiKeys, id)
	return nil
}
func (m *mockStore) CreateAgentKey(_ context.Context, keyHash, name, orgID string) (*adminstore.AgentKey, error) {
	k := &adminstore.AgentKey{ID: "agent-key-1", KeyHash: keyHash, Name: name, OrgID: orgID, Active: true}
	m.agentKeys[k.ID] = k
	return k, nil
}
func (m *mockStore) CreateAgentKeyDelegated(_ context.Context, p adminstore.AgentKeyCreateParams) (*adminstore.AgentKey, error) {
	k := &adminstore.AgentKey{ID: "agent-key-child", KeyHash: p.KeyHash, Name: p.Name, OrgID: p.OrgID, Active: true,
		ParentID: p.ParentID, ExpiresAt: p.ExpiresAt, DailyLimitCents: p.DailyLimitCents}
	m.agentKeys[k.ID] = k
	return k, nil
}
func (m *mockStore) GetAgentKeyByID(_ context.Context, id string) (*adminstore.AgentKey, error) {
	k, ok := m.agentKeys[id]
	if !ok {
		return nil, fmt.Errorf("agent key not found")
	}
	return k, nil
}
func (m *mockStore) ListAgentKeys(_ context.Context, orgID string) ([]*adminstore.AgentKey, error) {
	var out []*adminstore.AgentKey
	for _, k := range m.agentKeys {
		if k.OrgID == orgID {
			out = append(out, k)
		}
	}
	return out, nil
}
func (m *mockStore) GetAgentBudget(_ context.Context, agentID string) (*adminstore.AgentBudget, error) {
	if b, ok := m.agentBudgets[agentID]; ok {
		return &adminstore.AgentBudget{AgentID: b.AgentID, DailyLimitCents: b.DailyLimitCents, UpdatedAt: b.UpdatedAt}, nil
	}
	return &adminstore.AgentBudget{AgentID: agentID, DailyLimitCents: 5000}, nil
}
func (m *mockStore) UpsertAgentBudget(_ context.Context, agentID string, cents int64) (*adminstore.AgentBudget, error) {
	b := &adminstore.AgentBudget{AgentID: agentID, DailyLimitCents: cents}
	m.agentBudgets[agentID] = b
	return &adminstore.AgentBudget{AgentID: agentID, DailyLimitCents: cents}, nil
}
func (m *mockStore) DeleteAgentBudget(_ context.Context, agentID string) error {
	delete(m.agentBudgets, agentID)
	return nil
}

// AF-09: agent budget CAS against the mock's stored rows.
func (m *mockStore) UpsertAgentBudgetPreconditioned(_ context.Context, agentID string, cents int64, expect *adminstore.AgentBudgetExpectation) (*adminstore.AgentBudget, error) {
	cur, ok := m.agentBudgets[agentID]
	if expect != nil {
		if expect.Absent {
			if ok {
				return &adminstore.AgentBudget{AgentID: cur.AgentID, DailyLimitCents: cur.DailyLimitCents}, adminstore.ErrPreconditionFailed
			}
		} else if !ok || cur.DailyLimitCents != expect.DailyLimitCents {
			var current *adminstore.AgentBudget
			if ok {
				current = &adminstore.AgentBudget{AgentID: cur.AgentID, DailyLimitCents: cur.DailyLimitCents}
			}
			return current, adminstore.ErrPreconditionFailed
		}
	}
	b := &adminstore.AgentBudget{AgentID: agentID, DailyLimitCents: cents}
	m.agentBudgets[agentID] = b
	return &adminstore.AgentBudget{AgentID: agentID, DailyLimitCents: cents}, nil
}

func (m *mockStore) DeleteAgentBudgetPreconditioned(_ context.Context, agentID string, expectCents int64) (bool, *adminstore.AgentBudget, error) {
	cur, ok := m.agentBudgets[agentID]
	if !ok || cur.DailyLimitCents != expectCents {
		var current *adminstore.AgentBudget
		if ok {
			current = &adminstore.AgentBudget{AgentID: cur.AgentID, DailyLimitCents: cur.DailyLimitCents}
		}
		return false, current, adminstore.ErrPreconditionFailed
	}
	delete(m.agentBudgets, agentID)
	return true, nil, nil
}

// ---- AUDIT-P1-03: delegation-budget capability methods on the mock ----
// delegationErr, when set, fails exactly ONE checked delegation-budget call
// with that error (sentinel→HTTP mapping and outage tests); the mock then
// clears it. The checked mocks otherwise mirror the production invariant at
// toy scale: the parent budget row must exist and the cap must fit under
// it (the enforcement semantics themselves are proven against real Postgres
// in pkg/adminstore/agent_budgets_delegation_int_test.go).

// checkedDelegationErr consumes the one-shot injected error.
func (m *mockStore) checkedDelegationErr() error {
	err := m.delegationErr
	m.delegationErr = nil
	return err
}

func (m *mockStore) CreateAgentKeyDelegatedChecked(ctx context.Context, p adminstore.AgentKeyCreateParams) (*adminstore.AgentKey, error) {
	if err := m.checkedDelegationErr(); err != nil {
		return nil, err
	}
	if p.ParentID != nil && p.DailyLimitCents != nil {
		pb, ok := m.agentBudgets[*p.ParentID]
		if !ok {
			return nil, fmt.Errorf("%w: parent %s", adminstore.ErrParentBudgetMissing, *p.ParentID)
		}
		if *p.DailyLimitCents > pb.DailyLimitCents {
			return nil, fmt.Errorf("%w: cap %d > parent limit %d",
				adminstore.ErrDelegationHeadroomExceeded, *p.DailyLimitCents, pb.DailyLimitCents)
		}
	}
	key, err := m.CreateAgentKeyDelegated(ctx, p)
	if err != nil {
		return nil, err
	}
	if key != nil && p.DailyLimitCents != nil {
		// Production writes the enforcement row in the same transaction;
		// the mock mirrors that so downstream reads see the cap.
		m.agentBudgets[key.ID] = &adminstore.AgentBudget{AgentID: key.ID, DailyLimitCents: *p.DailyLimitCents, UpdatedAt: time.Now()}
	}
	return key, nil
}

// childBudgetHeadroomErr validates parent-key resolution and the headroom
// invariant WITHOUT writing — the plain and CAS-checked upserts both use it
// before choosing their write strategy.
func (m *mockStore) childBudgetHeadroomErr(agentID string, cents int64) error {
	k, ok := m.agentKeys[agentID]
	if !ok {
		return adminstore.ErrNotFound
	}
	if k.ParentID != nil {
		pb, ok := m.agentBudgets[*k.ParentID]
		if !ok {
			return fmt.Errorf("%w: parent %s", adminstore.ErrParentBudgetMissing, *k.ParentID)
		}
		if cents > pb.DailyLimitCents {
			return fmt.Errorf("%w: cap %d > parent limit %d",
				adminstore.ErrDelegationHeadroomExceeded, cents, pb.DailyLimitCents)
		}
	}
	return nil
}

func (m *mockStore) UpsertAgentBudgetChecked(ctx context.Context, agentID string, cents int64) (*adminstore.AgentBudget, error) {
	if err := m.checkedDelegationErr(); err != nil {
		return nil, err
	}
	if err := m.childBudgetHeadroomErr(agentID, cents); err != nil {
		return nil, err
	}
	return m.UpsertAgentBudget(ctx, agentID, cents)
}

func (m *mockStore) UpsertAgentBudgetPreconditionedChecked(ctx context.Context, agentID string, cents int64, expect *adminstore.AgentBudgetExpectation) (*adminstore.AgentBudget, error) {
	// Headroom first (like production), then the CAS semantics — never an
	// unconditional write before the CAS comparison.
	if err := m.checkedDelegationErr(); err != nil {
		return nil, err
	}
	if err := m.childBudgetHeadroomErr(agentID, cents); err != nil {
		return nil, err
	}
	return m.UpsertAgentBudgetPreconditioned(ctx, agentID, cents, expect)
}

func (m *mockStore) RevokeAgentKey(_ context.Context, id string) error {
	k, ok := m.agentKeys[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	k.Active = false
	return nil
}
func (m *mockStore) CreateModel(_ context.Context, modelName, displayName, tier string, upstreamURL, upstreamAPIKey *string) (*adminstore.ModelRegistry, error) {
	m2 := &adminstore.ModelRegistry{ID: "model-1", ModelName: modelName, DisplayName: displayName, Tier: tier}
	m2.UpstreamURL = upstreamURL
	m2.UpstreamAPIKey = upstreamAPIKey
	m.models[m2.ID] = m2
	return m2, nil
}
func (m *mockStore) CreateModelWithParams(_ context.Context, p adminstore.CreateModelParams) (*adminstore.ModelRegistry, error) {
	if p.Provider == "" {
		p.Provider = "openai-compat"
	}
	m2 := &adminstore.ModelRegistry{
		ID: "model-1", ModelName: p.ModelName, DisplayName: p.DisplayName, Tier: p.Tier,
		Provider: p.Provider,
	}
	if p.UpstreamURL != nil {
		m2.UpstreamURL = p.UpstreamURL
	}
	if p.UpstreamAPIKey != nil {
		m2.UpstreamAPIKey = p.UpstreamAPIKey
	}
	if p.FallbackModel != nil {
		m2.FallbackModel = p.FallbackModel
	}
	if len(p.FailoverModels) > 0 {
		m2.FailoverModels = p.FailoverModels
	} else {
		m2.FailoverModels = []string{}
	}
	if len(p.TierPool) > 0 {
		m2.TierPool = p.TierPool
	} else {
		m2.TierPool = []string{}
	}
	m2.UpstreamTimeoutMs = p.UpstreamTimeoutMs
	m.models[m2.ID] = m2
	return m2, nil
}
func (m *mockStore) GetModelByName(_ context.Context, modelName string) (*adminstore.ModelRegistry, error) {
	for _, m2 := range m.models {
		if m2.ModelName == modelName {
			return m2, nil
		}
	}
	return nil, fmt.Errorf("model not found")
}
func (m *mockStore) ListModels(_ context.Context, f adminstore.PageFilter) ([]*adminstore.ModelRegistry, int64, error) {
	var result []*adminstore.ModelRegistry
	for _, m2 := range m.models {
		result = append(result, m2)
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateModel(_ context.Context, modelName, displayName string, tier *string, upstreamURL *string, upstreamAPIKey *string, enabled *bool) error {
	for _, m2 := range m.models {
		if m2.ModelName == modelName {
			m2.DisplayName = displayName
			if tier != nil {
				m2.Tier = *tier
			}
			if upstreamURL != nil {
				m2.UpstreamURL = upstreamURL
			}
			if upstreamAPIKey != nil {
				m2.UpstreamAPIKey = upstreamAPIKey
			}
			if enabled != nil {
				m2.Enabled = *enabled
			}
			return nil
		}
	}
	return fmt.Errorf("model not found")
}
func (m *mockStore) UpdateModelWithParams(_ context.Context, p adminstore.UpdateModelParams) error {
	for _, m2 := range m.models {
		if m2.ModelName == p.ModelName {
			if p.DisplayName != nil {
				m2.DisplayName = *p.DisplayName
			}
			if p.Tier != nil {
				m2.Tier = *p.Tier
			}
			if p.UpstreamURL != nil {
				m2.UpstreamURL = p.UpstreamURL
			}
			if p.UpstreamAPIKey != nil {
				m2.UpstreamAPIKey = &[]string{*p.UpstreamAPIKey}[0]
			}
			if p.ClearUpstreamKey {
				m2.UpstreamAPIKey = nil
			}
			if p.Provider != nil {
				m2.Provider = *p.Provider
			}
			if p.FallbackModel != nil {
				m2.FallbackModel = p.FallbackModel
			}
			if len(p.FailoverModels) > 0 {
				m2.FailoverModels = p.FailoverModels
			}
			if len(p.TierPool) > 0 {
				m2.TierPool = p.TierPool
			}
			if p.UpstreamTimeoutMs != nil {
				m2.UpstreamTimeoutMs = p.UpstreamTimeoutMs
			}
			if p.Enabled != nil {
				m2.Enabled = *p.Enabled
			}
			return nil
		}
	}
	return fmt.Errorf("model not found")
}

func (m *mockStore) UpdateModelEnabled(_ context.Context, modelName string, enabled bool) error {
	for _, m2 := range m.models {
		if m2.ModelName == modelName {
			m2.Enabled = enabled
			return nil
		}
	}
	return fmt.Errorf("model not found")
}
func (m *mockStore) DeleteModel(_ context.Context, modelName string) error {
	for id, m2 := range m.models {
		if m2.ModelName == modelName {
			delete(m.models, id)
			return nil
		}
	}
	return fmt.Errorf("model not found")
}
func (m *mockStore) CreateRoutingRule(_ context.Context, orgID, matchExpr, targetModel string, priority int) (*adminstore.RoutingRule, error) {
	r := &adminstore.RoutingRule{ID: "rule-1", OrgID: orgID, MatchExpr: matchExpr, TargetModel: targetModel, Priority: priority}
	m.rules[r.ID] = r
	return r, nil
}
func (m *mockStore) GetRoutingRuleByID(_ context.Context, id string) (*adminstore.RoutingRule, error) {
	r, ok := m.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found")
	}
	return r, nil
}
func (m *mockStore) ListRoutingRulesByOrg(_ context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.RoutingRule, int64, error) {
	var result []*adminstore.RoutingRule
	for _, r := range m.rules {
		if r.OrgID == orgID {
			result = append(result, r)
		}
	}
	total := int64(len(result))
	return paginate(result, f), total, nil
}
func (m *mockStore) UpdateRoutingRule(_ context.Context, id, matchExpr, targetModel string, priority *int) error {
	r, ok := m.rules[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	if matchExpr != "" {
		r.MatchExpr = matchExpr
	}
	if targetModel != "" {
		r.TargetModel = targetModel
	}
	if priority != nil {
		r.Priority = *priority
	}
	return nil
}
func (m *mockStore) UpdateRoutingRuleEnabled(_ context.Context, id string, enabled bool) error {
	r, ok := m.rules[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	r.Enabled = enabled
	return nil
}
func (m *mockStore) DeleteRoutingRule(_ context.Context, id string) error {
	if _, ok := m.rules[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.rules, id)
	return nil
}
func (m *mockStore) AddKeyWhitelist(_ context.Context, apiKeyID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	w := &adminstore.WhitelistEntry{ID: 1, TargetID: apiKeyID, ModelName: modelName, Allowed: allowed}
	m.keyWhitelist[apiKeyID] = append(m.keyWhitelist[apiKeyID], w)
	return w, nil
}
func (m *mockStore) ListKeyWhitelist(_ context.Context, apiKeyID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error) {
	entries := m.keyWhitelist[apiKeyID]
	return paginate(entries, f), int64(len(entries)), nil
}
func (m *mockStore) DeleteKeyWhitelist(_ context.Context, apiKeyID, modelName string) error {
	entries, ok := m.keyWhitelist[apiKeyID]
	if !ok {
		return fmt.Errorf("not found")
	}
	for i, e := range entries {
		if e.ModelName == modelName {
			m.keyWhitelist[apiKeyID] = append(entries[:i], entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("whitelist entry not found")
}
func (m *mockStore) AddTeamWhitelist(_ context.Context, teamID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	w := &adminstore.WhitelistEntry{ID: 1, TargetID: teamID, ModelName: modelName, Allowed: allowed}
	m.teamWhitelist[teamID] = append(m.teamWhitelist[teamID], w)
	return w, nil
}
func (m *mockStore) ListTeamWhitelist(_ context.Context, teamID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error) {
	entries := m.teamWhitelist[teamID]
	return paginate(entries, f), int64(len(entries)), nil
}

// paginate is a generic helper that applies LIMIT/OFFSET semantics from a PageFilter
// to a slice. Used by mockStore List* methods to emulate pagination.
func paginate[T any](items []*T, f adminstore.PageFilter) []*T {
	if f.PageSize <= 0 {
		f = adminstore.NewPageFilter(f.Page, f.PageSize)
	}
	start := f.Offset()
	if start >= len(items) {
		return nil
	}
	end := start + f.PageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
func (m *mockStore) DeleteTeamWhitelist(_ context.Context, teamID, modelName string) error {
	entries, ok := m.teamWhitelist[teamID]
	if !ok {
		return fmt.Errorf("not found")
	}
	for i, e := range entries {
		if e.ModelName == modelName {
			m.teamWhitelist[teamID] = append(entries[:i], entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("whitelist entry not found")
}

// AF-09: allowlist CAS. The restore-add requires the entry to be absent; the
// rollback-removal requires the stored allowed value to match.
func (m *mockStore) AddKeyWhitelistPreconditioned(_ context.Context, apiKeyID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	if current := findWhitelistEntry(m.keyWhitelist[apiKeyID], modelName); current != nil {
		return current, adminstore.ErrPreconditionFailed
	}
	w := &adminstore.WhitelistEntry{ID: 1, TargetID: apiKeyID, ModelName: modelName, Allowed: allowed}
	m.keyWhitelist[apiKeyID] = append(m.keyWhitelist[apiKeyID], w)
	return w, nil
}

func (m *mockStore) DeleteKeyWhitelistPreconditioned(_ context.Context, apiKeyID, modelName string, expectAllowed bool) (bool, *adminstore.WhitelistEntry, error) {
	current := findWhitelistEntry(m.keyWhitelist[apiKeyID], modelName)
	if current == nil || current.Allowed != expectAllowed {
		return false, current, adminstore.ErrPreconditionFailed
	}
	entries := m.keyWhitelist[apiKeyID]
	for i, e := range entries {
		if e.ModelName == modelName {
			m.keyWhitelist[apiKeyID] = append(entries[:i], entries[i+1:]...)
			return true, nil, nil
		}
	}
	return false, nil, adminstore.ErrPreconditionFailed
}

func (m *mockStore) AddTeamWhitelistPreconditioned(_ context.Context, teamID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	if current := findWhitelistEntry(m.teamWhitelist[teamID], modelName); current != nil {
		return current, adminstore.ErrPreconditionFailed
	}
	w := &adminstore.WhitelistEntry{ID: 1, TargetID: teamID, ModelName: modelName, Allowed: allowed}
	m.teamWhitelist[teamID] = append(m.teamWhitelist[teamID], w)
	return w, nil
}

func (m *mockStore) DeleteTeamWhitelistPreconditioned(_ context.Context, teamID, modelName string, expectAllowed bool) (bool, *adminstore.WhitelistEntry, error) {
	current := findWhitelistEntry(m.teamWhitelist[teamID], modelName)
	if current == nil || current.Allowed != expectAllowed {
		return false, current, adminstore.ErrPreconditionFailed
	}
	entries := m.teamWhitelist[teamID]
	for i, e := range entries {
		if e.ModelName == modelName {
			m.teamWhitelist[teamID] = append(entries[:i], entries[i+1:]...)
			return true, nil, nil
		}
	}
	return false, nil, adminstore.ErrPreconditionFailed
}

func findWhitelistEntry(entries []*adminstore.WhitelistEntry, modelName string) *adminstore.WhitelistEntry {
	for _, e := range entries {
		if e.ModelName == modelName {
			return e
		}
	}
	return nil
}
func (m *mockStore) GetRequestLogStats(_ context.Context, _ *string, _ time.Time) (*adminstore.RequestLogStats, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.requestLogStats, nil
}
func (m *mockStore) TopModels(_ context.Context, _ *string, _ int) ([]adminstore.TopModelCount, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.topModels, nil
}
func (m *mockStore) TopOrgs(_ context.Context, _ int) ([]adminstore.TopOrgCount, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.topOrgs, nil
}
func (m *mockStore) RequestTimeSeries(_ context.Context, _ *string, _ time.Time, _ string) ([]adminstore.TimeSeriesPoint, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.timeSeries, nil
}
func (m *mockStore) ErrorBreakdown(_ context.Context, _ *string, _ time.Time) ([]adminstore.ErrorBreakdownEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.errorBreakdown, nil
}
func (m *mockStore) LatencyPercentiles(_ context.Context, _ *string, _ time.Time) (*adminstore.LatencyPercentile, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.latencyPercentiles, nil
}
func (m *mockStore) RecentErrors(_ context.Context, _ *string, _ int) ([]adminstore.RecentErrorLog, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.recentErrors, nil
}
func (m *mockStore) GetCostAnalytics(_ context.Context, _ string, _ time.Time, _ time.Time, _ string) (*adminstore.CostReport, error) {
	return &adminstore.CostReport{
		TotalCostUSD:       1.23,
		CounterfactualCost: 2.46,
		SavingsUSD:         1.23,
		SavingsPercent:     50.0,
		RequestCount:       100,
		AvgCostPerRequest:  0.0123,
		ByModel:            []adminstore.ModelCostBreakdown{{ModelName: "gpt-4", TotalCost: 1.0, RequestCount: 50, TokensIn: 50000, TokensOut: 25000}},
		ByDay:              []adminstore.DailyCost{{Date: "2024-01-01", TotalCost: 1.23, RequestCount: 100}},
	}, nil
}
func (m *mockStore) GetGlobalCostStats(_ context.Context, _ time.Time, _ time.Time) (*adminstore.CostReport, error) {
	return &adminstore.CostReport{
		TotalCostUSD:       5.0,
		CounterfactualCost: 10.0,
		SavingsUSD:         5.0,
		SavingsPercent:     50.0,
		RequestCount:       500,
		AvgCostPerRequest:  0.01,
	}, nil
}
func (m *mockStore) ListRequests(_ context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	m.lastRequestFilters = f
	if m.err != nil {
		return nil, 0, m.err
	}
	if f.ContentSearch != "" && f.PayloadAuthorizationSet && !f.PayloadSearchAllowed {
		return []adminstore.RequestListRow{}, 0, nil
	}
	return []adminstore.RequestListRow{
		{RequestID: "req-1", OrgID: f.OrgID, ModelUsed: "gpt-4o-mini", StatusCode: 200, CostUSD: 0.002, TokensIn: 100, TokensOut: 50, CreatedAt: time.Now(), PayloadOwned: f.PayloadUserID == "subject-a"},
	}, 1, nil
}
func (m *mockStore) GetToolCallsReport(_ context.Context, orgID string, days int) (*adminstore.ToolCallsReport, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &adminstore.ToolCallsReport{TotalCalls: 3, DistinctTools: 2}, nil
}

func (m *mockStore) RequestStats(_ context.Context, f adminstore.RequestListFilters) (*adminstore.RequestListStats, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &adminstore.RequestListStats{
		TotalRequests:  1,
		SuccessRate:    1,
		AvgLatencyMs:   42,
		P95LatencyMs:   42,
		TotalTokensIn:  100,
		TotalTokensOut: 50,
		TotalCostUSD:   0.002,
	}, nil
}
func (m *mockStore) GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error) {
	if m.err != nil {
		return nil, m.err
	}
	if requestID != "req-1" || orgID != "org-1" {
		return nil, adminstore.ErrNotFound
	}
	if access, ok := adminstore.RequestPayloadAccessFromContext(ctx); ok {
		if access.DenyOwnHistory && access.UserID == "subject-a" {
			return nil, adminstore.ErrNotFound
		}
		// GAP-A1 (RV-1 audit): mirror the real store's detail contract for
		// non-human subjects (pkg/adminstore/request_detail.go — a non-human
		// subject owns nothing, so a row without a verified grant or org-wide
		// metadata does not exist for it: 404, never a metadata-only 200).
		human := access.SubjectType == "" || access.SubjectType == adminstore.RequestPayloadHuman
		if !human && !access.Grant && !access.OrgWideMetadata {
			return nil, adminstore.ErrNotFound
		}
	}
	detail := &adminstore.RequestDetail{
		RequestID: "req-1", OrgID: orgID, ModelRequested: "gpt-4o-mini", ModelUsed: "gpt-4o-mini",
		Method: "POST", StatusCode: 200, DurationMs: 42, TokensIn: 100, TokensOut: 50,
		PromptHash: "sha256:abc", Response: json.RawMessage(`{"choices":[]}`),
		UpstreamRequest:  json.RawMessage(`{"messages":[{"content":"source"}]}`),
		UpstreamResponse: json.RawMessage(`{"id":"upstream-response"}`),
		TierUsed:         "easy", CostUSD: 0.002, HomeRegion: "us",
		// Recorded tool calls (tool_calls table source): names only.
		ToolCalls: []adminstore.RequestToolCall{{ToolName: "bash"}, {ToolName: "read"}},
		// Per-occurrence invocations (0014): args recorded pre-truncation;
		// call_id null mirrors "provider omitted the id".
		ToolCallInvocations: []adminstore.RequestToolCallInvocation{
			{Seq: 0, CallID: strPtr("call_b1"), ToolName: "bash", Arguments: strPtr(`{"cmd":"git status"}`)},
			{Seq: 1, ToolName: "bash", Arguments: strPtr(`{"cmd":"git diff"}`)},
		},
	}
	if access, ok := adminstore.RequestPayloadAccessFromContext(ctx); ok && (access.DenyOwnHistory || (!access.Grant && access.UserID != "subject-a")) {
		detail.Response = nil
		detail.UpstreamRequest = nil
		detail.UpstreamResponse = nil
		detail.UpstreamURL = ""
		detail.Error = ""
		detail.ToolCalls = []adminstore.RequestToolCall{}
		detail.ToolCallInvocations = []adminstore.RequestToolCallInvocation{}
	}
	if access, ok := adminstore.RequestPayloadAccessFromContext(ctx); !ok || !access.Originals {
		detail.UpstreamRequest = nil
		detail.UpstreamResponse = nil
		detail.UpstreamURL = ""
	}
	return detail, nil
}

// strPtr is a test helper for nullable RequestDetail fields.
func strPtr(s string) *string { return &s }

func (m *mockStore) GetTaskAnalytics(_ context.Context, orgID string, from, to time.Time, groupBy string, limit int) (*adminstore.TaskAnalyticsReport, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &adminstore.TaskAnalyticsReport{
		OrgID: orgID, From: from, To: to, GroupBy: groupBy,
		Groups: []adminstore.TaskAnalyticsGroup{
			{Group: "task-1", CostUSD: 1.0, CounterfactualUSD: 2.0, SavingsUSD: 1.0, CacheHits: 5, RequestCount: 50},
		},
		TotalCostUSD: 1.0,
	}, nil
}
func (m *mockStore) GetShadowComparison(_ context.Context, _ string, _ int) (*adminstore.ShadowComparison, error) {
	return &adminstore.ShadowComparison{Verdict: "insufficient_data", ByModel: []adminstore.ShadowModelCompare{}}, nil
}

func (m *mockStore) GetQualityScores(_ context.Context, _ string, _, _ time.Time) (*adminstore.QualityReport, error) {
	return &adminstore.QualityReport{Verdict: "insufficient_data", ByModel: []adminstore.QualityModelScore{}, ByTaskClass: []adminstore.QualityTaskClassScore{}}, nil
}
func (m *mockStore) RunAnalyticsQuery(_ context.Context, _ *adminstore.AnalyticsQuery) (*adminstore.AnalyticsResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.analytics != nil {
		return m.analytics, nil
	}
	return &adminstore.AnalyticsResult{Source: "raw", Columns: []adminstore.AnalyticsColumn{}, Rows: [][]any{}, Totals: map[string]any{}}, nil
}
func (m *mockStore) ListLabelKeys(_ context.Context, _ string, _, _ time.Time) ([]adminstore.LabelKeyStat, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []adminstore.LabelKeyStat{}, nil
}

// ADL-06 agent-profile methods.
func (m *mockStore) CreateAgentProfile(_ context.Context, p adminstore.AgentProfileCreateParams) (*adminstore.AgentProfile, error) {
	pr := &adminstore.AgentProfile{ID: "profile-1", OrgID: p.OrgID, Name: p.Name, TierHint: p.TierHint, MCPGrants: p.MCPGrants, BudgetCapCents: p.BudgetCapCents, GuardMode: p.GuardMode}
	if pr.GuardMode == "" {
		pr.GuardMode = "standard"
	}
	if pr.MCPGrants == nil {
		pr.MCPGrants = []string{}
	}
	m.agentProfiles[pr.ID] = pr
	return pr, nil
}
func (m *mockStore) GetAgentProfile(_ context.Context, id string) (*adminstore.AgentProfile, error) {
	if p, ok := m.agentProfiles[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("profile not found")
}
func (m *mockStore) ListAgentProfiles(_ context.Context, orgID string) ([]*adminstore.AgentProfile, error) {
	var out []*adminstore.AgentProfile
	for _, p := range m.agentProfiles {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}
func (m *mockStore) UpdateAgentProfile(_ context.Context, id string, p adminstore.AgentProfileUpdateParams) (*adminstore.AgentProfile, error) {
	pr, ok := m.agentProfiles[id]
	if !ok {
		return nil, fmt.Errorf("profile not found")
	}
	if p.Name != nil {
		pr.Name = *p.Name
	}
	if p.TierHint != nil {
		pr.TierHint = *p.TierHint
	}
	if p.MCPGrants != nil {
		pr.MCPGrants = *p.MCPGrants
	}
	if p.BudgetCapCents != nil {
		pr.BudgetCapCents = *p.BudgetCapCents
	}
	if p.GuardMode != nil {
		pr.GuardMode = *p.GuardMode
	}
	return pr, nil
}
func (m *mockStore) DeleteAgentProfile(_ context.Context, id string) error {
	if _, ok := m.agentProfiles[id]; !ok {
		return fmt.Errorf("profile not found")
	}
	delete(m.agentProfiles, id)
	return nil
}

// ENT-02 org membership (RBAC) methods.
func (m *mockStore) CreateOrgMembership(_ context.Context, mem adminstore.OrgMembership) (*adminstore.OrgMembership, error) {
	k := mem.UserID + "/" + mem.OrgID
	if _, ok := m.orgMembers[k]; ok {
		return nil, fmt.Errorf("membership for that user and org already exists")
	}
	now := time.Now()
	m.orgMembers[k] = &adminstore.OrgMembership{ID: "mem-" + k, UserID: mem.UserID, OrgID: mem.OrgID, Role: mem.Role, CreatedAt: now, UpdatedAt: now}
	return m.orgMembers[k], nil
}
func (m *mockStore) SetOrgMembership(_ context.Context, userID, orgID string, role adminstore.OrgRole) (*adminstore.OrgMembership, error) {
	// Mirror the real store's role gate (pkg/adminstore/roles.go): only the
	// declared roles may land on a membership, no matter who calls.
	if !adminstore.ValidOrgRole(role) {
		return nil, fmt.Errorf("set org membership: invalid role %q", role)
	}
	if m.ssoSetMemberErr != nil {
		return nil, m.ssoSetMemberErr
	}
	k := userID + "/" + orgID
	now := time.Now()
	if existing, ok := m.orgMembers[k]; ok {
		existing.Role = role
		existing.UpdatedAt = now
		return existing, nil
	}
	m.orgMembers[k] = &adminstore.OrgMembership{ID: "mem-" + k, UserID: userID, OrgID: orgID, Role: role, CreatedAt: now, UpdatedAt: now}
	return m.orgMembers[k], nil
}
func (m *mockStore) DeleteOrgMembership(_ context.Context, userID, orgID string) error {
	if _, ok := m.orgMembers[userID+"/"+orgID]; !ok {
		return fmt.Errorf("membership not found")
	}
	delete(m.orgMembers, userID+"/"+orgID)
	return nil
}
func (m *mockStore) GetUserOrgRoles(_ context.Context, userID string) (map[string]adminstore.OrgRole, error) {
	out := map[string]adminstore.OrgRole{}
	for _, mem := range m.orgMembers {
		if mem.UserID == userID {
			out[mem.OrgID] = mem.Role
		}
	}
	return out, nil
}

// GetAdminUserGlobalRole returns the platform-level global role
// (admin_users.global_role). AUTH-01: the global audit gate must consult ONLY
// this — never org memberships. Unknown user → ErrNotFound (fail-closed).
func (m *mockStore) GetAdminUserGlobalRole(_ context.Context, userID string) (string, error) {
	if m.globalRoleErr != nil {
		return "", m.globalRoleErr
	}
	role, ok := m.globalRoles[userID]
	if !ok {
		return "", adminstore.ErrNotFound
	}
	return role, nil
}

func (m *mockStore) ListOrgMembers(_ context.Context, orgID string) ([]*adminstore.OrgMembership, error) {
	var out []*adminstore.OrgMembership
	for _, mem := range m.orgMembers {
		if mem.OrgID == orgID {
			out = append(out, mem)
		}
	}
	return out, nil
}

// ---- N04-P01 SSO group→role mapping methods (mirrors the migration-0012
// storage semantics: one rule per (org, group, effect), per-(org,user)
// provenance) ----

func ssoRuleKey(orgID, group string, effect adminstore.SSOGroupRuleEffect) string {
	return orgID + "|" + group + "|" + string(effect)
}

func (m *mockStore) SetSSOGroupRoleRule(_ context.Context, orgID string, rule adminstore.SSOGroupRoleRule) (*adminstore.SSOGroupRoleRule, error) {
	if m.ssoErr != nil {
		return nil, m.ssoErr
	}
	if existing, ok := m.ssoRules[ssoRuleKey(orgID, rule.Group, rule.Effect)]; ok {
		existing.Role = rule.Role
		return existing, nil
	}
	stored := rule
	stored.ID = fmt.Sprintf("sso-rule-%s-%s-%s", orgID, rule.Group, rule.Effect)
	stored.OrgID = orgID
	m.ssoRules[ssoRuleKey(orgID, rule.Group, rule.Effect)] = &stored
	return &stored, nil
}

func (m *mockStore) ListSSOGroupRoleRules(_ context.Context, orgID string) ([]adminstore.SSOGroupRoleRule, error) {
	if m.ssoErr != nil {
		return nil, m.ssoErr
	}
	var out []adminstore.SSOGroupRoleRule
	for _, rule := range m.ssoRules {
		if rule.OrgID == orgID {
			out = append(out, *rule)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Effect < out[j].Effect
	})
	return out, nil
}

func (m *mockStore) DeleteSSOGroupRoleRule(_ context.Context, orgID, ruleID string) error {
	if m.ssoErr != nil {
		return m.ssoErr
	}
	for key, rule := range m.ssoRules {
		if rule.OrgID == orgID && rule.ID == ruleID {
			delete(m.ssoRules, key)
			return nil
		}
	}
	return fmt.Errorf("sso group rule not found")
}

func ssoGrantKey(orgID, userID string) string { return orgID + "|" + userID }

func (m *mockStore) GetSSOGrantedRole(_ context.Context, orgID, userID string) (adminstore.OrgRole, bool, error) {
	if m.ssoErr != nil {
		return "", false, m.ssoErr
	}
	role, ok := m.ssoGrants[ssoGrantKey(orgID, userID)]
	return role, ok, nil
}

func (m *mockStore) SetSSOGrantedRole(_ context.Context, orgID, userID string, role adminstore.OrgRole) error {
	// Mirror the real store's role gate (pkg/adminstore/sso_groups.go): the
	// mapping may only record provenance for a declared local role, so a
	// corrupted grant rule can never reach the provenance table either.
	if !adminstore.ValidOrgRole(role) {
		return fmt.Errorf("set sso granted role: invalid role %q", role)
	}
	if m.ssoErr != nil {
		return m.ssoErr
	}
	if m.ssoSetGrantErr != nil {
		return m.ssoSetGrantErr
	}
	m.ssoGrants[ssoGrantKey(orgID, userID)] = role
	return nil
}

func (m *mockStore) DeleteSSOGrantedRole(_ context.Context, orgID, userID string) error {
	if m.ssoErr != nil {
		return m.ssoErr
	}
	delete(m.ssoGrants, ssoGrantKey(orgID, userID))
	return nil
}

func (m *mockStore) GetSavingsReport(_ context.Context, _ string, _ int, _ string) (*adminstore.SavingsReport, error) {
	return &adminstore.SavingsReport{
		Period:             "last_7_days",
		TotalRequests:      1000,
		ActualCostUSD:      5.0,
		CounterfactualCost: 10.0,
		CombinedSavingsPct: 50.0,
		KillCriterionMet:   true,
		CacheHits:          300,
		CacheSavingsPct:    30.0,
		RoutedRequests:     700,
		RoutingSavingsPct:  20.0,
	}, nil
}
func (m *mockStore) CreatePricing(_ context.Context, p adminstore.CreatePricingParams) (*adminstore.PricingEntry, error) {
	return &adminstore.PricingEntry{
		ID:             1,
		Provider:       p.Provider,
		Model:          p.Model,
		InputPerM:      p.InputPerM,
		OutputPerM:     p.OutputPerM,
		CacheWritePerM: p.CacheWritePerM,
		CacheReadPerM:  p.CacheReadPerM,
	}, nil
}
func (m *mockStore) UpdatePricing(_ context.Context, p adminstore.UpdatePricingParams) (*adminstore.PricingEntry, error) {
	return &adminstore.PricingEntry{ID: p.ID}, nil
}
func (m *mockStore) DeletePricing(_ context.Context, _ int64) error {
	return nil
}
func (m *mockStore) ListPricing(_ context.Context, _ adminstore.ListPricingOptions) ([]adminstore.PricingEntry, error) {
	return []adminstore.PricingEntry{}, nil
}
func (m *mockStore) ImportCatalogPricing(_ context.Context, catalog pricing.PriceFile, mappings []adminstore.CatalogPriceMap, onlyMapped, apply bool, updatedBy string) (adminstore.CatalogImportResult, error) {
	if m.pricingImport == nil {
		mode := "dry_run"
		if apply {
			mode = "apply"
		}
		return adminstore.CatalogImportResult{Mode: mode, Created: 1, Unchanged: 0, Unmatched: []string{}, Errors: []string{}}, nil
	}
	return m.pricingImport(catalog, mappings, onlyMapped, apply, updatedBy)
}
func (m *mockStore) ListModelAliases(context.Context) ([]adminstore.ModelAlias, error) {
	return []adminstore.ModelAlias{}, nil
}
func (m *mockStore) CreateModelAlias(_ context.Context, alias, target string) (*adminstore.ModelAlias, error) {
	return &adminstore.ModelAlias{Alias: alias, TargetModel: target}, nil
}
func (m *mockStore) DeleteModelAlias(context.Context, string) error { return nil }
func (m *mockStore) GetOrgSpendAlertSettings(_ context.Context, orgID string) (*adminstore.OrgSpendAlertSettings, error) {
	return &adminstore.OrgSpendAlertSettings{SpendToday: 0}, nil
}
func (m *mockStore) UpdateOrgSpendAlertSettings(_ context.Context, _ string, _ *float64, _ *string) error {
	return nil
}
func (m *mockStore) ListOrgsWithSpendAlerts(_ context.Context) ([]adminstore.SpendAlertOrg, error) {
	return nil, nil
}
func (m *mockStore) SpendToday(_ context.Context, _ string) (float64, error) {
	return 0, nil
}
func (m *mockStore) UpdateLastAlertAt(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// GetTeamSpendSummary mirrors the SQL projection: the stored budget joins
// when present; an absent row keeps the fail-closed defaults (limit 0,
// hard) instead of presenting an unbudgeted team as soft/unlimited.
func (m *mockStore) GetTeamSpendSummary(_ context.Context, teamID string) (*adminstore.TeamSpendSummary, error) {
	summary := &adminstore.TeamSpendSummary{TeamID: teamID, MonthlyLimitUSD: 0, HardLimit: true}
	if spend, ok := m.teamSpends[teamID]; ok {
		summary.SpendUSD = spend
	}
	if b, ok := m.teamBudgets[teamID]; ok {
		summary.MonthlyLimitUSD = b.MonthlyLimitUSD
		summary.HardLimit = b.HardLimit
	}
	return summary, nil
}
func (m *mockStore) UpsertTeamBudget(_ context.Context, teamID string, monthlyLimit float64, hardLimit bool) error {
	if m.teamBudgetUpsert != nil {
		return m.teamBudgetUpsert
	}
	m.teamBudgets[teamID] = &adminstore.TeamBudget{TeamID: teamID, MonthlyLimitUSD: monthlyLimit, HardLimit: hardLimit}
	return nil
}

// AF-09: team budget CAS against the mock's stored rows.
func (m *mockStore) UpsertTeamBudgetPreconditioned(_ context.Context, teamID string, monthlyLimit float64, hardLimit bool, expect *adminstore.TeamBudgetExpectation) (*adminstore.TeamBudget, error) {
	cur, ok := m.teamBudgets[teamID]
	if expect != nil {
		if expect.Absent {
			if ok {
				return cloneTeamBudget(cur), adminstore.ErrPreconditionFailed
			}
		} else if !ok || cur.MonthlyLimitUSD != expect.MonthlyLimitUSD || cur.HardLimit != expect.HardLimit {
			var current *adminstore.TeamBudget
			if ok {
				current = cloneTeamBudget(cur)
			}
			return current, adminstore.ErrPreconditionFailed
		}
	}
	nb := &adminstore.TeamBudget{TeamID: teamID, MonthlyLimitUSD: monthlyLimit, HardLimit: hardLimit}
	m.teamBudgets[teamID] = nb
	return cloneTeamBudget(nb), nil
}

func (m *mockStore) DeleteTeamBudgetPreconditioned(_ context.Context, teamID string, expect adminstore.TeamBudgetExpectation) (bool, *adminstore.TeamBudget, error) {
	cur, ok := m.teamBudgets[teamID]
	if !ok || cur.MonthlyLimitUSD != expect.MonthlyLimitUSD || cur.HardLimit != expect.HardLimit {
		var current *adminstore.TeamBudget
		if ok {
			current = cloneTeamBudget(cur)
		}
		return false, current, adminstore.ErrPreconditionFailed
	}
	delete(m.teamBudgets, teamID)
	return true, nil, nil
}

func cloneTeamBudget(b *adminstore.TeamBudget) *adminstore.TeamBudget {
	if b == nil {
		return nil
	}
	out := *b
	return &out
}
func (m *mockStore) DeleteTeamBudget(_ context.Context, _ string) error {
	return nil
}
func (m *mockStore) ListTeamBudgetsByOrg(_ context.Context, _ string) ([]adminstore.TeamSpendSummary, error) {
	return nil, nil
}

// ---- AdminHandlers struct and New() constructor ----
type testAdminHandlers struct {
	*AdminHandlers
	store       *mockStore
	revocations *oidcRevocationTestStore
}

func newTestAdminH(store *mockStore) *testAdminHandlers {
	return &testAdminHandlers{
		AdminHandlers: New(store, "", "", []string{}),
		store:         store,
	}
}

func registerMethod(router *chi.Mux, method, pattern string, handler http.HandlerFunc) {
	switch method {
	case "GET":
		router.Get(pattern, handler)
	case "POST":
		router.Post(pattern, handler)
	case "PUT":
		router.Put(pattern, handler)
	case "DELETE":
		router.Delete(pattern, handler)
	case "PATCH":
		router.Patch(pattern, handler)
	default:
		router.HandleFunc(pattern, handler)
	}
}

func serveHandlerWithParams(t *testing.T, handlerFunc http.HandlerFunc, routePattern string, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), method, path, body)
	router := chi.NewRouter()

	chiCtx := &chi.Context{}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

	patternParts := strings.Split(routePattern, "/")
	pathParts := strings.Split(path, "/")
	for i, p := range patternParts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			key := p[1 : len(p)-1]
			if i < len(pathParts) {
				chiCtx.URLParams.Add(key, pathParts[i])
			}
		}
	}

	registerMethod(router, method, routePattern, handlerFunc)
	router.ServeHTTP(w, req)
	return w
}

func wrapWithParams(handlerFunc http.HandlerFunc, routePattern string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		patternParts := strings.Split(routePattern, "/")
		pathParts := strings.Split(path, "/")
		for i, p := range patternParts {
			if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
				key := p[1 : len(p)-1]
				if i < len(pathParts) {
					chiCtx := chi.RouteContext(r.Context())
					if chiCtx == nil {
						chiCtx = &chi.Context{}
						r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, chiCtx))
					}
					chiCtx.URLParams.Add(key, pathParts[i])
				}
			}
		}
		handlerFunc(w, r)
	}
}

// ---- CRUD Organization Tests ----

func TestCreateOrganization(t *testing.T) {
	h := newTestAdminH(newMockStore())
	body := strings.NewReader(`{"name":"Acme","slug":"acme"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/organizations", body)
	w := httptest.NewRecorder()
	h.CreateOrganization()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Acme", resp["name"])
	assert.Equal(t, "acme", resp["slug"])
}

func TestCreateOrganization_BadRequest(t *testing.T) {
	h := newTestAdminH(newMockStore())
	body := strings.NewReader(`not json`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/organizations", body)
	w := httptest.NewRecorder()
	h.CreateOrganization()(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOrganizationByID(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Acme", Slug: "acme"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/organizations/org-1", nil)
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/organizations/{id}", h.GetOrganization())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Acme", resp["name"])
}

func TestGetOrganizationByID_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/organizations/nonexistent", nil)
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/organizations/{id}", h.GetOrganization())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListOrganizations(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Acme", Slug: "acme"}
	store.orgs["org-2"] = &adminstore.Organization{ID: "org-2", Name: "Globex", Slug: "globex"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/organizations", nil)
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Get("/api/organizations", h.ListOrganizations())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data       []*adminstore.Organization `json:"data"`
		Pagination struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
	assert.Equal(t, int64(2), resp.Pagination.Total)
}

func TestUpdateOrganization(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Old", Slug: "old"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"name":"New","slug":"new"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/organizations/org-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateOrganization(), "/api/organizations/{id}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	org, err := store.GetOrganizationByID(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, "New", org.Name)
	assert.Equal(t, "new", org.Slug)
}

func TestUpdateOrganization_IssueURL(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Old", Slug: "old", IssueURLTemplate: "https://old.example/{issue}"}
	h := newTestAdminH(store)

	body := strings.NewReader(`{"name":"New","slug":"new"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/organizations/org-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateOrganization(), "/api/organizations/{id}")(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	org, err := store.GetOrganizationByID(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, "https://old.example/{issue}", org.IssueURLTemplate)

	bad := strings.NewReader(`{"name":"New","slug":"new","issue_url_template":"http://x/{issue}"}`)
	req = httptest.NewRequestWithContext(context.Background(), "PUT", "/api/organizations/org-1", bad)
	w = httptest.NewRecorder()
	wrapWithParams(h.UpdateOrganization(), "/api/organizations/{id}")(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	ok := strings.NewReader(`{"name":"New","slug":"new","issue_url_template":"https://tracker.example/browse/{issue}"}`)
	req = httptest.NewRequestWithContext(context.Background(), "PUT", "/api/organizations/org-1", ok)
	w = httptest.NewRecorder()
	wrapWithParams(h.UpdateOrganization(), "/api/organizations/{id}")(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	org, err = store.GetOrganizationByID(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, "https://tracker.example/browse/{issue}", org.IssueURLTemplate)
}

func TestUpdateOrganization_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	body := strings.NewReader(`{"name":"New","slug":"new"}`)
	w := serveHandlerWithParams(t, h.UpdateOrganization(), "/api/organizations/{id}", "PUT", "/api/organizations/nonexistent", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteOrganization(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Acme"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "DELETE", "/api/organizations/org-1", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.DeleteOrganization(), "/api/organizations/{id}")(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteOrganization_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	req := httptest.NewRequestWithContext(context.Background(), "DELETE", "/api/organizations/nonexistent", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.DeleteOrganization(), "/api/organizations/{id}")(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- CRUD Team Tests ----

func TestCreateTeam(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"org_id":"org-1","name":"Dev Team","slug":"dev-team"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/teams", body)
	w := httptest.NewRecorder()
	h.CreateTeam()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Dev Team", resp["name"])
}

func TestGetTeamByID(t *testing.T) {
	store := newMockStore()
	store.teams["team-1"] = &adminstore.Team{ID: "team-1", Name: "Dev Team"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/teams/team-1", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetTeam(), "/api/teams/{id}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetTeamByID_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/teams/nonexistent", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetTeam(), "/api/teams/{id}")(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListTeamsByOrg(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	store.teams["team-1"] = &adminstore.Team{ID: "team-1", OrgID: "org-1", Name: "Dev"}
	store.teams["team-2"] = &adminstore.Team{ID: "team-2", OrgID: "org-1", Name: "Ops"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/teams?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.ListTeams()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data       []map[string]interface{} `json:"data"`
		Pagination struct {
			Total int64 `json:"total"`
		} `json:"pagination"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
	assert.Equal(t, int64(2), resp.Pagination.Total)
}

func TestUpdateTeam(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	store.teams["team-1"] = &adminstore.Team{ID: "team-1", OrgID: "org-1", Name: "Old"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"name":"New","slug":"new"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/teams/team-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateTeam(), "/api/teams/{id}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	team, err := store.GetTeamByID(context.Background(), "team-1")
	require.NoError(t, err)
	assert.Equal(t, "New", team.Name)
}

func TestDeleteTeam_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.DeleteTeam(), "/api/teams/{id}", "DELETE", "/api/teams/nonexistent", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- CRUD API Key Tests ----

// NEXT-01: no team_id in the payload — the handler rejects it (the mock
// store used to accept what the real NOT NULL schema never could). The
// full create→resolve→rotate path with a real team lives in
// keys_onboarding_int_test.go.
func TestCreateAPIKey(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"name":"prod-key","org_id":"org-1"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	// NEXT-01 owner decision 2026-09-18: default-team fallback — an omitted
	// team_id resolves to the org's default team, so this now succeeds.
	assert.Equal(t, http.StatusCreated, w.Code)
}

// NEXT-01 owner decision 2026-09-18: default-team fallback. A request
// without team_id resolves to the org's default team (slug='default',
// created on first use). In the mock store, the default team always
// resolves, so the create succeeds — the real-DB no-org case is covered
// by the integration tests.
func TestCreateAPIKey_NoTeam_Rejected(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	body := strings.NewReader(`{"name":"prod-key"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	// Mock: default team resolves → 201. Real DB without org fails earlier.
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGetAPIKeyByID(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/api-keys/key-1", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetAPIKey(), "/api/api-keys/{id}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListAPIKeys(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key"}
	store.apiKeys["key-2"] = &adminstore.APIKey{ID: "key-2", Name: "dev-key"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/api-keys?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.ListAPIKeys()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateAPIKeyActive(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"active":false}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1/active", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}/active")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	key, err := store.GetAPIKeyByID(context.Background(), "key-1")
	require.NoError(t, err)
	assert.False(t, key.Active)
}

func TestRotateAPIKey(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"key_hash":"rotated-hash"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys/key-1/rotate", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.RotateAPIKey(), "/api/api-keys/{id}/rotate")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	key, err := store.GetAPIKeyByID(context.Background(), "key-1")
	require.NoError(t, err)
	assert.Equal(t, "rotated-hash", key.KeyHash)
}

func TestDeleteAPIKey_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.DeleteAPIKey(), "/api/api-keys/{id}", "DELETE", "/api/api-keys/nonexistent", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// PO-04: request detail endpoint. The mock returns a row for org-1/req-1 and
// ErrNotFound otherwise, so this also pins the org-scoped 404 behavior.
func TestRequestDetail_Found(t *testing.T) {
	h := newTestAdminH(newMockStore())
	// Root has no automatic payload grant; the record is metadata-only.
	req := rootRequest("GET", "/api/organizations/org-1/requests/req-1", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"request_id":"req-1"`)
	assert.Contains(t, w.Body.String(), `"prompt_hash":"sha256:abc"`)
	assert.NotContains(t, w.Body.String(), `"response"`)
	assert.Contains(t, w.Body.String(), `"tool_calls":[]`)
	assert.Contains(t, w.Body.String(), `"tool_call_invocations":[]`)
}

func TestRequestDetail_OwnPayloadVisible(t *testing.T) {
	h := newTestAdminH(newMockStore())
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "subject-a")
	ctx = WithOrgRole(ctx, "org-1", adminstore.RoleReader)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/req-1", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"response":{"choices":[]}`)
	assert.Contains(t, w.Body.String(), `"arguments":"{\"cmd\":\"git status\"}"`)
}

func TestRequestDetail_OtherOrg_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	// req-1 belongs to org-1; asking for it under org-2 must 404 (no existence leak).
	w := serveHandlerWithParams(t, h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}", "GET", "/api/organizations/org-2/requests/req-1", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRequestDetail_Unknown_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}", "GET", "/api/organizations/org-1/requests/nope", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---- CRUD Model Tests ----

func TestCreateModel(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	body := strings.NewReader(`{"model_name":"gpt-4","display_name":"GPT 4","tier":"premium"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/models", body)
	w := httptest.NewRecorder()
	h.CreateModel()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestGetModelByName(t *testing.T) {
	store := newMockStore()
	store.models["model-1"] = &adminstore.ModelRegistry{ID: "model-1", ModelName: "gpt-4"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/models/gpt-4", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetModel(), "/api/models/{name}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetModelByName_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/models/nonexistent", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetModel(), "/api/models/{name}")(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListModels(t *testing.T) {
	store := newMockStore()
	store.models["model-1"] = &adminstore.ModelRegistry{ID: "model-1", ModelName: "gpt-4"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/models", nil)
	w := httptest.NewRecorder()
	h.ListModels()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateModel(t *testing.T) {
	store := newMockStore()
	store.models["model-1"] = &adminstore.ModelRegistry{ID: "model-1", ModelName: "gpt-4", DisplayName: "Old"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"display_name":"New GPT 4","tier":"standard"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/models/gpt-4", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateModel(), "/api/models/{name}")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	models, _, err := store.ListModels(context.Background(), adminstore.PageFilter{})
	require.NoError(t, err)
	assert.Equal(t, "New GPT 4", models[0].DisplayName)
}

func TestUpdateModelEnabled(t *testing.T) {
	store := newMockStore()
	store.models["model-1"] = &adminstore.ModelRegistry{ID: "model-1", ModelName: "gpt-4", Enabled: true}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"enabled":false}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/models/gpt-4/enable", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateModelEnabled(), "/api/models/{name}/enable")(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	models, _, err := store.ListModels(context.Background(), adminstore.PageFilter{})
	require.NoError(t, err)
	assert.False(t, models[0].Enabled)
}

func TestDeleteModel_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.DeleteModel(), "/api/models/{name}", "DELETE", "/api/models/nonexistent", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- CRUD Routing Rule Tests ----

func TestCreateRoutingRule(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"match_expr":"model == 'gpt-4'","target_model":"gpt-4","priority":1}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/rules", body)
	w := httptest.NewRecorder()
	h.CreateRoutingRule()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestListRoutingRulesByOrg(t *testing.T) {
	store := newMockStore()
	store.rules["rule-1"] = &adminstore.RoutingRule{ID: "rule-1", OrgID: "org-1"}
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/rules?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.ListRoutingRules()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateRoutingRule(t *testing.T) {
	store := newMockStore()
	store.rules["rule-1"] = &adminstore.RoutingRule{ID: "rule-1", OrgID: "org-1", TargetModel: "old-model"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"target_model":"new-model"}`)
	w := serveHandlerWithParams(t, h.UpdateRoutingRule(), "/api/rules/{id}", "PUT", "/api/rules/rule-1", body)

	assert.Equal(t, http.StatusOK, w.Code)
	rule, err := store.GetRoutingRuleByID(context.Background(), "rule-1")
	require.NoError(t, err)
	assert.Equal(t, "new-model", rule.TargetModel)
}

func TestUpdateRoutingRuleEnabled(t *testing.T) {
	store := newMockStore()
	store.rules["rule-1"] = &adminstore.RoutingRule{ID: "rule-1", OrgID: "org-1", Enabled: true}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"enabled":false}`)
	w := serveHandlerWithParams(t, h.UpdateRoutingRuleEnabled(), "/api/rules/{id}/enable", "PUT", "/api/rules/rule-1/enable", body)

	assert.Equal(t, http.StatusOK, w.Code)
	rule, err := store.GetRoutingRuleByID(context.Background(), "rule-1")
	require.NoError(t, err)
	assert.False(t, rule.Enabled)
}

func TestDeleteRoutingRule_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.DeleteRoutingRule(), "/api/rules/{id}", "DELETE", "/api/rules/nonexistent", nil)

	// RT-06: the delete handler resolves the rule (for the org-scoped cache
	// invalidation) before deleting, so a missing id is an explicit 404 —
	// previously the silent no-op surfaced as 500.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---- Whitelist Tests ----

func TestAddKeyWhitelist(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"model_name":"gpt-4","allowed":true}`)
	w := serveHandlerWithParams(t, h.addKeyWhitelist(), "/api/whitelist/api-keys/{target_id}", "POST", "/api/whitelist/api-keys/key-1", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestListKeyWhitelist(t *testing.T) {
	store := newMockStore()
	store.keyWhitelist["key-1"] = []*adminstore.WhitelistEntry{{ID: 1, TargetID: "key-1", ModelName: "gpt-4"}}
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.listKeyWhitelist(), "/api/whitelist/api-keys/{target_id}", "GET", "/api/whitelist/api-keys/key-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListKeyWhitelist_NotFound(t *testing.T) {
	h := newTestAdminH(newMockStore())
	w := serveHandlerWithParams(t, h.listKeyWhitelist(), "/api/whitelist/api-keys/{target_id}", "GET", "/api/whitelist/api-keys/nonexistent", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteKeyWhitelist_NotFound(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1"}
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.removeKeyWhitelist(), "/api/whitelist/api-keys/{target_id}/{model_name}", "DELETE", "/api/whitelist/api-keys/key-1/gpt-4", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAddTeamWhitelist(t *testing.T) {
	store := newMockStore()
	store.teams["team-1"] = &adminstore.Team{ID: "team-1"}
	h := newTestAdminH(store)
	body := strings.NewReader(`{"model_name":"gpt-4","allowed":true}`)
	w := serveHandlerWithParams(t, h.addTeamWhitelist(), "/api/whitelist/teams/{target_id}", "POST", "/api/whitelist/teams/team-1", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestListTeamWhitelist(t *testing.T) {
	store := newMockStore()
	store.teamWhitelist["team-1"] = []*adminstore.WhitelistEntry{{ID: 1, TargetID: "team-1", ModelName: "gpt-4"}}
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.listTeamWhitelist(), "/api/whitelist/teams/{target_id}", "GET", "/api/whitelist/teams/team-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteTeamWhitelist_NotFound(t *testing.T) {
	store := newMockStore()
	store.teams["team-1"] = &adminstore.Team{ID: "team-1"}
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.removeTeamWhitelist(), "/api/whitelist/teams/{target_id}/{model_name}", "DELETE", "/api/whitelist/teams/team-1/gpt-4", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- Analytics Tests ----

func TestGetRequestLogStats(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiAnalyticsStats(), "/api/analytics/stats", "GET", "/api/analytics/stats", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetRequestLogStats_Error(t *testing.T) {
	store := newMockStore()
	store.err = fmt.Errorf("store error")
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiAnalyticsStats(), "/api/analytics/stats", "GET", "/api/analytics/stats", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTopModels(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiTopModels(), "/api/analytics/top-models", "GET", "/api/analytics/top-models?limit=5", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var topModels []interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &topModels)
	assert.Len(t, topModels, 2)
}

func TestTopOrgs(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiTopOrgs(), "/api/analytics/top-orgs", "GET", "/api/analytics/top-orgs?limit=5", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestTimeSeries(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiTimeSeries(), "/api/analytics/time-series", "GET", "/api/analytics/time-series?bucket=hour", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestErrorBreakdown(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiErrorBreakdown(), "/api/analytics/errors", "GET", "/api/analytics/errors", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLatencyPercentiles(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiLatency(), "/api/analytics/latency", "GET", "/api/analytics/latency", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRecentErrors(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	w := serveHandlerWithParams(t, h.apiRecentErrors(), "/api/analytics/recent-errors", "GET", "/api/analytics/recent-errors?limit=5", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---- H5: Non-root admin must receive 403 on root-only endpoints ----

// makeSessionCookie builds a session cookie for the seeded fixture users in
// newMockStore: "admin-root" (root) and "admin-1" (non-root). TP-02 wires
// session revalidation, so the cookie's user must exist in the store and the
// store's role is authoritative.
func makeSessionCookie(isRoot bool, secret string) *http.Cookie {
	id := "admin-1"
	if isRoot {
		id = "admin-root"
	}
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    id,
		Email:     "test@example.com",
		IsRoot:    isRoot,
		SessionID: "sess-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, secret)
	if err != nil {
		panic(err)
	}
	return cookie
}

func TestRootOnly_Endpoints_RejectNonRoot_Admin(t *testing.T) {
	h := New(newMockStore(), "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(false, "test-secret-32-bytes-long-here!!")

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/teams"},
		{http.MethodPost, "/api/teams"},
		{http.MethodGet, "/api/teams/team-1"},
		{http.MethodPut, "/api/teams/team-1"},
		{http.MethodDelete, "/api/teams/team-1"},
		{http.MethodGet, "/api/models"},
		{http.MethodPost, "/api/models"},
		{http.MethodGet, "/api/models/model-1"},
		{http.MethodPut, "/api/models/model-1"},
		{http.MethodDelete, "/api/models/model-1"},
		{http.MethodGet, "/api/rules"},
		{http.MethodPost, "/api/rules"},
		{http.MethodPost, "/api/rules/preview"},
		{http.MethodGet, "/api/rules/rule-1"},
		{http.MethodPut, "/api/rules/rule-1"},
		{http.MethodDelete, "/api/rules/rule-1"},
		{http.MethodGet, "/api/whitelist/api-keys/key-1"},
		{http.MethodPost, "/api/whitelist/api-keys/key-1"},
		{http.MethodDelete, "/api/whitelist/api-keys/key-1/model-1"},
		{http.MethodGet, "/api/whitelist/teams/team-1"},
		{http.MethodPost, "/api/whitelist/teams/team-1"},
		{http.MethodDelete, "/api/whitelist/teams/team-1/model-1"},
		{http.MethodGet, "/api/admin-users"},
		{http.MethodPost, "/api/admin-users"},
		{http.MethodGet, "/api/admin-users/admin-1"},
		{http.MethodPut, "/api/admin-users/admin-1"},
		{http.MethodDelete, "/api/admin-users/admin-1"},
	}

	for _, tc := range tests {
		t.Run(tc.path+"_"+tc.method, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			req.AddCookie(cookie)
			router.ServeHTTP(rw, req)
			if rw.Code != http.StatusForbidden {
				t.Errorf("%s %s: expected 403 Forbidden for non-root admin, got %d", tc.method, tc.path, rw.Code)
			}
		})
	}
}

// C3: an authenticated request to an unknown /api/* path must get a JSON 404,
// not the plain-text chi 404 or a browser-oriented response.
func TestUnknownAPIPath_ReturnsJSON404(t *testing.T) {
	h := New(newMockStore(), "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(true, "test-secret-32-bytes-long-here!!")
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/definitely-not-a-real-endpoint", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown /api path, got %d", rw.Code)
	}
	if ct := rw.Header().Get("Content-Type"); ct == "" || ct == "text/plain" {
		t.Errorf("expected a JSON Content-Type for unknown /api 404, got %q (body=%q)", ct, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "not found") {
		t.Errorf("expected JSON body to contain 'not found', got %q", rw.Body.String())
	}
}

func TestRootOnly_AdminUsers_Endpoint_RejectNonRoot(t *testing.T) {
	h := New(newMockStore(), "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(false, "test-secret-32-bytes-long-here!!")

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin-users", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-root admin on /api/admin-users, got %d", rw.Code)
	}
}

func TestRootOnly_Endpoints_AllowRoot_Admin(t *testing.T) {
	store := newMockStore()
	h := New(store, "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(true, "test-secret-32-bytes-long-here!!")

	tests := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/api/teams?org_id=test-org", http.StatusOK},
		{http.MethodGet, "/api/api-keys", http.StatusOK},
		{http.MethodGet, "/api/models", http.StatusOK},
		{http.MethodGet, "/api/rules?org_id=test-org", http.StatusOK},
		{http.MethodGet, "/api/whitelist/api-keys/key-1", http.StatusOK},
		{http.MethodGet, "/api/whitelist/teams/team-1", http.StatusOK},
		{http.MethodGet, "/api/admin-users", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.path+"_"+tc.method, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			req.AddCookie(cookie)
			router.ServeHTTP(rw, req)
			if rw.Code != tc.want {
				t.Errorf("%s %s: expected %d for root admin, got %d", tc.method, tc.path, tc.want, rw.Code)
			}
		})
	}
}

func TestNonRoot_Admin_CannotAccess_OrganizationEndpoints(t *testing.T) {
	store := newMockStore()
	h := New(store, "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(false, "test-secret-32-bytes-long-here!!")

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/organizations", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-root admin on /api/organizations, got %d", rw.Code)
	}
}

// NEXT-15-F1: analytics are org-scoped reads gated by RBAC. The old contract
// ("200 for any non-root admin on any analytics route, org optional") was the
// cross-org leak this fix closed.
func TestNonRoot_Admin_Analytics_RBAC(t *testing.T) {
	store := newMockStore()
	// The non-root session user holds reader on org-rbac-1 only.
	cookie := makeSessionCookie(false, "test-secret-32-bytes-long-here!!")
	userID := adminUserIDFromSession(t, cookie)
	store.orgMembers = map[string]*adminstore.OrgMembership{
		userID + "/org-rbac-1": {UserID: userID, OrgID: "org-rbac-1", Role: adminstore.RoleReader},
	}
	h := New(store, "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	scoped := []string{
		"/api/analytics/stats",
		"/api/analytics/top-models",
		"/api/analytics/time-series",
		"/api/analytics/error-breakdown",
		"/api/analytics/latency",
		"/api/analytics/recent-errors",
	}

	for _, path := range scoped {
		t.Run(path+" own org = 200", func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path+"?org_id=org-rbac-1", nil)
			req.AddCookie(cookie)
			router.ServeHTTP(rw, req)
			if rw.Code != http.StatusOK {
				t.Errorf("own-org analytics = %d, want 200", rw.Code)
			}
		})
		t.Run(path+" foreign org = 403", func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path+"?org_id=org-foreign", nil)
			req.AddCookie(cookie)
			router.ServeHTTP(rw, req)
			if rw.Code != http.StatusForbidden {
				t.Errorf("foreign-org analytics = %d, want 403", rw.Code)
			}
		})
	}

	t.Run("no org target = 400 fail-closed", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/analytics/stats", nil)
		req.AddCookie(cookie)
		router.ServeHTTP(rw, req)
		if rw.Code != http.StatusBadRequest {
			t.Errorf("org-less analytics = %d, want 400", rw.Code)
		}
	})

	t.Run("top-orgs aggregate = 403 for non-root", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/analytics/top-orgs", nil)
		req.AddCookie(cookie)
		router.ServeHTTP(rw, req)
		if rw.Code != http.StatusForbidden {
			t.Errorf("top-orgs as non-root = %d, want 403", rw.Code)
		}
	})
}

// adminUserIDFromSession decodes the test session's user id (the mock
// membership store keys roles by it).
func adminUserIDFromSession(t *testing.T, c *http.Cookie) string {
	t.Helper()
	sess, err := adminauth.ParseAdminSessionCookie(c.Value, "test-secret-32-bytes-long-here!!")
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	return sess.UserID
}

func TestNoSessionCookie_RootOnly_Endpoints_Return401(t *testing.T) {
	h := New(newMockStore(), "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/teams", nil)
	router.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without session cookie, got %d", rw.Code)
	}
}

func TestRootOnly_Endpoints_ReturnJSON_Error(t *testing.T) {
	h := New(newMockStore(), "test-secret-32-bytes-long-here!!", "", []string{})
	router := h.SetupRouter()

	cookie := makeSessionCookie(false, "test-secret-32-bytes-long-here!!")

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/teams", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rw.Code)
	}

	if !strings.Contains(rw.Body.String(), "forbidden") {
		t.Errorf("expected forbidden body, got: %s", rw.Body.String())
	}
}
