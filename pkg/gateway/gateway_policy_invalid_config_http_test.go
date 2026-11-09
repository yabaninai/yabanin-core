package cli

// through the real gateway routes over a real PostgreSQL policy store
// (testcontainers), not only through direct runtime helper calls. The stored
// document is accepted by the store (which only refuses empty YAML), so the
// gateway load is the boundary under test: stage-classified rejection before
// any shadow downgrade, an atomic candidate that never partially installs,
// last-good enforcement across an invalid refresh, and the cold outcome by
// mode — enforce refuses with the bounded policy_configuration_unavailable
// code while shadow never blocks; nothing tenant- or content-shaped leaks.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// seedPolicyInvalidConfig stores a policy whose active version is invalid for
// the gateway pipeline compiler through the real store API (create → activate
// → enable → attach to chat). The store accepts any non-empty document, so
// the stored config stays broken until a repaired version is activated.
func seedPolicyInvalidConfig(t *testing.T, ctx context.Context, store *adminstore.Store, orgID, name, yamlDoc string) string {
	t.Helper()
	p, _, err := store.CreatePolicy(ctx, orgID, name, yamlDoc, "r01005-test", "r01005-test")
	if err != nil {
		t.Fatalf("create synthetic invalid policy: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgID, p.ID, 1); err != nil {
		t.Fatalf("activate synthetic invalid policy version: %v", err)
	}
	if _, err := store.UpdatePolicy(ctx, orgID, p.ID, true); err != nil {
		t.Fatalf("enable synthetic invalid policy: %v", err)
	}
	if _, err := store.SetPolicyAttachments(ctx, orgID, p.ID, []adminstore.PolicyAttachment{
		{ModelPattern: "*", Endpoint: "chat", Priority: 1},
	}); err != nil {
		t.Fatalf("attach synthetic invalid policy: %v", err)
	}
	return p.ID
}

// activatePolicyVersion appends a new version through the real versioning API
// and activates it — the repair path an operator would take after fixing the
// stored document.
func activatePolicyVersion(t *testing.T, ctx context.Context, store *adminstore.Store, orgID, policyID, yamlDoc string) {
	t.Helper()
	v, err := store.CreatePolicyVersion(ctx, orgID, policyID, yamlDoc, "r01005-test", "r01005-test")
	if err != nil {
		t.Fatalf("create repaired policy version: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgID, policyID, v.Version); err != nil {
		t.Fatalf("activate repaired policy version: %v", err)
	}
}

// policyRuntimePlanCount reads the installed snapshot's compiled plan count
// (zero when no snapshot is installed).
func policyRuntimePlanCount(t *testing.T, rt *PolicyRuntime, orgID string) int {
	t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e := rt.orgs[orgID]
	if e == nil {
		return 0
	}
	return len(e.plans)
}

// TestPolicyInvalidConfigHTTPColdOutcomeByMode drives the cold invalid-config
// outcome by mode through the real chat route: enforce answers 503 with the
// bounded policy_configuration_unavailable code (never the store-outage code,
// never a silent pass-through), shadow keeps nonblocking progress without
// installing the rejected candidate, an unknown stored mode is rejected
// before the global shadow downgrade could rescue it, and a repaired valid
// version activates through the same boundary on the next cold retry.
func TestPolicyInvalidConfigHTTPColdOutcomeByMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	policyStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := newPolicyAvailabilityUpstream(t, &upstreamCalls)

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"

	enforceLog := &capturedPolicyLog{}
	enforceRT, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(enforceLog))
	if err != nil {
		t.Fatalf("construct enforce runtime: %v", err)
	}
	shadowLog := &capturedPolicyLog{}
	shadowRT, err := NewPolicyRuntime(policyStore, nil, PolicyModeShadow, nil, slog.New(shadowLog))
	if err != nil {
		t.Fatalf("construct shadow runtime: %v", err)
	}
	enforceServer, enforceClient := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, enforceRT)
	shadowServer, shadowClient := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, shadowRT)

	chatBody := `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`
	denyBody := strings.Replace(chatBody, "hello", "r01005-blocked", 1)
	decodeCode := func(body string) string {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatalf("decode error envelope: %v; body=%s", err, body)
		}
		return envelope.Error.Code
	}

	// --- enforce, malformed stored YAML: cold invalid refusal is bounded ---
	enforceOrg, enforceKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "r01005-invalid-yaml")
	malformedYAML := "apiVersion: ypp/v1\nkind: deny\nname: [r01005-unclosed\n"
	malformedID := seedPolicyInvalidConfig(t, ctx, seedStore, enforceOrg, "r01005-invalid-yaml", malformedYAML)

	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	beforeUpstream := upstreamCalls.Load()
	resp := policyAvailabilityRequest(t, ctx, enforceClient, enforceServer.URL, "/v1/chat/completions", chatBody, enforceKey)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cold invalid-config status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	if got := decodeCode(resp.Body); got != "policy_configuration_unavailable" {
		t.Fatalf("invalid-config code = %q, want policy_configuration_unavailable (not the store-outage code); body=%s", got, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeUpstream {
		t.Fatalf("invalid-config request reached upstream: %d calls, want unchanged %d", got, beforeUpstream)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("cold invalid-config counter = %v, want %v", after, beforeCold+1)
	}
	if enforceRT.hasSnapshot(enforceOrg) {
		t.Fatal("cold invalid-config installed a snapshot")
	}
	if enforceLog.find("policy load failed", map[string]string{
		"mode": "enforce", "cache_state": "cold", "failure_class": "invalid_config", "stage": "yaml_document",
	}) < 0 {
		t.Fatalf("cold invalid-config was not audited with the bounded yaml_document stage: %+v", enforceLog.records)
	}
	if strings.Contains(resp.Body, enforceOrg) || strings.Contains(resp.Body, "r01005-unclosed") {
		t.Fatalf("tenant id or policy content leaked in the invalid-config response: %s", resp.Body)
	}

	// Repair through the real versioning API: the next cold retry loads the
	// valid candidate and its deny becomes observable — the rejection was
	// bounded to the invalid candidate, not a permanent refusal.
	activatePolicyVersion(t, ctx, seedStore, enforceOrg, malformedID, denyWordYAML("r01005-invalid-yaml", "r01005-blocked"))
	resp = policyAvailabilityRequest(t, ctx, enforceClient, enforceServer.URL, "/v1/chat/completions", chatBody, enforceKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repaired-config status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeUpstream+1 {
		t.Fatalf("repaired-config upstream calls = %d, want %d", got, beforeUpstream+1)
	}
	if !enforceRT.hasSnapshot(enforceOrg) {
		t.Fatal("repaired candidate did not install a snapshot")
	}
	denyBefore := upstreamCalls.Load()
	resp = policyAvailabilityRequest(t, ctx, enforceClient, enforceServer.URL, "/v1/chat/completions", denyBody, enforceKey)
	if resp.StatusCode != http.StatusBadRequest || decodeCode(resp.Body) != policyDenyErrorCode {
		t.Fatalf("repaired enforce deny status = %d body=%s; want 400 %s", resp.StatusCode, resp.Body, policyDenyErrorCode)
	}
	if got := upstreamCalls.Load(); got != denyBefore {
		t.Fatalf("denied request reached upstream: %d calls, want unchanged %d", got, denyBefore)
	}

	// --- shadow, unknown stored mode: rejected before the global downgrade ---
	shadowOrg, shadowKey := createPolicyAvailabilityIdentity(t, ctx, seedStore, "r01005-bad-mode")
	unknownModeYAML := strings.Replace(denyWordYAML("r01005-bad-mode", "r01005-never"), "mode: enforce", "mode: observe", 1)
	badModeID := seedPolicyInvalidConfig(t, ctx, seedStore, shadowOrg, "r01005-bad-mode", unknownModeYAML)

	beforeShadowCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("shadow", "cold"))
	beforeShadowUpstream := upstreamCalls.Load()
	resp = policyAvailabilityRequest(t, ctx, shadowClient, shadowServer.URL, "/v1/chat/completions", chatBody, shadowKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shadow invalid-config status = %d, want nonblocking 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeShadowUpstream+1 {
		t.Fatalf("shadow invalid-config upstream calls = %d, want %d", got, beforeShadowUpstream+1)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("shadow", "cold")); after != beforeShadowCold+1 {
		t.Fatalf("shadow cold invalid-config counter = %v, want %v", after, beforeShadowCold+1)
	}
	if shadowRT.hasSnapshot(shadowOrg) {
		t.Fatal("shadow invalid candidate installed a snapshot")
	}
	if shadowLog.find("policy load failed", map[string]string{
		"mode": "shadow", "cache_state": "cold", "failure_class": "invalid_config", "stage": "schema_mode",
	}) < 0 {
		t.Fatalf("unknown stored mode was not audited with the bounded schema_mode stage: %+v", shadowLog.records)
	}
	if strings.Contains(resp.Body, shadowOrg) || strings.Contains(resp.Body, "r01005-never") {
		t.Fatalf("tenant id or policy content leaked in the shadow response: %s", resp.Body)
	}

	// A valid repaired version loads through the same boundary: under global
	// shadow the downgrade now applies lawfully (validation passed first),
	// and the shadow policy runs without raising the verdict.
	activatePolicyVersion(t, ctx, seedStore, shadowOrg, badModeID, denyWordYAML("r01005-bad-mode", "r01005-never-marker"))
	resp = policyAvailabilityRequest(t, ctx, shadowClient, shadowServer.URL, "/v1/chat/completions", chatBody, shadowKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shadow repaired-config status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != beforeShadowUpstream+2 {
		t.Fatalf("shadow repaired-config upstream calls = %d, want %d", got, beforeShadowUpstream+2)
	}
	if !shadowRT.hasSnapshot(shadowOrg) {
		t.Fatal("repaired shadow candidate did not install a snapshot")
	}
}

// TestPolicyInvalidConfigHTTPAtomicCandidateKeepsEnforcing drives the atomic
// candidate contract through the real chat route with a controlled clock: a
// valid candidate activates and enforces; appending one broken member to the
// same org rejects the WHOLE candidate at the step_compile stage — the
// last-good snapshot keeps enforcing its original deny with its original load
// timestamp and plans — and repairing the member lets the full two-plan
// candidate load atomically. Enforce never silently degrades to off between
// the invalid refresh and the repair.
func TestPolicyInvalidConfigHTTPAtomicCandidateKeepsEnforcing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startPolicyAvailabilityPostgres(t, ctx)
	directPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated seed/auth pool: %v", err)
	}
	t.Cleanup(directPool.Close)
	seedStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	policyStore := adminstore.New(directPool, slog.New(slog.DiscardHandler), nil)
	var upstreamCalls atomic.Int64
	upstreamServer := newPolicyAvailabilityUpstream(t, &upstreamCalls)

	runtimeLog := &capturedPolicyLog{}
	runtime, err := NewPolicyRuntime(policyStore, nil, PolicyModeEnforce, nil, slog.New(runtimeLog))
	if err != nil {
		t.Fatalf("construct enforce runtime: %v", err)
	}
	clock := newPolicyAvailabilityClock()
	runtime.now = clock.Now

	cfg := config.Gateway{}
	cfg.AuthMode = "header"
	cfg.Provider = upstreamServer.URL
	cfg.FallbackModel = "r00905-model"
	cfg.UnknownModelPolicy = "reject"
	server, client := startPolicyAvailabilityHTTPGateway(t, cfg, upstreamServer.URL, directPool, runtime)

	org, key := createPolicyAvailabilityIdentity(t, ctx, seedStore, "r01005-atomic")
	seedPolicyAvailabilityPolicy(t, ctx, seedStore, org)

	chatBody := `{"model":"r00905-model","messages":[{"role":"user","content":"hello"}]}`
	denyBody := strings.Replace(chatBody, "hello", "r00905-blocked", 1)

	// Working input: the valid candidate activates and its deny is
	// observable before the upstream.
	resp := policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warm valid-config status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("warm valid deny status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	loadedAt := policyAvailabilityLoadedAt(t, runtime, org)
	if loadedAt.IsZero() {
		t.Fatal("warm request did not install a policy snapshot")
	}
	if plans := policyRuntimePlanCount(t, runtime, org); plans != 1 {
		t.Fatalf("warm snapshot plans = %d, want 1", plans)
	}

	// Partially valid set: one broken member joined to the valid one. The
	// whole candidate must be rejected as a unit at the bounded compile
	// stage — no partial plans may replace the last-good snapshot.
	unknownStepYAML := strings.Replace(denyWordYAML("r01005-broken-step", "r01005-never"), "builtin/contains", "builtin/not-registered", 1)
	brokenID := seedPolicyInvalidConfig(t, ctx, seedStore, org, "r01005-broken-step", unknownStepYAML)

	clock.Advance(2 * policyCacheTTL)
	beforeStale := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale"))

	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("last-good deny during invalid refresh status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("last-good deny reached upstream: %d calls, want unchanged 1", got)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+1 {
		t.Fatalf("invalid refresh counter = %v, want %v", after, beforeStale+1)
	}
	if got := policyAvailabilityLoadedAt(t, runtime, org); !got.Equal(loadedAt) {
		t.Fatalf("invalid refresh mutated the last-good timestamp: %v, want %v", got, loadedAt)
	}
	if plans := policyRuntimePlanCount(t, runtime, org); plans != 1 {
		t.Fatalf("invalid refresh published %d plans, want the retained single plan", plans)
	}
	if runtimeLog.find("policy load failed", map[string]string{
		"mode": "enforce", "cache_state": "stale", "failure_class": "invalid_config", "stage": "step_compile",
	}) < 0 {
		t.Fatalf("invalid refresh was not audited with the bounded step_compile stage: %+v", runtimeLog.records)
	}

	// Ordinary traffic keeps flowing through the retained snapshot; the
	// per-request retry fails bounded again and enforces nothing new.
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("last-good ordinary request status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("last-good ordinary upstream calls = %d, want 2", got)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+2 {
		t.Fatalf("second invalid refresh counter = %v, want %v", after, beforeStale+2)
	}
	if got := policyAvailabilityLoadedAt(t, runtime, org); !got.Equal(loadedAt) {
		t.Fatalf("second invalid refresh mutated the last-good timestamp: %v, want %v", got, loadedAt)
	}

	// Repair the broken member through the real versioning API: the whole
	// two-plan candidate now loads atomically and enforcement resumes on it.
	activatePolicyVersion(t, ctx, seedStore, org, brokenID, flagWordYAML("r01005-broken-step", "r01005-never-marker"))
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", chatBody, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repaired candidate status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}
	recoveredAt := policyAvailabilityLoadedAt(t, runtime, org)
	if !recoveredAt.After(loadedAt) {
		t.Fatalf("recovered snapshot loadedAt = %v, want newer than %v", recoveredAt, loadedAt)
	}
	if plans := policyRuntimePlanCount(t, runtime, org); plans != 2 {
		t.Fatalf("recovered snapshot plans = %d, want 2 (atomic full-candidate load)", plans)
	}
	if runtimeLog.find("policy store load succeeded", map[string]string{}) < 0 {
		t.Fatalf("recovery success log missing: %+v", runtimeLog.records)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+2 {
		t.Fatalf("healthy load added a stale signal: %v, want %v", after, beforeStale+2)
	}

	// The original deny member still enforces on the recovered snapshot.
	denyBefore := upstreamCalls.Load()
	resp = policyAvailabilityRequest(t, ctx, client, server.URL, "/v1/chat/completions", denyBody, key)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-recovery deny status = %d, want 400; body=%s", resp.StatusCode, resp.Body)
	}
	if got := upstreamCalls.Load(); got != denyBefore {
		t.Fatalf("post-recovery deny reached upstream: %d calls, want unchanged %d", got, denyBefore)
	}
}
