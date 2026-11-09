package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/trcli"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// TestPolicyReconcile_TwoLongLivedGateways exercises the real CLI command,
// Postgres/Redis persistence and both authenticated HTTP consumers. The
// gateways and their PolicyRuntime values stay alive across every apply.
func TestPolicyReconcile_TwoLongLivedGateways(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	ensureReconcileCreditsTable(t, pg)
	store := adminstore.New(pg, slog.New(slog.DiscardHandler), nil)
	versionReader := adminstore.NewPolicyVersionCache(rdb, slog.New(slog.DiscardHandler))
	pgURI := pg.Config().ConnString()

	orgA := createReconcileHTTPOrg(t, store, "a")
	orgB := createReconcileHTTPOrg(t, store, "b")
	orgC := createReconcileHTTPOrg(t, store, "c")
	orgs := []reconcileHTTPOrg{orgA, orgB, orgC}
	t.Cleanup(func() {
		for _, org := range orgs {
			_, _ = pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, org.keyID)
			_, _ = pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.id)
		}
	})

	var upstreamRequests atomic.Int64
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"fixture","choices":[{"text":"ok"}]}`)
	}))
	defer upstreamServer.Close()

	clock := time.Now().UTC()
	gatewayA := newPolicyReconcileHTTPGateway(t, pg, rdb, store, versionReader, upstreamServer.URL, &clock)
	gatewayB := newPolicyReconcileHTTPGateway(t, pg, rdb, store, versionReader, upstreamServer.URL, &clock)
	if gatewayA.runtime == gatewayB.runtime {
		t.Fatal("two independent gateway runtimes are required")
	}
	defer gatewayA.server.Close()
	defer gatewayB.server.Close()
	initialRuntimeA, initialRuntimeB := gatewayA.runtime, gatewayB.runtime
	initialServerA, initialServerB := gatewayA.server, gatewayB.server

	root := t.TempDir()
	declRoot := filepath.Join(root, "declarations")

	writeReconcileHTTPDecl(t, declRoot, orgA.slug, "r01305-a-v1")
	writeReconcileHTTPDecl(t, declRoot, orgB.slug, "r01305-b-v1")
	writeReconcileHTTPDecl(t, declRoot, orgC.slug, "r01305-c-v1")
	for _, org := range orgs {
		out := executeReconcileHTTPApply(t, ctx, pgURI, rdb.Options().Addr, declRoot, org.slug)
		if !strings.Contains(out, "bumped") {
			t.Fatalf("initial apply for synthetic organization %s did not report its version bump: %s", org.slug, out)
		}
	}

	keyA := adminstore.PolicyVersionKeyPrefix + orgA.id
	keyB := adminstore.PolicyVersionKeyPrefix + orgB.id
	keyC := adminstore.PolicyVersionKeyPrefix + orgC.id
	aV1 := readReconcileVersion(t, ctx, rdb, keyA)
	bV1 := readReconcileVersion(t, ctx, rdb, keyB)
	cV1 := readReconcileVersion(t, ctx, rdb, keyC)

	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, "r01305-a-v1", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, "r01305-a-v2", http.StatusOK, "", &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, "r01305-b-v1", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, "r01305-a-v2", http.StatusOK, "", &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgC, "r01305-c-v1", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgC, "r01305-c-v2", http.StatusOK, "", &upstreamRequests)
	}
	baseC := clock

	// A changes while B remains unchanged; both running gateways must consume
	// A's new version on the next authenticated HTTP request.
	writeReconcileHTTPDecl(t, declRoot, orgA.slug, "r01305-a-v2")
	out := executeReconcileHTTPApply(t, ctx, pgURI, rdb.Options().Addr, declRoot, orgA.slug)
	if !strings.Contains(out, "bumped") {
		t.Fatalf("changed apply did not report its bump: %s", out)
	}
	aV2 := readReconcileVersion(t, ctx, rdb, keyA)
	if aV2 == aV1 {
		t.Fatal("A's Redis version did not change after the actual CLI apply")
	}
	if got := readReconcileVersion(t, ctx, rdb, keyB); got != bV1 {
		t.Fatalf("A's apply changed B's Redis version: before %d, after %d", bV1, got)
	}
	assertReconcileStoredVersion(t, ctx, store, orgA.id, 2, "r01305-a-v2")
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, "r01305-a-v2", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, "r01305-a-v1", http.StatusOK, "", &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, "r01305-b-v1", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, "r01305-a-v2", http.StatusOK, "", &upstreamRequests)
	}

	// An in-sync apply must not bump A's Redis version.
	out = executeReconcileHTTPApply(t, ctx, pgURI, rdb.Options().Addr, declRoot, orgA.slug)
	if !strings.Contains(out, "unchanged=1") {
		t.Fatalf("identical apply was not idempotent: %s", out)
	}
	if got := readReconcileVersion(t, ctx, rdb, keyA); got != aV2 {
		t.Fatalf("idempotent apply changed A's Redis version: before %d, after %d", aV2, got)
	}

	// C's DB mutation commits but its actual Redis bump is rejected by a
	// listener owned for the rest of the test. The healthy shared key remains
	// untouched, so both runtimes prove the bounded TTL fallback.
	rejectAddr, closeReject := newReconcileRejectingRedis(t, ctx)
	defer closeReject()
	writeReconcileHTTPDecl(t, declRoot, orgC.slug, "r01305-c-v2")
	out = executeReconcileHTTPApply(t, ctx, pgURI, rejectAddr, declRoot, orgC.slug)
	if !strings.Contains(out, "WARNING: gateway cache bump failed") || !strings.Contains(out, "TTL fallback") {
		t.Fatalf("failed bump warning missing from actual CLI result: %s", out)
	}
	assertReconcileStoredVersion(t, ctx, store, orgC.id, 2, "r01305-c-v2")
	if got := readReconcileVersion(t, ctx, rdb, keyC); got != cV1 {
		t.Fatalf("failed bump changed the live healthy Redis version: before %d, after %d", cV1, got)
	}

	clock = baseC.Add(policyCacheTTL - time.Nanosecond)
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgC, "r01305-c-v2", http.StatusOK, "", &upstreamRequests)
	}
	if got := readReconcileVersion(t, ctx, rdb, keyC); got != cV1 {
		t.Fatalf("pre-TTL requests changed the live Redis version: want %d, got %d", cV1, got)
	}
	clock = baseC.Add(policyCacheTTL)
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgC, "r01305-c-v2", http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
	}
	if got := readReconcileVersion(t, ctx, rdb, keyC); got != cV1 {
		t.Fatalf("TTL refresh unexpectedly changed the live Redis version: want %d, got %d", cV1, got)
	}

	if gatewayA.runtime != initialRuntimeA || gatewayB.runtime != initialRuntimeB || gatewayA.server != initialServerA || gatewayB.server != initialServerB {
		t.Fatal("gateway runtime or HTTP server was replaced during reconciliation")
	}
	t.Logf("synthetic identities: A(org=%s key=%s) B(org=%s key=%s) C(org=%s key=%s); Redis versions A=%d→%d B=%d C=%d; upstream requests=%d", orgA.id, orgA.keyID, orgB.id, orgB.keyID, orgC.id, orgC.keyID, aV1, aV2, bV1, cV1, upstreamRequests.Load())
}

type reconcileHTTPOrg struct {
	id, slug, plaintext, keyID string
}

type reconcileHTTPGateway struct {
	runtime *PolicyRuntime
	server  *httptest.Server
	client  *http.Client
}

func ensureReconcileCreditsTable(t *testing.T, pg *pgxpool.Pool) {
	t.Helper()
	_, err := pg.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS org_credits (
		org_id text PRIMARY KEY,
		balance_cents bigint DEFAULT 0 NOT NULL,
		updated_at timestamptz DEFAULT now() NOT NULL
	)`)
	if err != nil {
		t.Fatalf("ensure org_credits: %v", err)
	}
}

func createReconcileHTTPOrg(t *testing.T, store *adminstore.Store, suffix string) reconcileHTTPOrg {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("r01305-%s-%d", suffix, time.Now().UnixNano())
	org, err := store.CreateOrganization(ctx, "R01305 synthetic "+suffix, slug)
	if err != nil {
		t.Fatalf("create synthetic org %s: %v", suffix, err)
	}
	team, err := store.CreateTeam(ctx, org.ID, "R01305 team", slug+"-team", nil)
	if err != nil {
		t.Fatalf("create synthetic team: %v", err)
	}
	key, err := auth.GeneratePersonalKey()
	if err != nil {
		t.Fatalf("generate synthetic API key: %v", err)
	}
	apiKey, err := store.CreateAPIKey(ctx, auth.HashKey(key), "R01305 integration", &org.ID, &team.ID)
	if err != nil {
		t.Fatalf("create synthetic API key row: %v", err)
	}
	return reconcileHTTPOrg{id: org.ID, slug: slug, plaintext: key, keyID: apiKey.ID}
}

func newPolicyReconcileHTTPGateway(t *testing.T, pg *pgxpool.Pool, rdb *redis.Client, store *adminstore.Store, versions PolicyVersionReader, upstreamURL string, clock *time.Time) *reconcileHTTPGateway {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	runtime, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, logger)
	if err != nil {
		t.Fatalf("construct independent policy runtime: %v", err)
	}
	runtime.now = func() time.Time { return *clock }
	resolver := auth.NewResolver(pg, rdb, 300, nil)
	gw := &gateway{
		gatewayCore: gatewayCore{cfg: config.Gateway{
			AuthMode:           "header",
			Provider:           upstreamURL,
			FallbackModel:      "r01305-model",
			UnknownModelPolicy: "reject",
		}, log: logger},
		gatewayEgress: gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: upstreamURL})},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			"r01305-model": {ModelName: "r01305-model", Provider: "openai", Enabled: true},
		}},
		gatewayCompliance: gatewayCompliance{policyRuntime: runtime},
	}
	gw.auth = NewAuthMiddleware(gw.cfg, resolver)
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	client := server.Client()
	client.Timeout = 10 * time.Second
	return &reconcileHTTPGateway{runtime: runtime, server: server, client: client}
}

func writeReconcileHTTPDecl(t *testing.T, root, slug, deniedMarker string) {
	t.Helper()
	dir := filepath.Join(root, slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create policy declaration directory: %v", err)
	}
	content := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: marker-blocker
mode: enforce
hooks: [pre_upstream]
steps:
  - id: marker
    detector: builtin/contains
    params:
      words: [%q]
      action: deny
---
enabled: true
attachments:
  - key_label: ""
    model_pattern: "*"
    endpoint: completions
    priority: 100
`, deniedMarker)
	if err := os.WriteFile(filepath.Join(dir, "marker-blocker.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write synthetic policy declaration: %v", err)
	}
}

func executeReconcileHTTPApply(t *testing.T, ctx context.Context, pgURI, redisAddr, root, slug string) string {
	t.Helper()
	cmd := trcli.RootCommand() //nolint:contextcheck // factory builds callbacks; I/O inherits bounded ctx through ExecuteContext.
	cmd.SetContext(ctx)
	var stdout, stderr strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"policies", "reconcile", "--pg-uri", pgURI, "--redis-addr", redisAddr, "--dir", root, "--org", slug, "--git-sha", "r01305-integration", "--apply"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("actual yb policies reconcile --apply failed for %s: %v; stdout=%s stderr=%s", slug, err, stdout.String(), stderr.String())
	}
	return stdout.String() + stderr.String()
}

func readReconcileVersion(t *testing.T, ctx context.Context, rdb *redis.Client, key string) int64 {
	t.Helper()
	raw, err := rdb.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("read live policy version key: %v", err)
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatalf("policy version is not a decimal int64: %v", err)
	}
	return version
}

func assertReconcileStoredVersion(t *testing.T, ctx context.Context, store *adminstore.Store, orgID string, version int, marker string) {
	t.Helper()
	policies, err := store.ListPolicies(ctx, orgID)
	if err != nil || len(policies) != 1 {
		t.Fatalf("read persisted policy for synthetic org: err=%v count=%d", err, len(policies))
	}
	if policies[0].CurrentVersion != version || !policies[0].Enabled {
		t.Fatalf("persisted active policy=%d enabled=%t; want version %d enabled", policies[0].CurrentVersion, policies[0].Enabled, version)
	}
	stored, err := store.GetPolicyVersion(ctx, orgID, policies[0].ID, version)
	if err != nil || !strings.Contains(stored.YAML, marker) {
		t.Fatalf("read persisted policy version %d marker: err=%v", version, err)
	}
}

func assertReconcileHTTPVerdict(t *testing.T, ctx context.Context, gateway *reconcileHTTPGateway, org reconcileHTTPOrg, marker string, wantStatus int, wantCode string, upstreamRequests *atomic.Int64) {
	t.Helper()
	before := upstreamRequests.Load()
	body := fmt.Sprintf(`{"model":"r01305-model","prompt":%q,"max_tokens":8}`, marker)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.server.URL+"/v1/completions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create authenticated request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := gateway.client.Do(req)
	if err != nil {
		t.Fatalf("send authenticated gateway request: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read gateway response: %v", err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("gateway status for org %s marker %q = %d, want %d; response=%s", org.slug, marker, resp.StatusCode, wantStatus, respBody)
	}
	if wantStatus == http.StatusBadRequest {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			t.Fatalf("decode policy denial response: %v", err)
		}
		if envelope.Error.Code != wantCode {
			t.Fatalf("gateway error code=%q, want %q", envelope.Error.Code, wantCode)
		}
		if got := upstreamRequests.Load(); got != before {
			t.Fatalf("denied request reached mock upstream: requests before=%d after=%d", before, got)
		}
		return
	}
	if got := upstreamRequests.Load(); got != before+1 {
		t.Fatalf("allowed request did not reach mock upstream exactly once: before=%d after=%d", before, got)
	}
}

func newReconcileRejectingRedis(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind owned rejecting Redis listener: %v", err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			_ = conn.Close()
		}
	}()
	closeListener := func() {
		close(stop)
		_ = listener.Close()
		<-done
	}
	return listener.Addr().String(), closeListener
}

// probeSnapshotRevision sends one authenticated completions request for the
// SIGNAL marker (the one only v2 denies) and reports the observed revision:
// allowed (200) = v1 still active, denied (400) = v2 active.
func probeSnapshotRevision(ctx context.Context, gateway *reconcileHTTPGateway, org reconcileHTTPOrg, marker string) (int, error) {
	body := fmt.Sprintf(`{"model":"r01905-model","prompt":%q,"max_tokens":8}`, marker)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.server.URL+"/v1/completions", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := gateway.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return 2, nil // v2 (which denies the signal marker) is active
	case http.StatusOK:
		return 1, nil // v1 (which does not know the signal marker) is active
	default:
		return 0, fmt.Errorf("unexpected status %d during activation transition", resp.StatusCode)
	}
}

// integration anchor: actual HTTP traffic straddles a real CLI activation on
// TWO independently constructed, long-lived gateways. Every request finishes
// on one internally coherent revision, observations never regress from the
// new revision back to the old one, both gateways converge without a restart,
// a concurrent org never sees foreign policies, and a forced bump failure
// immediate convergence.
func TestPolicyRuntime_SnapshotAcrossActivationTwoGateways(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	ensureReconcileCreditsTable(t, pg)
	store := adminstore.New(pg, slog.New(slog.DiscardHandler), nil)
	versionReader := adminstore.NewPolicyVersionCache(rdb, slog.New(slog.DiscardHandler))
	pgURI := pg.Config().ConnString()

	orgA := createReconcileHTTPOrg(t, store, "snap-a")
	orgB := createReconcileHTTPOrg(t, store, "snap-b")
	orgs := []reconcileHTTPOrg{orgA, orgB}
	t.Cleanup(func() {
		for _, org := range orgs {
			_, _ = pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, org.keyID)
			_, _ = pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.id)
		}
	})

	var upstreamRequests atomic.Int64
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"fixture","choices":[{"text":"ok"}]}`)
	}))
	defer upstreamServer.Close()

	clock := time.Now().UTC()
	gatewayA := newPolicyReconcileHTTPGateway(t, pg, rdb, store, versionReader, upstreamServer.URL, &clock)
	gatewayB := newPolicyReconcileHTTPGateway(t, pg, rdb, store, versionReader, upstreamServer.URL, &clock)
	defer gatewayA.server.Close()
	defer gatewayB.server.Close()
	runtimeA, runtimeB := gatewayA.runtime, gatewayB.runtime

	// org A v1 denies only m1; the later changed apply ships v2 denying only
	// m2 — the m2 verdict is the revision signal (200=v1, 400=v2).
	const (
		aV1Marker = "r01905-a-m1"
		aV2Marker = "r01905-a-m2"
		bV1Marker = "r01905-b-m1"
		bV2Marker = "r01905-b-m2"
	)
	declRoot := filepath.Join(t.TempDir(), "declarations")
	writeReconcileHTTPDecl(t, declRoot, orgA.slug, aV1Marker)
	writeReconcileHTTPDecl(t, declRoot, orgB.slug, bV1Marker)
	for _, org := range orgs {
		out := executeReconcileHTTPApply(t, ctx, pgURI, rdb.Options().Addr, declRoot, org.slug)
		if !strings.Contains(out, "bumped") {
			t.Fatalf("initial apply for %s did not bump: %s", org.slug, out)
		}
	}

	// Baseline: both gateways observe the coherent v1 state for org A and
	// org B's own untouched policy.
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV1Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV1Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
	}

	// The activation: actual requests keep flowing on BOTH gateways while
	// the real CLI apply commits and bumps. Every observation is the v2
	// signal marker's verdict (200 = v1 active, 400 = v2 active) and must
	// never regress from v2 back to v1.
	writeReconcileHTTPDecl(t, declRoot, orgA.slug, aV2Marker)
	type observation struct{ rev int }
	observationsA := make([]observation, 0)
	observationsB := make([]observation, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	stop := make(chan struct{})
	burst := func(gateway *reconcileHTTPGateway, org reconcileHTTPOrg, marker string, sink *[]observation) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rev, err := probeSnapshotRevision(ctx, gateway, org, marker)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			*sink = append(*sink, observation{rev: rev})
			mu.Unlock()
		}
	}
	wg.Add(2)
	go burst(gatewayA, orgA, aV2Marker, &observationsA)
	go burst(gatewayB, orgA, aV2Marker, &observationsB)
	out := executeReconcileHTTPApply(t, ctx, pgURI, rdb.Options().Addr, declRoot, orgA.slug)
	if !strings.Contains(out, "bumped") {
		t.Fatalf("activation apply did not bump: %s", out)
	}
	close(stop)
	wg.Wait()

	assertNoRegression := func(name string, obs []observation) {
		t.Helper()
		seenV2 := false
		for i, o := range obs {
			switch o.rev {
			case 2:
				seenV2 = true
			case 1:
				if seenV2 {
					t.Fatalf("%s: observation %d regressed to v1 after v2 was active (%+v)", name, i, obs)
				}
			default:
				t.Fatalf("%s: observation %d is not a revision signal (%+v)", name, i, obs)
			}
		}
	}
	mu.Lock()
	assertNoRegression("gatewayA", observationsA)
	assertNoRegression("gatewayB", observationsB)
	aObs, bObs := len(observationsA), len(observationsB)
	mu.Unlock()
	if aObs == 0 || bObs == 0 {
		t.Fatalf("activation burst produced no observations on some gateway: A=%d B=%d", aObs, bObs)
	}

	// Convergence without restart: fresh requests on both gateways observe
	// exactly the new revision (m1 allowed again, m2 denied).
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV2Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV1Marker, http.StatusOK, "", &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV1Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
	}

	// Simulate a persisted activation whose new version cannot be compiled.
	// Both warm gateways must continue to serve their last-known-good v2
	// snapshot, then recover after explicitly reactivating the prior version.
	policies, err := store.ListPolicies(ctx, orgA.id)
	if err != nil || len(policies) != 1 {
		t.Fatalf("list org A policies for failed activation: policies=%d err=%v", len(policies), err)
	}
	goodVersion := policies[0].CurrentVersion
	badVersion, err := store.CreatePolicyVersion(ctx, orgA.id, policies[0].ID, "not: [valid", "", "test")
	if err != nil {
		t.Fatalf("append invalid candidate policy: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgA.id, policies[0].ID, badVersion.Version); err != nil {
		t.Fatalf("activate invalid candidate: %v", err)
	}
	if err := versionReader.SetPolicyVersion(ctx, orgA.id, time.Now().UnixNano()); err != nil {
		t.Fatalf("invalidate gateway snapshots after failed activation: %v", err)
	}
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV2Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
	}
	if _, err := store.SetActivePolicyVersion(ctx, orgA.id, policies[0].ID, goodVersion); err != nil {
		t.Fatalf("roll back to last-known-good policy version %d: %v", goodVersion, err)
	}
	if err := versionReader.SetPolicyVersion(ctx, orgA.id, time.Now().UnixNano()); err != nil {
		t.Fatalf("invalidate gateways after policy rollback: %v", err)
	}
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV2Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgA, aV1Marker, http.StatusOK, "", &upstreamRequests)
	}

	// Forced bump failure: B's DB change commits, its Redis bump is rejected.
	// Both gateways must keep serving the OLD revision until the hard TTL —
	// eventual freshness only, never immediate convergence.
	rejectAddr, closeReject := newReconcileRejectingRedis(t, ctx)
	defer closeReject()
	baseClock := clock
	writeReconcileHTTPDecl(t, declRoot, orgB.slug, bV2Marker)
	out = executeReconcileHTTPApply(t, ctx, pgURI, rejectAddr, declRoot, orgB.slug)
	if !strings.Contains(out, "WARNING: gateway cache bump failed") || !strings.Contains(out, "TTL fallback") {
		t.Fatalf("failed bump warning missing from actual CLI result: %s", out)
	}
	clock = baseClock.Add(policyCacheTTL - time.Nanosecond)
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV2Marker, http.StatusOK, "", &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV1Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
	}
	clock = baseClock.Add(policyCacheTTL)
	for _, gateway := range []*reconcileHTTPGateway{gatewayA, gatewayB} {
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV2Marker, http.StatusBadRequest, policyDenyErrorCode, &upstreamRequests)
		assertReconcileHTTPVerdict(t, ctx, gateway, orgB, bV1Marker, http.StatusOK, "", &upstreamRequests)
	}

	if gatewayA.runtime != runtimeA || gatewayB.runtime != runtimeB {
		t.Fatal("gateway runtime was replaced during reconciliation; gateways must converge without restart")
	}
	t.Logf("activation burst observations: A=%d B=%d; upstream requests=%d", aObs, bObs, upstreamRequests.Load())
}
