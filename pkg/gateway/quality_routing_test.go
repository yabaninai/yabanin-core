package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/agenteval/contracts"
	"github.com/reireirei/yabanin/pkg/agenteval/results"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// fakeQualitySource is a scriptable router.QualitySource for gateway tests.
type fakeQualitySource struct {
	calls int
	snap  *fallbackrouter.QualitySnapshot // returned when err == nil
	err   error
}

func (f *fakeQualitySource) QualitySnapshot(_ context.Context, _ string) (*fallbackrouter.QualitySnapshot, error) {
	f.calls++
	return f.snap, f.err
}

// qualityTestGateway wires the auto branch minimally: rule-tier classifier,
// a two-model easy pool, and an injectable routing-mode loader. src may be the
// fake or the REAL pkg/agenteval/results adapter (/-05 boundary tests).
func qualityTestGateway(t *testing.T, mode string, src fallbackrouter.QualitySource) *gateway {
	t.Helper()
	gw := &gateway{
		cfg:         config.Gateway{Provider: "http://up.example", DecisionHeaderEnabled: true, DecisionEventEnabled: true},
		pool:        upstream.NewPool(upstream.Options{BaseURL: "http://up.example"}),
		retryPolicy: retry.Policy{MaxAttempts: 1},
		log:         slog.Default(),
	}
	reg := classifier.NewRegistry(classifier.NewRuleTier())
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(reg), nil, gw.log)
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "qual-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "qual-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}, nil)
	gw.qualitySource = src
	gw.routingModeLoader = func(_ context.Context, _ string) *adminstore.OrgRoutingSettings {
		return &adminstore.OrgRoutingSettings{RoutingMode: mode}
	}
	return gw
}

func freshQualitySnapshot(version string, age time.Duration) *fallbackrouter.QualitySnapshot {
	return &fallbackrouter.QualitySnapshot{
		Version:   version,
		Source:    "agenteval",
		CreatedAt: time.Now().Add(-age),
		Overall: map[string]fallbackrouter.QualityScore{
			"qual-a": {Score: 0.4, Samples: 50},
			"qual-b": {Score: 0.9, Samples: 50},
		},
	}
}

// TestSelectTierModel_OffByDefault pins the gating invariant: unless the org
// routing_mode is "quality" AND a source is wired, quality is never consulted.
func TestSelectTierModel_OffByDefault(t *testing.T) {
	src := &fakeQualitySource{snap: freshQualitySnapshot("v12", time.Hour)}

	// mode=auto with a perfectly good wired source → quality not consulted.
	gw := qualityTestGateway(t, "auto", src)
	m, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", "auto")
	require.NoError(t, err)
	assert.NotEmpty(t, m.Name)
	assert.False(t, outcome.Used)
	assert.Empty(t, outcome.FallbackReason, "non-quality modes must be bit-for-bit the classifier path")
	assert.Zero(t, src.calls, "the quality source must not even be read outside routing_mode=quality")

	// mode=quality but no source wired → plain path, no fallback noise.
	gw.qualitySource = nil
	m, outcome, _, err = gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err)
	assert.NotEmpty(t, m.Name)
	assert.False(t, outcome.Used)
	assert.Empty(t, outcome.FallbackReason)
}

func TestSelectTierModel_QualityRankingDecides(t *testing.T) {
	src := &fakeQualitySource{snap: freshQualitySnapshot("v12", time.Hour)}
	gw := qualityTestGateway(t, routingModeQuality, src)

	m, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err)
	assert.Equal(t, "qual-b", m.Name, "the better-scored model inside the policy pool wins")
	assert.True(t, outcome.Used)
	assert.Equal(t, "v12", outcome.Version)
	assert.Equal(t, 1, src.calls)
}

func TestSelectTierModel_FallbackOnUnavailableSource(t *testing.T) {
	src := &fakeQualitySource{err: errors.New("store down")}
	gw := qualityTestGateway(t, routingModeQuality, src)

	m, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err, "fallback must never fail the request")
	assert.NotEmpty(t, m.Name)
	assert.False(t, outcome.Used)
	assert.Equal(t, fallbackrouter.QualityFallbackSourceUnavailable, outcome.FallbackReason)
}

func TestSelectTierModel_FallbackOnNilSnapshot(t *testing.T) {
	src := &fakeQualitySource{}
	gw := qualityTestGateway(t, routingModeQuality, src)

	_, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err)
	assert.False(t, outcome.Used)
	assert.Equal(t, fallbackrouter.QualityFallbackNoSnapshot, outcome.FallbackReason)
}

func TestSelectTierModel_FallbackOnStaleSnapshot(t *testing.T) {
	src := &fakeQualitySource{snap: freshQualitySnapshot("v9", qualitySnapshotMaxAge+time.Hour)}
	gw := qualityTestGateway(t, routingModeQuality, src)

	_, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err)
	assert.False(t, outcome.Used)
	assert.Equal(t, fallbackrouter.QualityFallbackStale, outcome.FallbackReason)
	assert.Equal(t, "v9", outcome.Version)
}

// with no CreatedAt is fail-closed stale — Fresh never accepts a zero or
// forged-fresh timestamp, so the classifier path decides.
func TestSelectTierModel_FallbackOnZeroTimeSnapshot(t *testing.T) {
	corrupt := freshQualitySnapshot("v0", 0)
	corrupt.CreatedAt = time.Time{}
	src := &fakeQualitySource{snap: corrupt}
	gw := qualityTestGateway(t, routingModeQuality, src)

	_, outcome, _, err := gw.selectTierModel(context.Background(), classifier.ClassEasy, "org-1", "", "", routingModeQuality)
	require.NoError(t, err, "a corrupt snapshot must never fail the request")
	assert.False(t, outcome.Used)
	assert.Equal(t, fallbackrouter.QualityFallbackStale, outcome.FallbackReason)
	assert.Equal(t, "v0", outcome.Version)
}

// the deployment boundary — config wires a results dir that does not exist.
// The REAL adapter (not the fake) answers router.ErrQualityUnavailable on
// every call; the chat boundary serves the request via the unchanged
// classifier path with the explicit reason in the decision header, and
// repeated requests (retry of the operation) stay stable.
func TestChatCompletions_QualityMode_SourceDirAbsent_ExplicitFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)

	missing := filepath.Join(t.TempDir(), "absent-runs")
	src := results.NewSource(missing, filepath.Join(missing, "approvals.json"))
	gw := qualityTestGateway(t, routingModeQuality, src)
	gw.res = stubModelResolver{
		"qual-a": {ModelName: "qual-a", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"qual-b": {ModelName: "qual-b", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)

	for i := 0; i < 3; i++ {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
			strings.NewReader(string(nonStreamBody("qual-a", "Translate this"))))
		r.Header.Set("X-Org-Id", "org-1")
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)

		require.Equal(t, http.StatusOK, rec.Code, "attempt %d: absent source dir must never fail the client", i)
		var dec routingDecision
		require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
		assert.Equal(t, decisionSourceTierRouter, dec.Source, "attempt %d: classifier path decided", i)
		assert.Equal(t, "quality_fallback:source_unavailable", dec.Reason, "attempt %d: diagnosable fallback cause", i)
		assert.Empty(t, dec.QualityVersion)
	}
}

func TestApplyQualityOutcome_DecisionFields(t *testing.T) {
	used := routingDecision{Source: decisionSourceTierRouter, To: "m"}
	applyQualityOutcome(&used, fallbackrouter.QualityOutcome{Used: true, Version: "v12"})
	assert.Equal(t, decisionSourceQualityEval, used.Source)
	assert.Equal(t, "v12", used.QualityVersion)
	assert.Empty(t, used.Reason)

	fb := routingDecision{Source: decisionSourceTierRouter, To: "m"}
	applyQualityOutcome(&fb, fallbackrouter.QualityOutcome{FallbackReason: fallbackrouter.QualityFallbackStale})
	assert.Equal(t, decisionSourceTierRouter, fb.Source)
	assert.Equal(t, "quality_fallback:stale_snapshot", fb.Reason)
	assert.Empty(t, fb.QualityVersion)

	untouched := routingDecision{Source: decisionSourceTierRouter}
	applyQualityOutcome(&untouched, fallbackrouter.QualityOutcome{})
	assert.Equal(t, routingDecision{Source: decisionSourceTierRouter}, untouched)
}

// TestChatCompletions_QualityMode_DecisionHeaderAndModel: end-to-end proof —
// an org in routing_mode=quality with a fresh owner-approved snapshot gets the
// eval favorite, and X-Yabanin-Decision carries source=quality_eval + version.
func TestChatCompletions_QualityMode_DecisionHeaderAndModel(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)

	src := &fakeQualitySource{snap: freshQualitySnapshot("v12", time.Hour)}
	gw := qualityTestGateway(t, routingModeQuality, src)
	gw.res = stubModelResolver{
		"qual-a": {ModelName: "qual-a", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"qual-b": {ModelName: "qual-b", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)

	body := nonStreamBody("qual-a", "Translate this") // rule tier: easy, 0.90 ≥ 0.6 threshold
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "qual-b", gotModel, "the quality favorite inside the pool must be called")

	hdr := rec.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, hdr)
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(hdr), &dec))
	assert.Equal(t, decisionSourceQualityEval, dec.Source)
	assert.Equal(t, "v12", dec.QualityVersion)
	assert.Equal(t, "easy", dec.Class)
}

// TestChatCompletions_QualityMode_FallbackVisibleInDecision: with the source
// erroring, the classifier path serves the request unchanged and the decision
// names the fallback reason (degradation is visible, never silent).
func TestChatCompletions_QualityMode_FallbackVisibleInDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)

	src := &fakeQualitySource{err: errors.New("store down")}
	gw := qualityTestGateway(t, routingModeQuality, src)
	gw.res = stubModelResolver{
		"qual-a": {ModelName: "qual-a", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"qual-b": {ModelName: "qual-b", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)

	body := nonStreamBody("qual-a", "Translate this")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, decisionSourceTierRouter, dec.Source, "fallback keeps the classifier-path source")
	assert.Equal(t, "quality_fallback:source_unavailable", dec.Reason)
	assert.Empty(t, dec.QualityVersion)
}

// writeIntegrationRunDir materializes a REAL versioned agenteval run directory
// themselves — the same wire form the owner flow produces. outcomes maps
// arm id → (completed episodes, successes among them).
func writeIntegrationRunDir(t *testing.T, root, runID string, arms []contracts.Arm, outcomes map[string][2]int) string {
	t.Helper()
	dir := filepath.Join(root, runID)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	capUSD := 0.25
	manifest := contracts.Manifest{
		SchemaVersion: contracts.SchemaVersion,
		RunID:         runID,
		CreatedAt:     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		Profile:       "QUALITY_40",
		GitCommit:     "fb9889df0000",
		Dataset:       contracts.DatasetRef{CatalogID: "catalog-v5", SelectionFile: "sel.json", SHA256: []string{"sha256-" + runID}, Split: "eval"},
		Arms:          arms,
		Caps:          contracts.Caps{MaxLLMAttempts: 6, MaxToolCalls: 12, MaxWallSeconds: 300, EpisodeCapUSD: &capUSD},
		PriceSnapshot: contracts.PriceSnapshot{Source: "console", AsOf: "2026-10-01", Currency: "USD"},
		Spend:         contracts.Spend{Authorized: true, LimitUSD: 10, ApprovedBy: "owner"},
		Integrity:     map[string]string{},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600))

	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, arm := range arms {
		completed, successes := outcomes[arm.ID][0], outcomes[arm.ID][1]
		for i := 0; i < completed; i++ {
			outcome := "fail"
			if i < successes {
				outcome = "success"
			}
			tokens := int64(100)
			cost := 0.01
			stop := "natural"
			verdict := "verdict-" + runID[:8]
			require.NoError(t, enc.Encode(contracts.EpisodeRecord{
				EpisodeID:       fmt.Sprintf("%s-%s-%03d", runID[:8], arm.ID, i),
				RootID:          runID,
				CaseID:          fmt.Sprintf("case-%s-%03d", runID[:8], i),
				Arm:             arm.ID,
				Repetition:      1,
				ExecutionStatus: contracts.StatusCompleted,
				StopReason:      &stop,
				TaskOutcome:     &outcome,
				SafetyOutcome:   "clean",
				ProtocolOutcome: "ok",
				Usage:           contracts.Usage{LLMCalls: 2, ToolCalls: 1, TokensIn: &tokens, TokensOut: &tokens},
				Cost:            contracts.CostSummary{EstimatedUSD: &cost, Coverage: 0.5},
				VerdictRef:      &verdict,
			}))
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "episodes.jsonl"), []byte(sb.String()), 0o600))
	return dir
}

// integrationArms is the two-model stand: qual-a (base) and qual-b (favorite).
func integrationArms() []contracts.Arm {
	return []contracts.Arm{
		{ID: "arm-a", ModelSlug: "qual-a", EndpointURL: "https://up.example/v1", ProviderPinning: "pinned", HeadersAllowed: []string{"authorization"}},
		{ID: "arm-b", ModelSlug: "qual-b", EndpointURL: "https://up.example/v1", ProviderPinning: "pinned", HeadersAllowed: []string{"authorization"}},
	}
}

// consumer path — a REAL versioned results directory + approvals file,
// consumed through the chat boundary by the real pkg/agenteval/results
// adapter (no fakes on the quality path). The two-model stand proves:
//   - the eval favorite (qual-b, 27/30) is called upstream;
//   - the decision is explainable by the saved run identity
//     (source=quality_eval, quality_version=<run_id> in X-Yabanin-Decision);
//   - the residency profile still runs on the quality-selected candidate
//     (X-Residency-Region present; quality routing cannot bypass it);
//   - an org without approval on the SAME stand falls back explicitly
//     (tenant isolation through the boundary).
func TestChatCompletions_QualityMode_RealResultsDir_EndToEnd(t *testing.T) {
	var gotModel string
	var gotMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotMu.Lock()
		gotModel, _ = body["model"].(string)
		gotMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)

	runID := "5f0c9d3a-1b2e-4c7a-9d80-11a22bb33cc4"
	root := t.TempDir()
	writeIntegrationRunDir(t, root, runID, integrationArms(), map[string][2]int{
		"arm-a": {30, 18}, // qual-a: 0.60 over 30 samples
		"arm-b": {30, 27}, // qual-b: 0.90 over 30 samples (favorite, >= 20 samples)
	})
	approvals := filepath.Join(root, "approvals.json")
	rawReg, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"approvals": map[string]any{
			"org-1": results.Approval{RunID: runID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(approvals, rawReg, 0o600))

	gw := qualityTestGateway(t, routingModeQuality, results.NewSource(root, approvals))
	gw.res = stubModelResolver{
		"qual-a": {ModelName: "qual-a", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"qual-b": {ModelName: "qual-b", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG"}}

	post := func(org string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
			strings.NewReader(string(nonStreamBody("qual-a", "Translate this"))))
		r.Header.Set("X-Org-Id", org)
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)
		return rec
	}

	// Approved org: quality ranking decides, provenance visible, residency intact.
	rec := post("org-1")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	gotMu.Lock()
	assert.Equal(t, "qual-b", gotModel, "the measured favorite inside the policy pool must serve the request")
	gotMu.Unlock()
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, decisionSourceQualityEval, dec.Source)
	assert.Equal(t, runID, dec.QualityVersion, "the decision explains itself by the saved run identity")
	assert.Equal(t, "easy", dec.Class)
	assert.Equal(t, "SG", rec.Header().Get("X-Residency-Region"), "residency ran on the quality-selected candidate — not bypassed")

	// Unapproved org on the same stand: explicit fallback, no data, still 200.
	rec = post("org-2")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var dec2 routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec2))
	assert.Equal(t, decisionSourceTierRouter, dec2.Source, "org without approval uses the classifier path")
	assert.Equal(t, "quality_fallback:source_unavailable", dec2.Reason)
	assert.Empty(t, dec2.QualityVersion)
}
