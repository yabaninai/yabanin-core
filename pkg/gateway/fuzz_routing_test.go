package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/require"
)

// fuzzModelLoader serves one static easy-pool model.
type fuzzModelLoader struct{}

func (fuzzModelLoader) ListModels(context.Context) ([]router.ModelInfo, error) {
	return []router.ModelInfo{{
		Name: "m-easy", Tier: "cheap", TierPool: []string{"easy"},
		Weight: 1, Enabled: true,
	}}, nil
}

// fuzzRedis satisfies the router's unexported redisClient seam structurally.
type fuzzRedis struct{}

func (fuzzRedis) Incr(ctx context.Context, _ string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx, "fuzz")
	cmd.SetVal(1)
	return cmd
}

func (fuzzRedis) Expire(ctx context.Context, _ string, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx, "fuzz")
	cmd.SetVal(true)
	return cmd
}

// fuzzQualitySource serves one canned snapshot or error.
type fuzzQualitySource struct {
	snap *router.QualitySnapshot
	err  error
}

func (s fuzzQualitySource) QualitySnapshot(context.Context, string) (*router.QualitySnapshot, error) {
	return s.snap, s.err
}

func fuzzRoutingGateway(quality bool) *gateway {
	gw := &gateway{log: discardLogger()}
	gw.tierRouter = router.NewTierRouter(fuzzModelLoader{}, fuzzRedis{})
	if quality {
		gw.qualitySource = fuzzQualitySource{}
	}
	return gw
}

func FuzzRoutingDecision(f *testing.F) {
	for id := 1; id <= 26; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-decision seeds: finite round-trip and a NaN-confidence body.
	f.Add([]byte{0x00, 0x01, 0x02, 0x00})
	f.Add([]byte{0x40, 0x01, 0x02, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 1 && data[0] >= 1 && data[0] <= 26 {
			fuzzRDCases[int(data[0])](t)
			return
		}
		rdGenerated(t, data)
	})
}

// rdGenDecision derives a decision from fuzzed bytes: source, class and
// affinity strings, a confidence/threshold pair where non-finite values are
// selected by bits (the marshal-failure path), and a preferred model echo.
func rdGenDecision(p []byte) routingDecision {
	sources := []string{decisionSourcePassthrough, decisionSourceTierRouter, decisionSourceQualityEval}
	d := routingDecision{
		Source:     sources[int(p[0])%len(sources)],
		Class:      fmt.Sprintf("c-%02x", p[1]),
		Affinity:   fmt.Sprintf("a-%02x", p[2]),
		Confidence: float64(p[4]) / 255,
		Threshold:  float64(p[1]) / 255,
	}
	if p[0]&0x10 != 0 { // preferred echo is a generated-only variant
		d.Preferred = fmt.Sprintf("p-%02x", p[3])
	}
	switch p[3] % 3 {
	case 1:
		d.Confidence = math.NaN()
	case 2:
		d.Confidence = math.Inf(1)
	}
	return d
}

// rdGenOracle holds the independent header invariants: a non-finite
// confidence must suppress the header entirely (marshal-failure path), a
// finite decision must round-trip field-exactly and deterministically.
func rdGenOracle(t *testing.T, d routingDecision, hdr string, hdrSet bool) {
	t.Helper()
	finite := !math.IsNaN(d.Confidence) && !math.IsInf(d.Confidence, 0)
	if !finite {
		if hdrSet {
			t.Fatalf("rd gen: non-finite confidence must suppress the header: %q", hdr)
		}
		return
	}
	if !hdrSet || !json.Valid([]byte(hdr)) {
		t.Fatalf("rd gen: finite decision must set a JSON header: %q", hdr)
	}
	want := map[string]any{"source": d.Source, "class": d.Class, "affinity": d.Affinity}
	if d.Preferred != "" {
		want["preferred"] = d.Preferred
	}
	if d.Threshold != 0 {
		want["threshold"] = d.Threshold
	}
	if d.Confidence != 0 {
		want["confidence"] = d.Confidence
	}
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(hdr), &got))
	require.Equal(t, want, got)
}

// fuzzRoutingGenerated exercises decision serialization with generated
// fields and tier selection determinism with generated session/model
// inputs against the canned router fixtures.
func rdGenerated(t *testing.T, data []byte) {
	t.Helper()
	var p [5]byte
	copy(p[:], data)
	d := rdGenDecision(p[:])
	w := httptest.NewRecorder()
	d.set(w)
	hdr, hdrSet := w.Header()[decisionHeaderKey]
	rdGenOracle(t, d, strings.Join(hdr, ""), hdrSet)

	w2 := httptest.NewRecorder()
	d.set(w2)
	if strings.Join(hdr, "") != strings.Join(w2.Header()[decisionHeaderKey], "") {
		t.Fatal("rd gen: decision header not deterministic")
	}

	gw := fuzzRoutingGateway(true)
	ctx := context.Background()
	preferred := fmt.Sprintf("pref-%02x", p[0])
	session := fmt.Sprintf("sess-%02x%02x", p[1], p[2])
	for range 2 {
		model, quality, canary, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", preferred, session, routingModeQuality)
		require.NoError(t, err)
		require.Equal(t, "m-easy", model.Name)
		require.Equal(t, router.QualityOutcome{FallbackReason: "no_snapshot"}, quality)
		require.Equal(t, router.CanaryDecision{}, canary)
	}
}

var fuzzRDCases = map[int]func(*testing.T){
	1:  fuzzRD01,
	2:  fuzzRD02,
	3:  fuzzRD03,
	4:  fuzzRD04,
	5:  fuzzRD05,
	6:  fuzzRD06,
	7:  fuzzRD07,
	8:  fuzzRD08,
	9:  fuzzRD09,
	10: fuzzRD10,
	11: fuzzRD11,
	12: fuzzRD12,
	13: fuzzRD13,
	14: fuzzRD14,
	15: fuzzRD15,
	16: fuzzRD16,
	17: fuzzRD17,
	18: fuzzRD18,
	19: fuzzRD19,
	20: fuzzRD20,
	21: fuzzRD21,
	22: fuzzRD22,
	23: fuzzRD23,
	24: fuzzRD24,
	25: fuzzRD25,
	26: fuzzRD26,
}

func fuzzRD01(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	(routingDecision{Source: decisionSourcePassthrough}).set(w)
	got := w.Header().Get(decisionHeaderKey)
	if got != `{"source":"passthrough"}` {
		t.Fatalf("RD-01: header %q", got)
	}
}

func fuzzRD02(t *testing.T) {
	t.Helper()

	w := httptest.NewRecorder()
	(routingDecision{Source: decisionSourcePassthrough, Confidence: math.NaN()}).set(w)
	if _, ok := w.Header()[decisionHeaderKey]; ok {
		t.Fatal("RD-02: header must not be set on marshal error")
	}
}

func fuzzRD03(t *testing.T) {
	t.Helper()

	cc := &chatContext{}
	cc.stampCanary(router.CanaryDecision{})
	if cc.dec != (routingDecision{}) || cc.canary.Active() {
		t.Fatalf("RD-03: decision mutated: %+v", cc.dec)
	}
}

func fuzzRD04(t *testing.T) {
	t.Helper()

	cc := &chatContext{}
	cc.stampCanary(router.CanaryDecision{RolloutID: "ro1", Version: 2, Arm: "canary", Percent: 10})
	if cc.dec.Arm != "canary" || cc.dec.RolloutID != "ro1" || cc.dec.RolloutVersion != 2 || cc.dec.CanaryPercent != 10 {
		t.Fatalf("RD-04: stamp wrong: %+v", cc.dec)
	}
}

func fuzzRD05(t *testing.T) {
	t.Helper()

	if decisionSourceCacheHit("semantic") != decisionSourceCacheSemantic ||
		decisionSourceCacheHit("exact") != decisionSourceCacheExact ||
		decisionSourceCacheHit("other") != decisionSourceCacheExact {
		t.Fatal("RD-05: cache source mapping wrong")
	}
}

func fuzzRD06(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := fuzzRoutingGateway(false)
	m, qo, dec, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", "", "sess1", "")
	if err != nil || m.Name != "m-easy" || qo != (router.QualityOutcome{}) || dec.Active() {
		t.Fatalf("RD-06: %v %+v %+v %v", m, qo, dec, err)
	}
}

func fuzzRD07(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := fuzzRoutingGateway(true)
	gw.qualitySource = fuzzQualitySource{err: router.ErrQualityUnavailable}
	m, qo, _, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", "", "sess1", routingModeQuality)
	if err != nil || m.Name != "m-easy" || qo.FallbackReason != router.QualityFallbackSourceUnavailable || qo.Used {
		t.Fatalf("RD-07: %+v %+v %v", m, qo, err)
	}
}

func fuzzRD08(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := fuzzRoutingGateway(true)
	m, qo, _, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", "", "sess1", routingModeQuality)
	if err != nil || m.Name != "m-easy" || qo.FallbackReason != router.QualityFallbackNoSnapshot || qo.Used {
		t.Fatalf("RD-08: %+v %+v %v", m, qo, err)
	}
}

func fuzzRD09(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := fuzzRoutingGateway(true)
	gw.qualitySource = fuzzQualitySource{snap: &router.QualitySnapshot{
		Version: "v8", CreatedAt: time.Now().Add(-40 * 24 * time.Hour)}}
	m, qo, _, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", "", "sess1", routingModeQuality)
	if err != nil || m.Name != "m-easy" || qo.FallbackReason != router.QualityFallbackStale ||
		qo.Version != "v8" || qo.Used {
		t.Fatalf("RD-09: %+v %+v %v", m, qo, err)
	}
}

func fuzzRD10(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := fuzzRoutingGateway(true)
	gw.qualitySource = fuzzQualitySource{snap: &router.QualitySnapshot{
		Version: "v9", CreatedAt: time.Now(),
		Overall: map[string]router.QualityScore{
			"m-easy": {Score: 0.9, Samples: 50}}}}
	m, qo, dec, err := gw.selectTierModel(ctx, classifier.ClassEasy, "org1", "", "sess1", routingModeQuality)
	if err != nil || m.Name != "m-easy" || !qo.Used || qo.Version != "v9" || dec.Active() {
		t.Fatalf("RD-10: %+v %+v %+v %v", m, qo, dec, err)
	}
}

func fuzzRD11(t *testing.T) {
	t.Helper()

	dec := &routingDecision{Source: decisionSourceTierRouter}
	applyQualityOutcome(dec, router.QualityOutcome{Used: true, Version: "v9"})
	if dec.Source != decisionSourceQualityEval || dec.QualityVersion != "v9" || dec.Reason != "" {
		t.Fatalf("RD-11: %+v", dec)
	}
}

func fuzzRD12(t *testing.T) {
	t.Helper()

	dec := &routingDecision{Source: decisionSourceTierRouter}
	applyQualityOutcome(dec, router.QualityOutcome{FallbackReason: "stale_snapshot", Version: "v8"})
	if dec.Reason != "quality_fallback:stale_snapshot" || dec.Source != decisionSourceTierRouter {
		t.Fatalf("RD-12: %+v", dec)
	}
	untouched := &routingDecision{Source: decisionSourcePassthrough}
	applyQualityOutcome(untouched, router.QualityOutcome{})
	if *untouched != (routingDecision{Source: decisionSourcePassthrough}) {
		t.Fatalf("RD-12: zero outcome must not mutate: %+v", untouched)
	}
}

func fuzzRD13(t *testing.T) {
	t.Helper()

	pe := capabilityPolicy(&provider.CapabilityError{Provider: "vertex",
		Capability: "streaming", Model: "gemini-x", Detail: "vertex does not support streaming for gemini-x"})
	if pe.Status != http.StatusBadRequest || pe.ErrType != "invalid_request_error" ||
		pe.ErrCode != "capability_not_supported" ||
		!strings.Contains(pe.Message, "vertex does not support streaming") {
		t.Fatalf("RD-13: %+v", pe)
	}
}

func fuzzRD14(t *testing.T) {
	t.Helper()

	if got := injectReasoningEffort([]byte(`{"model":"m"}`), ""); string(got) != `{"model":"m"}` {
		t.Fatalf("RD-14: empty effort must not patch: %s", got)
	}
	if got := injectReasoningEffort(nil, "low"); got != nil {
		t.Fatalf("RD-14: empty body must return as-is: %s", got)
	}
	if got := injectReasoningEffort([]byte("not json"), "low"); string(got) != "not json" {
		t.Fatalf("RD-14: bad json must pass through: %s", got)
	}
	if got := injectReasoningEffort([]byte("null"), "low"); string(got) != "null" {
		t.Fatalf("RD-14: json null must pass through byte-identical: %s", got)
	}
}

func fuzzRD15(t *testing.T) {
	t.Helper()

	in := []byte(`{"model":"m","metadata":{"big":9007199254740993},"temperature":0.5}`)
	got := string(injectReasoningEffort(in, "high"))
	if !strings.Contains(got, `"reasoning_effort":"high"`) ||
		!strings.Contains(got, "9007199254740993") ||
		!strings.Contains(got, `"temperature":0.5`) {
		t.Fatalf("RD-15: patched body wrong: %s", got)
	}
}

func fuzzRD16(t *testing.T) {
	t.Helper()

	gw := &gateway{cfg: config.Gateway{EffortRoutingEnabled: true},
		effortModels: []string{"glm-5.3", ""}}
	if got := gw.effortForCandidate(resolver.ModelInfo{ModelName: "GLM-5.3-Flash", Provider: "zai-coding"}, classifier.ClassEasy); got != "low" {
		t.Fatalf("RD-16: fragment match: %q", got)
	}
	if got := gw.effortForCandidate(resolver.ModelInfo{ModelName: "glm-5.3", Provider: "anthropic"}, classifier.ClassEasy); got != "" {
		t.Fatalf("RD-16: anthropic excluded: %q", got)
	}
	if got := gw.effortForCandidate(resolver.ModelInfo{ModelName: "gpt-9"}, classifier.ClassEasy); got != "" {
		t.Fatalf("RD-16: no fragment match: %q", got)
	}
	if got := gw.effortForCandidate(resolver.ModelInfo{ModelName: "glm-5.3"}, classifier.Class("unknown")); got != "" {
		t.Fatalf("RD-16: unknown class: %q", got)
	}
	off := &gateway{cfg: config.Gateway{EffortRoutingEnabled: false}, effortModels: []string{"glm-5.3"}}
	if got := off.effortForCandidate(resolver.ModelInfo{ModelName: "glm-5.3"}, classifier.ClassEasy); got != "" {
		t.Fatalf("RD-16: disabled: %q", got)
	}
}

func fuzzRD17(t *testing.T) {
	t.Helper()

	gw := &gateway{cfg: config.Gateway{EffortRoutingEnabled: true}, effortModels: []string{"o3"}}
	same := []byte(`{"model":"o3-mini","messages":[]}`)
	if got := gw.maybeInjectEffort(same, resolver.ModelInfo{ModelName: "o3-mini"}, classifier.ClassHard); !strings.Contains(string(got), `"reasoning_effort":"high"`) {
		t.Fatalf("RD-17: must inject: %s", got)
	}
	other := []byte(`{"model":"gpt-x"}`)
	if got := gw.maybeInjectEffort(other, resolver.ModelInfo{ModelName: "gpt-x"}, classifier.ClassEasy); string(got) != `{"model":"gpt-x"}` {
		t.Fatalf("RD-17: no-match must be identity: %s", got)
	}
}

func fuzzRD18(t *testing.T) {
	t.Helper()

	def := (&gateway{}).zaiCodingEndpoint()
	if def == "" || !strings.HasPrefix(def, "https://") {
		t.Fatalf("RD-18: default endpoint %q", def)
	}
	if got := (&gateway{cfg: config.Gateway{ZAICodingBaseURL: "https://zai.example"}}).zaiCodingEndpoint(); got != "https://zai.example" {
		t.Fatalf("RD-18: override %q", got)
	}
}

func fuzzRD19(t *testing.T) {
	t.Helper()

	gw := &gateway{cfg: config.Gateway{Provider: "https://default.example/v1"}}
	if got := gw.upstreamURL(resolver.ModelInfo{Provider: zaiCodingProvider}); got != provider.ZAICodingEndpoint("") {
		t.Fatalf("RD-19: zai arm %q", got)
	}
	if got := gw.upstreamURL(resolver.ModelInfo{Provider: "openai", UpstreamURL: "https://custom.example"}); got != "https://custom.example" {
		t.Fatalf("RD-19: per-model arm %q", got)
	}
	if got := gw.upstreamURL(resolver.ModelInfo{Provider: "openai"}); got != "https://default.example/v1" {
		t.Fatalf("RD-19: fallback arm %q", got)
	}
}

// RD-20 zai coding gate arms
func fuzzRD20(t *testing.T) {
	t.Helper()

	fuzzRD20GateArms(t)
	gr, blocked := zaiCodingViolation(true, "glm-5.3", resolver.ModelInfo{Provider: zaiCodingProvider})
	if blocked || gr.Outcome != gateAllowed {
		t.Fatalf("RD-20: allowed model: %+v", gr)
	}
	gr, blocked = zaiCodingViolation(true, "gpt-9", resolver.ModelInfo{Provider: zaiCodingProvider, ModelName: "gpt-9"})
	if !blocked || gr.Status != http.StatusBadRequest || gr.ErrCode != "unsupported_feature" {
		t.Fatalf("RD-20: disallowed model: %+v", gr)
	}
}

func fuzzRD20GateArms(t *testing.T) {
	t.Helper()

	if gr, blocked := zaiCodingViolation(true, "glm-4.7", resolver.ModelInfo{Provider: "openai"}); blocked || gr.Outcome != gateAllowed {
		t.Fatalf("RD-20: non-zai must be allowed: %+v", gr)
	}
	gr, blocked := zaiCodingViolation(false, "glm-5.3", resolver.ModelInfo{Provider: zaiCodingProvider})
	if !blocked || gr.Status != http.StatusForbidden || gr.ErrCode != "provider_not_authorized" {
		t.Fatalf("RD-20: disabled plan: %+v", gr)
	}
}

func fuzzRD21(t *testing.T) {
	t.Helper()

	gw := &gateway{}
	status, errType, code, msg := gw.mapProviderUpstream(zaiCodingProvider, 401, nil)
	if status != http.StatusForbidden || errType != "permission_denied_error" || code != "provider_not_authorized" ||
		!strings.Contains(msg, "not authorized") {
		t.Fatalf("RD-21: %d %s %s %s", status, errType, code, msg)
	}
}

func fuzzRD22(t *testing.T) {
	t.Helper()

	gw := &gateway{}
	status, _, code, msg := gw.mapProviderUpstream(zaiCodingProvider, 429, nil)
	if status != http.StatusTooManyRequests || code != "quota_exhausted" || !strings.Contains(msg, "quota") {
		t.Fatalf("RD-22: %d %s %s", status, code, msg)
	}
}

func fuzzRD23(t *testing.T) {
	t.Helper()

	gw := &gateway{}
	status, errType, code, msg := gw.mapProviderUpstream(zaiCodingProvider, 500, nil)
	if status != http.StatusBadGateway || errType != "api_error" || code != "" || msg != "upstream provider unavailable" {
		t.Fatalf("RD-23: %d %s %s %s", status, errType, code, msg)
	}
}

func fuzzRD24(t *testing.T) {
	t.Helper()

	gw := &gateway{}
	status, errType, _, _ := gw.mapProviderUpstream("openai", 0, context.DeadlineExceeded)
	if status != http.StatusGatewayTimeout || errType != "api_error" {
		t.Fatalf("RD-24: %d %s", status, errType)
	}
}

func fuzzRD25(t *testing.T) {
	t.Helper()

	gw := &gateway{}
	status, errType, _, _ := gw.mapProviderUpstream("openai", 429, context.DeadlineExceeded)
	if status != http.StatusTooManyRequests || errType != "rate_limit_exceeded" {
		t.Fatalf("RD-25: %d %s", status, errType)
	}
}

func fuzzRD26(t *testing.T) {
	t.Helper()

	if got := allowedUpstreamsForGateway(nil, false, "https://zai", ""); got != nil {
		t.Fatalf("RD-26: empty+empty must be nil: %v", got)
	}
	if got := allowedUpstreamsForGateway(nil, false, "https://zai", "https://p.example"); len(got) != 1 || got[0] != "https://p.example" {
		t.Fatalf("RD-26: provider default: %v", got)
	}
	if got := allowedUpstreamsForGateway([]string{"https://a"}, false, "https://zai", "https://p.example"); len(got) != 1 {
		t.Fatalf("RD-26: list without zai: %v", got)
	}
	if got := allowedUpstreamsForGateway([]string{"https://a"}, true, "https://zai", "https://p.example"); len(got) != 2 || got[0] != "https://a" || got[1] != "https://zai" {
		t.Fatalf("RD-26: list with zai: %v", got)
	}
}
