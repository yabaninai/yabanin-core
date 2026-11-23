package cli

// G2 coverage recovery (TEST-ONLY): independent behavioral and fault-injection
// tests for the zero-coverage critical blocks identified by the coverage
// distillation in pkg/gateway/chat.go, pkg/gateway/events.go and
// pkg/gateway/sessionkeys_api.go. Every test drives the real production
// function through its documented failure mode and asserts the externally
// visible contract (HTTP envelope, event/log side effects, store calls) —
// never the internal branch boolean alone. Reuses the same-package fakes
// (fakeInvocationStore, fuzzDeadRedis) read-only; all new helpers carry the
// g2 prefix.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/evalgate"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/openai"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// ---------------------------------------------------------------------------
// g2 helpers
// ---------------------------------------------------------------------------

// g2DiscardLogger drops records without the default handler's stderr noise.
func g2DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// g2LogRecord is one captured record; g2LogHandler is a thread-safe
// recording slog.Handler (Debug level and up) used to assert log side
// effects of failure paths.
type g2LogRecord struct {
	Level slog.Level
	Msg   string
}

type g2LogHandler struct {
	mu      sync.Mutex
	records []g2LogRecord
}

func (h *g2LogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *g2LogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, g2LogRecord{Level: r.Level, Msg: r.Message})
	return nil
}

func (h *g2LogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *g2LogHandler) WithGroup(string) slog.Handler      { return h }

func (h *g2LogHandler) find(level slog.Level, msgPart string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range h.records {
		if rec.Level == level && strings.Contains(rec.Msg, msgPart) {
			return true
		}
	}
	return false
}

// g2ErrReader always fails: request bodies built on it exercise the read
// guard of readChatRequest.
type g2ErrReader struct{}

func (g2ErrReader) Read([]byte) (int, error) { return 0, errors.New("g2 synthetic body read failure") }

// g2FailWriter accepts headers but fails every body Write: it exercises the
// client-write failure branches while still allowing header assertions.
type g2FailWriter struct {
	header http.Header
}

func newG2FailWriter() *g2FailWriter { return &g2FailWriter{header: http.Header{}} }

func (w *g2FailWriter) Header() http.Header       { return w.header }
func (w *g2FailWriter) Write([]byte) (int, error) { return 0, errors.New("g2 synthetic write failure") }
func (w *g2FailWriter) WriteHeader(int)           {}

// g2RecordingCache implements responseCache and records Write calls (even
// the failing ones) for post-hoc assertions.
type g2CacheWrite struct {
	ri        cache.RouteIdentity
	body      []byte
	response  []byte
	tokensIn  int
	tokensOut int
}

type g2RecordingCache struct {
	mu     sync.Mutex
	writes []g2CacheWrite
	err    error
}

func (c *g2RecordingCache) LookupWithResult(context.Context, cache.RouteIdentity, []byte) (*cache.CacheHit, error) {
	return nil, nil
}

func (c *g2RecordingCache) Write(_ context.Context, ri cache.RouteIdentity, body, response json.RawMessage, tokensIn, tokensOut int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, g2CacheWrite{ri: ri, body: body, response: response, tokensIn: tokensIn, tokensOut: tokensOut})
	return c.err
}

func (c *g2RecordingCache) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *g2RecordingCache) lastWrite() g2CacheWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes[len(c.writes)-1]
}

// g2FailingVerdictStore implements verdictStore and records the verdict
// insert attempt before returning the scripted error.
type g2VerdictCall struct {
	orgID, requestID, prompt, cheapModel, premiumModel string
	verdict    *evalgate.Verdict
	confidence float64
}

type g2FailingVerdictStore struct {
	mu    sync.Mutex
	calls []g2VerdictCall
	err   error
}

func (s *g2FailingVerdictStore) InsertVerdict(_ context.Context, orgID, requestID, prompt, cheapModel, premiumModel string, v *evalgate.Verdict, rawConfidence float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, g2VerdictCall{orgID: orgID, requestID: requestID, prompt: prompt, cheapModel: cheapModel, premiumModel: premiumModel, verdict: v, confidence: rawConfidence})
	return s.err
}

func (s *g2FailingVerdictStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *g2FailingVerdictStore) lastCall() g2VerdictCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

// g2RecordingResolver implements modelResolver: every resolution is
// announced on the names channel (buffered, non-blocking sends keep the
// detached evalgate goroutine lock-free) and answered with the scripted
// info/error pair.
type g2RecordingResolver struct {
	names chan string
	err   error
	info  resolver.ModelInfo
}

func (r *g2RecordingResolver) Resolve(_ context.Context, modelName string) resolver.ModelInfo {
	r.record(modelName)
	return r.info
}

func (r *g2RecordingResolver) ResolveChecked(_ context.Context, modelName string) (resolver.ModelInfo, error) {
	r.record(modelName)
	if r.err != nil {
		return resolver.ModelInfo{}, r.err
	}
	return r.info, nil
}

func (r *g2RecordingResolver) record(name string) {
	if r.names == nil {
		return
	}
	select {
	case r.names <- name:
	default:
	}
}

// g2EnforceLoader forces enforce mode for every org (no DB).
func g2EnforceLoader(context.Context, string) (budget.OrgSettings, error) {
	return budget.OrgSettings{Mode: budget.ModeEnforce}, nil
}

// g2ChatContext builds the minimal chatContext the finished-path functions
// accept: recorder-backed writer, non-nil request, discard logger and the
// trusted identity fields.
func g2ChatContext(w http.ResponseWriter, r *http.Request) *chatContext {
	return &chatContext{
		w:              w,
		r:              r,
		l:              g2DiscardLogger(),
		reqID:          "req-g2",
		orgID:          "org-g2",
		apiKeyID:       "1",
		sessionID:      "sess-g2",
		requestedModel: "gpt-4o-mini",
		model:          "gpt-4o-mini",
		req: openai.ChatCompletionRequest{
			Model:    "gpt-4o-mini",
			Messages: []openai.ChatMessage{{Role: "user", Content: "g2 test prompt"}},
		},
	}
}

const g2ValidCompletion = `{"id":"g2c","object":"chat.completion","choices":[{"index":0,` +
	`"message":{"role":"assistant","content":"g2 cached answer"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`

const g2ValidRequestBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"g2 test prompt"}]}`

// ---------------------------------------------------------------------------
// chat.go: readChatRequest body guard (block 266)
// ---------------------------------------------------------------------------

func TestGWCovG2_ReadChatRequestBodyReadError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	r.Body = io.NopCloser(g2ErrReader{})

	raw, req, ok := readChatRequest(w, r)

	if ok {
		t.Fatalf("readChatRequest admitted a failing body reader")
	}
	if raw != nil {
		t.Errorf("raw body must be nil on read failure, got %q", raw)
	}
	if req.Model != "" {
		t.Errorf("typed request must be zero on read failure, got model %q", req.Model)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "request body too large or malformed") {
		t.Errorf("body %q must explain the malformed-body refusal", body)
	}
}

// ---------------------------------------------------------------------------
// chat.go: applyChatVerticalResult patch failures (blocks 341, 347)
// ---------------------------------------------------------------------------

func TestGWCovG2_ApplyChatVerticalResultPatchFailures(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		samePrompt  bool
		wantOK      bool
		wantBodySub string
	}{
		{
			name:        "patch failure: guarded body has no messages array",
			body:        `{"model":"gpt-4o-mini"}`,
			wantOK:      false,
			wantBodySub: "failed to apply vertical transform to request body",
		},
		{
			name:        "patched body no longer decodes as a chat completion request",
			body:        `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"old"}],"max_tokens":"bad"}`,
			wantOK:      false,
			wantBodySub: "malformed JSON",
		},
		{
			name:       "control: identical prompt passes through untouched",
			body:       g2ValidRequestBody,
			samePrompt: true,
			wantOK:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tt.body))
			cc := g2ChatContext(w, r)
			cc.body = []byte(tt.body)

			transformed := verticals.Request{Prompt: "g2 transformed prompt", Metadata: map[string]string{"lang": "en"}}
			if tt.samePrompt {
				transformed.Prompt = "g2 test prompt" // equal to the typed prompt → early true
			}

			ok := applyChatVerticalResult(w, cc, transformed)
			if ok != tt.wantOK {
				t.Fatalf("applyChatVerticalResult = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantBodySub != "" {
				if w.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", w.Code)
				}
				if body := w.Body.String(); !strings.Contains(body, tt.wantBodySub) {
					t.Errorf("body %q must contain %q", body, tt.wantBodySub)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// chat.go: prepareChatDispatch refuses an unpriced model under enforce (block 156)
// ---------------------------------------------------------------------------

func TestGWCovG2_PrepareChatDispatchRefusesUnpricedModel(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	// Enforced admission with NO rate source: every wallet bound is unpriced
	// (I3), so the plan itself must refuse the dispatch before any cache
	// lookup or provider call.
	gw.admission = budget.NewAdmission(nil, budget.ScopedRateSource{}, gw.log, "rep-g2",
		budget.ModeEnforce, g2EnforceLoader, budget.AdmissionConfig{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)
	cc.info = resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}

	ctx, gate, ok := gw.prepareChatDispatch(context.Background(), w, r, cc)

	if ok {
		t.Fatalf("prepareChatDispatch must refuse an unpriced enforce-mode model")
	}
	if ctx != nil || gate != nil {
		t.Errorf("refused dispatch must return nil ctx/gate, got %v/%v", ctx, gate)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "model_unpriced") {
		t.Errorf("body %q must carry the model_unpriced code", body)
	}
}

// ---------------------------------------------------------------------------
// chat.go: confirmChatDispatch when the reservation store is unreachable (block 163)
// ---------------------------------------------------------------------------

func TestGWCovG2_ConfirmChatDispatchReservationStoreOutage(t *testing.T) {
	// Lazy pool to a closed loopback port: every acquire fails fast with
	// ECONNREFUSED, never a hang (connect_timeout pins the dial).
	pool, err := pgxpool.New(context.Background(),
		"postgres://g2:g2@127.0.0.1:1/g2?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("bogus pool: %v", err)
	}
	t.Cleanup(pool.Close)

	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.admission = budget.NewAdmission(
		budget.NewReservationStore(pool, gw.log),
		budget.ScopedRateSource{},
		gw.log,
		"rep-g2",
		budget.ModeEnforce,
		g2EnforceLoader,
		budget.AdmissionConfig{},
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)
	cc.info = resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}

	// Hand-built enforce plan with a bound far above the fresh admission's
	// local escrow (0): Reserve must fall through to the durable grant,
	// whose store Begin fails → fail-closed denial.
	plan := &budget.Plan{
		Mode:  budget.ModeEnforce,
		OrgID: cc.orgID,
		Scopes: []budget.ScopeBound{{
			Scope: budget.ScopeWallet,
			Key:   cc.orgID,
			Bound: money.MicroUSD(1) << 50,
		}},
	}
	gate := &reservationGate{gw: gw, w: w, plan: plan, endpoint: "chat.completions"}

	if ok := gw.confirmChatDispatch(context.Background(), cc, gate); ok {
		t.Fatalf("confirmChatDispatch must refuse when the reservation store is unreachable")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "reservation admission temporarily unavailable") {
		t.Errorf("body %q must report the reservation store outage", body)
	}
}

// ---------------------------------------------------------------------------
// chat.go: tryChatModel pool init failure (block 952)
// ---------------------------------------------------------------------------

func TestGWCovG2_TryChatModelUpstreamClientFailure(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.pool = upstream.NewPool(upstream.Options{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)

	mi := resolver.ModelInfo{
		ModelName:     "gpt-x",
		Provider:      "no-such-provider-x",
		UpstreamAPIKey: "sk-g2",
		Enabled:       true,
	}

	code, err := gw.tryChatModel(context.Background(), cc, mi, &chatExecution{}, new(atomic.Int32))
	if err == nil {
		t.Fatalf("tryChatModel must fail when the upstream client cannot be constructed")
	}
	if code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
	if msg := err.Error(); !strings.Contains(msg, "upstream client for no-such-provider-x") {
		t.Errorf("error %q must name the unconstructable provider client", msg)
	}
}

// ---------------------------------------------------------------------------
// chat.go: finishChatHop upstream error synthesis (block 1064)
// ---------------------------------------------------------------------------

func TestGWCovG2_FinishChatHopUpstreamError(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	ex := &chatExecution{}

	code, err := gw.finishChatHop("http://upstream-g2", retry.Result{StatusCode: http.StatusBadGateway}, orgCredentialUse{}, ex)
	if err == nil {
		t.Fatalf("a 5xx hop without a typed error must synthesize one")
	}
	if code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
	if msg := err.Error(); msg != "upstream error 502" {
		t.Errorf("error = %q, want the synthesized upstream error 502", msg)
	}

	// Control: a sub-500 hop with no error is a success and captures the body.
	ex2 := &chatExecution{}
	res2 := retry.Result{StatusCode: http.StatusOK, Body: []byte(`{"ok":true}`), Headers: http.Header{"X-Up": []string{"1"}}}
	code2, err2 := gw.finishChatHop("http://upstream-g2", res2, orgCredentialUse{}, ex2)
	if err2 != nil || code2 != http.StatusOK {
		t.Fatalf("success control: (%d, %v), want (200, nil)", code2, err2)
	}
	if !bytes.Equal(ex2.body, res2.Body) || ex2.headers.Get("X-Up") != "1" {
		t.Errorf("success control must capture body and headers, got body=%q headers=%v", ex2.body, ex2.headers)
	}
}

// ---------------------------------------------------------------------------
// chat.go: rejectChatAttempt unknown-outcome envelope (block 1112)
// ---------------------------------------------------------------------------

func TestGWCovG2_RejectChatAttemptUnknownOutcome(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)

	lastErr := unknownOutcomeError(errors.New("g2 upstream connection lost"))

	// lastCode 0 (no upstream status known) → the envelope must upgrade to 502.
	handled := gw.rejectChatAttempt(context.Background(), cc, lastErr, 0, 1, 0)
	if !handled {
		t.Fatalf("rejectChatAttempt must terminal-handle an unknown outcome")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "upstream outcome unknown; request was not retried") {
		t.Errorf("body %q must state that the outcome is unknown and untried", body)
	}
}

// ---------------------------------------------------------------------------
// chat.go: validateChatCacheReplay refuses malformed cached tool_calls (block 1218)
// ---------------------------------------------------------------------------

func TestGWCovG2_ValidateChatCacheReplayBadToolCalls(t *testing.T) {
	l := g2DiscardLogger()

	badToolCalls := `{"id":"g2t","choices":[{"index":0,` +
		`"message":{"role":"assistant","content":"calling","tool_calls":[1]},` +
		`"finish_reason":"tool_calls"}]}`
	validDoc := g2ValidCompletion

	tests := []struct {
		name   string
		doc    string
		stream bool
		wantOK bool
	}{
		{name: "stream: tool_calls is not an array of objects", doc: badToolCalls, stream: true, wantOK: false},
		{name: "stream: control doc replays", doc: validDoc, stream: true, wantOK: true},
		{name: "json: control doc usable without replay frames", doc: validDoc, stream: false, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit := &cache.CacheHit{Data: []byte(tt.doc), ModelUsed: "gpt-4o-mini", SourceType: "exact"}
			frames, ok := validateChatCacheReplay(l, "org-g2", hit, tt.stream)
			if ok != tt.wantOK {
				t.Fatalf("validateChatCacheReplay usable = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK && tt.stream && len(frames) == 0 {
				t.Errorf("a usable stream hit must produce replay frames")
			}
			if !tt.wantOK && frames != nil {
				t.Errorf("an unusable hit must not produce frames, got %d", len(frames))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// chat.go: finishChatCacheHit effort attribution + write failure (blocks 1294, 1320)
// ---------------------------------------------------------------------------

func TestGWCovG2_FinishChatCacheHitEffortAttribution(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.cfg.EffortRoutingEnabled = true
	gw.effortModels = []string{"gpt-4o"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)
	cc.info = resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}
	cc.classifierClass = string(classifier.ClassEasy)

	hit := &cache.CacheHit{Data: []byte(g2ValidCompletion), ModelUsed: "gpt-4o-mini", SourceType: "exact"}

	gw.finishChatCacheHit(context.Background(), cc, hit, nil)

	if cc.dec.Effort != "low" {
		t.Errorf("easy class on an effort-eligible model must stamp effort %q, got %q", "low", cc.dec.Effort)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Cache"); got != "EXACT" {
		t.Errorf("X-Cache = %q, want EXACT (upper-cased source type)", got)
	}
	if !bytes.Equal(w.Body.Bytes(), hit.Data) {
		t.Errorf("body must be the cached payload verbatim, got %q", w.Body.String())
	}
}

func TestGWCovG2_FinishChatCacheHitWriteFailure(t *testing.T) {
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	lh := &g2LogHandler{}

	w := newG2FailWriter()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.l = slog.New(lh)
	cc.body = []byte(g2ValidRequestBody)
	cc.info = resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true}

	hit := &cache.CacheHit{Data: []byte(g2ValidCompletion), ModelUsed: "gpt-4o-mini", SourceType: "exact"}

	gw.finishChatCacheHit(context.Background(), cc, hit, nil)

	if !lh.find(slog.LevelError, "cache hit write failed") {
		t.Errorf("a failed cache-hit body write must log an error; captured records: %+v", lh.records)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("headers must still be applied before the failed write, Content-Type = %q", ct)
	}
}

// ---------------------------------------------------------------------------
// chat.go: chatUsageAdapter unknown provider fallback (block 1571)
// ---------------------------------------------------------------------------

func TestGWCovG2_ChatUsageAdapterUnknownProvider(t *testing.T) {
	lh := &g2LogHandler{}
	p := chatUsageAdapter(resolver.ModelInfo{Provider: "no-such-provider-x"}, slog.New(lh))

	if got := fmt.Sprintf("%T", p); got != "provider.OpenAI" {
		t.Errorf("unknown provider must degrade to the OpenAI usage parser, got %s", got)
	}
	if !lh.find(slog.LevelWarn, "usage accounting skipped: unknown provider") {
		t.Errorf("the fallback must be logged loudly; captured records: %+v", lh.records)
	}

	// Control: a known provider resolves its own adapter.
	known := chatUsageAdapter(resolver.ModelInfo{Provider: "anthropic"}, g2DiscardLogger())
	if got := fmt.Sprintf("%T", known); got == "provider.OpenAI" {
		t.Errorf("a known provider must not degrade to the OpenAI parser, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// chat.go: evalgateSample bounds and random draw (blocks 1634, 1639)
// ---------------------------------------------------------------------------

func TestGWCovG2_EvalgateSampleBounds(t *testing.T) {
	if evalgateSample(0) {
		t.Errorf("rate 0 must never sample")
	}
	if evalgateSample(-0.5) {
		t.Errorf("negative rate must never sample")
	}
	if !evalgateSample(1) {
		t.Errorf("rate 1 must always sample without consuming randomness")
	}
	if !evalgateSample(2) {
		t.Errorf("rates above 1 must always sample")
	}

	// Statistical control of the crypto/rand draw: 256 Bernoulli(0.5)
	// draws must land inside [64, 192] (~8 sigma). The source is
	// crypto/rand, so a failure means a broken sampler, not flakiness.
	const draws = 256
	hits := 0
	for i := 0; i < draws; i++ {
		if evalgateSample(0.5) {
			hits++
		}
	}
	if hits < 64 || hits > 192 {
		t.Errorf("evalgateSample(0.5) over %d draws hit %d times, outside [64, 192]", draws, hits)
	}
}

// ---------------------------------------------------------------------------
// chat.go: maybeEvalgateSample premium fallback + resolution failure (blocks 1683, 1712)
// ---------------------------------------------------------------------------

func TestGWCovG2_MaybeEvalgateSampleFallbackPremiumResolutionFailure(t *testing.T) {
	res := &g2RecordingResolver{
		names: make(chan string, 4),
		err:   errors.New("g2 premium model resolution failed"),
	}
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.cfg.EvalgateSampleRate = 1 // deterministic: every eligible request samples
	gw.res = res

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)
	cc.classifierClass = string(classifier.ClassMedium)
	cc.classifierConfidence = 0.5 // below the 0.7 gate

	resp := []byte(`{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"cheap answer"},"finish_reason":"stop"}]}`)
	ev := &eventpub.Event{}
	gw.maybeEvalgateSample(context.Background(), cc, "gpt-4o-mini", resp, ev)

	if !ev.EvalgateSampled {
		t.Fatalf("a medium/low-confidence request at rate 1 must be stamped EvalgateSampled")
	}

	// The detached judge must have attempted the tier-router-less fallback
	// premium model and stopped at the resolution failure (nothing sent).
	select {
	case name := <-res.names:
		if name != "gpt-4o" {
			t.Errorf("premium fallback model = %q, want gpt-4o (tier router unwired)", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the detached judge never attempted premium model resolution")
	}

	// Negative control: an easy-class request is never sampled.
	res2 := &g2RecordingResolver{names: make(chan string, 4), err: errors.New("unreachable")}
	gw2 := &gateway{}
	gw2.log = g2DiscardLogger()
	gw2.cfg.EvalgateSampleRate = 1
	gw2.res = res2
	cc2 := g2ChatContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody)))
	cc2.classifierClass = string(classifier.ClassEasy)
	ev2 := &eventpub.Event{}
	gw2.maybeEvalgateSample(context.Background(), cc2, "gpt-4o-mini", resp, ev2)
	if ev2.EvalgateSampled {
		t.Errorf("an easy-class request must not be evalgate-sampled")
	}
}

// ---------------------------------------------------------------------------
// chat.go: evalgateJudge verdict store failure (block 1756)
// ---------------------------------------------------------------------------

func TestGWCovG2_EvalgateJudgeVerdictStoreFailure(t *testing.T) {
	var premiumHits, judgeHits atomic.Int32
	premiumSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		premiumHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"p1","choices":[{"index":0,"message":{"role":"assistant","content":"premium answer"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(premiumSrv.Close)

	verdictJSON := `{"cheap_quality":0.4,"premium_quality":0.9,"should_upgrade":true,"reason":"g2 judge"}`
	judgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		judgeHits.Add(1)
		payload, merr := json.Marshal(map[string]interface{}{
			"id": "j1",
			"choices": []interface{}{map[string]interface{}{
				"index":         0,
				"message":       map[string]interface{}{"role": "assistant", "content": verdictJSON},
				"finish_reason": "stop",
			}},
		})
		if merr != nil {
			http.Error(w, merr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(judgeSrv.Close)

	store := &g2FailingVerdictStore{err: errors.New("g2 verdict insert failed")}

	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.res = &g2RecordingResolver{info: resolver.ModelInfo{
		ModelName:     "gpt-4o",
		Provider:      "openai",
		UpstreamURL:   premiumSrv.URL, // httptest loopback passes the SSRF gate
		UpstreamAPIKey: "sk-g2",
		Enabled:       true,
	}}
	gw.pool = upstream.NewPool(upstream.Options{})
	gw.invocations = &fakeInvocationStore{} // durable start/terminal succeed
	gw.judge = evalgate.NewJudge(judgeSrv.URL, g2DiscardLogger())
	gw.evalStore = store
	// Dead-redis publisher: the retention toggle lookup fails closed, so the
	// pre-mask judge prompt must NOT be persisted.
	gw.publisher = fuzzDeadRedis(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
	cc := g2ChatContext(w, r)
	cc.body = []byte(g2ValidRequestBody)

	// Direct synchronous call: the store failure is contained (Debug log)
	// and the verdict insert was fully attempted.
	gw.evalgateJudge(context.Background(), cc, candidateIdentity{OrgID: cc.orgID, APIKeyID: cc.apiKeyID},
		"g2 judge prompt", "cheap answer", "gpt-4o-mini", "gpt-4o", 0.5)

	if got := store.callCount(); got != 1 {
		t.Fatalf("verdict insert attempts = %d, want 1 (a store failure must still record the verdict)", got)
	}
	call := store.lastCall()
	if call.orgID != "org-g2" || call.requestID != "req-g2" {
		t.Errorf("verdict call attribution = %q/%q, want org-g2/req-g2", call.orgID, call.requestID)
	}
	if call.cheapModel != "gpt-4o-mini" || call.premiumModel != "gpt-4o" {
		t.Errorf("verdict pair = %q vs %q, want gpt-4o-mini vs gpt-4o", call.cheapModel, call.premiumModel)
	}
	if call.prompt != "" {
		t.Errorf("retention fail-closed must persist an empty prompt, got %q", call.prompt)
	}
	if call.confidence != 0.5 {
		t.Errorf("confidence = %v, want 0.5", call.confidence)
	}
	if call.verdict == nil || !call.verdict.ShouldUpgrade || call.verdict.PremiumQuality != 0.9 {
		t.Errorf("parsed verdict = %+v, want ShouldUpgrade=true PremiumQuality=0.9", call.verdict)
	}
	if got := premiumHits.Load(); got != 1 {
		t.Errorf("premium upstream hits = %d, want exactly 1", got)
	}
	if got := judgeHits.Load(); got != 1 {
		t.Errorf("judge evaluator hits = %d, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// chat.go: writeChatCacheAsync skip and failure (blocks 1781, 1785)
// ---------------------------------------------------------------------------

func TestGWCovG2_WriteChatCacheAsyncSkipAndFailure(t *testing.T) {
	ctx := context.Background()
	resp := []byte(g2ValidCompletion)

	t.Run("invalid provider token counts skip the write", func(t *testing.T) {
		rc := &g2RecordingCache{}
		gw := &gateway{}
		gw.log = g2DiscardLogger()
		gw.cache = rc

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
		cc := g2ChatContext(w, r)
		cc.body = []byte(g2ValidRequestBody)

		gw.writeChatCacheAsync(ctx, cc, resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai"}, "gpt-4o-mini", resp,
			provider.Usage{PromptTokens: -1, CompletionTokens: 5, Source: provider.UsageSourceProvider})

		if got := rc.writeCount(); got != 0 {
			t.Errorf("negative provider token counts must skip the cache write, got %d writes", got)
		}
	})

	t.Run("failing cache write is contained and recorded", func(t *testing.T) {
		rc := &g2RecordingCache{err: errors.New("g2 cache write boom")}
		lh := &g2LogHandler{}
		gw := &gateway{}
		gw.log = g2DiscardLogger()
		gw.cache = rc

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
		cc := g2ChatContext(w, r)
		cc.l = slog.New(lh)
		cc.body = []byte(g2ValidRequestBody)

		gw.writeChatCacheAsync(ctx, cc, resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai"}, "gpt-4o-mini", resp,
			provider.Usage{PromptTokens: 10, CompletionTokens: 5, Source: provider.UsageSourceProvider})

		if got := rc.writeCount(); got != 1 {
			t.Fatalf("cache write attempts = %d, want 1", got)
		}
		last := rc.lastWrite()
		if last.ri.OrgID != "org-g2" || last.ri.Model != "gpt-4o-mini" {
			t.Errorf("route identity = %s/%s, want org-g2/gpt-4o-mini", last.ri.OrgID, last.ri.Model)
		}
		if !bytes.Equal(last.body, cc.body) || !bytes.Equal(last.response, resp) {
			t.Errorf("write must carry the guarded request body and the governed response")
		}
		if last.tokensIn != 10 || last.tokensOut != 5 {
			t.Errorf("token counts = %d/%d, want 10/5", last.tokensIn, last.tokensOut)
		}
		if !lh.find(slog.LevelDebug, "chat cache write failed") {
			t.Errorf("a failing cache write must be logged; captured records: %+v", lh.records)
		}
	})
}

// ---------------------------------------------------------------------------
// chat.go: writeChatJSONClient client-write failure (block 1799)
// ---------------------------------------------------------------------------

func TestGWCovG2_WriteChatJSONClientWriteFailure(t *testing.T) {
	lh := &g2LogHandler{}
	resp := []byte(g2ValidCompletion)
	usage := provider.Usage{Source: provider.UsageSourceProvider, PromptTokens: 10, CompletionTokens: 5, CacheReadTokens: 7}

	w := newG2FailWriter()
	writeChatJSONClient(w, slog.New(lh), usage, resp, "gpt-4o-mini")

	if !lh.find(slog.LevelError, "write response failed") {
		t.Errorf("a failed client write must log an error; captured records: %+v", lh.records)
	}
	// Headers are applied before the body write even when it fails.
	if got := w.Header().Get(PromptCacheHeader); got != "hit" {
		t.Errorf("%s = %q, want hit (CacheReadTokens > 0, provider-reported)", PromptCacheHeader, got)
	}

	// Control: the success path answers the governed body with the
	// prompt-cache outcome header.
	rec := httptest.NewRecorder()
	writeChatJSONClient(rec, g2DiscardLogger(), usage, resp, "gpt-4o-mini")
	if rec.Header().Get(PromptCacheHeader) != "hit" || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("control headers = %v", rec.Header())
	}
	if !bytes.Equal(rec.Body.Bytes(), resp) {
		t.Errorf("control body must be the governed response verbatim, got %q", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// chat.go: finishPolicyDeniedJSON terminal accounting failure (block 1884)
// ---------------------------------------------------------------------------

func TestGWCovG2_FinishPolicyDeniedJSONAccountingFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("terminal facts failure withholds the response", func(t *testing.T) {
		store := &fakeInvocationStore{factsErr: errors.New("g2 terminal facts boom")}
		gw := &gateway{}
		gw.log = g2DiscardLogger()
		gw.invocations = store

		h := newInvocationIdentity("org-g2", "req-g2", "sess-g2", "1", "2", "gpt-4o-mini")
		if err := h.beginPaidDispatch(ctx, store, invocationKindForChat(false)); err != nil {
			t.Fatalf("admit invocation: %v", err)
		}
		gctx := withInvocationIdentity(ctx, h)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
		r.Header.Set("X-Session-Key-Id", "2")
		cc := g2ChatContext(w, r)
		cc.body = []byte(g2ValidRequestBody)
		cc.invocation = h

		gw.finishPolicyDeniedJSON(gctx, cc,
			resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true},
			provider.Usage{Source: provider.UsageSourceProvider, PromptTokens: 10, CompletionTokens: 5},
			provider.ExtendedUsage{EstimatedCostUSD: 0.01, PriceKnown: true},
			&chatExecution{},
			[]byte(`{"masked":true}`))

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 (accounting failure, not the 400 denial)", w.Code)
		}
		if got := w.Header().Get("X-Should-Retry"); got != "false" {
			t.Errorf("X-Should-Retry = %q, want false (a retry would double-bill)", got)
		}
		if body := w.Body.String(); !strings.Contains(body, accountingCommitFailedCode) {
			t.Errorf("body %q must carry the %s code", body, accountingCommitFailedCode)
		}
	})

	t.Run("control: committed facts answer the denial envelope", func(t *testing.T) {
		store := &fakeInvocationStore{}
		gw := &gateway{}
		gw.log = g2DiscardLogger()
		gw.invocations = store

		h := newInvocationIdentity("org-g2", "req-g2", "sess-g2", "1", "2", "gpt-4o-mini")
		if err := h.beginPaidDispatch(ctx, store, invocationKindForChat(false)); err != nil {
			t.Fatalf("admit invocation: %v", err)
		}
		gctx := withInvocationIdentity(ctx, h)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(g2ValidRequestBody))
		cc := g2ChatContext(w, r)
		cc.body = []byte(g2ValidRequestBody)
		cc.invocation = h

		gw.finishPolicyDeniedJSON(gctx, cc,
			resolver.ModelInfo{ModelName: "gpt-4o-mini", Provider: "openai", Enabled: true},
			provider.Usage{Source: provider.UsageSourceProvider, PromptTokens: 10, CompletionTokens: 5},
			provider.ExtendedUsage{EstimatedCostUSD: 0.01, PriceKnown: true},
			&chatExecution{},
			[]byte(`{"masked":true}`))

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
		if body := w.Body.String(); !strings.Contains(body, policyDenyErrorCode) || !strings.Contains(body, "response blocked by organization policy") {
			t.Errorf("body %q must be the policy-denial envelope", body)
		}
	})
}

// ---------------------------------------------------------------------------
// events.go: finishRequestLogged facts failure (block 559)
// ---------------------------------------------------------------------------

func TestGWCovG2_FinishRequestLoggedFactsFailure(t *testing.T) {
	store := &fakeInvocationStore{factsErr: errors.New("g2 terminal facts boom")}
	gw := &gateway{}
	gw.log = g2DiscardLogger()
	gw.invocations = store

	h := newInvocationIdentity("org-g2", "req-g2", "sess-g2", "1", "2", "gpt-4o-mini")
	if err := h.beginPaidDispatch(context.Background(), store, invocationKindForChat(false)); err != nil {
		t.Fatalf("admit invocation: %v", err)
	}
	ctx := withInvocationIdentity(context.Background(), h)

	lh := &g2LogHandler{}
	gw.finishRequestLogged(ctx, slog.New(lh), requestFinish{
		base: eventBase{
			EventType: "request.completed",
			RequestID: "req-g2",
			SessionID: "sess-g2",
			OrgID:     "org-g2",
			ModelUsed: "gpt-4o-mini",
		},
		noSettle: true, // cache-style end: no reservation to settle
	})

	if !lh.find(slog.LevelError, "terminal facts commit failed; event withheld from consumer") {
		t.Errorf("a facts-commit failure on the logged path must be reported loudly; captured records: %+v", lh.records)
	}
}

// ---------------------------------------------------------------------------
// events.go: publishAttempt against a dead publisher (block 167 vicinity)
// ---------------------------------------------------------------------------

// Due diligence for the retry-ladder cap: the published-ladder cap at
// events.go:167 (delay > maxDelay) is arithmetically unreachable — the
// ladder is baseDelay<<(attempt-1) with maxRetries=3, i.e. at most
// 200ms < maxDelay=300ms, and both constants are function-local. This test
// proves the full failing ladder itself completes against a dead
// publisher without hanging or panicking.
func TestGWCovG2_PublishAttemptDeadPublisherCompletes(t *testing.T) {
	ev := &eventpub.Event{
		EventType: "request.completed",
		RequestID: "req-g2",
		OrgID:     "org-g2",
		ModelUsed: "gpt-4o-mini",
	}
	publisher := fuzzDeadRedis(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		publishAttempt(context.Background(), publisher, g2DiscardLogger(), ev)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("publishAttempt did not complete against a dead publisher within 10s")
	}
}

// ---------------------------------------------------------------------------
// sessionkeys_api.go block 487 — intentionally no test.
//
// parseOwnUsageParams marshals a freshly built map[string]string filter.
// json.Marshal of a string-valued map cannot fail: encoding/json coerces
// invalid UTF-8 in strings to U+FFFD rather than erroring, and there is no
// seam (no custom Marshaler, no injected encoder) to force an error. The
// error branch is unreachable by construction; reported as UNCOVERABLE
// rather than papering over it with a fake assertion.
// ---------------------------------------------------------------------------
