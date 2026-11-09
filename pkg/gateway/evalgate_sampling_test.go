package cli

import (
	"context"
	"encoding/json"
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

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/evalgate"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// fakeVerdictStore records InsertVerdict calls for evalgate sampling tests.
// Every call also signals a channel (non-blocking), so tests can synchronize
// on the verdict instead of polling.
type fakeVerdictStore struct {
	mu       sync.Mutex
	verdicts []evalgate.Verdict
	calls    chan struct{}
}

func newFakeVerdictStore() *fakeVerdictStore {
	return &fakeVerdictStore{calls: make(chan struct{}, 8)}
}

func (f *fakeVerdictStore) InsertVerdict(_ context.Context, _, _, _, _, _ string, v *evalgate.Verdict, _ float64) error {
	f.mu.Lock()
	f.verdicts = append(f.verdicts, *v)
	f.mu.Unlock()
	select {
	case f.calls <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeVerdictStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.verdicts)
}

// waitForVerdicts waits (bounded) for n stored verdicts; the store signals
// every insert, so no polling or fixed sleeps are needed.
func (f *fakeVerdictStore) waitForVerdicts(t *testing.T, n int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for i := 0; i < n; i++ {
		select {
		case <-f.calls:
		case <-timer.C:
			t.Fatalf("only %d of %d expected verdicts stored", f.count(), n)
		}
	}
}

// emptyModelLoader keeps the tier router pools empty: SelectModel errors and
// the sampling code falls back to the default premium model.
type emptyModelLoader struct{}

func (emptyModelLoader) ListModels(context.Context) ([]fallbackrouter.ModelInfo, error) {
	return nil, fmt.Errorf("no models in test")
}

// evalgateTestGateway builds a gateway whose evalgate sampling is fully wired:
// rule-tier classifier (medium prompts score 0.60 < 0.7), empty tier router,
// judge pointed at judgeURL and a recording verdict store.
func evalgateTestGateway(t *testing.T, primaryURL, judgeURL string, store verdictStore) *gateway {
	t.Helper()
	cfg := config.Gateway{
		Provider:           primaryURL,
		APIKey:             "primary-key",
		FallbackKey:        "fallback-key",
		FallbackModel:      "smart",
		AuthMode:           "header",
		EvalgateSampleRate: 1.0,
	}
	gw := &gateway{
		cfg:         cfg,
		pool:        upstream.NewPool(upstream.Options{BaseURL: primaryURL}),
		fallback:    fallbackrouter.NewFallbackExecutor(nil, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1},
		log:         slog.Default(),
		judge:       evalgate.NewJudge(judgeURL, nil),
		evalStore:   store,
	}
	reg := classifier.NewRegistry(classifier.NewRuleTier())
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(reg), nil, slog.Default())
	gw.tierRouter = fallbackrouter.NewTierRouter(emptyModelLoader{}, nil)
	return gw
}

// judgeHitServer counts judge calls and answers with a valid verdict. Every
// request signals hit (non-blocking); the returned snapshot function gives
// the last judge request body race-free.
func judgeHitServer(t *testing.T, hits *int32) (*httptest.Server, <-chan struct{}, func() string) {
	t.Helper()
	hit := make(chan struct{}, 8)
	var mu sync.Mutex
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		select {
		case hit <- struct{}{}:
		default:
		}
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastBody = string(raw)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]interface{}{"content": `{"cheap_quality":0.4,"premium_quality":0.9,"should_upgrade":true,"reason":"thin answer"}`}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, hit, func() string {
		mu.Lock()
		defer mu.Unlock()
		return lastBody
	}
}

// waitJudgeHit waits (bounded) for one judge HTTP hit via the judge server's
// signal channel.
func waitJudgeHit(t *testing.T, hit <-chan struct{}) {
	t.Helper()
	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("the judge endpoint was never hit")
	}
}

// mediumPrompt classifies as medium with rule-tier confidence 0.60 (<0.7),
// making the request evalgate-sampling eligible.
const mediumPrompt = "Tell me about AI"

// TestTP04_NonStreamValidResponseStillJudged: a medium/low-confidence
// non-stream request with a full comparable text answer keeps producing a
// judge verdict — the TP-04 skip must not break valid evaluations.
func TestTP04_NonStreamValidResponseStillJudged(t *testing.T) {
	var judgeHits int32
	judgeSrv, _, judgeBody := judgeHitServer(t, &judgeHits)
	store := newFakeVerdictStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	store.waitForVerdicts(t, 1)
	if got := atomic.LoadInt32(&judgeHits); got != 1 {
		t.Fatalf("judge hits = %d, want 1", got)
	}
	if got := store.count(); got != 1 {
		t.Fatalf("stored verdicts = %d, want 1", got)
	}
	// The cheap side of the pair must be the real response text, never a
	// placeholder.
	if prompt := judgeBody(); !strings.Contains(prompt, "Response A (from a cheaper/faster model)") ||
		strings.Contains(prompt, "[streaming response") {
		t.Fatalf("judge prompt must compare the real cheap response: %s", prompt)
	}
}

// TestTP04_NonStreamToolOnlySkipsJudge: a tool-only completion (content null,
// tool_calls present) has no comparable text answer and must not fabricate a
// judge pair.
func TestTP04_NonStreamToolOnlySkipsJudge(t *testing.T) {
	var judgeHits int32
	judgeSrv, _, _ := judgeHitServer(t, &judgeHits)
	store := newFakeVerdictStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","choices":[{"index":0,"message":{"role":"assistant","content":null,` +
			`"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{}"}}]},` +
			`"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// The tool-only skip is decided synchronously inside the finishRequest
	// evalgate hook (chat.go) before the handler returns — no detached
	// goroutine is spawned, so no settle wait is needed: the decision is
	// final once chatCompletions has returned.
	if got := atomic.LoadInt32(&judgeHits); got != 0 {
		t.Fatalf("judge hits = %d, want 0 (tool-only must not be judged)", got)
	}
	if got := store.count(); got != 0 {
		t.Fatalf("stored verdicts = %d, want 0", got)
	}
}

// TestTP04_StreamingSkipsJudgeAndPreservesStream: the cheap response was
// streamed to the client; no full comparable answer exists, so no judge pair
// may be fabricated — and the client stream must be relayed unchanged.
func TestTP04_StreamingSkipsJudgeAndPreservesStream(t *testing.T) {
	var judgeHits int32
	judgeSrv, _, _ := judgeHitServer(t, &judgeHits)
	store := newFakeVerdictStore()

	const sseData = "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseData))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["stream"] = true
	body, _ = json.Marshal(m)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	// Client stream contract: both deltas and [DONE] must reach the client.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	got := w.Body.String()
	for _, want := range []string{"hel", "lo", "[DONE]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("client stream lost %q:\n%s", want, got)
		}
	}

	// The streaming skip is decided synchronously in finishSuccess
	// (stream.go) before serveStream returns — no detached goroutine is
	// spawned, so no settle wait is needed: the decision is final once the
	// handler has returned.
	if got := atomic.LoadInt32(&judgeHits); got != 0 {
		t.Fatalf("judge hits = %d, want 0 (streaming must not fabricate a pair)", got)
	}
	if got := store.count(); got != 0 {
		t.Fatalf("stored verdicts = %d, want 0", got)
	}
}

// TestTP04_ComparableCheapResponse unit-tests the availability check.
func TestTP04_ComparableCheapResponse(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"text answer", `{"choices":[{"message":{"role":"assistant","content":"a real answer"}}]}`, true},
		{"content null", `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[]}}]}`, false},
		{"tool only", `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"c"}]}}]}`, false},
		{"empty content", `{"choices":[{"message":{"role":"assistant","content":""}}]}`, false},
		{"whitespace content", `{"choices":[{"message":{"role":"assistant","content":"   \n\t "}}]}`, false},
		{"no choices", `{"id":"x","choices":[]}`, false},
		{"not json", `garbage`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := comparableCheapResponse([]byte(tc.body)); ok != tc.want {
				t.Fatalf("comparableCheapResponse(%s) = %v, want %v", tc.name, ok, tc.want)
			}
		})
	}
}

// recordingVerdictStore counts InsertVerdict calls without dereferencing the
// verdict. A guard regression must surface as a clean count mismatch here —
// dereferencing a nil verdict (what a failing Evaluate hands over) would
// panic the detached judge goroutine and crash the whole test binary instead.
// Every call also signals calls (non-blocking), so the test's bounded
// negative window fails fast on a regression instead of sleeping on hope.
type recordingVerdictStore struct {
	mu    sync.Mutex
	calls int
	depth chan struct{}
}

func newRecordingVerdictStore() *recordingVerdictStore {
	return &recordingVerdictStore{depth: make(chan struct{}, 8)}
}

func (s *recordingVerdictStore) InsertVerdict(_ context.Context, _, _, _, _, _ string, _ *evalgate.Verdict, _ float64) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	select {
	case s.depth <- struct{}{}:
	default:
	}
	return nil
}

func (s *recordingVerdictStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestTP03_JudgeErrorSkipsInsertVerdict: a judge that FAILS (non-200 →
// Evaluate returns an error, not a malformed-verdict case) must stop before
// InsertVerdict — the store stays empty and the client response is unaffected.
// This is the store-side half of the TP-03 error contract, complementing
// pkg/evalgate TestTP03_JudgeVerdictValidation (which covers Evaluate only).
func TestTP03_JudgeErrorSkipsInsertVerdict(t *testing.T) {
	var judgeHits int32
	judgeHit := make(chan struct{}, 1)
	judgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&judgeHits, 1)
		select {
		case judgeHit <- struct{}{}:
		default:
		}
		http.Error(w, "judge unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(judgeSrv.Close)
	store := newRecordingVerdictStore()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(completeResp("gpt-4o-mini"))
	}))
	t.Cleanup(primary.Close)

	gw := evalgateTestGateway(t, primary.URL, judgeSrv.URL, store)

	body := nonStreamBody("gpt-4o-mini", mediumPrompt)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	// Client contract: the judge's failure must not affect the served answer.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, `"content":"ok"`) || !strings.Contains(respBody, `"model":"gpt-4o-mini"`) {
		t.Fatalf("client response altered by judge failure:\n%s", respBody)
	}

	// Prove the error path was actually exercised: the judge endpoint was hit
	// (and returned the injected error).
	waitJudgeHit(t, judgeHit)
	if got := atomic.LoadInt32(&judgeHits); got != 1 {
		t.Fatalf("judge hits = %d, want 1", got)
	}

	// The judge goroutine is detached, so its exit is unobservable; a buggy
	// variant would call InsertVerdict right after consuming the judge error
	// response. The store signals every insert, so this bounded negative
	// window fails fast on a regression and only the correct case pays the
	// full bound.
	select {
	case <-store.depth:
		t.Fatal("InsertVerdict reached despite the judge error")
	case <-time.After(200 * time.Millisecond):
	}
	if got := store.count(); got != 0 {
		t.Fatalf("InsertVerdict calls = %d, want 0 (judge error must not reach the store)", got)
	}
}
