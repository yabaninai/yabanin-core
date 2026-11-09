package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/shadow"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// shadowTestGateway builds a minimal non-streaming-capable gateway: real
// upstream pool → httptest primary, shadow dispatcher → httptest shadow
// target. No DB/Redis — the pin check is injected directly.
func shadowTestGateway(t *testing.T, primaryURL, shadowURL string) *gateway {
	t.Helper()
	cfg := config.Gateway{
		Provider:      primaryURL,
		APIKey:        "primary-key",
		FallbackKey:   "fallback-key",
		FallbackModel: "smart",
		AuthMode:      "header",
	}
	cfg.Shadow = config.Shadow{
		Enabled:       true,
		Model:         "gpt-4o",
		UpstreamURL:   shadowURL,
		APIKey:        "shadow-key",
		SampleRate:    1.0,
		Timeout:       "5s",
		MaxConcurrent: 4,
	}
	vcfg, err := shadow.Config{
		Enabled:       true,
		Model:         cfg.Shadow.Model,
		UpstreamURL:   cfg.Shadow.UpstreamURL,
		APIKey:        cfg.Shadow.APIKey,
		SampleRate:    cfg.Shadow.SampleRate,
		Timeout:       cfg.Shadow.ShadowTimeout(),
		MaxConcurrent: cfg.Shadow.MaxConcurrent,
	}.Validate()
	if err != nil {
		t.Fatalf("shadow config: %v", err)
	}
	gw := &gateway{
		cfg:         cfg,
		pool:        upstream.NewPool(upstream.Options{BaseURL: primaryURL}),
		fallback:    fallbackrouter.NewFallbackExecutor(nil, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1},
		log:         slog.Default(),
		shadow:      shadow.NewDispatcher(vcfg, slog.Default()),
	}
	// No DB in tests: pin check via closure.
	gw.shadow.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool {
		return orgID == "pinned-org"
	})
	return gw
}

// nonStreamBody returns a valid non-streaming chat completion body.
func nonStreamBody(model, content string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{"role": "user", "content": content},
		},
		"stream": false,
	})
	return b
}

// completeResp is a minimal OpenAI-shaped response with usage.
func completeResp(model string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c1","object":"chat.completion","model":%q,
	"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
	"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`, model))
}

// shadowHitChan returns the signal channel a shadow target handler feeds with
// one non-blocking send per request, so tests synchronize on the call instead
// of polling.
func shadowHitChan() chan struct{} { return make(chan struct{}, 4) }

// signalShadowHit signals one request on hit (safe on a nil channel).
func signalShadowHit(hit chan struct{}) {
	select {
	case hit <- struct{}{}:
	default:
	}
}

// waitShadowCall waits (bounded) for the detached shadow call to land.
func waitShadowCall(t *testing.T, hit <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-hit:
	case <-time.After(d):
		t.Fatal("the shadow target never received the expected call")
	}
}

// assertNoShadowCall proves, within a bounded negative window, that no shadow
// call is made: the window fails fast on a regression and only the correct
// case pays the full bound.
func assertNoShadowCall(t *testing.T, hit <-chan struct{}) {
	t.Helper()
	select {
	case <-hit:
		t.Error("shadow call made where none was expected")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestMaybeShadow_PassthroughUnaffectedByShadowError(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()
	// Shadow target is down: connection refused.
	deadShadow := "http://127.0.0.1:1"

	gw := shadowTestGateway(t, primary.URL, deadShadow)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Session-Id", "sess-1")
	w := httptest.NewRecorder()

	gw.chatCompletions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("primary status = %d, want 200 (passthrough invariant)", w.Code)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("primary response not JSON: %v", err)
	}
	if got["model"] != "gpt-4o-mini" {
		t.Errorf("primary model = %v, want gpt-4o-mini", got["model"])
	}
	// The client response must be the primary model's, never the shadow's.
	if strings.Contains(w.Body.String(), "gpt-4o\"") && !strings.Contains(w.Body.String(), "gpt-4o-mini") {
		t.Errorf("response leaked shadow model: %s", w.Body.String())
	}
}

func TestMaybeShadow_PassthroughUnaffectedByShadowTimeout(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()
	slowShadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)                   // exceeds the 50ms shadow timeout below
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer slowShadow.Close()

	gw := shadowTestGateway(t, primary.URL, slowShadow.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	// Tighten the shadow timeout so the test is fast.
	gw.shadow = shadow.NewDispatcher(mustShadowCfg(t, 50*time.Millisecond), slog.Default())
	gw.shadow.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool { return orgID == "pinned-org" })
	gw.shadow.SetEnabled(true)

	start := time.Now()
	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	elapsed := time.Since(start)

	if w.Code != http.StatusOK {
		t.Fatalf("primary status = %d, want 200", w.Code)
	}
	// The client must not wait for the shadow: primary path < 1s even though
	// the shadow target sleeps 3s.
	if elapsed > time.Second {
		t.Errorf("primary path took %v — shadow blocked the client", elapsed)
	}
}

func TestMaybeShadow_ShadowPanicCannotReachClient(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer shadowSrv.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	// The real panic-inside-Run path is covered by TestRun_PanicRecovered in
	// pkg/shadow. Here we assert the gateway-level invariant: the client
	// response is complete and correct even though the shadow goroutine is
	// in flight (or has panicked) — the request path never observes it.
	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic escaped the request path: %v", rec)
		}
	}()
	gw.chatCompletions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("primary status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "gpt-4o-mini") {
		t.Errorf("client response must be the primary model's: %s", w.Body.String())
	}
}

func TestMaybeShadow_SkipsWhenDisabled(t *testing.T) {
	var shadowCalls int32
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(false)

	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if n := atomic.LoadInt32(&shadowCalls); n != 0 {
		t.Errorf("shadow calls = %d, want 0 (disabled)", n)
	}
}

// TestChatCompletions_StreamingPrimaryIsMirrored: a streaming request routes
// chatCompletions -> serveStream, which (V10) fires a detached shadow call.
// v9 skipped streaming entirely; v10 mirrors it because a shadow call is
// always a plain non-streaming request to the candidate regardless of how the
// primary was served.
func TestChatCompletions_StreamingPrimaryIsMirrored(t *testing.T) {
	var shadowCalls int32
	const sessionID = "r019-shadow-streaming-primary-mirrored"
	shadowHit := shadowHitChan()
	shadowCompleted := make(chan eventpub.Event, 1)
	restoreObserver := observeEvent(func(event *eventpub.Event) {
		if event == nil || event.EventType != "request.shadow_completed" || event.OrgID != "org-1" || event.SessionID != sessionID {
			return
		}
		select {
		case shadowCompleted <- *event:
		default:
		}
	})
	t.Cleanup(restoreObserver)
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
		signalShadowHit(shadowHit)
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: [DONE]\n\n") //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	body := nonStreamBody("gpt-4o-mini", "hi")
	// Flip to streaming.
	var m map[string]interface{}
	_ = json.Unmarshal(body, &m)
	m["stream"] = true
	body, _ = json.Marshal(m)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Session-Id", sessionID)
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)

	// Streaming path now mirrors: the detached shadow call must arrive.
	waitShadowCall(t, shadowHit, 2*time.Second)
	// Receiving the HTTP request is earlier than shadow dispatcher completion.
	// Wait until the detached completion event has passed the package-global
	// observer so a later test cannot mistake it for its own event.
	select {
	case event := <-shadowCompleted:
		if event.EventType != "request.shadow_completed" || event.OrgID != "org-1" || event.SessionID != sessionID {
			t.Fatalf("shadow completion event = (%q, %q, %q), want request.shadow_completed for org-1 session %q", event.EventType, event.OrgID, event.SessionID, sessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow completion event did not reach the observer")
	}
	if n := atomic.LoadInt32(&shadowCalls); n != 1 {
		t.Errorf("shadow calls = %d, want 1 (streaming primary is mirrored in V10)", n)
	}
}

func TestMaybeShadow_SkipsPinnedOrg(t *testing.T) {
	var shadowCalls int32
	shadowHit := shadowHitChan()
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
		signalShadowHit(shadowHit)
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "pinned-org") // the injected pin check flags this org
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// The pin check runs synchronously in fireShadow before any goroutine is
	// spawned, so once the handler returns the skip is final; the bounded
	// window guards the regression.
	assertNoShadowCall(t, shadowHit)
	if n := atomic.LoadInt32(&shadowCalls); n != 0 {
		t.Errorf("shadow calls = %d, want 0 (pinned org)", n)
	}
}

func TestMaybeShadow_MirrorsEligibleRequest(t *testing.T) {
	var shadowCalls int32
	var mu sync.Mutex
	var gotShadowModel, gotShadowKey string
	shadowHit := shadowHitChan()
	shadowCompleted := make(chan eventpub.Event, 1)
	restoreObserver := observeEvent(func(event *eventpub.Event) {
		if event == nil || event.EventType != "request.shadow_completed" || event.OrgID != "org-1" {
			return
		}
		select {
		case shadowCompleted <- *event:
		default:
		}
	})
	t.Cleanup(restoreObserver)
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
		var b map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&b); err == nil {
			mu.Lock()
			gotShadowModel, _ = b["model"].(string)
			mu.Unlock()
		}
		mu.Lock()
		gotShadowKey = r.Header.Get("Authorization")
		mu.Unlock()
		// Signal after the body/auth capture: waitShadowCall must not race
		// the test's read of the recorded fields.
		signalShadowHit(shadowHit)
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(completeResp("gpt-4o-mini"))) //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	body := nonStreamBody("gpt-4o-mini", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	waitShadowCall(t, shadowHit, 2*time.Second)
	// Receiving the HTTP request is earlier than shadow dispatcher completion.
	// Wait until the detached completion event has passed the package-global
	// observer so a later test cannot mistake it for its own event.
	select {
	case event := <-shadowCompleted:
		if event.EventType != "request.shadow_completed" || event.OrgID != "org-1" {
			t.Fatalf("shadow completion event = (%q, %q), want request.shadow_completed for org-1", event.EventType, event.OrgID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow completion event did not reach the observer")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotShadowModel != "gpt-4o" {
		t.Errorf("shadow model = %q, want gpt-4o", gotShadowModel)
	}
	if gotShadowKey != "Bearer shadow-key" {
		t.Errorf("shadow auth = %q, want Bearer shadow-key", gotShadowKey)
	}
}

func TestMaybeShadow_SameModelIsSkipped(t *testing.T) {
	var shadowCalls int32
	shadowHit := shadowHitChan()
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
		signalShadowHit(shadowHit)
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	// Shadow model == primary model → same_model skip.
	gw.cfg.Shadow.Model = "gpt-4o"
	gw.shadow = shadow.NewDispatcher(mustShadowCfg(t, 5*time.Second), slog.Default())
	gw.shadow.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool { return orgID == "pinned-org" })
	gw.shadow.SetEnabled(true)

	body := nonStreamBody("gpt-4o", "hi")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.chatCompletions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// The same-model check runs synchronously in ShouldMirror before any
	// goroutine is spawned, so once the handler returns the skip is final;
	// the bounded window guards the regression.
	assertNoShadowCall(t, shadowHit)
	if n := atomic.LoadInt32(&shadowCalls); n != 0 {
		t.Errorf("shadow calls = %d, want 0 (same model)", n)
	}
}

// mustShadowCfg builds a valid shadow.Config for tests.
func mustShadowCfg(t *testing.T, timeout time.Duration) shadow.Config {
	t.Helper()
	c := shadow.Config{
		Enabled:       true,
		Model:         "gpt-4o",
		SampleRate:    1.0,
		Timeout:       timeout,
		MaxConcurrent: 4,
	}
	vc, err := c.Validate()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return vc
}
