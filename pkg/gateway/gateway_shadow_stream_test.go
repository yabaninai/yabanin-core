package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/shadow"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// streamBody returns a valid streaming chat completion body.
func shadowStreamBody(model, content string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"model": model,
		"messages": []map[string]interface{}{
			{"role": "user", "content": content},
		},
		"stream": true,
	})
	return b
}

// ssePrimary returns a primary upstream that emits a small fixed SSE stream
// (two content chunks + [DONE]) and counts requests. The bytes are the
// mandatory-passthrough oracle: the client must receive exactly these.
func ssePrimary(t *testing.T, calls *int32) *httptest.Server {
	t.Helper()
	const sse = "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, sse) //nolint:errcheck
	}))
}

// TestMaybeShadowStream_MirrorsEligibleRequest: a streaming primary that is
// eligible (different model, enabled, not pinned) fires exactly one detached
// shadow call to the candidate.
func TestMaybeShadowStream_MirrorsEligibleRequest(t *testing.T) {
	var shadowCalls int32
	shadowHit := shadowHitChan()
	shadowCompleted := make(chan eventpub.Event, 1)
	restoreObserver := observeEvent(func(event *eventpub.Event) {
		if event == nil || event.EventType != "request.shadow_completed" || event.OrgID != "org-1" || event.SessionID != "sess-1" {
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
		// The shadow body must be a plain (non-streaming) completion request:
		// the candidate gets "stream": false even though the primary streamed.
		var got map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["stream"] != false {
			t.Errorf("shadow body stream = %v, want false (must be a plain completion)", got["stream"])
		}
		if got["model"] != "gpt-4o" {
			t.Errorf("shadow body model = %v, want gpt-4o (candidate)", got["model"])
		}
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
	gw.shadow.SetEnabled(true)

	gw.maybeShadowStream(context.Background(), shadowStreamBody("gpt-4o-mini", "hi"),
		"gpt-4o-mini", "org-1", "team-1", "sess-1", "req-stream-1")

	// The detached call must arrive; the shadow target signals every request.
	waitShadowCall(t, shadowHit, 2*time.Second)
	// Receiving the HTTP request is earlier than shadow dispatcher completion.
	// Wait until the detached completion event has passed the package-global
	// observer so a later test cannot mistake it for its own event.
	select {
	case event := <-shadowCompleted:
		if event.EventType != "request.shadow_completed" || event.OrgID != "org-1" || event.SessionID != "sess-1" {
			t.Fatalf("shadow completion event = (%q, %q, %q), want request.shadow_completed for org-1 session sess-1", event.EventType, event.OrgID, event.SessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow completion event did not reach the observer")
	}
	if n := atomic.LoadInt32(&shadowCalls); n != 1 {
		t.Fatalf("shadow calls = %d, want 1 (streaming primary must be mirrored)", n)
	}
}

// TestMaybeShadowStream_SkipsWhenDisabled: with the runtime switch off, no
// shadow call is made for a streaming primary.
func TestMaybeShadowStream_SkipsWhenDisabled(t *testing.T) {
	var shadowCalls int32
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shadowCalls, 1)
	}))
	defer shadowSrv.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: [DONE]\n\n") //nolint:errcheck
	}))
	defer primary.Close()

	gw := shadowTestGateway(t, primary.URL, shadowSrv.URL)
	gw.cfg.Provider = primary.URL
	gw.shadow.SetEnabled(false)

	gw.maybeShadowStream(context.Background(), shadowStreamBody("gpt-4o-mini", "hi"),
		"gpt-4o-mini", "org-1", "team-1", "sess-1", "req-stream-off")

	// The disabled check runs synchronously in ShouldMirror (shadow.go)
	// before any goroutine is spawned — once maybeShadowStream has returned,
	// no shadow call can ever be made.
	if n := atomic.LoadInt32(&shadowCalls); n != 0 {
		t.Errorf("shadow calls = %d, want 0 (disabled)", n)
	}
}

// TestServeStream_PassthroughUnaffectedByDeadShadow: the mandatory-passthrough
// invariant for the streaming path. The primary emits a fixed SSE stream and the
// shadow target is completely dead (connection refused). The client must
// receive the primary's SSE bytes verbatim — the dead shadow must not
// truncate, corrupt, or delay-visible the stream.
func TestServeStream_PassthroughUnaffectedByDeadShadow(t *testing.T) {
	var primaryCalls int32
	primary := ssePrimary(t, &primaryCalls)
	defer primary.Close()
	deadShadow := "http://127.0.0.1:1"

	gw := shadowTestGateway(t, primary.URL, deadShadow)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow.SetEnabled(true)

	body := shadowStreamBody("gpt-4o-mini", "hi")
	w := httptest.NewRecorder()
	// httptest.ResponseRecorder does not implement http.Flusher, so wrap it to
	// satisfy serveStream's flusher assertion.
	wf := &flushRecorder{ResponseRecorder: w}

	info := resolver.ModelInfo{
		ModelName:   "gpt-4o-mini",
		Provider:    "openai",
		UpstreamURL: primary.URL,
	}
	gw.serveStream(wf, context.Background(), info, body, false,
		"sess-1", "org-1", "team-1", "task", "req-stream-pass", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	// The client must get the full primary SSE stream, byte for byte.
	want := "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	if got := wf.Body.String(); got != want {
		t.Fatalf("client SSE bytes != primary stream (passthrough violated)\n got: %q\nwant: %q", got, want)
	}
	if ct := wf.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	// The shadow was attempted (and failed) but the primary was still served.
	if primaryCalls == 0 {
		t.Errorf("primary was not called")
	}
}

// TestServeStream_PassthroughUnaffectedByShadowTimeout: the same invariant when
// the shadow target hangs past the shadow timeout. The client's stream is
// unaffected and returns promptly.
func TestServeStream_PassthroughUnaffectedByShadowTimeout(t *testing.T) {
	var primaryCalls int32
	primary := ssePrimary(t, &primaryCalls)
	defer primary.Close()
	slowShadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)                   // exceeds the tightened shadow timeout
		fmt.Fprint(w, string(completeResp("gpt-4o"))) //nolint:errcheck
	}))
	defer slowShadow.Close()

	gw := shadowTestGateway(t, primary.URL, slowShadow.URL)
	gw.cfg.Provider = primary.URL
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: primary.URL})
	gw.shadow = shadow.NewDispatcher(mustShadowCfg(t, 50*time.Millisecond), testLogger())
	gw.shadow.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool { return orgID == "pinned-org" })
	gw.shadow.SetEnabled(true)

	body := shadowStreamBody("gpt-4o-mini", "hi")
	wf := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	info := resolver.ModelInfo{
		ModelName:   "gpt-4o-mini",
		Provider:    "openai",
		UpstreamURL: primary.URL,
	}

	start := time.Now()
	gw.serveStream(wf, context.Background(), info, body, false,
		"sess-1", "org-1", "team-1", "task", "req-stream-to", testLogger(), routingDecision{}, "", 0, "", "", "", false)
	elapsed := time.Since(start)

	want := "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	if got := wf.Body.String(); got != want {
		t.Fatalf("client SSE bytes != primary stream\n got: %q\nwant: %q", got, want)
	}
	// The primary stream itself must not be delayed by the hanging shadow (the
	// shadow runs detached; the drain of the ~3-line primary is sub-ms).
	if elapsed > 2*time.Second {
		t.Errorf("serveStream took %v — a hanging shadow must not delay the client stream", elapsed)
	}
}

// flushRecorder wraps httptest.ResponseRecorder to also satisfy http.Flusher,
// which serveStream requires.
type flushRecorder struct {
	*httptest.ResponseRecorder
}

func (f *flushRecorder) Flush() {}
