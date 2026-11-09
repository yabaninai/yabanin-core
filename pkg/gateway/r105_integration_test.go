package cli

// real http.Client → real gateway TCP server (chi routes, production
// middleware wiring) → live httptest upstreams. Fills the boundary gaps the
// handlers through a ResponseRecorder): incremental SSE visibility through a
// real transport, a real client disconnect mid-session (transport teardown,
// not a context cancel), and the 413 cap over the real wire. Everything else
// duplicated. Hermetic: synthetic data, isolated httptest stand, no external
// service, nothing published, active OpenCode stand untouched.

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// r105GatewayServer mounts the gateway routes on a real TCP server.
func r105GatewayServer(t *testing.T, gw *gateway, middlewares ...func(http.Handler) http.Handler) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	for _, mw := range middlewares {
		r.Use(mw)
	}
	gw.routes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// r105RealPost performs a real client POST against the gateway server.
func r105RealPost(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("real client request failed: %v", err)
	}
	return resp
}

// TestR105_RealHTTPBoundary_Unary: rerank and moderations through the real
// consumer boundary — auth header over the wire, canonical model override
// reaching the live upstream, byte-exact relay and the completion event with
// real provider usage (D3).
func TestR105_RealHTTPBoundary_Unary(t *testing.T) {
	cases := []struct {
		name         string
		path, body   string
		model        resolver.ModelInfo
		upstreamPath string
		upstreamBody string
	}{
		{
			name: "rerank", path: "/v1/rerank",
			body:         `{"model":"m","query":"capital of france","documents":["paris","berlin"]}`,
			model:        resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamAPIKey: "up", Enabled: true},
			upstreamPath: "/v1/rerank",
			upstreamBody: `{"id":"rr-9","results":[{"index":0,"relevance_score":0.9}],"usage":{"prompt_tokens":41,"total_tokens":41}}`,
		},
		{
			name: "moderations", path: "/v1/moderations",
			body:         `{"model":"m","input":"hello world"}`,
			model:        resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamAPIKey: "up", Enabled: true},
			upstreamPath: "/v1/moderations",
			upstreamBody: `{"id":"mod-9","results":[{"flagged":false}],"usage":{"prompt_tokens":12,"total_tokens":12}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamPath atomic.Value
			var upstreamBody atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamPath.Store(r.URL.Path)
				raw, _ := io.ReadAll(r.Body)
				upstreamBody.Store(string(raw))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.upstreamBody))
			}))
			defer server.Close()

			info := tc.model
			info.UpstreamURL = server.URL
			gw := r105TestGateway(t, info)
			evCh := make(chan *eventpub.Event, 1)
			gw.eventNote = func(e *eventpub.Event) { evCh <- e }
			srv := r105GatewayServer(t, gw)

			resp := r105RealPost(t, srv, tc.path, tc.body)
			got, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("real client read failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, got)
			}
			if string(got) != tc.upstreamBody {
				t.Fatalf("relay over real boundary altered bytes:\n%q\nwant\n%q", got, tc.upstreamBody)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content type over the wire %q", ct)
			}
			if p, _ := upstreamPath.Load().(string); p != tc.upstreamPath {
				t.Fatalf("upstream path %q", p)
			}
			if b, _ := upstreamBody.Load().(string); !strings.Contains(b, `"`+tc.model.ModelName+`"`) {
				t.Fatalf("canonical model not overridden upstream: %q", b)
			}
			select {
			case ev := <-evCh:
				if ev.EventType != "request.completed" || ev.Endpoint != strings.TrimPrefix(tc.path, "/v1/") {
					t.Fatalf("event %+v", ev)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no completion event through the real boundary")
			}
		})
	}
}

// TestRealtime_RealHTTPStreamBoundary: the SSE session streams incrementally
// through a real transport — the client observes the first event while the
// upstream is still holding the rest back (no whole-response buffering), the
// bytes arrive verbatim, and the last usage-bearing event bills (D3).
func TestRealtime_RealHTTPStreamBoundary(t *testing.T) {
	const prefix = "event: session.created\n" + `data: {"type":"session.created","session":{}}` + "\n\n"
	const usageEvent = "event: response.done\n" +
		`data: {"type":"response.done","response":{"usage":{"input_tokens":31,"output_tokens":5,"total_tokens":36}}}` + "\n\n"
	prefixVisible := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, prefix)
		w.(http.Flusher).Flush()
		close(prefixVisible)
		select {
		case <-release:
		case <-time.After(10 * time.Second):
			return
		}
		_, _ = io.WriteString(w, usageEvent)
		w.(http.Flusher).Flush()
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }
	srv := r105GatewayServer(t, gw)

	resp := r105RealPost(t, srv, "/v1/realtime", `{"model":"m"}`)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type over the wire %q", ct)
	}

	var acc strings.Builder
	reader := bufio.NewReader(resp.Body)
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer closeRelease()
	seenIncremental := false
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("stream never completed; read so far:\n%s", acc.String())
		}
		line, rerr := reader.ReadString('\n')
		acc.WriteString(line)
		if !seenIncremental && strings.Contains(acc.String(), "session.created") {
			// The first event is visible to a real client BEFORE the
			// upstream released the rest — incremental relay proof.
			seenIncremental = true
			select {
			case <-prefixVisible:
			case <-time.After(time.Second):
				t.Fatal("prefix not yet flushed upstream")
			}
			closeRelease()
		}
		if rerr != nil {
			break // EOF — the upstream ended the session after the usage event
		}
	}
	if !seenIncremental {
		t.Fatal("first event never observed incrementally")
	}
	if !strings.Contains(acc.String(), "response.done") {
		t.Fatalf("stream ended without the usage event:\n%s", acc.String())
	}
	if acc.String() != prefix+usageEvent {
		t.Fatalf("relay over real boundary altered bytes:\n%q", acc.String())
	}
	select {
	case ev := <-evCh:
		if ev.EventType != "request.completed" || ev.TokensIn != 31 || ev.TokensOut != 5 {
			t.Fatalf("event %+v", ev)
		}
		if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
			t.Fatalf("honest billing through real boundary: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no completion event through the real boundary")
	}
}

// TestRealtime_RealClientDisconnectSettlesPrefix (negative scenario «разрыв
// потока», client side, real transport): the client walks away mid-session
// by closing the connection (transport teardown — not a context cancel); the
// gateway settles the consumed prefix with client_cancel and request.failed —
// usage is never lost (G3 parity) over the real boundary.
func TestRealtime_RealClientDisconnectSettlesPrefix(t *testing.T) {
	const prefix = "event: response.done\n" +
		`data: {"type":"response.done","response":{"usage":{"input_tokens":17,"output_tokens":2,"total_tokens":19}}}` + "\n\n"
	prefixVisible := make(chan struct{})
	clientGone := make(chan struct{})
	var goneOnce sync.Once
	signalGone := func() { goneOnce.Do(func() { close(clientGone) }) }
	defer signalGone()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, prefix)
		w.(http.Flusher).Flush()
		close(prefixVisible)
		<-clientGone
		// Keep producing so the relay attempts a write onto the dead
		// connection and observes the transport teardown.
		chunk := strings.Repeat("x", 32*1024)
		for i := 0; i < 200; i++ {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }
	srv := r105GatewayServer(t, gw)

	resp := r105RealPost(t, srv, "/v1/realtime", `{"model":"m"}`)
	buf := make([]byte, len(prefix)+64)
	n, err := io.ReadFull(resp.Body, buf[:len(prefix)])
	if err != nil || string(buf[:n]) != prefix {
		t.Fatalf("prefix not received verbatim (n=%d err=%v): %q", n, err, string(buf[:n]))
	}
	// Real transport teardown: close the response body mid-stream.
	_ = resp.Body.Close()
	signalGone()

	select {
	case ev := <-evCh:
		if ev.EventType != "request.failed" {
			t.Fatalf("event type %q, want request.failed", ev.EventType)
		}
		if ev.TokensIn != 17 || ev.TokensOut != 2 || ev.UsageSource != "provider" {
			t.Fatalf("consumed prefix usage lost over real boundary: %+v", ev)
		}
		// The termination-class stamp (client_cancel) is proven at the -02
		// recorder anchors with the injected reservation stub — context
		// values cannot cross the real HTTP boundary, and wiring a live
		// Admission store is the Docker-gated NEXT-18c suite's domain.
	case <-time.After(10 * time.Second):
		t.Fatal("client disconnect settled no event — usage would be lost")
	}
}

// TestR105_RealHTTP413ThroughProductionWiring: an oversized body through the
// real server with the production MaxBody wiring answers 413 on the wire
// before any upstream call (contract example 2 over the real boundary).
func TestR105_RealHTTP413ThroughProductionWiring(t *testing.T) {
	for _, fam := range r105Families("") {
		t.Run(fam.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
			}))
			defer server.Close()

			gw := r105TestGateway(t, withURL(fam.model, server.URL))
			srv := r105GatewayServer(t, gw, httpmw.MaxBody(10*1024*1024))

			big := strings.Repeat("a", 10*1024*1024+1024)
			var body string
			switch fam.name {
			case "rerank":
				body = `{"model":"m","query":"` + big + `","documents":["a"]}`
			case "moderations":
				body = `{"model":"m","input":"` + big + `"}`
			default:
				body = `{"model":"m","session":{"instructions":"` + big + `"}}`
			}
			resp := r105RealPost(t, srv, fam.path, body)
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("status %d, want 413: %s", resp.StatusCode, raw)
			}
			var env struct {
				Error struct {
					Type string `json:"type"`
				} `json:"error"`
			}
			if err := json.Unmarshal(raw, &env); err != nil || env.Error.Type != "invalid_request_error" {
				t.Fatalf("envelope %s", raw)
			}
			if calls.Load() != 0 {
				t.Fatalf("oversized body reached upstream %d times", calls.Load())
			}
		})
	}
}
