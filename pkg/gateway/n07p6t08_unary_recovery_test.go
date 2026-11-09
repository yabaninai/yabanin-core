package cli

// N07-P06-T08 — recovery pins for the packet's unary passthrough surfaces
// (rerank, moderations): interruption is surfaced as a mapped error
// envelope with the reservation settled and NO automatic retry (one
// upstream attempt per request); repeating the same input command after
// recovery is a fresh, successful attempt — recovery and re-entry within
// the contract, with no exactly-once claim on the failed first call (the
// upstream may or may not have processed it; the gateway only guarantees
// the settled, eventless client outcome).
//
// Already covered elsewhere (cited, not duplicated): chat SSE
// interruption/retry/resume — n03p3t08_recovery_test.go (drain failure,
// client cancel well-formed termination, control-stream reconstruction,
// replay denial) and responses_cancel_test.go; realtime SSE relay
// interruption — realtime_boundary_test.go (upstream break settles
// prefix, idle timeout, cancel-without-usage) and
// realtime_endpoint_test.go TestRealtime_ClientCancelSettlesConsumedPrefix;
// refusal rows are retry-stable and upstream-free by T02/T04/T05/T06 pins.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// t08FlakyUpstream fails the first hit with 503, passes every later hit
// through with a surface-specific payload.
func t08FlakyUpstream(t *testing.T, okBody string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"upstream outage drill"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okBody))
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func t08Gateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	info := resolver.ModelInfo{ModelName: "compat-canon", Provider: "openai", UpstreamURL: upstreamURL, UpstreamAPIKey: "up", Enabled: true}
	return &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamURL},
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info, info.ModelName: info},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

// TestN07P6T08_UnaryUpstreamFailure_SingleAttemptThenFreshRetry: the first
// attempt hits an outage — the client gets the mapped 502 api_error
// envelope (no partial payload, no request.completed event, exactly one
// upstream hit: the gateway does not auto-retry unary passthrough); the
// identical command is then re-entered and succeeds verbatim with a
// request.completed event. One outage, one settle, one fresh success.
func TestN07P6T08_UnaryUpstreamFailure_SingleAttemptThenFreshRetry(t *testing.T) {
	for _, tc := range []struct {
		name, path, okBody string
	}{
		{"rerank", "/v1/rerank", `{"id":"rr-1","model":"compat-canon","results":[{"index":0,"relevance_score":0.9}],"usage":{"prompt_tokens":7,"total_tokens":7}}`},
		{"moderations", "/v1/moderations", `{"id":"mod-1","model":"compat-canon","results":[{"flagged":false}],"usage":{"prompt_tokens":3,"total_tokens":3}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, hits := t08FlakyUpstream(t, tc.okBody)
			gw := t08Gateway(t, server.URL)
			var events []*eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { events = append(events, e) }

			// Attempt 1 — interrupted by the upstream outage.
			rec1 := postR105(t, gw, tc.path, `{"model":"m","query":"q","documents":["d"],"input":"x"}`, nil)
			if rec1.Code != http.StatusBadGateway {
				t.Fatalf("attempt 1: status %d, want 502 (MapUpstreamStatus 503); body=%s", rec1.Code, rec1.Body.String())
			}
			if got := errorType(t, rec1); got != "api_error" {
				t.Fatalf("attempt 1: error.type %q, want api_error", got)
			}
			if strings.Contains(rec1.Body.String(), "relevance_score") || strings.Contains(rec1.Body.String(), "flagged") {
				t.Fatalf("attempt 1 must deliver no partial upstream payload, got %s", rec1.Body.String())
			}
			if n := hits.Load(); n != 1 {
				t.Fatalf("attempt 1: upstream hits %d, want exactly 1 (no silent auto-retry on unary passthrough)", n)
			}
			if len(events) != 0 {
				t.Fatalf("attempt 1 must publish no request.completed event (settle is eventless), got %+v", events)
			}

			// Attempt 2 — identical command re-entered after recovery.
			rec2 := postR105(t, gw, tc.path, `{"model":"m","query":"q","documents":["d"],"input":"x"}`, nil)
			if rec2.Code != http.StatusOK {
				t.Fatalf("attempt 2: status %d, want 200 (fresh attempt, no stale state); body=%s", rec2.Code, rec2.Body.String())
			}
			if strings.TrimSpace(rec2.Body.String()) != tc.okBody {
				t.Fatalf("attempt 2: passthrough body %q, want verbatim %q", rec2.Body.String(), tc.okBody)
			}
			if n := hits.Load(); n != 2 {
				t.Fatalf("attempt 2: upstream hits %d, want 2 (one per client attempt)", n)
			}
			if len(events) != 1 || events[0].EventType != "request.completed" {
				t.Fatalf("attempt 2 must emit exactly one request.completed event, got %+v", events)
			}
		})
	}
}

// TestN07P6T08_UpstreamUnreachable_SettleThenRecoveredRoute: a dead
// upstream yields the connect-failure envelope (502, no event); once the
// resolver row is re-pointed at a healthy upstream, the same command
// succeeds — the recovery seam is the model registry row, not process
// state.
func TestN07P6T08_UpstreamUnreachable_SettleThenRecoveredRoute(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("dead upstream must not be reached")
	}))
	dead.Close() // port freed — connect refused

	gw := t08Gateway(t, dead.URL)
	var events []*eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { events = append(events, e) }

	rec1 := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["d"]}`, nil)
	if rec1.Code != http.StatusBadGateway {
		t.Fatalf("dead upstream: status %d, want 502; body=%s", rec1.Code, rec1.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("dead upstream must settle eventless, got %+v", events)
	}

	// Recovery: re-point the resolver row at a healthy upstream.
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[],"usage":{"prompt_tokens":1,"total_tokens":1}}`)
	}))
	t.Cleanup(okServer.Close)
	info := resolver.ModelInfo{ModelName: "compat-canon", Provider: "openai", UpstreamURL: okServer.URL, Enabled: true}
	gw.res = stubModelResolver{"m": info, info.ModelName: info}

	rec2 := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["d"]}`, nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("recovered route: status %d, want 200; body=%s", rec2.Code, rec2.Body.String())
	}
	if len(events) != 1 || events[0].EventType != "request.completed" {
		t.Fatalf("recovered route must emit request.completed once, got %+v", events)
	}
}
