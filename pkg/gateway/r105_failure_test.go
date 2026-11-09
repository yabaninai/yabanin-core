package cli

// failure stage — extends the -02 boundary matrix:
// malformed provider responses are relayed byte-honestly and never turn into
// fabricated usage or results; rate limits interact on both sides (the
// production per-IP limiter in front of the routes, the admission team
// budget before any egress, upstream 429 without retry); a failed request
// does not poison subsequent processing — the retry after a failure completes normally.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

type r105Family struct {
	name    string
	path    string
	body    string
	model   resolver.ModelInfo
	respond func(w http.ResponseWriter, call int64)
}

// r105Families returns the three ratified families wired to one upstream.
func r105Families(upstreamURL string) []r105Family {
	return []r105Family{
		{
			name: "rerank", path: "/v1/rerank",
			body: `{"model":"m","query":"q","documents":["a"]}`,
			model: resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai",
				UpstreamURL: upstreamURL, UpstreamAPIKey: "up", Enabled: true},
			respond: func(w http.ResponseWriter, _ int64) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"results":[{"index":0,"relevance_score":0.5}],"usage":{"prompt_tokens":3,"total_tokens":3}}`))
			},
		},
		{
			name: "moderations", path: "/v1/moderations",
			body: `{"model":"m","input":"x"}`,
			model: resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai",
				UpstreamURL: upstreamURL, UpstreamAPIKey: "up", Enabled: true},
			respond: func(w http.ResponseWriter, _ int64) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"mod","results":[{"flagged":false}],"usage":{"prompt_tokens":2,"total_tokens":2}}`))
			},
		},
		{
			name: "realtime", path: "/v1/realtime",
			body: `{"model":"m"}`,
			model: resolver.ModelInfo{ModelName: "gpt-4o-realtime-canon", Provider: "openai",
				UpstreamURL: upstreamURL, UpstreamAPIKey: "up", Enabled: true},
			respond: func(w http.ResponseWriter, _ int64) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: " + `{"usage":{"input_tokens":4,"total_tokens":4}}` + "\n\n"))
			},
		},
	}
}

// TestRerank_MalformedUpstreamNeverFabricates (card step 1, "неизвестная
// цена"/malformed provider responses): an upstream 200 body that is truncated
// JSON, non-JSON, or carries a non-object usage block is relayed verbatim and
// accounted as no_usage with zero tokens — the gateway never invents rerank
// results, usage, or a price the provider did not report (D3).
func TestRerank_MalformedUpstreamNeverFabricates(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"truncated json", `{"results":[{"index":0,"relevance_score":0.`},
		{"not json", `internal server error text`},
		{"usage wrong type", `{"results":[],"usage":"20 tokens"}`},
		{"usage null", `{"results":[],"usage":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai",
				UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true})
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }

			rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if rec.Body.String() != tc.body {
				t.Fatalf("relay altered the malformed body:\n%q\nwant\n%q", rec.Body.String(), tc.body)
			}
			if ev == nil || ev.EventType != "request.completed" {
				t.Fatalf("no completed event: %+v", ev)
			}
			if ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
				t.Fatalf("malformed upstream body fabricated accounting: %+v", ev)
			}
			if ev.TokensIn != 0 || ev.TokensOut != 0 {
				t.Fatalf("fabricated tokens: %+v", ev)
			}
		})
	}
}

// TestRealtime_MalformedSSEEventsNeverFabricate: garbage data lines, a
// [DONE]-style sentinel and usage blocks of the wrong type inside the relayed
// event stream never produce fabricated usage — the stream is relayed
// byte-honestly and the session accounts as no_usage until a well-formed
// usage event actually arrives (D3 actual billing).
func TestRealtime_MalformedSSEEventsNeverFabricate(t *testing.T) {
	const stream = "event: session.created\n" +
		`data: {"type":"session.created","session":{}}` + "\n\n" +
		"data: this is not json\n\n" +
		"data: [DONE]\n\n" +
		"event: response.done\n" +
		`data: {"type":"response.done","response":{"usage":"about 20 tokens"}}` + "\n\n" +
		`data: {"usage":null}` + "\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(stream))
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != stream {
		t.Fatalf("relay altered the malformed stream:\n%q\nwant\n%q", rec.Body.String(), stream)
	}
	if ev == nil || ev.EventType != "request.completed" {
		t.Fatalf("no completed event: %+v", ev)
	}
	if ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
		t.Fatalf("malformed SSE events fabricated accounting: %+v", ev)
	}
	if ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("fabricated tokens: %+v", ev)
	}
}

// TestR105_PerIPRateLimiterRefusesBeforeEgress (rate-limit interactions,
// gateway side): with the production httpmw.RateLimiter in front of the
// routes (gateway.go wiring parity), the request past the burst is refused
// 429 with Retry-After before any handler work — zero additional upstream
// calls, zero analytics events.
func TestR105_PerIPRateLimiterRefusesBeforeEgress(t *testing.T) {
	for _, fam := range r105Families("") {
		t.Run(fam.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fam.respond(w, calls.Add(1))
			}))
			defer server.Close()

			gw := r105TestGateway(t, withURL(fam.model, server.URL))
			var events atomic.Int64
			gw.eventNote = func(*eventpub.Event) { events.Add(1) }

			// One limiter instance (one bucket store) shared by both
			// requests — the production wiring mounts it once per router.
			r := chi.NewRouter()
			r.Use(httpmw.RateLimiter(httpmw.RateLimitConfig{RequestsPerSecond: 0.001, BurstSize: 1}))
			gw.routes(r)
			do := func() *httptest.ResponseRecorder {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, fam.path, strings.NewReader(fam.body))
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, req)
				return rec
			}

			first := do()
			if first.Code != http.StatusOK {
				t.Fatalf("first request status %d %s", first.Code, first.Body.String())
			}
			second := do()
			if second.Code != http.StatusTooManyRequests {
				t.Fatalf("limited request status %d, want 429: %s", second.Code, second.Body.String())
			}
			if got := second.Header().Get("Retry-After"); got == "" {
				t.Fatal("limited response carries no Retry-After")
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream called %d times, want 1 (the limited request must not egress)", calls.Load())
			}
			if events.Load() != 1 {
				t.Fatalf("events published %d, want 1 (none for the limited request)", events.Load())
			}
		})
	}
}

// TestR105_TeamBudgetExceededRefusesBeforeEgress (rate-limit interactions,
// admission side): an exhausted team budget refuses 429 budget_exceeded
// before any upstream call for every family — spend gating applies to the
// new endpoints exactly as to chat (P6.10 fail-safe parity).
func TestR105_TeamBudgetExceededRefusesBeforeEgress(t *testing.T) {
	for _, fam := range r105Families("") {
		t.Run(fam.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				fam.respond(w, 1)
			}))
			defer server.Close()

			gw := r105TestGateway(t, withURL(fam.model, server.URL))
			gw.auth = NewAuthMiddleware(gw.cfg, newTestResolver("team-budget", nil))
			gw.budgetEnforcer = fakeTeamBudget{err: budget.ErrBudgetExceeded}

			rec := postR105(t, gw, fam.path, fam.body, nil)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if errorType(t, rec) != "budget_exceeded" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("budget-refused request reached upstream %d times", calls.Load())
			}
		})
	}
}

// TestR105_FailureThenRetrySucceeds (card step 4, "повтор операции"): after
// an upstream 5xx failure the immediate retry against the recovered upstream
// completes normally — the failure path leaves no poisoned state, and both
// requests together see exactly two upstream calls (one per request, no
// hidden retry that could double-charge).
func TestR105_FailureThenRetrySucceeds(t *testing.T) {
	for _, fam := range r105Families("") {
		t.Run(fam.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if n == 1 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":{"message":"upstream exploded"}}`))
					return
				}
				fam.respond(w, n)
			}))
			defer server.Close()

			gw := r105TestGateway(t, withURL(fam.model, server.URL))
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }

			first := postR105(t, gw, fam.path, fam.body, nil)
			if first.Code != http.StatusBadGateway {
				t.Fatalf("first status %d %s", first.Code, first.Body.String())
			}
			if ev != nil {
				t.Fatalf("failed request published an event: %+v", ev)
			}

			ev = nil
			second := postR105(t, gw, fam.path, fam.body, nil)
			if second.Code != http.StatusOK {
				t.Fatalf("retry status %d %s", second.Code, second.Body.String())
			}
			if ev == nil || ev.EventType != "request.completed" {
				t.Fatalf("retry settled no completed event: %+v", ev)
			}
			if calls.Load() != 2 {
				t.Fatalf("upstream called %d times, want 2 (one per client request, no hidden retry)", calls.Load())
			}
		})
	}
}

// withURL returns a copy of the family model pointed at the test upstream.
func withURL(info resolver.ModelInfo, upstreamURL string) resolver.ModelInfo {
	info.UpstreamURL = upstreamURL
	return info
}
