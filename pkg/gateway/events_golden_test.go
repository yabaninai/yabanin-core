package cli

// surface of the eventpub.Event every endpoint publishes, BEFORE the unified
// event builder + finishRequest consolidation lands. Each test drives the
// real production handler with an httptest upstream and captures the event
// through observeEvent (the funnel publishEvent calls synchronously before
// its detached publish goroutine). Timing fields (duration_ms,
// first_token_ms) are compared zeroed; everything else must match verbatim.
//
// A diff in these tests after the refactor is a behavior change, not a
// refactor — update production, never these expectations, to go green.
//
// Exception (N07-P01-T04, 2026-10-31): the card deliberately changed the
// upstream payload bytes (RawMessage model override preserves consumer key
// order and value literals instead of the float64 round-trip normalization).
// The UpstreamPayload expectations are derived from the same helper
// production uses, so they were switched from upstream.OverrideModel to
// upstream.OverrideModelRaw — a documented behavior change, not a silent
// golden edit.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/shadow"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// --- capture + compare helpers ------------------------------------------------

// goldenCapture records every event the publishEvent funnel observes. The
// observer fires synchronously in the caller goroutine; the shadow dispatcher
// publishes from its own goroutine, so access is mutex-guarded. Every add
// also signals notify (non-blocking), so tests can wait for a count of
// events instead of polling.
type goldenCapture struct {
	mu     sync.Mutex
	evs    []*eventpub.Event
	notify chan struct{}
}

func (c *goldenCapture) add(ev *eventpub.Event) {
	c.mu.Lock()
	cp := *ev
	c.evs = append(c.evs, &cp)
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *goldenCapture) last(t *testing.T) *eventpub.Event {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.evs, "expected at least one captured event")
	return c.evs[len(c.evs)-1]
}

func (c *goldenCapture) all() []*eventpub.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*eventpub.Event(nil), c.evs...)
}

// waitFor waits (bounded) for n captured events; every add signals the
// capture's channel, so no polling or fixed sleeps are needed.
func (c *goldenCapture) waitFor(t *testing.T, n int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		if len(c.all()) >= n {
			return
		}
		select {
		case <-c.notify:
		case <-timer.C:
			t.Fatalf("only %d of %d expected events arrived", len(c.all()), n)
		}
	}
}

// captureAll installs the event observer for the test and restores it on
// cleanup.
func captureAll(t *testing.T) *goldenCapture {
	t.Helper()
	c := &goldenCapture{notify: make(chan struct{}, 16)}
	t.Cleanup(observeEvent(c.add))
	return c
}

// goldenEvent compares the captured event with the want template. duration_ms
// and first_token_ms are clock-derived and are zeroed on both sides; the
// volatile callback asserts their ranges plus any prefix-shaped fields.
func goldenEvent(t *testing.T, name string, got, want *eventpub.Event, volatile func(t *testing.T, ev *eventpub.Event)) {
	t.Helper()
	require.NotNil(t, got, "%s: no event captured", name)
	g, w := *got, *want
	g.DurationMs, w.DurationMs = 0, 0
	g.FirstTokenMs, w.FirstTokenMs = 0, 0
	if w.Error == "SENTINEL" {
		// Prefix-shaped errors are asserted in the volatile callback.
		w.Error = g.Error
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s: golden event drifted\n got: %+v\nwant: %+v", name, g, w)
	}
	if volatile != nil {
		volatile(t, got)
	}
}

// FIX-20 (2026-11-02): the events gained the processed, client-facing
// response envelope (eventBase.ProcessedResponse → wire processed_response)
// — a deliberate, documented behavior change, not a silent golden edit.
// The expectations below are derived from the SAME production helpers the
// handlers use (envelopeFromCompletionDoc for JSON/cache-hit bodies,
// responseHistoryCapture for SSE), so producer drift still fails here.

func goldenProcessedFromDoc(t *testing.T, doc []byte, model string) string {
	t.Helper()
	return envelopeFromCompletionDoc(doc, model).marshal()
}

func goldenProcessedFromSSE(t *testing.T, sse, status, reason string) string {
	t.Helper()
	c := newResponseHistoryCapture(httptest.NewRecorder())
	_, _ = c.Write([]byte(sse))
	return c.finishEnvelope(status, reason).marshal()
}

// goldenChatGateway wires the full chat pipeline (streamTestGateway base) to a
// resolved "gpt-4o" candidate on the given upstream.
func goldenChatGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.res = stubModelResolver{
		"gpt-4o": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true},
	}
	return gw
}

// goldenIdentity sets the full trusted-identity header set the pipelines read.
func goldenIdentity(r *http.Request) {
	r.Header.Set("X-Org-Id", "org-g1")
	r.Header.Set("X-Team-Id", "team-g1")
	r.Header.Set("X-API-Key-Id", "key-g1")
	r.Header.Set("X-Session-Id", "sess-g1")
	r.Header.Set("X-Session-Key-Id", "ybs-g1")
	r.Header.Set("X-Agent-Id", "agent-g1")
	r.Header.Set("X-User-Id", "user-g1")
	r.Header.Set("X-Yabanin-Task", "task-g1")
}

// goldenBudgetExceeded is a teamBudgetChecker/agentBudgetChecker double.
type goldenBudgetEnforcer struct{ err error }

func (b goldenBudgetEnforcer) CheckBudget(context.Context, string) error { return b.err }

func (b goldenBudgetEnforcer) CheckAgentBudget(context.Context, string) error { return b.err }

const goldenChatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"golden-chat"}]}`

const goldenChatUsage = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_tokens_details":{"cached_tokens":30}}}`

// goldenChatCost is the deterministic price of goldenChatUsage on gpt-4o.
func goldenChatCost() float64 {
	return provider.ComputeCost(provider.Usage{
		PromptTokens:     100,
		CompletionTokens: 5,
		TotalTokens:      105,
		CacheReadTokens:  30,
		Source:           provider.UsageSourceProvider,
	}, "openai", "gpt-4o").EstimatedCostUSD
}

// --- chat JSON: request.completed ---------------------------------------------

func TestGoldenEvent_ChatJSON_Completed(t *testing.T) {
	var sentUpstream []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sentUpstream = append([]byte(nil), raw...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat json completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		RequestID:                  "",
		SessionID:                  "sess-g1",
		Payload:                    goldenChatBody,
		UpstreamPayload:            string(upstream.OverrideModelRaw([]byte(goldenChatBody), "gpt-4o")),
		UpstreamResponse:           goldenChatUsage,
		ProcessedResponse:          goldenProcessedFromDoc(t, []byte(goldenChatUsage), "gpt-4o"),
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   100,
		TokensOut:                  5,
		CacheReadTokens:            30,
		CacheCreationTokens:        0,
		EstimatedCostUSD:           goldenChatCost(),
		Endpoint:                   "chat.completions",
		UsageSource:                "provider",
		CostStatus:                 "priced",
		ResaleCostUSD:              0,
		Method:                     "POST",
		CounterfactualCostUSD:      goldenChatCost(),
		TierUsed:                   "",
		ClassifierClass:            "",
		ClassifierConfidence:       0,
		ClassifierSource:           "",
		RoutingDecision:            "",
		AttemptCount:               1,
		RetryCount:                 0,
		Labels:                     map[string]string{},
		InferenceRegion:            "",
		ModelOriginCountry:         "openai",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "openai",
		Reservations:               "",
		Termination:                "",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		assert.Equal(t, string(sentUpstream), ev.UpstreamPayload,
			"upstream_payload is the model-overridden body actually forwarded")
	})
}

// --- chat SSE: request.completed ----------------------------------------------

const goldenSSEFixture = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n" +
	"data: [DONE]\n\n"

func TestGoldenEvent_ChatSSE_Completed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, goldenSSEFixture)
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	cap := captureAll(t)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"golden-sse"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	// serveStream reads APIKeyID/SessionKeyID from the principal (not headers).
	r = r.WithContext(withPrincipal(r.Context(), principal{APIKeyID: "key-g1", SessionKeyID: "ybs-g1"}))
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat sse completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		RequestID:                  "",
		SessionID:                  "sess-g1",
		Payload:                    "",
		UpstreamPayload:            string(upstream.OverrideModelRaw([]byte(body), "gpt-4o")),
		UpstreamResponse:           goldenSSEFixture,
		ProcessedResponse:          goldenProcessedFromSSE(t, goldenSSEFixture, responseHistoryStatusComplete, ""),
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "",
		UserID:                     "",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   7,
		TokensOut:                  3,
		EstimatedCostUSD:           provider.ComputeCost(provider.Usage{PromptTokens: 7, CompletionTokens: 3, TotalTokens: 10, Source: provider.UsageSourceProvider}, "openai", "gpt-4o").EstimatedCostUSD,
		Endpoint:                   "chat.completions",
		UsageSource:                "provider",
		CostStatus:                 "priced",
		CounterfactualCostUSD:      provider.ComputeCost(provider.Usage{PromptTokens: 7, CompletionTokens: 3, TotalTokens: 10, Source: provider.UsageSourceProvider}, "openai", "gpt-4o").EstimatedCostUSD,
		ResaleCostUSD:              0,
		Method:                     "POST",
		TierUsed:                   "",
		RoutingDecision:            "",
		AttemptCount:               1,
		RetryCount:                 0,
		Labels:                     map[string]string{},
		InferenceRegion:            "",
		ModelOriginCountry:         "",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "",
	}, nil)
}

// --- chat JSON: upstream exhausted → request.failed ---------------------------

func TestGoldenEvent_ChatJSON_UpstreamFailed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat json upstream failed", ev, &eventpub.Event{
		EventType:                  "request.failed",
		Source:                     "gateway",
		RequestID:                  "",
		SessionID:                  "sess-g1",
		Payload:                    goldenChatBody,
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "",
		UpstreamURL:                up.URL,
		StatusCode:                 500,
		TokensIn:                   0,
		TokensOut:                  0,
		Endpoint:                   "chat.completions",
		UsageSource:                "none",
		CostStatus:                 "no_usage",
		Method:                     "POST",
		Error:                      "SENTINEL",
		TierUsed:                   "",
		AttemptCount:               1,
		RetryCount:                 0,
		Labels:                     map[string]string{},
		InferenceRegion:            "",
		ModelOriginCountry:         "",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		assert.Contains(t, ev.Error, "upstream error 500",
			"error carries the upstream failure: %q", ev.Error)
		assert.Empty(t, ev.UpstreamPayload, "the JSON failure event carries no captures")
		assert.Empty(t, ev.UpstreamResponse)
	})
}

// --- chat cache hit: exact + semantic provenance -------------------------------

const goldenCachedDoc = `{"id":"cached","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`

func TestGoldenEvent_CacheHit_Exact(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a cache hit must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	c := newRT05Cache()
	gw.cache = c
	warmBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"golden-cache"}]}`
	require.NoError(t, c.Write(context.Background(),
		rt05WarmRI(gw, "org-g1", "gpt-4o"),
		[]byte(warmBody), json.RawMessage(goldenCachedDoc), 3, 2))
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(warmBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
	ev := cap.last(t)
	goldenEvent(t, "cache hit exact", ev, &eventpub.Event{
		EventType:             "request.completed",
		Source:                "gateway",
		RequestID:             "",
		SessionID:             "sess-g1",
		Payload:               warmBody,
		OrgID:                 "org-g1",
		TeamID:                "team-g1",
		ModelRequested:        "gpt-4o",
		ModelUsed:             "gpt-4o",
		UpstreamURL:           up.URL,
		StatusCode:            200,
		DurationMs:            0,
		TokensIn:              0,
		TokensOut:             0,
		CacheReadTokens:       0,
		CacheCreationTokens:   0,
		EstimatedCostUSD:      0,
		Endpoint:              "chat.completions",
		UsageSource:           "none",
		CostStatus:            "cache_hit",
		Method:                "POST",
		CacheHitType:          "exact",
		CacheSimilarity:       1,
		ProcessedResponse:     goldenProcessedFromDoc(t, []byte(goldenCachedDoc), "gpt-4o"),
		CounterfactualCostUSD: provider.ComputeCost(provider.Usage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5}, "openai", "gpt-4o").EstimatedCostUSD,
		TierUsed:              "",
		RoutingDecision:       "",
		Labels:                map[string]string{},
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		assert.Positive(t, ev.CounterfactualCostUSD,
			"the hit counterfactual prices the cached usage as if it went upstream")
		// Nothing else may be set: no upstream captures, no attempt counts.
		assert.Zero(t, ev.AttemptCount)
		assert.Zero(t, ev.RetryCount)
		assert.Empty(t, ev.UpstreamPayload)
		assert.Empty(t, ev.UpstreamResponse)
	})
}

func TestGoldenEvent_CacheHit_Semantic(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a cache hit must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.cache = &rt07SemanticCache{rt05Cache: func() *rt05Cache {
		c := newRT05Cache()
		warmBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"golden-semantic"}]}`
		require.NoError(t, c.Write(context.Background(),
			rt05WarmRI(gw, "org-g1", "gpt-4o"),
			[]byte(warmBody), json.RawMessage(goldenCachedDoc), 3, 2))
		return c
	}()}
	cap := captureAll(t)

	warmBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"golden-semantic"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(warmBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "SEMANTIC", rec.Header().Get("X-Cache"))
	ev := cap.last(t)
	goldenEvent(t, "cache hit semantic", ev, &eventpub.Event{
		EventType:             "request.completed",
		Source:                "gateway",
		SessionID:             "sess-g1",
		Payload:               warmBody,
		OrgID:                 "org-g1",
		TeamID:                "team-g1",
		ModelRequested:        "gpt-4o",
		ModelUsed:             "gpt-4o",
		UpstreamURL:           up.URL,
		StatusCode:            200,
		Endpoint:              "chat.completions",
		UsageSource:           "none",
		CostStatus:            "cache_hit",
		Method:                "POST",
		CacheHitType:          "semantic",
		CacheSimilarity:       0.92,
		ProcessedResponse:     goldenProcessedFromDoc(t, []byte(goldenCachedDoc), "gpt-4o"),
		CounterfactualCostUSD: provider.ComputeCost(provider.Usage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5}, "openai", "gpt-4o").EstimatedCostUSD,
		Labels:                map[string]string{},
	}, nil)
}

// --- chat admission events: invalid / unknown-model reject / budget -----------

func TestGoldenEvent_Chat_ValidatorInvalid(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an invalid request must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	cap := captureAll(t)

	body := `{"model":"gpt-4o"}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat validator invalid", ev, &eventpub.Event{
		EventType:      "request.invalid",
		Source:         "gateway",
		SessionID:      "sess-g1",
		Payload:        body,
		OrgID:          "org-g1",
		TeamID:         "team-g1",
		ModelRequested: "gpt-4o",
		Error:          "messages is required",
		Labels:         map[string]string{"workload": "agent:agent-g1"},
	}, nil)
}

func TestGoldenEvent_Chat_UnknownModelReject(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a rejected unknown model must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.unknownModelPolicy = "reject"
	gw.res = stubModelResolver{
		"ghost": {ModelName: "fb-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true, Fallback: true},
	}
	cap := captureAll(t)

	body := `{"model":"ghost","messages":[{"role":"user","content":"golden-ghost"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat unknown model reject", ev, &eventpub.Event{
		EventType:      "request.invalid",
		Source:         "gateway",
		SessionID:      "sess-g1",
		Payload:        body,
		OrgID:          "org-g1",
		TeamID:         "team-g1",
		ModelRequested: "ghost",
		Error:          `model "ghost" is not available on this gateway`,
		Labels:         map[string]string{},
	}, nil)
}

func TestGoldenEvent_Chat_BudgetExceeded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a budget-denied request must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.budgetEnforcer = goldenBudgetEnforcer{err: budget.ErrBudgetExceeded}
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	ev := cap.last(t)
	goldenEvent(t, "chat budget exceeded", ev, &eventpub.Event{
		EventType:      "request.budget_exceeded",
		Source:         "gateway",
		SessionID:      "sess-g1",
		Payload:        goldenChatBody,
		OrgID:          "org-g1",
		TeamID:         "team-g1",
		UserID:         "user-g1",
		ModelRequested: "gpt-4o",
		Error:          "team budget exceeded",
		Labels:         map[string]string{"workload": "agent:agent-g1"},
	}, nil)
}

// --- chat SSE: connection failure + idle-timeout drain failure -----------------

func TestGoldenEvent_ChatSSE_ConnectionFailed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	up.Close() // connection refused

	gw := goldenChatGateway(t, up.URL)
	cap := captureAll(t)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"golden-sse-down"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-g1")
	r.Header.Set("X-Team-Id", "team-g1")
	r.Header.Set("X-Session-Id", "sess-g1")
	r = r.WithContext(withPrincipal(r.Context(), principal{APIKeyID: "key-g1", SessionKeyID: "ybs-g1"}))
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	out := rec.Body.String()
	assert.Contains(t, out, `"error"`, "the connection failure surfaces as a terminal SSE error frame")
	assert.NotContains(t, out, `"delta"`, "no content frames may follow a connection failure")
	ev := cap.last(t)
	goldenEvent(t, "chat sse connection failed", ev, &eventpub.Event{
		EventType:                  "request.failed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		Payload:                    "",
		UpstreamPayload:            string(upstream.OverrideModelRaw([]byte(body), "gpt-4o")),
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 0,
		Endpoint:                   "chat.completions",
		UsageSource:                "none",
		CostStatus:                 "no_usage",
		Method:                     "POST",
		Error:                      "SENTINEL",
		AttemptCount:               1,
		RetryCount:                 0,
		Labels:                     map[string]string{},
		InferenceRegion:            "",
		ModelOriginCountry:         "",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		assert.True(t, strings.HasPrefix(ev.Error, "upstream stream failed: "),
			"error carries the connection failure: %q", ev.Error)
	})
}

func TestChatJSON_UnknownTransportOutcomeStopsRetryAndFallback(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		fallbackCalls.Add(1)
	}))
	defer fallback.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close() // request body arrived; response was lost
		}
	}))
	defer primary.Close()

	gw := streamTestGateway(primary.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 3, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}
	gw.res = stubModelResolver{
		"gpt-4o":   {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: primary.URL, Enabled: true, FailoverModels: []string{"fallback"}},
		"fallback": {ModelName: "fallback", Provider: "openai", UpstreamURL: fallback.URL, Enabled: true},
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "outcome unknown")
	assert.Equal(t, int32(1), primaryCalls.Load(), "unknown outcome must not retry the primary")
	assert.Zero(t, fallbackCalls.Load(), "unknown outcome must not invoke provider fallback")
}

func TestGoldenEvent_ChatSSE_IdleTimeout_DrainFailed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Real-timeout stall: the silent stretch must comfortably outlast the
		// 60ms idle timeout below so the abort wins the race against [DONE].
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.streamIdleTimeout = 60 * time.Millisecond
	cap := captureAll(t)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"golden-idle"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-g1")
	r.Header.Set("X-Team-Id", "team-g1")
	r.Header.Set("X-Session-Id", "sess-g1")
	r = r.WithContext(withPrincipal(r.Context(), principal{APIKeyID: "key-g1", SessionKeyID: "ybs-g1"}))
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "upstream stream idle timeout")
	ev := cap.last(t)
	// prefix as the byte estimate — prompt from the guarded body, completion
	// from the delta bytes actually streamed ("half").
	prompt := int64((len(upstream.OverrideModel([]byte(body), "gpt-4o")) + 3) / 4)
	estimated := provider.Usage{PromptTokens: prompt, CompletionTokens: 1, TotalTokens: prompt + 1, Source: provider.UsageSourceEstimated}
	goldenCost := provider.ComputeCost(estimated, "openai", "gpt-4o").EstimatedCostUSD
	goldenEvent(t, "chat sse idle timeout drain failed", ev, &eventpub.Event{
		EventType:                  "request.failed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		Payload:                    "",
		UpstreamPayload:            string(upstream.OverrideModelRaw([]byte(body), "gpt-4o")),
		UpstreamResponse:           "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half\"}}]}\n\n",
		ProcessedResponse:          goldenProcessedFromSSE(t, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half\"}}]}\n\n", responseHistoryStatusPartial, responseHistoryReasonIdleTimeout),
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		Endpoint:                   "chat.completions",
		TokensIn:                   prompt,
		TokensOut:                  1,
		EstimatedCostUSD:           goldenCost,
		CounterfactualCostUSD:      goldenCost,
		UsageSource:                "estimated",
		CostStatus:                 "priced",
		Method:                     "POST",
		Error:                      "upstream stream idle timeout",
		AttemptCount:               1,
		RetryCount:                 0,
		Labels:                     map[string]string{},
		InferenceRegion:            "",
		ModelOriginCountry:         "",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		assert.Positive(t, ev.DurationMs)
	})
}

// --- completions ----------------------------------------------------------------

const goldenCompletionsUpstream = `{"id":"cmpl","object":"text_completion","choices":[{"index":0,"text":"ok","finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`

func goldenPost(t *testing.T, gw *gateway, handler func(w http.ResponseWriter, r *http.Request), path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	handler(rec, r)
	return rec
}

func TestGoldenEvent_Completions_Completed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenCompletionsUpstream))
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.res = stubModelResolver{
		"alias-c": {ModelName: "fim-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.completions, "/v1/completions", `{"model":"alias-c","prompt":"hi","max_tokens":8}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "completions completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		Payload:                    `{"model":"alias-c","prompt":"hi","max_tokens":8}`,
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "alias-c",
		ModelUsed:                  "fim-model",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   4,
		TokensOut:                  1,
		Endpoint:                   "completions",
		UsageSource:                "provider",
		CostStatus:                 "unknown_price",
		Method:                     "POST",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "openai",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "openai",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		// This pipeline captures neither the upstream payload nor a
		// counterfactual and reports no chain attempt counts.
		assert.Empty(t, ev.UpstreamPayload)
		assert.Empty(t, ev.UpstreamResponse)
		assert.Zero(t, ev.CounterfactualCostUSD)
		assert.Zero(t, ev.AttemptCount)
		assert.Zero(t, ev.RetryCount)
	})
}

// --- embeddings -----------------------------------------------------------------

func TestGoldenEvent_Embeddings_Completed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[],"model":"emb-model","usage":{"prompt_tokens":2,"total_tokens":2}}`))
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.res = stubModelResolver{
		"emb": {ModelName: "emb-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.embeddings, "/v1/embeddings", `{"model":"emb","input":"hi"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "embeddings completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		Payload:                    `{"model":"emb","input":"hi"}`,
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "emb",
		ModelUsed:                  "emb-model",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   2,
		TokensOut:                  0,
		Endpoint:                   "embeddings",
		UsageSource:                "provider",
		CostStatus:                 "unknown_price",
		Method:                     "POST",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "openai",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "openai",
	}, nil)
}

// --- embeddings admission events: unknown reject + budget (non-chat shape) ------

func TestGoldenEvent_Admission_UnknownModelReject_NoChatPath(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a rejected unknown model must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.unknownModelPolicy = "reject"
	gw.res = stubModelResolver{
		"ghost": {ModelName: "fb-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true, Fallback: true},
	}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.embeddings, "/v1/embeddings", `{"model":"ghost","input":"hi"}`)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "admission unknown model reject", ev, &eventpub.Event{
		EventType:      "request.invalid",
		Source:         "gateway",
		SessionID:      "sess-g1",
		Payload:        `{"model":"ghost","input":"hi"}`,
		OrgID:          "org-g1",
		TeamID:         "team-g1",
		ModelRequested: "ghost",
		Error:          `model "ghost" is not available on this gateway`,
		Labels:         map[string]string{},
	}, nil)
}

func TestGoldenEvent_Admission_BudgetExceeded_NoUserID(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a budget-denied request must not reach the provider")
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.budgetEnforcer = goldenBudgetEnforcer{err: budget.ErrBudgetExceeded}
	gw.res = stubModelResolver{
		"alias-e": {ModelName: "target-e", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.embeddings, "/v1/embeddings", `{"model":"alias-e","input":"hi"}`)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "admission budget exceeded", ev, &eventpub.Event{
		EventType:      "request.budget_exceeded",
		Source:         "gateway",
		SessionID:      "sess-g1",
		Payload:        `{"model":"alias-e","input":"hi"}`,
		OrgID:          "org-g1",
		TeamID:         "team-g1",
		UserID:         "",
		ModelRequested: "target-e",
		Error:          "team budget exceeded",
		Labels:         map[string]string{"workload": "agent:agent-g1"},
	}, nil)
}

// --- native messages --------------------------------------------------------------

const goldenAnthropicOK = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022",` +
	`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
	`"usage":{"input_tokens":11,"output_tokens":4,"cache_read_input_tokens":6,"cache_creation_input_tokens":2}}`

func TestGoldenEvent_MessagesNative_Completed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenAnthropicOK))
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.res = stubModelResolver{
		"claude": {ModelName: "claude-3-5-sonnet-20241022", Provider: "anthropic", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	body := `{"model":"claude","max_tokens":16,"messages":[{"role":"user","content":"golden-anthropic"}]}`
	rec := goldenPost(t, gw, gw.messages, "/v1/messages", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The Anthropic adapter folds cache tokens into PromptTokens
	// (input + cache_read + cache_creation = 11 + 6 + 2).
	usage := provider.Anthropic{}.ParseUsage([]byte(goldenAnthropicOK))
	require.Equal(t, int64(19), usage.PromptTokens)
	ev := cap.last(t)
	goldenEvent(t, "messages native completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		Payload:                    "",
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "claude",
		ModelUsed:                  "claude-3-5-sonnet-20241022",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   usage.PromptTokens,
		TokensOut:                  usage.CompletionTokens,
		CacheReadTokens:            6,
		CacheCreationTokens:        2,
		EstimatedCostUSD:           provider.ComputeCost(usage, "anthropic", "claude-3-5-sonnet-20241022").EstimatedCostUSD,
		Endpoint:                   "messages",
		UsageSource:                "provider",
		CostStatus:                 "priced",
		Method:                     "POST",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "anthropic",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "anthropic",
	}, nil)
}

func TestGoldenEvent_MessagesNative_UpstreamFailed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`))
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.res = stubModelResolver{
		"claude": {ModelName: "claude-3-5-sonnet-20241022", Provider: "anthropic", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.messages, "/v1/messages", `{"model":"claude","max_tokens":16,"messages":[{"role":"user","content":"golden-anthropic-bad"}]}`)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "messages native upstream failed", ev, &eventpub.Event{
		EventType:                  "request.failed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "claude",
		ModelUsed:                  "claude-3-5-sonnet-20241022",
		UpstreamURL:                up.URL,
		StatusCode:                 400,
		Endpoint:                   "messages",
		UsageSource:                "none",
		CostStatus:                 "no_usage",
		Method:                     "POST",
		Error:                      "upstream request failed",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "anthropic",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "anthropic",
	}, nil)
}

// --- native responses --------------------------------------------------------------

func TestGoldenEvent_ResponsesNative_Completed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","model":"gpt-4o","output":[],"usage":{"input_tokens":9,"output_tokens":2,"input_tokens_details":{"cached_tokens":3}}}`))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.responses, "/v1/responses", `{"model":"gpt-4o","input":"hi"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	usage := provider.Usage{PromptTokens: 9, CompletionTokens: 2, CacheReadTokens: 3, Source: provider.UsageSourceProvider}
	ev := cap.last(t)
	goldenEvent(t, "responses native completed", ev, &eventpub.Event{
		EventType:                  "request.completed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 200,
		TokensIn:                   9,
		TokensOut:                  2,
		CacheReadTokens:            3,
		EstimatedCostUSD:           provider.ComputeCost(usage, "openai", "gpt-4o").EstimatedCostUSD,
		Endpoint:                   "responses",
		UsageSource:                "provider",
		CostStatus:                 "priced",
		Method:                     "POST",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "openai",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "openai",
	}, nil)
}

func TestGoldenEvent_ResponsesNative_UpstreamFailed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream boom"}}`))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	cap := captureAll(t)

	rec := goldenPost(t, gw, gw.responses, "/v1/responses", `{"model":"gpt-4o","input":"hi"}`)
	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())

	ev := cap.last(t)
	goldenEvent(t, "responses native upstream failed", ev, &eventpub.Event{
		EventType:                  "request.failed",
		Source:                     "gateway",
		SessionID:                  "sess-g1",
		OrgID:                      "org-g1",
		TeamID:                     "team-g1",
		AgentID:                    "agent-g1",
		UserID:                     "user-g1",
		APIKeyID:                   "key-g1",
		SessionKeyID:               "ybs-g1",
		TaskID:                     "task-g1",
		ModelRequested:             "gpt-4o",
		ModelUsed:                  "gpt-4o",
		UpstreamURL:                up.URL,
		StatusCode:                 502,
		Endpoint:                   "responses",
		UsageSource:                "none",
		CostStatus:                 "no_usage",
		Method:                     "POST",
		Error:                      "upstream request failed",
		Labels:                     map[string]string{"workload": "agent:agent-g1"},
		InferenceRegion:            "",
		ModelOriginCountry:         "openai",
		LogStorageRegion:           "",
		ProviderEntityJurisdiction: "openai",
	}, nil)
}

// --- MCP / A2A audit surfaces -------------------------------------------------------

func TestGoldenEvent_MCPAudit_FullSurface(t *testing.T) {
	ok := mcpAuditEvent(mcpagg.AuditEvent{
		OrgID:          "org-m",
		AgentID:        "agent-m",
		ServerName:     "srv",
		Tool:           "weather",
		ParamsRedacted: json.RawMessage(`{"city":"x"}`),
		LatencyMS:      12,
		Outcome:        mcpagg.OutcomeOK,
		UpstreamStatus: 200,
		RequestID:      "req-m",
		TaskID:         "task-m",
		TeamID:         "team-m",
		UpstreamURL:    "https://mcp.example.com",
	})
	goldenEvent(t, "mcp audit ok", ok, &eventpub.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      "req-m",
		OrgID:          "org-m",
		TeamID:         "team-m",
		ModelRequested: "mcp",
		ModelUsed:      "mcp:srv:weather",
		UpstreamURL:    "https://mcp.example.com",
		StatusCode:     200,
		DurationMs:     12,
		Method:         "POST",
		AgentID:        "agent-m",
		TaskID:         "task-m",
		Payload:        `{"city":"x"}`,
	}, nil)

	failed := mcpAuditEvent(mcpagg.AuditEvent{
		OrgID:          "org-m",
		AgentID:        "agent-m",
		ServerName:     "srv",
		Tool:           "weather",
		LatencyMS:      5,
		Outcome:        mcpagg.OutcomeUpstreamError,
		UpstreamStatus: 500,
		RequestID:      "req-m2",
		TeamID:         "team-m",
	})
	goldenEvent(t, "mcp audit failed", failed, &eventpub.Event{
		EventType:      "request.failed",
		Source:         "gateway",
		RequestID:      "req-m2",
		OrgID:          "org-m",
		TeamID:         "team-m",
		ModelRequested: "mcp",
		ModelUsed:      "mcp:srv:weather",
		StatusCode:     500,
		DurationMs:     5,
		Method:         "POST",
		AgentID:        "agent-m",
		Error:          "mcp:upstream_error (upstream 500)",
	}, nil)
}

func TestGoldenEvent_A2AAudit_FullSurface(t *testing.T) {
	ok := a2aAuditEvent(a2aagg.AuditEvent{
		OrgID:          "org-a2",
		AgentID:        "agent-a2",
		TeamID:         "team-a2",
		RequestID:      "req-a2",
		TaskID:         "task-a2",
		TargetName:     "peer",
		ParamsRedacted: json.RawMessage(`{"msg":"hi"}`),
		LatencyMS:      7,
		Outcome:        a2aagg.OutcomeOK,
		UpstreamStatus: 200,
		UpstreamURL:    "https://a2a.example.com",
	})
	goldenEvent(t, "a2a audit ok", ok, &eventpub.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      "req-a2",
		OrgID:          "org-a2",
		TeamID:         "team-a2",
		ModelRequested: "a2a",
		ModelUsed:      "a2a:peer",
		UpstreamURL:    "https://a2a.example.com",
		StatusCode:     200,
		DurationMs:     7,
		Method:         "POST",
		AgentID:        "agent-a2",
		TaskID:         "task-a2",
		Payload:        `{"msg":"hi"}`,
	}, nil)
}

// --- shadow exclusion ----------------------------------------------------------------

// TestGoldenEvent_Shadow_ExcludedFromPrimary: the primary request's event
// stays a plain request.completed (no ab_group, no shadow cost), and the
// mirror publishes its own request.shadow_completed with ab_group="shadow"
// through the same funnel — the shadow never bleeds into primary attribution.
func TestGoldenEvent_Shadow_ExcludedFromPrimary(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(primary.Close)
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(mirror.Close)

	gw := goldenChatGateway(t, primary.URL)
	sc := config.Shadow{
		// The dispatcher skips mirroring onto the same model (SkipSameModel),
		// so the shadow target differs from the primary.
		Enabled: true, Model: "gpt-4o-mini", UpstreamURL: mirror.URL, APIKey: "shadow-key",
		SampleRate: 1.0, Timeout: "5s", MaxConcurrent: 4,
	}
	vcfg, err := shadow.Config{
		Enabled: true, Model: sc.Model, UpstreamURL: sc.UpstreamURL, APIKey: sc.APIKey,
		SampleRate: sc.SampleRate, Timeout: sc.ShadowTimeout(), MaxConcurrent: sc.MaxConcurrent,
	}.Validate()
	require.NoError(t, err)
	gw.cfg.Shadow = sc
	gw.shadow = shadow.NewDispatcher(vcfg, testLogger())
	gw.shadow.SetPinnedOrgFunc(func(context.Context, string) bool { return false })

	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-g1")
	r.Header.Set("X-Session-Id", "sess-g1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The primary event is captured synchronously; the mirror's event arrives
	// from the detached shadow goroutine, which the capture signals.
	cap.waitFor(t, 2)
	evs := cap.all()
	require.Len(t, evs, 2, "exactly the primary event and one shadow event")

	var primaryEv, shadowEv *eventpub.Event
	for _, ev := range evs {
		switch ev.EventType {
		case "request.completed":
			primaryEv = ev
		case "request.shadow_completed":
			shadowEv = ev
		}
	}
	require.NotNil(t, primaryEv, "the primary event stays request.completed")
	require.NotNil(t, shadowEv, "the mirror publishes request.shadow_completed")

	assert.Empty(t, primaryEv.ABGroup, "the primary event carries no shadow marker")
	// OP-8 Policy field must stay empty on BOTH events. The populated pin
	// golden (services/loggerd/consumer/policy_decisions_test.go) and the
	// producer-side TestEventPolicyContractShape round-trip.
	assert.Empty(t, primaryEv.Policy, "no pipeline evaluated: the primary event carries no policy payload")

	// buildShadowJob rewrites the body via map marshal (sorted keys): the
	// shadow model forced in and stream:false.
	shadowBody, mErr := json.Marshal(map[string]interface{}{
		"model":    "gpt-4o-mini",
		"stream":   false,
		"messages": []map[string]string{{"role": "user", "content": "golden-chat"}},
	})
	require.NoError(t, mErr)

	goldenEvent(t, "shadow event", shadowEv, &eventpub.Event{
		EventType:        "request.shadow_completed",
		Source:           "gateway",
		SessionID:        "sess-g1",
		Payload:          string(shadowBody),
		OrgID:            "org-g1",
		ModelRequested:   "gpt-4o",
		ModelUsed:        "gpt-4o-mini",
		StatusCode:       200,
		TokensIn:         100,
		TokensOut:        5,
		CacheReadTokens:  30,
		EstimatedCostUSD: provider.ComputeCost(provider.Usage{PromptTokens: 100, CompletionTokens: 5, TotalTokens: 105, CacheReadTokens: 30, Source: provider.UsageSourceProvider}, "openai", "gpt-4o-mini").EstimatedCostUSD,
		Method:           "POST",
		ABGroup:          "shadow",
		Policy:           "",
	}, func(t *testing.T, ev *eventpub.Event) {
		t.Helper()
		// Shadow exclusion: the mirror carries no cache counterfactual and
		// no endpoint/cost-status admission shape.
		assert.Zero(t, ev.CounterfactualCostUSD)
		assert.Empty(t, ev.Endpoint)
		assert.Empty(t, ev.CostStatus)
		// (policy rides request.completed/request.failed stages only).
		assert.Empty(t, ev.Policy, "the shadow mirror carries no policy payload")
	})
}

// TestGoldenEvent_ContentProfile_LegacyUnchanged: with no profile configured
// profile fields stay empty (the DeepEqual goldens above pin this too; this
// test states the intent explicitly).
func TestGoldenEvent_ContentProfile_LegacyUnchanged(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "") // empty = legacy, deterministic
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev := cap.last(t)
	// The captures' byte-exact shape is pinned by the DeepEqual goldens; this
	// test pins presence.
	assert.JSONEq(t, goldenChatBody, ev.Payload, "legacy keeps the request capture")
	assert.JSONEq(t, goldenChatUsage, ev.UpstreamResponse, "legacy keeps the response capture")
	assert.Empty(t, ev.ContentProfile, "legacy declares no profile on the wire")
	assert.Empty(t, ev.PromptHash, "legacy stamps no digest")
}

// TestGoldenEvent_ContentProfile_MetadataOnly_Sanitizes: under the local
// metadata-only profile the observer sees the sanitized copy — captures
// stripped, digest stamped from the raw body, metadata intact.
func TestGoldenEvent_ContentProfile_MetadataOnly_Sanitizes(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev := cap.last(t)
	assert.Empty(t, ev.Payload)
	assert.Empty(t, ev.UpstreamPayload)
	assert.Empty(t, ev.UpstreamResponse)
	assert.Equal(t, "metadata-only", ev.ContentProfile)
	assert.Equal(t, eventpub.PromptDigest(goldenChatBody), ev.PromptHash,
		"the digest hashes the raw body the profile strips")
	assert.Empty(t, ev.Error, "success keeps error empty — no redaction notice injected")
	// Metadata survives the sanitization.
	assert.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, "org-g1", ev.OrgID)
	assert.Equal(t, "gpt-4o", ev.ModelUsed)
	assert.Equal(t, int64(100), ev.TokensIn)
	assert.Equal(t, int64(5), ev.TokensOut)
}

// TestGoldenEvent_ContentProfile_MetadataOnly_FailedRedactsError: a failed
// request under metadata-only carries the fixed redaction notice — the
// upstream error body never reaches the observer or the stream.
func TestGoldenEvent_ContentProfile_MetadataOnly_FailedRedactsError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom with secret detail"}`))
	}))
	t.Cleanup(up.Close)

	gw := goldenChatGateway(t, up.URL)
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
	ev := cap.last(t)
	assert.Equal(t, eventpub.ContentProfileRedactedError, ev.Error)
	assert.NotContains(t, ev.Error, "boom", "no upstream error content may leak")
	assert.Empty(t, ev.Payload)
	assert.Empty(t, ev.UpstreamPayload)
	assert.Empty(t, ev.UpstreamResponse)
	assert.Equal(t, eventpub.PromptDigest(goldenChatBody), ev.PromptHash)
}

// TestPublishEvent_ContentProfile_CopyOwnership pins the contract's copy
// ownership rule at the funnel: the observer and the publish goroutine get a
// sanitized COPY, and the caller's shared event is never mutated.
func TestPublishEvent_ContentProfile_CopyOwnership(t *testing.T) {
	orig := &eventpub.Event{
		EventType: "request.failed",
		Payload:   `{"secret":"body"}`,
		Error:     `upstream error 500: {"leak":true}`,
		// Wire-declared strict profile alone (no env) must sanitize.
		ContentProfile: "metadata-only",
	}
	cap := captureAll(t)
	publishEvent(nil, testLogger(), orig)

	got := cap.last(t)
	require.NotSame(t, orig, got, "the observer must see a copy, not the caller's event")
	assert.Empty(t, got.Payload)
	assert.Equal(t, eventpub.ContentProfileRedactedError, got.Error)
	assert.Equal(t, eventpub.PromptDigest(`{"secret":"body"}`), got.PromptHash)
	// The caller's event stays raw (byte-exact pin on the raw body).
	rawBody := `{"secret":"body"}`
	assert.Equal(t, rawBody, orig.Payload)
	assert.Equal(t, `upstream error 500: {"leak":true}`, orig.Error)

	t.Run("strictest of local and wire wins", func(t *testing.T) {
		t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "legacy")
		cap := captureAll(t)
		publishEvent(nil, testLogger(), &eventpub.Event{Payload: "x", ContentProfile: "metadata-only"})
		assert.Empty(t, cap.last(t).Payload, "wire strict beats local legacy")

		t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
		cap = captureAll(t)
		publishEvent(nil, testLogger(), &eventpub.Event{Payload: "x", ContentProfile: "legacy"})
		assert.Empty(t, cap.last(t).Payload, "local strict beats wire legacy")
	})
}

// TestGoldenEvent_ContentProfile_ShadowSanitized: the shadow mirror flows
// through the same funnel, so under the metadata-only profile BOTH the
// primary and the mirror events lose their captures and gain the digest of
// their own (rewritten) body.
func TestGoldenEvent_ContentProfile_ShadowSanitized(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(primary.Close)
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(goldenChatUsage))
	}))
	t.Cleanup(mirror.Close)

	gw := goldenChatGateway(t, primary.URL)
	sc := config.Shadow{
		Enabled: true, Model: "gpt-4o-mini", UpstreamURL: mirror.URL, APIKey: "shadow-key",
		SampleRate: 1.0, Timeout: "5s", MaxConcurrent: 4,
	}
	vcfg, err := shadow.Config{
		Enabled: true, Model: sc.Model, UpstreamURL: sc.UpstreamURL, APIKey: sc.APIKey,
		SampleRate: sc.SampleRate, Timeout: sc.ShadowTimeout(), MaxConcurrent: sc.MaxConcurrent,
	}.Validate()
	require.NoError(t, err)
	gw.cfg.Shadow = sc
	gw.shadow = shadow.NewDispatcher(vcfg, testLogger())
	gw.shadow.SetPinnedOrgFunc(func(context.Context, string) bool { return false })

	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(goldenChatBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Org-Id", "org-g1")
	r.Header.Set("X-Session-Id", "sess-g1")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	cap.waitFor(t, 2)
	evs := cap.all()
	require.Len(t, evs, 2)

	shadowBody, mErr := json.Marshal(map[string]interface{}{
		"model":    "gpt-4o-mini",
		"stream":   false,
		"messages": []map[string]string{{"role": "user", "content": "golden-chat"}},
	})
	require.NoError(t, mErr)

	for _, ev := range evs {
		assert.Empty(t, ev.Payload, "%s: shadow funnel strips captures", ev.EventType)
		assert.Empty(t, ev.UpstreamPayload)
		assert.Empty(t, ev.UpstreamResponse)
		assert.Equal(t, "metadata-only", ev.ContentProfile)
		switch ev.EventType {
		case "request.completed":
			assert.Equal(t, eventpub.PromptDigest(goldenChatBody), ev.PromptHash)
		case "request.shadow_completed":
			assert.Equal(t, eventpub.PromptDigest(string(shadowBody)), ev.PromptHash,
				"the mirror hashes its own rewritten body")
			assert.Equal(t, "shadow", ev.ABGroup)
		default:
			t.Fatalf("unexpected event type %q", ev.EventType)
		}
	}
}
