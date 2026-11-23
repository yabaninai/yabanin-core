package cli

// G1 coverage recovery (test-only): behavioral fault-injection tests for the
// uncovered block spans recorded for pkg/gateway/admission.go and
// pkg/gateway/agent_hop_budget.go. Every test drives the real function with
// an independently derived expected effect; no shared helper here mutates
// package state, and none of these tests may run in parallel (the event
// observer and the shared loop budget are process-wide).
//
// One recorded span in agent_hop_budget.go is deliberately NOT covered:
// hopTermination's final `return ""` (666) is dead defensive code — its two
// guards only fall through when budget.ValidTermination rejects the
// completion terminations, but completionTermination only ever returns
// TerminationClientCancel or TerminationCompleted, both valid. Reaching it
// would require a production edit (new termination class), not a test.

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// g1ErrResolver answers every ResolveChecked with an error (registry
// outage) so remap re-resolution fails terminally.
type g1ErrResolver struct{}

func (g1ErrResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	return resolver.ModelInfo{ModelName: name, Enabled: true}
}

func (g1ErrResolver) ResolveChecked(context.Context, string) (resolver.ModelInfo, error) {
	return resolver.ModelInfo{}, errors.New("g1: registry outage")
}

// g1JudgeClientAt wires a budgetedJudgeClient whose model resolver answers
// the given provider and base URL, mirroring the production wiring shape
// (off-mode admission, healthy store, literal target).
func g1JudgeClientAt(t *testing.T, providerName, rawURL string, mut func(*budgetedJudgeClient)) (*budgetedJudgeClient, llmjudge.ChatRequest) {
	t.Helper()
	client := &budgetedJudgeClient{
		pool: upstream.NewPool(upstream.Options{}),
		models: llmjudge.ModelResolverFunc(func(_ context.Context, ref string) (llmjudge.Target, error) {
			return llmjudge.Target{Model: ref, Provider: providerName, UpstreamURL: rawURL}, nil
		}),
		keys:        llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) { return "g1-key", nil }),
		loop:        budget.NewLoopBudget(0, 0),
		log:         judgeHopLogger(t),
		now:         time.Now,
		invocations: &fakeInvocationStore{},
	}
	if mut != nil {
		mut(client)
	}
	return client, judgeHopRequest("gpt-4o-mini")
}

// g1JudgeClientOver is g1JudgeClientAt over a live test server.
func g1JudgeClientOver(t *testing.T, providerName string, h http.Handler, mut func(*budgetedJudgeClient)) (*budgetedJudgeClient, llmjudge.ChatRequest) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return g1JudgeClientAt(t, providerName, srv.URL, mut)
}

// g1BlockFactsStore fronts the healthy fake store, but the first
// RecordTerminalFacts call blocks until the caller's context ends and then
// reports blockErr — the seam that lets the terminal-facts retry ladder
// observe its bounded context expiring mid-backoff.
type g1BlockFactsStore struct {
	fakeInvocationStore
	blockNext atomic.Bool
	blockErr  error
	total     atomic.Int64 // counts every call, including the blocked one
}

func (s *g1BlockFactsStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	s.total.Add(1)
	if s.blockNext.CompareAndSwap(true, false) {
		<-ctx.Done()
		return s.blockErr
	}
	return s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
}

// --- admission.go spans ---

// Span 211-216: a guarded body whose typed projection cannot be rebuilt is
// answered 400 invalid_request_error with the rebuild failure surfaced,
// and nothing else in the core runs.
func TestGWCovG1_AdmissionGuardsRebuildFailureAnswers400(t *testing.T) {
	gw := &gateway{} // no guard hooks wired: applyEgressGuards passes the body through
	rec := httptest.NewRecorder()
	out := &admissionCore{}
	in := admissionCoreInput{
		Body:    []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Rebuild: func([]byte) error { return errors.New("g1: projection rebuild failed") },
	}

	ok := gw.applyAdmissionGuards(rec, judgeHopLogger(t), in, out)

	require.False(t, ok, "an un-rebuildable guarded body must stop the admission core")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, "invalid_request_error", errorType(t, rec))
	require.Contains(t, rec.Body.String(), "malformed JSON: g1: projection rebuild failed")
	require.Equal(t, in.Body, out.Body, "the pass-through guarded body is stamped before the rebuild")
}

// Span 413: an agent with a configured budget that checks clean passes the
// G2 gate with no response written.
func TestGWCovG1_AgentBudgetPassWritesNothing(t *testing.T) {
	gw := &gateway{agentEnforcer: fakeAgentBudget{}} // zero err: budget checks clean
	rec := httptest.NewRecorder()
	out := &admissionCore{AgentID: "agent-g1"}

	ok := gw.checkAgentBudget(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", nil), out)

	require.True(t, ok, "a clean agent budget must admit")
	require.Empty(t, rec.Body.String(), "the pass path writes nothing")
	require.Equal(t, http.StatusOK, rec.Code, "the recorder is untouched on the pass path")
}

// Spans 662-665: a residency remap whose replacement model cannot be
// re-resolved is terminal 503 model_registry_unavailable — never routed on.
func TestGWCovG1_ResidencyRemapResolutionUnavailableAnswers503(t *testing.T) {
	gw := &gateway{
		log: slog.Default(),
		res: g1ErrResolver{},
		residencyEnforcer: fakeResidency{dec: policy.Decision{
			Allowed: true, Region: "SG", RemappedModel: "sg-local-g1",
		}},
	}
	rec := httptest.NewRecorder()
	out := &admitted{
		OrgID: "org-g1",
		Info:  resolver.ModelInfo{ModelName: "gpt-4o-mini", Region: "SG", Provider: "openai"},
	}

	ok := gw.enforceResidency(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", nil), gw.log, out, false)

	require.False(t, ok, "an unresolvable remap candidate must deny the request")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "model_registry_unavailable", errorType(t, rec))
	require.Contains(t, rec.Body.String(), "model registry temporarily unavailable")
}

// Span 672: an allowed decision carrying a real pack stamps both residency
// headers; the sentinel pack "none" never does.
func TestGWCovG1_ResidencyPackHeader(t *testing.T) {
	newCase := func(pack string) (*httptest.ResponseRecorder, bool) {
		gw := &gateway{
			log:               slog.Default(),
			residencyEnforcer: fakeResidency{dec: policy.Decision{Allowed: true, Region: "EU", PackID: pack}},
		}
		rec := httptest.NewRecorder()
		out := &admitted{OrgID: "org-g1", Info: resolver.ModelInfo{ModelName: "m", Region: "EU", Provider: "openai"}}
		ok := gw.enforceResidency(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/embeddings", nil), gw.log, out, false)
		return rec, ok
	}

	rec, ok := newCase("pack-g1-7")
	require.True(t, ok)
	require.Equal(t, "EU", rec.Header().Get("X-Residency-Region"))
	require.Equal(t, "pack-g1-7", rec.Header().Get("X-Residency-Pack"), "a real pack rides the response headers")

	// Negative control: the "none" sentinel is not a pack id.
	recNone, okNone := newCase("none")
	require.True(t, okNone)
	require.Equal(t, "EU", recNone.Header().Get("X-Residency-Region"))
	require.Empty(t, recNone.Header().Values("X-Residency-Pack"), "the none sentinel must not mint a pack header")
}

// --- agent_hop_budget.go spans ---

// Span 131: a nil logger falls back to the process default, never a nil
// pointer that would panic on the settle Debug.
func TestGWCovG1_JudgeClientDefaultLogger(t *testing.T) {
	c, ok := NewBudgetedJudgeClient(nil, nil, nil, nil, nil, nil, nil, nil).(*budgetedJudgeClient)
	require.True(t, ok, "the constructor must return the package-local client")
	require.Equal(t, slog.Default(), c.log, "a nil log argument must default to slog.Default()")
}

// Spans 692-693: a transient serialization failure (40001) on the
// terminal-facts commit is retried after the backoff timer and the hop
// still settles exactly one event — the funnel's idempotent-recommit
// contract.
func TestGWCovG1_JudgeTerminalFactsTransientRetrySettles(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	store := &fakeInvocationStore{
		factsErrs: []error{&pgconn.PgError{Code: "40001"}, nil}, // first commit collides, recommit wins
	}
	client, req := g1JudgeClientOver(t, "", up.handler(), func(c *budgetedJudgeClient) { c.invocations = store })

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	resp, err := client.JudgeChat(context.Background(), req)

	require.NoError(t, err, "a transient facts failure must not fail the hop")
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, 2, store.factsCalls, "exactly one recommit after the backoff")
	require.NotNil(t, ev, "the recovered commit still settles one event")
	require.Equal(t, "request.completed", ev.EventType)
	require.Equal(t, int64(11), ev.TokensIn)
	require.Equal(t, int64(1), up.hits.Load())
}

// Span 694 + the permanent ladder exit (701/702/705) + 597 + 225: when the
// bounded facts context expires mid-ladder, the retry select observes
// fctx.Done and the remaining attempt still runs; the hop then surfaces the
// wrapped store failure and the event is withheld from the consumer.
func TestGWCovG1_JudgeTerminalFactsDeadlineAndPermanentFailure(t *testing.T) {
	deadlineCase := func(t *testing.T) {
		t.Helper()
		up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
		store := &g1BlockFactsStore{
			fakeInvocationStore: fakeInvocationStore{factsErr: &pgconn.PgError{Code: "40001"}},
			blockErr:            &pgconn.PgError{Code: "40001"},
		}
		store.blockNext.Store(true)
		client, req := g1JudgeClientOver(t, "", up.handler(), func(c *budgetedJudgeClient) { c.invocations = store })

		start := time.Now()
		_, err := client.JudgeChat(context.Background(), req)

		require.Error(t, err, "the exhausted ladder fails the hop")
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
		require.GreaterOrEqual(t, time.Since(start), terminalFactsTimeout,
			"the blocked commit must hold the ladder until the bounded facts context expires")
		require.Equal(t, int64(3), store.total.Load(), "attempts: initial (blocked), post-timer, post-deadline")
		require.Equal(t, int64(1), up.hits.Load(), "the wire hop itself succeeded")
	}

	permanentCase := func(t *testing.T) {
		t.Helper()
		up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
		store := &fakeInvocationStore{factsErr: &pgconn.PgError{Code: "23505"}} // unique_violation: deterministic
		client, req := g1JudgeClientOver(t, "", up.handler(), func(c *budgetedJudgeClient) { c.invocations = store })

		var ev *eventpub.Event
		restore := observeEvent(func(e *eventpub.Event) { ev = e })
		defer restore()

		_, err := client.JudgeChat(context.Background(), req)

		require.Error(t, err, "a deterministic facts failure surfaces the settle error, not the wire success")
		require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
		require.Equal(t, 1, store.factsCalls, "non-transient classes are never retried")
		require.Nil(t, ev, "a completion without its facts row is never published")
		require.Equal(t, int64(1), up.hits.Load())
	}

	t.Run("deadline", deadlineCase)
	t.Run("permanent", permanentCase)
}

// Span 229: a 200 body without choices is a terminal verdict error after
// settlement — the hop still settles its real usage.
func TestGWCovG1_JudgeNoChoicesVerdictFails(t *testing.T) {
	const noChoices = `{"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: noChoices}
	client, req := g1JudgeClientOver(t, "", up.handler(), nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream response has no choices")
	require.NotNil(t, ev, "the dispatched hop settled its real usage")
	require.Equal(t, int64(3), ev.TokensIn)
	require.Equal(t, int64(2), ev.TokensOut)
	require.Empty(t, ev.Error, "the wire call itself succeeded")
}

// Span 270: a failing judge model resolver fails the hop before any local
// dispatch step.
func TestGWCovG1_JudgeModelResolveFailure(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := g1JudgeClientOver(t, "", up.handler(), func(c *budgetedJudgeClient) {
		c.models = llmjudge.ModelResolverFunc(func(context.Context, string) (llmjudge.Target, error) {
			return llmjudge.Target{}, errors.New("g1: judge registry down")
		})
	})

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge model resolve")
	require.Contains(t, err.Error(), "g1: judge registry down")
	require.Equal(t, int64(0), up.hits.Load())
}

// Spans 289-291 + 295: the never-dispatched release finalizes the
// reservation at zero spend and preserves the caller's failure; without a
// transport failure it answers the sentinel.
func TestGWCovG1_JudgeReleaseUndispatchedContract(t *testing.T) {
	c := &budgetedJudgeClient{log: judgeHopLogger(t), now: time.Now}
	rsv := &budget.Reservation{
		OrgID: "org-g1",
		Mode:  budget.ModeEnforce,
		Scopes: []budget.ScopeReserve{{
			Scope: budget.ScopeWallet, Key: "org-g1", Bound: 1500,
		}},
	}
	wireErr := errors.New("g1: wire failed")

	t.Run("release with caller failure", func(t *testing.T) {
		require.Same(t, wireErr, c.releaseUndispatched(rsv, wireErr),
			"the local failure keeps precedence over the zero-spend release")
	})
	t.Run("nil reservation passes through", func(t *testing.T) {
		require.Same(t, wireErr, c.releaseUndispatched(nil, wireErr))
	})
	t.Run("silent success answers the sentinel", func(t *testing.T) {
		err := c.releaseUndispatched(rsv, nil)
		require.EqualError(t, err, "judge hop never dispatched")
	})
	t.Run("empty release answers the sentinel", func(t *testing.T) {
		require.EqualError(t, c.releaseUndispatched(nil, nil), "judge hop never dispatched")
	})
}

// Span 449: an unknown provider name fails the pool adapter lookup before
// any wire traffic.
func TestGWCovG1_JudgePoolAdapterFailure(t *testing.T) {
	client, req := g1JudgeClientAt(t, "g1-unknown-provider", "http://127.0.0.1:1", nil)

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream client")
}

// Span 455: a payload that cannot be encoded (NaN temperature) fails the
// hop locally, before the durable start and the wire.
func TestGWCovG1_JudgeRequestEncodeFailure(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := g1JudgeClientOver(t, "", up.handler(), nil)
	req.Temperature = math.NaN()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge request encode")
	require.Contains(t, err.Error(), "NaN")
	require.Equal(t, int64(0), up.hits.Load())
}

// Span 459: the judge payload's response_format contract is rejected by the
// anthropic translator before any wire traffic.
func TestGWCovG1_JudgeRequestTranslateFailure(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := g1JudgeClientOver(t, "anthropic", up.handler(), nil)

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge request translate")
	require.Contains(t, err.Error(), "response_format", "the unmapped response_format must be named in the refusal")
	require.Equal(t, int64(0), up.hits.Load())
}

// Span 503: a failed durable start fails the hop closed at zero provider
// arrivals and settles nothing.
func TestGWCovG1_JudgeDurableStartFailure(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := g1JudgeClientOver(t, "", up.handler(), func(c *budgetedJudgeClient) {
		c.invocations = &fakeInvocationStore{admitErr: errors.New("g1: admit write failed")}
	})

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge hop durable start")
	require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	require.Equal(t, int64(0), up.hits.Load(), "a refused durable start means zero provider arrivals")
	require.Nil(t, ev, "a never-dispatched hop settles nothing")
}

// Span 509: a wire-level dial failure still settles exactly one event —
// dispatched latched before the Do.
func TestGWCovG1_JudgeUpstreamDialFailureSettles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rawURL := srv.URL
	srv.Close() // the pooled URL now dials into a closed listener

	client, req := g1JudgeClientAt(t, "", rawURL, nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream call")
	require.NotNil(t, ev, "a dispatched-then-failed hop settles its zero spend")
	require.NotEmpty(t, ev.Error)
	require.Equal(t, string(budget.TerminationUpstreamErr), ev.Termination)
}

// Span 521: a truncated 200 body fails the read after dispatch and settles
// the upstream-error termination.
func TestGWCovG1_JudgeUpstreamTruncatedReadFails(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"con`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // truncate the body mid-stream, as a dying upstream would
	})
	client, req := g1JudgeClientOver(t, "", h, nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream read")
	require.NotNil(t, ev)
	require.Equal(t, string(budget.TerminationUpstreamErr), ev.Termination)
}

// Span 527: a 200 body the provider adapter cannot translate fails the hop
// before the verdict parser ever sees it.
func TestGWCovG1_JudgeResponseTranslateFailure(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: `<<not-json>>`}
	client, req := g1JudgeClientOver(t, "anthropic", up.handler(), nil)
	req.ResponseJSON = false // let the request-side translation pass; only the response side fails

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream translate response")
	require.Equal(t, int64(1), up.hits.Load(), "the body did reach the wire; translation failed on the way back")
	require.NotNil(t, ev)
}

// Span 564: an empty provider name settles under the openai default — the
// cost fact must equal the independently computed openai quote.
func TestGWCovG1_JudgeSettleDefaultsProviderToOpenAI(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := g1JudgeClientOver(t, "", up.handler(), nil) // resolver target leaves Provider empty

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	resp, err := client.JudgeChat(context.Background(), req)

	require.NoError(t, err)
	require.Equal(t, "gpt-4o-mini", resp.Model)
	require.NotNil(t, ev)
	require.Equal(t, "priced", ev.CostStatus)
	want := provider.ComputeCost(provider.Usage{
		PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18, Source: provider.UsageSourceProvider,
	}, "openai", "gpt-4o-mini").EstimatedCostUSD
	require.InDelta(t, want, ev.EstimatedCostUSD, 0,
		"the empty provider must settle under the openai default, not an unpriced quote")
}

// Span 678: a client without a durable store fails the terminal commit
// closed, naming the invocation.
func TestGWCovG1_JudgeTerminalFactsNilStoreFailsClosed(t *testing.T) {
	c := &budgetedJudgeClient{log: judgeHopLogger(t), now: time.Now} // invocations nil
	h := newInvocationIdentity("org-g1", "req-g1", "sess-g1", "key-g1", "skey-g1", "m")

	err := c.commitHopTerminal(context.Background(), h, &eventpub.Event{})

	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvocationStoreUnavailable)
	require.Contains(t, err.Error(), h.ID(), "the refusal must name the invocation it could not close")
}
