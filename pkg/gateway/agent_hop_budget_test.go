package cli

// N06-P07-T03 unit acceptance for the budgeted internal-hop client: the
// recursion contract holds, the per-episode loop cap and the G2 agent
// budget block hops fail-closed BEFORE the wire, the §5 estimator answers
// unpriced judge models in enforce mode, and every completed hop settles
// exactly one request.completed event with EXACT upstream usage, computed
// cost and the reservation tuples. The batch non-bypass pin and the
// endpoint admission matrix live in endpoint_admission_matrix_test.go.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// judgeHopUpstream is a chat.completions upstream answering with the given
// usage and content; hits counts received requests and captures the wire
// shape for contract assertions.
type judgeHopUpstream struct {
	status int
	body   string
	hits   atomic.Int64

	t *testing.T
}

func (m *judgeHopUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)
		if r.Header.Get(llmjudge.JudgeHeader) == "" {
			m.t.Errorf("judge hop reached the wire without the %s marker", llmjudge.JudgeHeader)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(m.status)
		_, _ = w.Write([]byte(m.body))
	})
}

const judgeHopOKBody = `{"choices":[{"message":{"content":"{\"verdict\":\"allow\"}"}}],` +
	`"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`

func judgeHopMeta(org string) *pipeline.RequestMeta {
	return &pipeline.RequestMeta{
		Org:    org,
		Key:    "key-1",
		Labels: map[string]string{llmjudge.MetaLabelJudge: llmjudge.JudgeLabelValue},
	}
}

func judgeHopRequest(model string) llmjudge.ChatRequest {
	return llmjudge.ChatRequest{
		ModelRef: model,
		Messages: []pipeline.Message{
			{Role: "system", Content: "you are a judge"},
			{Role: "user", Content: "inspect this turn"},
		},
		Temperature:  0,
		MaxTokens:    512,
		ResponseJSON: true,
		Meta:         judgeHopMeta("org-judge"),
	}
}

// newJudgeHopClient wires the budgeted client over a mock upstream with a
// literal model resolver; mut lets a test swap collaborators.
func newJudgeHopClient(t *testing.T, up *judgeHopUpstream, mut func(c *budgetedJudgeClient)) (*budgetedJudgeClient, llmjudge.ChatRequest) {
	t.Helper()
	pool := upstream.NewPool(upstream.Options{})
	srv := httptest.NewServer(up.handler())
	t.Cleanup(srv.Close)
	client := &budgetedJudgeClient{
		pool: pool,
		models: llmjudge.ModelResolverFunc(func(_ context.Context, ref string) (llmjudge.Target, error) {
			return llmjudge.Target{Model: ref, Provider: "openai", UpstreamURL: srv.URL}, nil
		}),
		keys: llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) {
			return "upstream-key", nil
		}),
		loop:      sharedLoopBudget(),
		log:       judgeHopLogger(t),
		now:       time.Now,
		admission: budget.NewAdmission(nil, budget.ScopedRateSource{}, nil, "test", budget.ModeOff, nil, budget.AdmissionConfig{}),
	}
	if mut != nil {
		mut(client)
	}
	return client, judgeHopRequest("gpt-4o-mini")
}

func judgeHopLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.DiscardHandler)
}

// releaseHopEpisodes drops the test's episodes from the process-wide loop
// budget (sharedLoopBudget) on cleanup. JudgeChat consumes one shared-loop
// hop per call BEFORE the workload-cap check, so every test that drives hops
// over a request-id context accumulates accounting on the shared budget.
// `go test -count=N` re-runs the same test functions in one process; without
// the release, an episode such as req-wl-ci-fleet carries its hops into the
// next iteration, breaches DefaultLoopMaxHops, and later iterations fail
// with the loop-budget error instead of the behavior the test pins. This is
// the same release convention the integration and joint-scenario tests
// already follow (e.g. agent_hop_budget_int_test.go, n06p7t06, T07 corpus).
func releaseHopEpisodes(t *testing.T, episodes ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, episode := range episodes {
			sharedLoopBudget().Release(episode)
		}
	})
}

func TestBudgetedJudge_RefusesUnmarkedMeta(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := newJudgeHopClient(t, up, nil)
	req.Meta = &pipeline.RequestMeta{Org: "org-judge"} // marker stripped

	_, err := client.JudgeChat(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion-exclusion contract")
	require.Equal(t, int64(0), up.hits.Load(), "an unmarked judge call must never reach the wire")
}

func TestBudgetedJudge_LoopCapBlocksHop(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	loop := budget.NewLoopBudget(2, time.Minute)
	client, req := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.loop = loop })

	ctx := requestid.NewContext(context.Background(), requestid.ID("req-loop"))
	for i := 0; i < 2; i++ {
		_, err := client.JudgeChat(ctx, req)
		require.NoError(t, err, "hop %d under the cap", i+1)
	}
	require.Equal(t, 2, loop.Hops("req-loop"))

	_, err := client.JudgeChat(ctx, req)
	require.ErrorIs(t, err, budget.ErrLoopBudgetExceeded)
	require.Equal(t, int64(2), up.hits.Load(), "the refused hop must not reach the wire")

	// A new episode (fresh request id) is not throttled by the old one.
	_, err = client.JudgeChat(requestid.NewContext(context.Background(), requestid.ID("req-loop-2")), req)
	require.NoError(t, err)
}

func TestBudgetedJudge_LoopReleaseResetsEpisode(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	loop := budget.NewLoopBudget(1, time.Minute)
	client, req := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.loop = loop })

	ctx := requestid.NewContext(context.Background(), requestid.ID("req-release"))
	_, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	_, err = client.JudgeChat(ctx, req)
	require.ErrorIs(t, err, budget.ErrLoopBudgetExceeded)

	loop.Release("req-release")
	_, err = client.JudgeChat(ctx, req)
	require.NoError(t, err, "the episode's accounting is dropped with it")
}

func TestBudgetedJudge_AgentBudgetBlocksHop(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	releaseHopEpisodes(t, "req-agent")
	client, req := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) {
		c.agentEnforcer = fakeAgentBudget{err: budget.ErrAgentBudgetExceeded}
	})

	ctx := withPrincipal(requestid.NewContext(context.Background(), requestid.ID("req-agent")),
		principal{AgentID: "agent-1"})
	_, err := client.JudgeChat(ctx, req)
	require.ErrorIs(t, err, budget.ErrAgentBudgetExceeded)
	require.Contains(t, err.Error(), "judge agent budget")
	require.Equal(t, int64(0), up.hits.Load(), "a budget-denied hop must not reach the wire")
}

func TestBudgetedJudge_EnforceUnpricedModelDenied(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	// Enforce everywhere, nothing priced: the estimator must fail closed
	// before any upstream traffic (I3), exactly as it does for interactive
	// requests.
	adm := budget.NewAdmission(nil, budget.ScopedRateSource{}, nil, "test", budget.ModeEnforce,
		func(context.Context, string) (budget.OrgSettings, error) {
			return budget.OrgSettings{Mode: budget.ModeEnforce}, nil
		}, budget.AdmissionConfig{})
	client, req := newJudgeHopClient(t, up, func(c *budgetedJudgeClient) { c.admission = adm })

	_, err := client.JudgeChat(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge hop budget admission")
	require.ErrorIs(t, err, budget.ErrUnpricedModel)
	require.Equal(t, int64(0), up.hits.Load())
}

func TestBudgetedJudge_SettlesExactUsage(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	releaseHopEpisodes(t, "req-settle")
	client, req := newJudgeHopClient(t, up, nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	ctx := withPrincipal(requestid.NewContext(context.Background(), requestid.ID("req-settle")),
		principal{AgentID: "agent-1"})
	resp, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, "gpt-4o-mini", resp.Model)

	require.NotNil(t, ev, "every judge hop must settle exactly one event")
	require.Equal(t, "request.completed", ev.EventType)
	require.Equal(t, agentHopEndpoint, ev.Endpoint)
	require.Equal(t, "req-settle", ev.RequestID)
	require.Equal(t, "org-judge", ev.OrgID)
	require.Equal(t, "agent-1", ev.AgentID)
	require.Equal(t, "key-1", ev.APIKeyID)
	require.Equal(t, int64(11), ev.TokensIn, "EXACT upstream usage, never estimated")
	require.Equal(t, int64(7), ev.TokensOut)
	require.Equal(t, "provider", ev.UsageSource)
	require.Equal(t, "priced", ev.CostStatus)
	require.Empty(t, ev.Error)
	want := provider.ComputeCost(provider.Usage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18, Source: provider.UsageSourceProvider}, "openai", "gpt-4o-mini").EstimatedCostUSD
	require.InDelta(t, want, ev.EstimatedCostUSD, 0)
	require.Empty(t, ev.Reservations, "off mode publishes no reserve tuples")
}

func TestBudgetedJudge_UpstreamErrorSettlesZero(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusInternalServerError, body: `{"error":"boom"}`}
	client, req := newJudgeHopClient(t, up, nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream status 500")

	require.NotNil(t, ev, "a failed hop still settles its (zero) spend")
	require.Equal(t, "request.completed", ev.EventType)
	require.Equal(t, agentHopEndpoint, ev.Endpoint)
	require.Equal(t, int64(500), ev.StatusCode)
	require.NotEmpty(t, ev.Error)
	require.Equal(t, int64(0), ev.TokensIn)
	require.Equal(t, int64(0), ev.TokensOut)
	require.Zero(t, ev.EstimatedCostUSD)
	require.Equal(t, string(budget.TerminationUpstreamErr), ev.Termination)
}

func TestBudgetedJudge_WireShapeMatchesJudgeContract(t *testing.T) {
	var gotHeader string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(llmjudge.JudgeHeader)
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(judgeHopOKBody))
	}))
	defer srv.Close()

	pool := upstream.NewPool(upstream.Options{})
	client := &budgetedJudgeClient{
		pool: pool,
		models: llmjudge.ModelResolverFunc(func(_ context.Context, ref string) (llmjudge.Target, error) {
			return llmjudge.Target{Model: ref, Provider: "openai", UpstreamURL: srv.URL}, nil
		}),
		loop: budget.NewLoopBudget(0, 0),
		log:  judgeHopLogger(t),
		now:  time.Now,
	}
	resp, err := client.JudgeChat(context.Background(), judgeHopRequest("judge-model"))
	require.NoError(t, err)
	require.Equal(t, llmjudge.JudgeLabelValue, gotHeader, "the judge marker must ride the wire header")
	for _, want := range []string{
		`"model":"judge-model"`,
		`"temperature":0`,
		`"max_tokens":512`,
		`"response_format":{"type":"json_object"}`,
		`"content":"you are a judge"`,
		`"content":"inspect this turn"`,
	} {
		require.Contains(t, gotBody, want, "judge wire payload must match the packaged client's contract")
	}
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
}

func TestBudgetedJudge_NilPoolUnusable(t *testing.T) {
	client := &budgetedJudgeClient{log: judgeHopLogger(t), now: time.Now}
	_, err := client.JudgeChat(context.Background(), judgeHopRequest("m"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "pool is not wired")
}
