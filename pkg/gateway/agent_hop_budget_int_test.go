//go:build integration

// N06-P07-T03 live-Postgres acceptance for internal judge hops: in enforce
// mode a judge hop RESERVES through the same §5 controller as interactive
// traffic, settles its reservation on the hop's completion event (tuples +
// termination), and an exhausted org's hop is refused fail-closed BEFORE any
// upstream traffic.
package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// newJudgeHopUpstream serves a chat.completions answer with exact usage.
func newJudgeHopUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(judgeHopOKBody))
	}))
	t.Cleanup(up.Close)
	return up, &hits
}

// newLiveJudgeClient wires the budgeted client over the live reservations
// gateway: the gw's admission controller, pool and publisher, a literal
// model resolver pointing at the judge mock, and the shared loop budget.
func newLiveJudgeClient(t *testing.T, gw *gateway, up *httptest.Server) *budgetedJudgeClient {
	t.Helper()
	return &budgetedJudgeClient{
		pool: gw.pool,
		models: llmjudge.ModelResolverFunc(func(_ context.Context, ref string) (llmjudge.Target, error) {
			return llmjudge.Target{Model: ref, Provider: "openai", UpstreamURL: up.URL}, nil
		}),
		keys: llmjudge.KeyResolverFunc(func(context.Context, string, llmjudge.Target) (string, error) {
			return "k", nil
		}),
		loop:          sharedLoopBudget(),
		admission:     gw.admission,
		agentEnforcer: gw.agentEnforcer,
		publisher:     gw.publisher,
		log:           gw.log,
		now:           gw.now,
	}
}

func TestJudgeHopLive_EnforceReservesAndSettles(t *testing.T) {
	pool := testdb.Postgres(t)
	up, hits := newJudgeHopUpstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 500_00)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)

	// The hop's agent scope needs a real UUID with an agent_budgets row.
	agent := newTestAgentWithBudget(t, pool, org, "10000")
	client := newLiveJudgeClient(t, gw, up)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	req := judgeHopRequest("stub-model")
	req.Meta.Org = org
	ctx := withPrincipal(requestid.NewContext(context.Background(), requestid.ID("req-judge-live")),
		principal{AgentID: agent})

	resp, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	require.Equal(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, int64(1), hits.Load())

	require.NotNil(t, ev)
	require.Equal(t, agentHopEndpoint, ev.Endpoint)
	require.Equal(t, org, ev.OrgID)
	require.Equal(t, int64(11), ev.TokensIn)
	require.Equal(t, int64(7), ev.TokensOut)
	require.NotEmpty(t, ev.Reservations, "an enforce-mode hop must carry its reserve tuples")
	require.Equal(t, string(budget.TerminationCompleted), ev.Termination, "the settled hop terminates completed")
	require.Equal(t, 1, sharedLoopBudget().Hops("req-judge-live"), "the hop consumed loop quota")
	sharedLoopBudget().Release("req-judge-live")
}

// newTestAgentWithBudget seeds an agent identity (uuid) with a daily agent
// budget so the hop's ScopeAgentDay reservation has a capacity source.
func newTestAgentWithBudget(t *testing.T, pool *pgxpool.Pool, org, limitCents string) string {
	t.Helper()
	agent := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1::uuid, $2::bigint)`,
		agent.String(), limitCents)
	require.NoError(t, err)
	return agent.String()
}

func TestJudgeHopLive_EnforceExhaustedDenied(t *testing.T) {
	pool := testdb.Postgres(t)
	up, hits := newJudgeHopUpstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 0)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)
	client := newLiveJudgeClient(t, gw, up)

	var events int
	restore := observeEvent(func(*eventpub.Event) { events++ })
	defer restore()

	req := judgeHopRequest("stub-model")
	req.Meta.Org = org
	_, err := client.JudgeChat(
		withPrincipal(requestid.NewContext(context.Background(), requestid.ID("req-judge-deny")), principal{AgentID: "agent-live"}),
		req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge hop budget admission")
	require.Zero(t, hits.Load(), "a budget-denied hop must not reach the wire")
	require.Zero(t, events, "a denied hop spends nothing and settles no completion")
	sharedLoopBudget().Release("req-judge-deny")
}
