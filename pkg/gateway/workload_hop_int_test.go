//go:build integration

// N06-P07-T04 live-Postgres acceptance for the workload dimension: over the
// live reservations gateway a judge hop whose context carries the workload
// identity (the label admissionCore stamps for real HTTP traffic) settles a
// completion event with that label intact — the durable chargeback channel —
// and charges its settled actual against the replica-local ledger window;
// a workload whose window is at its cap refuses the hop fail-closed BEFORE
// any upstream traffic.
package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestJudgeHopLive_WorkloadLabelSettlesAndCharges(t *testing.T) {
	pool := testdb.Postgres(t)
	up, hits := newJudgeHopUpstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 500_00)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)
	agent := newTestAgentWithBudget(t, pool, org, "10000")
	client := newLiveJudgeClient(t, gw, up)
	ledger := presetWorkloadLedger(t, 100_000_000)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	// A priced model ref: the charge assertion needs a known price —
	// stub-model settles unknown_price, which contributes nothing by design.
	req := judgeHopRequest("gpt-4o-mini")
	req.Meta.Org = org
	ctx := withPrincipal(workloadHopContext("ci-live"), principal{AgentID: agent})

	resp, err := client.JudgeChat(ctx, req)
	require.NoError(t, err)
	require.Equal(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, int64(1), hits.Load())

	require.NotNil(t, ev)
	require.Equal(t, "ci-live", ev.Labels["workload"],
		"the live settle event must carry the workload identity for the labels JSONB channel")
	require.Positive(t, ledger.Spent(org, "ci-live"),
		"the hop's settled actual must charge its workload window")
	require.NotEmpty(t, ev.Reservations, "the workload cap does not replace §5: the hop still reserves")
	sharedLoopBudget().Release("req-wl-ci-live")
}

func TestJudgeHopLive_WorkloadCapDenied(t *testing.T) {
	pool := testdb.Postgres(t)
	up, hits := newJudgeHopUpstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 500_00)
	gw := newReservationGateway(t, pool, up, budget.ModeEnforce)
	client := newLiveJudgeClient(t, gw, up)
	ledger := presetWorkloadLedger(t, 100)
	ledger.Charge(org, "ci-saturated", money.MicroUSD(100))

	var events int
	restore := observeEvent(func(*eventpub.Event) { events++ })
	defer restore()

	req := judgeHopRequest("stub-model")
	req.Meta.Org = org
	_, err := client.JudgeChat(
		withPrincipal(workloadHopContext("ci-saturated"), principal{AgentID: "agent-live"}),
		req)
	require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
	require.Zero(t, hits.Load(), "a workload-capped hop must not reach the wire")
	require.Zero(t, events, "a denied hop settles no completion")
}
