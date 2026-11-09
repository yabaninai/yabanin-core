package cli

// N06-P07-T04 unit acceptance for the workload dimension on internal judge
// hops: the hop rides the parent request's workload identity (the label
// admissionCore stamped on the context), the opt-in cap blocks the hop
// fail-closed BEFORE the wire, and the settle event carries the workload
// label with the hop's settled actual charged against the ledger — the
// durable attribution rides the event either way.

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/requestid"
)

func TestBudgetedJudge_WorkloadCapBlocksHop(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	// Both episodes below consume shared-loop hops (the ci-fleet hop is
	// denied by the workload cap AFTER the loop check counted it).
	releaseHopEpisodes(t, "req-wl-ci-fleet", "req-wl-other")
	ledger := presetWorkloadLedger(t, 100)
	// The hop's window is namespaced by the parent meta's org ("org-judge"
	// from the shared hop fixture).
	ledger.Charge("org-judge", "ci-fleet", money.MicroUSD(100))

	client, req := newJudgeHopClient(t, up, nil)
	ctx := workloadHopContext("ci-fleet")

	_, err := client.JudgeChat(ctx, req)
	require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
	require.Contains(t, err.Error(), "judge workload budget")
	require.Equal(t, int64(0), up.hits.Load(), "a workload-denied hop must not reach the wire")

	// Another workload under the same cap passes.
	_, err = client.JudgeChat(workloadHopContext("other"), req)
	require.NoError(t, err)
}

// TestBudgetedJudge_WorkloadChargeOrgNamespaced pins the F1 remediation on
// the hop path: the cap window and the settle charge are namespaced by the
// parent request's org (req.Meta.Org), so two tenants running identically
// named workloads never share a window — org A's saturation refuses only
// org A's hops, and org B's hop charges never touch org A's accounting.
func TestBudgetedJudge_WorkloadChargeOrgNamespaced(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	// Both episodes consume shared-loop hops (org A's hop is denied by the
	// workload cap AFTER the loop check counted it).
	releaseHopEpisodes(t, "req-wl-org-a", "req-wl-org-b")
	ledger := presetWorkloadLedger(t, 100)
	ledger.Charge("org-a", "ci", money.MicroUSD(100)) // org A's "ci" window saturated

	client, req := newJudgeHopClient(t, up, nil)

	req.Meta.Org = "org-a"
	_, err := client.JudgeChat(workloadHopContextID("req-wl-org-a", "ci"), req)
	require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
	require.Equal(t, int64(0), up.hits.Load(), "org A's capped hop must not reach the wire")

	req.Meta.Org = "org-b"
	_, err = client.JudgeChat(workloadHopContextID("req-wl-org-b", "ci"), req)
	require.NoError(t, err, "org B's identical workload name must not inherit org A's saturation")
	require.Equal(t, int64(1), up.hits.Load())
	require.Positive(t, ledger.Spent("org-b", "ci"), "the hop charges its own org's window")
	require.Equal(t, money.MicroUSD(100), ledger.Spent("org-a", "ci"),
		"org B's charges must not leak into org A's window")
}

func TestBudgetedJudge_SettlesWorkloadLabelAndCharge(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	releaseHopEpisodes(t, "req-wl-ci-fleet")
	ledger := presetWorkloadLedger(t, 10_000_000)

	client, req := newJudgeHopClient(t, up, nil)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(workloadHopContext("ci-fleet"), req)
	require.NoError(t, err)

	require.NotNil(t, ev)
	require.Equal(t, "ci-fleet", ev.Labels["workload"],
		"the settle event must carry the parent's workload identity")
	require.Positive(t, ledger.Spent("org-judge", "ci-fleet"),
		"the hop's settled actual must charge its workload window")
	require.Equal(t, money.MicroUSD(0), ledger.Spent("org-judge", "other"), "only the hop's own workload charges")
}

func TestBudgetedJudge_UnattributableHopSkipsWorkloadCap(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	// The workload cap is skipped (unattributable), but the hop still
	// consumes a shared-loop hop under the request id.
	releaseHopEpisodes(t, "req-nowl")
	ledger := presetWorkloadLedger(t, 1)
	ledger.Charge("org-judge", "saturate", money.MicroUSD(1))

	client, req := newJudgeHopClient(t, up, nil)
	ctx := requestid.NewContext(context.Background(), requestid.ID("req-nowl"))

	_, err := client.JudgeChat(ctx, req)
	require.NoError(t, err, "an unattributable hop allows without tracking")
}

func workloadHopContext(workload string) context.Context {
	return workloadHopContextID("req-wl-"+workload, workload)
}

func workloadHopContextID(requestID, workload string) context.Context {
	ctx := requestid.NewContext(context.Background(), requestid.ID(requestID))
	return withLabels(ctx, labels.Result{Labels: labels.Set{metaLabelWorkload: workload}})
}
