package cli

// N06-P07-T05 negative-path proof for the workload dimension at the gateway
// seam. The ledger unit negatives live in pkg/budget; these pin the
// fail-closed behavior where it meets callers: the missing-org namespace is
// a real, enforced tenant (never a bypass), a caller-asserted X-Org-Id
// cannot enter another tenant's window, a batch line cannot bypass the
// workload cap (it rides the same derived task:<id> key), an unknown price
// and a failed hop never fabricate a charge, and two orgs' identically named
// workloads never share a window even under concurrent judge hops.

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
)

// TestAdmissionRoutes_WorkloadMissingOrgNamespaceEnforced drives the REAL
// route stack with no org on the identity (strict api-key mode, no resolver
// — the header stays empty through admissionCore): the workload cap must
// still enforce per-key in the missing-org namespace, 429 with zero upstream
// traffic and zero events. Unknown/missing org is a tenant, not a bypass.
func TestAdmissionRoutes_WorkloadMissingOrgNamespaceEnforced(t *testing.T) {
	gw, hits, events := newAdmissionMatrixGateway(t)
	ledger := presetWorkloadLedger(t, 100)
	ledger.Charge("", "ci", money.MicroUSD(100)) // the missing-org "ci" window is saturated

	rec := postMatrixRequest(t, gw, "/v1/chat/completions", "application/json",
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Yabanin-Workload": "ci"})
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded", rec.Body.String())
	require.Zero(t, hits.Load(), "a capped workload must not reach the wire")
	require.Zero(t, events.Load(), "an admission denial settles no event")

	// The refusal is per-key, not a global lockout: another workload in the
	// same missing-org namespace admits normally.
	rec = postMatrixRequest(t, gw, "/v1/chat/completions", "application/json",
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Yabanin-Workload": "other"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestAdmissionRoutes_WorkloadOrgHeaderCannotHijackNamespace is the
// adversarial org assertion: a client sending X-Org-Id: org-victim with a
// saturated victim window must NOT be denied through the victim's namespace
// (the auth middleware strips the client's org header; strict mode without a
// resolver leaves the request in the missing-org namespace). The control
// charge proves the request truly lives in "" — the spoof lands nowhere.
func TestAdmissionRoutes_WorkloadOrgHeaderCannotHijackNamespace(t *testing.T) {
	gw, hits, _ := newAdmissionMatrixGateway(t)
	ledger := presetWorkloadLedger(t, 100)
	ledger.Charge("org-victim", "ci", money.MicroUSD(100)) // the victim's window is saturated

	rec := postMatrixRequest(t, gw, "/v1/chat/completions", "application/json",
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Org-Id": "org-victim", "X-Yabanin-Workload": "ci"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String(),
		"the caller-asserted org must not enter the victim's saturated window")
	require.Equal(t, int64(1), hits.Load())

	// Control: saturating the namespace the request ACTUALLY lands in ("")
	// now denies the identical request — the earlier pass was real routing,
	// not a skip of the cap.
	ledger.Charge("", "ci", money.MicroUSD(100))
	rec = postMatrixRequest(t, gw, "/v1/chat/completions", "application/json",
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Org-Id": "org-victim", "X-Yabanin-Workload": "ci"})
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded")
}

// TestBatchLine_WorkloadCapBlocksBatchLine pins the batch non-bypass through
// the workload dimension: the line's derived key is task:<batch-id> under the
// batch's org (the executor stamps both headers itself), so a saturated
// window fails the line 429 workload_budget_exceeded with zero upstream
// traffic — and a fresh batch id still runs.
func TestBatchLine_WorkloadCapBlocksBatchLine(t *testing.T) {
	gw, hits, _ := newAdmissionMatrixGateway(t)
	ledger := presetWorkloadLedger(t, 100)
	ledger.Charge("org-batch", "task:batch_wlcap", money.MicroUSD(100))

	line := func(batchID string) batchstore.Line {
		return batchstore.Line{
			BatchID:     batchID,
			LineNo:      1,
			CustomID:    "c1",
			RequestID:   "req_" + batchID + "_1",
			RequestBody: []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`),
		}
	}

	res := gw.batchLineRunner(context.Background(),
		&batchstore.Batch{ID: "batch_wlcap", OrgID: "org-batch", APIKeyID: "key-batch"}, line("batch_wlcap"))
	require.Equal(t, http.StatusTooManyRequests, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), "workload_budget_exceeded")
	require.Zero(t, hits.Load(), "a capped batch line must not reach the wire")

	res = gw.batchLineRunner(context.Background(),
		&batchstore.Batch{ID: "batch_wlok", OrgID: "org-batch", APIKeyID: "key-batch"}, line("batch_wlok"))
	require.Equal(t, http.StatusOK, res.Status, string(res.Body),
		"a fresh derived window must run — the cap is per-key, not per-executor")
	require.Equal(t, int64(1), hits.Load())
}

// TestBudgetedJudge_UnknownPriceHopSkipsWorkloadCharge pins the unknown-price
// negative on the hop path: a completed hop over an unpriced model publishes
// its settled event with the workload label and cost_status unknown_price,
// but charges NOTHING into the ledger — an unknown price must not fabricate
// spend, and the attribution label rides anyway.
func TestBudgetedJudge_UnknownPriceHopSkipsWorkloadCharge(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	releaseHopEpisodes(t, "req-wl-ci-fleet")
	ledger := presetWorkloadLedger(t, 1_000_000)

	client, req := newJudgeHopClient(t, up, nil)
	req.ModelRef = "gpt-november-99" // not in the pricing catalog

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(workloadHopContext("ci-fleet"), req)
	require.NoError(t, err)

	require.NotNil(t, ev, "the hop still settles its event")
	require.Equal(t, "ci-fleet", ev.Labels["workload"],
		"the attribution label rides the event regardless of price knowledge")
	require.Equal(t, "unknown_price", ev.CostStatus)
	require.Equal(t, money.MicroUSD(0), ledger.Spent("org-judge", "ci-fleet"),
		"an unknown price must not fabricate a ledger charge")
	require.Equal(t, int64(1), up.hits.Load())
}

// TestBudgetedJudge_FailedHopChargesNothing pins the failed-hop negative on
// the ledger side (the event side is pinned by
// TestBudgetedJudge_UpstreamErrorSettlesZero): a hop that dies at the
// upstream settles no ledger charge and leaves its window unpoisoned — the
// next good hop admits and charges normally.
func TestBudgetedJudge_FailedHopChargesNothing(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusInternalServerError, body: `{"error":"boom"}`}
	releaseHopEpisodes(t, "req-wl-ci-fleet", "req-wl-retry")
	ledger := presetWorkloadLedger(t, 1_000_000)

	client, req := newJudgeHopClient(t, up, nil)

	_, err := client.JudgeChat(workloadHopContext("ci-fleet"), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "judge upstream status 500")
	require.Equal(t, money.MicroUSD(0), ledger.Spent("org-judge", "ci-fleet"),
		"a failed hop must not charge its workload window")

	// The window is not poisoned: the next hop admits and charges.
	up.status, up.body = http.StatusOK, judgeHopOKBody
	_, err = client.JudgeChat(workloadHopContextID("req-wl-retry", "ci-fleet"), req)
	require.NoError(t, err)
	require.Positive(t, ledger.Spent("org-judge", "ci-fleet"),
		"the retry hop charges its own actual")
}

// TestBudgetedJudge_WorkloadCapCrossOrgConcurrent is the adversarial
// ≥2-orgs never-share invariant under concurrency at the hop seam: with org
// A's window saturated, three concurrent A hops must ALL fail closed while
// three concurrent B hops over the identically named workload all succeed —
// zero A leakage into B, exact A accounting, and exactly the B hops reaching
// the wire.
func TestBudgetedJudge_WorkloadCapCrossOrgConcurrent(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	// Every hop below consumes a shared-loop hop under its own episode id
	// (org A's hops are denied by the workload cap AFTER the loop check
	// counted them) — collect all six episodes for the cleanup release.
	const perOrg = 3
	var episodes []string
	for i := 1; i <= perOrg; i++ {
		episodes = append(episodes, fmt.Sprintf("req-wl-a-%d", i), fmt.Sprintf("req-wl-b-%d", i))
	}
	releaseHopEpisodes(t, episodes...)
	ledger := presetWorkloadLedger(t, 1_000_000)
	ledger.Charge("org-a", "ci", money.MicroUSD(1_000_000)) // org A saturated

	client, req := newJudgeHopClient(t, up, nil)

	var wg sync.WaitGroup
	aErrs := make([]error, perOrg)
	bErrs := make([]error, perOrg)

	// llmjudge.ChatRequest carries Meta by pointer: every goroutine gets its
	// own request copy with its own meta — a shared mutable Meta would be a
	// data race in the test itself.
	aReq, bReq := req, req
	aReq.Meta, bReq.Meta = judgeHopMeta("org-a"), judgeHopMeta("org-b")

	for i := 0; i < perOrg; i++ {
		wg.Add(2)
		go func(i int) { // org A: must be denied, pre-wire, every time
			defer wg.Done()
			_, aErrs[i] = client.JudgeChat(
				workloadHopContextID(fmt.Sprintf("req-wl-a-%d", i+1), "ci"), aReq)
		}(i)
		go func(i int) { // org B: must succeed despite A's saturation
			defer wg.Done()
			_, bErrs[i] = client.JudgeChat(
				workloadHopContextID(fmt.Sprintf("req-wl-b-%d", i+1), "ci"), bReq)
		}(i)
	}
	wg.Wait()

	for i, err := range aErrs {
		require.ErrorIsf(t, err, budget.ErrWorkloadBudgetExceeded,
			"org A hop %d must fail closed on its own saturated window", i)
	}
	for i, err := range bErrs {
		require.NoErrorf(t, err, "org B hop %d must not inherit org A's saturation", i)
	}

	require.Equal(t, int64(perOrg), up.hits.Load(),
		"exactly the admitted (org B) hops reach the wire")
	require.Equal(t, money.MicroUSD(1_000_000), ledger.Spent("org-a", "ci"),
		"org A's window keeps its exact accounting — no B charges, no drift")
	require.Positive(t, ledger.Spent("org-b", "ci"),
		"org B's hops charge org B's own window")
}
