package budget

// N06-P07 T08 — the repeat-and-recovery arcs of the in-process workload
// cap: an interrupted attempt must never phantom-charge the window, a
// retry must resume from the true spent without duplicates or losses, and
// the layer boundary under repeat stays explicit — the in-memory cap
// accumulates every settle it is told about; the once-only duty sits at
// the durable settlement identity, not here.
//
// Already pinned elsewhere (cited, not duplicated): day roll, TTL sweep,
// org namespaces, cardinality bound, overflow saturation and concurrent
// overshoot → agent_workload_test.go / agent_workload_negative_test.go /
// n06p7t07_boundary_test.go; LoopBudget cap refusal (the refused hop does
// not consume), release-resume and TTL-sweep resume → agent_test.go.

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkloadLedgerFailedAttemptChargesNothingAndRetryRecovers — the
// interruption arc of a non-chat attempt: admission succeeds, the wire
// fails, the settle rule records the failed attempt as zero spend, and the
// window is unchanged for the retry; the successful retry settles its
// actual exactly once and Spent equals that actual — the failed attempt
// contributed nothing: no duplicate, no loss, no poisoned window.
func TestWorkloadLedgerFailedAttemptChargesNothingAndRetryRecovers(t *testing.T) {
	l := NewWorkloadLedger(money.MustFromCents(100), 0)

	require.NoError(t, l.Admit("org-1", "agent:pipeline", money.MustFromCents(50)),
		"the first attempt admits against the empty window")
	l.Charge("org-1", "agent:pipeline", 0) // the failed attempt settles zero spend
	assert.Equal(t, money.MicroUSD(0), l.Spent("org-1", "agent:pipeline"),
		"a zero settle must not poison the window")

	require.NoError(t, l.Admit("org-1", "agent:pipeline", money.MustFromCents(50)),
		"the retry re-admits with the full cap — the failed attempt consumed nothing")
	l.Charge("org-1", "agent:pipeline", money.MustFromCents(70)) // the retry settles its actual
	assert.Equal(t, money.MustFromCents(70), l.Spent("org-1", "agent:pipeline"),
		"exactly the successful attempt's spend is recorded")
}

// TestWorkloadLedgerRefusedPlanLeavesSpentIntact — a denied planned
// admission never phantom-charges: the interruption-safe denial keeps
// Spent byte-exact, so a smaller plan (or a raised cap) resumes from the
// true spent instead of an inflated one.
func TestWorkloadLedgerRefusedPlanLeavesSpentIntact(t *testing.T) {
	l := NewWorkloadLedger(money.MustFromCents(100), 0)
	l.Charge("org-1", "agent:pipeline", money.MustFromCents(70))

	require.ErrorIs(t, l.Admit("org-1", "agent:pipeline", money.MustFromCents(31)),
		ErrWorkloadBudgetExceeded)
	assert.Equal(t, money.MustFromCents(70), l.Spent("org-1", "agent:pipeline"),
		"the refusal must not mutate the window — resume computes from the true spent")
	require.NoError(t, l.Admit("org-1", "agent:pipeline", money.MustFromCents(29)),
		"the smaller plan resumes immediately (the cap is fail-closed at-or-past: 70+30 would touch it)")
}

// TestWorkloadLedgerDoubleSettleAccumulatesNoCapLayerDedup — the layer
// boundary under repeat: settling the same quote twice doubles the window.
// The cap layer deliberately owns no dedup — deduplicating here would
// under-count legitimate repeated spend of the same shape; once-only
// settlement is the durable identity's duty (settlement_jobs
// (org_id, request_id, charge_kind)), pinned at the consumer seam.
func TestWorkloadLedgerDoubleSettleAccumulatesNoCapLayerDedup(t *testing.T) {
	l := NewWorkloadLedger(money.MustFromCents(100), 0)
	l.Charge("org-1", "agent:pipeline", money.MustFromCents(40))
	l.Charge("org-1", "agent:pipeline", money.MustFromCents(40))
	assert.Equal(t, money.MustFromCents(80), l.Spent("org-1", "agent:pipeline"),
		"repeat settles accumulate: the cap stays a best-effort bound, not a billing ledger")
}
