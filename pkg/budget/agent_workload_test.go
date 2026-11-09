package budget

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/money"
)

func TestValidWorkloadKey(t *testing.T) {
	valid := []string{"team-a", "task:1", "agent:7f3c", "ci.build.42", "x", "a-b_c:d.e"}
	for _, key := range valid {
		assert.Truef(t, ValidWorkloadKey(key), "expected %q valid", key)
	}
	assert.True(t, ValidWorkloadKey(string(make128())), "expected 128-char key valid")

	invalid := []string{"", "team a", "team/a", "ключ", "a b", "-leading-ok-but space no"}
	for _, key := range invalid {
		assert.Falsef(t, ValidWorkloadKey(key), "expected %q invalid", key)
	}
	assert.False(t, ValidWorkloadKey(string(make129())), "expected 129-char key invalid")
}

func make128() []byte {
	b := make([]byte, 128)
	for i := range b {
		b[i] = 'a'
	}
	return b
}

func make129() []byte {
	return append(make128(), 'b')
}

func TestDeriveWorkloadKey_Precedence(t *testing.T) {
	tests := []struct {
		name             string
		agentID, teamID  string
		taskID, explicit string
		want             string
	}{
		{name: "explicit wins", agentID: "agent-1", teamID: "t1", taskID: "job", explicit: "wl", want: "wl"},
		{name: "agent next", agentID: "agent-1", teamID: "t1", taskID: "job", want: "agent:agent-1"},
		{name: "team+task next", teamID: "t1", taskID: "job", want: "team:t1.task:job"},
		{name: "task only", taskID: "job", want: "task:job"},
		{name: "team without task", teamID: "t1", want: ""},
		{name: "nothing", want: ""},
		{name: "malformed explicit ignored", explicit: "not valid", agentID: "agent-1", want: "agent:agent-1"},
		{name: "malformed agent skipped", agentID: "not valid", teamID: "t1", taskID: "job", want: "team:t1.task:job"},
		{name: "oversized composite skipped to task", teamID: string(make128()), taskID: "job", want: "task:job"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveWorkloadKey(tt.agentID, tt.teamID, tt.taskID, tt.explicit)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWorkloadLedger_NilAndDisabled(t *testing.T) {
	var nilLedger *WorkloadLedger
	require.NoError(t, nilLedger.Admit("org-1", "wl", money.MustFromCents(100)))
	nilLedger.Charge("org-1", "wl", money.MustFromCents(1))
	assert.Equal(t, money.MicroUSD(0), nilLedger.Spent("org-1", "wl"))

	disabled := NewWorkloadLedger(0, 0)
	require.NoError(t, disabled.Admit("org-1", "wl", money.MustFromCents(100)))
	disabled.Charge("org-1", "wl", money.MustFromCents(50))
	assert.Equal(t, money.MicroUSD(0), disabled.Spent("org-1", "wl"), "disabled ledger records nothing")

	assert.NoError(t, disabled.Admit("org-1", "", money.MustFromCents(100)), "empty key is unattributable and allows")
}

func TestWorkloadLedger_ChargeAccrualAndDenial(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)

	l.Charge("", "wl", money.MustFromCents(70))
	assert.Equal(t, money.MustFromCents(70), l.Spent("", "wl"))

	require.ErrorIs(t, l.Admit("", "wl", money.MustFromCents(31)), ErrWorkloadBudgetExceeded,
		"70+31 past the 100-cent cap must deny")
	require.ErrorIs(t, l.Admit("", "wl", money.MustFromCents(30)), ErrWorkloadBudgetExceeded,
		"reaching the cap exactly also denies (fail-closed at-or-past)")
	require.NoError(t, l.Admit("", "wl", money.MustFromCents(29)),
		"leaving one unit of headroom admits")

	// Independent keys never share a window.
	l.Charge("", "other", money.MustFromCents(100))
	require.ErrorIs(t, l.Admit("", "other", money.MustFromCents(1)), ErrWorkloadBudgetExceeded)
	require.NoError(t, l.Admit("", "wl", 0))
}

// TestWorkloadLedger_OrgNamespacesWindows pins the F1 remediation: the cap
// window is keyed by (org, workload) — two tenants choosing the same
// workload name never share a counter, so org A's charges can never saturate
// org B's window or flip org B's Admit decision.
func TestWorkloadLedger_OrgNamespacesWindows(t *testing.T) {
	l := NewWorkloadLedger(money.MustFromCents(100), 0)

	// Org A fills its "ci" window to the cap.
	l.Charge("org-a", "ci", money.MustFromCents(100))
	require.ErrorIs(t, l.Admit("org-a", "ci", money.MustFromCents(1)), ErrWorkloadBudgetExceeded,
		"org A's window is saturated")

	// Org B picked the same name: its window is independent and admits.
	assert.Equal(t, money.MicroUSD(0), l.Spent("org-b", "ci"),
		"org A's charges must not appear in org B's window")
	require.NoError(t, l.Admit("org-b", "ci", money.MustFromCents(99)),
		"org B's identical workload name must not inherit org A's saturation")
	l.Charge("org-b", "ci", money.MustFromCents(50))
	assert.Equal(t, money.MustFromCents(50), l.Spent("org-b", "ci"))
	assert.Equal(t, money.MustFromCents(100), l.Spent("org-a", "ci"),
		"org B's charges must not leak into org A's window")

	// The same key under a third org stays independent too.
	l.Charge("org-c", "ci", money.MustFromCents(1))
	assert.Equal(t, money.MustFromCents(1), l.Spent("org-c", "ci"))
}

func TestWorkloadLedger_DayRollResetsWindow(t *testing.T) {
	now := time.Date(2026, 10, 25, 23, 50, 0, 0, time.UTC)
	l := NewWorkloadLedger(money.MustFromCents(100), 0)
	l.now = func() time.Time { return now }

	l.Charge("", "wl", money.MustFromCents(100))
	require.ErrorIs(t, l.Admit("", "wl", money.MustFromCents(1)), ErrWorkloadBudgetExceeded)

	now = now.Add(2 * time.Hour) // past the UTC day boundary
	require.NoError(t, l.Admit("", "wl", money.MustFromCents(1)), "new window starts empty")
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "wl"))
}

func TestWorkloadLedger_TTLSweepsIdleEntries(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	l := NewWorkloadLedger(money.MustFromCents(100), time.Hour)
	l.now = func() time.Time { return now }

	l.Charge("", "wl", money.MustFromCents(10))
	now = now.Add(2 * time.Hour)
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "wl"), "idle entry swept past the TTL")
}

// TestWorkloadLedger_BoundedKeyCardinality pins the F2 remediation: keys are
// caller-controlled and unlimited, so an enabled ledger must bound its map —
// inserting well past DefaultWorkloadMaxKeys-style bounds keeps the map at
// the bound (TTL sweep + oldest-half eviction) while a hot window that keeps
// being touched survives and keeps correct accounting.
func TestWorkloadLedger_BoundedKeyCardinality(t *testing.T) {
	const maxKeys = 8
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)
	l.maxKeys = maxKeys

	// A hot workload charges continuously while a tenant cycles distinct
	// keys past the bound (e.g. per-build names).
	const floods = 100
	cent := money.MustFromCents(1)
	for i := 0; i < floods; i++ {
		l.Charge("", fmt.Sprintf("build-%d", i), cent)
		l.Charge("", "hot", cent) // keeps "hot" the most recently touched key
	}

	assert.LessOrEqual(t, len(l.byKey), maxKeys,
		"the ledger's key cardinality must stay at the bound")
	assert.Equal(t, money.MustFromCents(floods), l.Spent("", "hot"),
		"the hot window must survive eviction and keep accruing")

	// Accounting stays correct after eviction: hot is exactly at its cap,
	// so a further projected charge is denied and headroom admits.
	require.ErrorIs(t, l.Admit("", "hot", cent), ErrWorkloadBudgetExceeded)
	l.Charge("", "post-eviction", cent)
	assert.Equal(t, cent, l.Spent("", "post-eviction"), "a window created after eviction starts fresh")
}

func TestWorkloadLedger_ConcurrentAdmitChargeOvershootBounded(t *testing.T) {
	const cap = int64(10_000_000) // 10 USD in micro-USD
	const charge = int64(10_000)  // 0.01 USD per admitted request
	const workers = 16
	const iterations = 64
	l := NewWorkloadLedger(money.MicroUSD(cap), 0)

	var mu sync.Mutex
	denied := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// The admit projects the request's own charge; only a pass
				// books it. Overshoot is bounded by concurrent passes whose
				// charges land before the next check observes them.
				if err := l.Admit("", "wl", money.MicroUSD(charge)); err != nil {
					mu.Lock()
					denied++
					mu.Unlock()
					continue
				}
				l.Charge("", "wl", money.MicroUSD(charge))
			}
		}()
	}
	wg.Wait()

	// Point-in-time admits are not reservations: each worker may hold one
	// in-flight charge past its last observation, so the window can end
	// past the cap — bounded by the workers' concurrent charges, exactly
	// the semantics documented on Admit.
	spent := l.Spent("", "wl")
	assert.Positive(t, spent, "charges must book under concurrency")
	assert.GreaterOrEqual(t, int64(spent), cap-int64(charge), "the window fills to its cap")
	assert.Less(t, int64(spent), cap+int64(workers)*int64(charge),
		"overshoot is bounded by the workers' in-flight charges")
	assert.Positive(t, denied, "a capped ledger must eventually deny under load")
}
