package budget

// N06-P07-T05 negative-path proof for the workload chargeback ledger: the
// failure modes must be observable and fail-closed, never silently absorbed.
// Covers the card's negative classes at the ledger seam — unknown/missing
// org namespaces, malformed usage records, eviction-boundary refusals, and
// the adversarial ≥2-orgs never-share-ledger invariant (including the
// concatenation-aliasing probe the workloadKey struct must defeat).

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/money"
)

// TestWorkloadLedger_KeyBoundOneRefusesNewKeys pins the fail-closed refusal
// at the degenerate key bound (maxKeys = 1): half-eviction cannot free a
// slot for a NEW key, so the ledger must refuse it — Admit denies with the
// standard sentinel, Charge records nothing — and the bound must hold. The
// existing key's window keeps working with exact accounting.
func TestWorkloadLedger_KeyBoundOneRefusesNewKeys(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)
	l.maxKeys = 1

	// The one tracked window works normally.
	l.Charge("", "held", money.MustFromCents(40))
	require.Equal(t, money.MustFromCents(40), l.Spent("", "held"))
	require.NoError(t, l.Admit("", "held", money.MustFromCents(59)),
		"the held window still has headroom below the cap")

	// A NEW key is refused, in both entry points, with zero state growth.
	err := l.Admit("", "intruder", money.MicroUSD(0))
	require.ErrorIs(t, err, ErrWorkloadBudgetExceeded,
		"a new key at the un-expandable bound must fail closed")
	require.Contains(t, err.Error(), "key bound",
		"the refusal must name the bound, not look like a cap saturation")
	l.Charge("", "intruder", money.MustFromCents(10))
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "intruder"),
		"a refused key must have no window and no recorded spend")
	assert.Len(t, l.byKey, 1, "the ledger must not grow past the bound")

	// Repeated refusals stay stable and the held window is untouched.
	for i := 0; i < 3; i++ {
		require.ErrorIs(t, l.Admit("", fmt.Sprintf("probe-%d", i), money.MicroUSD(0)),
			ErrWorkloadBudgetExceeded)
	}
	assert.Len(t, l.byKey, 1)
	assert.Equal(t, money.MustFromCents(40), l.Spent("", "held"),
		"refused probes must not disturb the tracked window")
}

// TestWorkloadLedger_EvictionBoundaryTwo pins the boundary where
// half-eviction CAN make room (maxKeys = 2): the third key evicts exactly the
// oldest half, the bound holds exactly, the hot window keeps exact
// accounting, and the evicted key restarts FRESH — the documented
// approximation loss, observable as neither an inherited phantom cap nor a
// forever-deny (the cap degrades, attribution lives in the events).
// A scripted clock orders lastSeen explicitly: real timestamps on this
// machine can tie within one tick and make the eviction choice nondeterministic.
// The anchor must also be a FIXED UTC instant far from any day boundary
// (flake-ledger F18, fixed 2026-11-02): this test was once anchored to
// time.Now(), and in covering battery 20261101T234941Z-f0bf146b it started
// at 23:58:20.225Z — the sequence's +3-minute synthetic window crossed UTC
// midnight before the second hot charge, so the ledger's by-design
// UTC-day-roll reset hot's window mid-sequence and the test failed with
// "expected: 100000 / actual: 50000" (registered flake, jobs.md update 192;
// mis-attributed to CPU load there). The product semantics were correct —
// the day roll is pinned by TestWorkloadLedger_DayRollResetsWindow — the
// wall-clock anchor was the defect: a day-windowed accumulator must never
// be driven by a wall-clock-anchored test clock. UTC noon leaves 12 hours
// of margin to any boundary; the midnight-crossing interplay itself is
// pinned deterministically, at any wall clock, by
// TestWorkloadLedger_EvictionBoundaryAcrossUTCDayRoll.
func TestWorkloadLedger_EvictionBoundaryTwo(t *testing.T) {
	const maxKeys = 2
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)
	l.maxKeys = maxKeys
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	// "old" saturates its window at t0 and is probed AT t0 — the probe must
	// precede the hot charges because every touch (Admit included, reset-
	// on-hit) refreshes lastSeen: a t2 probe would tie "old" with "hot" and
	// leave the eviction choice to randomized map order. Production corollary
	// pinned here implicitly: a denied window stays resident (fail-closed).
	l.Charge("", "old", cap)
	require.ErrorIs(t, l.Admit("", "old", money.MicroUSD(1)), ErrWorkloadBudgetExceeded)

	// "hot" stays warm at t1 > t0 and t2 > t1.
	now = now.Add(time.Minute)
	l.Charge("", "hot", money.MustFromCents(5))
	now = now.Add(time.Minute)
	l.Charge("", "hot", money.MustFromCents(5))

	// The third key at t3 > t2 forces eviction of exactly one — "old",
	// the least-recently-touched entry.
	now = now.Add(time.Minute)
	l.Charge("", "fresh", money.MustFromCents(1))
	assert.Len(t, l.byKey, maxKeys, "the bound must hold exactly at the boundary")
	assert.Equal(t, money.MustFromCents(1), l.Spent("", "fresh"),
		"the inserted key keeps its charge")
	assert.Equal(t, money.MustFromCents(10), l.Spent("", "hot"),
		"the hot window must survive the boundary eviction with exact accounting")

	// The evicted key restarts fresh: no inherited spend, no stuck denial.
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "old"),
		"the evicted key must not keep a phantom window")
	require.NoError(t, l.Admit("", "old", money.MustFromCents(99)),
		"the fresh window must admit again — eviction degrades the cap, it must not deadlock")
}

// TestWorkloadLedger_EvictionBoundaryAcrossUTCDayRoll is the deterministic
// regression pin for the F18 flake class: the exact boundary sequence run
// with a clock that crosses UTC midnight between hot's two charges — the
// scenario the boundary test used to hit by accident whenever a real run
// started between 23:57:00 and 00:00:00 UTC (fleet occurrence: battery
// 20261101T234941Z-f0bf146b, start 23:58:20.225Z, "expected: 100000 /
// actual: 50000"). Pinning the interplay here converts that once-per-day
// wall-clock lottery into an always-on assertion. The product contract in
// this scenario is threefold:
//
//  1. the UTC day roll resets the touched window to a fresh day window
//     (the documented approximation loss; TestWorkloadLedger_DayRollResetsWindow
//     pins the reset at the window level) — observable here as hot keeping
//     exactly its post-roll charge;
//  2. the roll still refreshes lastSeen at the touch, so the eviction
//     choice stays deterministic across the roll: "old" (longest untouched)
//     is evicted, the rolled window survives resident;
//  3. the bound holds exactly and the evicted key restarts fresh with no
//     stuck denial.
//
// A ledger change that breaks any of the three — a roll that stops
// refreshing day/lastSeen in the pinned order, or an eviction that no
// longer treats a rolled window by its refreshed lastSeen — fails this pin
// deterministically, at any wall clock, instead of once a day under fleet
// load.
func TestWorkloadLedger_EvictionBoundaryAcrossUTCDayRoll(t *testing.T) {
	const maxKeys = 2
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)
	l.maxKeys = maxKeys
	// 23:58 UTC: t0 lands on day 2026-10-26, the first hot charge at t1
	// stays on it, the second at t2 crosses 00:00 UTC into 2026-10-27 —
	// exactly the fleet failure's shape (23:58:20 → 00:00:20).
	now := time.Date(2026, 10, 26, 23, 58, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	l.Charge("", "old", cap)
	require.ErrorIs(t, l.Admit("", "old", money.MicroUSD(1)), ErrWorkloadBudgetExceeded)

	now = now.Add(time.Minute) // still day 1: hot's window opens with 5c
	l.Charge("", "hot", money.MustFromCents(5))
	now = now.Add(time.Minute) // day 2: the day-roll reset fires on the touch
	l.Charge("", "hot", money.MustFromCents(5))

	rolled := l.byKey[workloadKey{org: "", id: "hot"}]
	require.NotNil(t, rolled, "the rolled window must survive the boundary eviction, resident")
	assert.Equal(t, "2026-10-27", rolled.day,
		"the touch on the new UTC day must roll the window's day forward")
	assert.Equal(t, money.MustFromCents(5), rolled.spent,
		"the day roll resets the window: hot keeps exactly its post-roll charge (the fleet failure's 50000, pinned as contract)")

	// The third key at t3 (day 2) forces eviction of exactly one — "old",
	// still the least-recently-touched: the roll refreshed hot's lastSeen,
	// so the midnight crossing must not reorder the eviction choice.
	now = now.Add(time.Minute)
	l.Charge("", "fresh", money.MustFromCents(1))
	assert.Len(t, l.byKey, maxKeys, "the bound must hold exactly across the day roll")
	assert.Equal(t, money.MustFromCents(1), l.Spent("", "fresh"))
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "old"),
		"the pre-roll window is the one evicted — the roll must not flip the eviction choice")

	// The evicted key restarts fresh: no inherited spend, no stuck denial.
	require.NoError(t, l.Admit("", "old", money.MustFromCents(99)),
		"the fresh window must admit again — eviction degrades the cap, it must not deadlock")
}

// TestWorkloadLedger_MalformedChargesIgnored pins the malformed-usage-record
// refusals: a negative charge (a sign error or a hostile upstream quote) must
// be ignored without creating state or corrupting the window, and a zero
// charge (the consumer's QuoteZero) must never fabricate spend.
func TestWorkloadLedger_MalformedChargesIgnored(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)

	// Negative charge: ignored entirely — no window, no state change.
	// (Constructed via raw conversion: MustFromCents refuses negatives by
	// design — exactly the malformed sign a hostile or buggy upstream
	// usage record could still deliver at the Charge boundary.)
	l.Charge("", "wl", money.MicroUSD(-5))
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "wl"))
	assert.Empty(t, l.byKey, "a refused malformed charge must not build state")

	// The window still admits a full valid plan afterwards.
	require.NoError(t, l.Admit("", "wl", cap-money.MustFromCents(1)),
		"an ignored malformed charge must not consume headroom")

	// Zero charge: books nothing (QuoteZero semantics).
	l.Charge("", "wl", money.MicroUSD(0))
	assert.Equal(t, money.MicroUSD(0), l.Spent("", "wl"), "a zero quote fabricates no spend")

	// Valid accounting continues undistorted on the same window.
	l.Charge("", "wl", money.MustFromCents(70))
	assert.Equal(t, money.MustFromCents(70), l.Spent("", "wl"))
	require.ErrorIs(t, l.Admit("", "wl", money.MustFromCents(31)), ErrWorkloadBudgetExceeded,
		"the malformed charges must not have shifted the window off the real total")
}

// TestWorkloadLedger_OverflowSaturatesFailClosed pins the oversized-usage
// negative: charges near the int64 ceiling saturate the window instead of
// wrapping negative, and a saturated window denies every further admission —
// fail-closed, with Spent staying a valid non-negative money amount.
func TestWorkloadLedger_OverflowSaturatesFailClosed(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)

	huge := money.MicroUSD(math.MaxInt64)
	l.Charge("", "wl", huge)
	l.Charge("", "wl", huge) // the add that would overflow

	spent := l.Spent("", "wl")
	require.Equal(t, huge, spent, "the window must saturate, never wrap negative")
	require.ErrorIs(t, l.Admit("", "wl", money.MicroUSD(0)), ErrWorkloadBudgetExceeded,
		"a saturated window is past the cap — fail closed")
	l.Charge("", "wl", money.MustFromCents(1))
	assert.Equal(t, huge, l.Spent("", "wl"), "post-saturation charges keep the saturation")

	// A saturated window must not poison its neighbors.
	l.Charge("", "other", money.MustFromCents(1))
	assert.Equal(t, money.MustFromCents(1), l.Spent("", "other"))
}

// TestWorkloadLedger_OrgNamespaceAliasMatrix is the adversarial never-share
// probe: a concatenation key would collide ("a"+"·"+"b:c" == "a:b"+"·"+"c"),
// so an org id containing the workload separator could impersonate another
// tenant's window. The struct key must keep every cell distinct, and the
// missing-org namespace ("") is its own tenant. Each cell is charged a
// distinct amount and every read must return exactly that amount — any
// aliasing or cross-talk shows up as a wrong number.
func TestWorkloadLedger_OrgNamespaceAliasMatrix(t *testing.T) {
	l := NewWorkloadLedger(money.MustFromCents(100), 0)

	cells := []struct {
		org, wl string
		amount  int64
	}{
		{"a", "b:c", 11},
		{"a:b", "c", 22},
		{"a", "c", 33},
		{"a:b", "b:c", 44},
		{"", "b:c", 55},
		{"", "c", 66},
	}
	for _, c := range cells {
		l.Charge(c.org, c.wl, money.MustFromCents(c.amount))
	}
	for _, c := range cells {
		assert.Equalf(t, money.MustFromCents(c.amount), l.Spent(c.org, c.wl),
			"(%q, %q) must hold exactly its own charges — no aliasing with any other cell", c.org, c.wl)
	}
	assert.Len(t, l.byKey, len(cells), "every cell is a distinct window")
}

// TestWorkloadLedger_MissingOrgNamespaceOwnTenant pins the unknown/missing
// org negatives at the window level: the empty org is its own namespace —
// saturating it denies only it, a named org's saturation never leaks back,
// and an org the ledger has never seen starts from zero.
func TestWorkloadLedger_MissingOrgNamespaceOwnTenant(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)

	l.Charge("", "ci", cap)
	require.ErrorIs(t, l.Admit("", "ci", money.MicroUSD(1)), ErrWorkloadBudgetExceeded,
		"the missing-org namespace is still a real window — enforced fail-closed")
	require.NoError(t, l.Admit("org-x", "ci", cap-money.MustFromCents(1)),
		"the missing-org saturation must not leak into a named org")

	l.Charge("org-x", "ci", cap)
	require.ErrorIs(t, l.Admit("org-x", "ci", money.MicroUSD(1)), ErrWorkloadBudgetExceeded)
	assert.Equal(t, cap, l.Spent("", "ci"),
		"a named org's saturation must not leak back into the missing-org namespace")

	assert.Equal(t, money.MicroUSD(0), l.Spent("org-never-seen", "ci"))
	require.NoError(t, l.Admit("org-never-seen", "ci", cap-money.MustFromCents(1)),
		"an unknown org must start from zero, not from any existing window")
}

// TestWorkloadLedger_CrossOrgConcurrentNeverShare is the adversarial
// ≥2-orgs never-share-ledger invariant under concurrency: three namespaces
// (two named orgs + the missing org) hammer the SAME workload name on
// parallel goroutines while a reader polls Spent. Every org's window must
// end with EXACTLY that org's own charges, org B and the missing org may
// never see a denial while org A saturates, and every read stays
// non-negative. Race-detector food by construction.
func TestWorkloadLedger_CrossOrgConcurrentNeverShare(t *testing.T) {
	cap := money.MustFromCents(100)
	l := NewWorkloadLedger(cap, 0)

	const (
		aCharges = 120 // drives A to and past its cap
		bCharges = 30  // stays under the cap → every admit must pass
		eCharges = 20  // the missing-org namespace, same guarantee
	)
	cent := money.MustFromCents(1)

	start := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { // org A: charge unconditionally (Charge is bookkeeping of fact)
		defer wg.Done()
		<-start
		for i := 0; i < aCharges; i++ {
			l.Charge("org-a", "ci", cent)
		}
	}()

	wg.Add(1)
	go func() { // org B: admit-then-charge; a denial here means cross-org leakage
		defer wg.Done()
		<-start
		for i := 0; i < bCharges; i++ {
			if err := l.Admit("org-b", "ci", cent); err != nil {
				t.Errorf("org-b admit failed while org-a saturated the same workload name: %v", err)
				return
			}
			l.Charge("org-b", "ci", cent)
		}
	}()

	wg.Add(1)
	go func() { // the missing org: same never-deny guarantee
		defer wg.Done()
		<-start
		for i := 0; i < eCharges; i++ {
			if err := l.Admit("", "ci", cent); err != nil {
				t.Errorf("missing-org admit failed while org-a saturated the same workload name: %v", err)
				return
			}
			l.Charge("", "ci", cent)
		}
	}()

	// Concurrent pure reader: Spent stays race-clean and non-negative.
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		<-start
		for {
			select {
			case <-stop:
				return
			default:
				for _, org := range []string{"org-a", "org-b", ""} {
					if s := l.Spent(org, "ci"); s < 0 {
						t.Errorf("Spent(%q) went negative: %d", org, int64(s))
						return
					}
				}
			}
		}
	}()

	close(start)
	wg.Wait()
	close(stop)
	<-readerDone

	assert.Equal(t, money.MustFromCents(aCharges), l.Spent("org-a", "ci"),
		"org A's window must hold exactly its own charges")
	assert.Equal(t, money.MustFromCents(bCharges), l.Spent("org-b", "ci"),
		"org B's window must hold exactly its own charges")
	assert.Equal(t, money.MustFromCents(eCharges), l.Spent("", "ci"),
		"the missing-org window must hold exactly its own charges")

	// A is at/past the cap and denies; the same name under B still admits.
	require.ErrorIs(t, l.Admit("org-a", "ci", cent), ErrWorkloadBudgetExceeded)
	require.NoError(t, l.Admit("org-b", "ci", cent), "org B keeps headroom of its own window")
}
