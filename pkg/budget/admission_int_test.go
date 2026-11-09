//go:build integration

// NEXT-18c acceptance tests on a disposable live Postgres (ADR-0001 rev. 3
// §10, heavy runs under the machine semaphore): the admission layer's
// pre-check, local-escrow reserve/grant cycle, finalize accounting, idle
// return + renewal housekeeping, the multi-replica reserved+Δ ≤ L invariant
// under concurrency 1/10/100, crash → TTL → reconcile, shadow
// accounts-without-denying and the unpriced refusal (I3).
package budget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// stubPricer prices every model at the given USD-per-1M rates.
type stubPricer struct {
	in, out float64
}

func (p stubPricer) Lookup(_, _ string) (pricing.Price, bool) {
	return pricing.Price{InputPerM: p.in, OutputPerM: p.out}, true
}

type emptyPricer struct{}

func (emptyPricer) Lookup(_, _ string) (pricing.Price, bool) { return pricing.Price{}, false }

// admissionTestHarness wires store + controller for one test org. The
// controller's org loader returns fixed settings (the mode under test); the
// store uses floor 0 so the wallet's free capacity equals its balance.
type admissionTestHarness struct {
	store *ReservationStore
	adm   *Admission
	org   string
	mode  Mode
}

func newHarness(t *testing.T, pool *pgxpool.Pool, org string, mode Mode) *admissionTestHarness {
	t.Helper()
	store := NewReservationStoreWithConfig(pool, nil, ReservationConfig{
		DefaultGraceFloorCents: 0, // zero floor: free capacity == balance exactly
	})
	loader := func(context.Context, string) (OrgSettings, error) {
		return OrgSettings{Mode: mode}, nil
	}
	adm := NewAdmission(store, ScopedRateSource{
		Base:   BaseRateSource{Pricer: stubPricer{in: 2, out: 2}},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, stubPricer{in: 2.3, out: 2.3}, nil)},
	}, nil, "int-replica-"+uuid.NewString()[:8], mode, loader, AdmissionConfig{})
	return &admissionTestHarness{store: store, adm: adm, org: org, mode: mode}
}

// request is the harness's standard chat-shaped estimate: 100 input bytes,
// no explicit output cap (out_cap = 65536 default).
func (h *admissionTestHarness) request() Request {
	return Request{
		OrgID:      h.org,
		Chain:      []ChainHop{{Provider: "openai", Model: "stub-model"}},
		InputBytes: 100,
	}
}

func TestNext18cLive_PlanPrecheckDeniesExhaustion(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	t.Run("enforce denies before any work (D7)", func(t *testing.T) {
		org := "org-18c-exh-" + uuid.NewString()[:8]
		setWallet(t, pool, org, 0, nil) // free = 0 < bound
		h := newHarness(t, pool, org, ModeEnforce)

		plan, err := h.adm.Plan(ctx, h.request())
		require.Nil(t, plan)
		require.Error(t, err)
		var denial *Denial
		require.True(t, errors.As(err, &denial))
		require.Equal(t, ScopeWallet, denial.Scope)
		require.True(t, errors.Is(err, ErrInsufficientCapacity))

		// The refusal caches for the pre-check TTL: a second plan refuses
		// the same way without a fresh probe.
		_, err = h.adm.Plan(ctx, h.request())
		require.True(t, errors.Is(err, ErrInsufficientCapacity))
	})

	t.Run("shadow records would-deny and proceeds", func(t *testing.T) {
		org := "org-18c-shexh-" + uuid.NewString()[:8]
		setWallet(t, pool, org, 0, nil)
		h := newHarness(t, pool, org, ModeShadow)

		plan, err := h.adm.Plan(ctx, h.request())
		require.NoError(t, err)
		require.Equal(t, ModeShadow, plan.Mode)
		bound := plan.Scopes[0].Bound // priced despite the would-deny
		require.Len(t, plan.WouldDeny, 1)
		require.True(t, errors.Is(plan.WouldDeny[0].Err, ErrInsufficientCapacity))

		// Shadow never refuses: a funded wallet reserves for accounting.
		// (A fresh controller mirrors the 5s refusal cache expiring.)
		setWallet(t, pool, org, 1000, nil) // $10.00 → free 10M µ ≫ bound
		h2 := newHarness(t, pool, org, ModeShadow)
		plan, err = h2.adm.Plan(ctx, h2.request())
		require.NoError(t, err)
		require.Empty(t, plan.WouldDeny)
		rsv, err := h2.adm.Reserve(ctx, plan)
		require.NoError(t, err)
		require.NotNil(t, rsv)
		require.NotEmpty(t, rsv.TuplesJSON())
		require.Equal(t, int64(bound), walletState(t, pool, org))
	})
}

// TestNext18cLive_DeploymentGateClampsStoredMode (N06-P03/T06, live
// environment, real store): the deployment gate at shadow degrades a stored
// enforce org — the whole runtime pipeline (Plan bounds against the real
// wallet, Reserve, Finalize) runs exactly as shadow and carries the clamped
// mode, the same value budget.EffectiveMode computes for the admin API's
// effective_reservations_mode. The exhausted-wallet case is the sharpest
// negative: under the stored enforce mode it would deny (see
// PlanPrecheckDeniesExhaustion), under the clamped shadow it is served.
func TestNext18cLive_DeploymentGateClampsStoredMode(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	// The loader returns the STORED org mode (enforce); the controller's
	// global gate is the deployment rollout stage (shadow).
	storedEnforce := func(context.Context, string) (OrgSettings, error) {
		return OrgSettings{Mode: ModeEnforce}, nil
	}
	newClamped := func(replica string) *Admission {
		return NewAdmission(NewReservationStoreWithConfig(pool, nil, ReservationConfig{DefaultGraceFloorCents: 0}),
			ScopedRateSource{
				Base:   BaseRateSource{Pricer: stubPricer{in: 2, out: 2}},
				Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, stubPricer{in: 2.3, out: 2.3}, nil)},
			}, nil, replica, ModeShadow, storedEnforce, AdmissionConfig{})
	}

	t.Run("funded wallet reserves as shadow under the clamped mode", func(t *testing.T) {
		org := "org-n06p3-clamp-" + uuid.NewString()[:8]
		setWallet(t, pool, org, 1000, nil) // $10.00 → free 10M µ ≫ bound
		adm := newClamped("int-replica-" + uuid.NewString()[:8])

		plan, err := adm.Plan(ctx, Request{
			OrgID: org, Chain: []ChainHop{{Provider: "openai", Model: "stub-model"}}, InputBytes: 100,
		})
		require.NoError(t, err)
		require.Equal(t, ModeShadow, plan.Mode, "stored enforce degraded to the deployment shadow gate")
		require.Empty(t, plan.WouldDeny)
		require.Positive(t, int64(plan.Scopes[0].Bound))

		rsv, err := adm.Reserve(ctx, plan)
		require.NoError(t, err)
		require.NotNil(t, rsv)
		require.Equal(t, ModeShadow, rsv.Mode)
		require.NotEmpty(t, rsv.TuplesJSON())
		adm.Finalize(rsv, 1_000_000, 1_000_000)
	})

	t.Run("exhausted wallet is served with would-deny, not denied", func(t *testing.T) {
		org := "org-n06p3-clampx-" + uuid.NewString()[:8]
		setWallet(t, pool, org, 0, nil) // free = 0 < bound
		adm := newClamped("int-replica-" + uuid.NewString()[:8])

		plan, err := adm.Plan(ctx, Request{
			OrgID: org, Chain: []ChainHop{{Provider: "openai", Model: "stub-model"}}, InputBytes: 100,
		})
		require.NoError(t, err, "clamped shadow must not deny what stored enforce would")
		require.Equal(t, ModeShadow, plan.Mode)
		require.Len(t, plan.WouldDeny, 1)
		require.True(t, errors.Is(plan.WouldDeny[0].Err, ErrInsufficientCapacity))
	})
}

// TestNext18cLive_ReserveGrantLocalFitFinalize: the first reserve grants
// from Postgres (escrow visible in the scope row), the second fits locally
// without a new grant, finalize consumes the local escrow by the actual and
// leaves the DB reserve to the worker.
func TestNext18cLive_ReserveGrantLocalFitFinalize(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18c-cycle-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1000, nil) // $10.00 → free 10M µ
	h := newHarness(t, pool, org, ModeEnforce)

	plan, err := h.adm.Plan(ctx, h.request())
	require.NoError(t, err)
	require.Equal(t, ModeEnforce, plan.Mode)
	require.Len(t, plan.Scopes, 1)
	require.Equal(t, ScopeWallet, plan.Scopes[0].Scope)
	bound := plan.Scopes[0].Bound // priced (rates include the 15% default markup)
	require.Positive(t, int64(bound))

	// A spend history sizes the grant above one bound: rate 1M µ/s × 5s
	// horizon = 5M µ, clamped to 10% of the 10M µ capacity = 1M µ escrow.
	// Several bounds fit — the second request must ride the local escrow.
	h.adm.mu.Lock()
	h.adm.spendRate[ledgerKey{ScopeWallet, org, ""}] = rateStat{ratePerSecond: 1_000_000, avgBound: bound}
	h.adm.mu.Unlock()

	rsv, err := h.adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.NotNil(t, rsv)
	require.Equal(t, int64(1_000_000), walletState(t, pool, org), "grant sized min(rate×horizon, 10%×free)")

	_, granted, returned, status, _ := allowanceRow(t, pool, h.adm.replicaID, ScopeWallet, org, "")
	require.Equal(t, int64(1_000_000), granted)
	require.Equal(t, int64(0), returned)
	require.Equal(t, AllowanceActive, status)

	// Second request: the bound fits the remaining local escrow — no new
	// grant, even though the first request is still in flight.
	plan2, err := h.adm.Plan(ctx, h.request())
	require.NoError(t, err)
	rsv2, err := h.adm.Reserve(ctx, plan2)
	require.NoError(t, err)
	require.NotNil(t, rsv2)
	_, granted2, _, _, _ := allowanceRow(t, pool, h.adm.replicaID, ScopeWallet, org, "")
	require.Equal(t, granted, granted2, "local fit must not grow the grant")

	// Finalize: in-flight bounds release; the actual spend (half the bound
	// each) accumulates locally. The DB reserve is untouched — the worker
	// settles it later against the tuples.
	half := bound / 2
	h.adm.Finalize(rsv, half, half)
	h.adm.Finalize(rsv2, half, half)
	require.Equal(t, int64(1_000_000), walletState(t, pool, org))
	require.Equal(t, int64(1_000_000-2*int64(half)), int64(h.adm.LocalEscrow()))
}

// TestNext18cLive_MultiReplicaConcurrentInvariant: two admission instances
// ("replicas") over ONE Postgres admit under concurrency 1/10/100. The
// invariant reserved + Δ ≤ L holds exactly: ⌊L/bound⌋ requests are admitted
// and the scope row's reserve never exceeds the capacity.
func TestNext18cLive_MultiReplicaConcurrentInvariant(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	for _, concurrency := range []int{1, 10, 100} {
		t.Run(fmt.Sprintf("concurrency_%d", concurrency), func(t *testing.T) {
			org := fmt.Sprintf("org-18c-conc-%d-%s", concurrency, uuid.NewString()[:8])

			replicas := []*Admission{
				newHarness(t, pool, org, ModeEnforce).adm,
				newHarness(t, pool, org, ModeEnforce).adm,
			}

			// Measure the bound on the unseeded org (the pre-check probe
			// stays silent without a wallet row) and size the wallet to
			// exactly `concurrency` bounds: free capacity = ceil(c×b/100¢),
			// which fits c bounds and cannot fit c+1.
			probe, err := replicas[0].Plan(ctx, Request{
				OrgID:      org,
				Chain:      []ChainHop{{Provider: "openai", Model: "stub-model"}},
				InputBytes: 100,
				MaxTokens:  ptrInt64(999_960),
			})
			require.NoError(t, err)
			bound := int64(probe.Scopes[0].Bound)
			require.Positive(t, bound)
			setWallet(t, pool, org, (int64(concurrency)*bound+9999)/10000, nil)

			var wg sync.WaitGroup
			var admitted, denied atomic.Int64
			var errMu sync.Mutex
			var unexpected []error
			record := func(err error) {
				errMu.Lock()
				unexpected = append(unexpected, err)
				errMu.Unlock()
			}
			for i := 0; i < concurrency*100; i++ { // heavy oversubscription
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					adm := replicas[n%len(replicas)]
					req := Request{
						OrgID:      org,
						Chain:      []ChainHop{{Provider: "openai", Model: "stub-model"}},
						InputBytes: 100,
						MaxTokens:  ptrInt64(999_960), // same shape the bound was measured with
					}
					plan, err := adm.Plan(ctx, req)
					if err != nil {
						if errors.Is(err, ErrInsufficientCapacity) {
							denied.Add(1)
							return
						}
						record(err)
						return
					}
					rsv, err := adm.Reserve(ctx, plan)
					if err != nil {
						if errors.Is(err, ErrInsufficientCapacity) {
							denied.Add(1)
							return
						}
						record(err)
						return
					}
					if rsv != nil {
						admitted.Add(1)
					}
				}(i)
			}
			wg.Wait()
			for _, err := range unexpected {
				t.Fatalf("unexpected error: %v", err)
			}

			require.Equal(t, int64(concurrency), admitted.Load(), "exactly ⌊L/bound⌋ admits")
			reserved := walletState(t, pool, org)
			require.LessOrEqual(t, reserved, int64(concurrency)*bound, "reserved ≤ L")
			require.Equal(t, int64(concurrency)*bound, reserved, "escrow exactly allocated")
		})
	}
}

func ptrInt64(n int64) *int64 { return &n }

// TestR040_MissingSettingFailsClosed: the negative scenario «нет настройки»
// pinned end-to-end at the admission layer. A request attributed to a team
// WITHOUT a team_budgets row must deny in enforce mode (D14 fail-closed,
// *Denial wrapping ErrNoCapacitySource) — never a silent unlimited admit.
// The probe stays the authority the pre-check defers to: it reports the
// missing source explicitly. The wallet face of «нет настройки» — a NULL
// per-org grace floor — means the platform default −$1.00 (D1 stays:
// DefaultReservationConfig), surfaced as free = balance + 1M µ.
func TestR040_MissingSettingFailsClosed(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-nosetting-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000, nil) // NULL per-org floor

	// Enforce: the pre-check stays silent on the missing team row (the
	// grant decides); Reserve's grant refuses the whole request.
	h := newHarness(t, pool, org, ModeEnforce)
	plan, err := h.adm.Plan(ctx, Request{
		OrgID:      org,
		TeamID:     uuid.NewString(), // exists nowhere: no team_budgets row
		Chain:      []ChainHop{{Provider: "openai", Model: "stub-model"}},
		InputBytes: 100,
	})
	require.NoError(t, err, "the pre-check defers a missing capacity source to the grant")
	_, err = h.adm.Reserve(ctx, plan)
	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.ErrorIs(t, err, ErrNoCapacitySource, "missing budget row denies (D14), never unlimited")

	// The probe surface names the missing source explicitly.
	_, err = h.store.ProbeFreeCapacity(ctx, org, GrantRequest{
		Scope: ScopeTeamMonth, Key: uuid.NewString(), Period: "2026-10", Bound: 1,
	})
	require.ErrorIs(t, err, ErrNoCapacitySource)

	// Shadow never denies for a missing source: the request proceeds
	// unreserved with the would-deny recorded.
	hs := newHarness(t, pool, org, ModeShadow)
	plan, err = hs.adm.Plan(ctx, Request{
		OrgID:      org,
		TeamID:     uuid.NewString(),
		Chain:      []ChainHop{{Provider: "openai", Model: "stub-model"}},
		InputBytes: 100,
	})
	require.NoError(t, err)
	_, err = hs.adm.Reserve(ctx, plan)
	require.ErrorIs(t, err, ErrNotReserved, "shadow proceeds unreserved, never unlimited-granted")
	require.Len(t, plan.WouldDeny, 1)
	require.ErrorIs(t, plan.WouldDeny[0].Err, ErrNoCapacitySource)

	// D1 stays: a NULL per-org floor means the platform default −$1.00
	// (the §14 store default), not zero and not unlimited.
	defStore := NewReservationStore(pool, nil)
	free, err := defStore.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	require.Equal(t, int64(101_000_000), int64(free),
		"$100 balance + $1 platform-default floor = 101M µ free")
}

// TestNext18cLive_CrashReleasesViaReconcile: a replica that dies between
// grant and finalize stops renewing; its lease lapses, reconcile releases
// the allowance and the freed capacity funds a NEW replica's grant.
func TestNext18cLive_CrashReleasesViaReconcile(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18c-crash-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 200, nil) // free 2M µ ≫ one bound

	crashed := newHarness(t, pool, org, ModeEnforce)
	plan, err := crashed.adm.Plan(ctx, crashed.request())
	require.NoError(t, err)
	bound := plan.Scopes[0].Bound
	rsv, err := crashed.adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.NotNil(t, rsv)
	require.Equal(t, int64(bound), walletState(t, pool, org))

	// The replica crashes: no shutdown, no finalize, no renewal. Force the
	// lease lapse the way time would.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '1 hour' WHERE replica_id = $1`,
		crashed.adm.replicaID)
	require.NoError(t, err)

	summary, err := crashed.store.ReconcileRelease(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), summary.Released)
	require.Equal(t, int64(0), walletState(t, pool, org), "reconcile returns the reserve")

	// A new replica instance grants the freed capacity.
	fresh := newHarness(t, pool, org, ModeEnforce)
	plan2, err := fresh.adm.Plan(ctx, fresh.request())
	require.NoError(t, err)
	rsv2, err := fresh.adm.Reserve(ctx, plan2)
	require.NoError(t, err)
	require.NotNil(t, rsv2, "freed capacity funds a fresh replica")
	require.NotEqual(t, rsv.Scopes[0].AllowanceID, rsv2.Scopes[0].AllowanceID)
}

// TestNext18cLive_ReturnRemainingHoldback: the idle return hands back the
// DB remainder minus the unsettled holdback — in-flight bounds and
// finalized-but-unsettled spend stay claimed for their settles.
func TestNext18cLive_ReturnRemainingHoldback(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18c-hold-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10000, nil) // free 100M µ → fraction cap 10M µ

	h := newHarness(t, pool, org, ModeEnforce)
	// A spend history sizes the grant above the bound: rate 2M µ/s × 5s
	// horizon = 10M µ (the fraction cap 10.1M does not pinch).
	h.adm.mu.Lock()
	h.adm.spendRate[ledgerKey{ScopeWallet, org, ""}] = rateStat{ratePerSecond: 2_000_000, avgBound: 200_000}
	h.adm.mu.Unlock()

	plan, err := h.adm.Plan(ctx, h.request())
	require.NoError(t, err)
	rsv, err := h.adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.NotNil(t, rsv)
	require.Equal(t, int64(10_000_000), walletState(t, pool, org), "grant sized rate×horizon")

	// Idle return with a 1M µ holdback (one request still unsettled):
	// returns 9M µ, the holdback stays claimed.
	summary, err := h.store.ReturnRemaining(ctx, org, h.adm.replicaID, []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 1_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(9_000_000), summary.ReturnedMicroUSD)
	require.Equal(t, int64(1_000_000), walletState(t, pool, org))

	// Finalizing records the spend locally; the holdback now carries it, so
	// the worker's later settle (min(actual,bound) = 300k) cannot underflow.
	h.adm.Finalize(rsv, 300_000, 300_000)
	summary, err = h.store.ReturnRemaining(ctx, org, h.adm.replicaID, []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 300_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(700_000), summary.ReturnedMicroUSD)
	require.Equal(t, int64(300_000), walletState(t, pool, org),
		"unsettled spend stays claimed until the worker settles it")

	// An over-held remainder returns nothing.
	summary, err = h.store.ReturnRemaining(ctx, org, h.adm.replicaID, []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 999_999_999},
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), summary.ReturnedMicroUSD)
}

// TestNext18cLive_HousekeepRenewsAndReturnsIdle: the housekeeping cycle
// renews lapsed leases and returns idle escrow — both driven
// deterministically through the pinned clock.
func TestNext18cLive_HousekeepRenewsAndReturnsIdle(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18c-house-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1000, nil)

	h := newHarness(t, pool, org, ModeEnforce)
	now := time.Now()
	h.adm.SetClock(func() time.Time { return now })

	plan, err := h.adm.Plan(ctx, h.request())
	require.NoError(t, err)
	rsv, err := h.adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.NotNil(t, rsv)

	// Renewal: force the lease to lapse, then a renewal-due housekeep
	// restores active status with a fresh lease.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '1 minute', status = $2 WHERE replica_id = $1`,
		h.adm.replicaID, AllowanceExpired)
	require.NoError(t, err)
	h.adm.housekeep(ctx, true)
	_, _, _, status, lease := allowanceRow(t, pool, h.adm.replicaID, ScopeWallet, org, "")
	require.Equal(t, AllowanceActive, status)
	require.True(t, time.Until(lease) > 9*time.Minute, "renewal re-extends by one TTL")

	// Idle return: 10s of idleness (pinned clock) hands the escrow back.
	h.adm.Finalize(rsv, 0, 0)
	now = now.Add(11 * time.Second)
	h.adm.housekeep(ctx, false)
	require.Equal(t, int64(0), walletState(t, pool, org), "idle escrow returned")
	require.Equal(t, int64(0), int64(h.adm.LocalEscrow()), "ledger entry dropped")
}

// TestNext18cLive_UnpricedPlanFailsClosed: a chain without any priced
// candidate refuses estimation — enforce denies (I3 → 403 upstream), shadow
// records the would-deny and proceeds unreserved.
func TestNext18cLive_UnpricedPlanFailsClosed(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18c-unpriced-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1000, nil)

	store := NewReservationStoreWithConfig(pool, nil, ReservationConfig{DefaultGraceFloorCents: 0})
	unpricedRates := ScopedRateSource{
		Base:   BaseRateSource{Pricer: emptyPricer{}},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(pool, emptyPricer{}, nil)},
	}
	enforceLoader := func(context.Context, string) (OrgSettings, error) { return OrgSettings{Mode: ModeEnforce}, nil }
	adm := NewAdmission(store, unpricedRates, nil, "int-replica-"+uuid.NewString()[:8], ModeEnforce, enforceLoader, AdmissionConfig{})

	_, err := adm.Plan(ctx, Request{
		OrgID:      org,
		Chain:      []ChainHop{{Provider: "openai", Model: "mystery"}},
		InputBytes: 100,
	})
	require.True(t, errors.Is(err, ErrUnpricedModel))

	shadowLoader := func(context.Context, string) (OrgSettings, error) {
		return OrgSettings{Mode: ModeShadow}, nil
	}
	admShadow := NewAdmission(store, unpricedRates, nil, "int-replica-"+uuid.NewString()[:8], ModeShadow, shadowLoader, AdmissionConfig{})
	plan, err := admShadow.Plan(ctx, Request{
		OrgID:      org,
		Chain:      []ChainHop{{Provider: "openai", Model: "mystery"}},
		InputBytes: 100,
	})
	require.NoError(t, err)
	require.Equal(t, ModeShadow, plan.Mode)
	require.Len(t, plan.WouldDeny, 1)
	require.True(t, errors.Is(plan.WouldDeny[0].Err, ErrUnpricedModel))
	rsv, err := admShadow.Reserve(ctx, plan)
	require.ErrorIs(t, err, ErrNotReserved, "unpriced shadow request proceeds unreserved")
	require.Nil(t, rsv)
	require.Equal(t, int64(0), walletState(t, pool, org))
}
