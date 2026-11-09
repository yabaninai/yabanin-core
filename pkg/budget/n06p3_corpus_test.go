package budget

// N06-P03 T07 — the boundary corpus for the effective-mode chain and the
// budget admission boundaries. Two layers, one effective mode:
//
//   - the pure chain (ResolveMode → EffectiveMode): the full 3×3 gate ×
//     stored matrix plus the unknown fail-closed cases, including the
//     documented precondition that ResolveMode must run BEFORE EffectiveMode;
//   - the runtime boundary (Plan/Reserve over a read-only probe double):
//     exhausted-at-limit, the exact-limit admit edge, the grace floor,
//     deny-next fast path, top-up mid-window, soft/hard/advisory scopes and
//     the mode flip mid-flight (org-cache skew + in-flight reservations).
//
// The store-backed grant/settle/reconcile flows stay under the integration
// tag against live Postgres (TestNext18cLive_*, TestR040_*, TestR042SelfReap_*)
// — cited, not faked: this corpus fakes only the read-only capacity probe.

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/stretchr/testify/require"
)

// corpusPricer prices every model at fixed USD-per-1M rates.
type corpusPricer struct{ in, out float64 }

func (p corpusPricer) Lookup(_, _ string) (pricing.Price, bool) {
	return pricing.Price{InputPerM: p.in, OutputPerM: p.out}, true
}

// corpusRates prices every scope from the stub table. The wallet rides a
// nil-pool MarkupPricer — its documented no-DB fallback (default 15%
// markup), so the whole corpus runs without a database connection.
func corpusRates() ScopedRateSource {
	return ScopedRateSource{
		Base:   BaseRateSource{Pricer: corpusPricer{in: 2, out: 2}},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(nil, corpusPricer{in: 2, out: 2}, nil)},
	}
}

// corpusLoader answers one mutable stored mode — the admin-side flip a
// mid-flight mode change is modeled with.
type corpusLoader struct{ stored Mode }

func (l *corpusLoader) load(context.Context, string) (OrgSettings, error) {
	return OrgSettings{Mode: l.stored}, nil
}

// probeDB is a read-only reservationDB double: it answers the capacity-probe
// queries (ReservationStore.ProbeFreeCapacity) from seeded wallet/team rows
// and counts the reads. Every write path fails loudly — grant/return/reconcile
// semantics are proven live, never faked.
type probeDB struct {
	mu             sync.Mutex
	balanceCents   int64
	remainderMicro int64
	floorCents     *int64
	reservedMicro  int64

	teamLimitMicro int64
	teamHard       bool
	teamSpendMicro int64
	teamReserved   int64

	walletProbes int
}

func (d *probeDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case strings.Contains(query, "FROM org_credits"):
		d.walletProbes++
		if d.floorCents == nil {
			return &probeRow{vals: []any{d.balanceCents, d.remainderMicro, nil, d.reservedMicro}}
		}
		return &probeRow{vals: []any{d.balanceCents, d.remainderMicro, *d.floorCents, d.reservedMicro}}
	case strings.Contains(query, "FROM team_budgets"):
		return &probeRow{vals: []any{d.teamLimitMicro, d.teamHard}}
	case strings.Contains(query, "FROM team_spend_monthly"):
		return &probeRow{vals: []any{d.teamSpendMicro, d.teamReserved}}
	default:
		return &probeRow{err: fmt.Errorf("probeDB: unexpected query: %s", query)}
	}
}

func (d *probeDB) Begin(context.Context) (pgx.Tx, error) {
	return nil, fmt.Errorf("probeDB is read-only: write paths are covered by the live integration suite")
}
func (d *probeDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("probeDB is read-only: write paths are covered by the live integration suite")
}
func (d *probeDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, fmt.Errorf("probeDB is read-only: write paths are covered by the live integration suite")
}
func (d *probeDB) probeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.walletProbes
}

// probeRow answers one canned QueryRow with exact column types
// (int64 / *int64 for the nullable floor / bool).
type probeRow struct {
	vals []any
	err  error
}

func (r *probeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.vals) {
		return fmt.Errorf("probeRow: %d destinations for %d values", len(dest), len(r.vals))
	}
	for i, d := range dest {
		switch v := d.(type) {
		case *int64:
			*v = r.vals[i].(int64)
		case **int64:
			if iv, ok := r.vals[i].(int64); ok {
				*v = &iv
			} else {
				*v = nil
			}
		case *bool:
			*v = r.vals[i].(bool)
		default:
			return fmt.Errorf("probeRow: unsupported destination %T", d)
		}
	}
	return nil
}

func newCorpusAdmission(t *testing.T, gate Mode, loader *corpusLoader, db *probeDB) *Admission {
	t.Helper()
	var store *ReservationStore
	if db != nil {
		store = NewReservationStoreWithConfig(db, nil, ReservationConfig{DefaultGraceFloorCents: 0})
	}
	adm := NewAdmission(store, corpusRates(), nil, "corpus-replica", gate, loader.load, AdmissionConfig{})
	t.Cleanup(adm.Stop)
	return adm
}

// corpusRequest is the standard chat-shaped estimate: 100 input bytes, no
// explicit output cap (out_cap falls to the 65536 default).
func corpusRequest(org string) Request {
	return Request{
		OrgID:      org,
		Chain:      []ChainHop{{Provider: "prov", Model: "stub-model"}},
		InputBytes: 100,
	}
}

// TestEffectiveModeBoundaryCorpus — T07 aspect 1: the complete 3×3
// (deployment gate × stored org mode) matrix through the ONE production
// chain, plus the unknown fail-closed cases on both inputs. The runtime
// (Admission.orgSettings) and the admin API
// (orgBudgetSettingsPayload.effective_reservations_mode) must derive the
// identical value — asserted here against the same pure function the API
// calls.
func TestEffectiveModeBoundaryCorpus(t *testing.T) {
	gates := []Mode{ModeOff, ModeShadow, ModeEnforce}
	stored := []Mode{ModeOff, ModeShadow, ModeEnforce}
	want := map[Mode]int{ModeOff: 0, ModeShadow: 1, ModeEnforce: 2}

	// The expected matrix: the deployment gate can only clamp DOWN
	// (enforce→shadow→off), never upgrade a stored mode; no clamp when the
	// stored mode is at or below the gate.
	for _, g := range gates {
		for _, s := range stored {
			expect := s
			if want[s] > want[g] {
				expect = g
			}
			name := fmt.Sprintf("gate_%s_stored_%s", g, s)
			t.Run(name, func(t *testing.T) {
				require.Equal(t, expect, EffectiveMode(g, s), "pure clamp")

				// The single runtime resolution (≤5s org cache) computes
				// exactly the pure value — one effective mode everywhere.
				ld := &corpusLoader{stored: s}
				adm := newCorpusAdmission(t, g, ld, nil)
				settings := adm.orgSettings(context.Background(), "org-matrix")
				require.Equal(t, expect, settings.Mode,
					"runtime and admin API derive the same effective mode")
			})
		}
	}

	// Unknown STORED values fail closed to off under every gate: a mistyped
	// or corrupt column value can never activate reservations.
	for _, g := range gates {
		for _, bad := range []string{"", "ENFORCE", "enforce_mistyped", "enforce ", "Shadow"} {
			t.Run(fmt.Sprintf("gate_%s_stored_unknown_%q", g, bad), func(t *testing.T) {
				require.Equal(t, ModeOff, EffectiveMode(g, ResolveMode(bad)))
			})
		}
	}

	// Unknown GATE values: the env/config side resolves through the same
	// ResolveMode before the clamp — a mistyped YABANIN_RESERVATIONS can
	// never raise the ceiling above off.
	for _, s := range gates {
		require.Equal(t, ModeOff, EffectiveMode(ResolveMode("enforc"), s))
	}

	// Documented precondition: EffectiveMode itself does NOT resolve unknowns
	// — an unknown org value has rank 0, which never exceeds any gate rank,
	// so the clamp never fires and the raw value passes through verbatim
	// under every gate. That is exactly why every caller (orgSettings, the
	// admin handler) applies ResolveMode first; pinning the raw passthrough
	// keeps the precondition honest.
	require.Equal(t, 0, modeRank(Mode("bogus")))
	for _, g := range gates {
		require.Equal(t, Mode("bogus"), EffectiveMode(g, Mode("bogus")),
			"an unknown stored mode passes through unclamped — the resolver must run first")
	}
}

// TestAdmissionModeMatrixRuntimeBoundary — the same 9-combo matrix plus the
// unknown fail-closed cases, pinned at the RUNTIME boundary (Plan/Reserve):
// off plans and reserves as legacy no-op; a clamped-to-shadow org is served
// with would-deny observability instead of denials; an unclamped enforce org
// denies; an unknown stored value behaves as off under every gate. The empty
// planned chain makes estimation fail, which surfaces each mode's distinct
// observable shape without any store.
func TestAdmissionModeMatrixRuntimeBoundary(t *testing.T) {
	ctx := context.Background()
	gates := []Mode{ModeOff, ModeShadow, ModeEnforce}
	stored := []Mode{ModeOff, ModeShadow, ModeEnforce}

	assertOutcome := func(t *testing.T, adm *Admission, want Mode) {
		t.Helper()
		plan, err := adm.Plan(ctx, Request{OrgID: "org-runtime"})
		switch want {
		case ModeOff:
			require.NoError(t, err)
			require.Equal(t, ModeOff, plan.Mode)
			require.Empty(t, plan.WouldDeny)
			rsv, rerr := adm.Reserve(ctx, plan)
			require.ErrorIs(t, rerr, ErrNotReserved, "off never reserves")
			require.Nil(t, rsv)
		case ModeShadow:
			require.NoError(t, err, "shadow never denies")
			require.Equal(t, ModeShadow, plan.Mode)
			require.NotEmpty(t, plan.WouldDeny, "the estimation failure is recorded, not raised")
			rsv, rerr := adm.Reserve(ctx, plan)
			require.ErrorIs(t, rerr, ErrNotReserved, "an unreserved shadow plan never reserves")
			require.Nil(t, rsv)
		default:
			require.Error(t, err, "enforce denies at the admission boundary")
			require.Nil(t, plan)
		}
	}

	for _, g := range gates {
		for _, s := range stored {
			t.Run(fmt.Sprintf("gate_%s_stored_%s", g, s), func(t *testing.T) {
				adm := newCorpusAdmission(t, g, &corpusLoader{stored: s}, nil)
				assertOutcome(t, adm, EffectiveMode(g, s))
			})
		}
	}
	for _, g := range gates {
		t.Run(fmt.Sprintf("gate_%s_stored_unknown", g), func(t *testing.T) {
			adm := newCorpusAdmission(t, g, &corpusLoader{stored: Mode("enforce_mistyped")}, nil)
			assertOutcome(t, adm, ModeOff)
		})
	}
}

// TestAdmissionModeFlipMidFlightBoundary — T07 mode-flip aspect: the admin
// flips an org's stored mode while requests are in flight. Documented
// contract: the ≤5s org cache serves the STALE effective mode inside the TTL
// window (Plan/Reserve decisions keep the pre-flip semantics); the flip lands
// at the latest on TTL expiry; and a reservation already made under the old
// mode finalizes exactly under the mode it was RESERVED with — the event
// tuples carry the reserve, so the settlement side never re-derives the mode.
func TestAdmissionModeFlipMidFlightBoundary(t *testing.T) {
	ctx := context.Background()
	const org = "org-flip"

	t.Run("enforce→shadow lands only after the org TTL; the stale mode governs inside it", func(t *testing.T) {
		ld := &corpusLoader{stored: ModeEnforce}
		adm := newCorpusAdmission(t, ModeEnforce, ld, nil)
		now := time.Now()
		adm.SetClock(func() time.Time { return now })

		_, err := adm.Plan(ctx, Request{OrgID: org})
		require.Error(t, err, "enforce denies before the flip")

		ld.stored = ModeShadow // mid-flight admin flip
		now = now.Add(time.Second)
		_, err = adm.Plan(ctx, Request{OrgID: org})
		require.Error(t, err, "the warm cache keeps serving the stale enforce inside the TTL")

		now = now.Add(5 * time.Second) // the documented OrgTTL expires
		plan, err := adm.Plan(ctx, Request{OrgID: org})
		require.NoError(t, err)
		require.Equal(t, ModeShadow, plan.Mode, "the flip lands on TTL expiry")
		require.NotEmpty(t, plan.WouldDeny)
	})

	t.Run("shadow→enforce mirrors the skew and lands as a denial", func(t *testing.T) {
		ld := &corpusLoader{stored: ModeShadow}
		adm := newCorpusAdmission(t, ModeEnforce, ld, nil)
		now := time.Now()
		adm.SetClock(func() time.Time { return now })

		plan, err := adm.Plan(ctx, Request{OrgID: org})
		require.NoError(t, err)
		require.Equal(t, ModeShadow, plan.Mode)

		ld.stored = ModeEnforce
		now = now.Add(time.Second)
		plan, err = adm.Plan(ctx, Request{OrgID: org})
		require.NoError(t, err, "still the stale shadow inside the TTL")
		require.Equal(t, ModeShadow, plan.Mode)

		now = now.Add(5 * time.Second)
		_, err = adm.Plan(ctx, Request{OrgID: org})
		require.Error(t, err, "the raised mode denies once the cache expires")
	})

	t.Run("an in-flight reservation finalizes under its reserved mode after the flip", func(t *testing.T) {
		ld := &corpusLoader{stored: ModeEnforce}
		adm := newCorpusAdmission(t, ModeEnforce, ld, nil)
		now := time.Now()
		adm.SetClock(func() time.Time { return now })

		// The replica escrow holds exactly one bound; the request reserves
		// locally under ENFORCE.
		const bound = money.MicroUSD(400_000)
		adm.applyGrants(org, []ScopeGrant{{
			Scope: ScopeWallet, Key: org, AllowanceID: 7, Delta: 1_000_000,
		}})
		rsv, err := adm.Reserve(ctx, &Plan{
			Mode: ModeEnforce, OrgID: org,
			Scopes: []ScopeBound{{Scope: ScopeWallet, Key: org, Bound: bound}},
		})
		require.NoError(t, err)
		require.NotNil(t, rsv)
		require.Equal(t, ModeEnforce, rsv.Mode)
		require.Equal(t, int64(600_000), int64(adm.LocalEscrow()),
			"granted 1M minus the 400k in-flight bound")

		// The org flips to shadow and the cache expires; then the request
		// completes. Finalize releases the in-flight bound and accumulates
		// the actual against the ORIGINAL (enforce) reservation.
		ld.stored = ModeShadow
		now = now.Add(10 * time.Second)
		adm.Finalize(rsv, 250_000, 250_000)
		require.Equal(t, int64(750_000), int64(adm.LocalEscrow()),
			"the 400k bound released, the 250k actual stays claimed for its settle")

		// New admissions under the landed shadow mode ride the same escrow —
		// the flip never strands the replica's accounting.
		shadowPlan, err := adm.Plan(ctx, Request{OrgID: org})
		require.NoError(t, err)
		require.Equal(t, ModeShadow, shadowPlan.Mode)

		// The event tuples are unchanged by the flip: the consumer settles
		// min(actual, bound) against THIS allowance, whatever the mode says
		// now (see the consumer-side interruption corpus).
		require.JSONEq(t,
			`[{"scope_kind":"wallet","scope_key":"`+org+`","period":"","allowance_id":7,"bound_micro_usd":400000}]`,
			rsv.TuplesJSON())
	})
}

// TestBudgetBoundaryCorpus — T07 aspect 2: the wallet and budget-area
// boundaries at the Plan pre-check, against a read-only capacity double.
//
//	§5.1: the pre-check refuses before any work (D7); the state cache is
//	bounded by PreCheckTTL (5s default, pinned by TestReservationConfigDefaults).
func TestBudgetBoundaryCorpus(t *testing.T) {
	ctx := context.Background()
	const org = "org-corpus"

	// fundedDB returns a wallet that can never deny.
	fundedDB := func() *probeDB { return &probeDB{balanceCents: 100_000_000} }

	t.Run("exhausted at the limit: enforce denies, shadow would-denies and serves", func(t *testing.T) {
		empty := &probeDB{balanceCents: 0, floorCents: corpusFloorPtr(0)}

		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, empty)
		plan, err := adm.Plan(ctx, corpusRequest(org))
		require.Nil(t, plan)
		require.ErrorIs(t, err, ErrInsufficientCapacity)
		var denial *Denial
		require.ErrorAs(t, err, &denial)
		require.Equal(t, ScopeWallet, denial.Scope)

		admS := newCorpusAdmission(t, ModeShadow, &corpusLoader{stored: ModeShadow}, empty)
		planS, err := admS.Plan(ctx, corpusRequest(org))
		require.NoError(t, err)
		require.Equal(t, ModeShadow, planS.Mode)
		require.Len(t, planS.WouldDeny, 1)
		require.ErrorIs(t, planS.WouldDeny[0].Err, ErrInsufficientCapacity)
	})

	t.Run("shadow under a store outage serves unreserved — never a denial", func(t *testing.T) {
		// The read-only double refuses every write: the grant path classifies
		// the failure as a store outage, and shadow answers unreserved
		// (ErrNotReserved) where enforce would fail closed with a denial.
		db := fundedDB()
		admS := newCorpusAdmission(t, ModeShadow, &corpusLoader{stored: ModeShadow}, db)
		plan, err := admS.Plan(ctx, corpusRequest(org))
		require.NoError(t, err)
		require.Empty(t, plan.WouldDeny, "the funded wallet passes the pre-check")
		rsv, rerr := admS.Reserve(ctx, plan)
		require.ErrorIs(t, rerr, ErrNotReserved)
		require.Nil(t, rsv)

		admE := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, fundedDB())
		planE, err := admE.Plan(ctx, corpusRequest(org))
		require.NoError(t, err)
		_, rerr = admE.Reserve(ctx, planE)
		require.Error(t, rerr)
		require.NotErrorIs(t, rerr, ErrNotReserved, "enforce fails closed with a denial, not an unreserved refusal")
	})

	t.Run("exact-limit admit edge: free == bound is eligible, one µUSD below denies", func(t *testing.T) {
		// Measure the bound against a funded wallet, then place the wallet
		// exactly on the edge. Sub-cent precision comes from the carried
		// remainder: free = balance·10000 − remainder.
		bound := func() money.MicroUSD {
			db := fundedDB()
			adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, db)
			plan, err := adm.Plan(ctx, corpusRequest(org))
			require.NoError(t, err)
			return plan.Scopes[0].Bound
		}()

		exact := &probeDB{balanceCents: 1, remainderMicro: 10_000 - int64(bound)}
		free, err := NewReservationStoreWithConfig(exact, nil, ReservationConfig{}).
			ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
		require.NoError(t, err)
		require.Equal(t, int64(bound), int64(free), "the seeded free equals the bound exactly")
		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, exact)
		plan, err := adm.Plan(ctx, corpusRequest(org))
		require.NoError(t, err, "the pre-check admits at exact capacity; the grant stays the authority")
		require.Empty(t, plan.WouldDeny)

		oneBelow := &probeDB{balanceCents: 1, remainderMicro: 10_000 - int64(bound) + 1}
		admBelow := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, oneBelow)
		_, err = admBelow.Plan(ctx, corpusRequest(org))
		require.ErrorIs(t, err, ErrInsufficientCapacity)
	})

	t.Run("grace floor widens capacity but is finite: deny-next beyond it", func(t *testing.T) {
		// out_cap 1_048_576 prices the bound above the 200¢ balance; the
		// −100¢ floor (grace) closes exactly that gap.
		req := corpusRequest(org)
		capTokens := int64(1_048_576)
		req.MaxTokens = &capTokens

		bound := func() money.MicroUSD {
			db := fundedDB()
			adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, db)
			plan, err := adm.Plan(ctx, req)
			require.NoError(t, err)
			return plan.Scopes[0].Bound
		}()
		require.Greater(t, int64(bound), int64(2_000_000), "the bound exceeds the bare 200¢ balance")

		overBalance := &probeDB{balanceCents: 200, floorCents: corpusFloorPtr(0)} // free 2M µ
		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, overBalance)
		_, err := adm.Plan(ctx, req)
		require.ErrorIs(t, err, ErrInsufficientCapacity, "no floor, no admission")

		graced := &probeDB{balanceCents: 200, floorCents: corpusFloorPtr(-100)} // free 3M µ
		admGrace := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, graced)
		plan, err := admGrace.Plan(ctx, req)
		require.NoError(t, err, "the grace floor admits what the bare balance cannot")
		require.Empty(t, plan.WouldDeny)

		// Beyond the floor the denial returns: grace is not unlimited credit.
		huge := int64(4_194_304)
		req.MaxTokens = &huge
		_, err = admGrace.Plan(ctx, req)
		require.ErrorIs(t, err, ErrInsufficientCapacity, "deny-next fires past the grace floor")
	})

	t.Run("deny-next fast path: the refusal caches for the pre-check TTL without re-probing", func(t *testing.T) {
		db := &probeDB{balanceCents: 0, floorCents: corpusFloorPtr(0)}
		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, db)
		now := time.Now()
		adm.SetClock(func() time.Time { return now })

		for i := 0; i < 3; i++ {
			_, err := adm.Plan(ctx, corpusRequest(org))
			require.ErrorIs(t, err, ErrInsufficientCapacity, "refusal %d", i)
		}
		require.Equal(t, 1, db.probeCount(),
			"the recent-refusal cache answers the fast path; one probe total")

		now = now.Add(5 * time.Second) // PreCheckTTL expires
		_, err := adm.Plan(ctx, corpusRequest(org))
		require.ErrorIs(t, err, ErrInsufficientCapacity)
		require.Equal(t, 2, db.probeCount(), "a fresh probe only after the TTL")
	})

	t.Run("top-up mid-window: stale refusal inside the TTL, the top-up lands after it", func(t *testing.T) {
		db := &probeDB{balanceCents: 0, floorCents: corpusFloorPtr(0)}
		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, db)
		now := time.Now()
		adm.SetClock(func() time.Time { return now })

		_, err := adm.Plan(ctx, corpusRequest(org))
		require.ErrorIs(t, err, ErrInsufficientCapacity)

		db.mu.Lock()
		db.balanceCents = 1_000_000 // the admin tops the wallet up mid-window
		db.mu.Unlock()

		now = now.Add(time.Second)
		_, err = adm.Plan(ctx, corpusRequest(org))
		require.ErrorIs(t, err, ErrInsufficientCapacity,
			"the cached refusal governs inside the documented ≤5s skew window")

		now = now.Add(5 * time.Second)
		plan, err := adm.Plan(ctx, corpusRequest(org))
		require.NoError(t, err, "the topped-up wallet admits after the TTL")
		require.Empty(t, plan.WouldDeny)
	})

	t.Run("soft team budgets are advisory: never denied at the probe; hard budgets deny at the limit", func(t *testing.T) {
		teamReq := func() Request {
			req := corpusRequest(org)
			req.TeamID = "22222222-2222-4222-8222-222222222222"
			return req
		}

		// Advisory (hard_limit=false): free capacity reports MaxInt64 — an
		// over-limit month never denies, whatever the spend. The gateway-side
		// soft=warn/hard=deny CheckBudget matrix is pinned by
		// TestCheckBudget_SoftLimitExceeded/HardLimitExceeded — cited.
		soft := &probeDB{
			balanceCents:   100_000_000,
			teamLimitMicro: 1_000_000, teamHard: false,
			teamSpendMicro: 5_000_000, // spend ≥ limit, still advisory
		}
		store := NewReservationStoreWithConfig(soft, nil, ReservationConfig{})
		free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{
			Scope: ScopeTeamMonth, Key: teamReq().TeamID, Period: "2026-10", Bound: 1,
		})
		require.NoError(t, err)
		require.Equal(t, int64(math.MaxInt64), int64(free),
			"advisory scopes report unlimited")

		adm := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, soft)
		plan, err := adm.Plan(ctx, teamReq())
		require.NoError(t, err)
		require.Empty(t, plan.WouldDeny, "an advisory budget never would-deny")

		// Hard budget exactly at the limit: the team scope denies (wallet
		// funded, so the team refusal surfaces).
		atLimit := &probeDB{
			balanceCents:   100_000_000,
			teamLimitMicro: 1_000_000, teamHard: true,
			teamSpendMicro: 1_000_000, teamReserved: 0,
		}
		admHard := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, atLimit)
		_, err = admHard.Plan(ctx, teamReq())
		require.ErrorIs(t, err, ErrInsufficientCapacity)
		var denial *Denial
		require.ErrorAs(t, err, &denial)
		require.Equal(t, ScopeTeamMonth, denial.Scope)

		// One bound of headroom admits.
		headroom := &probeDB{
			balanceCents:   100_000_000,
			teamLimitMicro: 3_000_000, teamHard: true,
			teamSpendMicro: 1_000_000,
		}
		admHead := newCorpusAdmission(t, ModeEnforce, &corpusLoader{stored: ModeEnforce}, headroom)
		plan, err = admHead.Plan(ctx, teamReq())
		require.NoError(t, err)
		require.Empty(t, plan.WouldDeny)

		// Shadow degrades the hard refusal to a would-deny and serves.
		admShadow := newCorpusAdmission(t, ModeShadow, &corpusLoader{stored: ModeShadow}, atLimit)
		planS, err := admShadow.Plan(ctx, teamReq())
		require.NoError(t, err)
		require.Len(t, planS.WouldDeny, 1)
		require.ErrorIs(t, planS.WouldDeny[0].Err, ErrInsufficientCapacity)
	})
}

// TestReserveBoundaryConcurrentLocalFit — the concurrent boundary of the
// local escrow: fitLocally is all-or-nothing per request and admits exactly
// ⌊escrow/bound⌋ requests under concurrency. The store-level concurrency
// invariant (reserved + Δ ≤ L across replicas, concurrency 1/10/100) is the
// live TestNext18cLive_MultiReplicaConcurrentInvariant — cited.
func TestReserveBoundaryConcurrentLocalFit(t *testing.T) {
	const org = "org-conc"
	const k = 8
	const bound = money.MicroUSD(100_000)

	adm := NewAdmission(nil, ScopedRateSource{}, nil, "rep-conc", ModeEnforce, nil, AdmissionConfig{})
	t.Cleanup(adm.Stop)
	adm.applyGrants(org, []ScopeGrant{{
		Scope: ScopeWallet, Key: org, AllowanceID: 3, Delta: k * bound,
	}})

	var admitted, refused atomic.Int64
	var wg sync.WaitGroup
	reserved := make([]*Reservation, 0, 200)
	var resMu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Every request is IN FLIGHT at once: the fit either consumes its
			// bound or refuses — no finalize until the barrier below.
			rsv := &Reservation{OrgID: org, Mode: ModeEnforce, created: time.Now()}
			if adm.fitLocally(rsv, []ScopeBound{{Scope: ScopeWallet, Key: org, Bound: bound}}) {
				resMu.Lock()
				reserved = append(reserved, rsv)
				resMu.Unlock()
				admitted.Add(1)
			} else {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int64(k), admitted.Load(), "exactly ⌊escrow/bound⌋ concurrent admits")
	require.Equal(t, int64(200-k), refused.Load())
	require.Equal(t, int64(0), int64(adm.LocalEscrow()), "the escrow drains to exactly zero, never negative")

	// The k in-flight requests complete: each releases exactly its bound.
	for _, rsv := range reserved {
		adm.Finalize(rsv, 0, 0)
	}
	require.Equal(t, int64(k*int(bound)), int64(adm.LocalEscrow()),
		"finalize restores the escrow exactly once per reservation")

	t.Run("multi-scope fit is all-or-nothing: no partial reservation", func(t *testing.T) {
		adm2 := NewAdmission(nil, ScopedRateSource{}, nil, "rep-conc-2", ModeEnforce, nil, AdmissionConfig{})
		t.Cleanup(adm2.Stop)
		adm2.applyGrants(org, []ScopeGrant{
			{Scope: ScopeWallet, Key: org, AllowanceID: 4, Delta: bound},
			// team escrow missing entirely
		})
		rsv := &Reservation{OrgID: org, Mode: ModeEnforce, created: time.Now()}
		ok := adm2.fitLocally(rsv, []ScopeBound{
			{Scope: ScopeWallet, Key: org, Bound: bound},
			{Scope: ScopeTeamMonth, Key: "team", Period: "2026-10", Bound: bound},
		})
		require.False(t, ok, "a partially-funded multi-scope request reserves nothing")
		adm2.mu.Lock()
		walletInflight := adm2.ledger[ledgerKey{ScopeWallet, org, ""}].inflight
		adm2.mu.Unlock()
		require.Equal(t, int64(0), int64(walletInflight),
			"the funded scope is not partially consumed either")

		// Funding the second scope admits the pair as a whole.
		adm2.applyGrants(org, []ScopeGrant{{
			Scope: ScopeTeamMonth, Key: "team", Period: "2026-10", AllowanceID: 5, Delta: bound,
		}})
		rsv = &Reservation{OrgID: org, Mode: ModeEnforce, created: time.Now()}
		require.True(t, adm2.fitLocally(rsv, []ScopeBound{
			{Scope: ScopeWallet, Key: org, Bound: bound},
			{Scope: ScopeTeamMonth, Key: "team", Period: "2026-10", Bound: bound},
		}))
	})
}

// TestReservationCrashRestartLedgerBoundary — T08 crash semantics at the
// ledger boundary: a crashed replica's in-memory escrow dies with the
// process; the replacement's cold ledger can never be corrupted by the dead
// incarnation's reservations; and the startup self-reap sweep fails closed
// on a gate of off or an unidentifiable replica id (no store round trip).
// The DB half of the interplay — sweep flips the crashed predecessor to
// draining, the safety window governs the frozen escrow, restart is a no-op —
// is the live TestR042SelfReap_* suite — cited.
func TestReservationCrashRestartLedgerBoundary(t *testing.T) {
	ctx := context.Background()
	const org = "org-crash"
	const replica = "gwbox-4242-1699999999999999999"
	const bound = money.MicroUSD(300_000)

	// Process A reserves and crashes: no Finalize, no Shutdown — the ledger
	// and the in-flight claim simply vanish.
	crashed := NewAdmission(nil, ScopedRateSource{}, nil, replica, ModeEnforce, nil, AdmissionConfig{})
	crashed.applyGrants(org, []ScopeGrant{{Scope: ScopeWallet, Key: org, AllowanceID: 11, Delta: bound}})
	dead, err := crashed.Reserve(ctx, &Plan{
		Mode: ModeEnforce, OrgID: org,
		Scopes: []ScopeBound{{Scope: ScopeWallet, Key: org, Bound: bound}},
	})
	require.NoError(t, err)
	require.NotNil(t, dead)

	// The replacement process starts cold (same host family — its startup
	// sweep reaps the predecessor per D1/D2).
	fresh := NewAdmission(nil, ScopedRateSource{}, nil, "gwbox-9999-1700000000000000001", ModeEnforce, nil, AdmissionConfig{})
	t.Cleanup(fresh.Stop)
	require.Equal(t, int64(0), int64(fresh.LocalEscrow()), "a new process starts with an empty ledger")

	// The dead incarnation's finalize can never corrupt the replacement:
	// the ledger entry is gone, so the settle is a no-op.
	fresh.Finalize(dead, bound, bound)
	require.Equal(t, int64(0), int64(fresh.LocalEscrow()))

	// The replacement re-grants from a NEW allowance slice and admits again.
	fresh.applyGrants(org, []ScopeGrant{{Scope: ScopeWallet, Key: org, AllowanceID: 12, Delta: bound}})
	rsv, err := fresh.Reserve(ctx, &Plan{
		Mode: ModeEnforce, OrgID: org,
		Scopes: []ScopeBound{{Scope: ScopeWallet, Key: org, Bound: bound}},
	})
	require.NoError(t, err)
	require.NotNil(t, rsv)
	require.Equal(t, int64(12), int64(rsv.Scopes[0].AllowanceID),
		"the fresh slice, never the crashed incarnation's allowance")

	// Self-reap fail-closed unit paths: a gate of off and a replica id
	// without an identifiable host family sweep NOTHING and never touch the
	// store (nil store here proves no round trip happens).
	offAdm := NewAdmission(nil, ScopedRateSource{}, nil, replica, ModeOff, nil, AdmissionConfig{})
	n, err := offAdm.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	require.Zero(t, n)

	anonymous := NewAdmission(nil, ScopedRateSource{}, nil, "bare-host", ModeEnforce, nil, AdmissionConfig{})
	n, err = anonymous.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "no own family — nothing may be identified as a predecessor")
}

func corpusFloorPtr(n int64) *int64 { return &n }
