package budget

// Recovery corpus for the reservation controller's retry arcs on non-chat
// workloads (unit-priced image/audio/character endpoints and batch lines):
//
//   - an interrupted attempt settles zero and a retry re-admits the full
//     bound from the same durable grant — the escrow never phantom-charges
//     a failed attempt and never asks the store twice for one bound;
//   - a partial completion resumes from the true spent amount: the next
//     admission sees the settled actual, never the refused bound;
//   - a store refusal freezes the ledger byte-exact (no escrow movement)
//     and arms the pre-check fast path until its TTL lapses;
//   - a non-chat shape whose unit axis cannot be priced — a rate source
//     with no unit catalog, a model the catalog does not know, a mismatched
//     metering axis, a batch line with no candidates — is refused closed in
//     enforce and only a would-deny in shadow; no mode lets it bypass
//     admission, and no durable money ever moves for it.
//
// The grant path runs over escrowDB, an in-memory reservationDB double
// reproducing the store's wallet SQL arithmetic (read-only probe, FOR UPDATE
// read, capacity-predicated reserve update, cumulative allowance upsert), so
// the refusal arcs exercise the real sizing math instead of canned answers.
// Live-Postgres proofs of the same flows stay under the integration tag
// (TestNext18cLive_*, TestR042SelfReap_*) — cited, not duplicated.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/stretchr/testify/require"
)

// allowanceRec is the fake's memory of one created allowance row: identity
// for the settle-time FOR SHARE lookup by id and the return-time FOR UPDATE
// lookup by (replica, scope, key, period).
type allowanceRec struct {
	id                          int64
	replica, scope, key, period string
}

func (r allowanceRec) composite() string {
	return r.replica + "|" + r.scope + "|" + r.key + "|" + r.period
}

// escrowDB is an in-memory reservationDB double with an honest wallet grant,
// settle and return path: one seeded org_credits row answers the DB-level
// probe and the tx-level FOR UPDATE read; the reserve update applies the
// same capacity predicate as the store's SQL (rows-affected 0 on a breach),
// the settle decrement and the idle return subtract under the same
// `reserved >= amount` guard, and the allowance upsert keeps the cumulative
// granted and returned amounts per (replica, scope, key, period) and counts
// committed grants. Every other statement fails loudly — the double fakes
// only what the recovery arcs exercise, so a stray production statement
// cannot silently pass.
type escrowDB struct {
	mu             sync.Mutex
	balanceCents   int64
	remainderMicro int64
	floorCents     int64 // the row always carries an explicit floor (non-NULL)
	reservedMicro  int64

	allowanceSeq   int64
	allowancesByID map[int64]allowanceRec
	idByKey        map[string]int64
	grantedByKey   map[string]int64
	returnedByKey  map[string]int64
	grants         int
	probes         int
}

func newEscrowDB(balanceCents, floorCents int64) *escrowDB {
	return &escrowDB{
		balanceCents:   balanceCents,
		floorCents:     floorCents,
		allowancesByID: map[int64]allowanceRec{},
		idByKey:        map[string]int64{},
		grantedByKey:   map[string]int64{},
		returnedByKey:  map[string]int64{},
	}
}

func (d *escrowDB) Begin(context.Context) (pgx.Tx, error) { return &escrowTx{d: d}, nil }

func (d *escrowDB) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, fmt.Errorf("escrowDB: unexpected DB-level exec")
}

func (d *escrowDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, fmt.Errorf("escrowDB: unexpected query")
}

func (d *escrowDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.Contains(query, "FROM org_credits") {
		d.probes++
		return d.walletRowLocked()
	}
	return &recRow{err: fmt.Errorf("escrowDB: unexpected query: %s", query)}
}

// walletRowLocked answers the four wallet columns with exact types
// (int64 / *int64 for the explicit floor).
func (d *escrowDB) walletRowLocked() *recRow {
	return &recRow{data: []any{d.balanceCents, d.remainderMicro, d.floorCents, d.reservedMicro}}
}

// walletFreeMicro is the capacity the store's SQL predicate computes:
// balance minus remainder minus floor minus already-reserved.
func (d *escrowDB) walletFreeMicro() int64 {
	return d.balanceCents*10_000 - d.remainderMicro - d.floorCents*10_000 - d.reservedMicro
}

func (d *escrowDB) grantCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.grants
}

func (d *escrowDB) probeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.probes
}

func (d *escrowDB) reservedSnapshot() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reservedMicro
}

// escrowTx applies the store's wallet write path in memory: the advisory
// lock is a no-op (the double serializes on its own mutex), the reserve
// update re-checks the SQL capacity predicate, the settle decrement
// subtracts under the same `reserved >= amount` guard, and the allowance
// upsert returns a fresh id plus the cumulative granted amount.
type escrowTx struct {
	pgx.Tx // nil-embedded: only Exec/QueryRow/Commit/Rollback are exercised
	d      *escrowDB
}

func (t *escrowTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(query, "pg_advisory_xact_lock"):
		return pgconn.NewCommandTag("SELECT 1"), nil
	case strings.Contains(query, "UPDATE org_credits SET") && strings.Contains(query, "reserved_micro_usd - $2"):
		// The §5.3 settle decrement: min(actual, bound) leaves the reserve.
		amount, ok := args[1].(int64)
		if !ok {
			return pgconn.CommandTag{}, fmt.Errorf("escrowTx: settle amount %T", args[1])
		}
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		if amount >= 0 && t.d.reservedMicro >= amount {
			t.d.reservedMicro -= amount
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		return pgconn.NewCommandTag("UPDATE 0"), nil
	case strings.Contains(query, "UPDATE org_credits SET"):
		// The §5.3 grant reserve update with its capacity predicate.
		delta, ok := args[1].(int64)
		if !ok {
			return pgconn.CommandTag{}, fmt.Errorf("escrowTx: reserve delta %T", args[1])
		}
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		// The same predicate the store's UPDATE carries: only an in-range
		// reservation moves the row, anything else is UPDATE 0.
		if delta >= 0 && delta <= t.d.walletFreeMicro() {
			t.d.reservedMicro += delta
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		return pgconn.NewCommandTag("UPDATE 0"), nil
	case strings.Contains(query, "UPDATE budget_allowances SET") &&
		strings.Contains(query, "returned_micro_usd = returned_micro_usd +"):
		// The §5.3 idle return: the allowance records what went back.
		id, ok := args[0].(int64)
		if !ok {
			return pgconn.CommandTag{}, fmt.Errorf("escrowTx: return id %T", args[0])
		}
		amount, ok := args[1].(int64)
		if !ok {
			return pgconn.CommandTag{}, fmt.Errorf("escrowTx: return amount %T", args[1])
		}
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		rec, ok := t.d.allowancesByID[id]
		if !ok {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		t.d.returnedByKey[rec.composite()] += amount
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, fmt.Errorf("escrowTx: unexpected exec: %s", query)
	}
}

func (t *escrowTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	switch {
	case strings.Contains(query, "FROM org_credits"):
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		return t.d.walletRowLocked()
	case strings.Contains(query, "FROM budget_allowances") && strings.Contains(query, "FOR SHARE"):
		// The settle-time lookup by allowance id; a vanished row is
		// pgx.ErrNoRows, exactly what SettleDecrementTx treats as
		// ledger-only.
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		id, ok := args[0].(int64)
		if !ok {
			return &recRow{err: fmt.Errorf("escrowTx: allowance id %T", args[0])}
		}
		rec, ok := t.d.allowancesByID[id]
		if !ok {
			return &recRow{err: pgx.ErrNoRows}
		}
		return &recRow{data: []any{rec.scope, rec.key, rec.period, AllowanceActive}}
	case strings.Contains(query, "FROM budget_allowances") && strings.Contains(query, "FOR UPDATE"):
		// The Return-time lookup by (replica, scope, key, period).
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		replica, ok1 := args[0].(string)
		scope, ok2 := args[1].(string)
		skey, ok3 := args[2].(string)
		period, ok4 := args[3].(string)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return &recRow{err: fmt.Errorf("escrowTx: return identity %v", args[:4])}
		}
		composite := allowanceRec{replica: replica, scope: scope, key: skey, period: period}.composite()
		id, ok := t.d.idByKey[composite]
		if !ok {
			return &recRow{err: pgx.ErrNoRows}
		}
		return &recRow{data: []any{id, t.d.grantedByKey[composite], t.d.returnedByKey[composite], AllowanceActive}}
	case strings.Contains(query, "INSERT INTO budget_allowances"):
		delta, ok := args[5].(int64)
		if !ok {
			return &recRow{err: fmt.Errorf("escrowTx: allowance delta %T", args[5])}
		}
		t.d.mu.Lock()
		defer t.d.mu.Unlock()
		replica, ok1 := args[0].(string)
		scope, ok2 := args[1].(string)
		skey, ok3 := args[2].(string)
		period, ok4 := args[3].(string)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return &recRow{err: fmt.Errorf("escrowTx: allowance identity %v", args[:4])}
		}
		// The real upsert is INSERT ... ON CONFLICT (replica, scope, key,
		// period) DO UPDATE: the existing row keeps its id and accumulates
		// granted_micro_usd. Mirror that — a fresh id per grant would make
		// applyGrants reset the local ledger entry (allowanceID mismatch),
		// losing concurrent in-flight bounds and producing false
		// "local escrow short after grant" denials under parallel Reserve.
		composite := allowanceRec{replica: replica, scope: scope, key: skey, period: period}.composite()
		if id, ok := t.d.idByKey[composite]; ok {
			t.d.grantedByKey[composite] += delta
			t.d.grants++
			return &recRow{data: []any{id, t.d.grantedByKey[composite]}}
		}
		t.d.allowanceSeq++
		rec := allowanceRec{id: t.d.allowanceSeq, replica: replica, scope: scope, key: skey, period: period}
		t.d.allowancesByID[rec.id] = rec
		t.d.idByKey[rec.composite()] = rec.id
		t.d.grantedByKey[rec.composite()] += delta
		t.d.grants++
		return &recRow{data: []any{rec.id, t.d.grantedByKey[rec.composite()]}}
	default:
		return &recRow{err: fmt.Errorf("escrowTx: unexpected query: %s", query)}
	}
}

func (t *escrowTx) Commit(context.Context) error   { return nil }
func (t *escrowTx) Rollback(context.Context) error { return nil }

// recoveryUnitCatalog is a one-entry unit catalog: it prices exactly
// openai:img at $0.25 per image (binary-exact in float64, a stand-in for
// the bundled snapshot's gpt-image-1.5 rate) and knows no other model.
type recoveryUnitCatalog struct{}

func (recoveryUnitCatalog) LookupUnit(provider, model string) (pricing.UnitEntry, bool) {
	if provider == "openai" && model == "img" {
		return pricing.UnitEntry{Provider: provider, Model: model, Unit: pricing.UnitPerImage, Rate: 0.25}, true
	}
	return pricing.UnitEntry{}, false
}

// recoveryRates is the corpus rate table plus the one-entry unit catalog.
// Token pricing stays irrelevant to these requests: every bound below is
// metered per image.
func recoveryRates() ScopedRateSource {
	src := corpusRates()
	src.Base.Units = recoveryUnitCatalog{}
	return src
}

// recoveryImageRequest is a unit-priced image workload: qty images, one
// candidate, no token traffic at all.
func recoveryImageRequest(org string, qty float64) Request {
	return Request{
		OrgID:    org,
		Chain:    []ChainHop{{Provider: "openai", Model: "img"}},
		UnitKind: pricing.UnitPerImage,
		UnitQty:  &qty,
	}
}

// newRecoveryStore wires the store over the given double with the explicit
// no-overdraft floor default; the row's own floor answers every read.
func newRecoveryStore(t *testing.T, db reservationDB) *ReservationStore {
	t.Helper()
	return NewReservationStoreWithConfig(db, nil, ReservationConfig{DefaultGraceFloorCents: 0})
}

// newRecoveryAdmission wires the controller over the given store.
func newRecoveryAdmission(t *testing.T, mode Mode, store *ReservationStore, rates ScopedRateSource) *Admission {
	t.Helper()
	loader := &corpusLoader{stored: mode}
	adm := NewAdmission(store, rates, nil, "recovery-replica", mode, loader.load, AdmissionConfig{})
	t.Cleanup(adm.Stop)
	return adm
}

// TestUnitPricedAttemptInterruptedThenRetryRecovers: an image generation
// that dies upstream settles zero, leaves the escrow exact, and the retry
// re-admits the full bound from the same durable grant — one bound, one
// grant, no phantom charge on the failed attempt.
func TestUnitPricedAttemptInterruptedThenRetryRecovers(t *testing.T) {
	db := newEscrowDB(3000, 500) // $30 balance, $5 floor → $25.00 free
	store := newRecoveryStore(t, db)
	adm := newRecoveryAdmission(t, ModeEnforce, store, recoveryRates())
	now := time.Now()
	adm.SetClock(func() time.Time { return now })
	ctx := context.Background()

	// 40 images at $0.25 → a $10.00 bound on the wallet scope.
	req := recoveryImageRequest("org-recv", 40)
	plan, err := adm.Plan(ctx, req)
	require.NoError(t, err)
	require.Equal(t, ModeEnforce, plan.Mode)
	require.Empty(t, plan.WouldDeny)
	require.Len(t, plan.Scopes, 1)
	require.Equal(t, ScopeWallet, plan.Scopes[0].Scope)
	require.Equal(t, money.MicroUSD(10_000_000), plan.Scopes[0].Bound)

	rsv, err := adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.NotEmpty(t, rsv.TuplesJSON(), "the admission tuples ride to settlement")
	require.Equal(t, 1, db.grantCount(), "the first admission rides exactly one durable grant")
	require.Zero(t, adm.LocalEscrow(), "the granted escrow is fully in flight")

	// The upstream dies before generating anything: a failed attempt
	// settles nothing.
	adm.Finalize(rsv, 0, 0)
	require.Equal(t, money.MicroUSD(10_000_000), adm.LocalEscrow(),
		"an interrupted attempt releases its full bound unspent")

	// The retry re-plans the same shape: identical bound, and the local
	// escrow covers it — the store is not asked for a second grant.
	retryPlan, err := adm.Plan(ctx, req)
	require.NoError(t, err)
	require.Equal(t, money.MicroUSD(10_000_000), retryPlan.Scopes[0].Bound)
	rsv2, err := adm.Reserve(ctx, retryPlan)
	require.NoError(t, err)
	require.Equal(t, 1, db.grantCount(), "the retry resumes locally: no duplicate durable grant")
	require.Zero(t, adm.LocalEscrow())

	// The retry completes and settles the exact unit cost.
	adm.Finalize(rsv2, 10_000_000, 10_000_000)
	require.Zero(t, adm.LocalEscrow(), "granted equals spent: no loss, no residue")
}

// TestRefusalThenResumeFromTrueSpent: a rival replica consumes the wallet's
// remaining capacity between this replica's cached probe and its reserve —
// the plan rides the still-hot pre-check view, but the grant is the capacity
// authority and refuses closed. The refusal moves nothing, arms the
// pre-check fast path until its TTL lapses, and once the rival returns its
// unused escrow the right-sized retry admits from the local escrow alone —
// the resumed admission sees the true settled spend, never the refused
// bound.
func TestRefusalThenResumeFromTrueSpent(t *testing.T) {
	db := newEscrowDB(3000, 500)
	store := newRecoveryStore(t, db)
	adm := newRecoveryAdmission(t, ModeEnforce, store, recoveryRates())
	now := time.Now()
	adm.SetClock(func() time.Time { return now })
	ctx := context.Background()

	// Attempt 1: 40 images ($10.00 bound); half of them complete before
	// the upstream dies mid-batch — the actual ($5.00) settles locally,
	// the durable reserve stays put until the settlement worker claims
	// the tuples.
	plan, err := adm.Plan(ctx, recoveryImageRequest("org-recv", 40))
	require.NoError(t, err)
	rsv, err := adm.Reserve(ctx, plan)
	require.NoError(t, err)
	require.Equal(t, 1, db.grantCount())
	adm.Finalize(rsv, 5_000_000, 5_000_000)
	require.Equal(t, money.MicroUSD(5_000_000), adm.LocalEscrow())

	// A fresh plan refreshes this replica's capacity view: $15.00 free
	// ($25.00 minus the still-unclosed $10.00 reserve), cached for the
	// pre-check TTL.
	_, err = adm.Plan(ctx, recoveryImageRequest("org-recv", 40))
	require.NoError(t, err)

	// A rival replica's grant consumes the remaining $15.00 while this
	// replica's probe cache is hot — the exact cross-replica race the
	// grant-as-authority rule exists for.
	_, err = store.Grant(ctx, "rival-replica", "org-recv", []GrantRequest{
		{Scope: ScopeWallet, Key: "org-recv", Bound: 15_000_000},
	})
	require.NoError(t, err)
	require.Equal(t, 2, db.grantCount())
	require.Equal(t, int64(25_000_000), db.reservedSnapshot())

	// Attempt 2 re-plans 40 images: the plan admits on the stale $15.00
	// view, but the durable free is $0.00 — the grant refuses, and
	// nothing moves.
	plan2, err := adm.Plan(ctx, recoveryImageRequest("org-recv", 40))
	require.NoError(t, err, "the stale probe still shows capacity: refusal is the grant's call")
	rsv2, err := adm.Reserve(ctx, plan2)
	require.ErrorIs(t, err, ErrInsufficientCapacity)
	require.Nil(t, rsv2)
	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.Equal(t, ScopeWallet, denial.Scope)
	require.Equal(t, 2, db.grantCount(), "a refused grant commits nothing")
	require.Equal(t, money.MicroUSD(5_000_000), adm.LocalEscrow(),
		"the refused bound never touches the ledger")
	require.Equal(t, int64(25_000_000), db.reservedSnapshot())

	// The fast path refuses the very next plan inside the pre-check TTL
	// with no store traffic at all.
	probes := db.probeCount()
	_, err = adm.Plan(ctx, recoveryImageRequest("org-recv", 40))
	require.ErrorIs(t, err, ErrInsufficientCapacity)
	require.Equal(t, probes, db.probeCount(), "the fast path must not re-probe")
	require.Equal(t, 2, db.grantCount())

	// Capacity comes back: the rival returns its unused escrow (§5.3
	// Return), the durable free returns to $15.00.
	require.NoError(t, store.Return(ctx, "org-recv", "rival-replica", []ReturnRequest{{
		Scope: ScopeWallet, Key: "org-recv", Amount: 15_000_000,
	}}))
	require.Equal(t, int64(10_000_000), db.reservedSnapshot(), "the return frees the rival's unused escrow")

	// After the TTL lapses the plan re-probes, and the right-sized retry —
	// the 20 images actually still owed — admits from the local escrow
	// alone.
	now = now.Add(6 * time.Second)
	plan3, err := adm.Plan(ctx, recoveryImageRequest("org-recv", 20))
	require.NoError(t, err)
	rsv3, err := adm.Reserve(ctx, plan3)
	require.NoError(t, err)
	require.Equal(t, 2, db.grantCount(), "the resume spends the true remainder, no new durable money")
	adm.Finalize(rsv3, 5_000_000, 5_000_000)
	require.Zero(t, adm.LocalEscrow(), "both attempts' true spend is exact: $10 granted, $10 settled")
}

// TestUnpriceableWorkloadCannotBypassAdmission: a non-chat shape whose unit
// axis cannot be priced — a rate source with no unit catalog, a model the
// catalog does not know, a mismatched metering axis, a batch line with no
// candidates — is refused closed in enforce and only a would-deny in
// shadow; no mode lets it through unpriced, and no durable money ever
// moves.
func TestUnpriceableWorkloadCannotBypassAdmission(t *testing.T) {
	tokenOnly := corpusRates()
	qty := 10.0
	cases := []struct {
		name  string
		rates ScopedRateSource
		req   Request
	}{
		{
			name:  "token-only source, unit-priced request",
			rates: tokenOnly,
			req:   recoveryImageRequest("org-recv", 10),
		},
		{
			name:  "unit catalog does not know the model",
			rates: recoveryRates(),
			req: Request{
				OrgID:    "org-recv",
				Chain:    []ChainHop{{Provider: "openai", Model: "whisper-1"}},
				UnitKind: pricing.UnitPerAudioSecond,
				UnitQty:  &qty,
			},
		},
		{
			name:  "unit axis mismatch",
			rates: recoveryRates(),
			req: Request{
				OrgID:    "org-recv",
				Chain:    []ChainHop{{Provider: "openai", Model: "img"}},
				UnitKind: pricing.UnitPerAudioSecond,
				UnitQty:  &qty,
			},
		},
		{
			name:  "batch line without candidates",
			rates: recoveryRates(),
			req:   Request{OrgID: "org-recv"},
		},
	}

	for _, mode := range []Mode{ModeEnforce, ModeShadow} {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				db := newEscrowDB(3000, 500)
				store := newRecoveryStore(t, db)
				adm := newRecoveryAdmission(t, mode, store, tc.rates)
				plan, err := adm.Plan(context.Background(), tc.req)
				if mode == ModeEnforce {
					require.ErrorIs(t, err, ErrUnpricedModel)
					require.Nil(t, plan)
				} else {
					require.NoError(t, err)
					require.Len(t, plan.WouldDeny, 1, "shadow records the would-deny")
					require.Empty(t, plan.Scopes)
					rsv, rerr := adm.Reserve(context.Background(), plan)
					require.ErrorIs(t, rerr, ErrNotReserved)
					require.Nil(t, rsv)
				}
				require.Zero(t, db.grantCount(), "an unpriced shape never moves durable money")
				require.Zero(t, db.reservedSnapshot(), "and never reserves capacity")
			})
		}
	}
}
