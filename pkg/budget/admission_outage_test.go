package budget

// Store-outage admission invariants (N12-P02; owner decisions I36/I44):
// a mandatory money check that cannot reach Postgres never becomes a false
// authorized status. Enforce mode refuses closed (the gateway maps the
// denial to 503), shadow mode proceeds unreserved with ErrNotReserved, and
// Plan itself stays advisory — its probe is best-effort by design (§5.1),
// so the outage surfaces exactly where the money decision is made.
// Unit-level on purpose: outageDB fakes the reservationDB seam, no live DB.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// outageDB is a reservationDB whose every call fails: the unit-level shape
// of a Postgres outage (connection refused, dead pool, …).
type outageDB struct{ err error }

func (d *outageDB) Begin(context.Context) (pgx.Tx, error) { return nil, d.err }

func (d *outageDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, d.err
}

func (d *outageDB) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, d.err }

func (d *outageDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return outageRow{err: d.err}
}

type outageRow struct{ err error }

func (r outageRow) Scan(...any) error { return r.err }

var errPGOutage = errors.New("pg outage: connection refused")

func outageLoader(context.Context, string) (OrgSettings, error) {
	return OrgSettings{Mode: ModeEnforce}, nil
}

func outageRequest() Request {
	return Request{
		OrgID:      "org-outage",
		Chain:      []ChainHop{{Provider: "prov", Model: "model-1"}},
		InputBytes: 1024,
	}
}

func newOutageAdmission(mode Mode) *Admission {
	store := NewReservationStoreWithConfig(&outageDB{err: errPGOutage}, nil, DefaultReservationConfig())
	return NewAdmission(store, corpusRates(), nil, "rep-outage", mode, outageLoader, AdmissionConfig{})
}

// TestAdmissionStoreOutageEnforceRefusesClosed pins the fail-closed money
// invariant: with the store unreachable, enforce mode hands out no
// reservation and reports the outage as a wallet denial the gateway maps
// to 503 — never as budget exhaustion (402/429) and never as a shadow
// downgrade of an enforce request.
func TestAdmissionStoreOutageEnforceRefusesClosed(t *testing.T) {
	adm := newOutageAdmission(ModeEnforce)
	plan, err := adm.Plan(context.Background(), outageRequest())
	require.NoError(t, err, "the Plan probe is advisory: a store outage must not surface there")
	require.Equal(t, ModeEnforce, plan.Mode)

	rsv, err := adm.Reserve(context.Background(), plan)
	require.Error(t, err, "enforce mode must refuse when the store cannot confirm capacity")
	require.Nil(t, rsv, "no reservation may be handed out on a failed money check")

	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.Equal(t, ScopeWallet, denial.Scope)
	require.ErrorContains(t, err, "reservation store unavailable")
	require.NotErrorIs(t, err, ErrInsufficientCapacity, "an outage is not budget exhaustion")
	require.NotErrorIs(t, err, ErrNoCapacitySource, "an outage is not a missing capacity source")
	require.NotErrorIs(t, err, ErrNotReserved, "enforce must not silently degrade to shadow")
}

// TestAdmissionStoreOutageShadowServesUnreserved pins the shadow behavior:
// the outage refuses the grant, the request still proceeds unreserved with
// ErrNotReserved — never reclassified as budget exhaustion. An outage is
// deliberately NOT a would-deny (that signal means "policy would have
// denied"): its visibility is the budget_grants_total{result="error"}
// counter, which this test pins.
func TestAdmissionStoreOutageShadowServesUnreserved(t *testing.T) {
	adm := newOutageAdmission(ModeShadow)
	plan, err := adm.Plan(context.Background(), outageRequest())
	require.NoError(t, err)
	require.Equal(t, ModeShadow, plan.Mode)

	// Sequential-scope note: this before/after snapshot is race-free only
	// because no unit test here runs t.Parallel while incrementing the same
	// series (the parallel budget suites are integration-gated). If a future
	// unit test parallelizes against these counters, snapshot first.
	before := testutil.ToFloat64(metrics.BudgetGrantsTotal.WithLabelValues(string(ScopeWallet), GrantResultError))
	rsv, err := adm.Reserve(context.Background(), plan)
	require.ErrorIs(t, err, ErrNotReserved)
	require.Nil(t, rsv)
	require.NotErrorIs(t, err, ErrInsufficientCapacity, "an outage is not budget exhaustion")
	require.Empty(t, plan.WouldDeny, "an outage is not a policy denial — no would_deny inflation")

	require.InDelta(t, float64(before+1),
		testutil.ToFloat64(metrics.BudgetGrantsTotal.WithLabelValues(string(ScopeWallet), GrantResultError)),
		1e-9,
		"a store outage in shadow mode must be counted, not just logged")
}

// TestAdmissionStoreOutageFinalizeWithoutGrantIsInert pins the settlement
// side of the same invariant: a request that never got a reservation must
// have no finalize ledger effect — Finalize is nil-safe on the gateway side
// (reservationGate only calls it for non-nil rsv), so here we pin that the
// refused Reserve left no local escrow entry for the scope.
func TestAdmissionStoreOutageFinalizeWithoutGrantIsInert(t *testing.T) {
	adm := newOutageAdmission(ModeEnforce)
	plan, err := adm.Plan(context.Background(), outageRequest())
	require.NoError(t, err)
	_, err = adm.Reserve(context.Background(), plan)
	require.Error(t, err)

	adm.mu.Lock()
	defer adm.mu.Unlock()
	require.Empty(t, adm.ledger, "a refused reserve must not create escrow entries")
}

// midTxDB is the mid-transaction outage shape: Begin succeeds, then every
// statement on the transaction fails (connection dropped between BEGIN and
// the first statement — the classic failover window). Production Grant
// wraps the first failure ("grant advisory lock: …") as a non-sentinel, so
// admission must land it in the same default outage branch as the dead
// pool: fail-closed in enforce, counted in shadow, never authorized.
type midTxDB struct{ err error }

func (d *midTxDB) Begin(context.Context) (pgx.Tx, error) { return &midTx{err: d.err}, nil }
func (d *midTxDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, d.err
}
func (d *midTxDB) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, d.err }
func (d *midTxDB) QueryRow(context.Context, string, ...any) pgx.Row        { return outageRow{err: d.err} }

type midTx struct{ err error }

func (t *midTx) Begin(context.Context) (pgx.Tx, error) { return nil, t.err }
func (t *midTx) Commit(context.Context) error          { return t.err }
func (t *midTx) Rollback(context.Context) error        { return t.err }
func (t *midTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, t.err
}
func (t *midTx) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, t.err }
func (t *midTx) QueryRow(context.Context, string, ...any) pgx.Row        { return outageRow{err: t.err} }
func (t *midTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, t.err
}
func (t *midTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (t *midTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (t *midTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, t.err
}
func (t *midTx) Conn() *pgx.Conn { return nil }

// TestAdmissionStoreOutageMidTransactionRefusesClosed pins review finding
// 1 (s1-10 review, 2026-10-28): an outage striking INSIDE the grant
// transaction must be classified exactly like the dead-pool outage —
// refuse closed, wallet-scoped, "reservation store unavailable", never
// budget exhaustion, never a silent shadow downgrade.
func TestAdmissionStoreOutageMidTransactionRefusesClosed(t *testing.T) {
	store := NewReservationStoreWithConfig(&midTxDB{err: errPGOutage}, nil, DefaultReservationConfig())
	adm := NewAdmission(store, corpusRates(), nil, "rep-outage", ModeEnforce, outageLoader, AdmissionConfig{})

	plan, err := adm.Plan(context.Background(), outageRequest())
	require.NoError(t, err, "the Plan probe stays advisory for mid-tx outages too")
	require.Equal(t, ModeEnforce, plan.Mode)

	rsv, err := adm.Reserve(context.Background(), plan)
	require.Error(t, err, "a mid-transaction outage must not authorize anything")
	require.Nil(t, rsv)

	var denial *Denial
	require.ErrorAs(t, err, &denial)
	require.Equal(t, ScopeWallet, denial.Scope)
	require.ErrorContains(t, err, "reservation store unavailable")
	require.NotErrorIs(t, err, ErrInsufficientCapacity, "an outage is not budget exhaustion")
	require.NotErrorIs(t, err, ErrNoCapacitySource, "an outage is not a missing capacity source")
	require.NotErrorIs(t, err, ErrNotReserved, "enforce must not silently degrade to shadow")
}
