package adminstore

// Unit coverage for the CM-00-02 dimensional-component store
// (dimensions.go): no database — every call runs against the mock
// pgxdb/auditTx doubles (store_test.go, policystore_pins_test.go), so these
// tests survive shuffle and race runs.
//
// Behavior locked here:
//   - StoreDimensionalComponents validates the whole batch BEFORE opening
//     the tx; a malformed component refuses with the named problem and no
//     statement ever runs (malformed-refusal oracle).
//   - The INSERT binds the org scope first, canonical decimal text for
//     quantity/bounds (nil stays nil; explicit zero is "0"), and the empty
//     coverage array for non-coverage rows.
//   - Instants travel as int64 nanoseconds (UnixNano ⇄ time.Unix(0, n)):
//     the sub-microsecond fixture times bind and scan exactly, and instants
//     outside the int64 nanosecond range refuse before any statement.
//   - The canonical-text oracle rejects a float-carried 2^53+1 literal;
//     every frozen fixture decimal survives a shortest-text float
//     roundtrip, so only this independent literal proves float rejection.
//   - A statement failure rolls back the whole batch; a replayed delivery
//     fails loudly on the unique key (23505) instead of deduplicating
//     (dedup semantics are CM-00-03).
//   - ListDimensionalComponents requires org AND tenant, keeps the
//     "org_id = $1 AND tenant_id = $2" clause in the leading bound positions
//     (tenant-scope oracle), scans the explicit column list back into exact
//     decimals, and preserves absence (nil quantity/bounds, nil coverage).
//   - Known-red controls: the canonical-decimal oracle rejects the forbidden
//     float carrier, and the tenant-scope oracle rejects a scope-less read
//     clause.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/dimensions"
)

// dimensionaIsolationExec is the withPolicyTx GUC statement that always
// precedes the store's own statements in the recorded exec/query logs.
const dimensionaIsolationExec = "SELECT set_config('app.current_org', $1, true)"

// dimensionalFrozenJSON is the hand-written frozen fixture (independently
// constructed, no self-computed expected values): USD 0.02 exact, 3 internal
// credits exact, energy estimated bounds-only 0.4-0.6 Wh, emissions unknown,
// an estimated energy point inside its own bounds, and an explicit-zero
// credit — mixed precision in one batch.
const dimensionalFrozenJSON = `[
  {"component_id":"comp-usd-fee","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"usage.cost","unit":"USD","quantity":"0.02",
   "source_kind":"gateway","source_ref":"resp-body","method":"provider-report",
   "factor_version":"tariff-2026-11","event_time":"2026-11-24T10:15:30.123456789Z",
   "effective_time":"2026-11-24T10:15:30.123456789Z","boundary":"measurement",
   "precision":"exact","lifecycle":"provisional"},
  {"component_id":"comp-credits-3","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"usage.credits","unit":"credits","quantity":"3",
   "source_kind":"internal","source_ref":"credit-ledger","method":"internal-meter",
   "factor_version":"ledger-v1","event_time":"2026-11-24T10:15:30.123456789Z",
   "effective_time":"2026-11-24T10:15:30.123456789Z",
   "boundary":"measurement","precision":"exact","lifecycle":"provisional"},
  {"component_id":"comp-energy-range","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"energy.grid","unit":"Wh",
   "bounds":{"lower":"0.4","upper":"0.6"},
   "source_kind":"estimate","source_ref":"cpu-seconds","method":"allocation-share",
   "formula":"cpu_seconds*0.8","factor_version":"ef-v4",
   "event_time":"2026-11-24T10:15:30.123456789Z","effective_time":"2026-11-24T10:15:30.123456789Z",
   "boundary":"allocation","allocation_basis":"cpu-seconds",
   "precision":"estimated","lifecycle":"provisional"},
  {"component_id":"comp-co2-unknown","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"emissions.co2e","unit":"gCO2e",
   "source_kind":"estimate","source_ref":"grid-mix","method":"factor-lookup",
   "corrects_component_id":"comp-co2-prior","coverage_meters":["emissions.co2e"],
   "event_time":"2026-11-24T10:15:30.123456789Z","effective_time":"2026-11-24T10:15:30.123456789Z",
   "boundary":"allocation","precision":"unknown","lifecycle":"corrected"},
  {"component_id":"comp-energy-point","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"energy.grid","unit":"Wh","quantity":"0.5",
   "bounds":{"lower":"0.4","upper":"0.6"},
   "source_kind":"estimate","source_ref":"cpu-seconds","method":"meter-interpolation",
   "factor_version":"ef-v4","event_time":"2026-11-24T10:15:30.123456789Z",
   "effective_time":"2026-11-24T10:15:30.123456789Z","boundary":"allocation",
   "allocation_basis":"cpu-seconds","precision":"estimated","lifecycle":"provisional"},
  {"component_id":"comp-credits-zero","event_id":"evt-frozen-1","request_id":"req-frozen-1",
   "tenant_id":"tenant-frozen","meter":"usage.credits","unit":"credits","quantity":"0",
   "source_kind":"internal","source_ref":"credit-ledger","method":"internal-meter",
   "factor_version":"ledger-v1","event_time":"2026-11-24T10:15:30.123456789Z",
   "effective_time":"2026-11-24T10:15:30.123456789Z",
   "boundary":"measurement","precision":"exact","lifecycle":"provisional"}
]`

// dimensionalFrozenComponents decodes the frozen fixture (JSON decode, the
// independent construction path — no struct-literal shortcut).
func dimensionalFrozenComponents(t *testing.T) []dimensions.Component {
	t.Helper()
	var comps []dimensions.Component
	require.NoError(t, json.Unmarshal([]byte(dimensionalFrozenJSON), &comps))
	require.Len(t, comps, 6)
	return comps
}

// dimensionalInsertExecs returns the INSERT execs recorded by the tx double,
// skipping the leading withPolicyTx GUC exec.
func dimensionalInsertExecs(tx *policyTxDouble) []policyExecRecord {
	var inserts []policyExecRecord
	for _, e := range tx.execs {
		if e.sql != dimensionaIsolationExec {
			inserts = append(inserts, e)
		}
	}
	return inserts
}

// TestKnownRed_FloatCarriedLargeIntegerFailsCanonicalOracle: 2^53+1 has no
// exact float64 carrier — ParseFloat rounds it to 2^53 and the shortest
// float text differs from the canonical decimal. Every decimal in the
// frozen fixture survives a shortest-text float roundtrip ("0.02", "3",
// "0.5"), which is exactly why the store-level control needs this
// independent literal: the canonical-text oracle must reject a
// float-carried value, not only drifted float addition.
func TestKnownRed_FloatCarriedLargeIntegerFailsCanonicalOracle(t *testing.T) {
	for _, tc := range []struct {
		name         string
		want         string
		floatCarries string
	}{
		{"quantity 2^53+1", "9007199254740993", "9007199254740992"},
		{"bounds upper 2^53+3", "9007199254740995", "9007199254740996"},
	} {
		f, err := strconv.ParseFloat(tc.want, 64)
		require.NoError(t, err)
		require.Equal(t, tc.floatCarries, strconv.FormatFloat(f, 'f', -1, 64),
			"%s: pinned float64 carrier", tc.name)
		want, err := dimensions.ParseDecimal(tc.want)
		require.NoError(t, err)
		require.Equal(t, tc.want, want.String(),
			"%s: the store oracle roundtrips the canonical text", tc.name)
		carried, err := dimensions.ParseDecimal(tc.floatCarries)
		require.NoError(t, err)
		require.NotEqual(t, tc.want, carried.String(),
			"%s: the store oracle must reject the float-carried text", tc.name)
	}

	// Control: 2^53-1 is exactly representable, so this bound edge cannot
	// catch a float carrier by itself — it exists to keep the DB roundtrip
	// bounds valid around the breaking literals.
	f, err := strconv.ParseFloat("9007199254740991", 64)
	require.NoError(t, err)
	require.Equal(t, "9007199254740991", strconv.FormatFloat(f, 'f', -1, 64),
		"the float-exact bound edge must stay exact under the carrier")
}

// TestStoreDimensionalComponents_RejectsInstantOutOfRange: the int64
// nanosecond carrier wraps silently outside roughly the years 1678-2262,
// so batch validation must refuse an out-of-range instant before any
// statement instead of persisting a wrapped instant as plausible data.
func TestStoreDimensionalComponents_RejectsInstantOutOfRange(t *testing.T) {
	comps := dimensionalFrozenComponents(t)[:1]
	comps[0].EventTime = time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)

	var execs int
	tx := &policyTxDouble{execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		execs++
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	err := store.StoreDimensionalComponents(context.Background(), "org-1", comps)

	require.Error(t, err)
	require.Contains(t, err.Error(), "outside the int64 nanosecond range")
	require.Zero(t, execs, "the refusal must precede every statement, the GUC included")
}

// TestStoreDimensionalComponents_RefusesMalformedBeforeAnyStatement: the
// malformed-refusal oracle — one malformed component refuses the whole
// batch with the named problem and no transaction or statement runs.
func TestStoreDimensionalComponents_RefusesMalformedBeforeAnyStatement(t *testing.T) {
	comps := dimensionalFrozenComponents(t)
	comps[1].Quantity = nil // exact without a quantity is malformed

	var began bool
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		began = true
		return &policyTxDouble{}, nil
	}}, newTestLogger(), nil)

	err := store.StoreDimensionalComponents(context.Background(), "org-1", comps)

	require.Error(t, err)
	var verr *dimensions.ValidationError
	require.ErrorAs(t, err, &verr)
	require.Contains(t, err.Error(), "quantity is required")
	require.False(t, began, "validation must happen before the tx opens")
}

// TestStoreDimensionalComponents_RefusesEmptyOrg: the org scope is
// server-selected; an absent org id refuses before anything runs.
func TestStoreDimensionalComponents_RefusesEmptyOrg(t *testing.T) {
	var began bool
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		began = true
		return &policyTxDouble{}, nil
	}}, newTestLogger(), nil)

	err := store.StoreDimensionalComponents(context.Background(), "", dimensionalFrozenComponents(t))

	require.Error(t, err)
	require.Contains(t, err.Error(), "org id is required")
	require.False(t, began)
}

// TestStoreDimensionalComponents_BindsOrgScopeAndCanonicalDecimals: the
// org scope binds first, every decimal travels as canonical text, absence
// stays NULL, and the closed-set precision kinds bind as plain text.
func TestStoreDimensionalComponents_BindsOrgScopeAndCanonicalDecimals(t *testing.T) {
	comps := dimensionalFrozenComponents(t)
	tx := &policyTxDouble{}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	require.NoError(t, store.StoreDimensionalComponents(context.Background(), "11111111-1111-1111-1111-111111111111", comps))

	inserts := dimensionalInsertExecs(tx)
	require.Len(t, inserts, 6)
	for i, e := range inserts {
		require.Contains(t, e.sql, "INSERT INTO dimensional_components", "exec %d", i)
		require.Contains(t, e.sql, "org_id, tenant_id, event_id, component_id", "explicit columns, exec %d", i)
		require.Equal(t, "11111111-1111-1111-1111-111111111111", e.args[0], "org scope binds first, exec %d", i)
	}

	// Frozen decimal carriers, in fixture order: 0.02 / 3 / nil / nil / 0.5 / 0.
	require.Equal(t, "0.02", *inserts[0].args[8].(*string))
	require.Equal(t, "3", *inserts[1].args[8].(*string))
	require.Nil(t, inserts[2].args[8])
	require.Nil(t, inserts[3].args[8])
	require.Equal(t, "0.5", *inserts[4].args[8].(*string))
	require.Equal(t, "0", *inserts[5].args[8].(*string), "explicit zero is stored, never nil")

	// Estimated bounds-only row: both sides bound, unknown row: both NULL.
	require.Equal(t, "0.4", *inserts[2].args[9].(*string))
	require.Equal(t, "0.6", *inserts[2].args[10].(*string))
	require.Nil(t, inserts[3].args[9])
	require.Nil(t, inserts[3].args[10])

	// Non-coverage rows carry the empty array; the coverage row binds meters.
	require.Equal(t, []string{}, inserts[0].args[23], "absent coverage binds the empty array, never nil")
	require.Equal(t, []string{"emissions.co2e"}, inserts[3].args[23].([]string))

	// Instant carrier regression guard: int64 nanoseconds bind exactly, so
	// the sub-microsecond fixture instants reach the statement untouched
	// (a timestamptz carrier would truncate them at the column).
	require.Equal(t, comps[0].EventTime.UnixNano(), inserts[0].args[16])
	require.Equal(t, comps[0].EffectiveTime.UnixNano(), inserts[0].args[17])
}

// TestStoreDimensionalComponents_StatementFailureRollsBackBatch: a failure
// on any insert rolls the whole batch back.
func TestStoreDimensionalComponents_StatementFailureRollsBackBatch(t *testing.T) {
	comps := dimensionalFrozenComponents(t)[:2]
	tx := &policyTxDouble{execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
		if sql != dimensionaIsolationExec && len(args) > 3 && args[3] == "comp-credits-3" { // args: 0=org, 1=tenant, 2=event, 3=component
			return pgconn.NewCommandTag(""), errors.New("boom")
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	err := store.StoreDimensionalComponents(context.Background(), "org-1", comps)

	require.Error(t, err)
	require.Contains(t, err.Error(), "comp-credits-3")
	require.True(t, tx.rolledBack)
	require.False(t, tx.committed)
}

// TestStoreDimensionalComponents_ReplayFailsLoudly: a replayed delivery
// hits the unique key (23505) and surfaces as a rollback error — silent
// dedup semantics are CM-00-03, out of this leaf.
func TestStoreDimensionalComponents_ReplayFailsLoudly(t *testing.T) {
	comps := dimensionalFrozenComponents(t)[:1]
	tx := &policyTxDouble{execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
		if sql != dimensionaIsolationExec {
			return pgconn.NewCommandTag(""), &pgconn.PgError{
				Code:    "23505",
				Message: "duplicate key value violates unique constraint",
			}
		}
		return pgconn.NewCommandTag("OK"), nil
	}}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	err := store.StoreDimensionalComponents(context.Background(), "org-1", comps)

	var pgErr *pgconn.PgError
	require.Error(t, err)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	require.True(t, tx.rolledBack)
}

// TestListDimensionalComponents_RequiresOrgAndTenant: neither id is
// optional; a read without both refuses before anything runs.
func TestListDimensionalComponents_RequiresOrgAndTenant(t *testing.T) {
	var began bool
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		began = true
		return &policyTxDouble{}, nil
	}}, newTestLogger(), nil)

	_, _, err := store.ListDimensionalComponents(context.Background(), "org-1", "", DimensionalComponentFilters{})
	require.Error(t, err)
	require.False(t, began)
}

// dimensionalTenantScopeOracle is the read-scope oracle: a dimensional read
// clause must filter org_id = $1 AND tenant_id = $2 with exactly those bound
// values in the leading positions, and every optional filter must come
// behind them.
func dimensionalTenantScopeOracle(clause string, args []any, orgID, tenantID string) error {
	if len(args) < 2 {
		return fmt.Errorf("read clause binds %d args, want at least the org and tenant scope", len(args))
	}
	if args[0] != orgID || args[1] != tenantID {
		return fmt.Errorf("leading bound args %v/%v are not the org %q and tenant %q scope", args[0], args[1], orgID, tenantID)
	}
	if !strings.Contains(clause, "org_id = $1") || !strings.Contains(clause, "tenant_id = $2") {
		return fmt.Errorf("read clause %q drops the org or tenant predicate", clause)
	}
	return nil
}

// TestListDimensionalComponents_WhereAlwaysScoped: the tenant-scope oracle
// passes the production clause with and without optional filters.
func TestListDimensionalComponents_WhereAlwaysScoped(t *testing.T) {
	var countSQL string
	var countArgs []any
	tx := &policyTxDouble{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			countSQL, countArgs = sql, args
			return &mockPGXRow{data: [][]interface{}{{int64(6)}}}
		},
		queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			require.NoError(t, dimensionalTenantScopeOracle(sql, args, "org-1", "tenant-frozen"))
			return &dimensionalRowsFake{}, nil
		},
	}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	filters := DimensionalComponentFilters{RequestID: "req-frozen-1", Meter: "usage.cost"}
	comps, total, err := store.ListDimensionalComponents(context.Background(), "org-1", "tenant-frozen", filters)

	require.NoError(t, err)
	require.EqualValues(t, 6, total)
	require.NotNil(t, comps)
	require.NoError(t, dimensionalTenantScopeOracle(countSQL, countArgs, "org-1", "tenant-frozen"))
	require.Contains(t, countSQL, "org_id = $1 AND tenant_id = $2")
	require.Contains(t, countSQL, "request_id = $3")
	require.Contains(t, countSQL, "meter = $4")
	require.Len(t, countArgs, 4)
}

// TestKnownRed_ScopelessReaderFailsTenantOracle: known-red control — a
// reader that regresses to org-only scoping fails the tenant-scope oracle,
// proving the oracle detects scope removal rather than rubber-stamping.
func TestKnownRed_ScopelessReaderFailsTenantOracle(t *testing.T) {
	err := dimensionalTenantScopeOracle(" WHERE org_id = $1", []any{"org-1"}, "org-1", "tenant-frozen")
	require.Error(t, err, "scope-less clause must fail the tenant-scope oracle")
	require.Error(t, dimensionalTenantScopeOracle(" WHERE tenant_id = $1", []any{"tenant-frozen"}, "org-1", "tenant-frozen"),
		"tenant-only scoping must also fail: the org scope is mandatory")

	// The production builder itself stays green under the same oracle.
	where, args := dimensionalWhere("org-1", "tenant-frozen", DimensionalComponentFilters{})
	require.NoError(t, dimensionalTenantScopeOracle(where, args, "org-1", "tenant-frozen"))
}

// dimensionalRowsFake is a standalone pgx.Rows double for the List scan
// tests. Unlike mockPGXRows it supports *[]string dests (coverage_meters)
// and injectable scan failures (failingScanRows pattern).
type dimensionalRowsFake struct {
	rows    [][]any
	scanErr error
	idx     int
}

func (r *dimensionalRowsFake) Next() bool { r.idx++; return r.idx <= len(r.rows) }
func (r *dimensionalRowsFake) Err() error { return nil }
func (r *dimensionalRowsFake) Close()     {}

func (r *dimensionalRowsFake) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *dimensionalRowsFake) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *dimensionalRowsFake) Conn() *pgx.Conn                              { return nil }
func (r *dimensionalRowsFake) RawValues() [][]byte                          { return nil }
func (r *dimensionalRowsFake) Values() ([]any, error)                       { return nil, nil }
func (r *dimensionalRowsFake) TypeMap() *pgtype.Map                         { return nil }

func (r *dimensionalRowsFake) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if r.idx == 0 || r.idx > len(r.rows) {
		return errors.New("no row")
	}
	row := r.rows[r.idx-1]
	if len(dest) != len(row) {
		return fmt.Errorf("scan dests %d != columns %d", len(dest), len(row))
	}
	for i, d := range dest {
		if err := dimensionalScanCell(d, row[i]); err != nil {
			return fmt.Errorf("column %d: %w", i, err)
		}
	}
	return nil
}

// dimensionalScanCell assigns one fake cell to one scan destination, in the
// shapes pgx hands each destination type (raw string/nil, never pointers).
func dimensionalScanCell(dest, cell any) error {
	if dimensionalEnumScan(dest, cell) {
		return nil
	}
	switch d := dest.(type) {
	case *string:
		*d = cell.(string)
	case **string:
		text, err := dimensionalCellText(cell)
		if err != nil {
			return err
		}
		*d = text
	case *[]string:
		coverage, err := dimensionalCellCoverage(cell)
		if err != nil {
			return err
		}
		*d = coverage
	case *int64:
		*d = cell.(int64)
	default:
		return fmt.Errorf("unsupported scan dest %T", dest)
	}
	return nil
}

// dimensionalEnumScan assigns the closed-set enum destinations from their
// raw string cells; it reports whether dest was one of them.
func dimensionalEnumScan(dest, cell any) bool {
	switch d := dest.(type) {
	case *dimensions.Precision:
		*d = dimensions.Precision(cell.(string))
	case *dimensions.Lifecycle:
		*d = dimensions.Lifecycle(cell.(string))
	case *dimensions.Boundary:
		*d = dimensions.Boundary(cell.(string))
	default:
		return false
	}
	return true
}

// dimensionalCellText maps a nullable text cell (nil or string).
func dimensionalCellText(cell any) (*string, error) {
	if cell == nil {
		return nil, nil
	}
	s, ok := cell.(string)
	if !ok {
		return nil, fmt.Errorf("nullable text cell %v is not a string", cell)
	}
	return &s, nil
}

// dimensionalCellCoverage maps a nullable coverage cell (nil or []string).
func dimensionalCellCoverage(cell any) ([]string, error) {
	if cell == nil {
		return nil, nil
	}
	m, ok := cell.([]string)
	if !ok {
		return nil, fmt.Errorf("coverage cell %v is not []string", cell)
	}
	return m, nil
}

// dimensionalFrozenInstant is the fake rows' shared instant, deliberately
// non-microsecond-aligned so a truncating carrier cannot pass by accident.
var dimensionalFrozenInstant = time.Date(2026, 11, 24, 10, 15, 30, 123456789, time.UTC)

// dimensionalFakeRow builds one fake result row in the explicit
// dimensionalComponentColumns order (hand-written literals, no fixtures
// shared with the write path). lifecycle/corrects/coverage shape the row's
// correction state so every row this helper builds can itself pass the
// component contract unless a test deliberately corrupts a cell.
func dimensionalFakeRow(quantity, lower, upper *string, precision dimensions.Precision, lifecycle dimensions.Lifecycle, corrects string, coverage []string) []any {
	// Nullable text cells hold nil or the raw string, the shape pgx hands a
	// **string dest (the *string here is the builder's option carrier).
	text := func(s *string) any {
		if s == nil {
			return nil
		}
		return *s
	}
	return []any{
		"tenant-frozen", "evt-frozen-1", "comp-r", "req-frozen-1", "",
		"usage.cost", "USD", text(quantity), text(lower), text(upper),
		"gateway", "resp-body", "provider-report", "", "tariff-2026-11",
		dimensionalFrozenInstant.UnixNano(), dimensionalFrozenInstant.UnixNano(),
		"measurement", "", string(precision), string(lifecycle), corrects, coverage,
	}
}

// TestListDimensionalComponents_ScanRoundtripPreservesAbsence: nil
// quantity/bounds read back as nil; canonical text reads back as the exact
// same decimal; empty coverage normalizes to nil. Two rows in one page —
// the absent one first to prove row state does not leak across scans.
func TestListDimensionalComponents_ScanRoundtripPreservesAbsence(t *testing.T) {
	tx := &policyTxDouble{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(4)}}}
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &dimensionalRowsFake{rows: [][]any{
				dimensionalFakeRow(nil, nil, nil, dimensions.PrecisionUnknown, dimensions.LifecycleProvisional, "", []string{}),
				dimensionalFakeRow(nil, ptrString("0.4"), ptrString("0.6"), dimensions.PrecisionEstimated, dimensions.LifecycleProvisional, "", nil),
				dimensionalFakeRow(ptrString("0.02"), nil, nil, dimensions.PrecisionExact, dimensions.LifecycleProvisional, "", nil),
				dimensionalFakeRow(nil, nil, nil, dimensions.PrecisionUnknown, dimensions.LifecycleCorrected, "comp-co2-prior", []string{"usage.cost"}),
			}}, nil
		},
	}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	comps, total, err := store.ListDimensionalComponents(context.Background(), "org-1", "tenant-frozen", DimensionalComponentFilters{})

	require.NoError(t, err)
	require.EqualValues(t, 4, total)
	require.Len(t, comps, 4)

	absent, ranged, exact, corrected := comps[0], comps[1], comps[2], comps[3]
	require.Nil(t, absent.Quantity, "unknown stays unknown, never zero")
	require.Nil(t, absent.Bounds)
	require.Nil(t, absent.CoverageMeters, "empty coverage reads back absent")
	require.Equal(t, dimensions.PrecisionUnknown, absent.Precision)
	require.True(t, absent.EventTime.Equal(dimensionalFrozenInstant),
		"the int64 nanosecond instant cell reconstructs the exact instant")
	require.True(t, absent.EffectiveTime.Equal(dimensionalFrozenInstant))

	require.Nil(t, ranged.Quantity, "bounds-only stays quantity-absent")
	require.NotNil(t, ranged.Bounds)
	require.NotNil(t, ranged.Bounds.Lower)
	require.Equal(t, "0.4", ranged.Bounds.Lower.String())
	require.Equal(t, "0.6", ranged.Bounds.Upper.String())

	require.NotNil(t, exact.Quantity)
	require.Equal(t, "0.02", exact.Quantity.String(), "canonical text roundtrips exactly")
	require.Nil(t, exact.Bounds)
	require.Equal(t, dimensions.PrecisionExact, exact.Precision)

	require.Equal(t, []string{"usage.cost"}, corrected.CoverageMeters)
	require.Equal(t, "comp-co2-prior", corrected.CorrectsComponentID)
	require.Equal(t, dimensions.LifecycleCorrected, corrected.Lifecycle)
}

// TestListDimensionalComponents_CorruptStoredRowFailsValidation: the
// read-side integrity oracle — a row whose stored fields contradict the
// component contract (unknown precision with a quantity) surfaces as a
// named validation error, never as a plausible component.
func TestListDimensionalComponents_CorruptStoredRowFailsValidation(t *testing.T) {
	tx := &policyTxDouble{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(1)}}}
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &dimensionalRowsFake{rows: [][]any{
				dimensionalFakeRow(ptrString("0.02"), nil, nil, dimensions.PrecisionUnknown, dimensions.LifecycleProvisional, "", nil),
			}}, nil
		},
	}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	_, _, err := store.ListDimensionalComponents(context.Background(), "org-1", "tenant-frozen", DimensionalComponentFilters{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "stored row fails the component contract")
	require.True(t, tx.rolledBack)
}

// TestListDimensionalComponents_ScanFailureRollsBack: a row-level scan
// failure aborts the read and rolls the tx back — no partial page.
func TestListDimensionalComponents_ScanFailureRollsBack(t *testing.T) {
	tx := &policyTxDouble{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(1)}}}
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &dimensionalRowsFake{
				rows:    [][]any{dimensionalFakeRow(nil, nil, nil, dimensions.PrecisionUnknown, dimensions.LifecycleProvisional, "", nil)},
				scanErr: errors.New("corrupted payload"),
			}, nil
		},
	}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	_, _, err := store.ListDimensionalComponents(context.Background(), "org-1", "tenant-frozen", DimensionalComponentFilters{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "scan dimensional component")
	require.True(t, tx.rolledBack)
}

// TestListDimensionalComponents_EmptyPageIsNonNil: an empty tenant reads
// back as an empty slice, never nil (JSON contract hygiene).
func TestListDimensionalComponents_EmptyPageIsNonNil(t *testing.T) {
	tx := &policyTxDouble{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(0)}}}
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &dimensionalRowsFake{}, nil
		},
	}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) {
		return tx, nil
	}}, newTestLogger(), nil)

	comps, total, err := store.ListDimensionalComponents(context.Background(), "org-1", "tenant-frozen", DimensionalComponentFilters{})

	require.NoError(t, err)
	require.EqualValues(t, 0, total)
	require.NotNil(t, comps)
	require.Empty(t, comps)
}

// TestKnownRed_FloatCarrierFailsCanonicalOracle: known-red control — the
// forbidden float64 carrier survives parsing but fails canonical equality:
// 0.1+0.2 in float64 formats back with the 17th-digit drift, while the
// exact decimal path reads "0.3". This is why ParseDecimal alone is not the
// decimal oracle and why no float ever touches the persistence path.
func TestKnownRed_FloatCarrierFailsCanonicalOracle(t *testing.T) {
	a, b := 0.1, 0.2 // runtime floats: constant folding would keep 0.1+0.2 exact
	floatCarried := strconv.FormatFloat(a+b, 'f', -1, 64)
	require.Equal(t, "0.30000000000000004", floatCarried, "the float carrier drifts at the 17th digit")

	parsed, err := dimensions.ParseDecimal(floatCarried)
	require.NoError(t, err, "parsing alone does not reject a drifted value")

	exactSum, err := dimensions.Add(mustDimensionalDecimal(t, "0.1"), mustDimensionalDecimal(t, "0.2"))
	require.NoError(t, err)
	require.Equal(t, "0.3", exactSum.String())
	require.NotEqual(t, "0.3", parsed.String(),
		"the canonical-equality oracle must reject the float-carried value")
}

// mustDimensionalDecimal parses a literal in tests, failing the test on a
// malformed literal (fixtures never self-compute values).
func mustDimensionalDecimal(t *testing.T, s string) dimensions.Decimal {
	t.Helper()
	d, err := dimensions.ParseDecimal(s)
	require.NoError(t, err)
	return d
}

// ptrString is the fixture helper for nullable text carriers.
func ptrString(s string) *string { return &s }
