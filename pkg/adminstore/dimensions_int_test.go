package adminstore

// DB-gated integration coverage for the CM-00-02 dimensional-component leaf
// (dimensions.go, migration 0035). Runs against the package's disposable,
// fully migrated Postgres stand: skipped in -short, Docker required outside
// -short (QG2-B3). Tests serialize on the package mutex (openAdminTestPool).
//
// Locked here, with independently constructed fixtures (JSON decode + raw
// SQL INSERT, no self-computed expectations):
//   - The frozen mixed-precision fixture roundtrips exactly: canonical
//     decimal text storage (0.02 stays 0.02; the raw carrier column is read
//     back by SQL, independent of Go), unknown stays NULL, explicit zero
//     stays zero, bounds and correction coverage survive.
//   - Tenant scope is mandatory: the same tenant id under two orgs is
//     invisible across the boundary in every direction, filters included.
//     Known-red control: a scope-less raw reader sees both orgs, proving
//     the fixture detects scope removal.
//   - RLS posture on the new table mirrors policy_decisions: a
//     yabanin_app session bound to an org sees only that org; an unbound
//     session sees nothing (fail closed).
//   - A malformed component refuses the whole batch and persists nothing;
//     the SQL CHECK constraints are the second, validation-independent net.
//   - Legacy monetary reads (SpendToday, request_logs rows) are untouched
//     by a dimensional write to the same org.
//   - A fresh pool (restart posture) reads the persisted rows back exactly.
//   - Sub-microsecond instants survive the int64 nanosecond carrier exactly
//     (a timestamptz column would truncate them), and large-integer decimals
//     that break under a float64 carrier roundtrip as exact text through the
//     real store (write AND read, SQL-level carrier included).
//   - Rows tied on (event_time, component_id) page deterministically on the
//     event_id tiebreak: no repeat, no skip across OFFSET page boundaries.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/dimensions"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// dimensionalTestOrgs creates two uniquely named orgs and registers their
// cleanup (organizations last, cascades wipe the dimensional rows).
func dimensionalTestOrgs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (string, string) {
	t.Helper()
	suffix := time.Now().UnixNano()
	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
		fmt.Sprintf("dim-ix-a-%d", suffix), fmt.Sprintf("dim-ix-a-%d", suffix)).Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
		fmt.Sprintf("dim-ix-b-%d", suffix), fmt.Sprintf("dim-ix-b-%d", suffix)).Scan(&orgB))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA, orgB})
	})
	return orgA, orgB
}

// dimensionalCount counts the tenant's stored rows inside the org scope by
// direct SQL (an independent oracle path — it bypasses the store).
func dimensionalCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, tenantID string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components WHERE org_id = $1::uuid AND tenant_id = $2`,
		orgID, tenantID).Scan(&n))
	return n
}

// TestDimensionalComponents_FrozenFixtureRoundtrip_Integration: the JSON
// fixture stores and reads back exactly, the decimal carrier is canonical
// text at the SQL level, replay fails loudly on the unique key, and page
// filters work inside the org+tenant scope.
func TestDimensionalComponents_FrozenFixtureRoundtrip_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)
	tenant := "tenant-frozen"
	comps := dimensionalFrozenComponents(t)

	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, comps))
	require.EqualValues(t, 6, dimensionalCount(t, ctx, pool, orgA, tenant))

	got, total, err := store.ListDimensionalComponents(ctx, orgA, tenant, DimensionalComponentFilters{})
	require.NoError(t, err)
	require.EqualValues(t, 6, total)
	require.Len(t, got, 6)

	byID := func(id string) int {
		for i := range got {
			if got[i].ComponentID == id {
				return i
			}
		}
		return -1
	}

	usd := got[byID("comp-usd-fee")]
	require.NotNil(t, usd.Quantity)
	require.Equal(t, "0.02", usd.Quantity.String(), "USD fee roundtrips exactly")
	require.Equal(t, "USD", usd.Unit)
	require.Equal(t, "tariff-2026-11", usd.FactorVersion)
	require.Equal(t, tenant, usd.TenantID)
	require.Equal(t, "evt-frozen-1", usd.EventID)
	require.True(t, usd.EventTime.Equal(time.Date(2026, 11, 24, 10, 15, 30, 123456789, time.UTC)),
		"sub-microsecond event time roundtrips exactly (regression guard: a timestamptz carrier would truncate)")
	require.True(t, usd.EffectiveTime.Equal(usd.EventTime))

	credits := got[byID("comp-credits-3")]
	require.NotNil(t, credits.Quantity)
	require.Equal(t, "3", credits.Quantity.String())

	ranged := got[byID("comp-energy-range")]
	require.Nil(t, ranged.Quantity, "bounds-only stays quantity-absent")
	require.NotNil(t, ranged.Bounds)
	require.Equal(t, "0.4", ranged.Bounds.Lower.String())
	require.Equal(t, "0.6", ranged.Bounds.Upper.String())
	require.Equal(t, "cpu-seconds", ranged.AllocationBasis)

	unknown := got[byID("comp-co2-unknown")]
	require.Nil(t, unknown.Quantity, "unknown stays unknown, never zero")
	require.Nil(t, unknown.Bounds)
	require.Equal(t, "comp-co2-prior", unknown.CorrectsComponentID)
	require.Equal(t, []string{"emissions.co2e"}, unknown.CoverageMeters)

	zero := got[byID("comp-credits-zero")]
	require.NotNil(t, zero.Quantity, "explicit zero persists as a measured zero")
	require.Equal(t, "0", zero.Quantity.String())

	// SQL-level carrier oracle: the stored quantity_text is exactly the
	// canonical literal, independent of any Go struct reconstruction.
	var carrier string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT quantity_text FROM dimensional_components
		 WHERE org_id = $1::uuid AND tenant_id = $2 AND component_id = 'comp-usd-fee'`,
		orgA, tenant).Scan(&carrier))
	require.Equal(t, "0.02", carrier)
	var unknownCarrier *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT quantity_text FROM dimensional_components
		 WHERE org_id = $1::uuid AND tenant_id = $2 AND component_id = 'comp-co2-unknown'`,
		orgA, tenant).Scan(&unknownCarrier))
	require.Nil(t, unknownCarrier, "unknown quantity is SQL NULL, never '0'")

	// Replay: the same delivery key fails loudly on the unique key (dedup
	// semantics are CM-00-03); the stored row count is unchanged.
	err = store.StoreDimensionalComponents(ctx, orgA, comps[:1])
	require.Error(t, err, "replayed delivery must fail on the unique key")
	require.EqualValues(t, 6, dimensionalCount(t, ctx, pool, orgA, tenant), "replay must not add rows")

	// Scoped filters: the request and meter filters bind behind the scope.
	filtered, total, err := store.ListDimensionalComponents(ctx, orgA, tenant,
		DimensionalComponentFilters{RequestID: "req-frozen-1", Meter: "usage.cost"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, "comp-usd-fee", filtered[0].ComponentID)

	_, total, err = store.ListDimensionalComponents(ctx, orgA, tenant,
		DimensionalComponentFilters{EventID: "evt-no-such-event"})
	require.NoError(t, err)
	require.Zero(t, total)
}

// TestDimensionalComponents_TenantScopeDenial_Integration: the same tenant
// id under two orgs never leaks in either direction; the known-red control
// proves the fixture detects a scope-less reader; RLS mirrors the
// policy_decisions fail-closed posture.
func TestDimensionalComponents_TenantScopeDenial_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, orgB := dimensionalTestOrgs(t, ctx, pool)
	// The shared tenant literal is the fixture's own embedded tenant_id
	// (tenant is component data; the org is the server-selected scope):
	// the same tenant id now exists under two orgs.
	tenant := "tenant-frozen"

	// org A gets the full frozen fixture through the store.
	comps := dimensionalFrozenComponents(t)
	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, comps))

	// org B gets one raw-SQL row under the SAME tenant id but a distinct
	// event id (raw INSERT: an org-external write path by construction).
	_, err := pool.Exec(ctx, `
		INSERT INTO dimensional_components
			(org_id, tenant_id, event_id, component_id, request_id, meter, unit,
			 quantity_text, source_kind, source_ref, method, factor_version,
			 event_time, effective_time, boundary, precision_kind, lifecycle)
		VALUES ($1::uuid, $2, 'evt-orgb', 'comp-orgb', 'req-orgb', 'usage.cost', 'USD',
			 '1.25', 'gateway', 'resp-body', 'provider-report', 'tariff-2026-11',
			 '2026-11-24T10:15:30.123456Z', '2026-11-24T10:15:30.123456Z',
			 'measurement', 'exact', 'provisional')`, orgB, tenant)
	require.NoError(t, err)

	// org A's read: exactly its own six rows, none of org B's event.
	orgARows, total, err := store.ListDimensionalComponents(ctx, orgA, tenant, DimensionalComponentFilters{})
	require.NoError(t, err)
	require.EqualValues(t, 6, total)
	for _, c := range orgARows {
		require.NotEqual(t, "evt-orgb", c.EventID, "org A's read must not contain org B's row")
	}
	cross, total, err := store.ListDimensionalComponents(ctx, orgA, tenant,
		DimensionalComponentFilters{EventID: "evt-orgb"})
	require.NoError(t, err)
	require.Zero(t, total, "the org B event must be unfilterable from org A's scope")
	require.Empty(t, cross)

	// org B's read: exactly its own row; org A's fixture is invisible.
	orgBRows, total, err := store.ListDimensionalComponents(ctx, orgB, tenant, DimensionalComponentFilters{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, "evt-orgb", orgBRows[0].EventID)

	// An unknown tenant inside a real org reads empty.
	_, total, err = store.ListDimensionalComponents(ctx, orgA, "tenant-no-such", DimensionalComponentFilters{})
	require.NoError(t, err)
	require.Zero(t, total)

	// Known-red control: the scope-less reader sees BOTH orgs' rows for the
	// shared tenant — the same rows the scoped reads above partitioned. If
	// the store ever dropped its predicates, its output would match this
	// leak and fail the exactly-scoped oracles above.
	var leak int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components WHERE tenant_id = $1`, tenant).Scan(&leak))
	require.EqualValues(t, 7, leak, "scope-less reader must see both orgs' rows (fixture sensitivity proof)")

	// RLS posture under the application role: bound to org A, only org A's
	// rows are visible; unbound, nothing is (fail closed).
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	require.NoError(t, withYabaninAppRole(t, ctx, conn))
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
	require.NoError(t, err)
	var seen int64
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components WHERE tenant_id = $1`, tenant).Scan(&seen))
	require.EqualValues(t, 6, seen, "a bound session must see only its own org's rows")
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components WHERE tenant_id = $1 AND org_id = $2::uuid`,
		tenant, orgB).Scan(&seen))
	require.Zero(t, seen, "a bound session must not see the foreign org's rows")

	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
	require.NoError(t, err)
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT count(*) FROM dimensional_components WHERE tenant_id = $1`, tenant).Scan(&seen))
	require.Zero(t, seen, "an unbound session must see no rows at all (fail closed)")
}

// withYabaninAppRole downgrades the connection to the application role,
// mirroring the policydecisions RLS test posture.
func withYabaninAppRole(t *testing.T, ctx context.Context, conn *pgxpool.Conn) error {
	t.Helper()
	if _, err := conn.Exec(ctx, "RESET ROLE"); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "SET row_security = on"); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "SET ROLE yabanin_app"); err != nil {
		return err
	}
	var currentUser string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser); err != nil {
		return err
	}
	if currentUser != "yabanin_app" {
		return fmt.Errorf("RLS assertions are void unless the session is downgraded, got %q", currentUser)
	}
	return nil
}

// TestDimensionalComponents_MalformedRefusal_Integration: a malformed
// component refuses the whole batch with nothing persisted, and the SQL
// CHECK constraints independently reject closed-set violations that bypass
// the store.
func TestDimensionalComponents_MalformedRefusal_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)
	tenant := "tenant-malformed"

	comps := dimensionalFrozenComponents(t)
	comps[1].Quantity = nil // exact without a quantity is malformed
	err := store.StoreDimensionalComponents(ctx, orgA, comps)
	require.Error(t, err)
	require.Contains(t, err.Error(), "quantity is required")
	// Regression guard (review finding 4): the refused batch rows are all
	// tenant-frozen, so the zero-write check must count that tenant — the
	// probe tenant below has zero rows regardless and would prove nothing.
	require.Zero(t, dimensionalCount(t, ctx, pool, orgA, "tenant-frozen"),
		"the malformed batch must persist nothing in the batch tenant")

	// DB-level net: a raw INSERT with an unknown precision kind violates
	// the CHECK constraint (independent of the app validation layer).
	_, err = pool.Exec(ctx, `
		INSERT INTO dimensional_components
			(org_id, tenant_id, event_id, component_id, request_id, meter, unit,
			 quantity_text, source_kind, source_ref, method, factor_version,
			 event_time, effective_time, boundary, precision_kind, lifecycle)
		VALUES ($1::uuid, $2, 'evt-check', 'comp-check', 'req-check', 'usage.cost', 'USD',
			 '1.00', 'gateway', 'resp-body', 'provider-report', 'tariff-2026-11',
			 1795515330123456789, 1795515330123456789,
			 'measurement', 'ballpark', 'provisional')`, orgA, tenant)
	require.Error(t, err, "unknown precision_kind must violate the CHECK constraint")
	var pgCode string
	if err != nil {
		var extractErr error
		pgCode, extractErr = pgErrorCode(err)
		require.NoError(t, extractErr)
	}
	require.Equal(t, "23514", pgCode, "the rejection must be the check_violation")
}

// pgErrorCode extracts the SQLSTATE of a pgconn.PgError chain.
func pgErrorCode(err error) (string, error) {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState(), nil
	}
	return "", fmt.Errorf("error %v carries no SQLSTATE", err)
}

// TestDimensionalComponents_LegacyMoneyUnchanged_Integration: a dimensional
// write into an org with a fully seeded monetary history leaves every
// legacy read bit-for-bit identical.
func TestDimensionalComponents_LegacyMoneyUnchanged_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	fx := seedContractFixture(t, pool)

	moneySnapshot := func() (string, float64) {
		t.Helper()
		var rows string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT coalesce(string_agg(row_to_json(rl)::text, E'\n' ORDER BY rl.id), '')
			FROM request_logs rl WHERE rl.org_id::text = $1`, fx.OrgA).Scan(&rows))
		spend, err := store.SpendToday(ctx, fx.OrgA)
		require.NoError(t, err)
		return rows, spend
	}
	beforeRows, beforeSpend := moneySnapshot()

	// Dimensional write into the same org (the fixture's tenant literal is
	// store data; the org scope is the seeded org).
	require.NoError(t, store.StoreDimensionalComponents(ctx, fx.OrgA, dimensionalFrozenComponents(t)))
	require.EqualValues(t, 6, dimensionalCount(t, ctx, pool, fx.OrgA, "tenant-frozen"))

	afterRows, afterSpend := moneySnapshot()
	require.Equal(t, beforeRows, afterRows, "request_logs rows must be untouched")
	require.Equal(t, beforeSpend, afterSpend, "SpendToday must be untouched")
}

// TestDimensionalComponents_RestartReadBack_Integration: rows written by
// one store/pool read back exactly through a fresh pool — the persistence
// posture a restart relies on.
func TestDimensionalComponents_RestartReadBack_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)
	tenant := "tenant-frozen" // the fixture's embedded tenant_id
	comps := dimensionalFrozenComponents(t)
	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, comps))

	// A brand-new pool over the same database (restart posture).
	fresh := testdb.PostgresPool(t, func(*pgxpool.Config) {})
	defer fresh.Close()
	restarted := New(fresh, slog.New(slog.DiscardHandler), nil)

	got, total, err := restarted.ListDimensionalComponents(ctx, orgA, tenant, DimensionalComponentFilters{})
	require.NoError(t, err)
	require.EqualValues(t, 6, total)
	require.Len(t, got, 6)
	usd := got[0]
	for _, c := range got {
		if c.ComponentID == "comp-usd-fee" {
			usd = c
		}
	}
	require.NotNil(t, usd.Quantity)
	require.Equal(t, "comp-usd-fee", usd.ComponentID, "the restart read must find the frozen row")
	require.Equal(t, "0.02", usd.Quantity.String())
	require.Equal(t, "tenant-frozen", usd.TenantID)
}

// TestDimensionalComponents_SubMicrosecondInstantsRoundtrip_Integration:
// regression guard for the timestamptz truncation found in review — the
// contract's time.Time instants keep nanoseconds, so distinct
// non-microsecond-aligned event/effective instants must read back exactly.
func TestDimensionalComponents_SubMicrosecondInstantsRoundtrip_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)

	event := time.Date(2026, 11, 24, 10, 15, 30, 123456789, time.UTC)
	effective := time.Date(2026, 11, 24, 10, 15, 30, 987654321, time.UTC)
	require.NotZero(t, event.UnixNano()%1000, "the event instant must be sub-microsecond-aligned")
	require.NotZero(t, effective.UnixNano()%1000, "the effective instant must be sub-microsecond-aligned")
	require.NotEqual(t, event.UnixNano(), effective.UnixNano())

	comps := dimensionalFrozenComponents(t)[:1]
	comps[0].EventID = "evt-submicro"
	comps[0].EventTime = event
	comps[0].EffectiveTime = effective
	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, comps))

	got, total, err := store.ListDimensionalComponents(ctx, orgA, "tenant-frozen",
		DimensionalComponentFilters{EventID: "evt-submicro"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, got, 1)
	require.Equal(t, event.UnixNano(), got[0].EventTime.UnixNano(),
		"the event instant must survive the int64 nanosecond carrier exactly")
	require.Equal(t, effective.UnixNano(), got[0].EffectiveTime.UnixNano(),
		"the effective instant must survive the int64 nanosecond carrier exactly")
	require.True(t, got[0].EventTime.Equal(event))
	require.True(t, got[0].EffectiveTime.Equal(effective))

	// SQL-level carrier oracle: the column stores the raw nanosecond
	// integer, independent of any Go reconstruction.
	var storedEvent, storedEffective int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_time, effective_time FROM dimensional_components
		 WHERE org_id = $1::uuid AND tenant_id = 'tenant-frozen' AND event_id = 'evt-submicro'`,
		orgA).Scan(&storedEvent, &storedEffective))
	require.Equal(t, event.UnixNano(), storedEvent)
	require.Equal(t, effective.UnixNano(), storedEffective)
}

// TestDimensionalComponents_LargeIntegerDecimalRoundtrip_Integration:
// regression guard for the float-carrier gap found in review — every frozen
// fixture decimal survives a shortest-text float64 roundtrip, so the store
// write+read path needs literals that break under a float carrier.
// 9007199254740993 (2^53+1) parses to the float 9007199254740992, and the
// upper bound 9007199254740995 rounds to 9007199254740996; only exact
// decimal text survives the store's oracle, asserted at both the store and
// the raw SQL level.
func TestDimensionalComponents_LargeIntegerDecimalRoundtrip_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)

	est := dimensionalFrozenComponents(t)[4] // the estimated point-in-range row: quantity AND bounds present
	est.EventID = "evt-2e53"
	est.ComponentID = "comp-2e53"
	wantQuantity := mustDimensionalDecimal(t, "9007199254740993")
	wantLower := mustDimensionalDecimal(t, "9007199254740991")
	wantUpper := mustDimensionalDecimal(t, "9007199254740995")
	est.Quantity = &wantQuantity
	est.Bounds = &dimensions.Bounds{Lower: &wantLower, Upper: &wantUpper}
	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, []dimensions.Component{est}))

	got, total, err := store.ListDimensionalComponents(ctx, orgA, "tenant-frozen",
		DimensionalComponentFilters{EventID: "evt-2e53"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].Quantity)
	require.Equal(t, "9007199254740993", got[0].Quantity.String(),
		"a float64 carrier would read back 9007199254740992")
	require.NotNil(t, got[0].Bounds)
	require.Equal(t, "9007199254740991", got[0].Bounds.Lower.String())
	require.Equal(t, "9007199254740995", got[0].Bounds.Upper.String(),
		"a float64 carrier would read back 9007199254740996")

	// SQL-level carrier oracle, independent of Go reconstruction.
	var storedQuantity, storedLower, storedUpper string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT quantity_text, bounds_lower_text, bounds_upper_text
		 FROM dimensional_components
		 WHERE org_id = $1::uuid AND tenant_id = 'tenant-frozen' AND event_id = 'evt-2e53'`,
		orgA).Scan(&storedQuantity, &storedLower, &storedUpper))
	require.Equal(t, "9007199254740993", storedQuantity)
	require.Equal(t, "9007199254740991", storedLower)
	require.Equal(t, "9007199254740995", storedUpper)
}

// TestDimensionalComponents_TiedTimesStableAcrossPages_Integration:
// regression guard for the non-total page ordering found in review — two
// different events can share event_time and component_id, so the page
// order must tiebreak on event_id (completing the in-scope primary key)
// and OFFSET paging must neither repeat nor skip the tied rows.
func TestDimensionalComponents_TiedTimesStableAcrossPages_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	orgA, _ := dimensionalTestOrgs(t, ctx, pool)

	base := dimensionalFrozenComponents(t)[:1]
	a, b := base[0], base[0]
	a.EventID, b.EventID = "evt-tied-a", "evt-tied-b"
	a.ComponentID, b.ComponentID = "comp-tied", "comp-tied"
	a.RequestID, b.RequestID = "req-tied-a", "req-tied-b"
	// Same event_time on both rows and identical component ids: the only
	// remaining total order is the event_id tiebreak.
	require.NoError(t, store.StoreDimensionalComponents(ctx, orgA, []dimensions.Component{a, b}))

	expected := []string{"evt-tied-b", "evt-tied-a"} // string-DESC on the event ids
	require.True(t, expected[0] > expected[1], "the expected order must itself be event_id-descending")

	var err error
	collected := []string{}
	for pageIdx := 0; pageIdx < 4; pageIdx++ {
		var page []dimensions.Component
		var pageTotal int64
		page, pageTotal, err = store.ListDimensionalComponents(ctx, orgA, "tenant-frozen",
			DimensionalComponentFilters{PageFilter: NewPageFilter(pageIdx+1, 1)})
		require.NoError(t, err)
		require.EqualValues(t, 2, pageTotal, "the tied pair is the whole tenant scope")
		if pageIdx < 2 {
			require.Len(t, page, 1)
			collected = append(collected, page[0].EventID)
			continue
		}
		require.Empty(t, page, "pages beyond the result set stay empty")
	}
	require.Equal(t, expected, collected,
		"tied rows must page in the deterministic event_id-descending order")
	require.NotEqual(t, collected[0], collected[1], "no row may repeat across page boundaries")
}
