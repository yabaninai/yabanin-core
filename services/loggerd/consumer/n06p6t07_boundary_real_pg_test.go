package consumer

// N06-P06-T07 boundary corpus, REAL stand (testcontainers Postgres, the
// established stand of this package, Docker required outside -short): the
// zoned bucketing edges that only live SQL can prove — rows seeded at
// EXACT boundary instants (±1µs around org-local midnights, including the
// 23h spring-forward and 25h fall-back days) and read back through the
// PgxSpendReconReader windows. Seeding follows the accepted T06 style
// (explicit created_at instants, org-scoped rows, cleanup); the tests are
// serialized on creditsIntegrationMu like every live test here.
//
// Distinct from T06: T06 ran one joint operator journey with mid-day
// timestamps; this corpus probes the window boundaries themselves, and the
// zone-change divergence (one physical row classified in and out of the
// period by the reporting timezone alone).

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	// Distinct org UUIDs: the testcontainers Postgres is a shared, migrated
	// container (one cached pool per region), so every seed is org-scoped.
	n06p6t07BoundaryOrgID = "5c8f3e4a-1d6b-4a9c-8e2f-7b4d9c0a1e53"
	n06p6t07ZoneOrgID     = "6d9a4f5b-2e7c-4b0d-9f3a-8c5e0d1b2f64"
)

// n06p6t07SeedOrg creates one NY-reporting org and registers cleanup of
// every fact table this corpus touches.
func n06p6t07SeedOrg(t *testing.T, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, timezone)
		VALUES ($1, 'n06p6-t07 boundary org', 'n06p6-t07-' || $2, $3)
		ON CONFLICT (id) DO NOTHING`,
		orgID, orgID[:8], n06p6t07NY)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	})
}

// n06p6t07SeedUsage inserts one priced usage row with an exact created_at
// instant and a distinct micro-USD cost (0.00000N) so day maps can be
// asserted exactly.
func n06p6t07SeedUsage(t *testing.T, pool *pgxpool.Pool, orgID, reqID, createdAt string, micro int64) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO request_logs (org_id, request_id, model_requested, model_used, status_code,
			duration_ms, cost_in_usd, cost_status, created_at, updated_at)
		VALUES ($1, $2, 'gpt-x', 'gpt-x', 200, 5, $3::numeric, 'priced', $4::timestamptz, $4::timestamptz)`,
		orgID, reqID, fmtMicroUSD(micro), createdAt)
	require.NoError(t, err)
}

// fmtMicroUSD renders micro-USD as the exact decimal literal (numeric(12,6)).
func fmtMicroUSD(micro int64) string {
	sign := ""
	if micro < 0 {
		sign, micro = "-", -micro
	}
	return sign + fmtInt(micro/1_000_000) + "." + pad6(micro%1_000_000)
}

func fmtInt(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func pad6(v int64) string {
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[:])
}

// TestN06P6T07RealPG_ZonedBoundaryInstants — REAL stand: rows seeded at
// ±1µs around org-local midnights land on exactly one side of every
// window, including the DST days. The unit pins of
// TestN06P6T07ZonedDayWindowLattice are confirmed by the live reader here.
func TestN06P6T07RealPG_ZonedBoundaryInstants(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	n06p6t07SeedOrg(t, pool, n06p6t07BoundaryOrgID)

	// September 2026 is EDT all month: local midnights are 04:00Z.
	// September window: [2026-09-01T04:00Z, 2026-10-01T04:00Z).
	for _, s := range []struct {
		id, at string
		micro  int64
	}{
		{"n06p6t07-s1", "2026-09-01T03:59:59.999999Z", 1}, // NY 08-31 23:59:59.999999 → before From
		{"n06p6t07-s2", "2026-09-01T04:00:00.000000Z", 2}, // NY 09-01 00:00:00.000000 → first in-window µ
		{"n06p6t07-s3", "2026-10-01T03:59:59.999999Z", 3}, // NY 09-30 23:59:59.999999 → last in-window µ
		{"n06p6t07-s4", "2026-10-01T04:00:00.000000Z", 4}, // NY 10-01 00:00:00.000000 → at/after To
	} {
		n06p6t07SeedUsage(t, pool, n06p6t07BoundaryOrgID, s.id, s.at, s.micro)
	}

	// Spring-forward day 2026-03-08 is 23h in NY (midnight 05:00Z).
	for _, s := range []struct {
		id, at string
		micro  int64
	}{
		{"n06p6t07-s5", "2026-03-08T04:59:59.999999Z", 5}, // NY 03-07 23:59:59.999999 → day 03-07
		{"n06p6t07-s6", "2026-03-08T05:00:00.000000Z", 6}, // first µ of the 23h day 03-08
		{"n06p6t07-s7", "2026-03-09T03:59:59.999999Z", 7}, // last µ of the 23h day 03-08
		{"n06p6t07-s8", "2026-03-09T04:00:00.000000Z", 8}, // first µ of the 24h day 03-09
	} {
		n06p6t07SeedUsage(t, pool, n06p6t07BoundaryOrgID, s.id, s.at, s.micro)
	}

	// Fall-back day 2026-11-01 is 25h in NY (midnight 04:00Z).
	for _, s := range []struct {
		id, at string
		micro  int64
	}{
		{"n06p6t07-s9", "2026-11-01T03:59:59.999999Z", 9},   // NY 10-31 23:59:59.999999 → excluded
		{"n06p6t07-s10", "2026-11-01T04:00:00.000000Z", 10}, // first µ of the 25h day 11-01
		{"n06p6t07-s11", "2026-11-02T04:59:59.999999Z", 11}, // last µ of the 25h day 11-01
		{"n06p6t07-s12", "2026-11-02T05:00:00.000000Z", 12}, // first µ of day 11-02
	} {
		n06p6t07SeedUsage(t, pool, n06p6t07BoundaryOrgID, s.id, s.at, s.micro)
	}

	reader := NewPgxSpendReconReader(pool)
	type windowCase struct {
		name      string
		from, to  time.Time
		want      []SpendReconUsageDay
		wantTotal int64
	}
	cases := []windowCase{
		{
			name:      "September EDT midnights",
			from:      time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC),
			to:        time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC),
			want:      []SpendReconUsageDay{{Day: "2026-09-01", ConfirmedMicro: 2, Requests: 1}, {Day: "2026-09-30", ConfirmedMicro: 3, Requests: 1}},
			wantTotal: 5,
		},
		{
			name:      "March spring-forward day (23h)",
			from:      time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC),
			to:        time.Date(2026, 4, 1, 4, 0, 0, 0, time.UTC),
			want:      []SpendReconUsageDay{{Day: "2026-03-07", ConfirmedMicro: 5, Requests: 1}, {Day: "2026-03-08", ConfirmedMicro: 13, Requests: 2}, {Day: "2026-03-09", ConfirmedMicro: 8, Requests: 1}},
			wantTotal: 26,
		},
		{
			name:      "November fall-back day (25h)",
			from:      time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC),
			to:        time.Date(2026, 12, 1, 5, 0, 0, 0, time.UTC),
			want:      []SpendReconUsageDay{{Day: "2026-11-01", ConfirmedMicro: 21, Requests: 2}, {Day: "2026-11-02", ConfirmedMicro: 12, Requests: 1}},
			wantTotal: 33,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The hand-baked window equals the period helper's window — the
			// unit lattice and the live reader share one definition.
			label := "2026-09"
			if tc.from.Month() == time.March {
				label = "2026-03"
			} else if tc.from.Month() == time.November {
				label = "2026-11"
			}
			period, err := budget.MonthReportPeriod(label, n06p6t07NY)
			require.NoError(t, err)
			require.True(t, period.From.Equal(tc.from) && period.To.Equal(tc.to),
				"period helper %s..%s != corpus window %s..%s", period.From, period.To, tc.from, tc.to)

			total, err := reader.UsageTotal(ctx, n06p6t07BoundaryOrgID, tc.from, tc.to)
			require.NoError(t, err)
			require.Equal(t, tc.wantTotal, total)

			days, err := reader.UsageByDay(ctx, n06p6t07BoundaryOrgID, tc.from, tc.to, n06p6t07NY)
			require.NoError(t, err)
			require.Equal(t, tc.want, days)
		})
	}

	// Ledger boundary: the exact From µ lands on the first day, the µ just
	// below To on the last day (wallet amounts are negative).
	_, err := pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type,
			request_id, amount_micro_usd, created_at)
		VALUES ($1, -1, 999999, 'usage', 'n06p6t07-l1', -10000, '2026-09-01T04:00:00.000000Z'::timestamptz),
		       ($1, -2, 999997, 'usage', 'n06p6t07-l2', -20000, '2026-10-01T03:59:59.999999Z'::timestamptz)`,
		n06p6t07BoundaryOrgID)
	require.NoError(t, err)
	ledger, err := reader.LedgerByDay(ctx, n06p6t07BoundaryOrgID,
		time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC), n06p6t07NY)
	require.NoError(t, err)
	require.Equal(t, []SpendReconLedgerDay{
		{Day: "2026-09-01", WalletMicro: -10_000, WalletCentsAppliedMicro: -10_000, WalletTxns: 1},
		{Day: "2026-09-30", WalletMicro: -20_000, WalletCentsAppliedMicro: -20_000, WalletTxns: 1},
	}, ledger)

	// Settlement boundary on the spring-forward day: the first µ of the 23h
	// day buckets to 03-08, the first µ of the next day to 03-09.
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, status,
			amount_micro_usd, created_at, updated_at)
		VALUES ($1, 'n06p6t07-j1', 'resale_deduction', 'pending', 3000, '2026-03-08T05:00:00.000000Z'::timestamptz, '2026-03-08T05:00:00.000000Z'::timestamptz),
		       ($1, 'n06p6t07-j2', 'resale_deduction', 'pending', 4000, '2026-03-09T04:00:00.000000Z'::timestamptz, '2026-03-09T04:00:00.000000Z'::timestamptz)`,
		n06p6t07BoundaryOrgID)
	require.NoError(t, err)
	settlements, err := reader.SettlementsByDay(ctx, n06p6t07BoundaryOrgID,
		time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 4, 0, 0, 0, time.UTC), n06p6t07NY)
	require.NoError(t, err)
	require.Equal(t, []SpendReconSettlementDay{
		{Day: "2026-03-08", EstimatedMicro: 3_000, EstimatedRequests: 1},
		{Day: "2026-03-09", EstimatedMicro: 4_000, EstimatedRequests: 1},
	}, settlements)
}

// TestN06P6T07RealPG_ZoneChangeDivergence — REAL stand: ONE physical usage
// row at 2026-04-01T02:00Z (= NY 2026-03-31 22:00) is in-period under NY
// March reporting, absent under UTC March reporting, and bucketed to a
// DIFFERENT day under UTC April reporting. The reporting timezone alone
// moves a row in and out of the billable period; a report exported before
// the zone change keeps its bytes afterwards.
func TestN06P6T07RealPG_ZoneChangeDivergence(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	n06p6t07SeedOrg(t, pool, n06p6t07ZoneOrgID)
	n06p6t07SeedUsage(t, pool, n06p6t07ZoneOrgID, "n06p6t07-z1", "2026-04-01T02:00:00.000000Z", 7)

	reader := NewPgxSpendReconReader(pool)

	// 1) NY March window: the row is NY 03-31 22:00 → in-period day 03-31.
	nym, err := budget.MonthReportPeriod("2026-03", n06p6t07NY)
	require.NoError(t, err)
	days, err := reader.UsageByDay(ctx, n06p6t07ZoneOrgID, nym.From, nym.To, n06p6t07NY)
	require.NoError(t, err)
	require.Equal(t, []SpendReconUsageDay{{Day: "2026-03-31", ConfirmedMicro: 7, Requests: 1}}, days)
	total, err := reader.UsageTotal(ctx, n06p6t07ZoneOrgID, nym.From, nym.To)
	require.NoError(t, err)
	require.Equal(t, int64(7), total)

	// 2) UTC March window: the same row is outside (2026-04-01 ≥ To).
	utcMarchFrom := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	utcMarchTo := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	days, err = reader.UsageByDay(ctx, n06p6t07ZoneOrgID, utcMarchFrom, utcMarchTo, "UTC")
	require.NoError(t, err)
	require.Empty(t, days)
	total, err = reader.UsageTotal(ctx, n06p6t07ZoneOrgID, utcMarchFrom, utcMarchTo)
	require.NoError(t, err)
	require.Equal(t, int64(0), total)

	// 3) UTC April window: the same row reappears, bucketed to 2026-04-01.
	utcAprilFrom := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	utcAprilTo := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	days, err = reader.UsageByDay(ctx, n06p6t07ZoneOrgID, utcAprilFrom, utcAprilTo, "UTC")
	require.NoError(t, err)
	require.Equal(t, []SpendReconUsageDay{{Day: "2026-04-01", ConfirmedMicro: 7, Requests: 1}}, days)

	// The NY-March report is exported, then a UTC-April report is computed
	// over the same org; the earlier export's bytes must be untouched and
	// the earlier report must recompute identically (no cross-run state).
	inNY := SpendReconInput{
		OrgID: n06p6t07ZoneOrgID, From: nym.From, To: nym.To, Zone: nyLoc(t),
		UITotalMicro:          7,
		Usage:                 []SpendReconUsageDay{{Day: "2026-03-31", ConfirmedMicro: 7, Requests: 1}},
		Invoice:               []SpendReconInvoiceDay{{Day: "2026-03-31", InvoiceMicro: 7}},
		InvoiceToleranceMicro: 1_000_000,
	}
	repNY := ReconcileSpend(inNY)
	require.Equal(t, SpendReconStatusOK, repNY.Status, "violations: %+v", repNY.Violations)
	var buf bytes.Buffer
	require.NoError(t, repNY.WriteCSV(&buf))
	exported := buf.Bytes()

	inUTC := SpendReconInput{
		OrgID: n06p6t07ZoneOrgID, From: utcAprilFrom, To: utcAprilTo, Zone: time.UTC,
		UITotalMicro:          7,
		Usage:                 []SpendReconUsageDay{{Day: "2026-04-01", ConfirmedMicro: 7, Requests: 1}},
		Invoice:               []SpendReconInvoiceDay{{Day: "2026-04-01", InvoiceMicro: 7}},
		InvoiceToleranceMicro: 1_000_000,
	}
	repUTC := ReconcileSpend(inUTC)
	require.Equal(t, SpendReconStatusOK, repUTC.Status, "violations: %+v", repUTC.Violations)
	require.Equal(t, "2026-04-01", repUTC.Days[0].Day)
	require.Equal(t, "2026-03-31", repNY.Days[0].Day, "one row, two zone-dependent day labels")

	var bufAfter bytes.Buffer
	require.NoError(t, repNY.WriteCSV(&bufAfter))
	require.True(t, bytes.Equal(exported, bufAfter.Bytes()),
		"the zone change must not mutate the earlier report's export")
	require.True(t, reflect.DeepEqual(repNY, ReconcileSpend(inNY)),
		"the earlier report must recompute identically after the other zone's run")
}
