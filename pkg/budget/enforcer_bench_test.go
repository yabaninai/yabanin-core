package budget

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// benchSnapshotDB serves one snapshot shape per query (no lock needed: the
// row is immutable for the benchmark's lifetime).
type benchSnapshotDB struct {
	row pgx.Row
}

func (d *benchSnapshotDB) QueryRow(_ context.Context, _ string, _ ...interface{}) pgx.Row {
	return d.row
}

func (d *benchSnapshotDB) Exec(_ context.Context, _ string, _ ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("OK"), nil
}

func BenchmarkCheckBudget_NoBudget(b *testing.B) {
	e := NewEnforcer(&benchSnapshotDB{row: &mockRow{err: pgx.ErrNoRows}}, newBudgetTestLogger())
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.CheckBudget(ctx, "team-123")
	}
}

func BenchmarkCheckBudget_WithinLimit(b *testing.B) {
	e := NewEnforcer(&benchSnapshotDB{row: &mockRow{data: [][]interface{}{{100.0, true, int64(50_000_000)}}}}, newBudgetTestLogger())
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.CheckBudget(ctx, "team-123")
	}
}

func BenchmarkCheckBudget_EmptyTeamID(b *testing.B) {
	e := NewEnforcer(nil, newBudgetTestLogger())
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.CheckBudget(ctx, "")
	}
}
