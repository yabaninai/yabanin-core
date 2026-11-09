package budget

import (
	"context"
	"testing"
)

func BenchmarkCheckBudget_NoBudget(b *testing.B) {
	e := &Enforcer{
		cache: make(map[string]*teamBudget),
		ttl:   60000000000, // 1 minute
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.CheckBudget(ctx, "team-123")
	}
}

func BenchmarkCheckBudget_EmptyTeamID(b *testing.B) {
	e := &Enforcer{}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.CheckBudget(ctx, "")
	}
}
