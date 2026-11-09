package evaluator

import (
	"fmt"
	"testing"
)

// RT-06 benchmarks: snapshot evaluation cost at 1/10/100 rules. Fixtures are
// identical across baseline and post-change runs; none of the rules match the
// evaluated request, so every AST in the snapshot is fully evaluated (the
// honest upper bound of the per-request scan).
func rt06BenchEvaluate(b *testing.B, n int) {
	b.Helper()
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = Rule{
			ID:          fmt.Sprintf("r%d", i),
			OrgID:       "org",
			MatchExpr:   fmt.Sprintf(`session_id == "bench-sess-%d"`, i),
			TargetModel: fmt.Sprintf("target-%d", i),
			Priority:    100 - i,
			Enabled:     true,
		}
	}
	snap := NewSnapshot("org", rules)
	ctx := Context{OrgID: "org", SessionID: "other-session", ClientIP: "10.0.0.1", UserAgent: "bench"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = snap.Evaluate(ctx, "requested-model")
	}
}

func BenchmarkRT06_Evaluate_1_Rule(b *testing.B)   { rt06BenchEvaluate(b, 1) }
func BenchmarkRT06_Evaluate_10_Rules(b *testing.B) { rt06BenchEvaluate(b, 10) }
func BenchmarkRT06_Evaluate_100_Rules(b *testing.B) {
	rt06BenchEvaluate(b, 100)
}
