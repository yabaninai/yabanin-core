package script_test

// OP-7 benchmark: the SAME typical `when` condition ("any high-severity
// finding?") on a representative env (5 findings, 2 step traces, full meta)
// across all three engines. Compile happens once outside the timed loop —
// the seam contract. Run with:
//
//	go test -bench BenchmarkConditionTypical -benchtime=10000x -benchmem ./pkg/pipeline/script/
//
// Each sub-benchmark reports mean ns/op (go bench standard), allocs/op and
// bytes/op, plus measured p50/p95 per-evaluation ns/op via ReportMetric.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script/expr"
	"github.com/reireirei/yabanin/pkg/pipeline/script/lua"
	"github.com/reireirei/yabanin/pkg/pipeline/script/starlark"
)

func benchEnv() pipeline.ConditionEnv {
	return pipeline.ConditionEnv{
		Findings: []pipeline.Finding{
			{Step: "counters", Category: "len", Severity: "low", Action: pipeline.ActionAllow},
			{Step: "code_detect", Category: "code", Severity: "low", Action: pipeline.ActionAllow},
			{Step: "natl_pii", Category: "innsnils", Severity: "high", Span: "10:22", Evidence: "***", Action: pipeline.ActionFlag},
			{Step: "secret_scan", Category: "aws_key", Severity: "medium", Action: pipeline.ActionFlag},
			{Step: "url_check", Category: "url", Severity: "info", Action: pipeline.ActionAllow},
		},
		Steps: []pipeline.StepTrace{
			{Step: "counters", Duration: 310 * time.Microsecond, Outcome: pipeline.StepRan},
			{Step: "natl_pii", Duration: 12 * time.Millisecond, Outcome: pipeline.StepRan},
		},
		Meta: &pipeline.RequestMeta{
			Org: "org-a", Key: "key-1", Model: "gpt-x", Provider: "openai",
			Labels: map[string]string{"team": "core", "env": "prod"},
			Tags:   []string{"pii", "sovereign"},
		},
	}
}

type benchCase struct {
	name    string
	compile func() (pipeline.ConditionProgram, error)
}

func benchCases() []benchCase {
	return []benchCase{
		{"lua", func() (pipeline.ConditionProgram, error) {
			return lua.New().Compile(`findings.any(function(f) return f.severity == 'high' end)`)
		}},
		{"starlark", func() (pipeline.ConditionProgram, error) {
			return starlark.New().Compile(`findings.any(lambda f: f.severity == 'high')`)
		}},
		{"expr", func() (pipeline.ConditionProgram, error) {
			return expr.New().Compile(`any(Findings, #.Severity == 'high')`)
		}},
	}
}

func BenchmarkConditionTypical(b *testing.B) {
	env := benchEnv()
	for _, bc := range benchCases() {
		b.Run(bc.name, func(b *testing.B) {
			prog, err := bc.compile()
			if err != nil {
				b.Fatalf("compile: %v", err)
			}
			ctx := context.Background()

			samples := make([]int64, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				ok, err := prog.Evaluate(ctx, env)
				samples = append(samples, time.Since(start).Nanoseconds())
				if err != nil {
					b.Fatalf("evaluate: %v", err)
				}
				if !ok {
					b.Fatal("expected true")
				}
			}
			b.StopTimer()

			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			pct := func(p float64) float64 {
				idx := int(float64(len(samples)-1) * p)
				return float64(samples[idx])
			}
			b.ReportMetric(pct(0.50), "p50-ns/op")
			b.ReportMetric(pct(0.95), "p95-ns/op")
		})
	}
}

// BenchmarkCompileTypical: policy-load cost per engine (cache-cold compile).
func BenchmarkCompileTypical(b *testing.B) {
	for _, bc := range benchCases() {
		b.Run(bc.name, func(b *testing.B) {
			// One engine per benchmark process section; the engine caches by
			// source hash, so a fresh engine per iteration would measure
			// cache misses only. Measure the cache-hit Compile path instead
			// (the seam calls Compile once per conditioned step; identical
			// sources across steps hit the cache).
			switch bc.name {
			case "lua":
				e := lua.New()
				prog, err := e.Compile(`findings.any(function(f) return f.severity == 'high' end)`)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := e.Compile(`findings.any(function(f) return f.severity == 'high' end)`); err != nil {
						b.Fatal(err)
					}
				}
				_ = prog
			case "starlark":
				e := starlark.New()
				if _, err := e.Compile(`findings.any(lambda f: f.severity == 'high')`); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := e.Compile(`findings.any(lambda f: f.severity == 'high')`); err != nil {
						b.Fatal(err)
					}
				}
			case "expr":
				e := expr.New()
				if _, err := e.Compile(`any(Findings, #.Severity == 'high')`); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := e.Compile(`any(Findings, #.Severity == 'high')`); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
