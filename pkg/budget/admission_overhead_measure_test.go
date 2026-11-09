package budget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// N13-P04-T03 measurement harness: synchronous admission overhead on the
// enforce happy path, vs the D17 shadow-exit gate (p95 ≤ 5ms, ADR-0001 §7.3)
// that alert BudgetAdmissionOverheadP95High wraps. The value the gate reads
// is budget_admission_overhead_seconds, observed at admission.go:701 around
// exactly this span (estimateBounds + exhaustion pre-check, §7.2), so the
// measurement is like-for-like with what production observes.
//
// Convention: pkg/cache/policy_measure_test.go (AF-11) — env-labeled output
// file, one fixed-size invocation, stated limitations, NOT part of any
// automated gate. Run it explicitly:
//
//	YABANIN_N13P04T03_LABEL=admission go test ./pkg/budget -run '^$' \
//		-bench BenchmarkAdmissionPlanEnforceOverhead -benchtime 1x
//
// Stated limitations:
//   - CPU-only leg. The PG legs of the layer (ProbeFreeCapacity on a cold
//     probe cache, Reserve grant/escrow roundtrips) are excluded: the probe
//     cache is pre-warmed and no Reserve call is made. The 5ms gate is
//     defined on THIS histogram's span (admission.go:698), so this exclusion
//     is exactly what the gate measures; PG-side latency of the grant leg is
//     watched separately by budget_grant_duration_seconds.
//   - Org settings, probe cache and clock are fixed/warm: this is the
//     steady-state request path, not cold-start.
//   - Prices are an authored synthetic operator fixture, independent of any
//     shipped catalog or review date; the resale leg runs with a nil pool, which
//     yields the zero-markup base quote (markup.go:204 skips the DB when the
//     pool is nil).
func BenchmarkAdmissionPlanEnforceOverhead(b *testing.B) {
	pricer, err := pricing.NewFilePricer(pricing.PriceFile{
		Source: "authored synthetic admission benchmark", Date: "2026-11-09",
		Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{{Provider: "fixture", Model: "admission-model", Input: 2.3, Output: 9.1}},
	}, "synthetic-admission-benchmark")
	if err != nil {
		b.Fatalf("load synthetic operator pricer: %v", err)
	}
	rates := ScopedRateSource{
		Base:   BaseRateSource{Pricer: pricer},
		Resale: ResaleRateSource{Markup: pricing.NewMarkupPricer(nil, pricer, nil)},
	}

	fixed := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	loader := func(_ context.Context, _ string) (OrgSettings, error) {
		return OrgSettings{Mode: ModeEnforce, DefaultOutCapTokens: 4096}, nil
	}
	adm := NewAdmission(nil, rates, nil, "bench-n13p04t03", ModeEnforce, loader, AdmissionConfig{})
	adm.SetClock(func() time.Time { return fixed })

	// Pre-warm the exhaustion pre-check probe cache for every scope the
	// request below generates (wallet/team-month/agent-day/session keys are
	// deterministic in estimateBounds:604-655). Free capacity is far above
	// any estimated bound, so the bench exercises the admit path, never a
	// fast-path refusal.
	const free = money.MicroUSD(1_000_000_000) // $1000.00
	adm.probes[ledgerKey{scope: ScopeWallet, key: "org-bench"}] =
		probeCacheEntry{free: free, until: fixed.Add(time.Hour)}
	adm.probes[ledgerKey{scope: ScopeTeamMonth, key: "team-bench", period: "2026-11"}] =
		probeCacheEntry{free: free, until: fixed.Add(time.Hour)}
	adm.probes[ledgerKey{scope: ScopeAgentDay, key: "agent-bench", period: "2026-11-04"}] =
		probeCacheEntry{free: free, until: fixed.Add(time.Hour)}
	adm.probes[ledgerKey{scope: ScopeSession, key: "sess-bench"}] =
		probeCacheEntry{free: free, until: fixed.Add(time.Hour)}

	req := Request{
		OrgID:        "org-bench",
		TeamID:       "team-bench",
		AgentID:      "agent-bench",
		SessionKeyID: "sess-bench",
		Chain:        []ChainHop{{Provider: "fixture", Model: "admission-model"}},
		InputBytes:   4096,
		MaxTokens:    int64Ptr(1024),
	}

	// Warmup + sanity: one Plan through the real entry point must succeed
	// (cached org settings, all probes hit, model priced).
	ctx := context.Background()
	plan, err := adm.Plan(ctx, req)
	if err != nil {
		b.Fatalf("warmup Plan failed: %v", err)
	}
	if plan.Mode != ModeEnforce || len(plan.Scopes) != 4 {
		b.Fatalf("unexpected plan: mode=%v scopes=%d", plan.Mode, len(plan.Scopes))
	}

	const ops = 20000
	samples := make([]time.Duration, 0, ops)
	var maxSample time.Duration
	b.ResetTimer()
	for i := 0; i < ops; i++ {
		start := time.Now()
		if _, err := adm.Plan(ctx, req); err != nil {
			b.Fatalf("Plan %d: %v", i, err)
		}
		d := time.Since(start)
		samples = append(samples, d)
		if d > maxSample {
			maxSample = d
		}
	}
	b.StopTimer()

	pct := func(p float64) time.Duration {
		s := append([]time.Duration(nil), samples...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[int(float64(len(s)-1)*p)]
	}
	var total time.Duration
	for _, s := range samples {
		total += s
	}

	summary := fmt.Sprintf(
		"admission Plan enforce overhead (n=%d): mean=%s p50=%s p95=%s p99=%s max=%s | D17 gate p95<=5ms -> headroom=%.0fx\n",
		ops, total/time.Duration(ops), pct(0.50), pct(0.95), pct(0.99), maxSample,
		float64(5*time.Millisecond)/float64(pct(0.95)),
	)
	b.ReportMetric(float64(total.Microseconds())/float64(ops), "µs/op")
	b.ReportMetric(float64(pct(0.95).Microseconds()), "p95-µs")
	writeMeasureLog(b, "admission-overhead", summary)
}

func int64Ptr(v int64) *int64 { return &v }

// writeMeasureLog writes the harness summary to
// $YABANIN_N13P04T03_OUT/<name>-$YABANIN_N13P04T03_LABEL.log (default
// <repo-root>/artifacts/agent-lanes/n13p04t03), mirroring
// pkg/cache/policy_measure_test.go. go test executes in the package
// directory, so the default resolves the repo root by walking up to go.mod.
func writeMeasureLog(b *testing.B, name, summary string) {
	b.Helper()
	dir := os.Getenv("YABANIN_N13P04T03_OUT")
	if dir == "" {
		dir = filepath.Join(repoRoot(b), "artifacts", "agent-lanes", "n13p04t03")
	}
	label := os.Getenv("YABANIN_N13P04T03_LABEL")
	if label == "" {
		label = "baseline"
	}
	//nolint:gosec // G703: dir is an operator-provided measurement artifact dir, local runs only
	if err := os.MkdirAll(dir, 0o750); err != nil {
		b.Logf("measure log dir: %v", err)
		return
	}
	path := filepath.Join(dir, name+"-"+label+".log")
	//nolint:gosec // G703: artifact path comes from dedicated test env vars, measurement output only
	if err := os.WriteFile(path, []byte(summary), 0o600); err != nil {
		b.Logf("measure log write: %v", err)
		return
	}
	b.Logf("measure log: %s", path)
}

// repoRoot walks up from the working directory to the directory containing
// go.mod (go test cwd is the package dir; artifacts live at the repo root).
func repoRoot(b *testing.B) string {
	b.Helper()
	wd, err := os.Getwd()
	if err != nil {
		b.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			b.Fatalf("go.mod not found above %s", wd)
		}
		dir = parent
	}
}
