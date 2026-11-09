package cache

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mixed-org measurement harness for AF-11 (docs/plans/AUDIT_FIX_PLAN_2026-10-02.md#af-11).
//
// One PolicyCache serves three traffic classes, matching the production
// topology (a single shared policy cache instance):
//   - warm orgs: frequently-hit entries, mostly served from cache,
//   - churn orgs: entries expire every ttl, forcing periodic cold reloads,
//   - one outage org: its loader hangs outageLatency then fails (DB outage),
//     so cache writes for it never succeed.
//
// Every op gets its own opTimeout context. The harness reports per-class
// p50/p95/p99, loader invocations (DB calls), loader-observed cancellations
// and ops that exceeded their deadline budget, then writes a summary plus raw
// per-op records to
// $YABANIN_AF11_OUT/mixed-org-$YABANIN_AF11_LABEL.log
// (default artifacts/agent-lanes/af11).
//
// Run it explicitly, e.g.:
//
//	YABANIN_AF11_LABEL=baseline go test ./pkg/cache -run '^$' \
//		-bench BenchmarkPolicyCacheMixedOrgLoad -benchtime 1x
//
// The identical harness ran against the pre-fix and post-fix code; results
// are compared in the AF-11 work record. In-process loader mocks cannot
// reproduce a real DB pool wait; that limitation is stated in the work
// record. The benchmark is not part of any automated gate: a fixed 4s window
// per invocation exceeds the default benchmark target, so the framework stops
// after the first invocation.
func BenchmarkPolicyCacheMixedOrgLoad(b *testing.B) {
	const (
		workers       = 16
		duration      = 4 * time.Second
		churnOrgs     = 40
		warmOrgs      = 8
		ttl           = 60 * time.Millisecond
		normalLoad    = 2 * time.Millisecond
		outageLatency = 40 * time.Millisecond
		opTimeout     = 25 * time.Millisecond
		outageOrg     = "org-outage"
	)

	outDir := os.Getenv("YABANIN_AF11_OUT")
	if outDir == "" {
		outDir = filepath.Join("..", "..", "artifacts", "agent-lanes", "af11")
	}
	label := os.Getenv("YABANIN_AF11_LABEL")
	if label == "" {
		label = "run"
	}

	var (
		loaderCalls    atomic.Int64
		outageCalls    atomic.Int64
		loaderCanceled atomic.Int64
	)
	errOutage := errors.New("db outage")
	loader := func(ctx context.Context, org string) (*OrgPolicy, error) {
		loaderCalls.Add(1)
		load := normalLoad
		if org == outageOrg {
			outageCalls.Add(1)
			load = outageLatency
		}
		timer := time.NewTimer(load)
		defer timer.Stop()
		select {
		case <-timer.C:
			if org == outageOrg {
				return nil, errOutage
			}
			return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
		case <-ctx.Done():
			loaderCanceled.Add(1)
			return nil, ctx.Err()
		}
	}

	pc := NewPolicyCache(ttl)

	type record struct {
		class    string
		latency  time.Duration
		exceeded bool
	}

	perWorker := make([][]record, workers)
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			//nolint:gosec // load generation for a measurement workload, not security-sensitive
			rng := rand.New(rand.NewSource(20261002 + int64(w)))
			recs := make([]record, 0, 4096)
			<-startBarrier
			for start := time.Now(); time.Since(start) < duration; {
				org, class := outageOrg, "outage"
				switch roll := rng.Intn(100); {
				case roll >= 58:
					org, class = fmt.Sprintf("org-warm-%d", rng.Intn(warmOrgs)), "warm"
				case roll >= 8:
					org, class = fmt.Sprintf("org-churn-%d", rng.Intn(churnOrgs)), "churn"
				}
				opStart := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
				pc.Get(ctx, org, loader)
				cancel()
				lat := time.Since(opStart)
				recs = append(recs, record{class: class, latency: lat, exceeded: lat > opTimeout})
			}
			perWorker[w] = recs
		}(w)
	}
	close(startBarrier)
	wg.Wait()

	var all []record
	for _, recs := range perWorker {
		all = append(all, recs...)
	}
	byClass := func(class string) []time.Duration {
		var out []time.Duration
		for _, r := range all {
			if class == "" || r.class == class {
				out = append(out, r.latency)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	percentile := func(sorted []time.Duration, p float64) time.Duration {
		if len(sorted) == 0 {
			return 0
		}
		idx := int(float64(len(sorted)-1) * p)
		return sorted[idx]
	}
	exceeded := 0
	for _, r := range all {
		if r.exceeded {
			exceeded++
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# AF-11 mixed-org measurement label=%s\n", label)
	fmt.Fprintf(&sb, "# workers=%d duration=%s ttl=%s normalLoad=%s outageLatency=%s opTimeout=%s churnOrgs=%d warmOrgs=%d\n",
		workers, duration, ttl, normalLoad, outageLatency, opTimeout, churnOrgs, warmOrgs)
	fmt.Fprintf(&sb, "ops_total=%d\n", len(all))
	for _, class := range []string{"warm", "churn", "outage", ""} {
		name := class
		if name == "" {
			name = "all"
		}
		s := byClass(class)
		if len(s) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%s_ops=%d %s_p50=%s %s_p95=%s %s_p99=%s %s_max=%s\n",
			name, len(s),
			name, percentile(s, 0.50).Round(time.Microsecond),
			name, percentile(s, 0.95).Round(time.Microsecond),
			name, percentile(s, 0.99).Round(time.Microsecond),
			name, s[len(s)-1].Round(time.Microsecond))
	}
	fmt.Fprintf(&sb, "db_loader_calls=%d db_outage_calls=%d loader_cancellations=%d ops_over_deadline=%d\n",
		loaderCalls.Load(), outageCalls.Load(), loaderCanceled.Load(), exceeded)

	//nolint:gosec // G703: outDir is an operator-provided measurement artifact dir, local runs only
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		b.Fatalf("create output dir: %v", err)
	}
	outPath := filepath.Join(outDir, "mixed-org-"+label+".log")
	//nolint:gosec // artifact path comes from dedicated test env vars, measurement output only
	f, err := os.Create(outPath)
	if err != nil {
		b.Fatalf("create output file: %v", err)
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		b.Fatalf("write summary: %v", err)
	}
	for _, r := range all {
		if _, err := fmt.Fprintf(f, "%s,%s,%s\n", r.class, strconv.FormatInt(r.latency.Microseconds(), 10), strconv.FormatBool(r.exceeded)); err != nil {
			b.Fatalf("write record: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close output file: %v", err)
	}
	b.Log("\n" + sb.String())
}
