package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// N13-P04-T03 measurement harness: cache write-queue drain behavior, vs the
// CacheWriteDrops alert (increase(cache_write_queue_drops_total[10m]) > 0,
// for: 5m). The writer is a 4-worker pool over a 256-slot channel
// (writerWorkers/writerQueueSize, writer.go:18-19); Submit is non-blocking
// and a rejection lands in the very counter the alert wraps.
//
// The drain floor measured here is the per-job orchestration cost
// (normalize + hash + seal + outcome accounting) with a nil pool and nil
// embedder: every job resolves through the full process() path to a failed
// outcome (fixture precedent: writer_test.go passes nil pool/embedder and
// drains without panic). Production per-job cost is dominated by the
// embedder call and the pgvector insert inside the 30s write deadline —
// those legs are NOT measurable tonight without live PG/embedder, and the
// sustained no-drop arrival rate in production is (4 workers) / (real
// per-job latency), not the floor below. The alert's 10m window exists
// precisely because that real latency — not the floor — is what saturation
// depends on.
//
// Convention: pkg/cache/policy_measure_test.go (AF-11) — env-labeled output,
// stated limitations, NOT part of any automated gate. Run it explicitly:
//
//	YABANIN_N13P04T03_LABEL=writer go test ./pkg/cache -run '^$' \
//		-bench BenchmarkCacheWriterQueueDrain -benchtime 1x
func BenchmarkCacheWriterQueueDrain(b *testing.B) {
	w := NewWriter(context.Background(), nil, nil, nil)
	defer w.Stop()

	const total = 4096
	job := writerJob{
		orgID:      "org-bench",
		modelTier:  "tier-bench",
		modelVer:   "v1",
		genParams:  `{"temperature":0}`,
		upstream:   "bench-endpoint",
		promptJSON: json.RawMessage(`{"messages":[{"role":"user","content":"bench"}]}`),
		response:   json.RawMessage(`{"ok":true}`),
		tokensIn:   100,
		tokensOut:  50,
	}

	fullEncounters := 0
	start := time.Now()
	submitted := 0
	for submitted < total {
		if w.Submit(job) {
			submitted++
			continue
		}
		fullEncounters++
		runtime.Gosched()
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		wr, f, sk := drainOutcomes(w)
		if wr+f+sk >= total || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	elapsed := time.Since(start)
	_, rejected, _ := w.Stats() // (queued, dropped, written); queued==total by loop invariant
	failed, skipped := w.OutcomeStats()

	drainRate := float64(total) / elapsed.Seconds()
	perJob := elapsed / time.Duration(total)
	perWorkerRate := drainRate / writerWorkers

	summary := fmt.Sprintf(
		"cache writer drain (total=%d, queue=%d, workers=%d):\n"+
			"  sustained=%.0f jobs/s, per-job=%s, per-worker=%.0f jobs/s (orchestration floor)\n"+
			"  outcomes: failed(nil-pool-store-leg)=%d skipped=%d rejected(queue-full)=%d; producer hit full queue %d times\n"+
			"  production saturation needs per-job embed+PG latency: alert window 10m covers sustained overload at any realistic latency\n",
		total, writerQueueSize, writerWorkers,
		drainRate, perJob, perWorkerRate,
		failed, skipped, rejected, fullEncounters,
	)
	b.ReportMetric(float64(perJob.Microseconds()), "µs/job")
	b.ReportMetric(drainRate, "jobs/s")
	writeMeasureLog(b, "cache-writer-drain", summary)
}

// drainOutcomes reads the three outcome counters atomically enough for the
// drain-wait loop (each counter is an atomic; the sum may transiently
// over/undercount by one in-flight job, which the loop tolerates).
func drainOutcomes(w *Writer) (written, failed, skipped int64) {
	_, _, written = w.Stats()
	failed, skipped = w.OutcomeStats()
	return written, failed, skipped
}

// writeMeasureLog mirrors the pkg/budget harness helper (same env vars,
// same default output dir); test helpers cannot be shared across packages.
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
