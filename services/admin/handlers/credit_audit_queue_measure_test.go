package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// N13-P04-T03 measurement harness: credit-audit queue drain behavior, vs the
// CreditAuditDropped alert (increase(credit_audit_drops_total[10m]) > 0,
// for: 1m). The queue is a 128-slot channel with ONE worker
// (auditQueueSize, credit_handlers.go); each entry is a durable
// InsertAuditLogEntry write under a 5s timeout (auditWorker). The alert's
// semantics — any drop is a signal — are only meaningful if drops are a
// DB-slowness symptom, not a volume symptom: this harness measures the drain
// floor that underwrites that reading.
//
// Convention: pkg/cache/policy_measure_test.go (AF-11) — env-labeled output,
// stated limitations, NOT part of any automated gate. Run it explicitly:
//
//	YABANIN_N13P04T03_LABEL=audit go test ./services/admin/handlers -run '^$' \
//		-bench BenchmarkCreditAuditQueueDrain -benchtime 1x
//
// Stated limitations:
//   - The stub InsertAuditLogEntry measures the enqueue/worker orchestration
//     floor only; the production entry cost is dominated by the PG insert
//     inside the same 5s timeout window. The overflow arithmetic in the
//     summary scales the measured floor linearly, which is exact for a
//     single serial worker.
//   - One worker, one queue: no concurrency variance to sample; the run is
//     deterministic up to scheduler noise.
type slowAuditLogger struct {
	mu      sync.Mutex
	delay   time.Duration
	written int
}

func (s *slowAuditLogger) InsertAuditLogEntry(_ context.Context, _ adminstore.AuditLogEntryRecord) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	s.written++
	s.mu.Unlock()
	return nil
}

func (s *slowAuditLogger) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

type nopCreditLogger struct{}

func (nopCreditLogger) Info(string, ...any)  {}
func (nopCreditLogger) Error(string, ...any) {}

func benchEntry() creditAuditEntry {
	return creditAuditEntry{
		action:   "bench.topup",
		resource: "org-bench",
		details:  "n13-p04-t03 harness",
		before:   []byte(`{"balance_cents":0}`),
		after:    []byte(`{"balance_cents":100}`),
		reason:   "measurement",
	}
}

func BenchmarkCreditAuditQueueDrain(b *testing.B) {
	// Scenario 1 — drain floor: instant stub writer. The 128-slot queue
	// is paced (batch ≤ queue capacity, wait for full drain between
	// batches) so nothing is dropped and the worker never idles on the
	// critical path; elapsed/N is the sustained per-entry cost of the
	// enqueue→worker→write cycle. Result underwrites: drops at
	// healthy-audit rates are impossible on the CPU path alone.
	stub := &slowAuditLogger{}
	h := &CreditHandlers{log: nopCreditLogger{}}
	h.SetAuditLogger(stub, nil)

	const n1 = 20000
	const batch = 64 // ≤ auditQueueSize; enqueue is non-blocking
	start := time.Now()
	for sent := 0; sent < n1; {
		end := sent + batch
		if end > n1 {
			end = n1
		}
		for i := sent; i < end; i++ {
			h.enqueueCreditAudit(benchEntry())
		}
		sent = end
		deadline := time.Now().Add(30 * time.Second)
		for stub.count() < sent && time.Now().Before(deadline) {
			time.Sleep(100 * time.Microsecond)
		}
		if stub.count() < sent {
			b.Fatalf("floor drain stalled at %d/%d", stub.count(), sent)
		}
	}
	floor := time.Since(start)
	drained := stub.count()
	if drained != n1 {
		b.Fatalf("floor drain incomplete: %d/%d", drained, n1)
	}
	floorPerEntry := floor / time.Duration(n1)
	floorRate := float64(n1) / floor.Seconds()

	// Scenario 2 — saturated drain: 10ms-per-entry stub stands in for a
	// slowed audit DB (production ceiling is the 5s insert timeout; the
	// arithmetic scales linearly on the serial worker). A burst of 256
	// entries (2x the 128-slot buffer) is enqueued non-blocking; drops
	// start once the buffer fills, and the backlog clears at 100/s. The
	// wait detects drain completion by stabilization (only accepted
	// entries ever complete; dropped ones are silently counted).
	stub2 := &slowAuditLogger{delay: 10 * time.Millisecond}
	h2 := &CreditHandlers{log: nopCreditLogger{}}
	h2.SetAuditLogger(stub2, nil)

	const burst = 2 * auditQueueSize
	start2 := time.Now()
	for i := 0; i < burst; i++ {
		h2.enqueueCreditAudit(benchEntry())
	}
	enqueueDone := time.Since(start2)
	accepted := 0
	lastChanged := time.Now()
	for time.Since(lastChanged) < 500*time.Millisecond {
		time.Sleep(10 * time.Millisecond)
		if c := stub2.count(); c != accepted {
			accepted = c
			lastChanged = time.Now()
		}
		if accepted >= burst {
			break
		}
	}
	clear := time.Since(start2)
	dropped2 := burst - accepted

	// Overflow arithmetic for the real ceiling (documented, not measured —
	// no PG tonight): at the 5s insert timeout the serial worker drains
	// 0.2 entries/s; the 128-slot buffer then holds ~640s = 10.7 min of
	// backlog, so drop bursts persist inside the alert's 10m window and
	// CreditAuditDropped fires while the audit DB is degraded — exactly the
	// intended semantics.
	timeoutDrainRate := 1.0 / 5.0
	backlogSeconds := float64(auditQueueSize) / timeoutDrainRate

	summary := fmt.Sprintf(
		"credit-audit queue drain (n1=%d, burst=%d @10ms/entry):\n"+
			"  floor: per-entry=%s sustained=%.0f entries/s\n"+
			"  saturated: enqueue-of-%d took=%s accepted=%d dropped=%d backlog-clear=%s\n"+
			"  arithmetic @5s-timeout ceiling: drain=%.1f/s full-buffer-backlog=%.0fs (%.1f min) vs alert window 10m\n",
		n1, burst,
		floorPerEntry, floorRate,
		burst, enqueueDone, accepted, dropped2, clear,
		timeoutDrainRate, backlogSeconds, backlogSeconds/60,
	)
	b.ReportMetric(float64(floorPerEntry.Microseconds()), "floor-µs/entry")
	b.ReportMetric(floorRate, "floor-entries/s")
	writeMeasureLog(b, "credit-audit-drain", summary)
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
