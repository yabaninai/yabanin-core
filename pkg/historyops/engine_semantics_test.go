package historyops

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// fakeClock is a deterministic clock the tests advance manually.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 3, 2, 11, 30, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// scriptedRunner is a Runner over a modeled hot store: applying a batch
// deletes ids from hot and counts each id's effect exactly once (the
// idempotent-per-batch contract of Runner.ExecuteBatch).
type scriptedRunner struct {
	mu      sync.Mutex
	hot     map[string]bool
	applied map[string]int // id → times the EFFECT happened (must end at 1 each)
	exec    map[int]int    // batch index → execution attempts (at-least-once is ok)

	plan      [][]string
	verifyErr error
	planErr   error
	batchErr  map[int]error

	// beforeBatch runs before executing batch idx (crash/cancel hooks).
	beforeBatch func(job *Job, idx int)

	verifyCalls int
	planCalls   int
}

func newScriptedRunner(batches [][]string, ids ...string) *scriptedRunner {
	hot := make(map[string]bool, len(ids))
	for _, id := range ids {
		hot[id] = true
	}
	return &scriptedRunner{
		hot:     hot,
		applied: make(map[string]int),
		exec:    make(map[int]int),
		plan:    batches,
	}
}

func (r *scriptedRunner) VerifySnapshot(_ context.Context, _ *Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyCalls++
	return r.verifyErr
}

func (r *scriptedRunner) Plan(_ context.Context, _ *Job) ([][]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.planCalls++
	if r.planErr != nil {
		return nil, r.planErr
	}
	out := make([][]string, len(r.plan))
	for i, b := range r.plan {
		out[i] = append([]string(nil), b...)
	}
	return out, nil
}

// ExecuteBatch applies idempotently: deleting an already-deleted id is a
// no-op, so re-execution after a crash cannot double-apply an effect.
func (r *scriptedRunner) ExecuteBatch(_ context.Context, job *Job, idx int, ids []string) (FamilyCounts, error) {
	r.mu.Lock()
	if err := r.batchErr[idx]; err != nil {
		r.mu.Unlock()
		return nil, err
	}
	hook := r.beforeBatch
	r.mu.Unlock()
	if hook != nil {
		hook(job, idx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exec[idx]++
	counts := FamilyCounts{}
	for _, id := range ids {
		if r.hot[id] {
			delete(r.hot, id)
			r.applied[id]++
			counts[FamilyRequestLogs]++
		}
	}
	return counts, nil
}

func (r *scriptedRunner) snapshot() (hot []string, applied map[string]int, exec map[int]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.hot {
		hot = append(hot, id)
	}
	out := make(map[string]int, len(r.applied))
	for id, n := range r.applied {
		out[id] = n
	}
	execOut := make(map[int]int, len(r.exec))
	for i, n := range r.exec {
		execOut[i] = n
	}
	return hot, out, execOut
}

// testHarness wires engine + store + journal + clock for one scenario.
type testHarness struct {
	clock   *fakeClock
	store   *MemoryJobStore
	journal *MemoryJournaler
	runner  *scriptedRunner
	engine  *Engine
	stamp   SchemaStamp
}

const testOrg = "org-alpha"

func newTestHarness(t *testing.T, batches [][]string, ids ...string) *testHarness {
	t.Helper()
	clock := newFakeClock()
	store := NewMemoryJobStore(clock.Now)
	journal := &MemoryJournaler{}
	runner := newScriptedRunner(batches, ids...)
	stamp := SchemaStamp{MigrationHead: 16, FamiliesSchemaVersion: FamiliesSchemaVersion}
	engine := NewEngine(store, journal, EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 3,
		Now:         clock.Now,
		Stamp: func(context.Context) (SchemaStamp, error) {
			return stamp, nil
		},
	})
	engine.RegisterRunner(OpArchiveRemoveHot, runner)
	return &testHarness{clock: clock, store: store, journal: journal, runner: runner, engine: engine, stamp: stamp}
}

func adminCaller() Caller {
	return Caller{
		UserID: "u-admin-1",
		Role:   adminstore.RoleOrgAdmin,
		Perms:  map[adminstore.Permission]bool{adminstore.PermRequestsRead: true},
	}
}

func harnessSelection() Selection {
	sel, err := NewSelection(testOrg, "", closedPeriod(), []Family{FamilyRequestLogs},
		SelectionFilters{Model: "glm-5"}, newFakeClock().Now())
	if err != nil {
		panic(err)
	}
	return sel
}

// testDestination is the org-local cold root used by harness enqueues of
// archive operations (inside this org's historyops namespace).
const testDestination = "file:///cold/historyops/" + testOrg + "/2026/03/"

func (h *testHarness) enqueue(t *testing.T, op Operation, key string) *Job {
	t.Helper()
	digest, err := SelectionDigest(op, harnessSelection(), h.stamp)
	require.NoError(t, err)
	job, err := h.engine.Enqueue(context.Background(), EnqueueRequest{
		OrgID:           testOrg,
		Op:              op,
		Selection:       harnessSelection(),
		PresentedDigest: digest,
		IdempotencyKey:  key,
		Destination:     destinationFor(op),
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)
	return job
}

// destinationFor returns a valid destination for archive operations and ""
// otherwise (other operations ignore destinations).
func destinationFor(op Operation) string {
	if op.needsDestination() {
		return testDestination
	}
	return ""
}

// TestWorkerRestartExactlyOnce pins A-R2: crash mid-run, lease expiry,
// resume from checkpoint, exactly-once effect, single completed journal,
// idempotent replay returns the same job.
func TestWorkerRestartExactlyOnce(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4", "r5", "r6"}
	h := newTestHarness(t, [][]string{{"r1", "r2", "r3"}, {"r4", "r5", "r6"}}, ids...)
	ctx := context.Background()

	// Worker A "dies" mid-run: the hook parks worker A before batch 1
	// executes, and it never returns for it — a zombie whose lease will
	// expire. Worker B must pass through untouched, so the park is scoped to
	// worker A. The goroutine joins at the end, after the release.
	parkBatch1 := make(chan struct{})
	h.runner.beforeBatch = func(job *Job, idx int) {
		if idx == 1 && job.WorkerID == "worker-a" {
			<-parkBatch1
		}
	}

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-2026-03")
	done := make(chan error, 1)
	go func() {
		claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
		if err != nil {
			done <- err
			return
		}
		if !claimed {
			done <- errors.New("worker A did not claim the job")
			return
		}
		done <- nil
	}()

	// Worker A runs batch 0 (checkpointed) and parks in batch 1.
	waitFor(t, func() bool {
		stored, err := h.store.JobByID(ctx, testOrg, job.ID)
		require.NoError(t, err)
		return stored.Status == JobProcessing && stored.Checkpoint.NextBatch == 1
	}, "worker A never checkpointed batch 0")

	hot, applied, exec := h.runner.snapshot()
	assert.Equal(t, []string{"r4", "r5", "r6"}, sortedStrings(hot),
		"only batch 0's rows are gone; batch 1 rows stay untouched")
	assert.Equal(t, 1, exec[0], "batch 0 executed once")
	assert.Zero(t, exec[1], "batch 1 not started")
	for _, id := range ids[:3] {
		assert.Equal(t, 1, applied[id], "batch 0 effects applied exactly once")
	}
	assert.EqualValues(t, 3, mustJob(t, ctx, h, job.ID).Confirmed.Total())

	// Worker A dies without finishing. Lease expires; recovery returns the
	// job to pending; worker B claims it and resumes from the checkpoint.
	h.clock.Advance(31 * time.Second)
	recovered, err := h.store.RecoverExpiredLeases(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, recovered)

	claimedB, err := h.engine.ExecuteNext(ctx, "worker-b")
	require.NoError(t, err)
	require.True(t, claimedB)

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobCompleted, stored.Status)
	assert.EqualValues(t, 6, stored.Confirmed.Total(), "all rows accounted exactly once")

	// Release the zombie worker A and join it; its late checkpoint attempt
	// must fail on the lost lease without corrupting the terminal state.
	close(parkBatch1)
	require.NoError(t, <-done)

	hot, applied, exec = h.runner.snapshot()
	assert.Empty(t, hot)
	for _, id := range ids {
		assert.Equal(t, 1, applied[id], "exactly-once effect for %s across restart", id)
	}
	assert.Equal(t, 1, exec[0], "batch 0 never re-executed after restart")
	assert.GreaterOrEqual(t, exec[1], 1,
		"batch 1 executed at least once (the zombie's parked attempt + worker B); the effects above stay exactly-once")

	stored = mustJob(t, ctx, h, job.ID)
	assert.Equal(t, JobCompleted, stored.Status, "zombie worker cannot un-complete a job")

	// Exactly one completed journal entry despite the restart.
	assert.Equal(t, 1, h.journal.Count(ActionCompleted))
	assert.Equal(t, 1, h.journal.Count(ActionStarted))

	// Idempotent replay: same key → same job, nothing re-runs.
	digest, err := SelectionDigest(OpArchiveRemoveHot, harnessSelection(), h.stamp)
	require.NoError(t, err)
	replay, err := h.engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           testOrg,
		Op:              OpArchiveRemoveHot,
		Selection:       harnessSelection(),
		PresentedDigest: digest,
		IdempotencyKey:  "cleanup-2026-03",
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)
	assert.Equal(t, job.ID, replay.ID, "repeated idempotency key returns the same job")
	_, applied2, exec2 := h.runner.snapshot()
	assert.Equal(t, applied, applied2, "no second cleanup")
	assert.Equal(t, exec, exec2, "no batch re-ran")
	assert.Equal(t, 1, h.journal.Count(ActionStarted), "no second started entry")
}

// mustJob re-reads a job and fails the test when it is gone.
func mustJob(t *testing.T, ctx context.Context, h *testHarness, jobID string) *Job {
	t.Helper()
	job, err := h.store.JobByID(ctx, testOrg, jobID)
	require.NoError(t, err)
	return job
}

// TestCheckpointRenewalRefusesSecondWorker pins F3 (review 0203): checkpoint
// = progress = renewal. Every batch takes 20s of clock (< LeaseTTL 30s), but
// the job's TOTAL runtime (60s) exceeds the claim's original lease (t0+30s).
// Without renewal, recovery would requeue the job mid-run and a second worker
// could claim it while worker A is between batches — concurrent
// double-execution. With renewal, the batch-0 checkpoint pushes the lease to
// t0+50s: at t0+40 (past the ORIGINAL claim horizon, inside the RENEWED TTL
// window) recovery must refuse to requeue and worker B's acquire must be
// refused; worker B holding no lease is fenced from checkpointing too.
func TestCheckpointRenewalRefusesSecondWorker(t *testing.T) {
	ids := []string{"r1", "r2", "r3"}
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}, {"r3"}}, ids...)
	ctx := context.Background()
	t0 := h.clock.Now()

	attackRan := false
	h.runner.beforeBatch = func(job *Job, idx int) {
		h.clock.Advance(20 * time.Second) // every batch takes 20s < LeaseTTL
		if idx != 1 {
			return
		}
		attackRan = true
		// Batch 1 starts at t0+40 — 10s past the ORIGINAL claim lease
		// (t0+30s), 10s inside the lease RENEWED by batch 0's checkpoint
		// (t0+50s, because batch 0 checkpointed at t0+20).
		stored := mustJob(t, ctx, h, job.ID)
		assert.Equal(t, JobProcessing, stored.Status,
			"the renewed lease keeps the job exclusively claimed")
		assert.True(t, stored.LeaseUntil.Equal(t0.Add(50*time.Second)),
			"batch 0's checkpoint renewed the lease from t0+30s to t0+50s, got %s", stored.LeaseUntil)

		recovered, err := h.store.RecoverExpiredLeases(ctx)
		require.NoError(t, err)
		assert.Zero(t, recovered,
			"a checkpointed job is never requeued while its renewed lease is live")
		_, err = h.store.ClaimNext(ctx, "worker-b", 30*time.Second)
		require.ErrorIs(t, err, ErrQueueEmpty,
			"second worker's acquire is refused inside the renewed TTL window")
		err = h.store.SaveCheckpoint(ctx, job.ID, "worker-b", 30*time.Second, Checkpoint{}, FamilyCounts{})
		assert.ErrorIs(t, err, ErrLeaseLost, "zombie fencing: worker B holds no lease")
	}

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-renew")
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)
	require.True(t, attackRan, "the mid-run attack hook must have executed")

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobCompleted, stored.Status)
	assert.True(t, stored.LeaseUntil.IsZero(), "finalize clears the lease")
	hot, applied, exec := h.runner.snapshot()
	assert.Empty(t, hot)
	for _, id := range ids {
		assert.Equal(t, 1, applied[id], "exactly-once effect for %s under lease renewal", id)
	}
	assert.Equal(t, 1, exec[0])
	assert.Equal(t, 1, exec[1])
	assert.Equal(t, 1, exec[2])
}

// TestZombieFencedThroughRenewedLeaseExpiry pins the other half of F3: the
// renewed lease is a REAL lease — when its worker stops checkpointing, it
// expires (recovery requeues, worker B resumes), and the zombie's late
// checkpoint is still fenced by the same guard. Worker A is parked from
// t0+25s to t0+60s (35s > LeaseTTL 30s): it survives the ORIGINAL claim
// horizon only through batch 0's renewal (t0+25s checkpoint → t0+55s lease).
func TestZombieFencedThroughRenewedLeaseExpiry(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4"}
	h := newTestHarness(t, [][]string{{"r1", "r2"}, {"r3", "r4"}}, ids...)
	ctx := context.Background()

	parkBatch1 := make(chan struct{})
	h.runner.beforeBatch = func(job *Job, idx int) {
		if job.WorkerID != "worker-a" {
			return
		}
		if idx == 0 {
			// Batch 0 takes 25s; its checkpoint renews the lease to t0+55s.
			h.clock.Advance(25 * time.Second)
		}
		if idx == 1 {
			<-parkBatch1
		}
	}

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-renew-zombie")
	done := make(chan error, 1)
	go func() {
		claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
		if err != nil {
			done <- err
			return
		}
		if !claimed {
			done <- errors.New("worker A did not claim the job")
			return
		}
		done <- nil
	}()

	// Worker A checkpointed batch 0 at t0+25s (lease renewed to t0+55s) and
	// parks in batch 1.
	waitFor(t, func() bool {
		stored, err := h.store.JobByID(ctx, testOrg, job.ID)
		require.NoError(t, err)
		return stored.Status == JobProcessing && stored.Checkpoint.NextBatch == 1
	}, "worker A never checkpointed batch 0")
	require.True(t, mustJob(t, ctx, h, job.ID).LeaseUntil.Equal(h.clock.Now().Add(30*time.Second)),
		"batch 0's checkpoint renewed the lease past the claim horizon")

	// Let the RENEWED lease expire: t0+25s + 35s = t0+60s > t0+55s. Recovery
	// must requeue the stopped-checkpointing worker, and worker B resumes
	// from the checkpoint.
	h.clock.Advance(35 * time.Second)
	recovered, err := h.store.RecoverExpiredLeases(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, recovered, "a worker that stops checkpointing loses the job")

	claimedB, err := h.engine.ExecuteNext(ctx, "worker-b")
	require.NoError(t, err)
	require.True(t, claimedB)

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobCompleted, stored.Status)
	assert.EqualValues(t, 4, stored.Confirmed.Total(), "all rows accounted exactly once")

	// Release the zombie: it was parked well past the claim horizon, its
	// renewed lease expired and worker B re-executed batch 1. The zombie's
	// late checkpoint must fail with ErrLeaseLost without corrupting the
	// terminal state.
	close(parkBatch1)
	require.NoError(t, <-done)

	hot, applied, exec := h.runner.snapshot()
	assert.Empty(t, hot)
	for _, id := range ids {
		assert.Equal(t, 1, applied[id], "exactly-once effect for %s across the renewed-lease restart", id)
	}
	assert.Equal(t, 1, exec[0], "batch 0 never re-executed after restart")
	assert.GreaterOrEqual(t, exec[1], 1,
		"batch 1 executed at least once (the zombie's parked attempt + worker B); effects stay exactly-once")

	stored = mustJob(t, ctx, h, job.ID)
	assert.Equal(t, JobCompleted, stored.Status, "zombie worker cannot un-complete a job")
	assert.Equal(t, 1, h.journal.Count(ActionCompleted))
	assert.Equal(t, 1, h.journal.Count(ActionStarted))
}

// waitFor polls cond until it holds or the deadline expires (deterministic
// replacement for sleeps in concurrency assertions).
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestCancelStopsBeforeNextBatch pins A-R6: cancel always stops before the
// next batch; applied rows stay applied; terminal state carries confirmed
// counts only; terminal/foreign cancels refuse.
func TestCancelStopsBeforeNextBatch(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4", "r5", "r6"}
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}, {"r3", "r4", "r5", "r6"}}, ids...)
	ctx := context.Background()

	// Cancel arrives during batch 1 (between batch boundaries): the engine's
	// cancel check runs before EVERY batch, so the cancel stops the job
	// before the NEXT batch (index 2) — batch 1 completes (it was already
	// in flight), batch 2 never starts.
	h.runner.beforeBatch = func(job *Job, idx int) {
		if idx == 1 {
			err := h.engine.RequestCancel(ctx, adminCaller(), testOrg, job.ID)
			require.NoError(t, err)
		}
	}

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-cancel")
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCanceled, stored.Status)
	assert.EqualValues(t, 2, stored.Confirmed.Total(), "confirmed counts only — no speculation")
	assert.Equal(t, 2, stored.Checkpoint.NextBatch)

	hot, applied, exec := h.runner.snapshot()
	assert.Equal(t, []string{"r3", "r4", "r5", "r6"}, sortedStrings(hot),
		"untouched batches stay in the hot store (no speculative deletion)")
	assert.Equal(t, 1, applied["r1"], "applied rows stay applied (never restored)")
	assert.Equal(t, 1, applied["r2"])
	assert.Equal(t, 1, exec[0])
	assert.Equal(t, 1, exec[1], "the in-flight batch completes")
	assert.Zero(t, exec[2], "cancel stopped BEFORE batch 2")
	assert.Equal(t, 1, h.journal.Count(ActionCanceled))

	// Cancel on a terminal job refuses (409-class).
	err = h.engine.RequestCancel(ctx, adminCaller(), testOrg, job.ID)
	require.ErrorIs(t, err, ErrJobTerminal)

	// Cancel from another org cannot even see the job (zero leakage).
	err = h.engine.RequestCancel(ctx, adminCaller(), "org-other", job.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestCancelPendingJob pins cancel-before-start: a cancel requested while the
// job is pending finalizes it canceled on claim without executing anything.
func TestCancelPendingJob(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1", "r2"}}, "r1", "r2")
	ctx := context.Background()
	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-pending")

	require.NoError(t, h.engine.RequestCancel(ctx, adminCaller(), testOrg, job.ID))
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobCanceled, stored.Status)
	_, applied, exec := h.runner.snapshot()
	assert.Empty(t, applied)
	assert.Empty(t, exec, "canceled before any batch ran")
}

// sortedStrings is a tiny deterministic order helper for assertions.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// TestSnapshotDriftRefuses pins the digest gate at run time (04-ACCEPTANCE
// §2): drift between preview and replay refuses fail-closed BEFORE the plan,
// so zero rows are touched.
func TestSnapshotDriftRefuses(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1", "r2"}}, "r1", "r2")
	h.runner.verifyErr = Refuse(RefusalDigestMismatch, "new rows appeared since preview")
	ctx := context.Background()

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-drift")
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, stored.Status)
	require.NotNil(t, stored.Refusal)
	assert.Equal(t, RefusalDigestMismatch, stored.Refusal.Code)

	hot, _, exec := h.runner.snapshot()
	assert.Len(t, hot, 2, "zero rows touched")
	assert.Empty(t, exec, "no batch ever executed")
	assert.Zero(t, h.runner.planCalls, "planning never started after a failed verification")
	assert.Equal(t, 1, h.journal.Count(ActionDenied))
}

// TestBatchGuardRevokedGrant pins A-R5: a grant revoked between enqueue and
// batch 1 stops the job before that batch (active_grant), batch 0's applied
// rows stay applied, and the refusal names grant ids.
func TestBatchGuardRevokedGrant(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4"}
	h := newTestHarness(t, [][]string{{"r1", "r2"}, {"r3", "r4"}}, ids...)
	ctx := context.Background()

	h.engine.SetBatchGuard(guardFunc(func(_ context.Context, job *Job, ids []string) error {
		if job.Checkpoint.NextBatch >= 1 {
			return Refuse(RefusalActiveGrant, "payload grant became active").WithGrants("g-77")
		}
		return nil
	}))

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-grant")
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, stored.Status)
	require.NotNil(t, stored.Refusal)
	assert.Equal(t, RefusalActiveGrant, stored.Refusal.Code)
	assert.Equal(t, []string{"g-77"}, stored.Refusal.GrantIDs,
		"the refusal names grant ids, never tokens")

	hot, applied, exec := h.runner.snapshot()
	assert.Equal(t, []string{"r3", "r4"}, sortedStrings(hot), "batch 1 untouched")
	assert.Equal(t, 1, applied["r1"], "batch 0 effects persist")
	assert.Equal(t, 1, exec[0])
	assert.Zero(t, exec[1], "refusal stopped BEFORE batch 1")
	assert.EqualValues(t, 2, stored.Confirmed.Total())
	assert.Equal(t, 1, h.journal.Count(ActionDenied), "mid-run denial is journalled")
}

// guardFunc adapts a function to BatchGuard.
type guardFunc func(ctx context.Context, job *Job, ids []string) error

func (f guardFunc) BatchAllowed(ctx context.Context, job *Job, ids []string) error {
	return f(ctx, job, ids)
}

// TestTransientRetryExhaustion: non-refusal errors retry with backoff until
// MaxAttempts, then fail terminally.
func TestTransientRetryExhaustion(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	h.runner.batchErr = map[int]error{0: errors.New("cold storage 503")}
	ctx := context.Background()

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-retry")

	// Attempt 1: fails transiently → released for retry.
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)
	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobPending, stored.Status, "transient failure returns to pending")
	assert.Equal(t, "batch 0: cold storage 503", stored.LastError)
	assert.Equal(t, 1, stored.Attempts)

	// Attempt 2 (after backoff): MaxAttempts=3, still transient → pending.
	h.clock.Advance(time.Minute)
	claimed, err = h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	// Attempt 3: attempts exhausted → terminal failure.
	h.clock.Advance(time.Minute)
	claimed, err = h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)
	stored, err = h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobFailed, stored.Status)
	assert.Equal(t, 3, stored.Attempts)

	hot, _, _ := h.runner.snapshot()
	assert.Len(t, hot, 1, "no partial deletion on transient failures")
	assert.Zero(t, h.journal.Count(ActionCompleted))
}

// TestRefusalNeverRetries: refusals are terminal on first occurrence.
func TestRefusalNeverRetries(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	h.runner.batchErr = map[int]error{0: Refuse(RefusalActiveGrant, "grant active")}
	ctx := context.Background()

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-refusal")
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobFailed, stored.Status)
	assert.Equal(t, 1, stored.Attempts, "refusal consumed exactly one attempt, no retry")
}

// TestCrossOrgZeroLeakage pins A-R4: forged/foreign job ids are
// indistinguishable from unknown ones — every scoped lookup 404s.
func TestCrossOrgZeroLeakage(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	ctx := context.Background()
	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-org-alpha")

	foreign := "org-beta"
	_, err := h.engine.Status(ctx, foreign, job.ID)
	require.ErrorIs(t, err, ErrNotFound, "foreign job id leaks nothing")
	_, err = h.engine.Status(ctx, foreign, "forged-id")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = h.engine.Status(ctx, testOrg, "forged-id")
	require.ErrorIs(t, err, ErrNotFound)

	err = h.store.RequestCancel(ctx, foreign, job.ID, h.clock.Now())
	require.ErrorIs(t, err, ErrNotFound)
}

// TestServiceActorStamping pins A-R7: auto-retention service jobs carry the
// actor type, author and policy version on the job and the journal.
func TestServiceActorStamping(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	ctx := context.Background()
	digest, err := SelectionDigest(OpArchiveRemoveHot, harnessSelection(), h.stamp)
	require.NoError(t, err)

	job, err := h.engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           testOrg,
		Op:              OpArchiveRemoveHot,
		Selection:       harnessSelection(),
		PresentedDigest: digest,
		IdempotencyKey:  "retention-auto-1",
		Destination:     destinationFor(OpArchiveRemoveHot),
		Actor:           JobActor{Type: ActorService, Author: "retention-svc", PolicyVersion: "ret-v3"},
	})
	require.NoError(t, err, "service actors skip caller authorization by design")
	assert.Equal(t, ActorService, job.Actor.Type)
	assert.Equal(t, "retention-svc", job.Actor.Author)
	assert.Equal(t, "ret-v3", job.Actor.PolicyVersion)

	started := 0
	for _, e := range h.journal.Entries() {
		if e.Action == JournalAction(OpArchiveRemoveHot, ActionStarted) {
			started++
			assert.Equal(t, "ret-v3", e.Details["policy_version"])
			assert.Equal(t, "service", e.Details["actor_type"])
		}
	}
	assert.Equal(t, 1, started)

	// Delegated interactive callers still cannot enqueue their own cleanup.
	_, err = h.engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           testOrg,
		Op:              OpArchiveRemoveHot,
		Selection:       harnessSelection(),
		PresentedDigest: digest,
		IdempotencyKey:  "ci-self-serve",
		Actor:           JobActor{Type: ActorUser, Author: "ci-runner"},
		Caller: Caller{
			UserID:  "ci-runner",
			Role:    adminstore.RoleOrgAdmin,
			Subject: adminstore.RequestPayloadCI,
			Perms:   map[adminstore.Permission]bool{adminstore.PermRequestsRead: true},
		},
	})
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "delegated subject must be a typed refusal, got %v", err)
	assert.Equal(t, RefusalInsufficientRights, refusal.Code)
}

// TestEmptySelectionNoOpCompletion: a valid selection matching zero rows
// completes as a no-op with planned=true (no replanning on restart).
func TestEmptySelectionNoOpCompletion(t *testing.T) {
	h := newTestHarness(t, nil /* empty plan */)
	ctx := context.Background()
	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-noop")

	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobCompleted, stored.Status)
	assert.True(t, stored.Checkpoint.Planned)
	assert.Zero(t, stored.Confirmed.Total())
	assert.Equal(t, 1, h.journal.Count(ActionCompleted))
}

// TestNoRunnerPoisons: an unregistered operation fails the job terminally
// instead of looping.
func TestNoRunnerPoisons(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	h.engine.RegisterRunner(OpArchiveRemoveHot, nil) // unregister
	ctx := context.Background()
	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-poison")

	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobFailed, stored.Status)
	assert.Contains(t, stored.LastError, "no runner registered")
}

// TestEnqueueRefusalCatalogue pins the enqueue-time refusal discipline: every
// refusal leaves zero job rows behind, and the successful case creates exactly
// one.
func TestEnqueueRefusalCatalogue(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	ctx := context.Background()
	sel := harnessSelection()
	digest, err := SelectionDigest(OpArchiveCopy, sel, h.stamp)
	require.NoError(t, err)
	purgeDigest, err := SelectionDigest(OpPurge, sel, h.stamp)
	require.NoError(t, err)

	type attempt struct {
		name string
		req  EnqueueRequest
		code RefusalCode
	}
	viewerCaller := Caller{
		UserID: "u-viewer",
		Role:   adminstore.RoleReader,
		Perms:  map[adminstore.Permission]bool{adminstore.PermRequestsRead: true},
	}
	attempts := []attempt{
		{
			name: "digest mismatch",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: "deadbeef", IdempotencyKey: "k1", Destination: testDestination,
				Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalDigestMismatch,
		},
		{
			name: "viewer enqueue",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: digest, IdempotencyKey: "k2", Destination: testDestination,
				Actor: JobActor{Author: "u-viewer"}, Caller: viewerCaller},
			code: RefusalInsufficientRights,
		},
		{
			name: "purge without confirmation store",
			req: EnqueueRequest{OrgID: testOrg, Op: OpPurge, Selection: sel,
				PresentedDigest: purgeDigest, IdempotencyKey: "k3",
				Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalPurgeConfirmationMissing,
		},
		{
			name: "archive without destination",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: digest, IdempotencyKey: "k4",
				Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalNoDestination,
		},
		{
			name: "unsupported destination scheme",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: digest, IdempotencyKey: "k5",
				Destination: "s3://cold/historyops/org-alpha/x",
				Actor:       JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalUnsupportedDestination,
		},
		{
			name: "foreign destination namespace",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: digest, IdempotencyKey: "k6",
				Destination: "file:///cold/historyops/org-beta/x",
				Actor:       JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalForeignDestination,
		},
		{
			name: "destination traversal",
			req: EnqueueRequest{OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
				PresentedDigest: digest, IdempotencyKey: "k7",
				Destination: "file:///cold/historyops/org-alpha/../../etc",
				Actor:       JobActor{Author: "u-admin-1"}, Caller: adminCaller()},
			code: RefusalUnsupportedDestination,
		},
	}
	for _, tc := range attempts {
		t.Run(tc.name, func(t *testing.T) {
			deniedBefore := h.journal.Count(ActionDenied)
			_, err := h.engine.Enqueue(ctx, tc.req)
			require.Error(t, err)
			refusal, ok := RefusalOf(err)
			require.True(t, ok, "expected typed refusal, got %v", err)
			assert.Equal(t, tc.code, refusal.Code)
			assert.Equal(t, deniedBefore+1, h.journal.Count(ActionDenied), "denial journalled")
		})
	}

	// The digest-mismatch path double-journalled (once per failed attempt);
	// the exact count is asserted per subtest. Now the happy path:
	harness := newTestHarness(t, nil)
	okDigest, err := SelectionDigest(OpArchiveCopy, sel, harness.stamp)
	require.NoError(t, err)
	job, err := harness.engine.Enqueue(ctx, EnqueueRequest{
		OrgID: testOrg, Op: OpArchiveCopy, Selection: sel,
		PresentedDigest: okDigest, IdempotencyKey: "ok-1",
		Destination: testDestination,
		Actor:       JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, job.ID)
	assert.Equal(t, 1, harness.journal.Count(ActionStarted))
	assert.Equal(t, 0, harness.journal.Count(ActionDenied))
}

// TestViewerCanPreviewCannotOperate: the preview op enqueues like any job but
// only destructive ops require org-admin — a viewer's preview job must be
// creatable by an admin and VISIBLE to the viewer (AuthorizeJobRead), while
// viewer enqueue of destructive ops stays refused (already pinned above).
func TestViewerCanPreviewCannotOperate(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}}, "r1")
	ctx := context.Background()
	sel := harnessSelection()
	digest, err := SelectionDigest(OpPreview, sel, h.stamp)
	require.NoError(t, err)

	job, err := h.engine.Enqueue(ctx, EnqueueRequest{
		OrgID: testOrg, Op: OpPreview, Selection: sel,
		PresentedDigest: digest, IdempotencyKey: "preview-1",
		Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err)

	viewer := Caller{
		UserID: "u-viewer",
		Role:   adminstore.RoleReader,
		Perms:  map[adminstore.Permission]bool{adminstore.PermRequestsRead: true},
	}
	require.NoError(t, AuthorizeJobRead(viewer), "viewer reads job progress")
	stored, err := h.engine.Status(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, OpPreview, stored.Op)
}

// TestRunLoopDrainsQueue: the Run loop processes everything then parks.
func TestRunLoopDrainsQueue(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}, {"r3"}}, "r1", "r2", "r3")
	ctx, cancel := context.WithCancel(context.Background())
	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-runloop")

	done := make(chan error, 1)
	go func() { done <- h.engine.Run(ctx, "worker-loop") }()
	// Wait until the job completes, then stop the loop.
	deadline := time.Now().Add(5 * time.Second)
	for {
		stored, err := h.store.JobByID(ctx, testOrg, job.ID)
		require.NoError(t, err)
		if stored.Status.Terminal() {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("run loop never completed the job")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)

	stored, err := h.store.JobByID(ctx, testOrg, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobCompleted, stored.Status)
	assert.EqualValues(t, 3, stored.Confirmed.Total())
}
