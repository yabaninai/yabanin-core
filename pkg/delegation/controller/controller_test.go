package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/delegation"
)

// countingFake counts Run calls so resume idempotency is observable.
type countingFake struct {
	calls atomic.Int64
	fail  atomic.Bool
}

func (f *countingFake) Name() string                   { return "fake" }
func (f *countingFake) Available(context.Context) bool { return true }
func (f *countingFake) Run(_ context.Context, _ delegation.Request) (delegation.Result, error) {
	if f.fail.Load() {
		return delegation.Result{Status: "error"}, errors.New("executor boom")
	}
	f.calls.Add(1)
	return delegation.Result{Status: "ok", Summary: "done"}, nil
}

func newTestController(t *testing.T, holder string) (*Controller, *countingFake, *Store) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	fake := &countingFake{}
	ctl := New(store, fake, holder, 40*time.Millisecond)
	return ctl, fake, store
}

// --- transition graph ---

func TestTransitionMatrix(t *testing.T) {
	allowed := map[EpisodeState][]EpisodeState{
		StatePending:  {StateRunning, StateCanceled},
		StateRunning:  {StateAwaiting, StateDone, StateFailed, StateCanceled},
		StateAwaiting: {StateDone, StateCanceled},
		StateDone:     {},
		StateFailed:   {},
		StateCanceled: {},
	}
	for from, targets := range allowed {
		for _, to := range targets {
			if !CanTransition(from, to) {
				t.Errorf("CanTransition(%s,%s) = false, want true", from, to)
			}
			e := &Episode{State: from}
			if err := e.Transition(to); err != nil {
				t.Errorf("Transition(%s->%s) err = %v, want nil", from, to, err)
			}
		}
		// Everything else must be rejected — enumerate the full set.
		all := []EpisodeState{StatePending, StateRunning, StateAwaiting, StateDone, StateFailed, StateCanceled}
		for _, to := range all {
			permitted := false
			for _, tt := range targets {
				if tt == to {
					permitted = true
				}
			}
			if !permitted && CanTransition(from, to) {
				t.Errorf("CanTransition(%s,%s) = true, want false", from, to)
			}
		}
	}
	for _, s := range []EpisodeState{StateDone, StateFailed, StateCanceled} {
		if !s.Terminal() {
			t.Errorf("%s must be terminal", s)
		}
	}
}

// --- lifecycle ---

func TestRunAnalyzeCompletes(t *testing.T) {
	ctl, fake, store := newTestController(t, "h1")
	e, err := ctl.Start("ep1", "summarize the repo", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StatePending || len(e.Steps) != 1 {
		t.Fatalf("new episode: state=%s steps=%d", e.State, len(e.Steps))
	}
	e, err = ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("analyze now lands in awaiting_review (auto-accept applies separately), got %s", e.State)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", fake.calls.Load())
	}
	if e.Lease != nil {
		t.Error("terminal episode must not hold a lease")
	}
	// Reload from disk: the state is durable (awaiting_review now).
	persisted, err := store.Load("ep1")
	if err != nil || persisted.State != StateAwaiting {
		t.Fatalf("persisted = %v, %v", persisted, err)
	}
}

func TestRunImplementAwaitsReview(t *testing.T) {
	ctl, _, _ := newTestController(t, "h1")
	e, _ := ctl.Start("ep2", "patch the parser", delegation.ModeImplement, "")
	if len(e.Steps) != 3 {
		t.Fatalf("implement steps = %d, want 3 (plan/implement/validate)", len(e.Steps))
	}
	e, err := ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("implement must await review, got %s", e.State)
	}
	// The controller never self-approves; Approve closes it.
	e, err = ctl.Approve(e)
	if err != nil || e.State != StateDone {
		t.Fatalf("approve: %v state=%s", err, e.State)
	}
}

func TestStepFailureFailsEpisode(t *testing.T) {
	ctl, fake, _ := newTestController(t, "h1")
	e, _ := ctl.Start("ep3", "task", delegation.ModeImplement, "")
	fake.fail.Store(true)
	if _, err := ctl.Run(context.Background(), e); err == nil {
		t.Fatal("failing step must surface an error")
	}
	e2, err := ctl.Start("ep3", "task", delegation.ModeImplement, "") // reload path
	if err != nil {
		t.Fatal(err)
	}
	if e2.State != StateFailed {
		t.Fatalf("state = %s, want failed", e2.State)
	}
}

func TestCancel(t *testing.T) {
	ctl, _, _ := newTestController(t, "h1")
	e, _ := ctl.Start("ep4", "task", delegation.ModeAnalyze, "")
	e, err := ctl.Cancel(e, "operator stopped it")
	if err != nil || e.State != StateCanceled || e.CancelReason == "" {
		t.Fatalf("cancel: %v %s %q", err, e.State, e.CancelReason)
	}
	// Canceling a terminal episode is an error, not a no-op.
	if _, err := ctl.Cancel(e, "again"); !errors.Is(err, ErrTransition) {
		t.Fatalf("second cancel err = %v, want ErrTransition", err)
	}
}

// --- resume, crash, fencing ---

func TestResumeSkipsFinishedSteps(t *testing.T) {
	ctl, fake, _ := newTestController(t, "h1")
	e, _ := ctl.Start("ep5", "task", delegation.ModeImplement, "")
	// Simulate a crash after step 1 completed: persisted running episode
	// with the first step done and no live lease (expired).
	e.State = StateRunning
	e.Steps[0].Status = "done"
	e.Steps[0].Result = &delegation.Result{Status: "ok"}
	e.Lease = nil
	if err := ctl.store.SaveFenced(e, ""); err != nil {
		t.Fatal(err)
	}
	e, err := ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("resumed implement must await review, got %s", e.State)
	}
	// Exactly the two unfinished steps ran.
	if got := fake.calls.Load(); got != 2 {
		t.Fatalf("executor calls after resume = %d, want 2", got)
	}
}

func TestForeignLiveLeaseBlocksSecondController(t *testing.T) {
	ctl1, _, store := newTestController(t, "controller-1")
	e, _ := ctl1.Start("ep6", "task", delegation.ModeAnalyze, "")
	if err := store.AcquireLease(e, "controller-1", time.Hour); err != nil {
		t.Fatal(err)
	}

	ctl2, _, _ := newTestController(t, "controller-2")
	if _, err := ctl2.Run(context.Background(), e); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second controller err = %v, want ErrLeaseHeld", err)
	}
}

func TestExpiredLeaseTakeoverFencesPredecessor(t *testing.T) {
	ctl1, _, store := newTestController(t, "controller-1")
	e, _ := ctl1.Start("ep7", "task", delegation.ModeAnalyze, "")
	// controller-1 grabbed a lease that expired (crashed).
	if err := store.AcquireLease(e, "controller-1", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	ctl2, fake2, _ := newTestController(t, "controller-2")
	e2, err := ctl2.Run(context.Background(), e)
	if err != nil {
		t.Fatalf("takeover run: %v", err)
	}
	if e2.State != StateAwaiting || fake2.calls.Load() != 1 {
		t.Fatalf("takeover did not complete (awaiting): %s calls=%d", e2.State, fake2.calls.Load())
	}

	// The CRASHED predecessor still holds the OLD episode object in memory.
	// Its next save must be fenced (stale generation), not silently win.
	stale, err := store.Load("ep7")
	if err != nil {
		t.Fatal(err)
	}
	stale.Generation-- // pretend we are the old in-memory copy
	stale.CancelReason = "ghost write"
	if err := store.SaveFenced(stale, "controller-1"); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale write err = %v, want ErrFenced", err)
	}
}

func TestStoreRejectsCorruptAndForeignSchema(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing err = %v", err)
	}
	// Corrupt JSON is an error, never a silent empty episode.
	if err := writeRaw(store, "bad", "{not json"); err == nil {
		_, lerr := store.Load("bad")
		if lerr == nil {
			t.Fatal("corrupt episode loaded without error")
		}
	}
	// Unknown schema version is rejected explicitly.
	if err := writeRaw(store, "future", `{"schema_version":99,"id":"future"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("future"); err == nil {
		t.Fatal("future schema must be rejected")
	}
}

func TestStartIsIdempotent(t *testing.T) {
	ctl, _, _ := newTestController(t, "h1")
	e1, _ := ctl.Start("ep8", "first task", delegation.ModeAnalyze, "")
	e2, err := ctl.Start("ep8", "DIFFERENT task", delegation.ModeImplement, "")
	if err != nil {
		t.Fatal(err)
	}
	if e2.Task != e1.Task || e2.Mode != e1.Mode {
		t.Fatal("Start must return the existing episode unchanged, never reset it")
	}
}

func writeRaw(s *Store, id, content string) error {
	return writeFileForTest(s.path(id), []byte(content))
}

// NEXT-12: auto-accept closes low-risk analyze episodes without human review.
func TestAutoAcceptAnalyzeEpisode(t *testing.T) {
	store, err := NewStore(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	fake := &countingFake{}
	ctl := New(store, fake, "h-auto", 40*time.Millisecond).WithAutoAccept(true)
	e, err := ctl.Start("ep-auto", "analyze task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err = ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateDone {
		t.Fatalf("auto-accept should close analyze: got %s", e.State)
	}
	if e.Review == nil || e.Review.Actor != "auto-accept:low-risk" {
		t.Fatalf("review provenance missing: %+v", e.Review)
	}
}

// Auto-accept must NOT close implement-mode episodes.
func TestAutoAcceptDoesNotCloseImplement(t *testing.T) {
	store, _ := NewStore(t.TempDir() + "/state")
	fake := &countingFake{}
	ctl := New(store, fake, "h-auto2", 40*time.Millisecond).WithAutoAccept(true)
	e, _ := ctl.Start("ep-auto2", "patch task", delegation.ModeImplement, "")
	e, err := ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("implement must still await review even with auto-accept: got %s", e.State)
	}
}

// Auto-accept disabled by default.
func TestAutoAcceptDisabledByDefault(t *testing.T) {
	store, _ := NewStore(t.TempDir() + "/state")
	fake := &countingFake{}
	ctl := New(store, fake, "h-auto3", 40*time.Millisecond)
	e, _ := ctl.Start("ep-auto3", "analyze task", delegation.ModeAnalyze, "")
	e, err := ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("without WithAutoAccept, analyze must stay awaiting: got %s", e.State)
	}
}

// --- TP-16: lease renewal lifecycle ---

// gateExecutor blocks inside Run until released (success path) or its
// context is canceled (lease loss / caller cancel). Every start and exit is
// signaled so tests synchronize on events, not on sleeps.
type gateExecutor struct {
	release chan struct{}
	started chan struct{}
	exits   chan error
	startOK sync.Once
}

func newGateExecutor() *gateExecutor {
	return &gateExecutor{
		release: make(chan struct{}),
		started: make(chan struct{}),
		exits:   make(chan error, 8),
	}
}

func (g *gateExecutor) Name() string                   { return "gate" }
func (g *gateExecutor) Available(context.Context) bool { return true }

func (g *gateExecutor) Run(ctx context.Context, _ delegation.Request) (delegation.Result, error) {
	g.startOK.Do(func() { close(g.started) })
	select {
	case <-g.release:
		return delegation.Result{Status: "ok", Summary: "released"}, nil
	case <-ctx.Done():
		g.exits <- ctx.Err()
		return delegation.Result{}, ctx.Err()
	}
}

type runResult struct {
	e   *Episode
	err error
}

func startRun(ctl *Controller, e *Episode) chan runResult {
	done := make(chan runResult, 1)
	go func() {
		ee, err := ctl.Run(context.Background(), e)
		done <- runResult{e: ee, err: err}
	}()
	return done
}

// tp16WaitCeiling bounds every event wait in the TP16 harness. Events
// (channels) are the synchronization mechanism — never sleeps; the ceiling
// guards only TRUE hangs, so a genuinely broken signal still fails the test
// instead of hanging the gate. It is deliberately generous: under a loaded
// gate battery, scheduler starvation can hold goroutines back for seconds,
// and the ceiling must never be what a healthy run hits (observed
// happy-path latencies are milliseconds; each is logged as evidence).
const tp16WaitCeiling = 60 * time.Second

func waitEvent(t *testing.T, name string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(tp16WaitCeiling):
		t.Fatalf("timeout waiting for %s: no event within %s (signal genuinely never fired)", name, tp16WaitCeiling)
	}
}

// A slow executor must survive several renewal ticks without a race: the
// renewal proof is read from the persisted lease (ExpiresAt moves forward
// while the executor is still in flight), and completion is event-driven.
func TestTP16_SlowExecutorSurvivesRenewalTicks(t *testing.T) {
	store, err := NewStore(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	exec := newGateExecutor()
	ctl := New(store, exec, "h-slow", 20*time.Millisecond) // tick every 10ms
	e, err := ctl.Start("tp16-slow", "task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	done := startRun(ctl, e)
	waitEvent(t, "executor start", exec.started)

	leaseExpiry := func() time.Time {
		persisted, lerr := store.Load("tp16-slow")
		if lerr != nil || persisted.Lease == nil {
			return time.Time{}
		}
		return persisted.Lease.ExpiresAt
	}
	first := leaseExpiry()
	if first.IsZero() {
		t.Fatal("no lease on disk while executor is in flight")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if cur := leaseExpiry(); cur.After(first) {
			break // a renewal fired mid-flight and extended the lease
		}
		if time.Now().After(deadline) {
			t.Fatal("no lease renewal observed while executor was in flight")
		}
		time.Sleep(2 * time.Millisecond)
	}

	close(exec.release)
	res := <-done
	if res.err != nil {
		t.Fatalf("slow run must complete cleanly, got %v", res.err)
	}
	if res.e.State != StateAwaiting {
		t.Fatalf("state = %s, want awaiting_review", res.e.State)
	}
}

// Losing the lease (a successor fenced us out) must cancel the in-flight
// executor, not let it finish orphaned, and Run must surface the fencing.
func TestTP16_LeaseLossCancelsInFlightExecutor(t *testing.T) {
	store, err := NewStore(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	exec := newGateExecutor()
	ctl := New(store, exec, "h-lost", 20*time.Millisecond)
	e, err := ctl.Start("tp16-lost", "task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	done := startRun(ctl, e)
	waitEvent(t, "executor start", exec.started)

	// Simulate the successor: state on disk is newer and its lease is live.
	// Our next renewal is fenced, which is the lease loss.
	//
	// The write must SURVIVE the predecessor's own saves: a raw write that
	// lands while the predecessor is between its Load and its rename (or
	// lags a scheduler stall and drags the generation backward — the
	// investigated D2/D3 shapes) is clobbered, and the flake came from
	// asserting a specific sentinel on a write that never stuck. The raw
	// write bypasses the store's flock by construction, so the takeover is
	// written and verified WHILE HOLDING the episode flock: that rules out
	// an in-flight predecessor save (one that loaded before us and renames
	// after our check — a check without the lock is itself a TOCTOU, as a
	// 32-way battery run demonstrated). Once the check passes under the
	// lock, the predecessor's next SaveFenced re-reads our state and must
	// fence. Bounded retries cover the predecessor winning a round while we
	// wait for the lock; a takeover that never sticks fails fast.
	const takeoverRetries = 100
	var survived bool
	for attempt := 0; attempt < takeoverRetries; attempt++ {
		unlock, err := store.lockEpisode("tp16-lost")
		if err != nil {
			t.Fatal(err)
		}
		current, err := store.Load("tp16-lost")
		if err != nil {
			unlock()
			t.Fatal(err)
		}
		current.Generation++
		current.Lease = &Lease{Holder: "successor", Generation: current.Lease.Generation + 1, ExpiresAt: time.Now().Add(time.Hour)}
		raw, err := json.MarshalIndent(current, "", "  ")
		if err != nil {
			unlock()
			t.Fatal(err)
		}
		if err := writeRaw(store, "tp16-lost", string(raw)); err != nil {
			unlock()
			t.Fatal(err)
		}
		check, err := store.Load("tp16-lost")
		if err != nil {
			unlock()
			t.Fatal(err)
		}
		survived = check.Lease != nil && check.Lease.Holder == "successor"
		unlock()
		if survived {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !survived {
		t.Fatalf("takeover write never survived the predecessor's saves after %d attempts", takeoverRetries)
	}

	// TP16 flake hardening: the lease-loss cancel is event-driven (exec.exits)
	// and normally lands within a few 10ms renewal ticks. The old fixed 5s
	// wall-clock deadline produced false failures when a 32-way gate battery
	// starved the scheduler; tp16WaitCeiling is generous and guards only true
	// hangs. A genuinely broken cancel still fails, bounded, at the ceiling —
	// and the elapsed guard plus the logged latency keep that ceiling out of
	// the happy path (vacuity: the ceiling is never the success condition).
	cancelWaitStart := time.Now()
	select {
	case got := <-exec.exits:
		if elapsed := time.Since(cancelWaitStart); elapsed >= tp16WaitCeiling {
			t.Fatalf("vacuity: cancel event arrived only at the %s hang ceiling (elapsed %s)", tp16WaitCeiling, elapsed)
		}
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("executor exit = %v, want context.Canceled", got)
		}
		t.Logf("lease-loss cancel observed after %s (hang ceiling %s)", time.Since(cancelWaitStart), tp16WaitCeiling)
	case <-time.After(tp16WaitCeiling):
		t.Fatalf("in-flight executor was not canceled after lease loss: no cancel event within %s", tp16WaitCeiling)
	}

	res := <-done
	// Contract-honest assertion (see Run's TP-16 contract): lease loss
	// surfaces as ErrFenced when the takeover carries a strictly newer
	// generation, or ErrLeaseHeld when the takeover lags and drags the
	// generation backward (D2 shape). Both fence this controller out and
	// both must have canceled the executor above.
	if !errors.Is(res.err, ErrFenced) && !errors.Is(res.err, ErrLeaseHeld) {
		t.Fatalf("run err = %v, want ErrFenced or ErrLeaseHeld", res.err)
	}
}

// Caller cancellation must terminate the in-flight executor and the run.
func TestTP16_ContextCancelTerminatesExecutorAndRun(t *testing.T) {
	store, err := NewStore(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	exec := newGateExecutor()
	ctl := New(store, exec, "h-cancel", 40*time.Millisecond)
	e, err := ctl.Start("tp16-cancel", "task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan runResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ee, rerr := ctl.Run(ctx, e)
		done <- runResult{e: ee, err: rerr}
	}()
	waitEvent(t, "executor start", exec.started)
	cancel()

	// Same mode-(b) hardening as the lease-loss test: the cancel event is
	// the mechanism; the generous ceiling guards only true hangs (caller
	// cancel is immediate, so healthy runs observe it in microseconds).
	cancelWaitStart := time.Now()
	select {
	case got := <-exec.exits:
		if elapsed := time.Since(cancelWaitStart); elapsed >= tp16WaitCeiling {
			t.Fatalf("vacuity: cancel event arrived only at the %s hang ceiling (elapsed %s)", tp16WaitCeiling, elapsed)
		}
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("executor exit = %v, want context.Canceled", got)
		}
		t.Logf("caller-cancel observed after %s (hang ceiling %s)", time.Since(cancelWaitStart), tp16WaitCeiling)
	case <-time.After(tp16WaitCeiling):
		t.Fatalf("in-flight executor was not canceled on context cancel: no cancel event within %s", tp16WaitCeiling)
	}
	res := <-done
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("run err = %v, want context.Canceled", res.err)
	}
	if res.e.State != StateFailed {
		t.Fatalf("canceled step must fail the episode honestly, got %s", res.e.State)
	}
}

// A series of short runs must not leave renewal workers behind: Run's
// deferred shutdown waits for the worker, so the goroutine count returns to
// the baseline once the runs finish (bounded eventual check, not a blind
// sleep — a leaked worker never lets it converge).
func TestTP16_ShortRunsLeaveNoRenewalWorker(t *testing.T) {
	store, err := NewStore(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	fake := &countingFake{}
	ctl := New(store, fake, "h-series", 40*time.Millisecond)

	baseline := runtime.NumGoroutine()
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("tp16-series-%d", i)
		e, serr := ctl.Start(id, "task", delegation.ModeAnalyze, "")
		if serr != nil {
			t.Fatal(serr)
		}
		e, rerr := ctl.Run(context.Background(), e)
		if rerr != nil || e.State != StateAwaiting {
			t.Fatalf("run %d: err=%v state=%s", i, rerr, e.State)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("goroutine count = %d after runs (baseline %d): leaked renewal worker", got, baseline)
	}
}
