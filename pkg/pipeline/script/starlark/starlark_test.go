package starlark

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// testEnv mirrors the lua package fixture: three findings, two step traces,
// full meta.
func testEnv() pipeline.ConditionEnv {
	return pipeline.ConditionEnv{
		Findings: []pipeline.Finding{
			{Step: "natl_pii", Category: "innsnils", Severity: "high", Span: "10:22", Evidence: "***", Action: pipeline.ActionDeny},
			{Step: "secret_scan", Category: "aws_key", Severity: "medium", Action: pipeline.ActionFlag},
			{Step: "code_detect", Category: "code", Severity: "low", Action: pipeline.ActionAllow},
		},
		Steps: []pipeline.StepTrace{
			{Step: "natl_pii", Duration: 12 * time.Millisecond, Outcome: pipeline.StepRan},
			{Step: "callout_presidio", Duration: 210 * time.Millisecond, Outcome: pipeline.StepTimeout, Error: "deadline"},
		},
		Meta: &pipeline.RequestMeta{
			Org: "org-a", Key: "key-1", Model: "gpt-x", Provider: "openai",
			Labels: map[string]string{"team": "core", "env": "prod"},
			Tags:   []string{"pii", "sovereign"},
		},
	}
}

func evalSource(t *testing.T, source string, env pipeline.ConditionEnv) (bool, error) {
	t.Helper()
	// The semantics/error/mutation contract tests must not depend on machine
	// load: the production-default 25ms wall-clock watchdog can cancel a
	// legitimate evaluation when the whole module suite runs in parallel.
	// The watchdog itself is pinned by TestStarlarkWatchdogBounded with an
	// explicit tight budget, so this helper uses a load-tolerant one.
	e := New(WithEvalTimeout(2 * time.Second))
	prog, err := e.Compile(source)
	if err != nil {
		return false, err
	}
	return prog.Evaluate(context.Background(), env)
}

func TestStarlarkConditionBooleanContract(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"any high", `findings.any(lambda f: f.severity == 'high')`, true},
		{"any missing", `findings.any(lambda f: f.category == 'absent')`, false},
		{"count pred", `findings.count(lambda f: f.action == 'deny') == 1`, true},
		{"count all", `findings.count() == 3`, true},
		{"count list len", `len(findings.list) == 3`, true},
		{"comprehension", `len([f for f in findings.list if f.severity == 'high']) == 1`, true},
		{"none", `findings.none(lambda f: f.severity == 'critical')`, true},
		{"all non-empty", `findings.all(lambda f: f.severity != '')`, true},
		{"steps ran", `steps.ran('natl_pii') and not steps.ran('absent')`, true},
		{"steps failed timeout", `steps.failed('callout_presidio')`, true},
		{"steps duration", `steps.duration_ms('natl_pii') < 40 and steps.duration_ms('absent') == None`, true},
		{"steps outcome", `steps.outcome('callout_presidio') == 'timeout'`, true},
		{"steps get", `steps.get('natl_pii').duration_ms < 40`, true},
		{"meta fields", `meta.org == 'org-a' and meta.model != None`, true},
		{"meta label helper", `meta.label('env') == 'prod' and meta.label('nope') == None`, true},
		{"meta has_tag", `meta.has_tag('pii') and not meta.has_tag('random')`, true},
		{"meta labels direct", `meta.labels['team'] == 'core'`, true},
	}
	for _, tt := range tests {
		got, err := evalSource(t, tt.source, env)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestStarlarkConditionErrors(t *testing.T) {
	env := testEnv()
	tests := []struct {
		name   string
		source string
	}{
		{"non-bool result", `findings.count()`},
		{"predicate non-bool", `findings.count(lambda f: f.severity)`},
		{"print returns none", `print('leak') or None`},
		{"unknown attribute", `meta.nope.field == 1`},
	}
	for _, tt := range tests {
		if _, err := evalSource(t, tt.source, env); err == nil {
			t.Errorf("%s: expected evaluation error, got none", tt.name)
		}
	}
}

func TestStarlarkCompileErrors(t *testing.T) {
	for _, source := range []string{
		``, `)`, `1 +`,
		"def f():\n  return 1\n",                // statements impossible in expression position
		`while True: pass`,                      // syntax error in expression position
		`open('/etc/passwd') != None`,           // unknown global rejected at resolve time
		`__import__('os').system('id') != None`, // no such predeclared
		`(lambda: 1)() == 1 and (globals) != None`,
	} {
		if _, err := New().Compile(source); err == nil {
			t.Errorf("source %q: expected compile error", source)
		}
	}
}

// TestStarlarkMutationIsFrozen proves the env snapshot is immutable: any
// attempt to mutate findings/steps/meta fails the evaluation.
func TestStarlarkMutationIsFrozen(t *testing.T) {
	env := testEnv()
	for _, source := range []string{
		`findings.list.append(findings.list[0])`,
		`meta.labels.setdefault('pwned', '1') != None`,
		`meta.tags.append('x')`,
	} {
		if got, err := evalSource(t, source, env); err == nil {
			t.Errorf("%q: expected frozen-mutation error, got %v", source, got)
		}
	}
}

// TestStarlarkStepBudget is the DoS core: comprehension bombs hit the native
// execution-step budget and return bounded.
func TestStarlarkStepBudget(t *testing.T) {
	e := New(WithStepLimit(50_000), WithEvalTimeout(2*time.Second))
	for _, source := range []string{
		`len([x for x in range(10 * 1000 * 1000)]) > 0`,
		`len([x for x in range(1000 * 1000) for y in range(1000)]) > 0`,
	} {
		prog, err := e.Compile(source)
		if err != nil {
			t.Fatalf("compile %q: %v", source, err)
		}
		start := time.Now()
		_, err = prog.Evaluate(context.Background(), testEnv())
		if err == nil {
			t.Fatalf("attack %q: expected step-budget error", source)
		}
		if !strings.Contains(err.Error(), "evaluation budget exceeded") {
			t.Errorf("attack %q: want step-budget abort, got: %v", source, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("attack %q: unbounded response: %s", source, time.Since(start))
		}
	}
}

// TestStarlarkWatchdogBounded: the wall-clock watchdog backs up the step
// budget for long-running evaluations (cancellation is observed between
// operations).
func TestStarlarkWatchdogBounded(t *testing.T) {
	e := New(WithStepLimit(10_000_000_000), WithEvalTimeout(5*time.Millisecond))
	prog, err := e.Compile(`len([x for x in range(1000 * 1000 * 1000)]) > 0`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = prog.Evaluate(context.Background(), testEnv())
	if err == nil {
		t.Fatal("expected watchdog abort")
	}
	if !strings.Contains(err.Error(), "evaluation budget exceeded") {
		t.Errorf("want watchdog abort, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("unbounded response: %s", elapsed)
	}
}

// TestStarlarkSingleOpAllocationNotBoundedByStepLimit documents the KNOWN GAP for
// the owner decision precisely: one native operation (string/list repeat)
// allocates at operand size in a single step — the step limit counts it as
// one step and the watchdog is only observed between steps, so the peak
// allocation is bounded by the OPERAND, not by any budget. Bounded here to
// 10 MB so the test itself stays small.
func TestStarlarkSingleOpAllocationNotBoundedByStepLimit(t *testing.T) {
	// Exercise the configured engine, not evalSource's default engine. The
	// watchdog has a separate regression: this test must not assume that a
	// 10 MB allocation finishes before a millisecond wall-clock deadline.
	e := New(WithStepLimit(32), WithEvalTimeout(5*time.Second))
	prog, err := e.Compile(`len("a" * 10000000) == 10000000`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := prog.Evaluate(context.Background(), testEnv())
	if err != nil {
		t.Fatalf("single-op allocation should fit the step budget: %v", err)
	}
	if !got {
		t.Fatal("repeat result wrong")
	}
}

func TestStarlarkEmptyEnvRoots(t *testing.T) {
	got, err := evalSource(t, `findings.count() == 0 and meta.org == None and not steps.ran('x')`, pipeline.ConditionEnv{})
	if err != nil {
		t.Fatalf("empty env: %v", err)
	}
	if !got {
		t.Fatal("empty env semantics wrong")
	}
}

func TestStarlarkRejectsOversizedSourceAndEvaluationEnvironment(t *testing.T) {
	if _, err := New().Compile(strings.Repeat("x", maxConditionSourceBytes+1)); err == nil {
		t.Fatal("oversized source accepted")
	}
	program, err := New().Compile(`True`)
	if err != nil {
		t.Fatal(err)
	}
	env := pipeline.ConditionEnv{Findings: make([]pipeline.Finding, maxEnvItems+1)}
	if _, err := program.Evaluate(context.Background(), env); err == nil || !strings.Contains(err.Error(), "evaluation input exceeds limits") {
		t.Fatalf("oversized input error=%v, want explicit budget error", err)
	}
}

func TestStarlarkConcurrentEvaluate(t *testing.T) {
	// Exercise shared-program safety independently of the production watchdog:
	// race instrumentation and other packages can delay a runnable goroutine.
	prog, err := New(WithEvalTimeout(5 * time.Second)).Compile(`findings.any(lambda f: f.severity == 'high') and meta.has_tag('pii')`)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				got, err := prog.Evaluate(context.Background(), env)
				if err != nil {
					t.Errorf("concurrent eval: %v", err)
					return
				}
				if !got {
					t.Error("concurrent eval: inconsistent result")
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestStarlarkConcurrentEvaluationsRespectWorkerLimit proves the evaluation
// semaphore invariant deterministically (FIX-13). The test-only evalProbe
// hook parks every evaluation while its slot is held, so the test
// synchronizes on acquire/release events instead of sampling len(evalSlots)
// every millisecond — the old sampling loop could miss the short
// 2-concurrent window entirely and observe 1 on a loaded or race-instrumented
// machine.
//
// Phases:
//  1. exactly two evaluations acquire slots and park (limit reached and
//     observed, not guessed);
//  2. with both slots held, no third evaluation acquires one (the semaphore
//     never over-issues);
//  3. releasing the holders lets the two waiters acquire the freed slots
//     (no lost wakeup, no slot leak) and everything drains.
func TestStarlarkConcurrentEvaluationsRespectWorkerLimit(t *testing.T) {
	e := New(WithMaxWorkers(2), WithStepLimit(1_000_000), WithEvalTimeout(2*time.Second))
	prog, err := e.Compile(`True`)
	if err != nil {
		t.Fatal(err)
	}

	var (
		running     atomic.Int64 // evaluations currently holding a slot
		maxObserved atomic.Int64 // high-water mark of the counter above
	)
	acquired := make(chan struct{}) // unbuffered: a receive pins one holder to its slot
	hold := make(chan struct{})     // closed once to release every parked holder

	e.evalProbe = func(event evalProbeEvent) {
		switch event {
		case probeAcquired:
			n := running.Add(1)
			for {
				m := maxObserved.Load()
				if n <= m || maxObserved.CompareAndSwap(m, n) {
					break
				}
			}
			acquired <- struct{}{} // announce the holder (blocks until observed)
			<-hold                 // keep holding the slot until the test releases
		case probeReleased:
			running.Add(-1)
		}
	}

	const goroutines = 4
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Go(func() {
			if _, err := prog.Evaluate(context.Background(), testEnv()); err != nil {
				t.Errorf("Evaluate(): %v", err)
			}
		})
	}

	// Phase 1: the first two goroutines hold the only two slots.
	waitAcquired(t, acquired, 2)
	if got := running.Load(); got != 2 {
		t.Fatalf("parked evaluations = %d, want 2", got)
	}

	// Phase 2: with both slots held, no third acquire may arrive. If the
	// semaphore over-issued, the third hook would already be blocked sending
	// on the unbuffered channel and this receive would catch it.
	select {
	case <-acquired:
		t.Fatal("worker limit over-issued: a third evaluation acquired a slot while two were held")
	case <-time.After(100 * time.Millisecond):
	}

	// Phase 3: release the holders; the two waiters must acquire the freed
	// slots and everything must drain without hangs or slot leaks.
	close(hold)
	waitAcquired(t, acquired, 2)
	drained := make(chan struct{})
	go func() { wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("evaluations did not drain: hang or evaluation-slot leak")
	}
	if got := running.Load(); got != 0 {
		t.Fatalf("running evaluations after drain = %d, want 0 (slot leak)", got)
	}
	if got := maxObserved.Load(); got != 2 {
		t.Fatalf("maximum observed workers = %d, want 2", got)
	}
}

// TestStarlarkCancelWhileWaitingForEvaluationSlot pins the cancel path of the
// worker-limit semaphore (FIX-13 acceptance: completion *and* cancellation
// must leave no hangs and no slot leaks). An evaluation blocked on a
// saturated semaphore must return promptly when its caller context is
// cancelled, must never have taken a slot, and must leave the semaphore
// fully usable afterwards. Event-driven via the same test-only evalProbe
// hook as the worker-limit test: no sampling, every wait deadline-guarded.
func TestStarlarkCancelWhileWaitingForEvaluationSlot(t *testing.T) {
	e := New(WithMaxWorkers(1), WithStepLimit(1_000_000), WithEvalTimeout(2*time.Second))
	prog, err := e.Compile(`True`)
	if err != nil {
		t.Fatal(err)
	}

	var running atomic.Int64
	acquired := make(chan struct{}) // unbuffered: a receive pins one acquisition
	hold := make(chan struct{})     // closed once to release the parked holder

	e.evalProbe = func(event evalProbeEvent) {
		switch event {
		case probeAcquired:
			running.Add(1)
			acquired <- struct{}{} // announce the holder (blocks until observed)
			<-hold                 // keep holding the only slot until released
		case probeReleased:
			running.Add(-1)
		}
	}

	// Holder: takes the only slot and parks in the probe.
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		if _, err := prog.Evaluate(context.Background(), testEnv()); err != nil {
			t.Errorf("holder Evaluate(): %v", err)
		}
	}()
	waitAcquired(t, acquired, 1)

	// Waiter: blocks on the saturated semaphore with a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := prog.Evaluate(ctx, testEnv())
		waiterDone <- err
	}()

	// While the holder keeps the only slot, the waiter must not acquire:
	// a receive here would mean the semaphore over-issued. (Bounded negative
	// check — the only way to assert absence.)
	select {
	case <-acquired:
		t.Fatal("worker limit over-issued: a cancelled-later waiter acquired the held slot")
	case <-time.After(50 * time.Millisecond):
	}

	// Cancel the waiter: it must return promptly with the caller-context
	// error. The holder still parks on hold, so the semaphore has no free
	// slot — the select must resolve through ctx.Done, deterministically.
	cancel()
	select {
	case err := <-waiterDone:
		if err == nil || !strings.Contains(err.Error(), "caller context") {
			t.Fatalf("cancelled waiter error = %v, want caller-context abort", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return: hang while blocked on the worker-limit semaphore")
	}

	// The cancelled evaluation must not have taken or leaked a slot: after
	// the holder releases, exactly one further acquisition (the probe below)
	// is observable, it completes, and running drains to zero.
	close(hold)
	<-holderDone
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		if _, err := prog.Evaluate(context.Background(), testEnv()); err != nil {
			t.Errorf("post-cancel Evaluate(): %v", err)
		}
	}()
	waitAcquired(t, acquired, 1)
	select {
	case <-probeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("post-cancel evaluation did not drain: stolen or leaked slot")
	}
	if got := running.Load(); got != 0 {
		t.Fatalf("running evaluations after drain = %d, want 0 (slot leak)", got)
	}
}

// waitAcquired receives n acquire events or fails the test on a bounded
// timeout; every wait in the test is deadline-guarded, so it cannot hang.
func waitAcquired(t *testing.T, acquired <-chan struct{}, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-acquired:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for acquire event %d of %d", i+1, n)
		}
	}
}

func TestStarlarkEvalTimeoutHonorsCallerContext(t *testing.T) {
	// The caller cancellation must be the first budget to expire in this test.
	// Watchdog enforcement has its own dedicated regression test.
	prog, err := New(WithStepLimit(1<<30), WithEvalTimeout(5*time.Second)).Compile(`len([x for x in range(1000 * 1000 * 1000)]) > 0`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = prog.Evaluate(ctx, testEnv())
	if err == nil || !strings.Contains(err.Error(), "caller context") {
		t.Fatalf("want caller-context abort, got: %v", err)
	}
}
