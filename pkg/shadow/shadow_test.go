package shadow

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
)

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func baseConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.Model = "gpt-4o"
	c.SampleRate = 1.0
	c.Timeout = 500 * time.Millisecond
	c.MaxConcurrent = 2
	return c
}

func mustValidate(t *testing.T, c Config) Config {
	t.Helper()
	vc, err := c.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	return vc
}

// --- Config -------------------------------------------------------------------

func TestConfigValidate_HardErrorEnabledWithoutModel(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.Model = ""
	if _, err := c.Validate(); err == nil {
		t.Fatal("expected error for enabled-without-model")
	}
}

func TestConfigValidate_Clamp(t *testing.T) {
	c := baseConfig()
	c.SampleRate = 7.0
	c.MaxConcurrent = 0
	c.Timeout = -1
	c.DailyBudgetUSD = -5
	vc, err := c.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vc.SampleRate != 1 {
		t.Errorf("SampleRate = %v, want 1 (clamped)", vc.SampleRate)
	}
	if vc.MaxConcurrent != 1 {
		t.Errorf("MaxConcurrent = %d, want 1", vc.MaxConcurrent)
	}
	if vc.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s default", vc.Timeout)
	}
	if vc.DailyBudgetUSD != 0 {
		t.Errorf("DailyBudgetUSD = %v, want 0", vc.DailyBudgetUSD)
	}
}

func TestConfigValidate_NaN(t *testing.T) {
	c := baseConfig()
	c.SampleRate = math.NaN()
	vc, _ := c.Validate()
	if vc.SampleRate != 0 {
		t.Errorf("NaN SampleRate = %v, want 0", vc.SampleRate)
	}
}

// --- NewDispatcher validation ---------------------------------------------------

// TestNewDispatcher_ClampsInvalidConfig pins the W-SHADOW fix: a raw, never
// validated Config used to build a zero-capacity semaphore (MaxConcurrent=0 =
// unbuffered channel), so every Run blocked past the 250ms grace window,
// skipped, and its waiter goroutine hung on the channel forever. NewDispatcher
// must clamp exactly like Validate — including on the enabled-without-model
// error path, which returns before any clamping happens there.
func TestNewDispatcher_ClampsInvalidConfig(t *testing.T) {
	d := NewDispatcher(Config{Enabled: true, Model: "gpt-4o", SampleRate: 1}, testLogger())
	if cap(d.sem) != 1 {
		t.Fatalf("sem capacity = %d, want 1 (MaxConcurrent=0 must clamp)", cap(d.sem))
	}
	if d.cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s default", d.cfg.Timeout)
	}

	// The hard-error path (enabled without a model) must still produce a
	// usable, clamped dispatcher instead of a zero-capacity one.
	bad := NewDispatcher(Config{Enabled: true}, testLogger())
	if cap(bad.sem) != 1 {
		t.Fatalf("sem capacity on invalid config = %d, want 1", cap(bad.sem))
	}

	// Behavioral proof: a call must actually execute (pre-fix every Run hit
	// the semaphore grace timeout and skipped).
	called := false
	job := Job{
		RequestID:   "req-clamp",
		ShadowModel: "gpt-4o",
		Call: func(ctx context.Context) ([]byte, error) {
			called = true
			return []byte("{}"), nil
		},
	}
	d.Run(job)
	if !called {
		t.Error("Call skipped on a clamped dispatcher — semaphore never usable")
	}
}

// --- ShouldMirror gates ---------------------------------------------------------

func TestShouldMirror_AllGates(t *testing.T) {
	// Note: there is no "streaming" gate. The primary's transport is not part
	// of the decision — a shadow call is always a plain non-streaming request
	// to the candidate, so a streaming primary is mirrored like any other.
	cases := []struct {
		name        string
		mutate      func(d *Dispatcher)
		model       string
		orgID       string
		wantMirror  bool
		wantSkip    string
		pinnedCalls int
	}{
		{"disabled", func(d *Dispatcher) { d.SetEnabled(false) }, "gpt-4o-mini", "o1", false, SkipDisabled, 0},
		{"same model", nil, "gpt-4o", "o1", false, SkipSameModel, 0},
		{"sample miss", func(d *Dispatcher) {
			d.randFn = func() float64 { return 0.99 }
			d.cfg.SampleRate = 0.5
		}, "gpt-4o-mini", "o1", false, SkipSampling, 0},
		{"sample hit at edge", func(d *Dispatcher) {
			d.randFn = func() float64 { return 0.5 }
		}, "gpt-4o-mini", "o1", true, SkipNone, 1},
		{"pinned org", nil, "gpt-4o-mini", "pinned-org", false, SkipResidency, 1},
		{"global org passes", nil, "gpt-4o-mini", "global-org", true, SkipNone, 1},
		{"empty org skips pin check", nil, "gpt-4o-mini", "", true, SkipNone, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
			var pinnedCalls int32
			d.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool {
				atomic.AddInt32(&pinnedCalls, 1)
				return orgID == "pinned-org"
			})
			if tc.mutate != nil {
				tc.mutate(d)
			}
			got, skip := d.ShouldMirror(context.Background(), tc.model, tc.orgID)
			if got != tc.wantMirror {
				t.Errorf("mirror = %v, want %v (skip=%q)", got, tc.wantMirror, skip)
			}
			if skip != tc.wantSkip {
				t.Errorf("skip = %q, want %q", skip, tc.wantSkip)
			}
			if n := int(atomic.LoadInt32(&pinnedCalls)); n != tc.pinnedCalls {
				t.Errorf("pinned calls = %d, want %d", n, tc.pinnedCalls)
			}
		})
	}
}

// --- Run: outcomes ---------------------------------------------------------------

func okJob(d *Dispatcher) Job {
	return Job{
		RequestID:    "req-1",
		SessionID:    "sess-1",
		OrgID:        "org-1",
		TeamID:       "team-1",
		PrimaryModel: "gpt-4o-mini",
		ShadowModel:  "gpt-4o",
		Body:         []byte(`{"model":"gpt-4o-mini","messages":[]}`),
		Call: func(ctx context.Context) ([]byte, error) {
			return []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`), nil
		},
		ParseUsage: func(body []byte) provider.Usage {
			return provider.Usage{PromptTokens: 10, CompletionTokens: 5}
		},
		ComputeCost: func(u provider.Usage, p, m string) float64 { return 0.01 },
	}
}

func TestRun_CompletedPublishesEvent(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	var mu sync.Mutex
	var gotReqID, gotModel, gotAB, gotSrc string
	var gotCost float64
	var gotIn, gotOut int64
	job := okJob(d)
	job.Publish = func(ev *eventpub.Event) {
		mu.Lock()
		defer mu.Unlock()
		gotReqID, gotModel, gotAB, gotSrc = ev.RequestID, ev.ModelUsed, ev.ABGroup, ev.EventType
		gotCost, gotIn, gotOut = ev.EstimatedCostUSD, ev.TokensIn, ev.TokensOut
	}
	d.Run(job)
	mu.Lock()
	defer mu.Unlock()
	if gotReqID != "req-1" || gotModel != "gpt-4o" || gotAB != "shadow" || gotSrc != "request.shadow_completed" {
		t.Errorf("event = (%q, %q, %q, %q), want (req-1, gpt-4o, shadow, request.shadow_completed)",
			gotReqID, gotModel, gotAB, gotSrc)
	}
	if gotCost != 0.01 {
		t.Errorf("cost = %v, want 0.01", gotCost)
	}
	if gotIn != 10 || gotOut != 5 {
		t.Errorf("tokens = (%d,%d), want (10,5)", gotIn, gotOut)
	}
}

func TestRun_ErrorOutcome(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	job := okJob(d)
	job.Call = func(ctx context.Context) ([]byte, error) { return nil, errors.New("upstream down") }
	d.Run(job) // must not panic
}

func TestRun_TimeoutOutcome(t *testing.T) {
	c := baseConfig()
	c.Timeout = 20 * time.Millisecond
	d := NewDispatcher(mustValidate(t, c), testLogger())
	job := okJob(d)
	job.Call = func(ctx context.Context) ([]byte, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return []byte("{}"), nil
		}
	}
	done := make(chan struct{})
	go func() { d.Run(job); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after timeout")
	}
}

func TestRun_PanicRecovered(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	job := okJob(d)
	job.Call = func(ctx context.Context) ([]byte, error) { panic("boom") }
	d.Run(job) // must not panic
}

func TestRun_DisabledIsNoop(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	d.SetEnabled(false)
	called := false
	job := okJob(d)
	job.Call = func(ctx context.Context) ([]byte, error) { called = true; return nil, nil }
	d.Run(job)
	if called {
		t.Error("Call executed while disabled")
	}
}

// --- Concurrency cap ---------------------------------------------------------------

func TestRun_SemaphoreBoundsInFlight(t *testing.T) {
	c := baseConfig()
	c.MaxConcurrent = 2
	c.Timeout = 2 * time.Second
	d := NewDispatcher(mustValidate(t, c), testLogger())

	var mu sync.Mutex
	var inFlight, maxInFlight int
	release := make(chan struct{})
	job := okJob(d)
	job.Call = func(ctx context.Context) ([]byte, error) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
		return []byte("{}"), nil
	}

	// Wave 1: two Run goroutines grab both semaphore slots and block inside
	// Call. Wave 2: fired while both slots are still held — both waiters must
	// hit the 250ms grace deadline and skip (their calls never start).
	fireWave := func() *sync.WaitGroup {
		wg := &sync.WaitGroup{}
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); d.Run(job) }()
		}
		return wg
	}
	wg1 := fireWave()
	time.Sleep(30 * time.Millisecond)  // wave-1 holds both slots
	wg2 := fireWave()                  // waiters: no slot for > 250ms
	time.Sleep(400 * time.Millisecond) // let the grace window elapse
	close(release)
	wg1.Wait()
	wg2.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight != 2 {
		t.Errorf("max in-flight = %d, want exactly 2 (wave 1 parallel, wave 2 skipped)", maxInFlight)
	}
}

// TestRun_SemaphoreCapacitySurvivesGraceTimeouts pins the W-SHADOW leak: a
// waiter that lost the 250ms grace race used to keep the slot it later won
// (its deferred drain never ran), permanently shrinking capacity until every
// future Run skipped. With MaxConcurrent=1, 100 calls in saturated waves must
// keep the single slot serving work: every wave completes at least one call
// and a final probe call still runs.
func TestRun_SemaphoreCapacitySurvivesGraceTimeouts(t *testing.T) {
	c := baseConfig()
	c.MaxConcurrent = 1
	c.Timeout = 5 * time.Second
	d := NewDispatcher(mustValidate(t, c), testLogger())

	const (
		waves   = 5
		perWave = 20 // 100 shadow calls total
	)
	var completed atomic.Int64
	newJob := func() Job {
		job := okJob(d)
		job.Call = func(ctx context.Context) ([]byte, error) {
			completed.Add(1)
			time.Sleep(20 * time.Millisecond) // hold the slot briefly
			return []byte("{}"), nil
		}
		return job
	}

	for w := 0; w < waves; w++ {
		before := completed.Load()
		var wg sync.WaitGroup
		wg.Add(perWave)
		for i := 0; i < perWave; i++ {
			go func() { defer wg.Done(); d.Run(newJob()) }()
		}
		wg.Wait()
		if completed.Load() == before {
			t.Fatalf("wave %d: zero calls completed — the semaphore slot is stranded", w+1)
		}
		// Let the wave's late waiters and slot drains settle before the next
		// wave (≥ one 250ms grace window).
		time.Sleep(300 * time.Millisecond)
	}

	before := completed.Load()
	d.Run(newJob())
	if got := completed.Load(); got != before+1 {
		t.Fatalf("post-wave probe: completed=%d, want %d — capacity never came back", got, before+1)
	}
}

// --- Event status code -----------------------------------------------------------

// TestRun_EventStatusCodeReportsOutcome pins the W-SHADOW status fix: the
// shadow event carries the upstream status the job actually reported; only a
// job without a reported status falls back to the completed-call 200.
func TestRun_EventStatusCodeReportsOutcome(t *testing.T) {
	cases := []struct {
		name    string
		jobCode int
		want    int64
	}{
		{"reported upstream status", 201, 201},
		{"unknown falls back to completed-call 200", 0, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
			var got int64
			job := okJob(d)
			job.StatusCode = tc.jobCode
			job.Publish = func(ev *eventpub.Event) { got = ev.StatusCode }
			d.Run(job)
			if got != tc.want {
				t.Errorf("event status = %d, want %d", got, tc.want)
			}
		})
	}
}

// --- Budget --------------------------------------------------------------------------

func TestRun_BudgetExhaustionSkips(t *testing.T) {
	c := baseConfig()
	c.DailyBudgetUSD = 0.02
	c.MaxConcurrent = 8 // headroom so serial budget tests never hit the grace window
	d := NewDispatcher(mustValidate(t, c), testLogger())
	job := okJob(d) // costs 0.01 per call

	// The exhaustion logic is ledger-driven: the ledger is set directly (it is
	// the unit under test) and the real Call/ParseUsage/ComputeCost pipeline
	// only proves that allowed calls execute and record spend.
	calls := 0
	job.Call = func(ctx context.Context) ([]byte, error) {
		calls++
		return []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`), nil
	}
	setLedgerMicro := func(micro int64) {
		d.budget.mu.Lock()
		d.budget.microUSD = micro
		d.budget.mu.Unlock()
	}
	// Directly exercise the ledger guard (the unit under test): the real
	// Call pipeline only proves that an allowed decision leads to a call.
	if !d.budget.hasHeadroom(c.DailyBudgetUSD) {
		t.Fatal("fresh budget must have headroom")
	}
	d.budget.add(0.02) // spend up to the exact limit
	if d.budget.hasHeadroom(c.DailyBudgetUSD) {
		t.Fatal("budget at the limit must report no headroom (strict <)")
	}
	d.budget.add(-1) // no-op for negative
	if d.budget.hasHeadroom(c.DailyBudgetUSD) {
		t.Fatal("negative add must not create headroom")
	}

	// End-to-end: with an exhausted ledger Run must skip without calling.
	setLedgerMicro(toMicro(c.DailyBudgetUSD))
	d.Run(job)
	if calls != 0 {
		t.Errorf("Run with exhausted budget: calls=%d, want 0", calls)
	}
	// ...and with a fresh ledger it must call.
	setLedgerMicro(0)
	d.Run(job)
	if calls != 1 {
		t.Errorf("Run with fresh budget: calls=%d, want 1", calls)
	}
}

// --- O00: budget unit correctness (micro-USD canonical) ------------------------

// TestBudget_OneCentsLeavesHeadroom pins the confirmed pre-O00 defect:
// $0.01 spent of a $1.00 daily limit must leave headroom. The old
// float64(cents) < limitUSD comparison blocked here (1 < 1 is false at
// cents=1).
func TestBudget_OneCentsLeavesHeadroom(t *testing.T) {
	var now atomic.Value
	now.Store(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	clock := func() time.Time { return now.Load().(time.Time) }
	d.nowFn = clock
	d.budget.nowFn = clock

	d.budget.add(0.01) // $0.01 of the $1.00 limit
	if !d.budget.hasHeadroom(1.0) {
		t.Fatal("$0.01 of a $1.00 limit must leave headroom (pre-O00 this blocked after $0.01)")
	}
	if got := d.budget.spentUSD(); got < 0.01 {
		t.Fatalf("spentUSD = %v, want >= 0.01", got)
	}
}

// TestBudget_MicroCostAccumulationReachesLimit pins the second pre-O00
// defect: 100 calls of $0.00002 ($0.000002 micro-USD each is sub-cent) must
// accumulate to $0.002 and exhaust a $0.002 limit. Per-operation truncation
// to cents rounded every one of these to 0 and the budget never fired.
func TestBudget_MicroCostAccumulationReachesLimit(t *testing.T) {
	var now atomic.Value
	now.Store(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	clock := func() time.Time { return now.Load().(time.Time) }
	d.nowFn = clock
	d.budget.nowFn = clock

	const limitUSD = 0.002
	for i := 0; i < 100; i++ {
		d.budget.add(0.00002)
	}
	if d.budget.hasHeadroom(limitUSD) {
		t.Fatalf("100 x $0.00002 = $0.002 must exhaust the $%v limit (spent=%v)", limitUSD, d.budget.spentUSD())
	}
	// And just before the last call there was still headroom — the budget
	// trips exactly at the boundary, not earlier.
	d.budget.add(-0.00002 * 0) // no-op; boundary re-check below instead
	d.budget.mu.Lock()
	d.budget.microUSD = toMicro(99 * 0.00002)
	d.budget.mu.Unlock()
	if !d.budget.hasHeadroom(limitUSD) {
		t.Fatal("99 x $0.00002 = $0.00198 must still have headroom under the $0.002 limit")
	}
}

// TestBudget_ZeroAndOff keep the original semantics: limit 0 = unlimited;
// negative costs and NaN are ignored.
func TestBudget_ZeroAndOff(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	if !d.budget.hasHeadroom(0) {
		t.Fatal("limit 0 must be unlimited")
	}
	d.budget.add(-5)
	d.budget.add(math.NaN())
	if got := d.budget.spentUSD(); got != 0 {
		t.Fatalf("negative/NaN adds must not count, spent=%v", got)
	}
}

// TestBudget_ConcurrentAddIsConsistent hammers add() from many goroutines and
// checks the exact sum (micro-USD is additive integer math; the mutex must
// keep it race-free and exact).
func TestBudget_ConcurrentAddIsConsistent(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	const (
		goroutines = 32
		perG       = 500
		cost       = 0.000003 // $0.000003 = 3 micro-USD
	)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				d.budget.add(cost)
			}
		}()
	}
	wg.Wait()
	want := toMicro(cost) * int64(goroutines*perG)
	d.budget.mu.Lock()
	got := d.budget.microUSD
	d.budget.mu.Unlock()
	if got != want {
		t.Fatalf("concurrent adds: microUSD=%d, want %d", got, want)
	}
}

func TestBudget_RollsAtUTCMidnight(t *testing.T) {
	var now atomic.Value
	now.Store(time.Date(2026, 8, 30, 23, 59, 0, 0, time.UTC))
	c := baseConfig()
	c.DailyBudgetUSD = 1.0
	d := NewDispatcher(mustValidate(t, c), testLogger())
	clock := func() time.Time { return now.Load().(time.Time) }
	d.nowFn = clock
	d.budget.nowFn = clock // budget uses the same frozen clock

	job := okJob(d)
	d.Run(job)
	if d.Status().BudgetUsedUSD < 0.01 {
		t.Fatal("expected spend recorded")
	}

	now.Store(time.Date(2026, 8, 31, 0, 0, 1, 0, time.UTC))
	if got := d.Status().BudgetUsedUSD; got != 0 {
		t.Errorf("budget after UTC midnight = %v, want 0", got)
	}
	if d.Status().Day != "2026-08-31" {
		t.Errorf("day = %q, want 2026-08-31", d.Status().Day)
	}
}

func TestStatus_NoAPIKey(t *testing.T) {
	c := baseConfig()
	c.APIKey = "sk-secret-should-not-appear"
	d := NewDispatcher(mustValidate(t, c), testLogger())
	b, err := json.Marshal(d.Status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret") {
		t.Errorf("status JSON leaked the API key: %s", b)
	}
}

// --- Runtime toggle ---------------------------------------------------------------------

func TestSetEnabled_TogglesState(t *testing.T) {
	d := NewDispatcher(mustValidate(t, baseConfig()), testLogger())
	if !d.Enabled() {
		t.Fatal("expected enabled by default from config")
	}
	d.SetEnabled(false)
	if d.Enabled() {
		t.Error("still enabled after SetEnabled(false)")
	}
	d.SetEnabled(true)
	if !d.Enabled() {
		t.Error("not enabled after SetEnabled(true)")
	}
}
