package controller

// TP-17 regression tests: an incomplete or failed executor result must never
// become a done step or an accepted episode — transport success (nil Go
// error) is not run success.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/delegation"
)

// statusFake returns a configured result status with a nil Go error — the
// exact boundary violation the controller must guard against.
type statusFake struct {
	status string
	calls  int
}

func (f *statusFake) Name() string                   { return "status" }
func (f *statusFake) Available(context.Context) bool { return true }
func (f *statusFake) Run(_ context.Context, _ delegation.Request) (delegation.Result, error) {
	f.calls++
	return delegation.Result{Status: f.status, Summary: "transport ok, run not"}, nil
}

func newIntegrityController(t *testing.T, exec delegation.Executor) *Controller {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return New(store, exec, "h-tp17", 40*time.Millisecond)
}

// Empty, unknown and error statuses arriving with a nil Go error fail the
// step and the episode honestly — never done, never accepted.
func TestTP17_NonOKResultStatusFailsStepAndEpisode(t *testing.T) {
	for _, tc := range []struct {
		status string
		id     string
	}{
		{status: "", id: "tp17-empty"},
		{status: "error", id: "tp17-error"},
		{status: "unknown", id: "tp17-unknown"},
	} {
		t.Run(tc.status+"_nil_go_error", func(t *testing.T) {
			exec := &statusFake{status: tc.status}
			ctl := newIntegrityController(t, exec).WithAutoAccept(true)
			e, err := ctl.Start(tc.id, "task", delegation.ModeAnalyze, "")
			if err != nil {
				t.Fatal(err)
			}
			e, err = ctl.Run(context.Background(), e)
			if err == nil {
				t.Fatalf("status %q with nil Go error must fail the run", tc.status)
			}
			if e.State != StateFailed {
				t.Fatalf("state = %s, want failed", e.State)
			}
			step := e.Steps[0]
			if step.Status != "failed" {
				t.Fatalf("step status = %s, want failed", step.Status)
			}
			if step.Result == nil || step.Result.Status != tc.status {
				t.Fatalf("step result must record the raw status %q: %+v", tc.status, step.Result)
			}
		})
	}
}

// The auto-accept policy table: only the fully successful permitted
// scenario closes itself; every incomplete/failed/honest-marker variant
// stays in awaiting_review — and none of them panics.
func TestTP17_AutoAcceptRejectsIncompleteResults(t *testing.T) {
	policy := AutoAcceptPolicy{Enabled: true}
	okResult := &delegation.Result{Status: "ok", Summary: "clean"}

	newEpisode := func(mutate func(*Episode)) *Episode {
		e := &Episode{
			Mode:  delegation.ModeAnalyze,
			State: StateAwaiting,
			Steps: []StepRecord{{Index: 0, Name: "analyze", Status: "done", Result: okResult}},
		}
		e.FinalResult = okResult
		if mutate != nil {
			mutate(e)
		}
		return e
	}

	cases := []struct {
		name    string
		episode *Episode
		want    bool
	}{
		{"permitted successful analyze", newEpisode(nil), true},
		{"nil episode", nil, false},
		{"nil final result", newEpisode(func(e *Episode) { e.FinalResult = nil }), false},
		{"empty status", newEpisode(func(e *Episode) { e.FinalResult = &delegation.Result{} }), false},
		{"error status", newEpisode(func(e *Episode) { e.FinalResult = &delegation.Result{Status: "error"} }), false},
		{"unknown status", newEpisode(func(e *Episode) { e.FinalResult = &delegation.Result{Status: "unknown"} }), false},
		{"skipped validation", newEpisode(func(e *Episode) {
			e.FinalResult = &delegation.Result{Status: "ok", Validation: "skipped"}
		}), false},
		{"writes recorded", newEpisode(func(e *Episode) {
			e.FinalResult = &delegation.Result{Status: "ok", Wrote: true}
		}), false},
		{"changed files recorded", newEpisode(func(e *Episode) {
			e.FinalResult = &delegation.Result{Status: "ok", ChangedFiles: []string{"a.go"}}
		}), false},
		{"mixed step results", newEpisode(func(e *Episode) { e.Steps[0].Status = "failed" }), false},
		{"pending step", newEpisode(func(e *Episode) { e.Steps[0].Status = "pending" }), false},
		{"implement mode", newEpisode(func(e *Episode) { e.Mode = delegation.ModeImplement }), false},
		{"still running", newEpisode(func(e *Episode) { e.State = StateRunning }), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.ShouldAutoAccept(tc.episode); got != tc.want {
				t.Fatalf("ShouldAutoAccept = %v, want %v", got, tc.want)
			}
		})
	}
	if (AutoAcceptPolicy{}).ShouldAutoAccept(newEpisode(nil)) {
		t.Fatal("disabled policy must never accept")
	}
}

// The skipped-validation marker is the honest sign of fake/simulated
// execution: it must survive verbatim through the step record and the final
// result (never rewritten into a passing claim), and the episode must stay
// in awaiting_review instead of self-certifying as done.
func TestTP17_SkippedValidationMarkerSurvivesHonestly(t *testing.T) {
	// The real FakeExecutor reports ok + validation skipped.
	ctl := newIntegrityController(t, delegation.NewFakeExecutor("codex")).WithAutoAccept(true)
	e, err := ctl.Start("tp17-fake", "task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err = ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("fake execution (validation skipped) must await review, got %s", e.State)
	}
	if e.FinalResult == nil || e.FinalResult.Validation != "skipped" {
		t.Fatalf("final result must keep the honest skipped marker: %+v", e.FinalResult)
	}
	if e.Steps[0].Result == nil || e.Steps[0].Result.Validation != "skipped" {
		t.Fatalf("step record must keep the honest skipped marker: %+v", e.Steps[0].Result)
	}
	// Persisted state keeps the marker too.
	persisted, err := ctl.Store().Load("tp17-fake")
	if err != nil {
		t.Fatal(err)
	}
	if persisted.FinalResult == nil || persisted.FinalResult.Validation != "skipped" {
		t.Fatalf("persisted final result must keep the skipped marker: %+v", persisted.FinalResult)
	}
}

// Re-running an episode that already finished its steps and awaits review is
// an idempotent no-op (safe resume on every state), not a transition error.
func TestTP17_RunOnAwaitingAllDoneIsIdempotent(t *testing.T) {
	exec := &okFake{}
	ctl := newIntegrityController(t, exec)
	e, err := ctl.Start("tp17-await", "task", delegation.ModeAnalyze, "")
	if err != nil {
		t.Fatal(err)
	}
	e, err = ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("state = %s, want awaiting_review", e.State)
	}
	calls := exec.calls
	e, err = ctl.Run(context.Background(), e)
	if err != nil {
		t.Fatalf("resume of awaiting episode must be a no-op, got %v", err)
	}
	if e.State != StateAwaiting {
		t.Fatalf("state = %s, want awaiting_review", e.State)
	}
	if exec.calls != calls {
		t.Fatalf("no-op resume must not run the executor again: %d -> %d", calls, exec.calls)
	}
}

// okFake is the plain successful executor (no validation claim).
type okFake struct{ calls int }

func (f *okFake) Name() string                   { return "ok" }
func (f *okFake) Available(context.Context) bool { return true }
func (f *okFake) Run(_ context.Context, _ delegation.Request) (delegation.Result, error) {
	f.calls++
	return delegation.Result{Status: "ok", Summary: "done"}, nil
}
