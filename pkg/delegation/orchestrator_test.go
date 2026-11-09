package delegation

import (
	"context"
	"testing"
	"time"
)

func TestOrchestrator_DelegateFakeAnalyze(t *testing.T) {
	o := NewOrchestrator("/tmp/ws", NewFakeExecutor("codex"), NewFakeExecutor("cursor"))
	out, err := o.Delegate(context.Background(), Request{Task: "summarize pkg/gateway", Mode: ModeAnalyze, Provider: ProviderAuto})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.Executor != "codex" {
		t.Fatalf("got %+v", out)
	}
	if out.SelectReason != "auto:codex" {
		t.Fatalf("reason=%q", out.SelectReason)
	}
	if len(out.ChangedFiles) != 0 {
		t.Fatalf("fake must not report writes: %v", out.ChangedFiles)
	}
}

func TestOrchestrator_ExplicitCursor(t *testing.T) {
	o := NewOrchestrator("/tmp/ws", NewFakeExecutor("codex"), NewFakeExecutor("cursor"))
	out, err := o.Delegate(context.Background(), Request{Task: "review", Mode: ModeImplement, Provider: ProviderCursor})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executor != "cursor" || out.SelectReason != "explicit:cursor" {
		t.Fatalf("got %+v", out)
	}
}

func TestOrchestrator_RejectsEmptyTaskAndBadMode(t *testing.T) {
	o := NewOrchestrator("/tmp/ws", NewFakeExecutor("codex"))
	if _, err := o.Delegate(context.Background(), Request{}); err == nil {
		t.Fatal("expected error for empty task")
	}
	if _, err := o.Delegate(context.Background(), Request{Task: "x", Mode: "full_access"}); err == nil {
		t.Fatal("expected error for destructive mode")
	}
}

func TestOrchestrator_NilIsDisabled(t *testing.T) {
	var o *Orchestrator
	out, err := o.Delegate(context.Background(), Request{Task: "x"})
	if err != nil {
		t.Fatalf("disabled orchestrator must not error: %v", err)
	}
	if out.Status != "disabled" {
		t.Fatalf("status=%q", out.Status)
	}
}

func TestHealth_Cooldown(t *testing.T) {
	h := NewHealth()
	h.MarkFailure(ProviderCodex, context.DeadlineExceeded, 50*time.Millisecond)
	if h.Healthy(ProviderCodex) {
		t.Fatal("expected cooldown")
	}
	time.Sleep(60 * time.Millisecond)
	if !h.Healthy(ProviderCodex) {
		t.Fatal("cooldown should have expired")
	}
}

func TestOrchestrator_FillsTrustedWorkspace(t *testing.T) {
	cap := &captureExec{name: "codex"}
	o := NewOrchestrator("/trusted/root", cap)
	_, err := o.Delegate(context.Background(), Request{Task: "x", Workspace: "/untrusted/escape"})
	if err != nil {
		t.Fatal(err)
	}
	if cap.got != "/trusted/root" {
		t.Fatalf("workspace=%q, client path must be ignored", cap.got)
	}
}

type captureExec struct {
	name string
	got  string
}

func (c *captureExec) Name() string { return c.name }

func (c *captureExec) Available(context.Context) bool { return true }

func (c *captureExec) Run(_ context.Context, req Request) (Result, error) {
	c.got = req.Workspace
	return Result{Status: "ok"}, nil
}

// statusExec returns a configured status with a nil Go error.
type statusExec struct {
	name   string
	status string
}

func (s *statusExec) Name() string { return s.name }

func (s *statusExec) Available(context.Context) bool { return true }

func (s *statusExec) Run(_ context.Context, _ Request) (Result, error) {
	return Result{Status: s.status}, nil
}

// TP-17: a transport-successful call whose result is not explicitly ok must
// fail the delegation (never be rewritten to ok) and mark the executor
// unhealthy so auto-selection backs off.
func TestTP17_DelegateRejectsNonOKStatus(t *testing.T) {
	for _, status := range []string{"", "error", "unknown"} {
		t.Run("status_"+status, func(t *testing.T) {
			o := NewOrchestrator("/tmp/ws", &statusExec{name: "codex", status: status})
			out, err := o.Delegate(context.Background(), Request{Task: "x", Provider: ProviderCodex})
			if err == nil {
				t.Fatalf("status %q with nil Go error must fail the delegation", status)
			}
			if out.Status == "ok" {
				t.Fatalf("status %q must never become ok: %+v", status, out)
			}
			if out.Error == "" {
				t.Fatalf("a rejected result must carry an honest error: %+v", out)
			}
			// Cooldown: the second explicit attempt must refuse the executor.
			if _, err := o.Delegate(context.Background(), Request{Task: "x", Provider: ProviderCodex}); err == nil {
				t.Fatal("executor with invalid result status must enter cooldown")
			}
		})
	}
}

// Auto failover continues past an executor that returns a non-ok status
// with a nil Go error: the next healthy provider takes over.
func TestTP17_DelegateFailoverOnBadStatus(t *testing.T) {
	o := NewOrchestrator("/tmp/ws", &statusExec{name: "codex", status: "error"}, &captureExec{name: "cursor"})
	out, err := o.Delegate(context.Background(), Request{Task: "x", Provider: ProviderAuto})
	if err != nil {
		t.Fatalf("failover must reach cursor: %v", err)
	}
	if out.Status != "ok" || out.Executor != "cursor" || out.SelectReason != "failover:cursor" {
		t.Fatalf("got %+v", out)
	}
}
