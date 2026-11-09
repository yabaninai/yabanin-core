package delegation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrchestrator_FailoverBeforeWrite(t *testing.T) {
	first := &scriptedExec{name: "codex", err: errors.New("quota_exhausted")}
	second := &scriptedExec{name: "cursor"}
	o := NewOrchestrator(t.TempDir(), first, second)
	out, err := o.Delegate(context.Background(), Request{Task: "x", Provider: ProviderAuto})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executor != "cursor" || out.SelectReason != "failover:cursor" {
		t.Fatalf("got %+v", out)
	}
	if first.runs != 1 || second.runs != 1 {
		t.Fatalf("runs first=%d second=%d", first.runs, second.runs)
	}
}

func TestOrchestrator_NoFailoverAfterWrite(t *testing.T) {
	first := &scriptedExec{name: "codex", err: errors.New("boom"), files: []string{"a.go"}}
	second := &scriptedExec{name: "cursor"}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := NewOrchestrator(root, first, second)
	out, err := o.Delegate(context.Background(), Request{Task: "x", Provider: ProviderAuto, Mode: ModeImplement})
	if err == nil {
		t.Fatal("expected error")
	}
	if out.Executor != "codex" {
		t.Fatalf("pinned to failing writer, got %+v", out)
	}
	if second.runs != 0 {
		t.Fatalf("failover after write is forbidden, cursor runs=%d", second.runs)
	}
}

func TestOrchestrator_StickyAfterWrite(t *testing.T) {
	codex := &scriptedExec{name: "codex", files: []string{"a.go"}}
	cursor := &scriptedExec{name: "cursor"}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := NewOrchestrator(root, cursor, codex)
	if _, err := o.Delegate(context.Background(), Request{Task: "x", Mode: ModeImplement, Provider: ProviderCodex}); err != nil {
		t.Fatal(err)
	}
	out, err := o.Delegate(context.Background(), Request{Task: "y", Mode: ModeImplement, Provider: ProviderAuto})
	if err != nil {
		t.Fatal(err)
	}
	if out.SelectReason != "pinned:codex" || out.Executor != "codex" {
		t.Fatalf("got %+v", out)
	}
}

func TestOrchestrator_WriteMutex(t *testing.T) {
	var inflight atomic.Int32
	var max atomic.Int32
	block := make(chan struct{})
	started := make(chan struct{}, 2)
	exec := &lockExec{
		name: "codex",
		run: func() {
			n := inflight.Add(1)
			for {
				cur := max.Load()
				if n <= cur || max.CompareAndSwap(cur, n) {
					break
				}
			}
			started <- struct{}{}
			<-block
			inflight.Add(-1)
		},
	}
	o := NewOrchestrator(t.TempDir(), exec)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, _ = o.Delegate(context.Background(), Request{Task: "x", Mode: ModeImplement})
		}()
	}
	<-started
	select {
	case <-started:
		t.Fatal("second implement started while first still held the write mutex")
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	wg.Wait()
	if max.Load() != 1 {
		t.Fatalf("overlapping writes: max inflight=%d", max.Load())
	}
}

func TestOrchestrator_DropsEscapingChangedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte("package ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exec := &scriptedExec{name: "codex", files: []string{filepath.Join(root, "ok.go"), "/etc/passwd"}}
	o := NewOrchestrator(root, exec)
	out, err := o.Delegate(context.Background(), Request{Task: "x", Mode: ModeImplement})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ChangedFiles) != 1 || out.ChangedFiles[0] != filepath.Join(root, "ok.go") {
		t.Fatalf("changed=%v", out.ChangedFiles)
	}
}

func TestOrchestrator_StatusOmitsSecrets(t *testing.T) {
	o := NewOrchestrator(t.TempDir(), NewFakeExecutor("codex"))
	st := o.Status(context.Background())
	if !st.Enabled || !st.Providers["codex"].Available {
		t.Fatalf("%+v", st)
	}
	raw := st.Providers["codex"].LastError
	if strings.Contains(raw, "sk-") || strings.Contains(raw, "cursor_") || strings.Contains(raw, "key=") {
		t.Fatalf("leaked secret in status: %q", raw)
	}
}

type scriptedExec struct {
	name  string
	err   error
	files []string
	runs  int
}

func (s *scriptedExec) Name() string { return s.name }

func (s *scriptedExec) Available(context.Context) bool { return true }

func (s *scriptedExec) Run(_ context.Context, _ Request) (Result, error) {
	s.runs++
	out := Result{Status: "ok", ChangedFiles: append([]string(nil), s.files...)}
	if s.err != nil {
		out.Status = "error"
		return out, s.err
	}
	return out, nil
}

type lockExec struct {
	name string
	run  func()
}

func (l *lockExec) Name() string { return l.name }

func (l *lockExec) Available(context.Context) bool { return true }

func (l *lockExec) Run(_ context.Context, _ Request) (Result, error) {
	l.run()
	return Result{Status: "ok", Wrote: true, ChangedFiles: []string{"a.go"}}, nil
}
