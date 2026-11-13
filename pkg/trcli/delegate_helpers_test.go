package trcli

// Unit tests for the helpers extracted from delegateCmd: error combination
// and worktree-diff rendering against real git worktrees.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/delegation/controller"
)

func TestCombineEpisodeErrors(t *testing.T) {
	runErr := errors.New("step 2 failed")
	evErr := errors.New("registry unreadable")

	if got := combineEpisodeErrors(nil, nil); got != nil {
		t.Errorf("both nil: want nil, got %v", got)
	}
	if got := combineEpisodeErrors(runErr, nil); !errors.Is(got, runErr) || got.Error() != "step 2 failed" {
		t.Errorf("run-only: want pass-through, got %v", got)
	}
	got := combineEpisodeErrors(nil, evErr)
	if !errors.Is(got, evErr) || got.Error() != "evidence: registry unreadable" {
		t.Errorf("evidence-only: want prefixed wrap, got %v", got)
	}
	got = combineEpisodeErrors(runErr, evErr)
	if !errors.Is(got, runErr) || !errors.Is(got, evErr) {
		t.Errorf("both: want both wrapped, got %v", got)
	}
	if want := "step 2 failed; evidence: registry unreadable"; got.Error() != want {
		t.Errorf("both: want %q, got %q", want, got.Error())
	}
}

// acquireWorktreeDiff returns a live worktree of a scratch repo plus a
// cleanup that releases its cross-process lock.
func acquireWorktreeDiff(t *testing.T, episodeID string) *controller.Workspace {
	t.Helper()
	repo := t.TempDir()
	if err := gitInit(repo); err != nil {
		t.Fatalf("git init: %v", err)
	}
	mgr, err := controller.NewWorkspaceManager(filepath.Join(t.TempDir(), "worktrees"))
	if err != nil {
		t.Fatalf("workspace manager: %v", err)
	}
	ws, err := mgr.Acquire(episodeID, repo)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = ws.Release() })
	return ws
}

func TestPrintWorktreeDiff(t *testing.T) {
	// nil workspace renders nothing (run without --repo).
	var buf bytes.Buffer
	printWorktreeDiff(&buf, nil, "diff:     ", "none (no files changed)")
	if buf.Len() != 0 {
		t.Errorf("nil workspace must print nothing, got %q", buf.String())
	}

	// Clean worktree: the none note under the given label.
	ws := acquireWorktreeDiff(t, "ep-clean")
	buf.Reset()
	printWorktreeDiff(&buf, ws, "diff:      ", "none")
	requireLine(t, buf.String(), "  diff:      none")

	// A modified tracked file: inventory line plus diffstat under run's
	// wider-alignment label.
	if err := os.WriteFile(filepath.Join(ws.Path, "README.md"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	printWorktreeDiff(&buf, ws, "diff:     ", "none (no files changed)")
	requireLine(t, buf.String(), "  diff:     README.md")
	requireLine(t, buf.String(), "  diffstat:")
	if !strings.Contains(buf.String(), "README.md | ") {
		t.Errorf("diffstat entry missing:\n%s", buf.String())
	}
}
