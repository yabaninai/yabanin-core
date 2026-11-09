package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// initGitRepo creates a throwaway repository with one commit.
func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		//nolint:gosec // G204: test fixture git against a temp dir.
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.invalid")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "base")
	return dir
}

func newMgr(t *testing.T) (*WorkspaceManager, string) {
	t.Helper()
	repo := initGitRepo(t)
	mgr, err := NewWorkspaceManager(filepath.Join(t.TempDir(), "wt"))
	if err != nil {
		t.Fatal(err)
	}
	return mgr, repo
}

func TestAcquireCreatesMarkedWorktree(t *testing.T) {
	mgr, repo := newMgr(t)
	ws, err := mgr.Acquire("ep-ws-1", repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Release() }()
	if _, err := os.Stat(filepath.Join(ws.Path, "README.md")); err != nil {
		t.Fatalf("worktree lacks the repo content: %v", err)
	}
	markerBytes, err := os.ReadFile(filepath.Join(ws.Path, markerFile))
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if !strings.Contains(string(markerBytes), `"ep-ws-1"`) {
		t.Fatalf("marker names a different episode: %s", markerBytes)
	}
}

func TestSecondAcquireWhileLockedIsBusy(t *testing.T) {
	mgr, repo := newMgr(t)
	ws, err := mgr.Acquire("ep-ws-2", repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Release() }()
	if _, err := mgr.Acquire("ep-ws-2", repo); err != ErrWorkspaceBusy {
		t.Fatalf("second acquire err = %v, want ErrWorkspaceBusy", err)
	}
	// After release the workspace is acquirable again (resume semantics).
	if err := ws.Release(); err != nil {
		t.Fatal(err)
	}
	ws2, err := mgr.Acquire("ep-ws-2", repo)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = ws2.Release()
}

// TestCrossProcessLock: a real child PROCESS holds the lock; the parent's
// acquire must report busy. Both sides carry hard deadlines so the test can
// never hang the suite.
func TestCrossProcessLock(t *testing.T) {
	if child := os.Getenv("WS_LOCK_CHILD"); child != "" {
		//nolint:gosec // G304: child path passed by the parent test's temp dir.
		fh, err := os.OpenFile(child, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			os.Exit(2)
		}
		if flockExNB(fh) != nil {
			os.Exit(3)
		}
		// Hold the lock until the stop file appears (10s hard cap).
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			//nolint:gosec // G304: child stop-file inside the test's temp dir.
			if _, err := os.Stat(child + ".go"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0)
	}

	mgr, repo := newMgr(t)
	ws, err := mgr.Acquire("ep-xproc", repo)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := ws.Path + ".lock"

	//nolint:gosec // G204: self-exec of the test binary (cross-process lock fixture).
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run", "^TestCrossProcessLock$", "-test.v")
	cmd.Env = append(os.Environ(), "WS_LOCK_CHILD="+lockPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = os.WriteFile(lockPath+".go", []byte("stop"), 0o600)
		}
		_ = cmd.Wait()
	}()

	// Release our lock, then wait until the CHILD demonstrably holds it:
	// a fresh non-blocking flock from this process must fail.
	if err := ws.Release(); err != nil {
		t.Fatal(err)
	}
	childHolds := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		//nolint:gosec // G304/G703: lockPath is inside the test's temp dir.
		probe, perr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if perr != nil {
			t.Fatal(perr)
		}
		busy := flockExNB(probe) != nil
		_ = probe.Close()
		if busy {
			childHolds = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !childHolds {
		t.Fatal("child never acquired the lock")
	}
	if _, err := mgr.Acquire("ep-xproc", repo); err != ErrWorkspaceBusy {
		t.Fatalf("acquire against a live child process lock err = %v, want ErrWorkspaceBusy", err)
	}
	// Stop the child deterministically before the deferred Wait.
	if err := os.WriteFile(lockPath+".go", []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopped = true
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exited badly: %v", err)
	}
	// With the child gone the workspace is acquirable again.
	ws2, err := mgr.Acquire("ep-xproc", repo)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws2.Release()
}

func TestDiffInventoriesActualChanges(t *testing.T) {
	mgr, repo := newMgr(t)
	ws, err := mgr.Acquire("ep-diff", repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Release() }()

	changed, _, err := ws.Diff()
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Fatalf("fresh worktree reports changes: %v", changed)
	}
	if err := os.WriteFile(filepath.Join(ws.Path, "README.md"), []byte("modified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws.Path, "new-file.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, _, err = ws.Diff()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(changed, ",")
	if !strings.Contains(joined, "README.md") || !strings.Contains(joined, "new-file.txt") {
		t.Fatalf("diff inventory = %q, want README.md and new-file.txt", joined)
	}
}

func TestRemoveRefusesForeignDirectories(t *testing.T) {
	mgr, repo := newMgr(t)
	ws, err := mgr.Acquire("ep-rm", repo)
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.Release()

	// A foreign directory under the root (no marker) must never be removed.
	foreign := mgr.pathFor("foreign-ep")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "precious.txt"), []byte("not mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Remove("foreign-ep"); err != ErrNotManagedWorkspace {
		t.Fatalf("foreign remove err = %v, want ErrNotManagedWorkspace", err)
	}
	if _, err := os.Stat(filepath.Join(foreign, "precious.txt")); err != nil {
		t.Fatal("foreign directory was touched")
	}

	// Removing a managed workspace leaves no directory behind.
	if err := mgr.Remove("ep-rm"); err != nil {
		t.Fatalf("managed remove: %v", err)
	}
	if _, err := os.Stat(mgr.pathFor("ep-rm")); !os.IsNotExist(err) {
		t.Fatalf("managed worktree still present: %v", err)
	}
}

func TestManagerErrorsOnMissingSourceRepo(t *testing.T) {
	mgr, _ := newMgr(t)
	if _, err := mgr.Acquire("ep-norepo", ""); err == nil {
		t.Fatal("empty source repo must be an error")
	}
	if _, err := mgr.Acquire("ep-norepo", filepath.Join(t.TempDir(), "not-a-git-repo")); err == nil {
		t.Fatal("non-git source repo must be an error")
	}
}
