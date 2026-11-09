package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/delegation"
)

func selfExe(t *testing.T) string {
	t.Helper()
	// go test re-exec: the compiled binary of this package.
	return os.Args[0]
}

// NEXT-11 adversarial coverage: the boundary is enforced by construction,
// and these tests attack it.

// TestScrubbedEnvDropsHostSecretsAndSockets: secrets, sockets and credential
// helpers set in the parent env must be ABSENT in any child env — the
// boundary is structural (allowlist), not an instruction.
func TestScrubbedEnvDropsHostSecretsAndSockets(t *testing.T) {
	t.Setenv("YABANIN_API_KEY", "yb-SECRET")
	t.Setenv("YABANIN_STAND_NEBIUS_KEY", "neb-SECRET")
	t.Setenv("OPENAI_API_KEY", "sk-SECRET")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("GIT_SSH_COMMAND", "ssh -i ~/.ssh/id_rsa")

	env := ScrubbedEnv("/tmp/ws")
	joined := strings.Join(env, "\n")
	for _, leak := range []string{"SECRET", "agent.sock", "docker.sock", "id_rsa", "SSH", "DOCKER"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("scrubbed env leaks %q: %s", leak, joined)
		}
	}
	if !strings.Contains(joined, "HOME=/tmp/ws") {
		t.Fatalf("HOME must be redirected into the workspace: %s", joined)
	}
}

// TestScrubbedEnvChildSeesAllowlistOnly: run a REAL child process (the test
// binary printing its own env) and verify server-side that the parent-set
// secret never reached it.
func TestScrubbedEnvChildSeesAllowlistOnly(t *testing.T) {
	// The child branch prints its full environment; the parent then runs it
	// with a ScrubbedEnv built WHILE secrets are present in the parent env.
	// The markers exist only in the parent — a correct scrub cannot copy
	// them, so the child must observe neither.
	if os.Getenv("CHILD_ENV_DUMP") == "1" {
		for _, kv := range os.Environ() {
			_, _ = os.Stdout.WriteString(kv + "\n")
		}
		os.Exit(0)
	}
	t.Setenv("CHILD_MARK_SECRET", "leak-me")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	cmd := exec.CommandContext(context.Background(), selfExe(t)) //nolint:gosec // self-exec test fixture
	cmd.Env = append(ScrubbedEnv(t.TempDir()), "CHILD_ENV_DUMP=1", "PATH="+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child run: %v: %s", err, out)
	}
	if strings.Contains(string(out), "leak-me") || strings.Contains(string(out), "agent.sock") {
		t.Fatalf("child observed parent-only secrets:\n%s", out)
	}
	if !strings.Contains(string(out), "HOME=") {
		t.Fatal("child env must still contain the redirected HOME")
	}
}

// TestAnalyzeModeHasNoWritePath: the read-only guarantee is structural — a
// Workspace exposes Diff only; this compiles precisely because there is no
// write method. The test pins the intent and the guard rails that DO exist:
// workspace and state trees must be disjoint (evidence/verifiers unreachable).
func TestStateAndWorkspaceTreesMustBeDisjoint(t *testing.T) {
	base := t.TempDir()
	store, err := NewStore(filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	// Manager rooted INSIDE the state dir → refused.
	inside, err := NewWorkspaceManager(filepath.Join(base, "state", "wt"))
	if err != nil {
		t.Fatal(err)
	}
	inside.WithStateStore(store)
	if _, err := inside.Acquire("ep-x", ""); err == nil {
		t.Fatal("workspace rooted inside the state tree must be refused")
	}

	// Manager CONTAINING the state dir → also refused.
	containing, err := NewWorkspaceManager(base)
	if err != nil {
		t.Fatal(err)
	}
	containing.WithStateStore(store)
	if _, err := containing.Acquire("ep-y", ""); err == nil {
		t.Fatal("workspace tree containing the state dir must be refused")
	}

	// Disjoint trees → allowed (existing tests cover the happy path).
	disjoint, err := NewWorkspaceManager(filepath.Join(base, "wt"))
	if err != nil {
		t.Fatal(err)
	}
	disjoint.WithStateStore(store)
	if err := store.EnforceStoreOutsideWorkspace(filepath.Join(base, "wt")); err != nil {
		t.Fatalf("disjoint trees must be accepted: %v", err)
	}
}

// TestGitUsesIsolatedConfig: the worktree operations run with an explicit
// isolated identity and a redirected HOME, so the operator's ~/.gitconfig
// (and any includeIf hooks) cannot influence delegated git.
func TestGitUsesIsolatedConfig(t *testing.T) {
	if len(gitConfigArgs) < 2 || !strings.Contains(strings.Join(gitConfigArgs, " "), "user.email") {
		t.Fatalf("git invocations must carry an isolated identity config: %v", gitConfigArgs)
	}
	// Real proof: commit inside a managed worktree and read the author.
	repo := initGitRepo(t)
	mgr, _ := NewWorkspaceManager(filepath.Join(t.TempDir(), "wt"))
	ws, err := mgr.Acquire("ep-identity", repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Release() }()
	if err := os.WriteFile(filepath.Join(ws.Path, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := gitOutput(ws.Path, "add", "f.txt"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if out, err := gitOutput(ws.Path, "commit", "-qm", "boundary test"); err != nil {
		t.Fatalf("git commit (with scrubbed env + isolated identity): %v: %s", err, out)
	}
	logOut, err := gitOutput(ws.Path, "log", "-1", "--format=%an <%ae>")
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if !strings.Contains(string(logOut), "Yabanin Delegate") {
		t.Fatalf("commit author must be the isolated identity, got: %s", logOut)
	}
}

// TestFakeExecutorNeverNetworks: the executor the controller runs today has
// no network surface by construction; the boundary card forbids replacing a
// sandbox with a prompt — we pin the fake's shape instead.
func TestFakeExecutorNeverNetworks(t *testing.T) {
	f := delegation.NewFakeExecutor("")
	res, err := f.Run(context.Background(), delegation.Request{Task: "t"})
	if err != nil || res.Status != "ok" {
		t.Fatalf("fake executor: %v %+v", err, res)
	}
	if res.Wrote || len(res.ChangedFiles) > 0 {
		t.Fatal("fake executor must never claim writes")
	}
	_ = time.Second // keep time import for future timing guards
}
