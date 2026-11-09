package trcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The delegate CLI runs the FakeExecutor — fully hermetic, no network.
func executeDelegate(t *testing.T, ws string, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "yb"}
	root.AddCommand(delegateCmd())
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"delegate"}, args...))
	err := root.Execute()
	return buf.String(), err
}

func TestDelegateCLIRunAnalyzeAndStatus(t *testing.T) {
	ws := t.TempDir()
	out, err := executeDelegate(t, ws, "run", "ep-a", "check the thing", "--workspace", ws)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	// TP-17: the hermetic FakeExecutor honestly reports validation
	// "skipped", so its analyze episodes stop at awaiting_review instead of
	// self-certifying as done.
	if !strings.Contains(out, "state:    awaiting_review") || !strings.Contains(out, "✓ step 0 analyze") {
		t.Fatalf("run output missing awaiting/step: %s", out)
	}

	out, err = executeDelegate(t, ws, "status", "ep-a", "--workspace", ws)
	if err != nil || !strings.Contains(out, "state:    awaiting_review") {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

func TestDelegateCLIRunImplementAwaitsReviewThenCancel(t *testing.T) {
	ws := t.TempDir()
	out, err := executeDelegate(t, ws, "run", "ep-b", "patch it", "--implement", "--workspace", ws)
	if err != nil {
		t.Fatalf("run --implement: %v\n%s", err, out)
	}
	if !strings.Contains(out, "state:    awaiting_review") {
		t.Fatalf("implement must await review: %s", out)
	}
	if !strings.Contains(out, "✓ step 1 implement") {
		t.Fatalf("implement step missing: %s", out)
	}

	out, err = executeDelegate(t, ws, "cancel", "ep-b", "operator changed mind", "--workspace", ws)
	if err != nil || !strings.Contains(out, "state:    canceled") || !strings.Contains(out, "operator changed mind") {
		t.Fatalf("cancel: %v\n%s", err, out)
	}
}

func TestDelegateCLICancelTerminalIsError(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-c", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	// Close the episode explicitly (TP-17: fake analyze no longer
	// self-closes) so it becomes terminal, then canceling must error.
	if _, err := executeDelegate(t, ws, "review", "reject", "ep-c", "--actor", "tester", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	out, err := executeDelegate(t, ws, "cancel", "ep-c", "--workspace", ws)
	if err == nil || !strings.Contains(out, "invalid episode state transition") {
		t.Fatalf("terminal cancel must error explicitly: %v\n%s", err, out)
	}
}

func TestDelegateCLIStatusMissingEpisode(t *testing.T) {
	_, err := executeDelegate(t, t.TempDir(), "status", "nope", "--workspace", t.TempDir())
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing episode must surface the fs error: %v", err)
	}
}

func TestDelegateCLIResumeIdempotentOnFinishedEpisode(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-d", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	// TP-17: the episode finished its steps and awaits review; resume is an
	// idempotent no-op success, not a transition error.
	out, err := executeDelegate(t, ws, "resume", "ep-d", "--workspace", ws)
	if err != nil || !strings.Contains(out, "state:    awaiting_review") {
		t.Fatalf("resume of finished episode must be a no-op success: %v\n%s", err, out)
	}
}

// TestDelegateCLIRunWithRepoReportsActualDiff: NEXT-09 wiring — the episode
// runs against an isolated worktree and the CLI prints the ACTUAL git diff
// (here: none, because FakeExecutor writes nothing).
func TestDelegateCLIRunWithRepoReportsActualDiff(t *testing.T) {
	ws := t.TempDir()
	repo := t.TempDir()
	if err := gitInit(repo); err != nil {
		t.Fatalf("git init: %v", err)
	}
	out, err := executeDelegate(t, ws, "run", "ep-ws", "analyze the repo", "--workspace", ws, "--repo", repo)
	if err != nil {
		t.Fatalf("run --repo: %v\n%s", err, out)
	}
	if !strings.Contains(out, "diff:") {
		t.Fatalf("run --repo must report the diff inventory: %s", out)
	}
	if !strings.Contains(out, "none") {
		t.Fatalf("fake executor changes nothing; inventory must say none: %s", out)
	}
}

func gitInit(dir string) error {
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "t@x.invalid"}, {"config", "user.name", "T"},
	} {
		//nolint:gosec // G204: test fixture git against a temp dir.
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w: %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("base\n"), 0o600); err != nil {
		return err
	}
	//nolint:gosec // G204: test fixture git against a temp dir.
	//nolint:gosec // G204: test fixture git against a temp dir.
	cmd := exec.CommandContext(context.Background(), "git", "-C", dir, "add", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add: %w: %s", err, out)
	}
	//nolint:gosec // G204: test fixture git against a temp dir.
	cmd = exec.CommandContext(context.Background(), "git", "-C", dir, "commit", "-qm", "base")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit: %w: %s", err, out)
	}
	return nil
}

// NEXT-12: review decisions carry actor/hash/time; conflicts are explicit
// errors, and anonymous approvals are refused.
func TestDelegateCLIReviewLifecycle(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-rev", "t", "--implement", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	// Anonymous approval is refused.
	out, err := executeDelegate(t, ws, "review", "approve", "ep-rev", "--workspace", ws)
	if err == nil || !strings.Contains(out+err.Error(), "actor") {
		t.Fatalf("anonymous approve must fail: %v\n%s", err, out)
	}
	// Approve with actor records provenance.
	out, err = executeDelegate(t, ws, "review", "approve", "ep-rev", "--actor", "alice", "--workspace", ws)
	if err != nil || !strings.Contains(out, "approved by alice") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	// Double decision is a conflict, not a silent no-op.
	out, err = executeDelegate(t, ws, "review", "approve", "ep-rev", "--actor", "bob", "--workspace", ws)
	if err == nil || !strings.Contains(out, "invalid episode state transition") {
		t.Fatalf("second decision must conflict: %v\n%s", err, out)
	}
	// Reject path.
	if _, err := executeDelegate(t, ws, "run", "ep-rej", "t", "--implement", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	out, err = executeDelegate(t, ws, "review", "reject", "ep-rej", "--actor", "alice", "--note", "bad", "--workspace", ws)
	if err != nil || !strings.Contains(out, "rejected by alice") && !strings.Contains(out, "canceled") {
		t.Fatalf("reject: %v\n%s", err, out)
	}
	// The recorded decision is visible in the bundle.
	out, err = executeDelegate(t, ws, "review", "ep-rej", "--workspace", ws)
	if err != nil || !strings.Contains(out, "rejected by alice") {
		t.Fatalf("bundle must show the decision: %v\n%s", err, out)
	}
}

// TP-18: an evidence write failure must fail the CLI with a non-zero exit,
// not stay a printed footnote. The registry path is pointed at a missing
// file for this run only.
func TestDelegateCLIEvidenceFailureFailsRun(t *testing.T) {
	ws := t.TempDir()
	restore := bootstrapRegistryPath
	bootstrapRegistryPath = filepath.Join(ws, "missing-registry.json")
	defer func() { bootstrapRegistryPath = restore }()

	out, err := executeDelegate(t, ws, "run", "ep-ev1", "task", "--workspace", ws)
	if err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("missing registry must fail the run CLI: %v\n%s", err, out)
	}
	if !strings.Contains(out, "evidence:  unavailable") || !strings.Contains(out, "episode ep-ev1") {
		t.Fatalf("output must still show the episode and the unavailable note: %s", out)
	}
}

// TP-18: evidence writes and verifies from any CWD — the registry path
// resolves against the repo root (go.mod walk-up), so a nested cwd cannot
// produce a false verify or a broken write.
func TestDelegateCLIEvidenceFromNestedCWD(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "scripts", "quality"), 0o750); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(root, "scripts", "quality", "commands.json")
	if err := os.WriteFile(reg, []byte(`{"schema_version":1,"profiles":{"bootstrap":{"exact":["go mod download"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(root, "ws")
	nested := filepath.Join(root, "deep", "nested", "cwd")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)

	out, err := executeDelegate(t, ws, "run", "ep-nest", "task", "--workspace", ws)
	if err != nil || !strings.Contains(out, "evidence:  written") {
		t.Fatalf("nested cwd must resolve the registry and write evidence: %v\n%s", err, out)
	}
	out, err = executeDelegate(t, ws, "review", "ep-nest", "--workspace", ws)
	if err != nil || !strings.Contains(out, "evidence:  verified") {
		t.Fatalf("nested cwd must verify the envelope: %v\n%s", err, out)
	}
}

// TP-18: a tampered envelope must fail the review bundle with a non-zero
// exit — never display "verified".
func TestDelegateCLIReviewTamperedEvidenceFails(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-tam", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(ws, ".yabanin", "delegate", "evidence-ep-tam.json")
	raw, err := os.ReadFile(p) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"outcome": "awaiting_review"`)) {
		t.Fatalf("unexpected envelope: %s", raw)
	}
	tampered := bytes.Replace(raw, []byte(`"outcome": "awaiting_review"`), []byte(`"outcome": "done"`), 1)
	if err := os.WriteFile(p, tampered, 0o600); err != nil { //nolint:gosec // G304/G703: test temp file under t.TempDir
		t.Fatal(err)
	}
	out, err := executeDelegate(t, ws, "review", "ep-tam", "--workspace", ws)
	if err == nil || !strings.Contains(out, "MISMATCH") {
		t.Fatalf("tampered envelope must fail review with a non-zero exit: %v\n%s", err, out)
	}
}
