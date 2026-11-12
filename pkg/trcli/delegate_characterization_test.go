package trcli

// Characterization tests pinning the delegate CLI surface (subcommands,
// flags, argument/flag validation, exit-driving errors and exact output
// lines) ahead of the delegateCmd decomposition; every line asserted here
// is observable operator behavior and must survive the refactor unchanged.
// A non-nil error from these commands is what drives the yb exit code.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireLine asserts out contains want as a full line, so column
// alignment (which differs between run and review) is pinned exactly.
func requireLine(t *testing.T, out, want string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if l == want {
			return
		}
	}
	t.Errorf("output missing exact line %q:\n%s", want, out)
}

func TestDelegateCharacterizationHelpSurface(t *testing.T) {
	out, err := executeDelegate(t, t.TempDir(), "--help")
	if err != nil {
		t.Fatalf("delegate --help: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Available Commands:",
		"  run ", "  status ", "  resume ", "  cancel ", "  review ", "  jit ",
		"--workspace string", "workspace root (state under .yabanin/delegate/)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("delegate --help missing %q:\n%s", want, out)
		}
	}
}

func TestDelegateCharacterizationSubcommandFlagHelp(t *testing.T) {
	for _, tc := range []struct{ sub, want string }{
		{"run", "implement mode (analyze is default)"},
		{"run", "source git repo: run the episode in an isolated worktree of it"},
		{"review", "source repo to render the actual worktree diff"},
		{"review approve", "reviewer identity (required)"},
		{"review reject", "free-form decision note"},
	} {
		args := append(strings.Fields(tc.sub), "--help")
		out, err := executeDelegate(t, t.TempDir(), args...)
		if err != nil {
			t.Fatalf("%s --help: %v\n%s", tc.sub, err, out)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s --help missing %q:\n%s", tc.sub, tc.want, out)
		}
	}
}

func TestDelegateCharacterizationArgAndFlagValidation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "only-one"}, "accepts 2 arg(s)"},
		{[]string{"status"}, "accepts 1 arg(s)"},
		{[]string{"status", "a", "b"}, "accepts 1 arg(s)"},
		{[]string{"resume", "a", "b"}, "accepts 1 arg(s)"},
		{[]string{"review"}, "requires at least 1 arg"},
		{[]string{"cancel"}, "requires at least 1 arg"},
		{[]string{"review", "approve", "a", "b"}, "accepts 1 arg(s)"},
		{[]string{"review", "approve", "a"}, `required flag(s) "actor" not set`},
		{[]string{"review", "reject", "a"}, `required flag(s) "actor" not set`},
	} {
		out, err := executeDelegate(t, t.TempDir(), tc.args...)
		if err == nil || !strings.Contains(out+err.Error(), tc.want) {
			t.Errorf("args %v: want error containing %q, got err=%v\n%s", tc.args, tc.want, err, out)
		}
	}
}

// run and review render the empty-diff inventory with different column
// alignment and phrasing; both are pinned byte-exact here.
func TestDelegateCharacterizationDiffNonePhrasing(t *testing.T) {
	ws := t.TempDir()
	repo := t.TempDir()
	if err := gitInit(repo); err != nil {
		t.Fatalf("git init: %v", err)
	}
	out, err := executeDelegate(t, ws, "run", "ep-diff", "task", "--workspace", ws, "--repo", repo)
	if err != nil {
		t.Fatalf("run --repo: %v\n%s", err, out)
	}
	requireLine(t, out, "  diff:     none (no files changed)")

	out, err = executeDelegate(t, ws, "review", "ep-diff", "--workspace", ws, "--repo", repo)
	if err != nil {
		t.Fatalf("review --repo: %v\n%s", err, out)
	}
	requireLine(t, out, "  diff:      none")
}

func TestDelegateCharacterizationDefaultCancelReason(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-cd", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	out, err := executeDelegate(t, ws, "cancel", "ep-cd", "--workspace", ws)
	if err != nil {
		t.Fatalf("cancel without reason: %v\n%s", err, out)
	}
	out, err = executeDelegate(t, ws, "status", "ep-cd", "--workspace", ws)
	if err != nil {
		t.Fatalf("status after cancel: %v\n%s", err, out)
	}
	requireLine(t, out, "  cancel:   operator cancel")
}

func TestDelegateCharacterizationReviewUndecidedHint(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-hint", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	out, err := executeDelegate(t, ws, "review", "ep-hint", "--workspace", ws)
	if err != nil {
		t.Fatalf("review bundle: %v\n%s", err, out)
	}
	requireLine(t, out, "  review:    not decided — use `review <id> approve|reject --actor <name>`")
}

// Evidence status notes: a decision-evolved state is a stale envelope
// (soft note), and a deleted envelope is "none written yet" (soft note,
// exit success) — only a genuine mismatch fails the command.
func TestDelegateCharacterizationEvidenceNotes(t *testing.T) {
	ws := t.TempDir()
	if _, err := executeDelegate(t, ws, "run", "ep-st", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := executeDelegate(t, ws, "review", "approve", "ep-st", "--actor", "a", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	out, err := executeDelegate(t, ws, "review", "ep-st", "--workspace", ws)
	if err != nil {
		t.Fatalf("review after decision must succeed softly: %v\n%s", err, out)
	}
	requireLine(t, out, "  evidence:  stale (state evolved after the envelope was written)")

	if _, err := executeDelegate(t, ws, "run", "ep-del", "task", "--workspace", ws); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(ws, ".yabanin", "delegate", "evidence-ep-del.json")); err != nil {
		t.Fatal(err)
	}
	out, err = executeDelegate(t, ws, "review", "ep-del", "--workspace", ws)
	if err != nil {
		t.Fatalf("review with deleted evidence must succeed softly: %v\n%s", err, out)
	}
	requireLine(t, out, "  evidence:  none written yet")
}

// An unknown flag is a hard error; an unknown subcommand under delegate
// prints help and exits success (delegate itself is not runnable) — pin
// both so the decomposition does not silently change exit behavior.
func TestDelegateCharacterizationUnknownSubcommandAndFlag(t *testing.T) {
	out, err := executeDelegate(t, t.TempDir(), "frobnicate")
	if err != nil {
		t.Fatalf("unknown subcommand must print help and succeed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Available Commands:") {
		t.Errorf("unknown subcommand must print the help surface:\n%s", out)
	}

	out, err = executeDelegate(t, t.TempDir(), "run", "a", "b", "--nope")
	if err == nil || !strings.Contains(out+err.Error(), "unknown flag") {
		t.Errorf("unknown flag must be a hard error, got err=%v\n%s", err, out)
	}
}
