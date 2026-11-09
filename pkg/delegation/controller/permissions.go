package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NEXT-11 permission/resource boundary. This is an IN-PROCESS boundary —
// enforced guarantees about what trusted tooling may do on behalf of an
// episode. It is NOT an OS sandbox: macOS process sandboxing (sandbox-exec)
// requires an environment decision and is recorded as the exact blocker in
// the work record.
//
// Enforced here:
//   - READ-ONLY IS READ-ONLY: analyze episodes get no write path at all —
//     the Workspace type exposes Diff only; there is no write API to misuse.
//   - NETWORK DENIED BY DEFAULT: the controller's only child processes are
//     fixed git invocations; no network-capable adapter is wired, and the
//     registry (NEXT-10) rejects non-matching commands.
//   - ENV ALLOWLIST: every child process runs with ScrubbedEnv — host
//     credentials, Docker/SSH sockets and all YABANIN_* secrets are absent
//     by construction, not by prompt instruction.
//   - PROTECTED FILES OUTSIDE THE WRITABLE MOUNT: the store refuses a
//     workspace root that would contain (or be contained by) the state
//     directory — episodes can never write their own evidence or verifier.

// scrubbedAllowlist is the exhaustive environment a controller child process
// may see. Anything not listed is dropped (HOME is redirected to the
// worktree so git cannot read the operator's ~/.gitconfig, ~/.ssh, etc.).
var scrubbedAllowlist = []string{"PATH", "TZ", "LANG", "LC_ALL", "TMPDIR"}

// ScrubbedEnv builds the child-process environment: allowlisted vars only,
// HOME redirected into the workspace. Secrets (YABANIN_*, *_KEY, tokens),
// Docker/SSH sockets and credential helpers can never leak because they are
// never copied.
func ScrubbedEnv(workspace string) []string {
	out := make([]string, 0, len(scrubbedAllowlist)+1)
	for _, k := range scrubbedAllowlist {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			out = append(out, k+"="+v)
		}
	}
	out = append(out, "HOME="+workspace)
	return out
}

// gitConfigArgs isolate git from host configuration: no ~/.gitconfig, no
// includeIf tricks, deterministic identity for worktree operations.
var gitConfigArgs = []string{
	"-c", "user.email=delegate@yabanin.invalid",
	"-c", "user.name=Yabanin Delegate",
}

// EnforceStoreOutsideWorkspace refuses a manager/workspace pair where the
// episode state (evidence, verifier inputs) is reachable from inside the
// workspace — protected files must live outside any writable mount.
func (s *Store) EnforceStoreOutsideWorkspace(wsRoot string) error {
	if s == nil || wsRoot == "" {
		return fmt.Errorf("workspace root is required")
	}
	absRoot, err := filepath.Abs(wsRoot)
	if err != nil {
		return err
	}
	absState, err := filepath.Abs(s.dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absState)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("state directory must live outside the workspace (it is reachable from %s)", absRoot)
	}
	rel2, err := filepath.Rel(absState, absRoot)
	if err == nil && rel2 != ".." && !strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return fmt.Errorf("workspace root must live outside the state directory (%s)", absState)
	}
	return nil
}

// maxGitOutput bounds the bytes kept from any git invocation (diffs on huge
// repos must not exhaust memory; the inventory only needs the head).
const maxGitOutput = 64 * 1024

func boundOutput(b []byte) []byte {
	if len(b) <= maxGitOutput {
		return b
	}
	return append(b[:maxGitOutput], []byte("\n…[output truncated]")...)
}
