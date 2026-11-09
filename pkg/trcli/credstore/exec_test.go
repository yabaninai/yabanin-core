package credstore

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Child re-exec guards for the shim tests below. The test binary is
// symlinked onto PATH as secret-tool, so the real ExecRunner launches it as
// the helper process; the guards turn that child into a dump or a failure.
const (
	childDumpEnv = "CREDSTORE_CHILD_DUMP"
	childFailEnv = "CREDSTORE_CHILD_FAIL"
)

// childLookupValue is what the shim prints on stdout for lookups.
const childLookupValue = "subprocess-helper-value"

// childPayload is the value the parent stores through the shim.
const childPayload = "subprocess-payload"

func runCredstoreChildDump(dumpDir string) {
	args := append([]string(nil), os.Args[1:]...)
	stdin, _ := io.ReadAll(os.Stdin)
	_ = os.WriteFile(filepath.Join(dumpDir, "argv"), []byte(strings.Join(args, "\n")), 0o600) //nolint:gosec // G703: dumpDir is the parent test's t.TempDir() relayed via the dump env var; no untrusted input
	_ = os.WriteFile(filepath.Join(dumpDir, "stdin"), stdin, 0o600)                           //nolint:gosec // G703: dumpDir is the parent test's t.TempDir() relayed via the dump env var; no untrusted input
	_, _ = os.Stdout.WriteString(childLookupValue + "\n")
	os.Exit(0)
}

// requireShim skips only on platforms where PATH shims via symlinks are not
// the exec mechanism; linux and darwin (the gated platforms) always run.
func requireShim(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("PATH shim re-exec is a unix mechanism")
	}
}

func installSecretToolShim(t *testing.T) {
	t.Helper()
	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "secret-tool")
	if err := os.Symlink(os.Args[0], shim); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestExecRunnerPassesPayloadViaStdinNotArgv drives the real ExecRunner
// against a shim helper (this test binary re-executed) and pins the process
// boundary end to end: the exact argv the helper received must match the
// fixed subcommand contract, and the stored value must arrive on stdin only.
func TestExecRunnerPassesPayloadViaStdinNotArgv(t *testing.T) {
	requireShim(t)
	if dump := os.Getenv(childDumpEnv); dump != "" {
		runCredstoreChildDump(dump)
		return
	}
	if os.Getenv(childFailEnv) != "" {
		os.Exit(3)
	}
	installSecretToolShim(t)

	run := ExecRunner{}
	found, err := run.LookPath("secret-tool")
	if err != nil {
		t.Fatalf("lookpath: %v", err)
	}
	if filepath.Base(found) != "secret-tool" {
		t.Fatalf("lookpath resolved %q", found)
	}
	store := secretTool{run: run}
	ctx := t.Context()

	putDump := t.TempDir()
	t.Setenv(childDumpEnv, putDump)
	if _, _, err := store.Put(ctx, "default", childPayload); err != nil {
		t.Fatalf("put: %v", err)
	}

	getDump := t.TempDir()
	t.Setenv(childDumpEnv, getDump)
	got, err := store.Get(ctx, "default")
	if err != nil || got != childLookupValue {
		t.Fatalf("get: %q %v", got, err)
	}

	readDump := func(dir string) (argv []string, stdin string) {
		t.Helper()
		argvBytes, err := os.ReadFile(filepath.Join(dir, "argv")) //nolint:gosec // G304: dump file written by this test's own shim inside its temp dir
		if err != nil {
			t.Fatal(err)
		}
		stdinBytes, err := os.ReadFile(filepath.Join(dir, "stdin")) //nolint:gosec // G304: dump file written by this test's own shim inside its temp dir
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(string(argvBytes), "\n"), string(stdinBytes)
	}
	putArgv, putStdin := readDump(putDump)
	if want := SecretToolStoreArgs("default"); !slices.Equal(putArgv, want) {
		t.Fatalf("helper argv %#v, want %#v", putArgv, want)
	}
	if putStdin != childPayload {
		t.Fatalf("helper stdin %q, want %q", putStdin, childPayload)
	}
	getArgv, getStdin := readDump(getDump)
	if want := SecretToolLookupArgs("default"); !slices.Equal(getArgv, want) {
		t.Fatalf("helper argv %#v, want %#v", getArgv, want)
	}
	if getStdin != "" {
		t.Fatalf("lookup stdin %q, want empty", getStdin)
	}
}

// TestExecRunnerPropagatesChildFailure runs the shim in fail mode: the helper
// process exits nonzero and the store must surface the failure instead of
// inventing a value.
func TestExecRunnerPropagatesChildFailure(t *testing.T) {
	requireShim(t)
	if os.Getenv(childFailEnv) != "" {
		os.Exit(3)
	}
	installSecretToolShim(t)
	t.Setenv(childFailEnv, "1")

	store := secretTool{run: ExecRunner{}}
	if got, err := store.Get(t.Context(), "default"); err == nil || got != "" {
		t.Fatalf("get from failing helper: got %q err %v", got, err)
	}
}

func TestExecRunnerRejectsUnknownHelper(t *testing.T) {
	// The allowlist is the boundary: nothing outside security and secret-tool
	// may be launched, and the rejection happens before any exec.
	if _, err := (ExecRunner{}).Run(t.Context(), nil, "curl", "-s"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("unknown helper: %v", err)
	}
}
