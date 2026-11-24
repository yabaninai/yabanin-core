package trcli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Built-binary audit checks compile the real cmd/yb executable and drive it
// the way an operator runs it, independent of the in-process RootCommand
// tests. Bad input must fail with its operator-facing message; it must never
// render an empty report.
//
// auditTestBinaryName is the fixed literal name every exec site below
// uses: the argv stays constant (no shell, no variable command), the
// binary lives only in a test-owned temp dir, and the build stages it at
// this literal relative path without overwriting or leaving a file.
const auditTestBinaryName = "./yb-audit-testbuild"

// writeAuditBuiltFixture writes the deterministic four-line log used by
// the built-binary checks into dir under its literal relative name: two
// repeated prompts (exact-cache hit), one malformed line (skipped, counted
// in the denominator), and one prompt-less gateway row (a miss, not a
// manufactured hit).
func writeAuditBuiltFixture(t *testing.T, dir string) {
	t.Helper()
	const log = `{"model":"gpt-4o","messages":[{"content":"alpha"}]}` + "\n" +
		`{broken}` + "\n" +
		`{"model":"gpt-4o","messages":[{"content":"alpha"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}` + "\n" +
		`{"model_used":"gpt-4o","tokens_in":700}` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(log), 0o600))
}

// buildAuditBinary compiles the real cmd/yb and returns the test-owned
// dir holding it under the fixed literal name. The `go build` argv is
// constant; only Cmd.Dir names the repository root. The build stages its
// output at the literal relative path, moves it into the test-owned dir
// before any use, and cleans up after itself: an existing staged file
// aborts the test (never an overwrite of a file the test did not create)
// and the cleanup removes only the staged artifact. Tests here run
// serially, so the fixed staging name has no concurrent collision window
// inside the package.
func buildAuditBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("built-binary audit check skipped in -short mode")
	}
	// The staging dir is created inside the repository root so the rename out
	// of the literal staging path cannot cross filesystems; os.MkdirTemp gives
	// it a unique suffix, and the cleanup removes the whole dir.
	dir, err := os.MkdirTemp(filepath.Join("..", ".."), "yb-audit-testbuild-")
	if err != nil {
		t.Fatalf("create the build staging dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	staged := filepath.Join("..", "..", auditTestBinaryName)
	if _, err := os.Stat(staged); err == nil {
		t.Fatalf("stale %s in the repository root; refusing to overwrite a file this test did not create", auditTestBinaryName)
	}
	defer func() { _ = os.Remove(staged) }() // no-op once the binary moved into dir

	build := exec.CommandContext(t.Context(), "go", "build", "-o", auditTestBinaryName, "./cmd/yb")
	build.Dir = filepath.Join("..", "..") // repository root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/yb: %v\n%s", err, out)
	}
	if err := os.Rename(staged, filepath.Join(dir, auditTestBinaryName)); err != nil {
		t.Fatalf("move the built binary into the test dir: %v", err)
	}
	return dir
}

// auditScenario enumerates the exact invocations these checks make against
// the staged binary; auditCommand holds the matching literal argv for each.
type auditScenario int

const (
	auditFixtureReport    auditScenario = iota // audit requests.jsonl -f json
	auditMissingFile                           // audit does-not-exist.jsonl
	auditEmptyStdin                            // audit -
	auditBadCSV                                // audit bad.csv
	auditSemanticRejected                      // audit requests.jsonl --cache-mode semantic
	auditFileExact                             // audit requests.jsonl -f json --provider local-pricer --no-prompts
	auditStdinExact                            // audit - -f json --provider local-pricer --no-prompts
)

// auditCommand builds the command for a named scenario. Every argv below is
// a compile-time literal: the executable is the fixed name of the binary
// buildAuditBinary staged in dir, and the arguments enumerate - one visible
// case each - the complete set of invocations these checks make. Nothing is
// forwarded from callers.
func auditCommand(t *testing.T, dir string, scenario auditScenario) *exec.Cmd {
	t.Helper()
	var cmd *exec.Cmd
	switch scenario {
	case auditFixtureReport:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "requests.jsonl", "-f", "json")
	case auditMissingFile:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "does-not-exist.jsonl")
	case auditEmptyStdin:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "-")
	case auditBadCSV:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "bad.csv")
	case auditSemanticRejected:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "requests.jsonl", "--cache-mode", "semantic")
	case auditFileExact:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "requests.jsonl", "-f", "json", "--provider", "local-pricer", "--no-prompts")
	case auditStdinExact:
		cmd = exec.CommandContext(t.Context(), auditTestBinaryName, "audit", "-", "-f", "json", "--provider", "local-pricer", "--no-prompts")
	default:
		t.Fatalf("unhandled audit scenario %d", scenario)
	}
	cmd.Dir = dir
	return cmd
}

// runAuditScenario runs the staged binary for a named scenario with the
// given stdin and an optional env override (nil inherits the test process
// environment). It is the single exec driver for the built binary.
func runAuditScenario(t *testing.T, dir string, scenario auditScenario, stdin string, env []string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := auditCommand(t, dir, scenario)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func TestAuditBuiltBinary_FixtureAndNegativeControls(t *testing.T) {
	dir := buildAuditBinary(t)
	writeAuditBuiltFixture(t, dir)

	t.Run("fixture renders the accounted JSON report offline", func(t *testing.T) {
		// Junk credentials in the environment prove the leaf reads no gateway
		// configuration and makes no network calls.
		junkEnv := append(os.Environ(),
			"YABANIN_ADMIN_API_KEY=must-not-be-read",
			"YABANIN_ADMIN_URL=http://127.0.0.1:1",
			"YABANIN_PG_URI=postgres://must-not-be-read",
		)
		out, errOut, err := runAuditScenario(t, dir, auditFixtureReport, "", junkEnv)
		require.NoError(t, err, "stderr: %s", errOut)

		var rep struct {
			S1 struct{ Requests int }
			S3 struct {
				HitRatePct    float64
				TokensAvoided int
			}
			S5 struct {
				Skipped     int
				Denominator int
			}
		}
		require.NoError(t, json.Unmarshal([]byte(out), &rep))
		assert.Equal(t, 3, rep.S1.Requests)
		assert.Equal(t, 1, rep.S5.Skipped)
		assert.Equal(t, 4, rep.S5.Denominator)
		assert.InDelta(t, 100.0/3.0, rep.S3.HitRatePct, 1e-9)
		assert.Equal(t, 11, rep.S3.TokensAvoided)
	})

	t.Run("negative: missing input file fails with the open error", func(t *testing.T) {
		_, stderr, err := runAuditScenario(t, dir, auditMissingFile, "", nil)
		require.Error(t, err, "a missing input must fail, not render a report")
		assert.NotZero(t, execExitCode(err))
		assert.Contains(t, stderr, "open input")
	})

	t.Run("negative: empty stdin fails with the accounted no-records error", func(t *testing.T) {
		_, stderr, err := runAuditScenario(t, dir, auditEmptyStdin, "", nil)
		require.Error(t, err, "empty stdin must fail, not render a report")
		assert.NotZero(t, execExitCode(err))
		assert.Contains(t, stderr, "no records ingested from -")
	})

	t.Run("negative: CSV without a model column fails with the header error", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.csv"), []byte("a,b\n1,2\n"), 0o600))
		_, stderr, err := runAuditScenario(t, dir, auditBadCSV, "", nil)
		require.Error(t, err)
		assert.NotZero(t, execExitCode(err))
		assert.Contains(t, stderr, "no recognized model column")
	})

	t.Run("negative: semantic cache mode is rejected, not silently degraded", func(t *testing.T) {
		_, stderr, err := runAuditScenario(t, dir, auditSemanticRejected, "", nil)
		require.Error(t, err)
		assert.NotZero(t, execExitCode(err))
		assert.Contains(t, stderr, "semantic audit is unavailable")
	})
}

// decodeAuditJSON parses a built-binary JSON report. Source is normalized to
// the empty string (the only permitted difference: it names the transport);
// GeneratedAt is the report's single wall-clock field and is compared apart.
func decodeAuditJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep), "report: %s", out)
	rep["Source"] = ""
	return rep
}

// auditAccounting is the typed view of the independently known report
// numbers, so JSON numbers decode as int/float64 instead of untyped any.
type auditAccounting struct {
	S1 struct {
		Requests     int
		TopProviders []struct {
			Name     string
			Requests int
			SharePct float64
		}
	}
	S3 struct {
		HitRatePct    float64
		TokensAvoided int
	}
	S5 struct {
		Skipped     int
		Denominator int
	}
}

func decodeAuditAccounting(t *testing.T, out string) auditAccounting {
	t.Helper()
	var rep auditAccounting
	require.NoError(t, json.Unmarshal([]byte(out), &rep), "report: %s", out)
	return rep
}

func TestAuditBuiltBinary_SameBytesFileVsStdin(t *testing.T) {
	dir := buildAuditBinary(t)
	const log = `{"model":"gpt-4o","messages":[{"content":"alpha"}]}` + "\n" +
		`{broken}` + "\n" +
		`{"model":"gpt-4o","messages":[{"content":"alpha"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}` + "\n" +
		`{"model_used":"gpt-4o","tokens_in":700}` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requests.jsonl"), []byte(log), 0o600))

	outFile, _, err := runAuditScenario(t, dir, auditFileExact, "", nil)
	require.NoError(t, err)
	outStdin, _, err := runAuditScenario(t, dir, auditStdinExact, log, nil)
	require.NoError(t, err)

	repFile := decodeAuditJSON(t, outFile)
	repStdin := decodeAuditJSON(t, outStdin)
	numFile := decodeAuditAccounting(t, outFile)
	numStdin := decodeAuditAccounting(t, outStdin)

	require.ElementsMatch(t, mapKeys(repFile), mapKeys(repStdin),
		"file and stdin reports must carry the same top-level keys")
	// Identical bytes must produce identical accounting regardless of the
	// transport; only Source may name it differently. GeneratedAt is compared
	// apart below as the report's one wall-clock value.
	for key, fileVal := range repFile {
		if key == "GeneratedAt" {
			continue
		}
		require.Equal(t, fileVal, repStdin[key], "section %s must match across file and stdin", key)
	}
	_, err = time.Parse(time.RFC3339, repFile["GeneratedAt"].(string))
	require.NoError(t, err, "GeneratedAt must stay a parseable timestamp")

	// Independently known accounting, asserted per transport over the typed
	// decode, not just cross-compared: 3 parsed, 1 skipped, denominator 4; the
	// repeated prompt hits once (11 tokens avoided) and the prompt-less row is
	// a miss.
	for name, rep := range map[string]auditAccounting{"file": numFile, "stdin": numStdin} {
		require.Equal(t, 3, rep.S1.Requests, "%s: requests", name)
		require.Equal(t, 1, rep.S5.Skipped, "%s: skipped", name)
		require.Equal(t, 4, rep.S5.Denominator, "%s: denominator", name)
		require.InDelta(t, 100.0/3.0, rep.S3.HitRatePct, 1e-9, "%s: exact hit rate", name)
		require.Equal(t, 11, rep.S3.TokensAvoided, "%s: tokens avoided", name)
	}

	t.Run("provider override surfaces in both reports", func(t *testing.T) {
		for name, rep := range map[string]auditAccounting{"file": numFile, "stdin": numStdin} {
			require.Len(t, rep.S1.TopProviders, 1, "%s: one overridden provider", name)
			row := rep.S1.TopProviders[0]
			require.Equal(t, "local-pricer", row.Name, "%s: --provider must override inference", name)
			require.Equal(t, 3, row.Requests, "%s: override applies to every record", name)
		}
	})
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// execExitCode returns the process exit code, or -1 when the error is not an
// exit-status error (e.g. the binary could not start).
func execExitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
