package contracts

// N09-P01-T09 [compatibility] — old/new configuration walk for
// pkg/agenteval/contracts.
//
// The walk drives the real Validate consumer over historical and current
// journal shapes so reader-side compatibility is pinned by behaviour:
//
//	legacy minimal manifest   missing optional blocks (spend, profile) —
//	                          still validates (documented tolerance)
//	unsupported shapes        wrong/absent schema_version, empty arms,
//	                          unknown fields — rejected LOUDLY with the
//	                          field name (never silently ignored)
//	journal forward-compat    unknown record fields and unknown
//	                          execution_status named with file + line
//	old writer tolerance      journal without trailing newline validates;
//	                          the T08 appendLine repair keeps records
//	                          unglued when new lines are added
//
// Existing coverage intentionally not duplicated: the happy path + example
// fixture (contracts_test.go), ID/referential integrity negatives, torn-line
// crash artifacts (T08).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// t09ManifestEdits replaces the manifest fixture with content produced by a
// modifier function over the canonical valid manifest.
func t09ManifestEdits(t *testing.T, dir string, edit func(string) string) {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, []byte(edit(string(raw))), 0o600))
}

// TestN09P1T09_Compat_MinimalLegacyManifestValidates pins reader tolerance
// for older writer shapes: a manifest without the spend block (written
// before the spend gate existed) and without the profile tag still
// validates. The tolerance is deliberate — the validator reports structure
// and invariants, it does not retro-require fields newer writers add.
func TestN09P1T09_Compat_MinimalLegacyManifestValidates(t *testing.T) {
	t.Run("spend block optional (pre-spend writer shape)", func(t *testing.T) {
		dir := validDir(t)
		t09ManifestEdits(t, dir, func(m string) string {
			return strings.Replace(m,
				`"spend":{"authorized":false,"limit_usd":0,"approved_by":"","approved_at":null},`, "", 1)
		})
		assert.NoError(t, Validate(dir),
			"older manifests without the spend block must keep validating")
	})

	t.Run("profile tag optional (pre-profile writer shape)", func(t *testing.T) {
		dir := validDir(t)
		t09ManifestEdits(t, dir, func(m string) string {
			return strings.Replace(m, `"profile":"AGENT_SMOKE_20",`, "", 1)
		})
		assert.NoError(t, Validate(dir),
			"older manifests without the profile tag must keep validating")
	})
}

// TestN09P1T09_Compat_UnsupportedManifestShapesRejectedLoudly pins the loud
// rejections: every unsupported manifest shape produces an actionable error
// that names the offending field and the expected value — nothing is
// silently defaulted.
func TestN09P1T09_Compat_UnsupportedManifestShapesRejectedLoudly(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(string) string
		wantErr string
	}{
		{
			name: "future schema_version",
			edit: func(m string) string {
				return strings.Replace(m, `"schema_version":1`, `"schema_version":2`, 1)
			},
			wantErr: "manifest.schema_version = 2, want 1",
		},
		{
			name: "absent schema_version",
			edit: func(m string) string {
				return strings.Replace(m, `"schema_version":1,`, "", 1)
			},
			wantErr: "manifest.schema_version = 0, want 1",
		},
		{
			name: "empty arms",
			edit: func(m string) string {
				return strings.Replace(m,
					`"arms":[{"id":"g1","model_slug":"gpt-4o","endpoint_url":"https://x.example/v1","provider_pinning":"openai","headers_allowed":["authorization"]}]`,
					`"arms":[]`, 1)
			},
			wantErr: "manifest.arms is empty",
		},
		{
			name: "unknown top-level field",
			edit: func(m string) string {
				return strings.Replace(m, `"schema_version":1,`, `"schema_version":1,"tolerances":"none",`, 1)
			},
			wantErr: `unknown field "tolerances"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := validDir(t)
			t09ManifestEdits(t, dir, tc.edit)
			err := Validate(dir)
			require.Error(t, err, "unsupported shape must be rejected")
			assert.Contains(t, err.Error(), tc.wantErr,
				"the error must name the field and the expectation")
		})
	}
}

// TestN09P1T09_Compat_UnknownJournalFieldsRejectedWithLineNumbers walks the
// journal forward-compat contract: a newer writer adding a record field, or
// emitting an unknown execution_status, gets a loud rejection that names the
// file, the line and the offending value.
func TestN09P1T09_Compat_UnknownJournalFieldsRejectedWithLineNumbers(t *testing.T) {
	t.Run("unknown record field", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "calls.jsonl")
		raw, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		// Inject the field into the SECOND record so the reported line
		// proves the line numbering.
		bad := strings.Replace(string(raw), `{"call_id":"call-002"`, `{"call_id":"call-002","billed_usd":1`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input

		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "calls.jsonl")
		assert.Contains(t, err.Error(), "line 2")
		assert.Contains(t, err.Error(), "billed_usd")
	})

	t.Run("unknown execution_status", func(t *testing.T) {
		dir := validDir(t)
		p := filepath.Join(dir, "episodes.jsonl")
		raw, err := os.ReadFile(p) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
		require.NoError(t, err)
		bad := strings.Replace(string(raw), `"execution_status":"completed"`, `"execution_status":"succeeded"`, 1)
		require.NoError(t, os.WriteFile(p, []byte(bad), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input

		err = Validate(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown execution_status "succeeded"`)
	})
}

// TestN09P1T09_Compat_OldJournalWithoutTrailingNewlineStillValidAndAppendRepairs
// pins the historical writer tolerance and its repair path: journals whose
// final line lacks the trailing newline (every pre-T08 writer) validate, and
// appending with the T08 repair helper neither glues records nor breaks
// validation.
func TestN09P1T09_Compat_OldJournalWithoutTrailingNewlineStillValidAndAppendRepairs(t *testing.T) {
	dir := validDir(t)
	callsPath := filepath.Join(dir, "calls.jsonl")

	raw, err := os.ReadFile(callsPath) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(callsPath, []byte(strings.TrimSuffix(string(raw), "\n")), 0o600)) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input

	require.NoError(t, Validate(dir),
		"a journal without the trailing newline is a legacy writer, not a crash artifact")

	// The T08 repair contract: appendLine terminates the previous record
	// before adding the new one, so no record is ever glued.
	appendLine(t, callsPath, `{"call_id":"call-003","episode_id":"ep-001","root_id":"r","attempt_index":3,"arm":"g1","model_requested":"gpt-4o","model_actual":null,"endpoint":"https://x.example/v1","generation_id":null,"finish_reason":"stop","status":"ok","usage":{"tokens_in":10,"tokens_out":5,"reasoning_tokens":null},"cost":{"estimated_usd":0.002,"observed_usd":null,"uncertain":true},"latency":{"ttft_ms":400,"total_ms":1500},"decision_header":null,"error":null}`)

	fixed, err := os.ReadFile(callsPath) //nolint:gosec // G304/G703: paths are t.TempDir() fixtures, not request input
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(fixed), "\n"), "appended journal must end with a newline")
	assert.Contains(t, string(fixed), "}\n{\"call_id\":\"call-003\"",
		"the repaired previous record must stay intact and separated")

	require.NoError(t, Validate(dir), "repaired journal must stay valid")
}
