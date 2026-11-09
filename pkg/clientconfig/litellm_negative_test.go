// Negative-contract tests for the LiteLLM migration (N16-P02-T05). Each
// test reproduces one packet negative scenario end-to-end at the library
// level and pins cause → expected result, so the dry-run can never report
// a false success:
//
//	N1  unsupported limit/route-shaped fields are never silently skipped;
//	    they are reported unsupported, never enter the plan, and are never
//	    cited by a plan entry (so the apply gate would refuse them);
//	N2  limit values that would silently change meaning (zero, negative,
//	    non-integer) are conflicts and exclude the deployment from the plan;
//	N3  the import never promises user, log or financial-history transfer:
//	    the scope statement is carried by every report in both renderers and
//	    the plan DTO has no field that could carry such entities;
//	N4  a source with nothing verified to transfer yields zero plan entries
//	    and the apply refuses instead of reporting success;
//	N5  secret-shaped fields are refused and redacted wherever they appear —
//	    including names outside the pinned matrix — and no renderer emits
//	    their values.
//
// The scenarios deliberately use inline YAML constants (not testdata files)
// so the quality classifier never falls back to the full battery on a new
// non-Go file (T04 run-3 lesson).
package clientconfig

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func mustDryRunBytes(t *testing.T, name, fixture string) *LiteLLMMigrationReport {
	t.Helper()
	rep, err := LiteLLMDryRun([]byte(fixture))
	if err != nil {
		t.Fatalf("LiteLLMDryRun(%s): unexpected error: %v", name, err)
	}
	if rep == nil {
		t.Fatalf("LiteLLMDryRun(%s): nil report", name)
	}
	return rep
}

// unsupportedPaths returns the sorted report paths of the unsupported
// findings and fails when the same path appears twice.
func unsupportedPaths(t *testing.T, rep *LiteLLMMigrationReport) []string {
	t.Helper()
	seen := map[string]bool{}
	var paths []string
	for _, f := range rep.Unsupported {
		if seen[f.Path] {
			t.Fatalf("duplicate unsupported finding at %q", f.Path)
		}
		seen[f.Path] = true
		paths = append(paths, f.Path)
	}
	return paths
}

// N1 fixture: a otherwise-clean deployment planted with one unknown field at
// every level a newer LiteLLM release could add fields to: a router limit
// name, a router route name, a settings key, a model_info limit, a
// litellm_params key and a deployment-level key.
const negativeUnsupportedFieldsFixture = `model_list:
  - model_name: "clean-one"
    model_info:
      mode: "chat"
      input_token_limit: 8192
    litellm_params:
      model: "openai/gpt-4o"
      tpm: 1000
      rpm: 60
      my_custom_flag: true
    pre_call_check: "plugin-x"
router_settings:
  rpm: 60
  preferred_route: "cheapest"
litellm_settings:
  request_cost_map: "custom"
`

// TestLiteLLMNegative_UnsupportedLimitRouteNeverSilent pins N1: every
// planted unknown field comes back as an explicit unsupported finding with
// its exact source path; none of them reaches the plan or its source paths.
func TestLiteLLMNegative_UnsupportedLimitRouteNeverSilent(t *testing.T) {
	rep := mustDryRunBytes(t, "unsupported-fields", negativeUnsupportedFieldsFixture)

	want := []string{
		"$.litellm_settings.request_cost_map",
		"$.router_settings.preferred_route",
		"$.router_settings.rpm",
		"model_list[0].litellm_params.my_custom_flag",
		"model_list[0].model_info.input_token_limit",
		"model_list[0].pre_call_check",
	}
	got := unsupportedPaths(t, rep)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unsupported paths:\n got %v\nwant %v", got, want)
	}
	// The clean parts still transfer: the row, its limits and the mode.
	assertCounts(t, rep, LiteLLMSummary{Transferable: 4, Differences: 2, Unsupported: 6, PlanEntries: 1})

	// The refusal detail names the matrix section and the no-silent-skip
	// promise (spot check on one planted field).
	f := findFinding(t, rep.Unsupported, "$.router_settings.rpm", LiteLLMRefused)
	if !strings.Contains(f.Detail, "is not in the pinned compatibility matrix for router_settings") ||
		!strings.Contains(f.Detail, "will not transfer silently") {
		t.Fatalf("rpm refusal detail = %q", f.Detail)
	}

	// The plan cites only the deployment row — never an unsupported field
	// path — so the apply gate's source-path link check can never wave an
	// unsupported field through.
	if len(rep.Plan) != 1 {
		t.Fatalf("plan = %+v", rep.Plan)
	}
	entry := rep.Plan[0]
	if !reflect.DeepEqual(entry.SourcePaths, []string{"model_list[0]"}) {
		t.Fatalf("plan source paths = %v", entry.SourcePaths)
	}
	for _, source := range entry.SourcePaths {
		for _, u := range rep.Unsupported {
			if u.Path == source {
				t.Fatalf("plan cites unsupported source path %q", source)
			}
		}
	}

	// Both consumer renderers surface every unsupported path (an operator
	// reading only one format still sees the refusal).
	text := RenderLiteLLMReport(rep)
	if !strings.Contains(text, "unsupported (6):") {
		t.Fatalf("text render missing unsupported count section:\n%s", text)
	}
	jsonBody, err := LiteLLMReportJSON(rep)
	if err != nil {
		t.Fatalf("json render: %v", err)
	}
	for _, out := range []string{text, jsonBody} {
		for _, path := range want {
			if !strings.Contains(out, path) {
				t.Fatalf("render missing unsupported path %q", path)
			}
		}
	}
}

// N2 fixture: every limit value that would silently change meaning.
const negativeLimitSemanticsFixture = `model_list:
  - model_name: "zeroed"
    litellm_params:
      model: "openai/m-zero"
      tpm: 0
      rpm: -5
  - model_name: "infozero"
    model_info:
      max_output_tokens: 0
    litellm_params:
      model: "openai/m-info"
  - model_name: "nonint"
    litellm_params:
      model: "openai/m-ni"
      tpm: "ten"
`

// TestLiteLLMNegative_LimitSemanticsRefused pins N2: zero reads as
// block-all in LiteLLM but unset (unlimited) in the catalog, negative bounds
// are invalid on both sides, and non-integers cannot transfer — each is a
// conflict at the exact path. A deployment whose identity-level limits are
// conflicted (tpm/rpm) is excluded from the plan entirely; a deployment
// whose only problem is a zero model_info output bound still transfers its
// verified identity row, but never the bound itself (a catalog absence of
// the field is semantically identical to the source zero: unset).
func TestLiteLLMNegative_LimitSemanticsRefused(t *testing.T) {
	rep := mustDryRunBytes(t, "limit-semantics", negativeLimitSemanticsFixture)

	assertCounts(t, rep, LiteLLMSummary{Transferable: 1, Conflicts: 4, PlanEntries: 1})

	cases := []struct{ path, detailFragment string }{
		{"model_list[0].litellm_params.tpm", `tpm=0 means "block all traffic"`},
		{"model_list[0].litellm_params.rpm", "negative rpm limit cannot transfer"},
		{"model_list[1].model_info.max_output_tokens", "max_output_tokens=0 cannot transfer"},
		{"model_list[2].litellm_params.tpm", "must be a plain decimal integer"},
	}
	for _, tc := range cases {
		f := findFinding(t, rep.Conflicts, tc.path, LiteLLMConflict)
		if f.Kind != LiteLLMKindLimit {
			t.Fatalf("%s: kind = %q, want limit", tc.path, f.Kind)
		}
		if !strings.Contains(f.Detail, tc.detailFragment) {
			t.Fatalf("%s: detail = %q, want it to contain %q", tc.path, f.Detail, tc.detailFragment)
		}
		// The same path must never also be a transfer: a conflicted limit
		// value has no verified semantics on the target side.
		for _, tr := range rep.Transferable {
			if tr.Path == tc.path {
				t.Fatalf("%s appears both as conflict and transfer", tc.path)
			}
		}
	}

	// Only the row with a clean identity reaches the plan — and it carries
	// no limits block at all: the refused zero bound is not silently
	// rewritten into some other value.
	if len(rep.Plan) != 1 {
		t.Fatalf("plan = %+v", rep.Plan)
	}
	if rep.Plan[0].Model != "m-info" || rep.Plan[0].Limits != nil {
		t.Fatalf("plan entry = %+v, want m-info without limits", rep.Plan[0])
	}
}

// TestLiteLLMNegative_ScopeExcludesUserLogSpendHistory pins N3: every report
// — clean or adversarial — states the import scope, and that scope never
// promises users, logs or financial history. The plan DTO itself has no
// field that could carry such entities.
func TestLiteLLMNegative_ScopeExcludesUserLogSpendHistory(t *testing.T) {
	fixtures := map[string]string{
		"minimal":     "model_list:\n  - model_name: \"m\"\n    litellm_params:\n      model: \"openai/gpt-4o\"\n",
		"empty":       "{}\n",
		"unsupported": negativeUnsupportedFieldsFixture,
		"adversarial": adversarialFixtureYAML,
	}
	notMigratedFragments := []string{
		"user accounts",     // users
		"request logs",      // old logs
		"financial history", // spend/financial history
		"credentials",       // secrets are also never part of the promise
	}
	for name, fixture := range fixtures {
		rep := mustDryRunBytes(t, name, fixture)
		if rep.Schema != LiteLLMDryRunSchema {
			t.Fatalf("%s: schema %d", name, rep.Schema)
		}
		joined := make([]string, 0, len(rep.Scope.NotMigrated))
		for _, item := range rep.Scope.NotMigrated {
			joined = append(joined, item.Item+" — "+item.Reason)
		}
		notMigrated := strings.Join(joined, "\n")
		for _, fragment := range notMigratedFragments {
			if !strings.Contains(notMigrated, fragment) {
				t.Fatalf("%s: scope.NotMigrated does not state %q:\n%s", name, fragment, notMigrated)
			}
		}
		// The migrated side is configuration-only: no user, log, spend,
		// history or credential wording may appear there (word-boundary
		// match — "catalog" must not trip the "log" check).
		migrated := strings.Join(rep.Scope.Migrated, "\n")
		for _, forbidden := range []string{"users?", "accounts?", "logs?", "spend", "history", "credentials?"} {
			re := regexp.MustCompile(`\b` + forbidden + `\b`)
			if re.MatchString(migrated) {
				t.Fatalf("%s: scope.Migrated promises %q: %q", name, forbidden, migrated)
			}
		}

		// Both renderers carry the non-goals.
		text := RenderLiteLLMReport(rep)
		if !strings.Contains(text, "NOT migrated: user accounts") ||
			!strings.Contains(text, "NOT migrated: request logs") ||
			!strings.Contains(text, "NOT migrated: spend tracking and financial history") {
			t.Fatalf("%s: text render misses the non-goals:\n%s", name, text)
		}
		var roundTrip LiteLLMMigrationReport
		jsonBody, err := LiteLLMReportJSON(rep)
		if err != nil {
			t.Fatalf("%s: json render: %v", name, err)
		}
		if err := json.Unmarshal([]byte(jsonBody), &roundTrip); err != nil {
			t.Fatalf("%s: json round trip: %v", name, err)
		}
		if !reflect.DeepEqual(roundTrip.Scope, rep.Scope) {
			t.Fatalf("%s: scope round trip mismatch:\n got %+v\nwant %+v", name, roundTrip.Scope, rep.Scope)
		}
	}
}

// TestLiteLLMNegative_PlanDTOHasNoUserLogSpendFields pins the structural
// half of N3: the plan entry vocabulary is closed — a JSON-encoded plan can
// only carry action/provider/model/aliases/capabilities/limits/source_paths,
// so no user account, log record or financial entry could ride along even in
// a hand-crafted report.
func TestLiteLLMNegative_PlanDTOHasNoUserLogSpendFields(t *testing.T) {
	rep := mustDryRunBytes(t, "minimal", "model_list:\n  - model_name: \"m\"\n    litellm_params:\n      model: \"openai/gpt-4o\"\n")
	if len(rep.Plan) != 1 {
		t.Fatalf("plan = %+v", rep.Plan)
	}
	body, err := json.Marshal(rep.Plan[0])
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("unmarshal plan: %v", err)
	}
	allowed := map[string]bool{
		"action": true, "provider": true, "model": true, "aliases": true,
		"capabilities": true, "limits": true, "source_paths": true,
	}
	for key := range keys {
		if !allowed[key] {
			t.Fatalf("plan DTO carries unexpected field %q", key)
		}
	}
	// Same closure on the wire format the apply consumes.
	var loose map[string]any
	jsonBody, err := LiteLLMReportJSON(rep)
	if err != nil {
		t.Fatalf("json render: %v", err)
	}
	if err := json.Unmarshal([]byte(jsonBody), &loose); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	plan, ok := loose["plan"].([]any)
	if !ok || len(plan) != 1 {
		t.Fatalf("report plan = %#v", loose["plan"])
	}
	row, ok := plan[0].(map[string]any)
	if !ok {
		t.Fatalf("plan row = %#v", plan[0])
	}
	for key := range row {
		if !allowed[key] {
			t.Fatalf("wire plan carries unexpected field %q", key)
		}
	}
}

// N4 fixture: a config with only unsupported settings and no deployments —
// nothing is verified, so there is nothing to apply.
const negativeUnsupportedOnlyFixture = `litellm_settings:
  acme_experimental: true
router_settings:
  custom_strategy: "latency"
`

// TestLiteLLMNegative_UnsupportedOnlyRefusedAtApply pins N4: the dry-run
// still produces a report (with the unsupported findings), but the plan is
// empty and the apply refuses with an explicit problem instead of reporting
// success — and it writes nothing.
func TestLiteLLMNegative_UnsupportedOnlyRefusedAtApply(t *testing.T) {
	rep := mustDryRunBytes(t, "unsupported-only", negativeUnsupportedOnlyFixture)
	assertCounts(t, rep, LiteLLMSummary{Unsupported: 2, PlanEntries: 0})

	dir := t.TempDir()
	catalogPath := dir + "/catalog.json"
	targets := LiteLLMApplyTargets{CatalogPath: catalogPath}
	_, err := LiteLLMApply(rep, targets)
	refusal, ok := err.(*LiteLLMApplyRefusal)
	if !ok {
		t.Fatalf("apply error = %v, want *LiteLLMApplyRefusal", err)
	}
	joined := strings.Join(refusal.Problems, "\n")
	if !strings.Contains(joined, "report carries no plan entries") {
		t.Fatalf("refusal problems = %v", refusal.Problems)
	}
	if _, statErr := os.Stat(catalogPath); !os.IsNotExist(statErr) {
		t.Fatalf("refused apply must not create the catalog (stat err = %v)", statErr)
	}
	// The dry-run summary already told the operator the plan is empty — the
	// negative status is visible before any apply is attempted.
	if rep.Summary.PlanEntries != 0 {
		t.Fatalf("summary plan entries = %d", rep.Summary.PlanEntries)
	}
}

// N5 fixture: credential-shaped fields under names outside the pinned
// matrix, in sections that have no explicit secret rule.
//
//nolint:gosec // G101: synthetic negative-fixture literals; the values are assertion probes that must be redacted, not credentials
const negativeSecretShapedFixture = `model_list:
  - model_name: "sec"
    model_info:
      mode: "chat"
      access_secret: "s3cr3t-value"
    litellm_params:
      model: "openai/gpt-4o"
      oauth2_client_secret: "oauth-secret-1"
router_settings:
  proxy_connection_string: "postgres://admin:hunter2@db.internal/litellm"
litellm_settings:
  acme_api_key: "sk-live-abcdef1234567890"
`

// TestLiteLLMNegative_SecretShapedUnknownFieldsRedacted pins N5: a
// credential-shaped field is treated as a secret wherever it appears — even
// when its name is not in the matrix — it enters the redaction ledger, its
// finding carries the redaction marker instead of the value, and no renderer
// emits the value.
func TestLiteLLMNegative_SecretShapedUnknownFieldsRedacted(t *testing.T) {
	rep := mustDryRunBytes(t, "secret-shaped", negativeSecretShapedFixture)

	// The clean parts survive: the row, its mode capability and the stated
	// refusals for everything else.
	if rep.Summary.Secrets != 4 {
		t.Fatalf("summary = %+v, want 4 secrets", rep.Summary)
	}
	wantLedger := []string{
		"$.litellm_settings.acme_api_key",
		"$.router_settings.proxy_connection_string",
		"model_list[0].litellm_params.oauth2_client_secret",
		"model_list[0].model_info.access_secret",
	}
	var gotLedger []string
	for _, s := range rep.Secrets {
		gotLedger = append(gotLedger, s.Path)
	}
	sort.Strings(gotLedger)
	wantSorted := append([]string(nil), wantLedger...)
	sort.Strings(wantSorted)
	if !reflect.DeepEqual(gotLedger, wantSorted) {
		t.Fatalf("secret ledger:\n got %v\nwant %v", gotLedger, wantSorted)
	}

	// Each secret location is also an explicit refusal whose source value is
	// the marker, never the raw credential.
	for _, path := range wantLedger {
		f := findFinding(t, rep.Unsupported, path, LiteLLMRefused)
		if f.SourceValue != LiteLLMRedacted {
			t.Fatalf("%s: source value = %q, want the redaction marker", path, f.SourceValue)
		}
		if f.Kind != LiteLLMKindSecret {
			t.Fatalf("%s: kind = %q, want secret", path, f.Kind)
		}
	}

	// No renderer emits any raw credential fragment.
	jsonBody, err := LiteLLMReportJSON(rep)
	if err != nil {
		t.Fatalf("json render: %v", err)
	}
	text := RenderLiteLLMReport(rep)
	for _, out := range []string{jsonBody, text} {
		for _, secret := range []string{"s3cr3t-value", "oauth-secret-1", "hunter2", "sk-live-abcdef1234567890", "postgres://admin"} {
			if strings.Contains(out, secret) {
				t.Fatalf("render emits credential fragment %q", secret)
			}
		}
	}

	// The plan (only the clean row) cannot cite a secret path.
	if len(rep.Plan) != 1 || !reflect.DeepEqual(rep.Plan[0].SourcePaths, []string{"model_list[0]"}) {
		t.Fatalf("plan = %+v", rep.Plan)
	}
}
