// Tests for the LiteLLM proxy-config dry-run (N16-P02-T03). Table-driven
// fixture tests pin the report content; drift tests keep the compatibility
// matrix aligned with pkg/provider, pkg/upstream and pkg/pricing.
package clientconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func mustDryRun(t *testing.T, fixture string) *LiteLLMMigrationReport {
	t.Helper()
	//nolint:gosec // G304: path is testdata/litellm + fixed fixture name from this test file's allowlist, not user input
	data, err := os.ReadFile(filepath.Join("testdata", "litellm", fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	rep, err := LiteLLMDryRun(data)
	if err != nil {
		t.Fatalf("LiteLLMDryRun(%s): unexpected error: %v", fixture, err)
	}
	if rep == nil {
		t.Fatalf("LiteLLMDryRun(%s): nil report", fixture)
	}
	return rep
}

func assertCounts(t *testing.T, rep *LiteLLMMigrationReport, want LiteLLMSummary) {
	t.Helper()
	if rep.Summary != want {
		t.Fatalf("summary mismatch:\n got %+v\nwant %+v", rep.Summary, want)
	}
	if got := len(rep.Transferable); got != want.Transferable {
		t.Fatalf("transferable list len %d, summary says %d", got, want.Transferable)
	}
	if got := len(rep.Differences); got != want.Differences {
		t.Fatalf("differences list len %d, summary says %d", got, want.Differences)
	}
	if got := len(rep.Conflicts); got != want.Conflicts {
		t.Fatalf("conflicts list len %d, summary says %d", got, want.Conflicts)
	}
	if got := len(rep.Unsupported); got != want.Unsupported {
		t.Fatalf("unsupported list len %d, summary says %d", got, want.Unsupported)
	}
	if got := len(rep.Secrets); got != want.Secrets {
		t.Fatalf("secrets list len %d, summary says %d", got, want.Secrets)
	}
	if got := len(rep.Plan); got != want.PlanEntries {
		t.Fatalf("plan len %d, summary says %d", got, want.PlanEntries)
	}
}

// findFinding returns the finding at path with disposition, failing if it is
// absent or duplicated.
func findFinding(t *testing.T, list []LiteLLMFinding, path, disposition string) LiteLLMFinding {
	t.Helper()
	var hits []LiteLLMFinding
	for _, f := range list {
		if f.Path == path && f.Disposition == disposition {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("no %s finding at %q in list of %d", disposition, path, len(list))
	}
	if len(hits) > 1 {
		t.Fatalf("duplicate %s findings at %q (%d)", disposition, path, len(hits))
	}
	return hits[0]
}

func TestLiteLLMDryRun_MinimalFixture(t *testing.T) {
	rep := mustDryRun(t, "minimal.yaml")
	assertCounts(t, rep, LiteLLMSummary{Transferable: 3, Differences: 2, PlanEntries: 1})
	row := findFinding(t, rep.Transferable, "model_list[0]", LiteLLMTransfer)
	if row.Target != "catalog row openai/gpt-4o" {
		t.Fatalf("row target = %q", row.Target)
	}
	tpm := findFinding(t, rep.Transferable, "model_list[0].litellm_params.tpm", LiteLLMTransfer)
	if tpm.Target != "catalog limits.max_tpm" || tpm.SourceValue != "10000" {
		t.Fatalf("tpm finding = %+v", tpm)
	}
	// The semantic difference of tpm/rpm is always stated: enforcement
	// posture (router limit) vs documented bound.
	diff := findFinding(t, rep.Differences, "model_list[0].litellm_params.tpm", LiteLLMDecision)
	if diff.SourceSemantics == "" || diff.TargetSemantics == "" {
		t.Fatalf("tpm difference must state both sides: %+v", diff)
	}
	if len(rep.Plan) != 1 {
		t.Fatalf("plan = %+v", rep.Plan)
	}
	entry := rep.Plan[0]
	if entry.Provider != "openai" || entry.Model != "gpt-4o" || entry.Action != "catalog.upsert" {
		t.Fatalf("plan entry = %+v", entry)
	}
	if entry.Limits == nil || entry.Limits.MaxTPM != 10000 || entry.Limits.MaxRPM != 100 {
		t.Fatalf("plan limits = %+v", entry.Limits)
	}
	// The group name equals the model id, so no alias is added (aliases are
	// only created for names that differ from the upstream model id).
	if len(entry.Aliases) != 0 {
		t.Fatalf("aliases = %v, want none", entry.Aliases)
	}
}

func TestLiteLLMDryRun_FullFixture(t *testing.T) {
	rep := mustDryRun(t, "full.yaml")
	assertCounts(t, rep, LiteLLMSummary{
		Transferable: 11, Differences: 8, Unsupported: 7, Secrets: 5, PlanEntries: 3,
	})

	// Key transfer paths.
	findFinding(t, rep.Transferable, "model_list[0]", LiteLLMTransfer)
	findFinding(t, rep.Transferable, "model_list[0].model_info.mode", LiteLLMTransfer)
	findFinding(t, rep.Transferable, "model_list[0].model_info.max_output_tokens", LiteLLMTransfer)
	findFinding(t, rep.Transferable, "model_list[1]", LiteLLMTransfer)
	findFinding(t, rep.Transferable, "model_list[3]", LiteLLMTransfer)
	findFinding(t, rep.Transferable, "$.router_settings.model_group_alias.sonnet", LiteLLMTransfer)

	// Semantic differences are explicit decisions.
	findFinding(t, rep.Differences, "model_list[0].model_info.max_input_tokens", LiteLLMDecision)
	findFinding(t, rep.Differences, "model_list[0].litellm_params.timeout", LiteLLMDecision)
	findFinding(t, rep.Differences, "model_list[1].litellm_params.api_base", LiteLLMDecision)
	findFinding(t, rep.Differences, "$.router_settings.fallbacks[0]", LiteLLMDecision)
	findFinding(t, rep.Differences, "$.router_settings.fallbacks[1]", LiteLLMDecision)
	findFinding(t, rep.Differences, "$.litellm_settings.request_timeout", LiteLLMDecision)

	// Unsupported capabilities are refused, never silent.
	findFinding(t, rep.Unsupported, "model_list[0].litellm_params.api_key", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "model_list[1].model_info.id", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "$.litellm_settings.drop_params", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "$.general_settings.master_key", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "$.general_settings.database_url", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "$.environment_variables.REDIS_URL", LiteLLMRefused)
	findFinding(t, rep.Unsupported, "$.environment_variables.SLACK_WEBHOOK_URL", LiteLLMRefused)

	// Plan merges the two anthropic deployments into one row with the two
	// group names plus the model_group_alias entry as aliases; limits and
	// capabilities ride the openai/gpt-4o row. The gpt-4o group name equals
	// the model id, so that row carries no aliases.
	wantPlan := []LiteLLMPlanEntry{
		{
			Action: "catalog.upsert", Provider: "openai", Model: "gpt-4o",
			Capabilities: map[string]bool{"chat": true},
			Limits:       &LiteLLMPlanLimits{MaxTPM: 20000, MaxRPM: 200, MaxOutputTokens: 16384},
			SourcePaths:  []string{"model_list[0]"},
		},
		{
			Action: "catalog.upsert", Provider: "openai", Model: "gpt-4o-mini",
			Aliases:     []string{"fast-openai"},
			SourcePaths: []string{"model_list[1]"},
		},
		{
			Action: "catalog.upsert", Provider: "anthropic", Model: "claude-sonnet-4-5",
			Aliases:      []string{"claude", "claude-fast", "sonnet"},
			Capabilities: map[string]bool{"chat": true},
			SourcePaths:  []string{"model_list[2]", "model_list[3]"},
		},
	}
	if !reflect.DeepEqual(rep.Plan, wantPlan) {
		t.Fatalf("plan mismatch:\n got %+v\nwant %+v", rep.Plan, wantPlan)
	}

	// Explicit scope statement (§14 negative promise).
	if len(rep.Scope.NotMigrated) == 0 {
		t.Fatal("scope.NotMigrated must be non-empty")
	}
	joined := ""
	for _, item := range rep.Scope.NotMigrated {
		joined += item.Item + " | "
	}
	for _, want := range []string{"user accounts", "request logs", "spend tracking"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scope.NotMigrated missing %q in %q", want, joined)
		}
	}

	// Report identifies the pinned source.
	if rep.Schema != LiteLLMDryRunSchema {
		t.Fatalf("schema = %d", rep.Schema)
	}
	if rep.Schema != 1 {
		t.Fatalf("schema bumped without updating this test: %d", rep.Schema)
	}
	if !strings.Contains(rep.Source.PinnedUpstream, "61a73c59b049a8cd6c559168d7f3a2557a1a8cf7") {
		t.Fatalf("pinned upstream = %q", rep.Source.PinnedUpstream)
	}
}

func TestLiteLLMDryRun_ConflictFixture(t *testing.T) {
	rep := mustDryRun(t, "conflicts.yaml")
	assertCounts(t, rep, LiteLLMSummary{Transferable: 4, Conflicts: 9, Unsupported: 1, Secrets: 2, PlanEntries: 1})

	// Zero tpm is a conflict, not a transfer: LiteLLM 0 blocks all traffic
	// while a catalog zero means unset — importing it would lift the limit.
	zero := findFinding(t, rep.Conflicts, "model_list[0].litellm_params.tpm", LiteLLMConflict)
	if !strings.Contains(zero.Detail, "block all traffic") || !strings.Contains(zero.Detail, "lift the limit") {
		t.Fatalf("tpm=0 conflict detail: %q", zero.Detail)
	}
	findFinding(t, rep.Conflicts, "model_list[1].litellm_params.rpm", LiteLLMConflict)
	// Duplicated model groups cannot become one catalog row.
	findFinding(t, rep.Conflicts, "model_list[model_name=gpt-4o]", LiteLLMConflict)
	cross := findFinding(t, rep.Conflicts, "model_list[model_name=duo]", LiteLLMConflict)
	if !strings.Contains(cross.Detail, "cross-provider") {
		t.Fatalf("duo conflict detail: %q", cross.Detail)
	}
	// Alias integrity.
	findFinding(t, rep.Conflicts, "$.router_settings.model_group_alias.ghost", LiteLLMConflict)
	shadow := findFinding(t, rep.Conflicts, "$.router_settings.model_group_alias.mistral-large-latest", LiteLLMConflict)
	if !strings.Contains(shadow.Detail, "shadows") {
		t.Fatalf("shadow conflict detail: %q", shadow.Detail)
	}
	findFinding(t, rep.Conflicts, "$.router_settings.model_group_alias.duo", LiteLLMConflict)
	// Undeterminable provider.
	findFinding(t, rep.Conflicts, "model_list[5].litellm_params.model", LiteLLMConflict)
	// Duplicate mapping key.
	dup := findFinding(t, rep.Conflicts, "$.general_settings", LiteLLMConflict)
	if !strings.Contains(dup.Detail, "duplicate key") {
		t.Fatalf("dup key conflict detail: %q", dup.Detail)
	}
	// Unknown fields are refused explicitly.
	unknown := findFinding(t, rep.Unsupported, "$.litellm_settings.unknown_future_switch", LiteLLMRefused)
	if !strings.Contains(unknown.Detail, "not in the pinned compatibility matrix") {
		t.Fatalf("unknown field detail: %q", unknown.Detail)
	}
	// The only unambiguous row survives in the plan.
	if len(rep.Plan) != 1 || rep.Plan[0].Provider != "mistral" || rep.Plan[0].Model != "mistral-large-latest" {
		t.Fatalf("plan = %+v", rep.Plan)
	}
}

func TestLiteLLMDryRun_WildcardFixture(t *testing.T) {
	rep := mustDryRun(t, "wildcard.yaml")
	assertCounts(t, rep, LiteLLMSummary{Differences: 1, Unsupported: 2})

	model := findFinding(t, rep.Unsupported, "model_list[0].litellm_params.model", LiteLLMRefused)
	if model.Kind != LiteLLMKindRoute || !strings.Contains(model.Detail, "wildcard") {
		t.Fatalf("wildcard model finding = %+v", model)
	}
	group := findFinding(t, rep.Unsupported, "model_list[1].model_name", LiteLLMRefused)
	if !strings.Contains(group.Detail, "wildcard") {
		t.Fatalf("wildcard group finding = %+v", group)
	}
	// The catch-all fallback is a stated decision, never a transfer.
	catch := findFinding(t, rep.Differences, "$.router_settings.fallbacks[0]", LiteLLMDecision)
	if catch.SourceValue == "" || !strings.Contains(catch.Target, "fallback_model") {
		t.Fatalf("catch-all finding = %+v", catch)
	}
	if len(rep.Plan) != 0 {
		t.Fatalf("wildcard config must produce no plan entries: %+v", rep.Plan)
	}
}

// TestLiteLLMDryRun_SecretsNeverLeak renders every fixture as JSON and text
// and asserts that no secret value reaches the output.
func TestLiteLLMDryRun_SecretsNeverLeak(t *testing.T) {
	forbidden := map[string][]string{
		"full.yaml": {
			"sk-1234abcdef123456", "hunter2", "os.environ/OPENAI_API_KEY",
			"T000/B000", "cache.internal", "OPENAI_API_KEY",
		},
		"conflicts.yaml": {"sk-aaaabbbbccccdddd", "sk-eeeeffffgggghhhh"},
		"secrets.yaml": {
			"sk-supersecret123456789", "p4ssw0rd", "topsecret-redis-pass",
			"sk-internalkey123456", "supersecret-azure-key",
		},
		"minimal.yaml":  nil,
		"wildcard.yaml": nil,
	}
	for fixture, secrets := range forbidden {
		rep := mustDryRun(t, fixture)
		jsonBody, err := LiteLLMReportJSON(rep)
		if err != nil {
			t.Fatalf("%s: json render: %v", fixture, err)
		}
		text := RenderLiteLLMReport(rep)
		for _, out := range []string{jsonBody, text} {
			for _, secret := range secrets {
				if strings.Contains(out, secret) {
					t.Fatalf("%s: output contains forbidden secret %q", fixture, secret)
				}
			}
		}
	}

	// The secrets fixture carries the redaction marker and the exact
	// redacted path list; the api_base value survives with its credential
	// component scrubbed.
	rep := mustDryRun(t, "secrets.yaml")
	jsonBody, err := LiteLLMReportJSON(rep)
	if err != nil {
		t.Fatalf("json render: %v", err)
	}
	if !strings.Contains(jsonBody, LiteLLMRedacted) {
		t.Fatal("secrets fixture report must contain the redaction marker")
	}
	apiBase := findFinding(t, rep.Differences, "model_list[0].litellm_params.api_base", LiteLLMDecision)
	if strings.Contains(apiBase.SourceValue, "p4ssw0rd") || !strings.Contains(apiBase.SourceValue, LiteLLMRedacted+"@gateway.internal/v1") {
		t.Fatalf("api_base scrub = %q", apiBase.SourceValue)
	}
	wantPaths := []string{
		"$.general_settings.master_key",
		"$.general_settings.database_url",
		"$.general_settings.redis_password",
		"model_list[0].litellm_params.api_key",
		"$.environment_variables.AZURE_API_KEY",
	}
	var gotPaths []string
	for _, s := range rep.Secrets {
		gotPaths = append(gotPaths, s.Path)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("secret paths:\n got %v\nwant %v", gotPaths, wantPaths)
	}
}

// TestLiteLLMDryRun_ParseErrors pins the hard-failure behavior for untrusted
// input: no report is produced for broken input.
func TestLiteLLMDryRun_ParseErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "\n\n"},
		{"scalar root", "hello\n"},
		{"sequence root", "- a\n- b\n"},
		{"trailing document", "model_list: []\n---\nfoo: 1\n"},
		{"malformed", "model_list: [unclosed\n"},
	}
	for _, tc := range cases {
		rep, err := LiteLLMDryRun([]byte(tc.input))
		if err == nil {
			t.Fatalf("%s: expected error, got report %+v", tc.name, rep)
		}
		if !strings.Contains(err.Error(), "parse litellm proxy config") {
			t.Fatalf("%s: error = %v", tc.name, err)
		}
		if rep != nil {
			t.Fatalf("%s: error case must not return a report", tc.name)
		}
	}
}

func TestLiteLLMDryRun_EmptyObjectMapping(t *testing.T) {
	rep, err := LiteLLMDryRun([]byte("{}\n"))
	if err != nil {
		t.Fatalf("empty mapping: %v", err)
	}
	assertCounts(t, rep, LiteLLMSummary{})
	if len(rep.Scope.Migrated) == 0 || len(rep.Scope.NotMigrated) == 0 {
		t.Fatal("scope statement is always present, even for an empty config")
	}
}

// TestLiteLLMDryRun_UnknownTopLevelIsRefused pins the explicit-disposition
// guarantee at the top level: an unknown section can never pass silently.
func TestLiteLLMDryRun_UnknownTopLevelIsRefused(t *testing.T) {
	rep, err := LiteLLMDryRun([]byte("callbacks:\n  success: https://x.example/hook\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := findFinding(t, rep.Unsupported, "$.callbacks", LiteLLMRefused)
	if f.SourceValue != "<mapping: 1 keys>" {
		t.Fatalf("composite values are summarized, never inlined: %q", f.SourceValue)
	}
	if !strings.Contains(f.Detail, "not part of the pinned import contract") {
		t.Fatalf("detail = %q", f.Detail)
	}
	if len(rep.Plan) != 0 {
		t.Fatalf("plan = %+v", rep.Plan)
	}
}

// TestLiteLLMDryRun_Deterministic pins deterministic output: same input
// yields byte-identical reports across runs.
func TestLiteLLMDryRun_Deterministic(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "litellm", "full.yaml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var prevJSON, prevText string
	for i := 0; i < 5; i++ {
		rep, err := LiteLLMDryRun(data)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		jsonBody, err := LiteLLMReportJSON(rep)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		text := RenderLiteLLMReport(rep)
		// Round-trip: JSON renders back into the same report shape.
		var back LiteLLMMigrationReport
		if err := json.Unmarshal([]byte(jsonBody), &back); err != nil {
			t.Fatalf("run %d: json round-trip: %v", i, err)
		}
		if back.Summary != rep.Summary {
			t.Fatalf("run %d: json round-trip changed the summary", i)
		}
		if i > 0 {
			if jsonBody != prevJSON {
				t.Fatalf("run %d: json output is not deterministic", i)
			}
			if text != prevText {
				t.Fatalf("run %d: text output is not deterministic", i)
			}
		}
		prevJSON, prevText = jsonBody, text
	}
}

func TestLiteLLMConfigPin_Stability(t *testing.T) {
	first := LiteLLMConfigPin()
	second := LiteLLMConfigPin()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("pin must be a stable value, not mutable package state")
	}
	wantSections := []string{
		"model_list", "router_settings", "litellm_settings", "general_settings", "environment_variables",
	}
	if !reflect.DeepEqual(first.SupportedSections, wantSections) {
		t.Fatalf("sections = %v", first.SupportedSections)
	}
	if !sort.StringsAreSorted(first.ProviderTargets) {
		t.Fatalf("provider targets not sorted: %v", first.ProviderTargets)
	}
	for _, limitation := range first.Limitations {
		if limitation == "" {
			t.Fatal("empty limitation entry")
		}
	}
	// The pin promises the §14 negative in writing.
	joined := strings.Join(first.Limitations, " ")
	for _, want := range []string{"no user accounts, request logs, or financial history", "never pass silently"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("pin limitations missing %q", want)
		}
	}
}

// TestLiteLLMProviderTargets_MatchProviderRegistry is a drift test: every
// configured target provider must be constructible in pkg/provider.
func TestLiteLLMProviderTargets_MatchProviderRegistry(t *testing.T) {
	for canonical, target := range litellmProviderTargets {
		if _, err := provider.New(target); err != nil {
			t.Errorf("target %q (litellm %q) is not constructible: %v", target, canonical, err)
		}
	}
	if _, err := provider.New("azure-openai"); err != nil {
		t.Errorf("azure deployments target azure-openai: %v", err)
	}
}

// TestLiteLLMModeCapabilities_MatchCatalogVocabulary is a drift test: every
// capability the mode map emits must exist in the upstream catalog
// vocabulary.
func TestLiteLLMModeCapabilities_MatchCatalogVocabulary(t *testing.T) {
	fields := upstream.CatalogCapabilityFields()
	for mode, capKey := range litellmModeCapabilities {
		if _, ok := fields[capKey]; !ok {
			t.Errorf("mode %q maps to %q which is not a catalog capability field", mode, capKey)
		}
	}
	// chat and embeddings stay reachable: the two most common modes.
	for _, capKey := range []string{"chat", "embeddings"} {
		if _, ok := fields[capKey]; !ok {
			t.Errorf("catalog lost capability %q", capKey)
		}
	}
}

// TestLiteLLMPlanLimits_MatchCatalogLimitJSONTags is a drift test: plan
// limit JSON tags must equal the upstream catalog document's tags so the
// apply step can assemble catalog entries without renaming.
func TestLiteLLMPlanLimits_MatchCatalogLimitJSONTags(t *testing.T) {
	catalogTags := map[string]string{}
	catType := reflect.TypeOf(upstream.CatalogLimits{})
	for i := 0; i < catType.NumField(); i++ {
		tag := catType.Field(i).Tag.Get("json")
		if tag == "" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		catalogTags[catType.Field(i).Name] = name
	}
	planType := reflect.TypeOf(LiteLLMPlanLimits{})
	for i := 0; i < planType.NumField(); i++ {
		field := planType.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		catalogTag, ok := catalogTags[field.Name]
		if !ok {
			t.Errorf("plan limit field %q has no counterpart in upstream.CatalogLimits", field.Name)
			continue
		}
		if tag != catalogTag {
			t.Errorf("plan limit %q json tag %q != catalog tag %q", field.Name, tag, catalogTag)
		}
	}
}

// TestLiteLLMConfigPin_MatchesPricingPinCommit pins both migration halves to
// the same upstream snapshot commit.
func TestLiteLLMConfigPin_MatchesPricingPinCommit(t *testing.T) {
	pp := pricing.LiteLLMFormatPin().PinnedUpstream
	idx := strings.Index(pp, " @ ")
	if idx < 0 {
		t.Fatalf("pricing pin upstream = %q", pp)
	}
	commit := strings.Fields(pp[idx+3:])[0]
	if commit != "61a73c59b049a8cd6c559168d7f3a2557a1a8cf7" {
		t.Fatalf("unexpected pricing commit %q (upstream bump must update this card's pin)", commit)
	}
	if !strings.Contains(LiteLLMConfigPin().PinnedUpstream, commit) {
		t.Fatal("config pin and pricing pin reference different upstream commits")
	}
}

// TestLiteLLMCanonicalProvider_FoldsLikePricing pins the provider folding:
// case, underscores, pinned aliases and the vertex region family.
func TestLiteLLMCanonicalProvider_FoldsLikePricing(t *testing.T) {
	cases := map[string]string{
		"openai":              "openai",
		"OpenAI":              "openai",
		"ollama_chat":         "ollama-chat",
		"OLLAMA-CHAT":         "ollama-chat",
		"vertex_ai_us-east-1": "vertex",
		"vertex-ai":           "vertex",
		"azure":               "azure",
		"bedrock":             "bedrock",
	}
	for raw, want := range cases {
		if got := litellmCanonicalProvider(raw); got != want {
			t.Errorf("litellmCanonicalProvider(%q) = %q, want %q", raw, got, want)
		}
	}
	// The canonical id then maps onto the Yabanin target provider.
	if got := litellmProviderTargets[litellmCanonicalProvider("ollama_chat")]; got != "ollama" {
		t.Errorf("ollama_chat target = %q, want ollama", got)
	}
	// The pin's alias table must keep agreeing with the folding: anything
	// the pricing importer canonicalizes one way cannot be re-folded here.
	for alias, canonical := range pricing.LiteLLMFormatPin().ProviderAliases {
		if got := litellmCanonicalProvider(alias); got != canonical {
			t.Errorf("alias %q folds to %q but the pricing pin says %q", alias, got, canonical)
		}
	}
}

func TestRenderLiteLLMReport_Text(t *testing.T) {
	rep := mustDryRun(t, "full.yaml")
	text := RenderLiteLLMReport(rep)
	for _, want := range []string{
		"DRY RUN ONLY",
		"NOT migrated: user accounts",
		"NOT migrated: request logs",
		"NOT migrated: spend tracking",
		"transferable (11):",
		"semantic differences (8):",
		"unsupported (7):",
		"secrets redacted (5 paths",
		"plan preview (3 catalog rows",
		"anthropic/claude-sonnet-4-5",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text report missing %q", want)
		}
	}
}

// TestLiteLLMDryRun_DuplicateKeysRefused pins the duplicate-key semantics:
// every occurrence of a duplicated key is ambiguous, the mapping-level
// conflict is the refusal, and the affected entity can never reach the plan
// (fail-closed), while the secret redaction ledger stays complete.
func TestLiteLLMDryRun_DuplicateKeysRefused(t *testing.T) {
	rep, err := LiteLLMDryRun([]byte(`model_list:
  - model_name: dup-limits
    litellm_params:
      model: openai/gpt-4o
      tpm: 10000
      tpm: 0
  - model_name: dup-info
    litellm_params:
      model: anthropic/claude-sonnet-4-5
    model_info:
      mode: chat
      mode: embeddings
  - model_name: clean
    litellm_params:
      model: openai/gpt-4o-mini
router_settings:
  model_group_alias:
    twice: clean
    twice: clean
general_settings:
  master_key: sk-aaaabbbbccccdddd
  master_key: sk-eeeeffffgggghhhh
environment_variables:
  DUP_VAR: one
  DUP_VAR: two
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Duplicate tpm: no limit finding can claim a verified value.
	for _, f := range rep.Transferable {
		if strings.Contains(f.Path, "dup-limits") {
			t.Fatalf("dup-limits deployment must not produce transfer findings: %+v", f)
		}
	}

	// Duplicate model_info.mode: the deployment is conflicted, no plan row.
	if got := len(rep.Plan); got != 1 {
		t.Fatalf("plan entries = %d, want only the clean deployment: %+v", got, rep.Plan)
	}
	if rep.Plan[0].Model != "gpt-4o-mini" {
		t.Fatalf("plan[0] = %+v", rep.Plan[0])
	}

	// Exactly one duplicate-key conflict per affected mapping.
	dupConflicts := 0
	for _, f := range rep.Conflicts {
		if strings.Contains(f.Detail, "duplicate key") {
			dupConflicts++
		}
	}
	if dupConflicts != 5 {
		t.Fatalf("duplicate-key conflicts = %d, want 5 (deployment params, model_info, alias map, general_settings, environment_variables)", dupConflicts)
	}

	// The secret ledger records every occurrence, but duplicate keys do not
	// repeat the unsupported refusal.
	secretHits := 0
	for _, s := range rep.Secrets {
		if s.Path == "$.general_settings.master_key" {
			secretHits++
		}
	}
	if secretHits != 2 {
		t.Fatalf("master_key ledger entries = %d, want 2 (one per occurrence)", secretHits)
	}
	masterRefusals := 0
	for _, f := range rep.Unsupported {
		if f.Path == "$.general_settings.master_key" {
			masterRefusals++
		}
	}
	if masterRefusals != 0 {
		t.Fatalf("duplicate master_key must be refused by the section conflict only, got %d unsupported findings", masterRefusals)
	}
	envHits := 0
	for _, s := range rep.Secrets {
		if s.Path == "$.environment_variables.DUP_VAR" {
			envHits++
		}
	}
	if envHits != 2 {
		t.Fatalf("DUP_VAR ledger entries = %d, want 2", envHits)
	}

	// A plan row without capabilities carries a nil map, so the JSON
	// omitempty tag drops the field entirely.
	jsonBody, err := LiteLLMReportJSON(rep)
	if err != nil {
		t.Fatalf("json render: %v", err)
	}
	if strings.Contains(jsonBody, `"capabilities": null`) {
		t.Fatal("empty capabilities must be omitted, not rendered as null")
	}
}
