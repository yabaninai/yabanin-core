// The LiteLLM proxy-config migration pin and dry-run report model
// (N16-P02-T03). The price/unit catalog slice of the LiteLLM migration lives
// in pkg/pricing (litellm_format.go); this file owns the config-level half:
// model_list / router_settings / litellm_settings / general_settings are
// parsed, classified and reported BEFORE anything is applied (owner decision
// I65: report of transferable settings, semantic differences and unsupported
// capabilities; PRODUCT-CONTRACT.md §14).
//
// Invariants pinned here and enforced by the walker:
//   - every input field gets an explicit disposition from the compatibility
//     matrix; a field that is not in the matrix is reported as unsupported —
//     an unsupported limit/route can never pass silently;
//   - the import promises nothing about user accounts, request logs or
//     financial history; the report states that scope explicitly;
//   - secret-bearing fields are refused and their values are replaced by
//     "[REDACTED]" everywhere, including path lists and free-form details.
package clientconfig

import (
	"regexp"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/redact"
)

// LiteLLMDryRunSchema is the report schema version. Bump when the report
// vocabulary changes; consumers must refuse schemas they do not know.
const LiteLLMDryRunSchema = 1

// Redaction marker and finding dispositions.
const (
	LiteLLMRedacted = "[REDACTED]"

	// LiteLLMTransfer marks a finding whose semantics are verified: the
	// entity has a plan entry and can be applied by a reviewed apply step.
	LiteLLMTransfer = "transfer"
	// LiteLLMDecision marks a semantic difference: LiteLLM and Yabanin
	// attach different meaning to the setting, so nothing transfers without
	// an explicit operator resolution.
	LiteLLMDecision = "decision"
	// LiteLLMConflict marks input that cannot be imported as-is (duplicate
	// identities, dangling references, limits that would invert meaning).
	LiteLLMConflict = "conflict"
	// LiteLLMRefused marks unsupported capabilities with an explicit reason.
	LiteLLMRefused = "refused"
)

// Finding kinds — what aspect of the source the finding talks about.
const (
	LiteLLMKindSetting    = "setting"
	LiteLLMKindLimit      = "limit"
	LiteLLMKindRoute      = "route"
	LiteLLMKindCapability = "capability"
	LiteLLMKindSecret     = "secret"
)

// LiteLLMReportSource identifies the pinned source format of a report.
type LiteLLMReportSource struct {
	Format         string `json:"format"`
	PinnedUpstream string `json:"pinned_upstream"`
	Notice         string `json:"notice"`
}

// LiteLLMSummary counts findings per class plus the derived transfer plan.
type LiteLLMSummary struct {
	Transferable int `json:"transferable"`
	Differences  int `json:"semantic_differences"`
	Conflicts    int `json:"conflicts"`
	Unsupported  int `json:"unsupported"`
	Secrets      int `json:"secrets_redacted"`
	PlanEntries  int `json:"plan_entries"`
}

// LiteLLMScopeItem is one scope statement of the import promise.
type LiteLLMScopeItem struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
}

// LiteLLMScope states what the import does and explicitly does not carry.
// The NotMigrated list is the contract-level negative (§14): no promise of
// user accounts, request logs or financial history.
type LiteLLMScope struct {
	Migrated    []string           `json:"migrated"`
	NotMigrated []LiteLLMScopeItem `json:"not_migrated"`
}

// LiteLLMFinding is one classified source location. SourceValue is always
// scrubbed; for secret paths it is the redaction marker and the value is
// never carried anywhere in the report.
type LiteLLMFinding struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Disposition string `json:"disposition"`
	// SourceValue is a scalar source value after scrubbing, or a shape
	// summary ("<mapping: n keys>") for non-scalars. Secret values are never
	// placed here.
	SourceValue string `json:"source_value,omitempty"`
	// Target names the Yabanin-side entity/field the setting relates to.
	Target string `json:"target,omitempty"`
	// SourceSemantics/TargetSemantics are filled for decision findings so
	// the operator sees both sides of the difference.
	SourceSemantics string `json:"source_semantics,omitempty"`
	TargetSemantics string `json:"target_semantics,omitempty"`
	// Detail explains the disposition. It never contains secret values.
	Detail string `json:"detail"`
}

// LiteLLMSecret records a redacted secret location by path and field name
// only. Values are never included.
type LiteLLMSecret struct {
	Path  string `json:"path"`
	Field string `json:"field"`
}

// LiteLLMPlanLimits mirrors the upstream catalog limits vocabulary
// (pkg/upstream.CatalogLimits: max_tpm/max_rpm/max_output_tokens). The JSON
// tags are drift-tested against the catalog document in tests.
type LiteLLMPlanLimits struct {
	MaxTPM          int64 `json:"max_tpm,omitempty"`
	MaxRPM          int64 `json:"max_rpm,omitempty"`
	MaxOutputTokens int64 `json:"max_output_tokens,omitempty"`
}

// LiteLLMPlanEntry is one planned catalog row for the reviewed apply step
// (N16-P02-T04). The shape mirrors pkg/upstream.CatalogModelEntry so the
// apply step can assemble a catalog document without re-deriving semantics;
// the mapping is drift-tested in tests.
type LiteLLMPlanEntry struct {
	Action       string             `json:"action"`
	Provider     string             `json:"provider"`
	Model        string             `json:"model"`
	Aliases      []string           `json:"aliases,omitempty"`
	Capabilities map[string]bool    `json:"capabilities,omitempty"`
	Limits       *LiteLLMPlanLimits `json:"limits,omitempty"`
	SourcePaths  []string           `json:"source_paths"`
}

// LiteLLMMigrationReport is the dry-run report: what transfers with verified
// semantics, what differs, what conflicts, what is unsupported — and the
// explicit non-goals. It contains no secret values.
type LiteLLMMigrationReport struct {
	Schema       int                 `json:"schema"`
	Source       LiteLLMReportSource `json:"source"`
	Summary      LiteLLMSummary      `json:"summary"`
	Scope        LiteLLMScope        `json:"scope"`
	Transferable []LiteLLMFinding    `json:"transferable,omitempty"`
	Differences  []LiteLLMFinding    `json:"semantic_differences,omitempty"`
	Conflicts    []LiteLLMFinding    `json:"conflicts,omitempty"`
	Unsupported  []LiteLLMFinding    `json:"unsupported,omitempty"`
	Secrets      []LiteLLMSecret     `json:"secrets_redacted,omitempty"`
	Plan         []LiteLLMPlanEntry  `json:"plan,omitempty"`
}

// LiteLLMConfigFormat is the pinned description of the LiteLLM proxy-config
// format this dry-run consumes. Returned by LiteLLMConfigPin(); callers
// cannot mutate package state through it.
type LiteLLMConfigFormat struct {
	Format            string   `json:"format"`
	PinnedUpstream    string   `json:"pinned_upstream"`
	Notice            string   `json:"notice"`
	SupportedSections []string `json:"supported_sections"`
	// ProviderTargets lists the canonical Yabanin provider ids a migrated
	// model row may use. Drift-tested against pkg/provider.New in tests.
	ProviderTargets []string `json:"provider_targets"`
	Limitations     []string `json:"limitations"`
}

// litellmVertexPrefix marks the vertex_ai[_<region>] model prefix family,
// which collapses to the "vertex" target provider. Kept in sync with the
// pricing pin by test (the pricing constant is unexported).
const litellmVertexPrefix = "vertex-ai-"

// litellmProviderTargets maps a canonical LiteLLM provider id to the
// Yabanin provider id used in plan entries. Canonical ids missing from this
// map are refused explicitly — never force-mapped.
var litellmProviderTargets = map[string]string{
	"openai":      "openai",
	"anthropic":   "anthropic",
	"azure":       "azure-openai",
	"vertex":      "vertex",
	"bedrock":     "bedrock",
	"mistral":     "mistral",
	"ollama":      "ollama",
	"ollama-chat": "ollama",
	"vllm":        "vllm",
	"tgi":         "tgi",
	"llamacpp":    "llamacpp",
}

// litellmModeCapabilities maps LiteLLM model_info.mode values to the catalog
// capability vocabulary. Unknown modes are refused explicitly.
var litellmModeCapabilities = map[string]string{
	"chat":                "chat",
	"completion":          "chat",
	"embedding":           "embeddings",
	"audio_transcription": "speech_transcription",
	"audio_speech":        "speech_synthesis",
	"image_generation":    "image_generation",
}

// litellmFieldRule is one row of the field-by-field compatibility matrix
// (owner decision I65): what happens to a known source field.
type litellmFieldRule struct {
	Disposition string // LiteLLMTransfer / LiteLLMDecision / LiteLLMConflict / LiteLLMRefused
	Kind        string
	Target      string
	Detail      string
	// Secret marks fields whose value is credential material: refused and
	// redacted regardless of disposition.
	Secret bool
	// SourceSemantics / TargetSemantics describe a decision finding.
	SourceSemantics string
	TargetSemantics string
}

// litellmParamFieldRules is the matrix for model_list[].litellm_params.
// model/tpm/rpm/custom_llm_provider are handled bespoke (they produce plan
// content); every other field lands here.
var litellmParamFieldRules = map[string]litellmFieldRule{
	"api_base": {Disposition: LiteLLMDecision, Kind: LiteLLMKindSetting,
		Target:          "deployment endpoint configuration (not a catalog field)",
		SourceSemantics: "per-deployment upstream endpoint override",
		TargetSemantics: "provider endpoints are deployment-level configuration in Yabanin; the catalog has no endpoint column",
		Detail:          "the model row itself transfers; the endpoint must be configured at deployment level when applying",
	},
	"api_key": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSecret, Secret: true,
		Detail: "credentials are never imported, previewed, logged, or reported (PRODUCT-CONTRACT.md §14)"},
	"max_tokens": {Disposition: LiteLLMDecision, Kind: LiteLLMKindLimit,
		Target:          "none (not a catalog limit)",
		SourceSemantics: "default max_tokens injected into each request through this deployment",
		TargetSemantics: "catalog limits.max_output_tokens documents the model bound; it is not a per-request default",
		Detail:          "different semantics: an injected request default would silently cap every migrated request; operator must decide",
	},
	"timeout": {Disposition: LiteLLMDecision, Kind: LiteLLMKindSetting,
		Target:          "gateway request_timeout (deployment configuration)",
		SourceSemantics: "per-deployment request timeout",
		TargetSemantics: "Yabanin applies one gateway-level request_timeout; per-model timeouts are not configured by import",
		Detail:          "configure the gateway timeout explicitly if the per-deployment value was load-bearing",
	},
	"num_retries": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "per-deployment retry policy is a LiteLLM router feature; retry/circuit behavior is owned by the Yabanin gateway"},
	"weight": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "deployment weighting for LiteLLM load balancing has no axis in a single-row catalog mapping"},
	"allowed_fails": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "router cooldown heuristic input; Yabanin circuit breakers are gateway-configured"},
	"cooldown_time": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "router cooldown window; Yabanin circuit breakers are gateway-configured"},
	"drop_params": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM silently drops unsupported provider params; the Yabanin translation layer owns parameter handling and this posture must not be imported"},
	"merge_reasoning_content_in_choices": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM response-shaping toggle; not part of the Yabanin vocabulary"},
	"stream": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSetting,
		Detail: "streaming is negotiated per request by the gateway, not pinned per deployment"},
	"stream_timeout": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSetting,
		Detail: "stream idle handling is gateway-level (stream_idle_timeout), not per deployment"},
}

// litellmModelInfoRules is the matrix for model_list[].model_info.
var litellmModelInfoRules = map[string]litellmFieldRule{
	"id": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSetting,
		Detail: "LiteLLM-internal deployment identity; the catalog rows are keyed by (provider, model), not by source deployment ids"},
	"mode": {Disposition: LiteLLMTransfer, Kind: LiteLLMKindCapability,
		Target: "catalog capabilities.<key>",
		Detail: "mode maps onto the pinned catalog capability vocabulary; unknown modes are refused explicitly"},
	"max_output_tokens": {Disposition: LiteLLMTransfer, Kind: LiteLLMKindLimit,
		Target: "catalog limits.max_output_tokens",
		Detail: "both sides document the per-completion output cap; the bound transfers verbatim as a positive integer"},
	"max_input_tokens": {Disposition: LiteLLMDecision, Kind: LiteLLMKindLimit,
		Target:          "catalog limits.context_window_tokens (operator decides the value)",
		SourceSemantics: "maximum input (prompt) tokens",
		TargetSemantics: "context_window_tokens documents the full context window (input + output); the bounds are not the same number",
		Detail:          "transferring an input cap as a full-window bound (or vice versa) would misstate the model; operator must supply the correct window",
	},
}

// litellmRouterRules is the matrix for router_settings.
// model_group_alias and fallbacks are handled bespoke (they need the model
// groups collected from model_list).
var litellmRouterRules = map[string]litellmFieldRule{
	"routing_strategy": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM routing strategies (least-busy, usage-based, latency- or cost-based) have no 1:1; Yabanin routing is expressed via labels, tier pools, session affinity and classifier policies configured separately"},
	"num_retries": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "router retry policy; Yabanin retry/circuit behavior is gateway-owned"},
	"timeout": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSetting,
		Detail: "router-level request timeout; Yabanin timeouts are gateway-level deployment configuration"},
	"allowed_fails": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "router cooldown heuristic; no Yabanin equivalent is configured by import"},
	"cooldown_time": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "router cooldown window; no Yabanin equivalent is configured by import"},
	"retry_policy": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "per-exception retry policy matrix; not representable in the Yabanin gateway configuration"},
	"allowed_fails_policy": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "per-model/per-exception cooldown policy; not representable in the Yabanin gateway configuration"},
	"redis_host": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM router-state Redis; Yabanin Redis configuration is deployment-level and independent"},
	"redis_port": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM router-state Redis; Yabanin Redis configuration is deployment-level and independent"},
	"redis_password": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSecret, Secret: true,
		Detail: "credentials are never imported, previewed, logged, or reported"},
	"context_window_fallbacks": {Disposition: LiteLLMRefused, Kind: LiteLLMKindRoute,
		Detail: "context-window-exceeded fallback routing is a LiteLLM router behavior; no Yabanin equivalent is configured by import"},
	"content_policy_fallbacks": {Disposition: LiteLLMRefused, Kind: LiteLLMKindRoute,
		Detail: "content-policy fallback routing is a LiteLLM router behavior; no Yabanin equivalent is configured by import"},
}

// litellmSettingsRules is the matrix for litellm_settings.
var litellmSettingsRules = map[string]litellmFieldRule{
	"drop_params": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "silently dropping unsupported provider params must not be imported as a posture; the Yabanin translation layer owns parameter handling"},
	"set_verbose": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSetting,
		Detail: "LiteLLM debug verbosity; Yabanin log levels are deployment configuration"},
	"telemetry": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "upstream telemetry opt-out is a LiteLLM feature; no telemetry posture is changed by import"},
	"success_callback": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "telemetry/export integrations (Langfuse, Slack, webhooks, ...) are unsupported; import never configures third-party exporters"},
	"failure_callback": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "telemetry/export integrations are unsupported; import never configures third-party exporters"},
	"callbacks": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "custom callback handlers are unsupported; import never configures exporters or handlers"},
	"service_callbacks": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "service-level callbacks are unsupported; import never configures exporters or handlers"},
	"cache": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM response caching is not mapped; the Yabanin semantic cache is configured separately at deployment level"},
	"cache_params": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM cache backend parameters are not mapped; credentials inside are never read"},
	"guards": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM guardrails are unsupported; Yabanin guard hooks are configured via the gateway guard_mode"},
	"guardrails": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM guardrails are unsupported; Yabanin guard hooks are configured via the gateway guard_mode"},
	"request_timeout": {Disposition: LiteLLMDecision, Kind: LiteLLMKindSetting,
		Target:          "gateway request_timeout (deployment configuration)",
		SourceSemantics: "proxy-wide upstream request timeout in seconds",
		TargetSemantics: "gateway-level request_timeout duration string applied to all upstream calls",
		Detail:          "the value transfers as a deployment decision, not as part of this import"},
	"num_retries": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "proxy-wide retry policy; Yabanin retry/circuit behavior is gateway-owned"},
	"max_budget": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "global USD spend control is not migrated; Yabanin budgets are per task/session token budgets and credits, configured separately"},
	"budget_duration": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "budget reset window belongs to the LiteLLM spend controls that are not migrated"},
	"max_user_budget": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "per-user budgets depend on LiteLLM users, which are out of scope by design"},
	"default_team_settings": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "team/team-member settings depend on LiteLLM teams and virtual keys, which are out of scope by design"},
	"turn_off_message_logging": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM message-logging toggle refers to LiteLLM logging features that are not migrated"},
	"redact_user_api_key_info": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM log-redaction toggle refers to LiteLLM logging features that are not migrated; Yabanin redaction is enforced at its own boundaries"},
}

// litellmGeneralRules is the matrix for general_settings.
var litellmGeneralRules = map[string]litellmFieldRule{
	"master_key": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSecret, Secret: true,
		Detail: "the LiteLLM master key is never imported or displayed; gateway admin auth is configured at deployment level"},
	"database_url": {Disposition: LiteLLMRefused, Kind: LiteLLMKindSecret, Secret: true,
		Detail: "connection strings are credentials; the referenced database holds LiteLLM users, keys and spend data, all of which are out of scope by design"},
	"database_type": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM database backend selection; the LiteLLM user/key/spend store is out of scope by design"},
	"database_connection_pool_params": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM database tuning; the LiteLLM store is out of scope by design"},
	"use_database_proxy": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM database proxy mode; the LiteLLM store is out of scope by design"},
	"allowed_ips": {Disposition: LiteLLMDecision, Kind: LiteLLMKindSetting,
		Target:          "deployment network policy",
		SourceSemantics: "IP allow-list in front of the LiteLLM proxy",
		TargetSemantics: "Yabanin network policy is deployment-level (ingress/proxy configuration), not part of this import",
		Detail:          "re-create the allow-list in the deployment network policy if it was load-bearing"},
	"ui_access_mode": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM UI access control; Yabanin console access is configured at deployment level"},
	"enforce_user_param": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM user attribution enforcement; user identity handling is not migrated"},
	"create_missing_admin_in_db": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM admin bootstrap behavior; Yabanin admin identities are provisioned separately"},
	"store_model_in_db": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM DB-backed model management; model state transfers only through this report's plan"},
	"alerting": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "alerting integrations (Slack, webhooks) are unsupported; import never configures exporters"},
	"alert_types": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "alerting integration types are unsupported; import never configures exporters"},
	"alerting_threshold": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "alerting thresholds belong to unsupported alerting integrations"},
	"proxy_batch_write_at": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM spend-store batching; spend data is out of scope by design"},
	"disable_spend_updates": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM spend tracking toggle; spend data is out of scope by design"},
	"disable_reset_budget": {Disposition: LiteLLMRefused, Kind: LiteLLMKindCapability,
		Detail: "LiteLLM budget reset toggle; spend controls are out of scope by design"},
}

// litellmSupportedSections lists the top-level config sections this dry-run
// consumes. Any other top-level key is reported as unsupported.
var litellmSupportedSections = []string{
	"model_list", "router_settings", "litellm_settings", "general_settings", "environment_variables",
}

// litellmScopeMigrated / litellmScopeNotMigrated are the explicit import
// promises (§14 / I65): the report always carries this statement.
var litellmScopeMigrated = []string{
	"model rows (provider, model, capabilities, per-model output-token bound)",
	"client-facing model group names and model_group_alias entries as catalog aliases",
	"per-model tpm/rpm limits into catalog limits.max_tpm/max_rpm",
}

var litellmScopeNotMigrated = []LiteLLMScopeItem{
	{Item: "user accounts, teams and proxy virtual keys",
		Reason: "LiteLLM users/keys live in the LiteLLM database; Yabanin identities are provisioned separately — the import never promises user migration"},
	{Item: "request logs and usage logs",
		Reason: "historical logs stay in the LiteLLM database; no log migration exists"},
	{Item: "spend tracking and financial history",
		Reason: "no balance/spend-ledger migration; Yabanin metering starts fresh at cutover"},
	{Item: "provider credentials (api keys, connection strings)",
		Reason: "credentials are re-entered as deployment secrets; they are never imported, previewed, logged, or reported"},
	{Item: "cached responses (LiteLLM response cache)",
		Reason: "cache backends are deployment-level features and their contents are not transferred"},
	{Item: "telemetry/callback integrations",
		Reason: "third-party exporters are never configured by import"},
}

// LiteLLMConfigPin returns the pinned proxy-config contract. The returned
// struct is a fresh copy; callers cannot mutate package state through it.
func LiteLLMConfigPin() LiteLLMConfigFormat {
	sections := append([]string(nil), litellmSupportedSections...)
	targets := make([]string, 0, len(litellmProviderTargets))
	for k := range litellmProviderTargets {
		targets = append(targets, k)
	}
	sort.Strings(targets)
	return LiteLLMConfigFormat{
		Format: "litellm_proxy_config",
		PinnedUpstream: "github.com/BerriAI/litellm proxy config @ " +
			"61a73c59b049a8cd6c559168d7f3a2557a1a8cf7 (historical format reference; pricing data is not bundled)",
		Notice:            "LiteLLM is BerriAI/litellm MIT content; attribution preserved in pkg/pricing/NOTICE-litellm.txt",
		SupportedSections: sections,
		ProviderTargets:   targets,
		Limitations: []string{
			"the config parser consumes the YAML (and JSON-as-YAML) proxy config layout verified against the pinned upstream commit; the exact supported LiteLLM release range stays an open owner decision (I65)",
			"configs are untrusted input: parse failures, non-object roots, trailing documents and duplicate mapping keys are hard findings, never silently repaired",
			"every source field receives an explicit disposition; a field outside the compatibility matrix is reported unsupported — unsupported limits/routes never pass silently",
			"master_key, database_url, api_key and every environment_variables value are refused secrets; report values are scrubbed and secret paths carry no values",
			"tpm/rpm transfer into catalog limits with a stated semantic difference: LiteLLM enforces them as router rate limits, Yabanin stores them as documented catalog bounds",
			"tpm/rpm of 0 are conflicts, not transfers: LiteLLM reads 0 as block-all while a catalog zero means unset (unlimited) — importing it would silently lift the limit",
			"wildcard routes (model \"/.../*\") are refused: the catalog admits explicit (provider, model) rows only",
			"no user accounts, request logs, or financial history are carried by design (PRODUCT-CONTRACT.md §14)",
			"apply/idempotency/rollback is the reviewed apply step (N16-P02-T04); this dry-run never mutates configuration",
			"Bifrost migration is a separate packet (N16-P03)",
		},
	}
}

// litellmCanonicalProvider folds a raw LiteLLM provider string to the
// canonical id used across the migration mapping. It mirrors the pricing
// importer's normalization (lowercase, '_'→'-', pinned alias table,
// vertex_ai region family collapse) and reuses the pricing alias table so
// the two cannot drift apart.
func litellmCanonicalProvider(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	p = strings.ReplaceAll(p, "_", "-")
	if mapped, ok := pricing.LiteLLMFormatPin().ProviderAliases[p]; ok {
		return mapped
	}
	if p == strings.TrimSuffix(litellmVertexPrefix, "-") || strings.HasPrefix(p, litellmVertexPrefix) {
		return "vertex"
	}
	return p
}

// Secret-shaped field names. Anything matching this pattern is treated as
// credential material regardless of section. Bare "token"/"key" are
// deliberately absent so ordinary names (max_tokens, model key) never trip
// it; the environment_variables section is fully redacted by rule instead.
var litellmSecretKeyName = regexp.MustCompile(
	`(?i)(?:^|[^a-z0-9])(api[-_]?key|master[-_]?key|secret|password|passwd|credentials?|private[-_]?key|database[-_]?url|connection[-_]?string|aws_access_key_id|aws_secret_access_key|aws_session_token)(?:[^a-z0-9]|$)`)

var (
	litellmURLUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://)([^@/\s]+)@`)
	litellmBearerValue = regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{8,}`)
)

// redactLiteLLMValue is the defense-in-depth scrub applied to every source
// value that reaches a report: URL userinfo, LiteLLM-style bearer tokens
// (sk-…), and the shared credential-shaped assignment scrubber. The result
// is deterministic.
func redactLiteLLMValue(s string) string {
	s = litellmURLUserinfo.ReplaceAllString(s, "$1"+LiteLLMRedacted+"@")
	s = litellmBearerValue.ReplaceAllString(s, LiteLLMRedacted)
	return redact.ScrubSecrets(s)
}
