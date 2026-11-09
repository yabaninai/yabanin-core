// Package contracts defines the agent-eval journal data contract from plan
// section Г: Go types with strict decode semantics, the episode state
// machine, JSON Schema files, and a run-directory validator.
//
// Nullable fields (marked N in the plan) are pointers: absence has
// semantics and is never equivalent to a zero value. Errors expose
// identifiers, digests, and line numbers only, never raw tool arguments.
package contracts

import (
	"fmt"
	"regexp"
)

// SchemaVersion is the only journal schema version this package understands.
const SchemaVersion = 1

// TaskTagPattern constrains agent task tags: short, URL-safe, no whitespace.
// Unicode case_ids are allowed in the journal, but task tags fed to routing
// and analytics must match this pattern.
const TaskTagPattern = `^[A-Za-z0-9._:-]{1,128}$`

var taskTagRe = regexp.MustCompile(TaskTagPattern)

// ValidateTaskTag reports whether tag is an acceptable agent task tag.
func ValidateTaskTag(tag string) error {
	if !taskTagRe.MatchString(tag) {
		return fmt.Errorf("task tag %q must match %s", tag, TaskTagPattern)
	}
	return nil
}

// uuidRe is the canonical 8-4-4-4-12 hex UUID shape.
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// EpisodeStatus is the execution lifecycle state of one episode.
type EpisodeStatus string

// Episode lifecycle states (plan §Г.7).
const (
	StatusNotRun          EpisodeStatus = "not_run"
	StatusRunning         EpisodeStatus = "running"
	StatusCompleted       EpisodeStatus = "completed"
	StatusFailed          EpisodeStatus = "failed"
	StatusBlocked         EpisodeStatus = "blocked"
	StatusCanceled        EpisodeStatus = "canceled"
	StatusBudgetExhausted EpisodeStatus = "budget_exhausted"
	StatusPartial         EpisodeStatus = "partial"
	StatusInvalid         EpisodeStatus = "invalid"
	StatusNeedsApproval   EpisodeStatus = "needs_approval"
)

var episodeTransitions = map[EpisodeStatus][]EpisodeStatus{
	StatusNotRun: {StatusRunning},
	StatusRunning: {
		StatusCompleted, StatusFailed, StatusBlocked, StatusCanceled,
		StatusBudgetExhausted, StatusPartial, StatusInvalid, StatusNeedsApproval,
	},
	StatusNeedsApproval: {StatusRunning, StatusCanceled},
}

// CanTransitionTo reports whether the s → t transition is allowed by §Г.7.
// Terminal states allow nothing; unknown states allow nothing.
func (s EpisodeStatus) CanTransitionTo(t EpisodeStatus) bool {
	for _, allowed := range episodeTransitions[s] {
		if allowed == t {
			return true
		}
	}
	return false
}

// Valid reports whether s is a known episode status.
func (s EpisodeStatus) Valid() bool {
	switch s {
	case StatusNotRun, StatusRunning, StatusCompleted, StatusFailed,
		StatusBlocked, StatusCanceled, StatusBudgetExhausted,
		StatusPartial, StatusInvalid, StatusNeedsApproval:
		return true
	}
	return false
}

// Manifest is the experiment manifest (manifest.json, §Г.1).
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	CreatedAt     string            `json:"created_at"`
	Profile       string            `json:"profile"`
	GitCommit     string            `json:"git_commit"`
	DirtyFiles    []string          `json:"dirty_files,omitempty"`
	Dataset       DatasetRef        `json:"dataset"`
	Arms          []Arm             `json:"arms"`
	Caps          Caps              `json:"caps"`
	PriceSnapshot PriceSnapshot     `json:"price_snapshot"`
	Spend         Spend             `json:"spend"`
	Replay        *ReplayRef        `json:"replay,omitempty"`
	Integrity     map[string]string `json:"integrity"`
}

// DatasetRef identifies the evaluation dataset and its integrity hashes.
type DatasetRef struct {
	CatalogID     string   `json:"catalog_id"`
	SelectionFile string   `json:"selection_file"`
	SHA256        []string `json:"sha256"`
	Split         string   `json:"split"`
}

// Arm is one evaluated configuration (model + endpoint pinning).
type Arm struct {
	ID              string   `json:"id"`
	ModelSlug       string   `json:"model_slug"`
	EndpointURL     string   `json:"endpoint_url"`
	ProviderPinning string   `json:"provider_pinning"`
	HeadersAllowed  []string `json:"headers_allowed"`
}

// Caps bounds every episode's resource consumption.
type Caps struct {
	MaxLLMAttempts   int64    `json:"max_llm_attempts"`
	MaxToolCalls     int64    `json:"max_tool_calls"`
	MaxWallSeconds   int64    `json:"max_wall_seconds"`
	EpisodeCapUSD    *float64 `json:"episode_cap_usd"`
	MaxChildAgents   int      `json:"max_child_agents"`
	MaxConcurrentLLM int      `json:"max_concurrent_llm"`
}

// PriceSnapshot freezes model pricing at verification time.
type PriceSnapshot struct {
	Source   string       `json:"source"`
	AsOf     string       `json:"as_of"`
	Currency string       `json:"currency"`
	Entries  []PriceEntry `json:"entries"`
}

// PriceEntry is one model's per-million-token price sheet entry.
type PriceEntry struct {
	Model      string   `json:"model"`
	InPer1M    *float64 `json:"in_per_1m"`
	OutPer1M   *float64 `json:"out_per_1m"`
	CacheWrite *float64 `json:"cache_write"`
	CacheRead  *float64 `json:"cache_read"`
}

// Spend records the owner's paid-run authorization.
type Spend struct {
	Authorized bool    `json:"authorized"`
	LimitUSD   float64 `json:"limit_usd"`
	ApprovedBy string  `json:"approved_by"`
	ApprovedAt *string `json:"approved_at"`
}

// ReplayRef links a mock run to its scripted responses.
type ReplayRef struct {
	Scripts []string `json:"scripts"`
}

// EpisodeRecord is one journal line of episodes.jsonl (§Г.2).
type EpisodeRecord struct {
	EpisodeID       string        `json:"episode_id"`
	RootID          string        `json:"root_id"`
	CaseID          string        `json:"case_id"`
	Arm             string        `json:"arm"`
	Repetition      int           `json:"repetition"`
	ExecutionStatus EpisodeStatus `json:"execution_status"`
	StopReason      *string       `json:"stop_reason"`
	TaskOutcome     *string       `json:"task_outcome"`
	SafetyOutcome   string        `json:"safety_outcome"`
	ProtocolOutcome string        `json:"protocol_outcome"`
	Usage           Usage         `json:"usage"`
	Cost            CostSummary   `json:"cost"`
	VerdictRef      *string       `json:"verdict_ref"`
	Artifacts       []string      `json:"artifacts,omitempty"`
}

// Usage aggregates per-episode consumption. Nullable counters keep the
// difference between "zero" and "not observed".
type Usage struct {
	LLMCalls        int64  `json:"llm_calls"`
	ToolCalls       int64  `json:"tool_calls"`
	TokensIn        *int64 `json:"tokens_in"`
	TokensOut       *int64 `json:"tokens_out"`
	ReasoningTokens *int64 `json:"reasoning_tokens"`
	CacheRead       *int64 `json:"cache_read"`
}

// CostSummary aggregates episode cost. Nil means unknown — never zero.
type CostSummary struct {
	EstimatedUSD *float64 `json:"estimated_usd"`
	ObservedUSD  *float64 `json:"observed_usd"`
	UncertainUSD *float64 `json:"uncertain_usd"`
	Coverage     float64  `json:"coverage"`
}

// CallRecord is one journal line of calls.jsonl (§Г.3).
type CallRecord struct {
	CallID         string      `json:"call_id"`
	EpisodeID      string      `json:"episode_id"`
	RootID         string      `json:"root_id"`
	AttemptIndex   int         `json:"attempt_index"`
	Arm            string      `json:"arm"`
	ModelRequested string      `json:"model_requested"`
	ModelActual    *string     `json:"model_actual"`
	Endpoint       string      `json:"endpoint"`
	GenerationID   *string     `json:"generation_id"`
	FinishReason   *string     `json:"finish_reason"`
	Status         string      `json:"status"`
	Usage          CallUsage   `json:"usage"`
	Cost           CallCost    `json:"cost"`
	Latency        CallLatency `json:"latency"`
	DecisionHeader *string     `json:"decision_header"`
	Error          *CallError  `json:"error"`
}

// CallUsage carries nullable token counters for one LLM call.
type CallUsage struct {
	TokensIn        *int64 `json:"tokens_in"`
	TokensOut       *int64 `json:"tokens_out"`
	ReasoningTokens *int64 `json:"reasoning_tokens"`
}

// CallCost carries the estimated and observed cost of one call. A nil
// ObservedUSD on a successful call is uncertainty, not zero.
type CallCost struct {
	EstimatedUSD *float64 `json:"estimated_usd"`
	ObservedUSD  *float64 `json:"observed_usd"`
	Uncertain    bool     `json:"uncertain"`
}

// CallLatency records first-token and total latency; nullable TTFT means the
// stream produced no tokens.
type CallLatency struct {
	TTFTMS  *int64 `json:"ttft_ms"`
	TotalMS int64  `json:"total_ms"`
}

// CallError describes an errored or timed-out call.
type CallError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ToolEvent is one journal line of tools.jsonl (§Г.4). Raw tool arguments are
// never journaled — only their SHA-256 digest.
type ToolEvent struct {
	EventID       string      `json:"event_id"`
	EpisodeID     string      `json:"episode_id"`
	CallRef       string      `json:"call_ref"`
	Tool          string      `json:"tool"`
	Phase         string      `json:"phase"`
	ArgsDigest    string      `json:"args_digest"`
	Receipt       *ReceiptRef `json:"receipt"`
	SideEffect    string      `json:"side_effect"`
	FaultInjected *bool       `json:"fault_injected"`
	Actor         string      `json:"actor"`
	DenyReason    *string     `json:"deny_reason"`
}

// ReceiptRef links a tool event to its idempotency receipt.
type ReceiptRef struct {
	ID             string  `json:"id"`
	IdempotencyKey *string `json:"idempotency_key"`
}

// ApprovalRecord journals one controller approval decision (§Г.5).
type ApprovalRecord struct {
	ApprovalID   string        `json:"approval_id"`
	Controller   string        `json:"controller"`
	Binds        ApprovalBinds `json:"binds"`
	Decision     string        `json:"decision"`
	DecidedAt    string        `json:"decided_at"`
	DeliveredVia string        `json:"delivered_via"`
}

// ApprovalBinds pins an approval to one entity version and parameter digest.
type ApprovalBinds struct {
	Org           string `json:"org"`
	Entity        string `json:"entity"`
	EntityVersion string `json:"entity_version"`
	ParamsDigest  string `json:"params_digest"`
}

// Receipt is the idempotency receipt of a mutating tool call (§Г.5).
type Receipt struct {
	ReceiptID string `json:"receipt_id"`
	Tool      string `json:"tool"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
	Outcome   string `json:"outcome"`
}

// VerdictRecord is the verifier's verdict for one episode.
type VerdictRecord struct {
	VerdictID   string  `json:"verdict_id"`
	EpisodeID   string  `json:"episode_id"`
	TaskOutcome string  `json:"task_outcome"`
	Notes       *string `json:"notes"`
}

// DemoArtifact is the public per-task artifact (§Г.8). Before a paid run,
// Observed is nil: cost and latency are unknown, not zero.
type DemoArtifact struct {
	TaskID          string        `json:"task_id"`
	Title           string        `json:"title"`
	Summary         string        `json:"summary"`
	Synthetic       bool          `json:"synthetic"`
	ExecutionStatus string        `json:"execution_status"`
	Observed        *ObservedDemo `json:"observed"`
}

// ObservedDemo carries the measured results of a publicly shown run.
type ObservedDemo struct {
	RunID           string   `json:"run_id"`
	Date            string   `json:"date"`
	Arm             string   `json:"arm"`
	VerifierOutcome string   `json:"verifier_outcome"`
	CostUSD         *float64 `json:"cost_usd"`
	LatencyP50MS    int64    `json:"latency_p50_ms"`
	Models          []string `json:"models"`
	TraceRef        string   `json:"trace_ref"`
}

// CostRecord is a standalone cost entry (§Г.6). Invariant: nil AmountUSD
// means the price was unknown — Uncertain must be true in that case.
type CostRecord struct {
	Source      string   `json:"source"`
	AmountUSD   *float64 `json:"amount_usd"`
	Scope       string   `json:"scope"`
	Uncertain   bool     `json:"uncertain"`
	MatchedRefs []string `json:"matched_refs"`
}
