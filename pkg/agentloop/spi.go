// Package agentloop defines the versioned public extension seam (SPI v1) for
// bounded model→tool→model agent loops.
//
// OWNERSHIP BOUNDARY (owner decision, PRODUCT-CONTRACT.md §2, I53): a supplied
// loop engine — the component that actually drives ExecutorSPI step by step —
// is an Enterprise, experimental module. THIS package stays free Apache core:
// the contract types, the shared OperationState transition machine and the
// interfaces BYO implementations need. Core does not ship a loop engine: no
// file in this package drives steps, retries or resume; it only fixes the
// semantics every engine must share.
//
// Every interface below states, in its doc comment, the invariant it enforces.
// The recurring invariants and their sources:
//
//   - Fail-closed: a mandatory check that cannot complete denies the step.
//   - Unknown-outcome-uncertain: an upstream or external effect whose outcome
//     is not confirmed stays uncertain — it is never reported as success, as
//     zero cost, or as a proven rollback, and it is never blindly repeated
//     (I45, I55).
//   - No-self-approval: agents and CI never approve their own calls; a human
//     different from the initiator is mandatory whenever policy requires one
//     (I57).
//   - Recheck-after-approval: approval never carries permissions forward;
//     rights, credentials and policy are revalidated before an approved step
//     resumes (I56–I58).
//   - Explicit writes only: external mutations require an explicit policy
//     allow for the concrete tool and action; credential access alone grants
//     nothing (I55).
//
// VERSIONING (docs/api/AGENT-LOOP-SPI.md): v1 is additive-only. New optional
// surface arrives as new interfaces or appended enum values; a breaking
// change ships as a parallel v2, never as a mutation of v1.
package agentloop

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/provider"
)

// SPIVersion identifies the contract version implemented by this package.
// Engines should record it in configuration and diagnostics so operators can
// verify which seam semantics a deployment runs.
const SPIVersion = "v1"

// DefaultApprovalTTL is the default waiting period for a human approval when
// the applicable policy does not configure one (I59). Policy overrides it;
// the default exists so an unconfigured deployment still terminates.
const DefaultApprovalTTL = 15 * time.Minute

// Sentinel errors shared across the seam. Implementations wrap them with
// %w so callers can classify failures with errors.Is without importing
// implementation packages.
var (
	// ErrIllegalTransition reports an OperationState change the shared
	// transition table does not allow (state.go). Engines must treat it as a
	// programming or persistence defect, not as a runtime outcome.
	ErrIllegalTransition = errors.New("agentloop: illegal operation state transition")

	// ErrUnknownTool reports that the requested tool is not registered.
	// Fail-closed: an unresolvable tool is never executable, and the loop
	// must surface the precise reason to the caller rather than skip the
	// step silently (I51).
	ErrUnknownTool = errors.New("agentloop: tool not registered")

	// ErrDuplicateSettlement reports a UsageEntry for the settlement key
	// tuple (OperationID, StepIndex, TurnID) that was already settled.
	// Exactly-once contract: implementations may either no-op idempotently
	// with a nil error or reject with an error wrapping this sentinel —
	// they must never add the amount twice.
	ErrDuplicateSettlement = errors.New("agentloop: usage already settled for operation step")

	// ErrApprovalExpired reports that the approval being decided or resumed
	// passed its TTL. An expired approval never triggers execution; a new
	// operation is required (I59).
	ErrApprovalExpired = errors.New("agentloop: approval expired")

	// ErrBudgetExceeded reports that a configured step/total/concurrency or
	// wall-time limit blocks the requested step.
	ErrBudgetExceeded = errors.New("agentloop: budget limit exceeded")

	// ErrBudgetUnavailable reports that the budget guard could not evaluate
	// its decision (store outage, timeout). Fail-closed: the step is denied,
	// never allowed on an unverifiable guard.
	ErrBudgetUnavailable = errors.New("agentloop: budget guard unavailable")
)

// OperationID is the durable identifier of one loop operation. It survives
// restarts, HA failover and client disconnects: UI and API address status,
// result and approvals by it, independent of any connection (I58). Possessing
// an OperationID is not authorization — access control applies to the status,
// result and approval surfaces separately.
type OperationID string

// SubjectKind mirrors the authenticated principal kind that owns an
// operation. The seam keeps its own minimal enum because the contract must
// not depend on the HTTP auth layer; implementations populate it from the
// trusted authenticated principal, never from client-controlled input.
type SubjectKind string

const (
	// SubjectHuman is an authenticated human principal.
	SubjectHuman SubjectKind = "human"
	// SubjectAgent is an autonomous agent principal. Agents never approve
	// their own calls; policy assigns a human approver (I57).
	SubjectAgent SubjectKind = "agent"
	// SubjectService is an org/project service principal. Service
	// credentials never substitute for a denied user delegation (I54).
	SubjectService SubjectKind = "service"
	// SubjectCI is a CI principal. Like agents, CI cannot self-approve.
	SubjectCI SubjectKind = "ci"
)

// Operation is the durable snapshot of one loop operation passed through the
// seam. The engine owns its lifecycle; seam implementations must treat it as
// read-only and must not mutate it in place. Model is the trusted resolved
// model identity (routing alias resolved) — policy input, never a credential
// (I51).
type Operation struct {
	ID        OperationID
	OrgID     string
	ProjectID string
	// Subject is the authenticated principal that owns the operation;
	// SubjectKind says whether it is a human, agent, service or CI identity.
	Subject     string
	SubjectKind SubjectKind

	// State is the current shared-machine state; only state.go transitions
	// are legal.
	State OperationState

	// Model is the resolved model identity this operation runs on. Tool
	// policy may allow tool calls from one model and deny another (I51).
	Model string

	// ApprovalTTL is the policy-configured approval waiting period; zero
	// means DefaultApprovalTTL applies (I59).
	ApprovalTTL time.Duration

	// StepsExecuted counts admitted, executed steps (model turns and tool
	// calls) for the bounded-loop limit.
	StepsExecuted int

	// SpendSoFar is the settled spend of the operation so far. Uncertain
	// attempts keep their reserved/settled amounts — a missing response is
	// not zero cost (I45).
	SpendSoFar money.MicroUSD

	// CreatedAt and UpdatedAt are engine-maintained wall-clock stamps
	// (persisted, so expiry and limits survive restarts).
	CreatedAt time.Time
	UpdatedAt time.Time
}

// StepKind enumerates the step units an ExecutorSPI may be asked to run.
type StepKind string

const (
	// StepModelTurn is one bounded model turn (ChatStream).
	StepModelTurn StepKind = "model_turn"
	// StepToolCall is one registered-tool invocation after the guard path.
	StepToolCall StepKind = "tool_call"
)

// StepEventKind enumerates the observable loop events. Kinds are append-only
// in v1.x; consumers must treat an unknown kind as diagnostic data, not as an
// error.
type StepEventKind string

const (
	// EventModelTurn marks a model turn attempt (start or completion detail
	// rides Detail).
	EventModelTurn StepEventKind = "model_turn"
	// EventToolCall marks a tool invocation admitted by the guard path.
	EventToolCall StepEventKind = "tool_call"
	// EventToolResult marks a tool result (post-guard payload reference).
	EventToolResult StepEventKind = "tool_result"
	// EventApprovalRequest marks a durable approval request opened.
	EventApprovalRequest StepEventKind = "approval_request"
	// EventApprovalDecision marks a human approval decision (approved,
	// rejected or expired-resolution).
	EventApprovalDecision StepEventKind = "approval_decision"
	// EventSettlement marks one exactly-once usage settlement.
	EventSettlement StepEventKind = "settlement"
	// EventBoundaryExceeded marks that a configured limit (steps, active
	// time, spend, concurrency) stopped the loop. Reaching a boundary is a
	// normal, reported outcome — the event exists so exhaustion is visible
	// and never silently treated as successful completion (I52).
	EventBoundaryExceeded StepEventKind = "boundary_exceeded"
)

// StepEvent is one journal line of loop activity. Detail is value-free
// diagnostic data: it names rules, ids and spans, never matched secrets or
// prompt material (the same discipline as toolpolicy findings). Events are
// append-only observations; they do not drive the state machine.
type StepEvent struct {
	OperationID OperationID
	StepIndex   int
	Kind        StepEventKind
	// TurnID is the attempt identity of the step attempt this event belongs
	// to (I45 planning implications: track request and attempt identity).
	TurnID string
	At     time.Time
	Detail json.RawMessage
}

// CredentialMode selects the external credential class for a tool call (I54).
// The choice is made by connection configuration and policy — never by
// fallback.
type CredentialMode string

const (
	// CredentialService references organization/project service credentials.
	CredentialService CredentialMode = "service"
	// CredentialDelegatedUser references a user-delegated credential the
	// user authorized explicitly. A denied or unavailable delegated
	// credential must NOT silently escalate to CredentialService (I54).
	CredentialDelegatedUser CredentialMode = "user"
)

// CredentialRef names a credential without carrying its secret. Gateway
// authentication secrets are never forwarded as external MCP credentials
// (I54).
type CredentialRef struct {
	Mode CredentialMode
	Ref  string
}

// ToolCallRequest is one concrete tool invocation offered to the guard path.
// Args are the model-proposed arguments; the guard path — not the model —
// decides whether they may execute.
type ToolCallRequest struct {
	// Server is the registry server name ("yabanin" for built-ins, the MCP
	// server name otherwise); Tool is the tool name within it.
	Server string
	Tool   string
	Args   json.RawMessage
	// Credential selects service or delegated-user credentials per
	// connection configuration and policy (I54).
	Credential CredentialRef
}

// ToolSpec describes a registered tool. Mutating marks tools that change
// external state: they execute only under an explicit policy allow for the
// concrete tool and action (I55) and are the natural approval candidates.
type ToolSpec struct {
	Server      string
	Name        string
	Description string
	Mutating    bool
	// ArgsSchema is the JSON Schema the args must satisfy, when declared.
	ArgsSchema json.RawMessage
}

// ToolDecisionOutcome is the policy outcome for one concrete tool call
// (I56): allow, deny, or require human approval. There is no "unknown"
// outcome — an evaluation that cannot complete denies (fail-closed).
type ToolDecisionOutcome string

const (
	// ToolAllow permits execution under the current policy.
	ToolAllow ToolDecisionOutcome = "allow"
	// ToolDeny blocks execution with a reason surfaced to the caller.
	ToolDeny ToolDecisionOutcome = "deny"
	// ToolApprovalRequired parks the call for a human decision through
	// ApprovalSPI.
	ToolApprovalRequired ToolDecisionOutcome = "approval_required"
)

// ToolDecision is the guard-path verdict for one concrete call. PolicyRef
// names the policy/policy-version that produced it for audit and recheck
// purposes; it never contains secrets.
type ToolDecision struct {
	Outcome   ToolDecisionOutcome
	Reason    string
	PolicyRef string
}

// AllowedChecker is the per-call permission surface returned by
// ToolRegistrySPI.Resolve. THE ONE GUARD PATH: tool execution permission is
// decided here — keyed by org, project, subject, actual model and concrete
// tool call — and nowhere else. Invariants:
//
//   - Never auto-allows: a missing policy, an unevaluatable policy or an
//     error denies (fail-closed); only an explicit evaluation result allows.
//   - Model-aware: the checker sees Operation.Model, so one model's tool
//     calls may be allowed while another's are denied (I51).
//   - Per-step: permission is evaluated for every step, not amortized across
//     the operation; a fresh evaluation after approval is mandatory (recheck,
//     I56–I58).
//   - Scope-separated: permission to execute is independent of permission to
//     expose the invocation or its result to a client, and of external
//     credential permissions (I51/I54).
type AllowedChecker interface {
	Allowed(ctx context.Context, op Operation, call ToolCallRequest) ToolDecision
}

// ToolRegistrySPI resolves registered tools. Invariant: fail-closed — an
// unknown or unregistered tool resolves to ErrUnknownTool and can never
// execute; Resolve never fabricates a permissive checker. Implementations
// are expected to delegate to the existing Apache registries (pkg/toolexec
// built-ins, MCP aggregator catalogs) rather than duplicate them.
type ToolRegistrySPI interface {
	// Resolve returns the spec of the server-qualified tool ("server:tool",
	// matching the existing toolexec addressing convention) together with
	// its AllowedChecker for this operation.
	Resolve(ctx context.Context, op Operation, name string) (ToolSpec, AllowedChecker, error)
}

// ChatTurnRequest is one bounded model turn. Messages and Tools use the
// gateway's canonical OpenAI wire schema as raw bytes: the loop's turns are
// internal frames (I52 — internal tool calls are not forwarded to the
// client), and every provider translation stays with the existing
// pkg/provider.TranslateRequest/TranslateResponse implementations, which this
// seam deliberately does not duplicate.
type ChatTurnRequest struct {
	// Model is the resolved model identity to serve the turn with.
	Model string
	// Messages is the OpenAI wire-format chat array (canonical schema).
	Messages json.RawMessage
	// Tools is the ALLOWED subset of tool definitions in OpenAI wire
	// format. The engine passes only tools the guard path admitted; the
	// model client must not widen it.
	Tools json.RawMessage
	// MaxOutputTokens bounds the turn's generation; implementations must
	// enforce the bound provider-side where supported.
	MaxOutputTokens int64
}

// ChatTurnResult is the outcome of one model turn. Usage reuses the
// canonical pkg/provider.Usage so settlement prices turns with the same
// accounting the gateway already trusts.
type ChatTurnResult struct {
	TurnID string
	// Response is the OpenAI wire-format response (canonical schema),
	// including any proposed tool calls for the engine to guard.
	Response json.RawMessage
	// Usage is the turn's token accounting. Source distinguishes provider
	// reported, estimated and absent usage.
	Usage provider.Usage
	// FinishReason is the provider finish reason, when reported.
	FinishReason string
	// Uncertain marks an unknown upstream outcome: disconnected socket,
	// timeout or missing bytes do NOT prove the provider did not execute
	// the request (I45). An uncertain turn is never retried blindly, never
	// settled as zero, and never reported as completed.
	Uncertain bool
}

// ModelClientSPI is the streaming model seam for one bounded turn.
// Invariants: a turn consumes budget like any other step; a cancelled or
// failed stream whose execution state is unknown yields ChatTurnResult.
// Uncertain = true (fail-closed classification, I45), never a fabricated
// empty success. Implementations wrap the existing pkg/provider.Provider and
// upstream pool; they do not open a second provider stack.
type ModelClientSPI interface {
	// ChatStream executes one model turn. onDelta, when non-nil, receives
	// raw streaming chunks as they arrive (best-effort observability for
	// ProgressSink consumers; internal loop frames are still not forwarded
	// to the initiating client — I52). An error from onDelta aborts the
	// stream: the implementation must then classify the turn honestly per
	// I45 (unknown execution stays unknown), never as a free success.
	ChatStream(ctx context.Context, req ChatTurnRequest, onDelta func(delta []byte) error) (ChatTurnResult, error)
}

// SideEffect classifies the external effect of a tool call. The class exists
// so an unconfirmed mutation can never masquerade as completed.
type SideEffect string

const (
	// SideEffectNone reports that the call only read or computed; nothing
	// external changed.
	SideEffectNone SideEffect = "none"
	// SideEffectDone reports that the external mutation is confirmed
	// complete.
	SideEffectDone SideEffect = "done"
	// SideEffectUncertain reports that it is unknown whether the external
	// mutation executed (timeout, cancellation, failover). The uncertainty
	// is durable: it stays uncertain — never reported as done, never
	// claimed as rolled back without evidence, never repeated without a
	// proven duplicate-prevention or non-execution guarantee (I45, I55).
	SideEffectUncertain SideEffect = "uncertain"
)

// ToolCallResult is the outcome of one admitted tool call.
type ToolCallResult struct {
	Call ToolCallRequest
	// Result is the post-guard tool payload (guardrails already applied).
	Result json.RawMessage
	// SideEffect classifies the external effect; SideEffectUncertain must
	// surface to status/history, not be smoothed over.
	SideEffect SideEffect
	LatencyMS  int64
}

// StepOutcome is the engine-visible result class of one executed step. It
// maps onto the shared state machine through Apply: awaiting_approval parks
// the operation, failed and uncertain are engine decisions that must respect
// the unknown-outcome rule, completed merely means this step finished (loop
// completion is a separate running→completed transition).
type StepOutcome string

const (
	// StepCompleted reports that the step finished with a confirmed
	// outcome.
	StepCompleted StepOutcome = "completed"
	// StepAwaitingApproval reports that the step parked on a human
	// decision (durable ApprovalRequest opened).
	StepAwaitingApproval StepOutcome = "awaiting_approval"
	// StepFailed reports that the step failed with a known outcome (guard
	// deny, provider error, boundary).
	StepFailed StepOutcome = "failed"
	// StepUncertain reports that the step's effect is unknown (I45).
	// Engines must preserve the uncertainty in status/history and must not
	// auto-repeat the step without proven dedup or guaranteed
	// non-execution.
	StepUncertain StepOutcome = "uncertain"
)

// StepRequest addresses one step to execute. Exactly one of Turn/Call is set,
// matching Kind. TurnID is the attempt identity: a repeat of an uncertain
// step is a NEW attempt with a NEW TurnID only when a proven upstream
// deduplication contract or guaranteed non-execution justifies it (I45).
type StepRequest struct {
	OperationID OperationID
	// StepIndex is the zero-based monotonic step number within the
	// operation; budget limits count against it.
	StepIndex int
	TurnID    string
	Kind      StepKind
	// Turn is set when Kind == StepModelTurn.
	Turn ChatTurnRequest
	// Call is set when Kind == StepToolCall.
	Call ToolCallRequest
}

// StepResult is what one executed step reports back through the seam.
type StepResult struct {
	StepIndex int
	Outcome   StepOutcome
	// Turn is set for model turns; Call for tool calls.
	Turn *ChatTurnResult
	Call *ToolCallResult
	// Events is the ordered journal of what happened (audit/progress
	// feed). EventBoundaryExceeded MUST appear when a limit stopped the
	// step, so exhaustion is observable and honest.
	Events []StepEvent
}

// ExecutorSPI is the primary step seam: it executes ONE bounded step of a
// loop operation and reports the outcome. Invariants it enforces:
//
//   - Pure seam, no loop driver: ExecuteStep runs exactly the step req
//     addresses and decides nothing beyond it — no step sequencing, no
//     retry loop, no resume scheduling, no self re-entry. Driving steps
//     belongs to the engine composing this seam; core ships no driver.
//   - Context is honored: ExecuteStep respects ctx cancellation and
//     deadline on every execution path; if cancellation leaves an external
//     effect's execution state unconfirmable, the step is reported per the
//     unknown-outcome rule, never as a fabricated success.
//   - Request fidelity: exactly one of StepRequest.Turn/Call is set,
//     matching Kind; the executor must not widen the admitted surface —
//     ChatTurnRequest.Tools reaches the model client exactly as admitted,
//     and no un-admitted tool is invoked.
//   - Uncertain stays uncertain (I45): an unknown outcome surfaces through
//     the StepResult fields — StepOutcome StepUncertain, plus
//     ChatTurnResult.Uncertain or ToolCallResult.SideEffect =
//     SideEffectUncertain — never smoothed into StepCompleted and never
//     auto-repeated inside the step.
//   - Honest boundary reporting: when a configured limit stopped the step,
//     StepResult.Events carries EventBoundaryExceeded (I52); exhaustion is
//     never silently dropped or misreported as completion.
//   - Sentinel errors: failures that fit the shared contract wrap the
//     package sentinels with %w where applicable (e.g. ErrUnknownTool for
//     an unresolvable tool, ErrApprovalExpired for a late approval
//     resume), so callers classify with errors.Is without importing
//     implementation packages.
type ExecutorSPI interface {
	// ExecuteStep executes one bounded step addressed by req against op and
	// reports its outcome. Implementations must not mutate op.
	ExecuteStep(ctx context.Context, op Operation, req StepRequest) (StepResult, error)
}

// ApprovalRequest is the durable, exactly-bound ask for a human decision
// (I56). The binding is what makes approvals non-transferable: normalized
// argument digest + policy/config version, so changed args or a changed
// policy cannot ride an old approval.
type ApprovalRequest struct {
	OperationID OperationID
	StepIndex   int
	TurnID      string
	// Initiator is the authenticated principal that owns the operation;
	// InitiatorKind drives the no-self-approval rule (I57).
	Initiator     string
	InitiatorKind SubjectKind
	// Server/Tool pin the concrete invocation; ArgsDigest is a SHA-256
	// digest over the normalized arguments (never the raw secret-bearing
	// args themselves). Normalization is canonical JSON: UTF-8 encoding,
	// object keys sorted lexicographically, no insignificant whitespace —
	// the same logical arguments yield the same digest across
	// implementations, and a differently serialized replay is a different
	// binding (re-approval), which keeps the check fail-closed.
	Server     string
	Tool       string
	ArgsDigest string
	// PolicyRef pins the policy/config version the binding was made under.
	PolicyRef string
	// TTL is the policy-configured waiting period; zero means
	// DefaultApprovalTTL (I59). A negative TTL is INVALID configuration:
	// ApprovalSPI.Request must reject it with a validation error at
	// request creation — never clamp it to the default and never let it
	// silently produce an already-expired deadline.
	TTL time.Duration
	// RequiresDifferentHuman records a policy that mandates a second human
	// approver; it overrides any self-approval permission (I57).
	RequiresDifferentHuman bool
}

// ApprovalState is the durable approval lifecycle. approved and rejected are
// decision outcomes; expiry resolves pending → expired, and an expired
// approval never triggers execution (I59).
type ApprovalState string

const (
	// ApprovalPending reports that the approval is awaiting a human
	// decision.
	ApprovalPending ApprovalState = "pending"
	// ApprovalApproved reports that a human approved within TTL. Resuming
	// still requires the mandatory rights/credentials/policy recheck
	// (I58).
	ApprovalApproved ApprovalState = "approved"
	// ApprovalRejected reports that a human rejected within TTL.
	ApprovalRejected ApprovalState = "rejected"
	// ApprovalExpired reports that the TTL passed without a decision.
	// Terminal; a new operation is required (I59).
	ApprovalExpired ApprovalState = "expired"
	// ApprovalCancelled reports that the operation was cancelled while
	// pending.
	ApprovalCancelled ApprovalState = "cancelled"
)

// ApprovalOutcome is the human decision carried by an ApprovalDecision.
type ApprovalOutcome string

const (
	// DecisionApproved approves the bound invocation.
	DecisionApproved ApprovalOutcome = "approved"
	// DecisionRejected rejects the bound invocation; the operation resolves
	// to cancelled through the shared state machine.
	DecisionRejected ApprovalOutcome = "rejected"
)

// ApprovalDecision is one human decision on a durable approval.
type ApprovalDecision struct {
	ApprovalID string
	Outcome    ApprovalOutcome
	// Approver is the authenticated HUMAN principal that decided. Agents
	// and CI never populate this — a decision whose approver resolves to
	// the initiating agent/CI subject violates the contract (I57).
	Approver  string
	DecidedAt time.Time
	// RecheckRequired flags decisions that demand strict revalidation
	// beyond the standard recheck (e.g. approver re-eligibility after a
	// policy change). The v1 contract treats a rights/credentials/policy
	// recheck after approval as mandatory for EVERY approval (I56–I58);
	// this flag can only add requirements, never waive the mandatory one —
	// the zero value is therefore safe.
	RecheckRequired bool
}

// ApprovalSPI is the durable human-approval seam. Invariants it enforces:
//
//   - Durable identity: requests carry a unique ApprovalID and survive
//     restart and HA failover; status is reachable via UI/API regardless of
//     the initiating client's connection (I56, I58).
//   - Exact binding: an approval is bound to the concrete invocation
//     (server/tool/args digest/policy version) — the digest uses the
//     canonical JSON form pinned on ApprovalRequest.ArgsDigest. Changed
//     args or policy never reuse it; duplicate submissions of the same
//     decision resolve once.
//   - No self-approval: the approver must be an eligible human; for agent/CI
//     initiators a human is assigned, and a different-human policy is
//     mandatory (I57).
//   - TTL: the request expires at policy TTL (default 15 min, I59); a
//     negative TTL is invalid and rejected with a validation error at
//     Request time (zero means DefaultApprovalTTL); expiry
//     is enforced across restarts; late or repeated decisions cannot revive
//     an expired request and are rejected with ErrApprovalExpired; the
//     decision-versus-expiry race resolves through one atomic transition.
//   - No bypass: approval never substitutes for the guard path — execution
//     after approval still revalidates rights, credentials and policy
//     (I56–I58).
type ApprovalSPI interface {
	// Request records a durable approval request and returns it with its
	// ApprovalID and computed expiry.
	Request(ctx context.Context, op Operation, req ApprovalRequest) (ApprovalRecord, error)
	// Decision records a human decision for the referenced approval. It
	// returns ErrApprovalExpired when the request already expired and the
	// resulting ApprovalState either way; implementations resolve the
	// expiry race atomically (I59).
	Decision(ctx context.Context, dec ApprovalDecision) (ApprovalRecord, error)
}

// ApprovalRecord is the durable state of one approval request as returned by
// ApprovalSPI.
type ApprovalRecord struct {
	ApprovalID string
	Request    ApprovalRequest
	State      ApprovalState
	// ExpiresAt is the absolute deadline persisted with the request so TTL
	// enforcement survives restart and failover (I59).
	ExpiresAt time.Time
	// Decision is set once a human decision resolved the request.
	Decision *ApprovalDecision
}

// CostEstimate is the worst-case resource ask of one step, evaluated by
// BudgetGuardSPI.AdmitStep BEFORE the step runs. MaxSpend must cover the
// uncertain case: a missing response does not imply zero cost, so the
// estimate bounds what the step could settle even when its outcome stays
// unknown (I45).
type CostEstimate struct {
	// MaxSpend is the worst-case settlement amount for the step.
	MaxSpend money.MicroUSD
	// EstimatedTokens is the expected token count (0 = unknown; guard on
	// MaxSpend).
	EstimatedTokens int64
	// MaxWallTime bounds the active execution time the step may consume.
	MaxWallTime time.Duration
}

// BudgetLimits are the configured loop bounds (I52: steps, time, spend and
// concurrency are bounded by policy). Zero means "not configured": the
// fail-closed reading — a limit that is not configured denies rather than
// allowing unbounded operation, mirroring the agent budget posture
// (ErrNoAgentBudget). Deployments opt in by configuring explicit limits;
// an explicit "unlimited" is a policy decision expressed outside this struct,
// never by leaving fields zero.
type BudgetLimits struct {
	// MaxSteps bounds executed steps per operation.
	MaxSteps int
	// MaxConcurrentSteps bounds simultaneously running steps across
	// replicas of the operation.
	MaxConcurrentSteps int
	// MaxActiveTime bounds accumulated ACTIVE execution wall time. Time
	// spent awaiting human approval is tracked separately from active time
	// (its TTL is the approval TTL), and the engine must document how the
	// two interact with budget reservations (I58 planning implications).
	MaxActiveTime time.Duration
	// MaxTotalSpend bounds the operation's settled spend.
	MaxTotalSpend money.MicroUSD
}

// BudgetGuardSPI admits one step before it runs. Invariants it enforces:
//
//   - Fail-closed: an admission that cannot be evaluated denies with an
//     error wrapping ErrBudgetUnavailable; it never fails open.
//   - Bounded loop: steps, active time, total spend and concurrency are all
//     checked against BudgetLimits; a refused step is reported (boundary
//     exceeded), never silently dropped (I52).
//   - Settlement coupling: reservations taken at admission settle or release
//     exactly once; uncertain outcomes keep their reservation (missing
//     response ≠ zero cost, I45).
//
// Implementations are expected to build on the existing pkg/budget and
// pkg/money machinery (MicroUSD accounting, reservations, loop-hop budget)
// rather than a parallel money path.
type BudgetGuardSPI interface {
	// AdmitStep returns nil when the step may run within the configured
	// limits, or an error wrapping ErrBudgetExceeded / ErrBudgetUnavailable.
	AdmitStep(ctx context.Context, op Operation, req StepRequest, est CostEstimate) error
}

// ProgressSink streams operation status and results for API/UI consumers.
// Invariants:
//
//   - Connection-independent: status and result remain reachable after the
//     initiating client disconnects (I58); the sink feeds durable status
//     surfaces, it is not a client socket.
//   - Not the record of record: the sink is best-effort observability. It is
//     NOT the audit trail and NOT the durability layer — ApprovalSPI,
//     SettlementSPI and the engine's persisted operation state own that.
//     Losing sink output loses convenience, never truth.
//   - Honest terminal reporting: the sink reports cancelled, expired,
//     failed, uncertain and boundary-exceeded outcomes with their reasons;
//     an unexecuted tool call is never reported as completed (I56).
type ProgressSink interface {
	// Status streams one progress event for the operation.
	Status(ctx context.Context, op Operation, event StepEvent)
	// Result streams the terminal result of the operation.
	Result(ctx context.Context, op Operation, result OperationResult)
}

// OperationResult is the terminal outcome of an operation as exposed to
// API/UI. Response carries the final client-visible answer; internal tool
// frames stay internal unless policy separately permits exposure (I52 —
// hiding frames does not grant trace-read rights, which remain governed by
// the content-access policy).
type OperationResult struct {
	OperationID OperationID
	FinalState  OperationState
	// Response is the final model answer in the canonical OpenAI wire
	// schema.
	Response json.RawMessage
	// Uncertain marks that some external effect of the operation remains
	// unconfirmed; consumers must surface it, not average it away (I45).
	Uncertain bool
	// Reason explains terminal states (boundary kind, expiry, failure
	// class) in value-free terms.
	Reason string
}

// UsageEntry is one settlement record: per model turn and per tool call,
// keyed exactly once by the tuple (OperationID, StepIndex, TurnID).
// Uncertain attempts are settled with AmountKnown=false — the unknown-price
// state — never silently as zero (I45; PRODUCT-CONTRACT §9: неизвестная
// цена — unknown_price). TurnID inside the key makes a justified
// re-attempt of an uncertain step settle as a NEW row (see SettlementSPI);
// the earlier row always stands.
type UsageEntry struct {
	OperationID OperationID
	StepIndex   int
	TurnID      string
	// Kind is the settlement-bearing event kind: EventModelTurn for model
	// turns, EventToolCall for tool calls.
	Kind StepEventKind
	// Usage carries token accounting for model turns (provider.Usage
	// reuse); tool calls leave it zero.
	Usage provider.Usage
	// Amount is the settled amount; meaningful only when AmountKnown.
	Amount money.MicroUSD
	// AmountKnown=false marks unknown price — preserved as unknown, not
	// billed as zero.
	AmountKnown bool
	// UncertainEffect marks that the settled step's external effect is
	// unconfirmed; settlement and uncertainty coexist (I45).
	UncertainEffect bool
}

// SettlementSPI records per-turn and per-tool usage exactly once.
// Invariants it enforces:
//
//   - Exactly-once by the key tuple (OperationID, StepIndex, TurnID): a
//     duplicate submission for an already-settled tuple no-ops
//     idempotently or fails with ErrDuplicateSettlement — the amount is
//     never added twice, and per-turn totals are never re-counted inside
//     later turns. Implementations make the tuple unique through a durable
//     constraint or transactional state machine so replays after
//     crash/failover cannot double-count.
//   - Re-attempt at the same StepIndex: a justified re-attempt of an
//     uncertain step carries a NEW TurnID (StepRequest, I45) and therefore
//     settles as a NEW settlement row; the earlier row always stands —
//     including an AmountKnown=false row, whose budget reservation
//     persists. Re-indexing is not a settlement event: only a genuinely
//     executed attempt with its own TurnID settles.
//   - Unknown-price amendment is OUT of v1 scope: an AmountKnown=false row
//     is final for v1.x. If the true price later becomes known, no v1.x
//     mechanism rewrites or amends the settled row; retroactive repricing,
//     if ever added, must arrive as additive surface with its own distinct
//     key semantics — never by mutating a settled row in place.
//   - Uncertainty-preserving: an unknown outcome or unknown price settles
//     as unknown (AmountKnown=false / UncertainEffect=true), never as a
//     fabricated zero; budget reservations for uncertain attempts persist.
//   - Completeness: every billable step — model turn AND tool call —
//     settles; skipping settlement for a class of steps undercounts spend
//     and violates the accounting contract (I52: all model turns and tool
//     costs are accounted for).
type SettlementSPI interface {
	// RecordUsage applies one settlement entry keyed by the tuple
	// (OperationID, StepIndex, TurnID).
	RecordUsage(ctx context.Context, op Operation, entry UsageEntry) error
}
