package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// modelResolver is the resolution surface the gateway wires. Request paths
// use ResolveChecked (RT-06): err != nil means the registry is unavailable or
// the request context ended — terminal, never treated as "model missing"
// (RM-09) and never routed around. The legacy Resolve remains on the surface
// because the fallback chain builder (router.FallbackExecutor) synthesises
// candidates from failover names and cannot fail a hop on resolution; its
// policy correctness is owned by the RT-03 per-attempt gate.
// *resolver.Resolver satisfies it in production.
type modelResolver interface {
	Resolve(ctx context.Context, modelName string) resolver.ModelInfo
	ResolveChecked(ctx context.Context, modelName string) (resolver.ModelInfo, error)
}

type modelAccess interface {
	Check(ctx context.Context, apiKeyID, teamID, modelName string) (bool, error)
}

type teamBudgetChecker interface {
	CheckBudget(ctx context.Context, teamID string) error
}

type agentBudgetChecker interface {
	CheckAgentBudget(ctx context.Context, agentID string) error
}

type residencyChecker interface {
	Enforce(ctx context.Context, orgID, requestedModel string, modelRegion policy.Region, family string) policy.Decision
}

// admitInput is the pre-routing admission request for a non-chat endpoint.
type admitInput struct {
	Endpoint string // "embeddings" | "completions" | "responses.native" | "messages.native" | "messages.count_tokens" | "audio.speech" | "audio.transcriptions" | "images.generation" | "rerank" | "moderations" | "realtime"
	Model    string // as the client sent it
	Body     []byte // raw client body (for guards)
	// NoRemap forbids a residency model swap (embeddings: another model is another dimension).
	NoRemap bool
	// SkipSpendChecks skips budgets (count_tokens is not spend).
	SkipSpendChecks bool
}

// admitted is the request after guards and policy checks.
type admitted struct {
	Info           resolver.ModelInfo
	RequestedModel string
	Body           []byte
	OrgID          string
	TeamID         string
	APIKeyID       string
	SessionKeyID   string
	AgentID        string
	UserID         string
	TaskID         string
	WorkloadID     string
	SessionID      string
	RequestID      string
}

// admissionCoreInput is the input of the shared pre-routing guard sequence.
type admissionCoreInput struct {
	Model string // as the client sent it
	Body  []byte // raw client body (for guards)
	// SkipSpendChecks skips budgets (count_tokens is not spend).
	SkipSpendChecks bool
	// Rebuild re-derives the caller's typed projection from the GUARDED body
	// after the guard hooks and before model resolution (chat, RT-04: every
	// downstream consumer must agree with the payload that is forwarded).
	// nil on the non-chat paths.
	Rebuild func(body []byte) error
	// BudgetEventUser stamps the key owner (user_id) on the team-budget
	// event — the historical chat event shape; non-chat events omit it.
	BudgetEventUser bool
}

// admissionCore is the request identity after the shared guard sequence ran.
type admissionCore struct {
	Body     []byte // guarded
	Info     resolver.ModelInfo
	Fallback bool

	RequestID    string
	SessionID    string
	OrgID        string
	TeamID       string
	APIKeyID     string
	SessionKeyID string
	AgentID      string
	UserID       string
	TaskID       string
	WorkloadID   string
	// FairTicket is the release handle for the admitted fair-admission slot
	// (nil when the feature is off or the request was shed). RATELIMIT-FALLBACK
	// F1: the chat path releases it synchronously at request end — the
	// context.AfterFunc anchor below fires in its own goroutine, which cannot
	// order the release before the batch executor's next in-process line.
	FairTicket *router.FairTicket
}

// admissionCore is the pre-routing guard sequence shared by admit() (every
// common admission core instead of its own copy). The ORDER is the contract,
// preserved verbatim from both call sites:
//
//	egress guards → (projection rebuild) → model resolution → unknown-model
//	policy → task tag → whitelist → team budget → agent budget → token/session
//	budgets.
//
// A false result means the request was answered terminally inside the core.
// Residency and the RT-02 final-candidate gate stay with the callers: chat
// runs them after routing, non-chat immediately after the core.
func (gw *gateway) admissionCore(w http.ResponseWriter, r *http.Request, l *slog.Logger, in admissionCoreInput) (admissionCore, bool) {
	out := admissionCore{
		RequestID:    logctx.RequestID(r.Context()),
		SessionID:    r.Header.Get("X-Session-Id"),
		OrgID:        r.Header.Get("X-Org-Id"),
		TeamID:       r.Header.Get("X-Team-Id"),
		APIKeyID:     r.Header.Get("X-API-Key-Id"),
		SessionKeyID: r.Header.Get("X-Session-Key-Id"),
		AgentID:      r.Header.Get("X-Agent-Id"),
		UserID:       r.Header.Get("X-User-Id"),
	}

	// U1: pre-egress guard hooks (deterministic PII/secrets/injection). Runs
	// once per request, before routing/forwarding. deny → 400, no forward;
	// redact → body is rewritten; log/off → pass-through.
	body, err := gw.applyEgressGuards(in.Body)
	if err != nil {
		l.Warn("guard hooks denied request", "error", err)
		apierrors.Write(w, http.StatusBadRequest, "guard_denied",
			"request blocked by guard hooks: sensitive data detected")
		return admissionCore{}, false
	}
	out.Body = body

	// RT-04 (chat): rebuild the typed projection from the GUARDED body
	// before anything downstream consumes it.
	if in.Rebuild != nil {
		if rerr := in.Rebuild(body); rerr != nil {
			l.Warn("guarded body is not a valid chat completion request", "error", rerr)
			apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"malformed JSON: "+rerr.Error())
			return admissionCore{}, false
		}
	}

	info, resErr := gw.resolveModelInfo(r.Context(), in.Model)
	if resErr != nil {
		// RT-06: a registry outage or a cancelled request is terminal — no
		// fallback substitution, no routing continuation, no upstream call.
		l.Warn("model resolution unavailable, denying request", "error", resErr, "requested", in.Model)
		writeResolutionUnavailable(w)
		return admissionCore{}, false
	}
	if info.Fallback && gw.unknownModelPolicy == "reject" {
		msg := fmt.Sprintf("model %q is not available on this gateway", in.Model)
		apierrors.WriteWithCode(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, msg, "model_not_found")
		publishEvent(gw.publisher, l, eventBase{ //nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
			EventType:      "request.invalid",
			RequestID:      out.RequestID,
			SessionID:      out.SessionID,
			Payload:        string(body),
			OrgID:          out.OrgID,
			TeamID:         out.TeamID,
			ModelRequested: in.Model,
			Error:          msg,
			Labels:         labelsFrom(r.Context()),
		}.build())
		return admissionCore{}, false
	}
	if info.Fallback {
		w.Header().Set("X-Yabanin-Model-Fallback", in.Model+"->"+info.ModelName)
	}
	out.Info = info
	out.Fallback = info.Fallback

	taskID := r.Header.Get("X-Yabanin-Task")
	if !budget.ValidTaskID(taskID) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_task_id",
			"X-Yabanin-Task must match [A-Za-z0-9._:-]{1,128}")
		return admissionCore{}, false
	}
	// ADL-01: CI task tag — a deployment-level default for requests that carry
	// no X-Yabanin-Task header of their own. An explicit per-request header
	// always wins.
	if taskID == "" && gw.taskTag != "" {
		taskID = gw.taskTag
	}
	out.TaskID = taskID

	// N06-P07-T04: workload identity — the chargeback dimension.
	//
	// X-Yabanin-Workload is a CALLER-ASSERTED attribution label, not a
	// verified identity: any well-formed key is accepted and rides the
	// caller's own org namespace in the cap ledger. It gates spend
	// attribution, never authorization. Because explicit keys are taken
	// verbatim, an explicit key shaped like a derived form ("team:x",
	// "agent:y") lands in the same window as the derivation that would
	// produce it — deliberate (one naming scheme, one window per shape),
	// and safe because the org component keeps it inside the caller's own
	// tenant.
	//
	// An explicit header wins; otherwise the key is derived from the
	// agent/team/task identity the request already carries, so every
	// request — batch lines included, which synthesize only X-Yabanin-Task —
	// is attributable and cannot bypass the dimension. A malformed explicit
	// key is a 400, the same shape as the task tag. The resolved key rides
	// the request's label context (metaLabelWorkload), which is how it
	// reaches every settle event downstream — the durable chargeback record.
	workloadID := r.Header.Get("X-Yabanin-Workload")
	if workloadID != "" && !budget.ValidWorkloadKey(workloadID) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_workload_id",
			"X-Yabanin-Workload must match [A-Za-z0-9._:-]{1,128}")
		return admissionCore{}, false
	}
	out.WorkloadID = budget.DeriveWorkloadKey(out.AgentID, out.TeamID, taskID, workloadID)
	setWorkloadLabel(r, out.WorkloadID)

	// P1.1: Whitelist enforcement — check model access before cache/routing.
	// Fail-closed: a datastore error must NOT admit a request whose model may
	// be restricted. The whitelist sees the alias-aware registry name (RT-02):
	// an alias is checked as its canonical target, matching chat.go and the
	// non-chat endpoints — the same alias must not behave differently per
	// endpoint. The RT-02 final gate re-checks the candidate after residency
	// remap.
	if gw.wl != nil {
		allowed, err := gw.wl.Check(r.Context(), out.APIKeyID, out.TeamID, whitelistModel(info, in.Model))
		if err != nil {
			l.Warn("whitelist check failed, denying request", "error", err, "key_id", out.APIKeyID, "model", info.ModelName)
			metrics.WlCheckErrors.Inc()
			apierrors.Write(w, http.StatusServiceUnavailable, "whitelist_check_unavailable",
				"whitelist check temporarily unavailable")
			return admissionCore{}, false
		}
		if !allowed {
			apierrors.Write(w, http.StatusForbidden, apierrors.ErrorCodePermissionDenied,
				fmt.Sprintf("model %q is not allowed for this API key", in.Model))
			return admissionCore{}, false
		}
	}

	if !in.SkipSpendChecks {
		// P6.10: Team budget enforcement. Fail-safe semantics:
		//   ErrNoBudget (no row) -> 403, ErrBudgetExceeded -> 429,
		//   any other (datastore error) -> 503. Never allow spend when the
		//   budget store is degraded.
		if gw.budgetEnforcer != nil && out.TeamID != "" {
			if err := gw.budgetEnforcer.CheckBudget(r.Context(), out.TeamID); err != nil {
				switch {
				case errors.Is(err, budget.ErrNoBudget):
					apierrors.Write(w, http.StatusForbidden, "budget_not_configured",
						"team has no budget configured — spending is disabled until a budget is set")
				case errors.Is(err, budget.ErrBudgetExceeded):
					apierrors.Write(w, http.StatusTooManyRequests, "budget_exceeded",
						fmt.Sprintf("team budget limit reached: %v", err))
					publishEvent(gw.publisher, l, eventBase{ //nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
						EventType:      "request.budget_exceeded",
						RequestID:      out.RequestID,
						SessionID:      out.SessionID,
						Payload:        string(body),
						OrgID:          out.OrgID,
						TeamID:         out.TeamID,
						UserID:         out.budgetEventUser(in.BudgetEventUser),
						ModelRequested: info.ModelName,
						Error:          err.Error(),
						Labels:         labelsFrom(r.Context()),
					}.build())
				default:
					apierrors.Write(w, http.StatusServiceUnavailable, "budget_check_unavailable",
						fmt.Sprintf("budget check temporarily unavailable: %v", err))
				}
				return admissionCore{}, false
			}
		}
		// G2: per-agent budget enforcement (fail-safe, mirrors the team
		// budget). Only runs for requests that carry an agent identity AND
		// have a configured agent budget row; agents without a row
		// (ErrNoAgentBudget) are denied.
		if gw.agentEnforcer != nil && out.AgentID != "" {
			if err := gw.agentEnforcer.CheckAgentBudget(r.Context(), out.AgentID); err != nil {
				switch {
				case errors.Is(err, budget.ErrNoAgentBudget):
					apierrors.Write(w, http.StatusForbidden, "agent_budget_not_configured",
						"agent has no budget configured — spending is disabled until a budget is set")
				case errors.Is(err, budget.ErrAgentBudgetExceeded):
					apierrors.Write(w, http.StatusTooManyRequests, "agent_budget_exceeded",
						fmt.Sprintf("agent daily budget limit reached: %v", err))
				default:
					apierrors.Write(w, http.StatusServiceUnavailable, "agent_budget_check_unavailable",
						fmt.Sprintf("agent budget check temporarily unavailable: %v", err))
				}
				return admissionCore{}, false
			}
		}
		// N06-P07-T04: workload cap (opt-in, per-replica). Fail-closed over
		// cap → 429, the same refusal shape as the team/agent budget areas;
		// a disabled ledger or an unattributable request is a no-op. The
		// window is namespaced by the AUTHENTICATED org (out.OrgID, as set
		// by the auth middleware — NEXT-02/F02 precedent): identical
		// workload names across orgs never share a counter, so one tenant's
		// charges can never 429 another tenant.
		if err := sharedWorkloadLedger().Admit(out.OrgID, out.WorkloadID, 0); err != nil {
			apierrors.Write(w, http.StatusTooManyRequests, "workload_budget_exceeded",
				fmt.Sprintf("workload budget limit reached: %v", err))
			return admissionCore{}, false
		}
		// G3: per-task / per-session token budgets (opt-in). 429 on exceed;
		// X-Yabanin-Budget-Warning when at/near cap. No-op when both caps 0.
		if !gw.checkTokenBudget(w, r, out.OrgID, taskID, out.SessionID) || !gw.checkSessionBudget(w, r) {
			return admissionCore{}, false
		}
	}

	// RATELIMIT-FALLBACK P3: per-replica fair admission in front of
	// upstream dispatch (opt-in; nil = off). This one site covers every
	// request the gateway admits — chat (JSON and stream share it) and all
	// non-chat endpoints — so the concurrency bounds cannot be routed
	// around by a different endpoint family. The ticket is released when
	// the request ends: the chat path releases it synchronously on handler
	// return (F1, batch lines are in-process and cannot absorb the async
	// fire), the AfterFunc below is the backstop that frees the slot early
	// on mid-request client disconnect, and non-chat endpoints release on
	// ServeHTTP return. FairTicket.Release is exactly-once (sync.Once), so
	// double release across the anchors is impossible and no handler
	// learns about the controller.
	if gw.fair != nil {
		ticket, err := gw.fair.Admit(r.Context(), out.OrgID, out.WorkloadID)
		if err != nil {
			var shed *router.FairShedError
			if errors.As(err, &shed) {
				secs := fairShedRetryAfterSeconds(shed.RetryAfter)
				if secs > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(secs))
				}
				l.Warn("fair admission shed request",
					"reason", string(shed.Reason), "retry_after", shed.RetryAfter.String())
				apierrors.WriteWithCode(w, http.StatusTooManyRequests,
					apierrors.ErrorCodeRateLimitExceeded,
					fairShedMessage(secs, shed.Reason),
					"rate_limit_exceeded")
				return admissionCore{}, false
			}
			// Dead context (client disconnect / timeout middleware): the
			// response belongs to whoever canceled. Best-effort no write —
			// a superfluous WriteHeader here would race the deadline
			// writer; the request simply ends.
			l.Debug("fair admission refused canceled request", "error", err)
			return admissionCore{}, false
		}
		out.FairTicket = ticket
		context.AfterFunc(r.Context(), ticket.Release)
	}

	return out, true
}

// fairShedRetryAfterSeconds converts the shed hint into whole seconds for
// the client Retry-After header. The hint already carries upward jitter, and
// the ceil keeps the header >= the base hint, so a client never retries
// before the window. The client-facing ceiling matches the other gateway
// hint writers (60s max). 0 = no hint configured → header omitted.
func fairShedRetryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	secs := int(math.Ceil(d.Seconds()))
	if secs > clientRetryAfterCeiling {
		secs = clientRetryAfterCeiling
	}
	return secs
}

// fairShedMessage renders the fair-admission 429 message. Mirrors the key
// rate limit wording ("retry in Ns") so clients and operators see one
// consistent 429 shape across admission layers.
func fairShedMessage(secs int, reason router.FairShedReason) string {
	if secs > 0 {
		return fmt.Sprintf("gateway capacity reached (%s), retry in %ds", reason, secs)
	}
	return fmt.Sprintf("gateway capacity reached (%s)", reason)
}

// budgetEventUser resolves the user_id stamped on the team-budget event: the
// chat pipeline historically carries it, the non-chat events omit it.
func (c admissionCore) budgetEventUser(chatShape bool) string {
	if chatShape {
		return c.UserID
	}
	return ""
}

// --- workload chargeback wiring (N06-P07-T04) ---

// WorkloadBudgetEnvUSD names the opt-in per-workload daily cap (USD) for the
// shared workload ledger. Unset, unparsable or non-positive values keep the
// ledger disabled — admission then only attributes (labels) and never caps,
// mirroring the opt-in shape of the token budgets.
const WorkloadBudgetEnvUSD = "YABANIN_WORKLOAD_BUDGET_USD"

var (
	workloadLedgerOnce   sync.Once
	workloadLedgerShared atomic.Pointer[budget.WorkloadLedger]
)

// sharedWorkloadLedger returns the process-wide workload ledger. It lives
// here (not on the gateway struct) because the gateway facets are outside
// this card's write scope — the same placement the shared loop budget uses
// (agent_hop_budget.go). Tests pre-set workloadLedgerShared (atomic Store)
// to inject a capped instance; a non-nil preset wins over the lazy build.
// The pointer is atomic because admissionCore consults the ledger on EVERY
// request — the fast-path read must synchronize with both the lazy build
// and a concurrent test preset (a plain read next to Once.Do is a data
// race the race detector catches under concurrent load).
func sharedWorkloadLedger() *budget.WorkloadLedger {
	if l := workloadLedgerShared.Load(); l != nil {
		return l
	}
	workloadLedgerOnce.Do(func() {
		// CAS keeps a preset (landed before or during the build) winning
		// over the lazy build — the semantics the nil check used to give.
		workloadLedgerShared.CompareAndSwap(nil, budget.NewWorkloadLedger(workloadCapFromEnv(), 0))
	})
	return workloadLedgerShared.Load()
}

// workloadCapFromEnv parses WorkloadBudgetEnvUSD. Any parse failure or
// non-positive value selects the disabled ledger — a misconfigured cap must
// never silently become a different (e.g. tiny) cap.
func workloadCapFromEnv() money.MicroUSD {
	raw := strings.TrimSpace(os.Getenv(WorkloadBudgetEnvUSD))
	if raw == "" {
		return 0
	}
	usd, err := strconv.ParseFloat(raw, 64)
	if err != nil || usd <= 0 {
		return 0
	}
	cap, err := money.FromUSD(usd)
	if err != nil {
		return 0
	}
	return cap
}

// setWorkloadLabel merges the resolved workload key into the request's
// label context under metaLabelWorkload so every downstream settle event
// (labelsFrom) carries it. Copy-on-write: the stored labels.Set may be
// shared with other readers of the request context (batch lines fan out
// from one parent context), so the map is never mutated in place. An empty
// key (unattributable request) leaves the context untouched.
func setWorkloadLabel(r *http.Request, key string) {
	if key == "" {
		return
	}
	res, _ := r.Context().Value(labelsCtxKey{}).(labels.Result)
	merged := make(labels.Set, len(res.Labels)+1)
	for k, v := range res.Labels {
		merged[k] = v
	}
	merged[metaLabelWorkload] = key
	res.Labels = merged
	*r = *r.WithContext(withLabels(r.Context(), res))
}

// admit runs the same checks as chatCompletions before routing, in the same
// order, and writes the same status and error type on failure. ok is false
// when a response was already written. chat.go is intentionally not a caller:
// its normalize stage funnels through admissionCore with the typed projection
// rebuild and continues with validation + vertical transform.
func (gw *gateway) admit(w http.ResponseWriter, r *http.Request, in admitInput) (admitted, bool) {
	l := logctx.From(r.Context(), gw.log)
	core, ok := gw.admissionCore(w, r, l, admissionCoreInput{
		Model:           in.Model,
		Body:            in.Body,
		SkipSpendChecks: in.SkipSpendChecks,
	})
	if !ok {
		return admitted{}, false
	}
	out := admitted{
		Info:           core.Info,
		RequestedModel: in.Model,
		Body:           core.Body,
		OrgID:          core.OrgID,
		TeamID:         core.TeamID,
		APIKeyID:       core.APIKeyID,
		SessionKeyID:   core.SessionKeyID,
		AgentID:        core.AgentID,
		UserID:         core.UserID,
		TaskID:         core.TaskID,
		WorkloadID:     core.WorkloadID,
		SessionID:      core.SessionID,
		RequestID:      core.RequestID,
	}

	if gw.residencyEnforcer != nil && out.OrgID != "" {
		resDec := gw.residencyEnforcer.Enforce(r.Context(), out.OrgID, out.Info.ModelName, policy.Region(out.Info.Region), out.Info.Provider)
		if !resDec.Allowed {
			l.Warn("residency enforcement denied",
				"org_id", out.OrgID, "region", resDec.Region,
				"pack", resDec.PackID, "reason", resDec.Reason,
				"violations", resDec.Violations)
			metrics.ResidencyEnforcementTotal.WithLabelValues(string(resDec.Region), "denied").Inc()
			apierrors.Write(w, http.StatusForbidden, "residency_policy_violation",
				"request violates organization residency policy: "+resDec.Reason)
			return admitted{}, false
		}
		if resDec.RemappedModel != "" {
			if in.NoRemap {
				apierrors.Write(w, http.StatusForbidden, "residency_policy_violation",
					"model is not allowed in the organization's region and cannot be remapped for this endpoint")
				return admitted{}, false
			}
			l.Debug("residency remap", "org_id", out.OrgID, "from", out.Info.ModelName, "to", resDec.RemappedModel)
			nfo, resErr := gw.resolveModelInfo(r.Context(), resDec.RemappedModel)
			if resErr != nil {
				l.Warn("remapped model resolution unavailable, denying request", "error", resErr, "requested", resDec.RemappedModel)
				writeResolutionUnavailable(w)
				return admitted{}, false
			}
			out.Info = nfo
			metrics.ResidencyRemapTotal.WithLabelValues(string(resDec.Region)).Inc()
		}
		metrics.ResidencyEnforcementTotal.WithLabelValues(string(resDec.Region), "allowed").Inc()
		w.Header().Set("X-Residency-Region", string(resDec.Region))
		if resDec.PackID != "" && resDec.PackID != "none" {
			w.Header().Set("X-Residency-Pack", resDec.PackID)
		}
	}

	// RT-02: final-candidate policy gate. Non-chat paths do not run the
	// classifier or org rules, but an alias target, an unknown-model fallback
	// and a residency remap can each replace the resolved candidate; it is
	// re-checked here under the same access + ZAI/data-boundary contracts as
	// chat. Deny/unavailable are terminal — no upstream attempt follows.
	if !gw.enforceFinalCandidateGate(w, r, candidateIdentity{OrgID: out.OrgID, TeamID: out.TeamID, APIKeyID: out.APIKeyID}, in.Model, out.Info) {
		return admitted{}, false
	}
	return out, true
}
