// Package router contains the multi-provider fallback chain executor. Given
// a primary model and its failover_models list, the executor walks the chain
// calling the user-supplied attempt function for each candidate and stops on
// the first success or non-retryable outcome.
package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
)

// AttemptOutcome records one fallback attempt's result. Slice of these is
// returned from Execute for observability — published in the request.completed
// event so loggerd/P6 dashboards can show fallback hit-rates.
type AttemptOutcome struct {
	ModelName   string        `json:"model_name"`
	UpstreamURL string        `json:"upstream_url"`
	Provider    string        `json:"provider"`
	StatusCode  int           `json:"status_code"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration_ms"`
	Success     bool          `json:"success"`
	// Outcome is the three-way upstream outcome classification of the
	// attempt ("unknown", "not_executed" or "executed", retry.OutcomeSafety
	// String). It records the evidence the attempt left behind; it does not
	// by itself change chain decisions.
	Outcome string `json:"outcome,omitempty"`
	// RequestID is the client-request identity shared by every attempt in one
	// Execute call, read once from the request context
	// (retry.RequestIdentityFrom). It is the join key that attributes each
	// attempt — including attempts served by different providers after a
	// fallback — to one client request and its usage records. The executor
	// never mints or rewrites it; "" when the caller attached none.
	RequestID string `json:"request_id,omitempty"`
	// Attempt is the 1-based position of this attempt in the chain (1 = the
	// primary candidate). It orders the per-attempt usage records within one
	// request identity.
	Attempt int `json:"attempt"`
}

// PolicyError is a terminal policy outcome (denied or unavailable) produced by
// an AttemptFunc — e.g. the RT-03 per-attempt candidate gate. It is NOT a
// transport failure: the chain must stop immediately, never advance to the
// next candidate, and the gateway must surface the carried wire envelope
// (403 denied / 503 unavailable) instead of an upstream error mapping. A
// degraded policy store must not be routed around either, so both outcomes
// are terminal.
//
// An enforce-mode route hint that cannot influence the route (no chain candidate
// runs on the hinted provider) is an explicit 400 refusal raised BEFORE any
// candidate is attempted — attempts stays empty and no endpoint is dialed.
type PolicyError struct {
	Status  int    // HTTP status to surface (400 hint refusal / 403 denied / 503 unavailable)
	ErrType string // OpenAI-style error type for the envelope
	ErrCode string // optional machine-readable code (provider contracts)
	Message string
}

func (e *PolicyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("policy gate: %s", e.Message)
}

// StatusClassifier decides whether an outcome warrants trying the next model
// in the fallback chain. Returning false stops the chain — either because the
// attempt succeeded or because the failure is non-retryable (4xx).
type StatusClassifier func(statusCode int, err error) bool

// DefaultRetryable matches the canonical policy: retry on any transport
// error and on 429 / 5xx. Other 4xx (auth, validation) return immediately.
// Intentionally broader than retry.Policy.RetryOn — the fallback chain tries
// every model before giving up, so we err on the side of advancing the chain.
// A terminal *PolicyError is never retryable: a policy denial (or a policy
// store outage) must not be satisfied by the next candidate.
//
// An attempt whose upstream outcome is unknown (no HTTP answer arrived and
// the error carries no proof the exchange never started — timeouts,
// cancellations, write/read failures) is also terminal: the provider may
// have executed the request and charged for it or performed side effects,
// and a next-candidate call would repeat that work. Automatic repetition
// requires proof of non-execution or a verified provider deduplication
// contract (WithIdempotencyProof); callers that explicitly override the
// classifier via WithClassifier take that responsibility on themselves.
// When the executor itself ends the chain on such an attempt, the refusal is
// explained by a *retry.SuppressedError: the stable machine-readable code
// (retry_suppressed_unknown_outcome) is what API/UI layers render, while the
// original cause stays reachable via errors.Is/errors.As.
var DefaultRetryable StatusClassifier = func(code int, err error) bool {
	var policyErr *PolicyError
	if errors.As(err, &policyErr) {
		return false
	}
	if err != nil && retry.Classify(code, err) == retry.OutcomeUnknown {
		return false
	}
	if err != nil {
		return true
	}
	return code == 429 || code == 529 || code >= 500
}

// AttemptFunc is the per-model callback supplied by the gateway. It must be
// idempotent — the executor may call it multiple times across the chain. The
// request identity is carried in ctx (retry.RequestIdentityFrom): every
// attempt of one request must present the same identity — the same request id
// and the same idempotency key — to the upstream, or a provider deduplication
// contract cannot recognize the repeated operation and per-attempt usage rows
// lose their join key.
type AttemptFunc func(ctx context.Context, info resolver.ModelInfo) (statusCode int, err error)

// ModelResolver is the minimal resolver surface the fallback executor needs.
// *resolver.Resolver satisfies this interface; tests can substitute stubs.
type ModelResolver interface {
	Resolve(ctx context.Context, modelName string) resolver.ModelInfo
}

// FallbackExecutor walks a failover_models chain. The zero value is NOT valid;
// always construct via NewFallbackExecutor.
type FallbackExecutor struct {
	resolv    ModelResolver
	maxHops   int
	retryable StatusClassifier
	proof     retry.IdempotencyProof
	log       *slog.Logger
}

// NewFallbackExecutor builds an executor that will resolve failover_models
// names via resolv (when non-nil) and walk at most maxHops candidates. A
// maxHops of 0 or less defaults to 3.
func NewFallbackExecutor(resolv ModelResolver, maxHops int, log *slog.Logger) *FallbackExecutor {
	if maxHops <= 0 {
		maxHops = 3
	}
	if log == nil {
		log = slog.Default()
	}
	return &FallbackExecutor{
		resolv:    resolv,
		maxHops:   maxHops,
		retryable: DefaultRetryable,
		log:       log,
	}
}

// WithClassifier overrides the retryable-classifier. Returns the receiver for
// chaining. Useful for tests that want deterministic skipping behaviour.
func (f *FallbackExecutor) WithClassifier(c StatusClassifier) *FallbackExecutor {
	if c != nil {
		f.retryable = c
	}
	return f
}

// WithIdempotencyProof attaches a verified provider/action deduplication
// contract (retry.IdempotencyProof). The contract is the second repetition
// permission beside proven non-execution: when it allows the repeat, the
// chain may advance past an attempt that produced no HTTP answer, because the
// upstream has committed to deduplicating the repeated operation. Without a
// proof (the default) such an attempt is terminal — the provider may have
// executed it. A nil proof is ignored.
//
// The permission is deliberately narrow: it never overrides a policy denial
// (terminal before the classifier) and never overrides a definitive HTTP
// answer — a contract about duplicate operations says nothing new once the
// upstream has answered, so the ordinary status-based policy still governs
// those attempts.
func (f *FallbackExecutor) WithIdempotencyProof(p retry.IdempotencyProof) *FallbackExecutor {
	if p != nil {
		f.proof = p
	}
	return f
}

// Execute walks the fallback chain starting at primary. For each model it
// invokes fn; the first success (err == nil AND status < 500) short-circuits.
// Non-retryable failures (4xx) abort the chain immediately. Retryable
// failures advance to the next model. When all models are exhausted the last
// failure is returned.
//
// Returns:
//   - finalInfo: the ModelInfo that produced the final outcome (success or
//     last failure)
//   - statusCode: that outcome's HTTP status (0 when fn never succeeded)
//   - err: the last error (nil on success)
//   - attempts: full trace, one entry per model tried
func (f *FallbackExecutor) Execute(
	ctx context.Context,
	primary resolver.ModelInfo,
	fn AttemptFunc,
) (resolver.ModelInfo, int, []AttemptOutcome, error) {
	return f.execute(ctx, f.buildChain(ctx, primary), fn)
}

// ExecuteWithProviderHint is Execute with a route-hint provider preference
// so candidates whose Provider matches the hint are attempted first, relative
// order otherwise preserved. The hint only reorders already-resolved
// candidates — it never adds providers, and every candidate still passes the
// caller's per-attempt gate (region/access decisions stay untouched: a hinted
// candidate the gate denies is a terminal PolicyError refusal, never routed
// around).
//
// A non-empty hint that matches NO candidate in the chain cannot influence
// the route. Enforce semantics require an explicit refusal in that case —
// a *PolicyError with status 400 and code route_hint_unsatisfiable is
// returned before any candidate is attempted (attempts is empty, no endpoint
// is dialed, no breaker penalty), replacing the earlier silent fall-through
// to the unchanged chain.
func (f *FallbackExecutor) ExecuteWithProviderHint(
	ctx context.Context,
	primary resolver.ModelInfo,
	providerHint string,
	fn AttemptFunc,
) (resolver.ModelInfo, int, []AttemptOutcome, error) {
	chain := f.buildChain(ctx, primary)
	if providerHint != "" {
		// Cancellation is terminal before anything else: a dead context must
		// not be misreported as a policy refusal (the per-attempt gate's
		// contract; the caller re-checks ctx inside fn exactly the same way).
		if err := ctx.Err(); err != nil {
			return resolver.ModelInfo{}, 0, nil, err
		}
		if !chainHasProvider(chain, providerHint) {
			refusal := HintRefusal(providerHint, "no allowed candidate runs on the hinted provider")
			f.log.Warn("route hint refused: no chain candidate matches the hinted provider",
				"hint", providerHint,
				"primary", primary.ModelName,
				"candidates", len(chain),
			)
			return resolver.ModelInfo{}, refusal.Status, nil, refusal
		}
		chain = preferProvider(chain, providerHint)
	}
	return f.execute(ctx, chain, fn)
}

// execute walks the prepared chain: for each model it invokes fn; the first
// success (err == nil AND status < 500) short-circuits. Non-retryable
// failures (4xx) abort the chain immediately. Retryable failures advance to
// the next model. When all models are exhausted the last failure is returned.
//
// Returns:
//   - finalInfo: the ModelInfo that produced the final outcome (success or
//     last failure)
//   - statusCode: that outcome's HTTP status (0 when fn never succeeded)
//   - err: the last error (nil on success)
//   - attempts: full trace, one entry per model tried
func (f *FallbackExecutor) execute(
	ctx context.Context,
	chain []resolver.ModelInfo,
	fn AttemptFunc,
) (resolver.ModelInfo, int, []AttemptOutcome, error) {
	// Request identity is read once per request and stamped unchanged on
	// every attempt entry: one client request keeps one identity across all
	// hops, whatever provider serves them.
	identity := retry.RequestIdentityFrom(ctx)
	attempts := make([]AttemptOutcome, 0, len(chain))
	// lastAttemptErr keeps the original error of the most recent failing
	// attempt so the exhaustion tail can wrap it without flattening the
	// typed structure (N07-P01-T05: errors.As on the surfaced error must
	// still find e.g. retry.RequestNotSentError).
	var lastAttemptErr error

	for i, info := range chain {
		start := time.Now()
		code, err := fn(ctx, info)
		outcome := AttemptOutcome{
			ModelName:   info.ModelName,
			UpstreamURL: info.UpstreamURL,
			Provider:    info.Provider,
			StatusCode:  code,
			Duration:    time.Since(start),
			Success:     err == nil && code < 500,
			Outcome:     retry.Classify(code, err).String(),
			RequestID:   identity.RequestID,
			Attempt:     i + 1,
		}
		if err != nil {
			outcome.Error = err.Error()
			lastAttemptErr = err
		}
		attempts = append(attempts, outcome)

		if outcome.Success {
			return info, code, attempts, nil
		}
		// RT-03: a policy outcome (denied candidate / unavailable policy
		// check) is chain-terminal. It is not a transport failure the next
		// model could satisfy — a mandatory denied/unavailable decision ends
		// the request here, and the caller translates the envelope.
		var policyErr *PolicyError
		if errors.As(err, &policyErr) {
			f.log.Warn("fallback: policy outcome is terminal, aborting chain",
				"candidate", info.ModelName,
				"status", policyErr.Status,
			)
			return info, policyErr.Status, attempts, err
		}
		if !f.retryable(code, err) {
			// A definitive HTTP answer (or a success-shaped no-error outcome
			// the classifier declines) is terminal on the ordinary policy
			// alone — no repetition question arises, and the error surfaces
			// unchanged.
			if code != 0 || err == nil {
				return info, code, attempts, err
			}
			// Repetition permission: beside proven non-execution (already
			// classifier-retryable above), only a verified provider/action
			// deduplication contract may advance the chain past an attempt
			// that produced no HTTP answer. A definitive HTTP answer is never
			// overridden by the contract, and a policy denial never reaches
			// this point (terminal above).
			safety := retry.Classify(code, err)
			if !retry.MayRepeat(safety, f.proof) {
				// The refusal to repeat is final and must be explainable to
				// UI/API layers: the typed error carries the stable
				// machine-readable reason, while errors.Is/errors.As keep the
				// original cause of the suppressed attempt reachable.
				return info, code, attempts, &retry.SuppressedError{
					Model:   info.ModelName,
					Outcome: safety,
					Err:     err,
				}
			}
			f.log.Warn("fallback: verified deduplication contract permits advancing past silent attempt",
				"failed_model", info.ModelName,
				"outcome", retry.Classify(code, err).String(),
			)
		}
		// A dead request context (client gone, gateway timeout) is not a
		// "retryable failure" — the chain aborts here, and the log must say
		// so instead of claiming the next model is about to be tried.
		if ctx.Err() != nil {
			f.log.Info("fallback: aborted — request context done",
				"failed_model", info.ModelName,
				"status", code,
				"error", ctx.Err(),
			)
			return info, code, attempts, ctx.Err()
		}
		f.log.Warn("fallback: retryable failure, advancing to next model",
			"failed_model", info.ModelName,
			"status", code,
			"error", err,
		)
	}

	if len(attempts) == 0 {
		return resolver.ModelInfo{}, 0, attempts, nil
	}
	last := attempts[len(attempts)-1]
	var lastErr error
	if last.Error != "" {
		lastErr = &fallbackError{model: last.ModelName, msg: last.Error, cause: lastAttemptErr}
	}
	return chain[len(chain)-1], last.StatusCode, attempts, lastErr
}

// buildChain assembles the ordered list of models to try: primary first, then
// each failover_models entry resolved via the resolver. The chain is bounded
// by maxHops. Unknown failover models (resolver falls back to default) are
// still included — the resolver's fallback model is a sane "last resort".
// They are never silently dropped here: gating unknown resolved candidates is
// the caller's per-attempt gate, not the chain builder's.
//
// A failover entry that resolves to a candidate the chain already contains
// (a cycle, or two names sharing one canonical model) is skipped: repeating
// an already-failed candidate cannot produce a different outcome and would
// only burn hops. maxHops remains the hard bound.
func (f *FallbackExecutor) buildChain(ctx context.Context, primary resolver.ModelInfo) []resolver.ModelInfo {
	chain := []resolver.ModelInfo{primary}
	if len(primary.FailoverModels) == 0 {
		return chain
	}
	seen := map[string]bool{primary.ModelName: true}
	for _, name := range primary.FailoverModels {
		if len(chain) >= f.maxHops {
			break
		}
		var info resolver.ModelInfo
		if f.resolv == nil {
			// Without a resolver we can only synthesise a name-only ModelInfo.
			info = resolver.ModelInfo{ModelName: name}
		} else {
			info = f.resolv.Resolve(ctx, name)
		}
		if info.ModelName != "" && seen[info.ModelName] {
			continue
		}
		if info.ModelName != "" {
			seen[info.ModelName] = true
		}
		chain = append(chain, info)
	}
	return chain
}

// fallbackError is a sentinel error type carrying the model that produced it,
// for downstream observability.
type fallbackError struct {
	model string
	msg   string
	// cause preserves the original attempt error (N07-P01-T05): msg is the
	// flattened string, and downstream renders that branch on typed errors
	// (e.g. the gateway's request-not-sent 400) must still unwrap to it.
	cause error
}

func (e *fallbackError) Error() string { return e.model + ": " + e.msg }

func (e *fallbackError) Unwrap() error { return e.cause }

// preferProvider reorders chain so candidates whose Provider equals hint are
// attempted first, preserving the relative order inside both groups. An empty
// hint or a hint no candidate matches returns the chain unchanged (the
// executor refuses such hints before reordering; this no-match branch stays
// defensive for direct uses).
func preferProvider(chain []resolver.ModelInfo, hint string) []resolver.ModelInfo {
	if hint == "" {
		return chain
	}
	preferred := make([]resolver.ModelInfo, 0, len(chain))
	rest := make([]resolver.ModelInfo, 0, len(chain))
	for _, info := range chain {
		if info.Provider == hint {
			preferred = append(preferred, info)
		} else {
			rest = append(rest, info)
		}
	}
	if len(preferred) == 0 || len(rest) == 0 {
		return chain
	}
	return append(preferred, rest...)
}

// chainHasProvider reports whether any candidate resolves to the hinted
// provider. Matching is exact (the same comparison preferProvider uses):
// a case-different or otherwise non-identical name is an unmatched hint
// and refuses, rather than being silently normalized.
func chainHasProvider(chain []resolver.ModelInfo, hint string) bool {
	for _, info := range chain {
		if info.Provider == hint {
			return true
		}
	}
	return false
}

// Callers and dashboards can distinguish an unsatisfiable hint from an
// upstream failure; ErrType follows the OpenAI-style envelope convention.
const (
	// HintUnsatisfiableCode marks an enforce-mode route hint that cannot
	// influence the route (no candidate on the hinted provider, or a
	// single-candidate pipeline running a different provider).
	HintUnsatisfiableCode = "route_hint_unsatisfiable"
	// HintUnsatisfiableErrType is the envelope error type for the refusal.
	HintUnsatisfiableErrType = "invalid_request_error"
	// hintEchoLimit bounds the hint text echoed back in refusal messages —
	// policy values are org-controlled, but the envelope must not reflect
	// unbounded input.
	hintEchoLimit = 64
)

// HintRefusal builds the terminal PolicyError for an enforce-mode route hint
// This is never a silent misroute or a partial outcome. reason names the
// concrete cause (unknown provider, single-candidate pipeline, ...) and is
// carried verbatim in the message.
func HintRefusal(hint, reason string) *PolicyError {
	return &PolicyError{
		Status:  http.StatusBadRequest,
		ErrType: HintUnsatisfiableErrType,
		ErrCode: HintUnsatisfiableCode,
		Message: fmt.Sprintf("route_hint %s cannot be satisfied: %s", hintEcho(hint), reason),
	}
}

// hintEcho quotes hint for an error message, truncating overlong values.
func hintEcho(hint string) string {
	if len(hint) > hintEchoLimit {
		return strconv.Quote(hint[:hintEchoLimit]) + "…(truncated)"
	}
	return strconv.Quote(hint)
}
