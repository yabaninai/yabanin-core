package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// STREAM-01: bounds of the stream-cache capture (pkg/cache RecordingWriter).
// The recorder sits in the hot response path; a long-lived SSE stream must
// never be retained in gateway memory without a ceiling. 1 MiB / 4096 frames
// comfortably cover the replayable chat completions the cache exists for;
// a larger stream latches an overflow and is simply not cached (the client
// bytes are unaffected either way).
const (
	streamCacheRecordMaxBytes  = 1 << 20
	streamCacheRecordMaxFrames = 4096
)

// serveStream handles streaming chat completions with provider-aware
// translation (P3.13a), fallback chains (P3.13b), and retry logic (P3.13c).
//
// The supplied body is forwarded to the upstream with only the "model" field
// rewritten per fallback hop — every other client-provided field (temperature,
// tools, response_format, ...) is preserved. In raw-body mode (P3.14) the
// body is forwarded completely as-is: model rewriting is skipped, schema
// translation is bypassed (caller signals the body is already in the
// upstream's native format), and the fallback chain is disabled because a
// provider-specific body cannot be safely re-targeted at a different provider.
//
// Retry and fallback operate ONLY at the connection-setup phase. Once a 200
// response is received from upstream we commit to that stream and drain it
// directly to the client via the provider's StreamHandler — no buffering.
// Mid-stream errors emit a terminal SSE error event + [DONE] to the client
// (partial data has already been flushed so we cannot retry transparently).
//
// boundedBuffer accumulates at most limit bytes then stops copying (the
// stream keeps flowing untouched). SSE capture for the explorer.
// firstAt records when the first upstream byte arrived — the time-to-first-
// token sample (observability parity: Bifrost first-token latency).
type boundedBuffer struct {
	buf     [16 * 1024]byte
	n       int
	full    bool
	firstAt time.Time
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.firstAt.IsZero() && len(p) > 0 {
		b.firstAt = time.Now()
	}
	if b.full {
		return len(p), nil
	}
	space := len(b.buf) - b.n
	if len(p) > space {
		copy(b.buf[b.n:], p[:space])
		b.n = len(b.buf)
		b.full = true
		return len(p), nil
	}
	copy(b.buf[b.n:], p)
	b.n += len(p)
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	if b.n == 0 {
		return ""
	}
	return string(b.buf[:b.n])
}

// firstTokenMs returns the milliseconds from start to the first upstream
// byte, and whether a first byte was observed at all.
func (b *boundedBuffer) firstTokenMs(start time.Time) (int64, bool) {
	if b.firstAt.IsZero() {
		return 0, false
	}
	d := b.firstAt.Sub(start)
	if d < 0 {
		d = 0
	}
	return d.Milliseconds(), true
}

// streamRun carries the per-request state across the serveStream phases
// (connection setup, drain, finalization). Grouping it in one struct lets
// each phase stay a small function without a positional parameter list
// pre-split implementation.
type streamRun struct {
	gw  *gateway
	w   http.ResponseWriter
	ctx context.Context // request context; streamCtx derives from it
	l   *slog.Logger

	// body is the guarded client body (post egress-guards) — the cache key
	// payload and the per-hop model-rewrite source.
	body        []byte
	rawBodyMode bool

	sessionID string
	orgID     string
	teamID    string
	taskID    string
	reqID     string
	agentID   string

	dec                  routingDecision
	classifierClass      string
	classifierConfidence float64
	tierUsed             string
	classifierSource     string

	cacheDisabled bool

	start time.Time
	gate  *reservationGate
	// gateID is the RT-03 trusted identity captured once — every stream hop
	// is gated under the same identity.
	gateID candidateIdentity
	// requestedModel is RT-03's requested model for the per-attempt gate:
	// dec.From (the client's original request) or the candidate name when
	// direct callers pass an empty decision.
	requestedModel string

	// streamCtx gets its own cancel so the idle watchdog (armed on the
	// upstream body during drain) can abort a stalled upstream without
	// touching the parent request context; the parent deadline (the /v1/
	// stream ceiling) still applies.
	streamCtx    context.Context
	cancelStream context.CancelFunc

	// rec captures SSE chunks for the semantic cache (nil when recording
	// is off).
	rec *cache.RecordingWriter

	// streamPolicy is the OP-4/OP-8 streaming-policy seam (nil when the
	// policy runtime is off or no stream_prefix/stream_final policy is
	// attached): the PrefixGate hold-back, the chunk FrameProcessor and the
	// FinalAggregate live there (stream_policy.go).
	streamPolicy *sseStreamPolicyWriter

	// sseTee is the bounded capture of what the model streamed back (the
	// explorer's response sample); streamIdle is the idle watchdog (nil
	// when disabled).
	sseTee     *boundedBuffer
	streamIdle *idleReader

	// history is the FIX-20 processed-response capture (nil in hand-assembled
	// test chains that skip wrapWriters): it records the client-bound frames
	// after every mutating layer and freezes the envelope JSON at the finish
	// sites. Same-goroutine discipline as clientSawDone: written during
	// drain, read by the finishers.
	history *responseHistoryCapture

	// clientSawDone records whether the terminal "data: [DONE]" frame was
	// already delivered to the client during the drain (N03-P01): a late
	// drain failure after the terminator must not emit a second terminal
	// event. Set by the terminal watch installed in drain and read by the
	// finishers on the same goroutine.
	clientSawDone bool

	// connection-phase results (connect).
	finalInfo        resolver.ModelInfo
	lastCode         int
	attempts         []router.AttemptOutcome
	lastErr          error
	streamResp       *http.Response
	sentBody         []byte // the body actually sent upstream (final chain hop)
	clientWantsUsage bool
	totalRetries     int
	// number of attempts, every candidate's circuit is open (finishConnect
	// failure then mirrors the admit-time 503 frame).
	openHops atomic.Int32
	// usedOrgKey reports whether the WINNING hop authenticated with an org
	// credential (BYOK); set by dialAttempt on the hop that won.
	usedOrgKey bool
	// ("" when the winning hop used no org credential).
	orgCredRef string
}

//nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
//nolint:gocritic // the trailing classifier parameters are an established positional call style shared by chat.go and the test suite
func (gw *gateway) serveStream(w http.ResponseWriter, ctx context.Context, info resolver.ModelInfo, body []byte, rawBodyMode bool, sessionID string, orgID string, teamID string, taskID string, reqID string, l *slog.Logger, dec routingDecision, classifierClass string, classifierConfidence float64, tierUsed string, classifierSource string, agentID string, cacheDisabled bool) {
	// clientWantsUsage (RM-03): whether the CLIENT asked for
	// stream_options.include_usage. dialAttempt clears it after
	// ensureStreamUsage injected the flag on the winning hop — then the
	// trailing usage-only chunk is suppressed client-side (usage still
	// parsed). Raw-body mode never rewrites the body, so it stays true
	// there.
	r := &streamRun{
		gw:                   gw,
		w:                    w,
		ctx:                  ctx,
		l:                    l,
		body:                 body,
		rawBodyMode:          rawBodyMode,
		sessionID:            sessionID,
		orgID:                orgID,
		teamID:               teamID,
		taskID:               taskID,
		reqID:                reqID,
		agentID:              agentID,
		dec:                  dec,
		classifierClass:      classifierClass,
		classifierConfidence: classifierConfidence,
		tierUsed:             tierUsed,
		classifierSource:     classifierSource,
		cacheDisabled:        cacheDisabled,
		clientWantsUsage:     true,
	}

	// The stream gets its own cancel so the idle watchdog (armed on the
	// upstream body during drain) can abort a stalled upstream without
	// touching the parent request context; the parent deadline (the /v1/
	// stream ceiling) still applies.
	//
	// OP-4/OP-8: the streaming policy hooks (stream_prefix buffer gate →
	// per-chunk FrameProcessor → stream_final aggregate, pkg/pipeline/
	// streaming) ride the writer chain built in wrapWriters; the per-stream
	// state lives in r.streamPolicy. With the runtime off, no org, or no
	// attached stream policy, the seam is not built and the relay is
	// bit-for-bit the pre-OP-8 passthrough.
	r.streamCtx, r.cancelStream = context.WithCancel(ctx)
	defer r.cancelStream()

	if _, ok := r.admit(info); !ok {
		return
	}

	// NEXT-18c: the reservation gate rides the request context (§5.1) —
	// every end-of-request path below settles the local escrow and stamps
	// the reserve tuples + termination on its analytics event.
	r.start = time.Now()
	r.gate = reservationGateFrom(ctx)
	r.gateID = candidateIdentity{OrgID: orgID, TeamID: teamID, APIKeyID: eventKeyID(ctx)}

	r.connect(info)
	if r.lastErr != nil {
		r.finishConnectFailure()
		return
	}

	// Connection succeeded — commit to draining this stream.
	defer r.streamResp.Body.Close() // best-effort close during fallback cleanup; body already drained

	// V10: shadow-mode for streaming primaries. The upstream answered 200, so
	// a candidate is served; fire a detached shadow call to the shadow target
	// now (before the drain) so its latency is measured concurrently with real
	// load. RT-05: the served model is the WINNING hop's model — when a
	// fallback won, attributing the mirror to the primary would be the same
	// dishonest identity a fallback cache write under the primary would be.
	// The shadow is a separate non-streaming request (buildShadowJob
	// forces stream:false) in its own goroutine — it cannot affect the client's
	// SSE bytes (mandatory passthrough).
	gw.maybeShadowStream(ctx, r.body, r.finalInfo.ModelName, orgID, teamID, sessionID, reqID) //nolint:contextcheck // fireShadow -> shadow.Run owns its own context

	usage, drainErr := r.drain(r.wrapWriters())

	// Time-to-first-token (observability parity): the tee saw the first
	// upstream byte, so TTFT is final even when the drain later errors.
	ttftMs, hasTTFT := r.sseTee.firstTokenMs(r.start)
	if hasTTFT {
		metrics.UpstreamFirstTokenSeconds.WithLabelValues(r.finalInfo.Provider, r.finalInfo.ModelName).
			Observe(float64(ttftMs) / 1000)
	}

	// OP-4/OP-8: end-of-stream policy boundary. The hold-back prefix is
	// released (or the stream aborted — a policy deny intercepted before any
	// buffered byte reached the client), the FrameProcessor tail flushes, and
	// the stream_final policies audit the aggregate of the frames the client
	// received. A post-issuance deny degrades to a flag on the event.
	if r.streamPolicy != nil {
		r.streamPolicy.finishStream()
		if r.streamPolicy.policyAborted() {
			r.finishStreamPolicyDenied(usage, ttftMs, hasTTFT)
			return
		}
		if drainErr == nil {
			r.streamPolicy.runFinalCheck(r.streamCtx)
		}
	}

	// P4: after a successful stream the captured chunks go to the cache.
	// H3 (saw-terminal contract): the drainErr gate is what refuses
	// truncated streams — a handler that saw EOF without its provider
	// terminal event returns an error wrapping provider.ErrStreamIncomplete,
	// so the truncated prefix never reaches writeStreamCacheAsync and the
	// run is accounted by finishDrainFailure (request.failed), not as a
	// completed request.
	if r.rec != nil && drainErr == nil {
		r.writeStreamCacheAsync(usage)
	}

	// Emit upstream metrics with the actual usage from the drained stream (P3.19).
	ext := provider.ComputeCost(usage, r.finalInfo.Provider, r.finalInfo.ModelName)
	gw.emitUpstreamMetrics(r.finalInfo.Provider, r.finalInfo.ModelName, http.StatusOK, time.Since(r.start), usage, ext.EstimatedCostUSD)

	// From here we've already flushed chunks to the client; we can only
	// report the outcome to observability.
	if drainErr != nil {
		r.finishDrainFailure(usage, drainErr, ttftMs, hasTTFT)
		return
	}

	r.finishSuccess(usage, ext, ttftMs, hasTTFT)
}

// dialAttempt is the AttemptFunc consumed by the fallback executor. It
// establishes the upstream connection only — it does NOT drain the body.
// Retry (P3.13c) wraps just this connection-setup phase; transient errors
// (transport/429/5xx) are retried against the same model before the chain
// advances to the next failover.
func (r *streamRun) dialAttempt(ctx context.Context, mi resolver.ModelInfo) (statusCode int, err error) {
	// Cancellation is terminal before anything else: gating with a dead
	// context would misreport the cancel as a policy-store outage.
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// RT-03: every actual provider attempt re-passes the shared gate. A
	// policy denial/unavailable is chain-terminal (router.PolicyError) —
	// it never starts the next, forbidden stream hop.
	mi, pol := r.gw.gateAttemptCandidate(ctx, r.gateID, r.requestedModel, mi)
	if pol != nil {
		return pol.Status, pol
	}
	url := r.gw.upstreamURL(mi)
	// breaker (no-op in global scope — the admit checkBreaker gate rules).
	// A tripped circuit fails this hop retryably so the chain can advance to
	// a candidate on another endpoint.
	if berr := r.gw.allowEndpoint(url); berr != nil {
		r.openHops.Add(1)
		return http.StatusServiceUnavailable, berr
	}
	// W-BYOK-CORE (one-block consistency edit to the W-PROV-merged chain,
	// coordinated per the merge note): the credential priority order — org
	// credential (BYOK) → this candidate's per-model upstream_api_key →
	// global default — lives in resolveUpstreamKey, shared with the JSON
	// path. An infrastructure failure while the org plausibly holds a
	// credential for this endpoint is fail-closed (never route the GLOBAL
	// key to an org-registered endpoint).
	key, use, kerr := r.gw.resolveUpstreamKey(ctx, r.orgID, mi)
	if kerr != nil {
		return 0, kerr
	}

	// Forward the original body. Per-hop model rewriting only in normal
	// mode — raw-body mode treats the body as opaque native-format bytes.
	reqBody := r.body
	hopWantsUsage := true
	if !r.rawBodyMode {
		// OverrideModelRaw (not the legacy map round-trip): extension values
		// must reach the upstream with exact JSON literals — a float64
		// re-encode corrupts integers beyond 2^53 (N07-P01-T04).
		reqBody = upstream.OverrideModelRaw(r.body, mi.ModelName)
		// Reasoning-effort injection (v15 E1, opt-in): per-model body,
		// after the cache lookup, so the cache key is unchanged.
		reqBody = r.gw.maybeInjectEffort(reqBody, mi, classifier.Class(r.classifierClass))
		// RM-03: ask OpenAI-compatible upstreams for stream usage
		// (tokens/cost/budgets are zero otherwise). Computed once per
		// hop, outside the retry closure — re-running it on a retried
		// attempt would mistake our own injection for a client request.
		reqBody, hopWantsUsage = ensureStreamUsage(reqBody, mi.Provider, r.gw.streamUsageProviders)
	}

	r.sentBody = reqBody
	client, perr := r.gw.pool.Get(url, mi.Provider)
	if perr != nil {
		// Pool initialisation failure (unknown provider / SSRF-allowlist
		// violation) is a configuration error, not transient: no retries —
		return http.StatusBadGateway, fmt.Errorf("upstream client for %s: %w", mi.Provider, perr)
	}

	attemptNum := 0 // tracks retries within this model's chain hop
	res := retry.Do(ctx, r.gw.retryPolicy, func(ctx context.Context) retry.Result {
		attemptNum++
		resp, serr := client.Stream(ctx, reqBody, key) //nolint:bodyclose // body ownership transfers to the fallback chain, drained by the caller below
		if serr != nil {
			if capErr, ok := provider.Refusal(serr); ok {
				// Adapter capability refusal: the feature check failed
				// before any byte left the gateway. Client-shaped 400 on a
				// terminal policy carrier — no retry, no failover to
				// another model (no silent downgrade), no breaker or
				// credential penalty, no upstream accounting.
				return retry.Result{
					StatusCode: http.StatusBadRequest,
					Err:        capabilityPolicy(capErr),
					Safety:     retry.OutcomeNotExecuted,
				}
			}
			// Connection-phase failure. Retry policy applies (transport /
			// 429 / 5xx per DefaultClassifier). streamResp stays nil so a
			// later fallback model gets a clean slate. The failed attempt's
			// headers (nil for refusals / not-sent) ride along so Retry-After
			// hints feed the retry scheduler.
			result := retry.Result{StatusCode: extractUpstreamStatus(serr), Err: serr, Headers: upstreamFailureHeaders(serr)}
			switch {
			case result.StatusCode > 0 || retry.DefinitelyNotSent(serr):
				result.Safety = retry.OutcomeNotExecuted
			case provider.IsUnsupportedFeature(serr):
				// N07-P05-T02: deterministic pre-flight capability
				// rejection — keep the typed error unwrapped so the terminal
				// handler answers an explicit 400 unsupported_feature SSE
				// frame instead of the opaque upstream_outcome_unknown 502.
			case retry.IsRequestNotSent(serr):
				// Translate-layer refusal (N07-P01-T05): typed proof the
				// request never left this process. Safety stays Unknown —
				// MayRepeat forbids repeating Unknown attempts (a
				// deterministic refusal must not be retried) — while
				// retry.Classify still reports NotExecuted to the fallback
				// chain. The error stays unwrapped so the terminal render
				// can errors.As the typed proof and surface the exact reason.
			default:
				result.Err = unknownOutcomeError(serr)
			}
			return result
		}
		// Got a 200 response — return success. The caller drains resp.Body
		// after the fallback chain returns. No retry from here: a partial
		// stream cannot be transparently restarted.
		r.streamResp = resp
		return retry.Result{StatusCode: http.StatusOK}
	})

	// Capability refusals ride the terminal policy carrier: nothing was
	// sent, the chain stops here, and no upstream accounting applies —
	// skip the metrics/quarantine/breaker path below entirely.
	var capPolicyErr *router.PolicyError
	if res.Err != nil && errors.As(res.Err, &capPolicyErr) {
		return res.StatusCode, res.Err
	}

	// Emit metrics for the attempt (connection phase only — no usage yet).
	r.gw.emitUpstreamMetrics(mi.Provider, mi.ModelName, res.StatusCode, time.Since(r.start), provider.Usage{}, 0)

	// Emit retry_total when retries occurred.
	if attemptNum > 1 {
		statusLabel := strconv.Itoa(res.StatusCode)
		if res.Err != nil && res.StatusCode == 0 {
			statusLabel = "0"
		}
		for i := 1; i < attemptNum; i++ {
			metrics.RetryTotal.WithLabelValues(strconv.Itoa(i), statusLabel).Inc()
		}
	}
	r.totalRetries += attemptNum - 1

	// 401/429 quarantines the CREDENTIAL that authenticated this hop (never
	// the endpoint breaker). Bookkeeping only; the hop's already-resolved
	// plaintext is unaffected.
	r.gw.recordOrgCredOutcome(ctx, r.orgID, mi.Provider, use, res.StatusCode)

	if res.Err != nil {
		// scope; no-op in global scope). A translate-layer refusal
		// (N07-P01-T05) never contacted the endpoint — counting it as an
		// endpoint failure would trip the breaker on a client-side request
		// problem.
		if !retry.IsRequestNotSent(res.Err) {
			r.gw.recordEndpointFailure(url)
		}
		return res.StatusCode, res.Err
	}
	// This hop won: its usage-request state decides whether the trailing
	// usage-only chunk reaches the client (last successful hop wins).
	r.clientWantsUsage = hopWantsUsage
	r.usedOrgKey = use.used
	r.orgCredRef = use.ref()
	// is the breaker-verdict boundary here — exactly like the global scope,
	// where drain failures never touch the breaker either.
	r.gw.recordEndpointSuccess(url)
	return http.StatusOK, nil
}

// admit is the pre-connection phase: SSE response headers, the routing
// decision header, the flusher capability check, the U1 egress guards, the
// RT-03 requested-model resolution, and the circuit-breaker check. On
// rejection it has already written the error response (JSON when no SSE byte
// could be written, structured SSE error frame otherwise) and returns
// ok=false.
func (r *streamRun) admit(info resolver.ModelInfo) (flusher http.Flusher, ok bool) {
	r.w.Header().Set("Content-Type", "text/event-stream")
	r.w.Header().Set("Cache-Control", "no-cache")
	r.w.Header().Set("Connection", "keep-alive")
	r.w.Header().Set("X-Accel-Buffering", "no")
	r.w.Header().Set("Proxy-Cache", "bypass")

	// v18 R1: machine-readable routing decision. The header must be set before
	// the first SSE byte is flushed (headers are sent on first write), so it is
	// emitted together with the other response headers above.
	if r.gw.cfg.DecisionHeaderEnabled {
		r.dec.set(r.w)
	}

	flusher, ok = r.w.(http.Flusher)
	if !ok {
		reservationGateFrom(r.ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		apierrors.Write(r.w, http.StatusNotImplemented, apierrors.ErrorCodeAPI,
			"streaming not supported by server")
		return flusher, false
	}

	// U1: pre-egress guard hooks on the streaming surface. The chatCompletions
	// entry already guards the body before branching, so for that path this is
	// a deterministic no-op re-scan (a redacted body has no secrets left to
	// detect; a deny would have stopped the request before it got here). It is
	// authoritative for any caller that reaches serveStream directly — no SSE
	// byte is written until after this check passes, so a deny emits a clean
	// terminal error frame instead of a half-open stream.
	guarded, err := r.gw.applyEgressGuards(r.body)
	if err != nil {
		r.l.Warn("guard hooks denied stream request", "error", err)
		reservationGateFrom(r.ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		writeSSEError(r.w, "guard_denied", "request blocked by guard hooks: sensitive data detected")
		return flusher, false
	}
	r.body = guarded

	// RT-03: the requested model for the per-attempt gate. dec.From is the
	// client's original request in production; direct callers that pass an
	// empty decision fall back to the candidate name.
	r.requestedModel = r.dec.From
	if r.requestedModel == "" {
		r.requestedModel = info.ModelName
	}

	if err := r.gw.checkBreaker(); err != nil {
		r.l.Error("circuit breaker open, rejecting stream", "error", err)
		reservationGateFrom(r.ctx).finalizeNoEvent(budget.TerminationPolicyDenied)
		writeSSEError(r.w, apierrors.ErrorCodeServiceUnavailable, "upstream provider unavailable")
		return flusher, false
	}
	return flusher, true
}

// connect runs the fallback chain over the per-hop dialer, then emits the
// fallback metrics for streaming chain advances (same as non-streaming).
func (r *streamRun) connect(info resolver.ModelInfo) {
	// In raw-body mode the body is in a specific provider's native format.
	// Forwarding it to a different provider (the fallback chain) would
	// produce malformed requests, so the chain is collapsed to primary-only
	// and a warning is logged for visibility.
	chainInfo := info
	if r.rawBodyMode && len(info.FailoverModels) > 0 {
		r.l.Warn("raw-body mode: disabling fallback chain (body is provider-specific)",
			"model", info.ModelName,
			"failover_count", len(info.FailoverModels))
		chainInfo = info
		chainInfo.FailoverModels = nil
	}

	r.finalInfo, r.lastCode, r.attempts, r.lastErr = r.gw.executeFallback(r.streamCtx, chainInfo, r.dialAttempt)

	for i := 1; i < len(r.attempts); i++ {
		from := r.attempts[i-1].ModelName
		to := r.attempts[i].ModelName
		reason := "transport"
		if !r.attempts[i-1].Success && r.attempts[i-1].StatusCode > 0 {
			reason = strconv.Itoa(r.attempts[i-1].StatusCode)
		}
		metrics.FallbackTotal.WithLabelValues(from, to, reason).Inc()
	}
}

// finishConnectFailure reports a terminal connection-phase failure. No bytes
// have been written to the client yet, so the structured SSE error frame is
// the contract.
func (r *streamRun) finishConnectFailure() {
	// N07-P05-T02: a media-capability rejection (image part on an adapter
	// without image input, unmapped content-part type) is a CLIENT format
	// error the adapter raised before any byte left the gateway. The
	// structured SSE frame carries the adapter's exact reason with status
	// 400 — never an opaque 5xx, no breaker penalty, and no analytics event
	// (the escrow settles locally; parity with the policy-denial path).
	var unsupportedFeatureErr *provider.UnsupportedFeatureError
	if errors.As(r.lastErr, &unsupportedFeatureErr) {
		r.gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		r.l.Warn("provider adapter rejected unsupported request feature",
			"error", r.lastErr, "attempts", len(r.attempts))
		r.w.WriteHeader(http.StatusBadRequest)
		// CONTRACT §1 parity: the JSON envelope carries the stable
		// unsupported_feature code, so the SSE frame rides the same code.
		writeSSEErrorWithCode(r.w, apierrors.ErrorCodeInvalidRequest,
			apierrors.CodeUnsupportedFeature, unsupportedFeatureErr.Error())
		return
	}
	// RT-03: a terminal policy outcome from a fallback hop. The denied
	// candidate was never called, so this is not a provider failure for the
	// circuit breaker.
	var policyErr *router.PolicyError
	var unknownErr *unknownOutcomeErrorType
	// N07-P01-T05: a translate-layer refusal is a client-side request
	// problem — the request never reached any endpoint, so the exact reason
	// (which modeled field was lost, and why) renders as a terminal 400
	// invalid_request_error SSE frame, never disguised as a generic upstream
	// failure (I51).
	var notSentErr *retry.RequestNotSentError
	if errors.As(r.lastErr, &notSentErr) {
		r.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		r.w.WriteHeader(http.StatusBadRequest)
		writeSSEError(r.w, apierrors.ErrorCodeInvalidRequest, notSentErr.Error())
		return
	}
	if errors.As(r.lastErr, &unknownErr) {
		r.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status := r.lastCode
		if status < 400 {
			status = http.StatusBadGateway
		}
		r.w.WriteHeader(status)
		writeSSEError(r.w, apierrors.ErrorCodeAPI, "upstream outcome unknown; request was not retried")
		return
	}
	if errors.As(r.lastErr, &policyErr) {
		// NEXT-18c: no analytics event on this path — settle the local
		// escrow (zero spend, in-flight bound released). A client-shaped
		// policy denial (adapters rejecting a capability the model chain
		// cannot serve) reports its own status before the SSE bytes are
		// written, keeping the streaming transport at parity with the
		// JSON path instead of an implicit 200.
		r.gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		if policyErr.Status >= http.StatusBadRequest {
			r.w.WriteHeader(policyErr.Status)
		}
		writeSSEErrorWithCode(r.w, policyErr.ErrType, policyErr.ErrCode, policyErr.Message)
		return
	}

	// parity of the admit-time rejection: the same 503 SSE frame, no
	// analytics event, the escrow settles locally. No endpoint was dialed,
	// so this is not an upstream failure to record.
	if r.lastCode == http.StatusServiceUnavailable && int(r.openHops.Load()) == len(r.attempts) {
		r.gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		r.l.Error("circuit breaker open, rejecting stream (all candidate endpoints open)",
			"attempts", len(r.attempts))
		writeSSEError(r.w, apierrors.ErrorCodeServiceUnavailable, "upstream provider unavailable")
		return
	}

	// All fallback attempts failed at connection phase.
	r.gw.recordBreakerFailure()
	r.l.Error("upstream stream error (all fallback attempts exhausted)",
		"error", r.lastErr, "attempts", len(r.attempts))

	// PB1: Lineage attestation for streaming error path.
	r.gw.finishRequest(r.ctx, requestFinish{
		base: eventBase{
			EventType:       "request.failed",
			RequestID:       r.reqID,
			SessionID:       r.sessionID,
			UpstreamPayload: boundedSample(r.sentBody, upstreamCaptureLimit),
			OrgID:           r.orgID,
			TeamID:          r.teamID,
			APIKeyID:        eventKeyID(r.ctx),
			SessionKeyID:    eventSessionID(r.ctx),
			ModelRequested:  r.dec.From, // the client's original request, not the routed model
			ModelUsed:       r.finalInfo.ModelName,
			UpstreamURL:     r.gw.upstreamURL(r.finalInfo),
			StatusCode:      int64(r.lastCode),
			DurationMs:      eventpub.ComputeDurationMs(r.start),
			Method:          "POST",
			Endpoint:        endpointFrom(r.ctx, "chat.completions"),
			UsageSource:     "none",
			CostStatus:      costStatus(false, "none", false),
			Error:           fmt.Sprintf("upstream stream failed: %v", r.lastErr),
			TierUsed:        r.tierUsed,

			ClassifierClass:      r.classifierClass,
			ClassifierConfidence: r.classifierConfidence,
			ClassifierSource:     r.classifierSource,
			RoutingDecision:      r.gw.decisionJSON(r.dec.Source, r.dec),
			AttemptCount:         len(r.attempts),
			RetryCount:           r.totalRetries,
			Labels:               labelsFrom(r.ctx),
			Policy:               r.streamPolicyJSON(),
		},
		attestModel: r.finalInfo.ModelName,
		info:        r.finalInfo,
		// NEXT-18c: tuples + upstream_error termination ride the failure
		// event (§5.3 Finalize); no usage accrued on the connection phase.
		termination: budget.TerminationUpstreamErr,
	}, nil)

	_, errType, _, errMsg := r.gw.mapProviderUpstream(r.finalInfo.Provider, r.lastCode, r.lastErr)
	// RATELIMIT-FALLBACK P2: on a decision-bearing upstream rate limit,
	// surface the provider's own Retry-After hint before the SSE error
	// frames (nothing is flushed yet on the connect-phase exhaustion path,
	// so the header is still settable). Unknown hints omit it — never
	// fabricated.
	if secs := clientRetryAfterSeconds(r.lastCode, r.lastErr); secs > 0 {
		r.w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	writeSSEError(r.w, errType, errMsg)
}

// wrapWriters layers the optional response wrappers over the raw writer and
// returns the flusher of the final wrapper: P4's RecordingWriter captures SSE
// chunks for future cache writes (only when caching is enabled AND the
// stream-cache kill-switch is on — STREAM-01: the switch was previously
// consulted only after the stream finished, so killed-switch streams carried
// a full passenger copy of the response for nothing), and TOOL-02 gates
// tool-call fragments per policy. RT-07: a no-store request must not
// populate the cache either — the lookup guard in chatCompletions skips the
// serve, this guard skips the record, so a response the client forbade
// storing never lands in the shared cache.
func (r *streamRun) wrapWriters() http.Flusher {
	var flusher http.Flusher
	recordCache := r.gw.cache != nil && r.orgID != "" && !r.cacheDisabled && r.gw.cfg.CacheStreamEnabled
	if recordCache {
		// STREAM-01: the capture is bounded — an arbitrarily long upstream
		// stream must not be retained frame by frame in gateway memory.
		r.rec = cache.NewRecordingWriterCapped(r.w, streamCacheRecordMaxBytes, streamCacheRecordMaxFrames)
		r.w = r.rec
	}

	// FIX-20: the processed-response capture sits between the cache recorder
	// and the streaming-policy seam — downstream of every mutating layer
	// (tool-gate drops, stream_final rewrites) upstream of the cache record,
	// so the envelope matches what the client receives byte-for-byte. It is
	// also correct when the cache/policy/tool layers are all absent: the
	// capture then wraps the raw writer and sees the handler's own output.
	// The wrap is unconditional, so the first live flusher derivation is the
	// one below (the capture forwards Flush to the layer it wraps).
	r.history = newResponseHistoryCapture(r.w)
	r.w = r.history
	flusher, _ = r.w.(http.Flusher)

	// OP-4/OP-8: the streaming-policy seam sits between the tool gate and
	// the cache RecordingWriter — a mutation happens BEFORE the cache record
	// (RT-05: client and cache observe the same mutated bytes) and the final
	// aggregate audits the frames the tool gate passes on. nil unless the
	// policy runtime is on and a stream_prefix/stream_final policy is
	// attached: the relay then stays bit-for-bit the pre-OP-8 passthrough
	// (no writer, no prefix hold, no TTFB budget).
	if pw := r.newStreamPolicyWriter(); pw != nil {
		r.streamPolicy = pw
		r.w = pw
		flusher, _ = r.w.(http.Flusher)
	}

	// TOOL-02: SSE-surface tool-call gating. Wraps the (possibly recording)
	// writer with a frame filter: a name-bearing first fragment of a call
	// decides per policy for that call index; denied fragments never reach
	// the client. Orgs without deny policies pay one cached bool lookup.
	if r.gw.toolPolicies != nil {
		r.w = newSSEToolGateWriter(r.ctx, r.w, r.gw.toolPolicies, r.orgID, r.agentID, r.gw.toolPolicies.HasDenyPolicies(r.ctx, r.orgID))
		flusher, _ = r.w.(http.Flusher)
	}
	return flusher
}

// streamIdentityRequest carries the stream stage's trusted identity headers
// for policyMetaWithTeam: serveStream receives extracted identities (there
// is no *http.Request at this depth), and r.teamID / eventKeyID(r.ctx) hold
// the same auth-resolved values the middleware set on X-Team-Id /
// X-API-Key-Id (chat.go passes the resolved team; the key principal rides
// the context). The shim keeps the live stream stage on the exact stamping
// path of the JSON-path call sites — one stamping rule, no drift.
func streamIdentityRequest(r *streamRun) *http.Request {
	hdr := http.Header{}
	hdr.Set("X-Team-Id", r.teamID)
	hdr.Set("X-API-Key-Id", eventKeyID(r.ctx))
	return &http.Request{Header: hdr}
}

// newStreamPolicyWriter builds the streaming-policy seam for one request
// (stream_policy.go): the PrefixGate only when a stream_prefix policy is
// attached (the hold-back is the only TTFB regression and must not be paid
// otherwise), the FinalAggregate only when a stream_final policy is attached.
func (r *streamRun) newStreamPolicyWriter() *sseStreamPolicyWriter {
	rt := r.gw.policyRuntime
	if rt == nil || r.orgID == "" {
		return nil
	}
	meta := policyMetaWithTeam(streamIdentityRequest(r), r.orgID, r.finalInfo.ModelName, r.finalInfo.Provider)
	prefixQ := policyQuery{endpoint: "chat", hook: pipeline.HookStreamPrefix, model: r.finalInfo.ModelName, keyLabels: principalKeyLabels(r.ctx)}
	finalQ := prefixQ
	finalQ.hook = pipeline.HookStreamFinal

	prefixPlans := rt.streamPlans(r.ctx, r.orgID, prefixQ)
	finalPlans := rt.streamPlans(r.ctx, r.orgID, finalQ)
	if len(prefixPlans) == 0 && len(finalPlans) == 0 {
		return nil
	}

	state := &streamPolicyState{}
	pw := &sseStreamPolicyWriter{
		w:        r.w,
		ctx:      r.streamCtx,
		cancel:   r.cancelStream,
		state:    state,
		meta:     meta,
		endpoint: "chat",
	}
	if len(prefixPlans) > 0 {
		tokens, delay, err := streamPrefixParams(prefixPlans)
		if err != nil {
			r.l.Warn("stream prefix policy params malformed; using buffer defaults", "error", err)
		}
		pw.gate = streaming.NewPrefixGate(streaming.PrefixConfig{
			MaxTokens: tokens,
			MaxDelay:  delay,
			Runner:    &streamPolicyRunner{rt: rt, orgID: r.orgID, q: prefixQ, state: state},
			Meta:      meta,
			Endpoint:  "chat",
		})
	}
	if len(finalPlans) > 0 {
		pw.agg = streaming.NewFinalAggregate()
		pw.finalRunner = &streamPolicyRunner{rt: rt, orgID: r.orgID, q: finalQ, state: state, final: true}
	}
	return pw
}

// streamPolicyJSON is the Event.Policy payload of the streaming stages
// ("" when the seam is absent — the wire field is omitted).
func (r *streamRun) streamPolicyJSON() string {
	if r.streamPolicy == nil {
		return ""
	}
	return r.streamPolicy.payloadJSON()
}

// finishStreamPolicyDenied finalizes a stream the prefix policies aborted:
// the client holds the AbortFrame termination, the upstream read was
// canceled, the consumed prefix bills (G3 parity), and the request.failed
// event carries termination=policy_denied plus the decision record — the
// same contract shape as the JSON-path denial. The upstream response stays
// OFF the event: denied content must not enter the log stream
// (publishPolicyDenial contract).
func (r *streamRun) finishStreamPolicyDenied(usage provider.Usage, ttftMs int64, hasTTFT bool) {
	r.l.Warn("stream blocked by policy",
		"org_id", r.orgID, "model", r.finalInfo.ModelName, "mode", string(r.gw.policyRuntime.mode))
	r.gw.accountUsage(r.ctx, r.w, usageRecord{
		orgID:         r.orgID,
		taskID:        r.taskID,
		sessionID:     r.sessionID,
		affinityModel: r.finalInfo.ModelName,
		usage:         usage,
	})

	ext := provider.ComputeCost(usage, r.finalInfo.Provider, r.finalInfo.ModelName)
	// The deny intercept returns before the shared emit below — emit here so
	// the upstream metrics keep their usage-bearing sample (drain-failure
	// parity).
	r.gw.emitUpstreamMetrics(r.finalInfo.Provider, r.finalInfo.ModelName, http.StatusOK, time.Since(r.start), usage, ext.EstimatedCostUSD)
	// N03-P06-T09: the denial bill below is the cache-discounted ComputeCost
	// quote, so the event carries the same provider-reported cache columns
	// the bill consumed (drain-failure/success parity and the invariant
	// documented at completions_endpoint.go:295–299).
	deniedBase := eventBase{
		EventType:           "request.failed",
		RequestID:           r.reqID,
		SessionID:           r.sessionID,
		UpstreamPayload:     boundedSample(r.sentBody, upstreamCaptureLimit),
		OrgID:               r.orgID,
		TeamID:              r.teamID,
		APIKeyID:            eventKeyID(r.ctx),
		SessionKeyID:        eventSessionID(r.ctx),
		ModelRequested:      r.dec.From, // the client's original request, not the routed model
		ModelUsed:           r.finalInfo.ModelName,
		UpstreamURL:         r.gw.upstreamURL(r.finalInfo),
		StatusCode:          http.StatusOK, // the stream was live; the denial is in-band
		DurationMs:          eventpub.ComputeDurationMs(r.start),
		TokensIn:            usage.PromptTokens,
		TokensOut:           usage.CompletionTokens,
		CacheReadTokens:     usage.CacheReadTokens,
		CacheCreationTokens: usage.CacheCreationTokens,
		EstimatedCostUSD:    ext.EstimatedCostUSD,
		Endpoint:            endpointFrom(r.ctx, "chat.completions"),
		UsageSource:         usageSourceOrNone(usage.Source),
		CostStatus:          costStatus(false, usage.Source, ext.PriceKnown),
		Method:              "POST",
		Error:               "stream blocked by policy: " + r.streamPolicy.abortMessage(),
		TierUsed:            r.tierUsed,
		ClassifierClass:     r.classifierClass,

		ClassifierConfidence: r.classifierConfidence,
		ClassifierSource:     r.classifierSource,
		RoutingDecision:      r.gw.decisionJSON(r.dec.Source, r.dec),
		AttemptCount:         len(r.attempts),
		RetryCount:           r.totalRetries,
		Labels:               labelsFrom(r.ctx),
		Policy:               r.streamPolicyJSON(),
	}
	if hasTTFT {
		deniedBase.FirstTokenMs = ttftMs
	}
	r.gw.finishRequest(r.ctx, requestFinish{
		base:        deniedBase,
		info:        r.finalInfo,
		resp:        r.streamResp,
		termination: budget.TerminationPolicyDenied,
	}, nil)
}

// drain pipes the committed upstream stream to the client through the
// the raw body first: silence for gw.streamIdleTimeout cancels streamCtx,
// which aborts the upstream read (the upstream request was made with
// streamCtx) and ends the drain. Zero disables the watchdog (manually
// assembled test gateways). The bounded sseTee capture rides the same pipe.
func (r *streamRun) drain(flusher http.Flusher) (usage provider.Usage, drainErr error) {
	var sseTee boundedBuffer
	var streamIdle *idleReader
	if r.streamResp != nil && r.streamResp.Body != nil {
		upstreamBody := io.Reader(r.streamResp.Body)
		if r.gw.streamIdleTimeout > 0 {
			streamIdle = newIdleReader(r.streamResp.Body, r.gw.streamIdleTimeout, r.cancelStream)
			defer streamIdle.Stop()
			upstreamBody = streamIdle
		}
		r.streamResp.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(upstreamBody, &sseTee), r.streamResp.Body}
	}
	r.sseTee = &sseTee
	r.streamIdle = streamIdle

	// RM-03: when the gateway injected include_usage on the client's behalf
	// (clientWantsUsage == false), suppress the trailing usage-only chunk
	// from the client bytes; usage is still parsed for tokens/cost/budgets.
	// The terminal watch rides the outermost writer so every producer's
	// [DONE] (passthrough, translation, policy flush) marks the delivery.
	watch := newSSETerminalWatch(r.w)
	handler := provider.NewStreamHandlerWithOptions(r.finalInfo.Provider, r.finalInfo.ModelName,
		provider.StreamOptions{SuppressUsageOnlyChunk: !r.clientWantsUsage, RequestBytes: len(r.body)})
	usage, drainErr = handler.HandleStream(r.streamCtx, watch, flusher, r.streamResp)
	r.clientSawDone = watch.sawDone()
	return usage, drainErr
}

// streamCacheChunk mirrors the chat.completion.chunk fields the stream cache
// accumulator consumes (decode pattern: provider/stream.go streamDeltaBytes).
type streamCacheChunk struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int     `json:"index"`
		FinishReason *string `json:"finish_reason"`
		Delta        struct {
			Role             *string                  `json:"role"`
			Content          json.RawMessage          `json:"content"`
			ReasoningContent json.RawMessage          `json:"reasoning_content"`
			ToolCalls        []streamToolCallFragment `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
	Usage json.RawMessage `json:"usage"`
}

// streamToolCallFragment is one delta.tool_calls entry: the function name
// rides the first fragment of a call, the arguments JSON is split across the
// consecutive fragments that share the call's index.
type streamToolCallFragment struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// streamToolCallAcc accumulates one streamed tool call.
type streamToolCallAcc struct {
	id   string
	name string
	args strings.Builder
}

func (tc *streamToolCallAcc) merge(f streamToolCallFragment) {
	if tc.id == "" {
		tc.id = f.ID
	}
	if tc.name == "" {
		tc.name = f.Function.Name
	}
	tc.args.WriteString(f.Function.Arguments)
}

// streamCompletionAcc assembles the synthetic chat.completion document a
// cache hit replays from the recorded chat.completion.chunk frames: message
// content (and reasoning content) concatenated from the deltas, tool calls
// merged by index, the last finish_reason seen, and the usage object carried
// over from the final frame when present (OpenAI-compatible streams put
// usage only on the last chunk).
//
// FIX-20: the same accumulator powers the processed-response capture with a
// byte budget (budget > 0) — text past the budget is not accumulated and the
// capture marks itself truncated. budget == 0 (the cache path) is unlimited
// and byte-identical to the pre-FIX-20 behavior.
//
// STREAM-02: every choice aggregates independently (n>1 streams used to
// collapse to choice 0, so cached multi-choice completions replayed with
// half their answers missing). The budget stays a single shared ceiling over
// the combined bytes of ALL choices — per-choice budgets would multiply the
// retention ceiling with n.
type streamCompletionAcc struct {
	sawChunk bool
	id       string
	created  int64
	model    string
	choices  map[int]*streamChoiceAcc // keyed by choice index, insertion-agnostic
	usage    map[string]interface{}

	budget    int  // combined content+reasoning+tool-arg byte cap; 0 = unlimited
	charged   int  // bytes charged against the budget so far
	truncated bool // set when the budget refused further text
}

// streamChoiceAcc accumulates one choice's streamed deltas.
type streamChoiceAcc struct {
	role      string
	content   strings.Builder
	reasoning strings.Builder
	tools     []*streamToolCallAcc
	toolIndex map[int]*streamToolCallAcc
	finish    *string
}

// choice returns the accumulator for the given index, creating it on first
// sight (choice indices arrive interleaved in n>1 streams).
func (a *streamCompletionAcc) choice(index int) *streamChoiceAcc {
	if c, ok := a.choices[index]; ok {
		return c
	}
	if a.choices == nil {
		a.choices = make(map[int]*streamChoiceAcc)
	}
	c := &streamChoiceAcc{}
	a.choices[index] = c
	return c
}

// primary returns choice 0's accumulator, creating it when the stream never
// referenced it (the FIX-20 envelope schema is defined over the primary
// choice, exactly like the pre-STREAM-02 behavior).
func (a *streamCompletionAcc) primary() *streamChoiceAcc {
	return a.choice(0)
}

// charge reserves n bytes against the budget. It answers false when the
// budget is exhausted (and latches truncated), true when unlimited.
func (a *streamCompletionAcc) charge(n int) bool {
	if a.budget <= 0 {
		return true
	}
	if a.truncated {
		return false
	}
	if a.charged+n > a.budget {
		a.truncated = true
		return false
	}
	a.charged += n
	return true
}

// addText decodes one delta text field (JSON string or null) and appends it
// when the budget allows.
func (a *streamCompletionAcc) addText(b *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return
	}
	if !a.charge(len(s)) {
		return
	}
	b.WriteString(s)
}

func (a *streamCompletionAcc) add(ch streamCacheChunk) {
	a.sawChunk = true
	if a.id == "" {
		a.id = ch.ID
	}
	if a.created == 0 {
		a.created = ch.Created
	}
	if a.model == "" {
		a.model = ch.Model
	}
	for _, choice := range ch.Choices {
		c := a.choice(choice.Index)
		if choice.Delta.Role != nil && *choice.Delta.Role != "" && c.role == "" {
			c.role = *choice.Delta.Role
		}
		a.addText(&c.content, choice.Delta.Content)
		a.addText(&c.reasoning, choice.Delta.ReasoningContent)
		for _, frag := range choice.Delta.ToolCalls {
			if !a.charge(len(frag.Function.Arguments)) {
				continue
			}
			c.toolCall(frag.Index).merge(frag)
		}
		if choice.FinishReason != nil {
			c.finish = choice.FinishReason
		}
	}
	carryStreamUsage(&a.usage, ch.Usage)
}

// toolCall returns the accumulator for the call at the given delta index,
// creating it on first sight (fragments arrive in index order).
func (c *streamChoiceAcc) toolCall(index int) *streamToolCallAcc {
	if c.toolIndex == nil {
		c.toolIndex = make(map[int]*streamToolCallAcc)
	}
	if tc, ok := c.toolIndex[index]; ok {
		return tc
	}
	tc := &streamToolCallAcc{}
	c.toolIndex[index] = tc
	c.tools = append(c.tools, tc)
	return tc
}

// document renders the accumulated stream as a chat.completion map, nil when
// nothing replayable was streamed: without a parseable chunk, or with no
// content/reasoning/tool-call payload on ANY choice — a role-only document
// would serve cache hits as empty answers, the exact defect this path must
// not re-introduce.
//
// STREAM-02: choices render in index order so the cached document is
// deterministic regardless of frame interleaving.
func (a *streamCompletionAcc) document() map[string]interface{} {
	if !a.sawChunk {
		return nil
	}
	indices := make([]int, 0, len(a.choices))
	hasPayload := false
	for i, c := range a.choices {
		indices = append(indices, i)
		hasPayload = hasPayload || c.content.Len() > 0 || c.reasoning.Len() > 0 || len(c.tools) > 0
	}
	if !hasPayload {
		return nil
	}
	sort.Ints(indices)

	choices := make([]interface{}, 0, len(indices))
	for _, i := range indices {
		c := a.choices[i]
		message := map[string]interface{}{"role": c.role}
		if c.role == "" {
			message["role"] = "assistant"
		}
		message["content"] = c.content.String()
		if c.reasoning.Len() > 0 {
			message["reasoning_content"] = c.reasoning.String()
		}
		if len(c.tools) > 0 {
			calls := make([]interface{}, 0, len(c.tools))
			for _, tc := range c.tools {
				fn := map[string]interface{}{"arguments": tc.args.String()}
				if tc.name != "" {
					fn["name"] = tc.name
				}
				call := map[string]interface{}{"type": "function", "function": fn}
				if tc.id != "" {
					call["id"] = tc.id
				}
				calls = append(calls, call)
			}
			message["tool_calls"] = calls
		}
		choice := map[string]interface{}{"index": i, "message": message}
		if c.finish != nil {
			choice["finish_reason"] = *c.finish
		}
		choices = append(choices, choice)
	}
	doc := map[string]interface{}{
		"object":  "chat.completion",
		"choices": choices,
	}
	if a.id != "" {
		doc["id"] = a.id
	}
	if a.created != 0 {
		doc["created"] = a.created
	}
	if a.model != "" {
		doc["model"] = a.model
	}
	if a.usage != nil {
		doc["usage"] = a.usage
	}
	return doc
}

// carryStreamUsage keeps the last non-empty usage object seen on the stream.
func carryStreamUsage(dst *map[string]interface{}, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var u map[string]interface{}
	if err := json.Unmarshal(raw, &u); err != nil || len(u) == 0 {
		return
	}
	*dst = u
}

// writeStreamCacheAsync persists the recorded SSE chunks to the semantic
// cache in a detached goroutine (P4). Every chunk is decoded and accumulated
// into the synthetic non-streaming chat.completion document a cache hit
// replays — the first delta frame (role-only) must not become the whole
// cached answer. cache.stream_enabled kill-switches the path (default off).
func (r *streamRun) writeStreamCacheAsync(usage provider.Usage) {
	if !r.gw.cfg.CacheStreamEnabled {
		return
	}
	// STREAM-01: a bounded capture that overflowed is a prefix of the real
	// stream — writing it would store a truncated answer that replays as if
	// complete. The next identical request repopulates from a full stream
	// (or overflows again, and simply stays uncached).
	if r.rec.Overflowed() {
		slog.Debug("stream cache write skipped, capture overflowed",
			"max_bytes", streamCacheRecordMaxBytes, "max_frames", streamCacheRecordMaxFrames)
		return
	}
	chunks := r.rec.Chunks()
	if len(chunks) == 0 {
		return
	}
	go func() {
		// Use context.Background with timeout so the request context cancel
		// after the stream response doesn't abort the cache write mid-flight.
		cacheCtx, cacheCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cacheCancel()

		// RecordingWriter captures per-line stream writes: `data: {...}`
		// frames, empty separator lines and `data: [DONE]`. Accumulate the
		// decoded chunks (concatenating frames does not parse — that
		// silently disabled stream caching); carry the usage object over
		// from the final frame when present.
		var acc streamCompletionAcc
		for _, c := range chunks {
			frame := strings.TrimSpace(strings.TrimPrefix(c.Data, "data: "))
			if frame == "" || frame == "[DONE]" {
				continue
			}
			var ch streamCacheChunk
			if err := json.Unmarshal([]byte(frame), &ch); err != nil {
				continue
			}
			acc.add(ch)
		}
		doc := acc.document()
		if doc == nil {
			return
		}
		respJSON, err := json.Marshal(doc)
		if err != nil {
			// RT-05: an unmarshalable completion document cannot
			// carry a verifiable provenance — skip the write
			// instead of storing an unattributable entry.
			slog.Debug("stream cache write skipped, marshal failed", "error", err)
			return
		}
		// RT-05: store under the identity of the model that
		// ACTUALLY streamed the response (the winning fallback
		// hop), never under the primary — a fallback response
		// must only ever be served by a route to that same model.
		ri := cache.RouteIdentity{
			OrgID:     r.orgID,
			Model:     r.finalInfo.ModelName,
			GenParams: r.gw.effortForCandidate(r.finalInfo, classifier.Class(r.classifierClass)),
			Upstream:  r.gw.cacheUpstreamFP(r.finalInfo), // H1: bind the entry to the endpoint that generated it
		}
		_ = r.gw.cache.Write(cacheCtx, ri, r.body, respJSON, int(usage.PromptTokens), int(usage.CompletionTokens))
	}()
}

// finishDrainFailure reports a stream that ended abnormally after partial
// delivery: client notification, budget accounting for the consumed prefix,
// and the request.failed event with the actual (partial) usage.
func (r *streamRun) finishDrainFailure(usage provider.Usage, drainErr error, ttftMs int64, hasTTFT bool) {
	// N03-P06-T02: the partial usage parsed before the break is still the
	// real upstream usage, so the prompt-cache trailer reports it the same
	// way accountUsage records it below. Best-effort transparency — no-ops
	// on wrapper writers; absent when no provider usage was parsed.
	setPromptCacheTrailer(r.w, usage)
	// Best-effort: notify the client that the stream ended abnormally.
	// writeSSEError emits an error frame + [DONE] terminator. An idle
	// watchdog abort is reported distinctly so clients (and logs) can
	// tell a stalled upstream from a mid-flight transport failure.
	idleAbort := r.streamIdle != nil && r.streamIdle.Fired()
	errDetail := fmt.Sprintf("stream drain failed: %v", drainErr)
	if idleAbort {
		errDetail = "upstream stream idle timeout"
	}
	r.l.Warn("stream drain ended with error",
		"error", drainErr, "model", r.finalInfo.ModelName, "idle_abort", idleAbort)
	// N03-P01: when the client already received the [DONE] terminator, the
	// stream is over on the wire — a late failure must not emit a second
	// terminal event (an error frame + duplicate [DONE] after [DONE] is an
	// invalid stream per pkg/apiformat.ValidateChatStream). The failure is
	// still logged here and reported as request.failed below.
	if !r.clientSawDone {
		if idleAbort {
			writeSSEError(r.w, apierrors.ErrorCodeAPI, "upstream stream idle timeout")
		} else {
			writeSSEError(r.w, apierrors.ErrorCodeAPI, "stream interrupted")
		}
	}

	// G3: record final token usage against task/session budgets even on
	// drain error — the prefix was consumed, so it counts. No settled
	// price exists for a partial stream: the session spend reports
	// (0, false) like the pre-consolidation path.
	r.gw.accountUsage(r.ctx, r.w, usageRecord{
		orgID:         r.orgID,
		taskID:        r.taskID,
		sessionID:     r.sessionID,
		affinityModel: r.finalInfo.ModelName,
		usage:         usage,
	})

	ext := provider.ComputeCost(usage, r.finalInfo.Provider, r.finalInfo.ModelName)

	// Compute resale cost for streaming error path.
	drainResale := r.gw.resaleCostUSD(r.ctx, r.orgID, r.finalInfo.Provider, r.finalInfo.ModelName, usage)

	// Observability parity with the non-stream path: the counterfactual
	// baseline is premium-pool cost for tier-routed requests, actual
	// spend otherwise. Leaving it 0 collapsed SUM(counterfactual) to ~0
	// and made the savings percentage explode negative on
	// streaming-heavy traffic.
	drainBase := eventBase{
		EventType:             "request.failed",
		RequestID:             r.reqID,
		SessionID:             r.sessionID,
		UpstreamPayload:       boundedSample(r.sentBody, upstreamCaptureLimit),
		UpstreamResponse:      r.sseTee.String(),
		OrgID:                 r.orgID,
		TeamID:                r.teamID,
		APIKeyID:              eventKeyID(r.ctx),
		SessionKeyID:          eventSessionID(r.ctx),
		ModelRequested:        r.dec.From, // the client's original request, not the routed model
		ModelUsed:             r.finalInfo.ModelName,
		UpstreamURL:           r.gw.upstreamURL(r.finalInfo),
		StatusCode:            http.StatusOK,
		DurationMs:            eventpub.ComputeDurationMs(r.start),
		TokensIn:              usage.PromptTokens,
		TokensOut:             usage.CompletionTokens,
		CacheReadTokens:       usage.CacheReadTokens,
		CacheCreationTokens:   usage.CacheCreationTokens,
		EstimatedCostUSD:      ext.EstimatedCostUSD,
		Endpoint:              endpointFrom(r.ctx, "chat.completions"),
		UsageSource:           usageSourceOrNone(usage.Source),
		CostStatus:            costStatus(false, usage.Source, ext.PriceKnown),
		CounterfactualCostUSD: r.gw.effectiveCounterfactual(r.ctx, r.dec.From, r.tierUsed, r.classifierClass, usage, ext.EstimatedCostUSD),
		ResaleCostUSD:         drainResale,
		Method:                "POST",
		Error:                 errDetail,
		TierUsed:              r.tierUsed,
		ClassifierClass:       r.classifierClass,

		ClassifierConfidence: r.classifierConfidence,
		ClassifierSource:     r.classifierSource,
		RoutingDecision:      r.gw.decisionJSON(r.dec.Source, r.dec),
		AttemptCount:         len(r.attempts),
		RetryCount:           r.totalRetries,
		Labels:               labelsFrom(r.ctx),
		Policy:               r.streamPolicyJSON(),
	}
	if hasTTFT {
		drainBase.FirstTokenMs = ttftMs
	}
	// FIX-20: the partial capture still becomes the envelope — the client
	// DID receive a prefix, and the contract demands an explicit status with
	// the interrupt reason. Reason mapping mirrors the termination class
	// below: idle timeout, client cancel, upstream error otherwise. A
	// budget-truncated capture sets truncated=true independently.
	if r.history != nil {
		reason := responseHistoryReasonUpstreamError
		switch {
		case idleAbort:
			reason = responseHistoryReasonIdleTimeout
		case r.ctx.Err() != nil:
			reason = responseHistoryReasonClientCancel
		}
		drainBase.ProcessedResponse = r.history.finishEnvelope(responseHistoryStatusPartial, reason).marshal()
	}
	// NEXT-18c (§5.3 Finalize): partial usage bills under the reserve
	// tuples (enforce mode, ADR §6/D5); the termination class tells the
	// consumer whether the interrupt was client-driven or upstream.
	term := budget.TerminationUpstreamErr
	switch {
	case idleAbort:
		term = budget.TerminationIdleTimeout
	case r.ctx.Err() != nil:
		term = budget.TerminationClientCancel
	}
	r.gw.finishRequest(r.ctx, requestFinish{
		base:        drainBase,
		info:        r.finalInfo,
		resp:        r.streamResp,
		termination: term,
	}, nil)
}

// finishSuccess finalizes a fully drained stream: breaker success, budget
// accounting, and the request.completed event.
func (r *streamRun) finishSuccess(usage provider.Usage, ext provider.ExtendedUsage, ttftMs int64, hasTTFT bool) {
	r.gw.recordBreakerSuccess()

	// N03-P06-T02: SSE headers were committed with the first relayed byte,
	// but the prompt-cache outcome derives from the trailing usage chunk —
	// deliver it as an HTTP trailer, mirroring the JSON header
	// (finalizeChatJSON). Usage is final here; absent when none was parsed.
	setPromptCacheTrailer(r.w, usage)

	// P5.9/TP-04: Evalgate sampling for streaming. The cheap response was
	// relayed straight to the client and the SSE tee is a bounded capture,
	// so no full comparable cheap answer exists here. Never fabricate a
	// judge pair from placeholder text: skip judging and record the reason.
	if r.gw.judge != nil && r.gw.evalStore != nil && r.orgID != "" {
		isMediumLowConf := r.classifierClass == "medium" && r.classifierConfidence < 0.7
		if isMediumLowConf && r.gw.cfg.EvalgateSampleRate > 0 {
			r.l.Debug("evalgate: full cheap response unavailable for streaming request, judge skipped",
				"org_id", r.orgID, "request_id", r.reqID)
		}
	}

	// G3: record final token usage against task/session budgets (success
	// path), correct the TPM reservation and warm the session affinity.
	r.gw.accountUsage(r.ctx, r.w, usageRecord{
		orgID:         r.orgID,
		taskID:        r.taskID,
		sessionID:     r.sessionID,
		affinityModel: r.finalInfo.ModelName,
		usage:         usage,
		costUSD:       ext.EstimatedCostUSD,
		priceKnown:    ext.PriceKnown,
	})

	// Compute resale cost for streaming success path.
	streamResale := r.gw.resaleCostUSD(r.ctx, r.orgID, r.finalInfo.Provider, r.finalInfo.ModelName, usage)

	successBase := eventBase{
		EventType:           "request.completed",
		RequestID:           r.reqID,
		SessionID:           r.sessionID,
		UpstreamPayload:     boundedSample(r.sentBody, upstreamCaptureLimit),
		UpstreamResponse:    r.sseTee.String(),
		OrgID:               r.orgID,
		TeamID:              r.teamID,
		APIKeyID:            eventKeyID(r.ctx),
		SessionKeyID:        eventSessionID(r.ctx),
		ModelRequested:      r.dec.From, // the client's original request, not the routed model
		ModelUsed:           r.finalInfo.ModelName,
		UpstreamURL:         r.gw.upstreamURL(r.finalInfo),
		StatusCode:          http.StatusOK,
		DurationMs:          eventpub.ComputeDurationMs(r.start),
		TokensIn:            usage.PromptTokens,
		TokensOut:           usage.CompletionTokens,
		CacheReadTokens:     usage.CacheReadTokens,
		CacheCreationTokens: usage.CacheCreationTokens,
		EstimatedCostUSD:    ext.EstimatedCostUSD,
		Endpoint:            endpointFrom(r.ctx, "chat.completions"),
		UsageSource:         usageSourceOrNone(usage.Source),
		CostStatus:          costStatus(false, usage.Source, ext.PriceKnown),
		// Savings baseline: premium-pool cost when tier-routed, actual otherwise.
		CounterfactualCostUSD: r.gw.effectiveCounterfactual(r.ctx, r.dec.From, r.tierUsed, r.classifierClass, usage, ext.EstimatedCostUSD),
		ResaleCostUSD:         streamResale,
		Method:                "POST",
		TierUsed:              r.tierUsed,
		ClassifierClass:       r.classifierClass,
		ClassifierConfidence:  r.classifierConfidence,
		ClassifierSource:      r.classifierSource,
		RoutingDecision:       r.gw.decisionJSON(r.dec.Source, r.dec),
		AttemptCount:          len(r.attempts),
		RetryCount:            r.totalRetries,
		UsedOrgKey:            r.usedOrgKey, // W-BYOK-CORE: BYOK attribution (no secret material)
		OrgCredentialRef:      r.orgCredRef,
		Labels:                labelsFrom(r.ctx),
		Policy:                r.streamPolicyJSON(),
	}
	if hasTTFT {
		successBase.FirstTokenMs = ttftMs
	}
	// FIX-20: the processed-response envelope of what the client received.
	// A stream that ended cleanly without the [DONE] terminator is honest
	// about it: partial + missing_done_frame. A budget-truncated capture is
	// upgraded to partial + capture_limit inside finishEnvelope.
	if r.history != nil {
		status, reason := responseHistoryStatusComplete, ""
		if !r.clientSawDone {
			status, reason = responseHistoryStatusPartial, responseHistoryReasonMissingDoneFram
		}
		successBase.ProcessedResponse = r.history.finishEnvelope(status, reason).marshal()
	}
	// NEXT-18c: settle the reservation with the actual spend (§5.3
	// Finalize) and stamp the tuples + completed termination on the event.
	r.gw.finishRequest(r.ctx, requestFinish{
		base:        successBase,
		info:        r.finalInfo,
		resp:        r.streamResp,
		termination: budget.TerminationCompleted,
	}, nil)
}

// cachedCompletion is the minimal shape of a chat.completion document stored
// in the cache (hit.Data). Streaming replays convert it into SSE chunks.
type cachedCompletion struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role             string          `json:"role"`
			Content          string          `json:"content"`
			ReasoningContent string          `json:"reasoning_content,omitempty"`
			Refusal          string          `json:"refusal,omitempty"`
			ToolCalls        json.RawMessage `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type cachedChunkDelta struct {
	Role             *string          `json:"role,omitempty"`
	Content          *string          `json:"content,omitempty"`
	ReasoningContent *string          `json:"reasoning_content,omitempty"`
	Refusal          *string          `json:"refusal,omitempty"`
	ToolCalls        []map[string]any `json:"tool_calls,omitempty"`
}

type cachedChunk struct {
	ID      string              `json:"id"`
	Object  string              `json:"object"`
	Created int64               `json:"created"`
	Model   string              `json:"model"`
	Choices []cachedChunkChoice `json:"choices"`
	Usage   json.RawMessage     `json:"usage,omitempty"`
}

type cachedChunkChoice struct {
	Index        int              `json:"index"`
	Delta        cachedChunkDelta `json:"delta"`
	FinishReason *string          `json:"finish_reason"`
}

// sseReplayFrames converts a cached chat.completion JSON document into OpenAI
// SSE frames (`data: {...}\n\n` chunks plus a terminal `data: [DONE]`) so a
// streaming client can replay a cache hit. The cache stores non-streaming
// completion documents regardless of how the response was produced, so the
// whole message is delivered as one content chunk followed by a finish chunk
// (with usage when known). Returns an error when data is not a completion
// document; callers should treat that as a cache miss and go upstream.
//
// H3 (saw-terminal replay gate): a document whose choices carry no
// finish_reason is the truncated-stream shape — a stream cut before its
// terminal event never emits the finish chunk. Replaying it would serve a
// partial answer as a complete one, so it is refused (read as a miss; the
// entry self-heals on refill).
func sseReplayFrames(data []byte) ([]byte, error) {
	var cc cachedCompletion
	if err := json.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("cache hit data is not a chat.completion document: %w", err)
	}
	if len(cc.Choices) == 0 {
		return nil, errors.New("cache hit document has no choices")
	}
	for _, ch := range cc.Choices {
		if ch.FinishReason == nil {
			return nil, errTruncatedCachedCompletion
		}
	}
	if cc.ID == "" {
		cc.ID = "cache-replay"
	}
	if cc.Created == 0 {
		cc.Created = time.Now().Unix()
	}
	if cc.Model == "" {
		cc.Model = "cache-replay"
	}

	var b strings.Builder
	writeChunk := func(ch cachedChunk) error {
		frame, err := json.Marshal(ch)
		if err != nil {
			return fmt.Errorf("marshal cache replay chunk: %w", err)
		}
		b.WriteString("data: " + string(frame) + "\n\n")
		return nil
	}
	for i, ch := range cc.Choices {
		delta := cachedChunkDelta{}
		if ch.Message.Role != "" {
			role := ch.Message.Role
			delta.Role = &role
		} else if i == 0 {
			role := "assistant"
			delta.Role = &role
		}
		if ch.Message.ReasoningContent != "" {
			rc := ch.Message.ReasoningContent
			delta.ReasoningContent = &rc
		}
		if ch.Message.Content != "" {
			content := ch.Message.Content
			delta.Content = &content
		}
		if ch.Message.Refusal != "" {
			// N07-P01-T03: a cached refusal must replay as a refusal —
			// dropping the field would stream a completed-looking answer.
			refusal := ch.Message.Refusal
			delta.Refusal = &refusal
		}
		if len(ch.Message.ToolCalls) > 0 {
			// N07-P01-T03 negative criterion: cached (parallel) tool calls
			// must survive the replay. Elements pass through verbatim (map
			// round-trip preserves unknown fields); a missing index is
			// stamped from the array position because streaming consumers
			// merge tool-call fragments by index. Undecodable tool_calls
			// fail the whole replay: callers treat that as a cache miss and
			// go upstream rather than stream a lossy completion.
			var rawCalls []map[string]any
			if err := json.Unmarshal(ch.Message.ToolCalls, &rawCalls); err != nil {
				return nil, fmt.Errorf("cache hit tool_calls is not a tool call array: %w", err)
			}
			for i, call := range rawCalls {
				if _, ok := call["index"]; !ok {
					call["index"] = i
				}
			}
			delta.ToolCalls = rawCalls
		}
		// Content frame (finish_reason null), then a canonical empty-delta
		// finish frame terminating the choice. Refusal and tool calls ride
		// the content frame's delta, so the whole cached message reaches the
		// streaming client.
		if err := writeChunk(cachedChunk{
			ID: cc.ID, Object: "chat.completion.chunk", Created: cc.Created, Model: cc.Model,
			Choices: []cachedChunkChoice{{Index: ch.Index, Delta: delta}},
		}); err != nil {
			return nil, err
		}
		finish := cachedChunk{
			ID: cc.ID, Object: "chat.completion.chunk", Created: cc.Created, Model: cc.Model,
			Choices: []cachedChunkChoice{{Index: ch.Index, Delta: cachedChunkDelta{}, FinishReason: ch.FinishReason}},
		}
		// Attach usage on the terminal frame of the replay.
		if i == len(cc.Choices)-1 && cc.Usage != nil {
			usage, _ := json.Marshal(cc.Usage)
			finish.Usage = usage
		}
		if err := writeChunk(finish); err != nil {
			return nil, err
		}
	}
	b.WriteString("data: [DONE]\n\n")
	return []byte(b.String()), nil
}

// sseDoneFrames are the [DONE] terminator line shapes pkg/apiformat.
// ValidateChatStream accepts: the "data:" prefix with the payload "[DONE]"
// after trimming at most ONE separating space — i.e. the canonical spaced
// form and the no-space form (plus a trailing CR, stripped by TrimSpace
// below). Both shapes terminate the client's stream per the validator, so
// both must mark the terminal delivery; anything else (two spaces, other
// payloads) the validator would reject as non-JSON data and must not count.
var sseDoneFrames = [][]byte{
	[]byte("data: [DONE]"), // spaced terminator (canonical)
	[]byte("data:[DONE]"),  // no-space terminator (same payload per ValidateChatStream)
}

// isSSEDoneFrame reports whether p — a single Write on the client writer —
// is exactly a [DONE] terminator line, optionally wrapped in the frame's
// newlines. A JSON chunk line never trims to a terminator shape, so a
// content delta merely mentioning "data: [DONE]" cannot trip the detection.
func isSSEDoneFrame(p []byte) bool {
	trimmed := bytes.TrimSpace(p)
	for _, frame := range sseDoneFrames {
		if bytes.Equal(trimmed, frame) {
			return true
		}
	}
	return false
}

// sseTerminalWatch wraps the client writer for the duration of a stream
// drain and records whether the terminal "data: [DONE]" frame reached the
// client (N03-P01: a late failure after the terminator must not emit a
// second terminal event). Producers emit the terminator either as the bare
// line (the OpenAI passthrough writes line and newline separately) or as
// the whole frame ("data: [DONE]\n\n"); both trim to the same payload, in
// the spaced and the no-space form (the shapes ValidateChatStream accepts
// as the terminator). A JSON chunk line never trims to a terminator shape,
// so a content delta merely mentioning "data: [DONE]" cannot trip the
// detection.
type sseTerminalWatch struct {
	http.ResponseWriter
	flusher http.Flusher
	seen    atomic.Bool
}

// newSSETerminalWatch wraps w; the watch itself stays a Flusher for
// producers that flush through the response writer.
func newSSETerminalWatch(w http.ResponseWriter) *sseTerminalWatch {
	flusher, _ := w.(http.Flusher)
	return &sseTerminalWatch{ResponseWriter: w, flusher: flusher}
}

// sawDone reports whether the [DONE] terminator was written to the client.
func (sw *sseTerminalWatch) sawDone() bool { return sw.seen.Load() }

func (sw *sseTerminalWatch) Write(p []byte) (int, error) {
	if !sw.seen.Load() && isSSEDoneFrame(p) {
		sw.seen.Store(true)
	}
	return sw.ResponseWriter.Write(p)
}

// Flush forwards to the wrapped writer's flusher.
func (sw *sseTerminalWatch) Flush() {
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
}

// writeSSEError emits a terminal error frame followed by [DONE]. It is
// best-effort by contract: a client that already disconnected can make the
// underlying Write/Flush panic inside net/http (the server may have recycled
// the response). The panic is contained here so the caller's remaining
// cleanup — budget accounting, session affinity, analytics events — always
// runs; this path is exactly the "stream failed" handler, and dying inside it
// would lose the very records that explain the failure.
func writeSSEError(w http.ResponseWriter, errType, message string) {
	writeSSEErrorWithCode(w, errType, "", message)
}

// writeSSEErrorWithCode is writeSSEError with the optional stable error
// code rendered in the frame (empty code keeps the frame byte-identical to
// the code-less form).
func writeSSEErrorWithCode(w http.ResponseWriter, errType, code, message string) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Debug("sse error write panicked (client gone)", "panic", rec)
		}
	}()
	payload := apierrs.SSEErrorFrame(&apierrs.E{Type: errType, Code: code, Message: message})
	if _, err := w.Write(payload); err != nil {
		slog.Debug("sse error write failed, client disconnected", "error", err)
	}
	if _, err := w.Write([]byte("data: [DONE]\n\n")); err != nil {
		slog.Debug("sse done-after-error write failed, client disconnected", "error", err)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// mapUpstreamError translates an upstream client error into (gateway HTTP status, OpenAI error type).
// A typed *upstream.Error carries the upstream status, mapped via
// MapUpstreamStatus; everything else (transport failure, translate-contract
// failure) defaults to 502 Bad Gateway.
func mapUpstreamError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return http.StatusGatewayTimeout, apierrors.ErrorCodeAPI
	}
	var uerr *upstream.Error
	if errors.As(err, &uerr) && uerr.Status > 0 {
		return apierrors.MapUpstreamStatus(uerr.Status)
	}
	// TranslateError and unknown failures: the upstream answered but its
	// payload is not servable — a gateway fault (502), not a client error.
	return http.StatusBadGateway, apierrors.ErrorCodeAPI
}
