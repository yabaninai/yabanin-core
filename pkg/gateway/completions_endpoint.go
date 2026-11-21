package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func (gw *gateway) completions(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model     string `json:"model"`
		Stream    bool   `json:"stream"`
		MaxTokens *int   `json:"max_tokens"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "completions",
		Model:    req.Model,
		Body:     body,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"completions are not supported for this provider", "completions_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// OP-8: unified policy-pipeline run point (pre-upstream, before the
	// reservation and the forward). One call site for both branches of this
	// endpoint (streaming hooks arrive with OP-4); the decision record rides
	// rctx into the finisher's event.
	guarded, policyEvent, ok := gw.policyPreUpstream(w, r, "completions", admitted.Info.ModelName, admitted.Info.Provider, admitted.Body)
	if !ok {
		return
	}
	admitted.Body = guarded
	// Serving provider of the single-candidate client pool (hoisted for the
	providerName := admitted.Info.Provider
	if providerName == "" {
		providerName = "openai"
	}
	// hint foreign to the serving provider refuses here, before any
	// reservation.
	if !gw.enforceSingularRouteHint(w, r, providerName) {
		return
	}

	// N03-P03-T09: the streaming-policy seam exists only in the chat
	// serveStream, so stream_prefix/stream_final policies attached to the
	// "completions" endpoint cannot be honored on this surface. Refuse
	// explicitly (before any reservation) instead of relaying a silently
	// unprotected stream; shadow mode never refuses, and a cold policy
	// store stays fail-open exactly like the seam's own plan lookup.
	if req.Stream && gw.unenforceableStreamPolicies(r.Context(), admitted.OrgID, admitted.Info.ModelName) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"stream policies are not enforced on legacy completions streams", "stream_policy_unsupported_surface")
		return
	}

	// NEXT-18c (ADR-0001 §5.1): pre-check, then reserve — this pipeline has
	// no cache branch, so both stages run back-to-back before the upstream
	// call. The gate rides the request-derived context for the finalize
	// stages below. The minted invocation identity rides the same context
	// so the confirmed start and the terminal facts bind to this request's
	// admission row on BOTH transports below.
	rctx := withPolicyEvent(r.Context(), policyEvent)
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	gate, ok := gw.reservationPlan(w, r, "completions",
		gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
			admitted.Info, admitted.Body, reservationMaxTokens(req.MaxTokens), false))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}

	apiKey := admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL := gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, providerName)
	if err != nil {
		l.Warn("upstream client unavailable", "provider", providerName, "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return
	}
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	// Stream capability precedes the durable start on every branch: a
	// writer that cannot flush would otherwise commit an admission for a
	// request that can never dispatch (chat streamRun.admit canon — fail
	// before anything durable, with zero provider arrivals).
	if req.Stream {
		if _, ok := w.(http.Flusher); !ok {
			gate.finalizeNoEvent(budget.TerminationUpstreamErr)
			apierrors.Write(w, http.StatusNotImplemented, apierrors.ErrorCodeAPI, "streaming not supported by server")
			return
		}
	}
	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the first paid provider dispatch — after every fallible local
	// setup step above (pool wiring, model remap, stream capability), so a
	// local failure never strands a durable admission for a request that
	// never dispatched. One admission per request; the JSON and stream
	// branches below share it and the kind binds to the transport actually
	// dispatched. Fail closed: an unwritten start (write error, timeout or
	// lost ACK — outcome unknown) refuses the request with ZERO provider
	// arrivals under the history_unavailable envelope, and the escrow is
	// released. The structured 503 precedes the stream branch, so it can
	// never land after client success headers.
	if err := gw.confirmPaidInvocation(rctx, invocationKindForChat(req.Stream)); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return
	}

	if req.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.completionsStream(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, providerName, upstreamURL, started, l)
		return
	}

	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/completions", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, embeddingsResponseLimit))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return
	}
	usage := completionsUsage(limited, body, client.Adapter())
	// OP-8: post-upstream policy hook. Usage was parsed from the ORIGINAL
	// body (the tokens were consumed); a mask replaces what the client and
	// the finisher see; a deny answers 400 instead of the upstream body.
	if gw.policyRuntime != nil {
		masked, postEvent, denied := gw.policyPostUpstream(r, "completions", admitted.Info.ModelName, admitted.Info.Provider, limited)
		if postEvent != "" {
			rctx = withPolicyEvent(rctx, appendPolicyEvents(policyEventFrom(rctx), postEvent))
		}
		if denied {
			if ferr := gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusBadRequest, started, resp); ferr != nil {
				// The client envelope is already the policy denial; the
				// withheld event is logged loudly (finishRequestLogged
				// canon).
				l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
			}
			apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	if ferr := gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusOK, started, resp); ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		l.Error("terminal facts commit failed; withholding reply", "error", ferr)
		writeTerminalAccountingFailure(w)
		return
	}
	// N03-P06-T02: provider prompt-cache transparency on the legacy
	// completions JSON path (absent for estimated usage — never fabricated).
	setPromptCacheHeader(w, usage)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

func (gw *gateway) completionsStream(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, providerName, upstreamURL string, started time.Time, l *slog.Logger) {
	upstreamBody, clientWantsUsage := ensureStreamUsage(upstreamBody, providerName, gw.streamUsageProviders)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Proxy-Cache", "bypass")

	// The caller checked the stream capability BEFORE the durable start,
	// so the writer is a Flusher by construction (a non-flusher writer
	// never reaches this function — it answered 501 with no admission).
	flusher, _ := w.(http.Flusher)

	// The stream context derives from the request-derived rctx (identity,
	// gate, policy record ride it into the finisher) — client
	// cancellation still propagates from the parent request context.
	streamCtx, cancelStream := context.WithCancel(rctx)
	defer cancelStream()

	resp, err := client.Do(streamCtx, "/v1/completions", upstreamBody, apiKey, true, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writeSSEError(w, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writeSSEError(w, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}

	body := io.Reader(resp.Body)
	if gw.streamIdleTimeout > 0 {
		idle := newIdleReader(resp.Body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		body = idle
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{body, resp.Body}

	handler := provider.NewStreamHandlerWithOptions("openai", admitted.Info.ModelName, provider.StreamOptions{
		SuppressUsageOnlyChunk: !clientWantsUsage,
		RequestBytes:           len(upstreamBody),
		// Legacy completions canon: a complete JSON data line that lost
		// only its blank separator to a transport cut is still dispatched
		// whole before the drain-failure error frame ([DONE], torn lines,
		// cancellation and policy-wrapped chat stay excluded — provider
		// scoping). The other three relays implement the same salvage at
		// the gateway frame buffer (apiformat.SSEFrameBuffer).
		RecoverLegacyCompletionLine: true,
	})
	// N03-P01: watch the terminal — a late failure after the client already
	// saw the [DONE] terminator must not emit a second terminal event. The
	// tail tracker sits under the watch so a torn last event is closed
	// before the drain-failure error frame composes (chat F2 canon).
	tail := &ssePassthroughTail{w: w}
	watch := newSSETerminalWatch(tail)
	// Central binding (Preview2 durable accounting, chat drain canon): an
	// admitted invocation holds the client-facing [DONE] until its terminal
	// facts commit — release happens exactly once after the durable write;
	// a failed write drops the terminator and surfaces the typed accounting
	// error frame instead.
	if h := invocationIdentityFrom(rctx); h != nil && h.Admitted() && gw.invocations != nil {
		watch.armDoneHold()
	}
	usage, drainErr := handler.HandleStream(streamCtx, watch, flusher, resp)
	if drainErr != nil {
		// NEXT-18c: no analytics event on this path — settle the escrow with
		// zero spend; the idle return sweeps it. The reconciler's grace
		// sweep owns the admitted-without-facts row. The client must NOT
		// observe a held success terminator for the failed stream: drop it
		// (chat drain canon) before the error frame.
		watch.failDoneHold()
		term := budget.TerminationUpstreamErr
		if rctx.Err() != nil {
			term = budget.TerminationClientCancel
		}
		gate.finalizeNoEvent(term)
		if !watch.sawDone() {
			tail.complete()
			writeSSEError(w, apierrors.ErrorCodeAPI, "stream drain failed")
		}
		return
	}
	// N03-P06-T02: stream headers committed long ago; outcome rides the
	// trailer once HandleStream returns final usage.
	setPromptCacheTrailer(w, usage)
	if ferr := gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusOK, started, resp); ferr != nil {
		// Central binding: the held terminator is dropped and replaced by
		// the accounting error frame — deliberately NO safe-retry language:
		// the work already ran under this invocation identity (chat stream
		// canon).
		watch.failDoneHold()
		writeSSEErrorWithCode(w, apierrors.ErrorCodeAPI, accountingCommitFailedCode,
			"stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge")
		l.Error("terminal facts commit failed after paid stream; [DONE] withheld from client",
			"invocation_id", invocationIDFromCtx(rctx), "error", ferr)
		return
	}
	watch.releaseDoneHold()
}

func closeUpstream(l *slog.Logger, resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	if cerr := resp.Body.Close(); cerr != nil && l != nil {
		l.Debug("close upstream body", "error", cerr)
	}
}

// completionsUsage parses upstream usage through the serving provider's
// adapter so the non-streaming completions path consumes the same shared
// parser as every OpenAI-compatible adapter (N03-P06-T04): transparent
// prompt-cache fields (prompt_tokens_details.cached_tokens, legacy
// prompt_cache_hit_tokens) must reach billing instead of being silently
// dropped at this seam. A body without a provider usage block keeps the
// pre-existing request-length estimate fallback.
func completionsUsage(body, request []byte, adapter provider.Provider) provider.Usage {
	u := adapter.ParseUsage(body)
	if u.Source == provider.UsageSourceProvider {
		if u.TotalTokens == 0 {
			u.TotalTokens = u.PromptTokens + u.CompletionTokens
		}
		return u
	}
	n := int64((len(request) + 3) / 4)
	return provider.Usage{PromptTokens: n, TotalTokens: n, Source: provider.UsageSourceEstimated}
}

// finishCompletion settles the legacy completions response durably — the
// usage record, terminal facts and the reservation — and returns the
// terminal-facts commit error so each transport can apply its canon:
// buffered callers withhold the upstream body, the stream caller drops
// the held [DONE] and closes with the accounting error frame.
func (gw *gateway) finishCompletion(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, providerName, upstreamURL string, status int, started time.Time, resp *http.Response) error {
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	gw.accountUsage(ctx, w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})
	_, ferr := gw.finishRequest(ctx, requestFinish{
		base: eventBase{
			EventType:      "request.completed",
			RequestID:      admitted.RequestID,
			SessionID:      admitted.SessionID,
			Payload:        string(admitted.Body),
			OrgID:          admitted.OrgID,
			TeamID:         admitted.TeamID,
			AgentID:        admitted.AgentID,
			UserID:         admitted.UserID,
			APIKeyID:       admitted.APIKeyID,
			SessionKeyID:   admitted.SessionKeyID,
			TaskID:         admitted.TaskID,
			ModelRequested: admitted.RequestedModel,
			ModelUsed:      admitted.Info.ModelName,
			UpstreamURL:    upstreamURL,
			StatusCode:     int64(status),
			DurationMs:     time.Since(started).Milliseconds(),
			TokensIn:       usage.PromptTokens,
			TokensOut:      usage.CompletionTokens,
			// N03-P06-T05: the event must carry the same provider-reported
			// cache reads the bill used — a discounted EstimatedCostUSD with
			// zero CacheReadTokens would make the analytics ledger
			// irreproducible from its own fields (parity with chat/messages/
			// responses/rerank/images finishers).
			CacheReadTokens:            usage.CacheReadTokens,
			CacheCreationTokens:        usage.CacheCreationTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "completions",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(ctx),
			Policy:                     policyEventFrom(ctx), // OP-8: decision record (OP-9 contract)
		},
		info:        admitted.Info,
		resp:        resp,
		termination: completionTermination(ctx),
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). Resale is not computed on this pipeline; the
		// wallet actual falls back to the base quote — the consumer's
		// own rule.
		eventNote: true,
	}, nil)
	return ferr
}

// completionTermination classifies a finished completion for the Finalize
// contract (§5.3): a dead request context means the client walked away.
func completionTermination(ctx context.Context) budget.Termination {
	if ctx.Err() != nil {
		return budget.TerminationClientCancel
	}
	return budget.TerminationCompleted
}

// unenforceableStreamPolicies reports whether the org has stream_prefix or
// stream_final policies attached to the "completions" endpoint (N03-P03-T09).
// The streaming-policy seam is built by the chat serveStream only, so those
// attachments can never be enforced here; the completions handler uses this
// to refuse explicitly instead of relaying a silently unprotected stream.
// Enforce mode only: shadow never breaks working streams, and a cold or
// unavailable runtime fails open exactly like the seam's own plan lookup.
func (gw *gateway) unenforceableStreamPolicies(ctx context.Context, orgID, model string) bool {
	rt := gw.policyRuntime
	if rt == nil || orgID == "" || rt.mode != PolicyModeEnforce {
		return false
	}
	q := policyQuery{endpoint: "completions", hook: pipeline.HookStreamPrefix, model: model, keyLabels: principalKeyLabels(ctx)}
	if len(rt.streamPlans(ctx, orgID, q)) > 0 {
		return true
	}
	q.hook = pipeline.HookStreamFinal
	return len(rt.streamPlans(ctx, orgID, q)) > 0
}
