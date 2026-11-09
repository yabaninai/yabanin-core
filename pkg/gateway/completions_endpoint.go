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
	// stages below.
	rctx := withPolicyEvent(r.Context(), policyEvent)
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

	if req.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.completionsStream(w, r, gate, admitted, client, upstreamBody, apiKey, providerName, upstreamURL, started, l)
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
			gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusBadRequest, started, resp)
			apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusOK, started, resp)
	// N03-P06-T02: provider prompt-cache transparency on the legacy
	// completions JSON path (absent for estimated usage — never fabricated).
	setPromptCacheHeader(w, usage)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

func (gw *gateway) completionsStream(w http.ResponseWriter, r *http.Request, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, providerName, upstreamURL string, started time.Time, l *slog.Logger) {
	upstreamBody, clientWantsUsage := ensureStreamUsage(upstreamBody, providerName, gw.streamUsageProviders)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Proxy-Cache", "bypass")

	flusher, ok := w.(http.Flusher)
	if !ok {
		apierrors.Write(w, http.StatusNotImplemented, apierrors.ErrorCodeAPI, "streaming not supported by server")
		return
	}

	streamCtx, cancelStream := context.WithCancel(r.Context())
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
	})
	// N03-P01: watch the terminal — a late failure after the client already
	// saw the [DONE] terminator must not emit a second terminal event.
	watch := newSSETerminalWatch(w)
	usage, drainErr := handler.HandleStream(streamCtx, watch, flusher, resp)
	if drainErr != nil {
		// NEXT-18c: no analytics event on this path — settle the escrow with
		// zero spend; the idle return sweeps it.
		term := budget.TerminationUpstreamErr
		if r.Context().Err() != nil {
			term = budget.TerminationClientCancel
		}
		gate.finalizeNoEvent(term)
		if !watch.sawDone() {
			writeSSEError(w, apierrors.ErrorCodeAPI, "stream drain failed")
		}
		return
	}
	// N03-P06-T02: stream headers committed long ago; outcome rides the
	// trailer once HandleStream returns final usage.
	setPromptCacheTrailer(w, usage)
	gw.finishCompletion(w, r.Context(), admitted, usage, providerName, upstreamURL, http.StatusOK, started, resp)
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

func (gw *gateway) finishCompletion(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, providerName, upstreamURL string, status int, started time.Time, resp *http.Response) {
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	gw.accountUsage(ctx, w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})
	gw.finishRequest(ctx, requestFinish{
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
		// wallet actual falls back to the base quote — the consumer's own
		// rule.
		eventNote: true,
	}, nil)
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
