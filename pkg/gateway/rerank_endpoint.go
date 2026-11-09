package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// rerankResponseLimit bounds the buffered upstream rerank response (64 MiB,
// images/embeddings parity): results[] scores are opaque JSON the gateway
// passes through without re-ranking anything itself.
const rerankResponseLimit = 64 << 20

// rerankMaxDocuments caps the client-supplied documents array (contract
// subset matrix): one rerank call prices and ranks at most 512 documents.
const rerankMaxDocuments = 512

// passthrough of {model, query, documents[], top_n} to the OpenAI-compat
// /v1/rerank path, byte-honest response relay, provider-token usage
// accounting (D3 — absent usage is zero + UsageSourceNone, an absent price
// stays unknown_price; no invented per-query price).
func (gw *gateway) rerank(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The 10 MiB gateway cap (httpmw.MaxBody) answers 413 — the
		// contract's payload-size refusal (audio/images parity,
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model     string          `json:"model"`
		Query     string          `json:"query"`
		Documents json.RawMessage `json:"documents"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}
	if req.Query == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "query is required")
		return
	}
	_, ok := rerankDocuments(w, req.Documents)
	if !ok {
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "rerank",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"rerank is not supported for this provider", "rerank_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the
	// embeddings-style input pre-estimate (no generated output tokens,
	// out_cap = 0); the wallet settles on the actual provider usage below.
	rctx := r.Context()
	gate, ok := gw.reservationPlan(w, r, "rerank",
		gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
			admitted.Info, admitted.Body, nil, true))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}

	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()

	providerName := admitted.Info.Provider
	if providerName == "" {
		providerName = "openai"
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
	resp, err := client.Do(ctx, "/v1/rerank", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (images
	// parity; the gateway never delivers a partial rerank payload).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, rerankResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if len(limited) > rerankResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream response too large")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return
	}

	usage := rerankUsage(limited)
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	gw.accountUsage(rctx, w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})

	gw.finishRequest(rctx, requestFinish{
		base: eventBase{
			EventType:                  "request.completed",
			RequestID:                  admitted.RequestID,
			SessionID:                  admitted.SessionID,
			Payload:                    string(admitted.Body),
			OrgID:                      admitted.OrgID,
			TeamID:                     admitted.TeamID,
			AgentID:                    admitted.AgentID,
			UserID:                     admitted.UserID,
			APIKeyID:                   admitted.APIKeyID,
			SessionKeyID:               admitted.SessionKeyID,
			TaskID:                     admitted.TaskID,
			ModelRequested:             admitted.RequestedModel,
			ModelUsed:                  admitted.Info.ModelName,
			UpstreamURL:                upstreamURL,
			StatusCode:                 http.StatusOK,
			DurationMs:                 time.Since(started).Milliseconds(),
			TokensIn:                   usage.PromptTokens,
			TokensOut:                  usage.CompletionTokens,
			CacheReadTokens:            usage.CacheReadTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "rerank",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(rctx),
		},
		info: admitted.Info,
		resp: resp,
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). No resale on this pipeline; the wallet actual
		// falls back to the base quote — the consumer's own rule.
		termination: completionTermination(rctx),
		eventNote:   true,
	}, nil)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

// rerankDocuments validates the documents field locally: a non-empty JSON
// array of at most rerankMaxDocuments items. Element shape is upstream-owned
// (string or object) and passed through verbatim.
func rerankDocuments(w http.ResponseWriter, raw json.RawMessage) ([]json.RawMessage, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "documents is required")
		return nil, false
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(raw, &docs); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "documents must be an array")
		return nil, false
	}
	if len(docs) == 0 {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "documents must not be empty")
		return nil, false
	}
	if len(docs) > rerankMaxDocuments {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"too many documents: the limit is 512 per request")
		return nil, false
	}
	return docs, true
}

// rerankUsage parses the upstream rerank usage block when present, accepting
// both token vocabularies seen across OpenAI-compat rerank implementations
// (prompt_tokens/input_tokens, total_tokens). An absent or malformed block
// yields zero tokens with UsageSourceNone — no fabricated estimate (D3
// actual-billing default; the price then honestly reads unknown/no_usage).
func rerankUsage(body []byte) provider.Usage {
	u, ok := tokenUsageBlock(body)
	if !ok {
		return provider.Usage{}
	}
	return u
}

// tokenUsageBlock extracts a top-level {"usage":{...}} block tolerant of the
// prompt_tokens/input_tokens naming split. ok is false when the body has no
// usable usage object.
func tokenUsageBlock(body []byte) (provider.Usage, bool) {
	var parsed struct {
		Usage *struct {
			PromptTokens     *int64 `json:"prompt_tokens"`
			InputTokens      *int64 `json:"input_tokens"`
			OutputTokens     *int64 `json:"output_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			TotalTokens      *int64 `json:"total_tokens"`
			CachedTokens     *int64 `json:"cached_tokens"`
			PromptDetailed   *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			InputDetailed *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"input_token_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Usage == nil {
		return provider.Usage{}, false
	}
	var in int64
	switch {
	case parsed.Usage.PromptTokens != nil:
		in = *parsed.Usage.PromptTokens
	case parsed.Usage.InputTokens != nil:
		in = *parsed.Usage.InputTokens
	}
	var out int64
	switch {
	case parsed.Usage.OutputTokens != nil:
		out = *parsed.Usage.OutputTokens
	case parsed.Usage.CompletionTokens != nil:
		out = *parsed.Usage.CompletionTokens
	}
	var total int64
	if parsed.Usage.TotalTokens != nil {
		total = *parsed.Usage.TotalTokens
	}
	if total == 0 {
		total = in + out
	}
	var cached int64
	switch {
	case parsed.Usage.CachedTokens != nil:
		cached = *parsed.Usage.CachedTokens
	case parsed.Usage.PromptDetailed != nil:
		cached = parsed.Usage.PromptDetailed.CachedTokens
	case parsed.Usage.InputDetailed != nil:
		cached = parsed.Usage.InputDetailed.CachedTokens
	}
	return provider.Usage{
		PromptTokens:     in,
		CompletionTokens: out,
		TotalTokens:      total,
		CacheReadTokens:  cached,
		Source:           provider.UsageSourceProvider,
	}, true
}
