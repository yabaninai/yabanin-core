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
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// rerankResponseLimit bounds the buffered upstream rerank response (64 MiB,
// images/embeddings parity): results[] scores are opaque JSON the gateway
// passes through without re-ranking anything itself.
const rerankResponseLimit = 64 << 20

// rerankMaxDocuments caps the client-supplied documents array (contract
// subset matrix): one rerank call prices and ranks at most 512 documents.
const rerankMaxDocuments = 512

// rerankRequest is the validated client shape of the rerank route.
type rerankRequest struct {
	Model     string          `json:"model"`
	Query     string          `json:"query"`
	Documents json.RawMessage `json:"documents"`
}

// parseRerankRequest reads and validates the client request. Every refusal
// lands BEFORE admission, so a rejected request leaves no durable trace.
func parseRerankRequest(w http.ResponseWriter, r *http.Request) (rerankRequest, []byte, bool) {
	body, ok := readRouteBody(w, r)
	if !ok {
		return rerankRequest{}, nil, false
	}
	var req rerankRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return rerankRequest{}, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return rerankRequest{}, nil, false
	}
	if req.Query == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "query is required")
		return rerankRequest{}, nil, false
	}
	if _, ok := rerankDocuments(w, req.Documents); !ok {
		return rerankRequest{}, nil, false
	}
	return req, body, true
}

// passthrough of {model, query, documents[], top_n} to the OpenAI-compat
// /v1/rerank path, byte-honest response relay, provider-token usage
// accounting (D3 — absent usage is zero + UsageSourceNone, an absent price
// stays unknown_price; no invented per-query price).
func (gw *gateway) rerank(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := parseRerankRequest(w, r)
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
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "rerank", "rerank is not supported for this provider") {
		return
	}
	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the
	// embeddings-style input pre-estimate (no generated output tokens,
	// out_cap = 0); the wallet settles on the actual provider usage below.
	rctx, gate, ok := gw.reservePaidDispatch(r.Context(), w, r, "rerank", admitted, nil, true)
	if !ok {
		return
	}
	client, upstreamBody, apiKey, providerName, upstreamURL, ok := gw.paidUpstreamClient(l, w, gate, admitted, admitted.Info.Provider)
	if !ok {
		return
	}
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindChat) {
		return
	}
	resp, usage, limited, ok := relayRerankResponse(rctx, w, l, gate, client, admitted.Info, upstreamBody, apiKey)
	if resp != nil {
		// The settle stages below keep the body open (headers ride the
		// finish event); it closes after the reply is written.
		defer resp.Body.Close()
	}
	if !ok {
		return
	}
	gw.finishBufferedJSONRoute(bufferedJSONFinish{
		rctx: rctx, w: w, admitted: admitted, usage: usage,
		providerName: providerName, endpoint: "rerank", upstreamURL: upstreamURL,
		started: started, resp: resp, payload: limited,
	})
}

// relayRerankResponse performs the paid /v1/rerank dispatch and buffers the
// upstream reply. On failure the refusal response was already written; the
// returned response (non-nil after a successful dial) still owns its open
// body, so the caller defers the close and the settle stages keep today's
// ordering.
func relayRerankResponse(rctx context.Context, w http.ResponseWriter, l *slog.Logger, gate *reservationGate, client *upstream.Client, info resolver.ModelInfo, upstreamBody []byte, apiKey string) (*http.Response, provider.Usage, []byte, bool) {
	timeout := info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/rerank", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return nil, provider.Usage{}, nil, false
	}

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (images
	// parity; the gateway never delivers a partial rerank payload).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, rerankResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		writePaidBodyError(w, "failed to read upstream response")
		return resp, provider.Usage{}, nil, false
	}
	if len(limited) > rerankResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "upstream response too large")
		return resp, provider.Usage{}, nil, false
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return resp, provider.Usage{}, nil, false
	}
	return resp, rerankUsage(limited), limited, true
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
