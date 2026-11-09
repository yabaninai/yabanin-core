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

const embeddingsResponseLimit = 64 << 20

func openAICompatProvider(name string) bool {
	switch name {
	case "openai", "openai-compat", "", "vllm", "ollama", "llamacpp", "mistral":
		return true
	default:
		return false
	}
}

func (gw *gateway) embeddings(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The 10 MiB gateway cap (httpmw.MaxBody) answers 413 — parity with
		// the audio/images payload-size refusal (owner decision 2026-10-13,
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model string          `json:"model"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}
	if len(req.Input) == 0 || string(req.Input) == "null" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "input is required")
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "embeddings",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"embeddings are not supported for this provider", "embeddings_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// NEXT-18c (ADR-0001 §5.1): pre-check + reserve before the upstream
	// call (no cache branch on this pipeline). Embeddings have no generated
	// output — out_cap = 0 in the bound (§4.3). The gate rides the
	// request-derived context for the finalize stages below.
	rctx := r.Context()
	gate, ok := gw.reservationPlan(w, r, "embeddings",
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
	resp, err := client.Do(ctx, "/v1/embeddings", upstreamBody, apiKey, false, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			if cerr := resp.Body.Close(); cerr != nil {
				l.Debug("close upstream body", "error", cerr)
			}
		}
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (parity with
	// images; the gateway never delivers a partial embeddings payload —
	limited, err := io.ReadAll(io.LimitReader(resp.Body, embeddingsResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if len(limited) > embeddingsResponseLimit {
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

	n, source := embeddingsUsage(limited, req.Input)
	usage := provider.Usage{PromptTokens: n, TotalTokens: n, Source: source}
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
			TokensIn:                   n,
			TokensOut:                  0,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "embeddings",
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

func embeddingsUsage(body, input []byte) (int64, string) {
	var parsed struct {
		Usage *struct {
			PromptTokens int64 `json:"prompt_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Usage != nil {
		n := parsed.Usage.PromptTokens
		if n == 0 {
			n = parsed.Usage.TotalTokens
		}
		return n, provider.UsageSourceProvider
	}
	n := int64((len(input) + 3) / 4)
	return n, provider.UsageSourceEstimated
}
