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

const embeddingsResponseLimit = 64 << 20

func openAICompatProvider(name string) bool {
	switch name {
	case "openai", "openai-compat", "", "vllm", "ollama", "llamacpp", "mistral":
		return true
	default:
		return false
	}
}

// embeddingsRequest is the validated client shape of the embeddings route.
type embeddingsRequest struct {
	Model string          `json:"model"`
	Input json.RawMessage `json:"input"`
}

// parseEmbeddingsRequest reads and validates the client request. Every
// refusal lands BEFORE admission, so a rejected request leaves no durable
// trace.
func parseEmbeddingsRequest(w http.ResponseWriter, r *http.Request) (embeddingsRequest, []byte, bool) {
	body, ok := readRouteBody(w, r)
	if !ok {
		return embeddingsRequest{}, nil, false
	}
	var req embeddingsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return embeddingsRequest{}, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return embeddingsRequest{}, nil, false
	}
	if len(req.Input) == 0 || string(req.Input) == "null" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "input is required")
		return embeddingsRequest{}, nil, false
	}
	return req, body, true
}

func (gw *gateway) embeddings(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := parseEmbeddingsRequest(w, r)
	if !ok {
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
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "embeddings", "embeddings are not supported for this provider") {
		return
	}
	// NEXT-18c (ADR-0001 §5.1): pre-check + reserve before the upstream
	// call. Embeddings have no generated output — out_cap = 0 in the bound
	// (§4.3); the wallet settles on the actual provider usage below.
	rctx, gate, ok := gw.reservePaidDispatch(r.Context(), w, r, "embeddings", admitted, nil, true)
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
	resp, limited, ok := relayEmbeddingsResponse(rctx, w, l, gate, client, admitted.Info, upstreamBody, apiKey)
	if resp != nil {
		// The settle stages below keep the body open (headers ride the
		// finish event); it closes after the reply is written.
		defer resp.Body.Close()
	}
	if !ok {
		return
	}
	n, source := embeddingsUsage(limited, req.Input)
	gw.finishBufferedJSONRoute(bufferedJSONFinish{
		rctx: rctx, w: w, admitted: admitted,
		usage:        provider.Usage{PromptTokens: n, TotalTokens: n, Source: source},
		providerName: providerName, endpoint: "embeddings", upstreamURL: upstreamURL,
		started: started, resp: resp, payload: limited,
	})
}

// relayEmbeddingsResponse performs the paid /v1/embeddings dispatch and
// buffers the upstream reply. On failure the refusal response was already
// written; the returned response (non-nil after a successful dial) still
// owns its open body, so the caller defers the close and the settle stages
// keep today's ordering.
func relayEmbeddingsResponse(rctx context.Context, w http.ResponseWriter, l *slog.Logger, gate *reservationGate, client *upstream.Client, info resolver.ModelInfo, upstreamBody []byte, apiKey string) (*http.Response, []byte, bool) {
	timeout := info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/embeddings", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return nil, nil, false
	}

	// Read one byte past the limit so an oversized upstream body is refused
	// instead of returning a partial embeddings payload.
	limited, err := io.ReadAll(io.LimitReader(resp.Body, embeddingsResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "failed to read upstream response")
		return resp, nil, false
	}
	if len(limited) > embeddingsResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "upstream response too large")
		return resp, nil, false
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return resp, nil, false
	}
	return resp, limited, true
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
