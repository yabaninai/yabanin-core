package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func (gw *gateway) countTokens(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAnthropicStatus(w, http.StatusBadRequest, "request body too large or malformed")
		return
	}
	var probe struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &probe) != nil || probe.Model == "" {
		writeAnthropicStatus(w, http.StatusBadRequest, "model is required")
		return
	}
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint:        "messages.count_tokens",
		Model:           probe.Model,
		Body:            body,
		SkipSpendChecks: true,
	})
	if !ok {
		return
	}
	if admitted.Info.Provider == "anthropic" {
		gw.countTokensPassthrough(w, r, admitted)
		return
	}
	w.Header().Set("X-Yabanin-Estimated", "true")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"input_tokens": estimateMessageTokens(body)})
}

func estimateMessageTokens(body []byte) int {
	var doc struct {
		System   json.RawMessage `json:"system"`
		Messages json.RawMessage `json:"messages"`
		Tools    json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return 0
	}
	n := len(doc.System) + len(doc.Messages) + len(doc.Tools)
	if n == 0 {
		return 0
	}
	return (n + 3) / 4
}

func (gw *gateway) countTokensPassthrough(w http.ResponseWriter, r *http.Request, admitted admitted) {
	l := logctx.From(r.Context(), gw.log)
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}
	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	apiKey := admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL := gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, "anthropic")
	if err != nil {
		l.Warn("upstream client unavailable", "provider", "anthropic", "error", err.Error())
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return
	}
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/messages/count_tokens", upstreamBody, apiKey, false, anthropicExtraHeaders(r))
	if err != nil {
		closeUpstream(l, resp)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			l.Debug("close upstream body", "error", cerr)
		}
	}()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, messagesResponseLimit))
	if err != nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	copyAnthropicPassthrough(w.Header(), resp.Header)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(limited)
}
