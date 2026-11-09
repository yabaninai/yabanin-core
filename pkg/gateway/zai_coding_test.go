package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func TestAllowedUpstreamsForGateway(t *testing.T) {
	// No operator list and no provider: nothing is allowed (fail-closed).
	assert.Nil(t, allowedUpstreamsForGateway(nil, false, "", ""))
	// No operator list with a configured provider: egress defaults to exactly
	// the provider origin; the ZAI coding endpoint joins only when enabled.
	got := allowedUpstreamsForGateway(nil, true, "https://api.z.ai/api/coding/paas/v4", "https://api.openai.com")
	require.Len(t, got, 2)
	assert.Equal(t, "https://api.openai.com", got[0])
	assert.Equal(t, "https://api.z.ai/api/coding/paas/v4", got[1])
	// An explicit operator list keeps its strict meaning.
	got = allowedUpstreamsForGateway([]string{"https://api.openai.com"}, true, "https://api.z.ai/api/coding/paas/v4", "https://other.example")
	require.Len(t, got, 2)
	assert.Equal(t, "https://api.z.ai/api/coding/paas/v4", got[1])
}

func TestChatCompletions_OpenCodeToolLoopForwardsTools(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`))
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	body := opencodeToolLoopJSON("gpt-4")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, gotBody, `"tools"`)
	assert.Contains(t, gotBody, `"tool_call_id"`)
	assert.Contains(t, gotBody, `"max_tokens":32768`)
	assert.Contains(t, rec.Body.String(), `"tool_calls"`)
}

func TestChatCompletions_ZAICodingDisabled(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	gw.res = resolver.NewResolver(zaiModelPool{info: resolver.ModelInfo{
		ModelName: "glm-5.3",
		Provider:  "zai-coding",
		Enabled:   true,
	}}, "smart", 0, slog.Default())

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		bytes.NewReader(opencodeToolLoopJSON("glm-5.3")))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), apierrors.CodeProviderNotAuthorized)
}

func TestChatCompletions_ZAICodingUnsupportedModel(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	gw.cfg.ZAICodingEnabled = true
	gw.res = resolver.NewResolver(zaiModelPool{info: resolver.ModelInfo{
		ModelName: "gpt-4o",
		Provider:  "zai-coding",
		Enabled:   true,
	}}, "smart", 0, slog.Default())

	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), apierrors.CodeUnsupportedFeature)
}

func TestChatCompletions_ZAICodingQuotaAndPinnedURL(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"quota"}}`))
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = srv.URL
	gw.cfg.APIKey = "plan-key"
	gw.pool = upstream.NewPool(upstream.Options{BaseURL: srv.URL})
	gw.res = resolver.NewResolver(zaiModelPool{info: resolver.ModelInfo{
		ModelName:      "glm-5.3",
		Provider:       "zai-coding",
		UpstreamURL:    "https://evil.example/v1",
		UpstreamAPIKey: "plan-key",
		Enabled:        true,
	}}, "smart", 0, slog.Default())

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}`)))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), apierrors.CodeQuotaExhausted)
	assert.Equal(t, "/chat/completions", gotPath)
	assert.Equal(t, "Bearer plan-key", gotAuth)
	assert.NotContains(t, rec.Body.String(), "plan-key")
	assert.Contains(t, gotBody, `"glm-5.3"`)
}

func TestServeStream_ZAICodingForwardsTools(t *testing.T) {
	var gotBody, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = srv.URL
	info := resolver.ModelInfo{
		ModelName:   "glm-5.3",
		Provider:    "zai-coding",
		UpstreamURL: "https://evil.example",
		Enabled:     true,
	}
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info, opencodeToolLoopJSON("glm-5.3"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "/chat/completions", gotPath)
	assert.Contains(t, gotBody, `"tools"`)
	assert.Contains(t, rec.Body.String(), "data: [DONE]")
}

func opencodeToolLoopJSON(model string) []byte {
	return []byte(`{
		"model":"` + model + `",
		"max_tokens":32768,
		"messages":[
			{"role":"system","content":"You are a coding agent."},
			{"role":"user","content":[{"type":"text","text":"fix the test"}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"a.go\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"package a"}
		],
		"tools":[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}]
	}`)
}

type zaiModelPool struct {
	info resolver.ModelInfo
}

func (p zaiModelPool) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return zaiModelRow(p)
}

func (zaiModelPool) Close() {}

type zaiModelRow struct {
	info resolver.ModelInfo
}

func (r zaiModelRow) Scan(dest ...interface{}) error {
	assign := func(i int, v any) {
		switch p := dest[i].(type) {
		case *string:
			*p = v.(string)
		case *bool:
			*p = v.(bool)
		case *int64:
			*p = v.(int64)
		case *[]string:
			*p = v.([]string)
		}
	}
	region := r.info.Region
	if region == "" {
		region = "GLOBAL"
	}
	failover := r.info.FailoverModels
	if failover == nil {
		failover = []string{}
	}
	assign(0, r.info.ModelName)
	assign(1, r.info.DisplayName)
	assign(2, r.info.Tier)
	assign(3, r.info.UpstreamURL)
	assign(4, "")
	assign(5, r.info.Provider)
	assign(6, failover)
	assign(7, r.info.Enabled)
	assign(8, int64(0))
	assign(9, region)
	return nil
}
