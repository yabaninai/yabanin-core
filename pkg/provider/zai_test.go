package provider_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/provider"
)

func TestFactory_New_ZAICoding(t *testing.T) {
	p, err := provider.New("zai-coding")
	require.NoError(t, err)
	assert.Equal(t, "zai-coding", p.Name())
	assert.Equal(t, "/chat/completions", p.Path(false))
}

func TestZAICoding_PrepareRequest_PinsOfficialEndpoint(t *testing.T) {
	req, err := provider.ZAICoding{}.PrepareRequest(
		context.Background(),
		"https://evil.example/v1", "/v1/chat/completions",
		[]byte(`{"model":"glm-5.3"}`), "plan-key", false,
	)
	require.NoError(t, err)
	assert.Equal(t, "https://api.z.ai/api/coding/paas/v4/chat/completions", req.URL.String())
	assert.Equal(t, "Bearer plan-key", req.Header.Get("Authorization"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"glm-5.3"}`, string(body))
}

func TestZAICoding_PrepareRequest_StreamAccept(t *testing.T) {
	req, err := provider.ZAICoding{}.PrepareRequest(
		context.Background(), "", "", []byte(`{}`), "k", true,
	)
	require.NoError(t, err)
	assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
	assert.True(t, strings.HasSuffix(req.URL.Path, "/chat/completions"))
}

func TestZAICoding_PrepareRequest_TestOverride(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer srv.Close()

	z := provider.NewZAICodingForTest(srv.URL)
	req, err := z.PrepareRequest(context.Background(), "https://ignored", z.Path(false), []byte(`{}`), "secret", false)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, "/chat/completions", gotPath)
	assert.Equal(t, "Bearer secret", gotAuth)
}

func TestZAICoding_TranslatePassthroughAndUsage(t *testing.T) {
	in := []byte(`{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function"}]}`)
	out, err := provider.ZAICoding{}.TranslateRequest(in)
	require.NoError(t, err)
	assert.Equal(t, in, out)

	resp := []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,"prompt_tokens_details":{"cached_tokens":1}}}`)
	u := provider.ZAICoding{}.ParseUsage(resp)
	assert.Equal(t, int64(3), u.PromptTokens)
	assert.Equal(t, int64(2), u.CompletionTokens)
	assert.Equal(t, int64(5), u.TotalTokens)
	assert.Equal(t, int64(1), u.CacheReadTokens)
}

func TestZAICodingModelAllowed(t *testing.T) {
	assert.True(t, provider.ZAICodingModelAllowed("GLM-5.3"))
	assert.True(t, provider.ZAICodingModelAllowed("glm-5.3-flash"))
	assert.True(t, provider.ZAICodingModelAllowed("glm-5-turbo"))
	assert.True(t, provider.ZAICodingModelAllowed("glm-4.7"))
	assert.True(t, provider.ZAICodingModelAllowed("glm-5.2"))
	assert.False(t, provider.ZAICodingModelAllowed("gpt-4o"))
	assert.False(t, provider.ZAICodingModelAllowed(""))
}

func TestMapZAICodingStatus(t *testing.T) {
	st, typ, code := provider.MapZAICodingStatus(401)
	assert.Equal(t, http.StatusForbidden, st)
	assert.Equal(t, "permission_denied_error", typ)
	assert.Equal(t, "provider_not_authorized", code)

	st, typ, code = provider.MapZAICodingStatus(429)
	assert.Equal(t, http.StatusTooManyRequests, st)
	assert.Equal(t, "rate_limit_exceeded", typ)
	assert.Equal(t, "quota_exhausted", code)

	st, typ, code = provider.MapZAICodingStatus(503)
	assert.Equal(t, http.StatusBadGateway, st)
	assert.Equal(t, "api_error", typ)
	assert.Empty(t, code)
}

func TestZAICodingEndpoint(t *testing.T) {
	assert.Equal(t, provider.ZAICodingOfficialEndpoint, provider.ZAICodingEndpoint(""))
	assert.Equal(t, "http://127.0.0.1:9", provider.ZAICodingEndpoint("http://127.0.0.1:9/"))
}

func TestPinZAICodingBaseURL(t *testing.T) {
	assert.Equal(t, provider.ZAICodingOfficialEndpoint, provider.PinZAICodingBaseURL("https://evil.example/v1"))
	assert.Equal(t, provider.ZAICodingOfficialEndpoint, provider.PinZAICodingBaseURL(""))
	assert.Equal(t, "http://127.0.0.1:1234", provider.PinZAICodingBaseURL("http://127.0.0.1:1234/"))
}
