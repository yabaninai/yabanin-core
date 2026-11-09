package mockanthropic_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/testutil/mockanthropic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_MessagesJSON(t *testing.T) {
	srv := mockanthropic.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetResponse(200, mockanthropic.MessagesJSON("claude-3-5-sonnet", "Hello from Claude"))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := drain(resp.Body)
	assert.Contains(t, string(body), `claude-3-5-sonnet`)
	assert.Contains(t, string(body), `Hello from Claude`)
}

func TestServer_MessagesJSONWithCache(t *testing.T) {
	srv := mockanthropic.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetResponse(200, mockanthropic.MessagesJSONWithCache("claude-3", "hi", 100, 50))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := drain(resp.Body)
	assert.Contains(t, string(body), `"cache_read_input_tokens"`)
	assert.Contains(t, string(body), `"cache_creation_input_tokens"`)
}

func TestServer_FailFirstN_ThenSuccess(t *testing.T) {
	srv := mockanthropic.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.FailFirstN(2, 429, "rate limited")
	srv.SetResponse(200, mockanthropic.MessagesJSON("claude-3", "ok"))

	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		if i < 2 {
			assert.Equal(t, 429, resp.StatusCode)
			_ = resp.Body.Close()
		} else {
			assert.Equal(t, 200, resp.StatusCode)
			_ = resp.Body.Close()
		}
	}

	srv.ResetFail()
	assert.Equal(t, 3, srv.CallCount())
}

func TestServer_RecordsAnthropicHeaders(t *testing.T) {
	srv := mockanthropic.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetResponse(200, mockanthropic.MessagesJSON("claude-3", "ok"))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	_ = resp.Body.Close()

	rec := srv.Requests()
	require.Len(t, rec, 1)
	assert.Equal(t, "test-key", rec[0].Header.Get("x-api-key"))
	assert.Equal(t, "prompt-caching-2024-07-31", rec[0].Header.Get("anthropic-beta"))
}

func TestServer_StreamMode(t *testing.T) {
	srv := mockanthropic.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetStreamMode(true)
	srv.SetResponse(200, `{"type":"message_start","message":{"role":"assistant"}}\n\n{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}\n\ndata: [DONE]\n`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/messages", strings.NewReader(`{}`))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() // test drains the body below
	allBody, _ := drain(resp.Body)
	assert.Contains(t, string(allBody), "message_start")
	assert.Contains(t, string(allBody), "Hello")
}

func drain(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 4096)
	var result []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break // EOF or read error: return what was drained
		}
	}
	//nolint:nilerr // drain helper: read error only ends the drain
	return result, nil
}
