package mockopenai_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_JSONResponse(t *testing.T) {
	srv := mockopenai.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetResponse(200, `{"id":"test-1","choices":[{"message":{"content":"hi"}}]}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "test-1", body["id"])

	rec := srv.Requests()
	require.Len(t, rec, 1)
	assert.Equal(t, "POST", rec[0].Method)
	assert.Equal(t, "/v1/chat/completions", rec[0].Path)
}

func TestServer_FailFirstN_ThenSuccess(t *testing.T) {
	srv := mockopenai.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// First 2 calls fail with 429, then succeed.
	srv.FailFirstN(2, 429, "rate limited")
	srv.SetResponse(200, `{"id":"ok","choices":[{"message":{"content":"ok"}}]}`)

	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{}`))
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

	srv.ResetFail() // clean up for next test
	assert.Equal(t, 3, srv.CallCount())
}

func TestServer_StreamMode(t *testing.T) {
	srv := mockopenai.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetStreamMode(true)
	srv.SetResponse(200, "{\"id\":\"s1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: [DONE]\n")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	allBody, _ := drain(resp.Body)
	assert.Contains(t, string(allBody), "Hello")
}

func TestServer_RecordsHeaders(t *testing.T) {
	srv := mockopenai.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	srv.SetResponse(200, `{"id":"h1","choices":[{"message":{"content":"ok"}}]}`)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("X-Custom", "value")
	req.Header.Set("Authorization", "Bearer my-key")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	_ = resp.Body.Close()

	rec := srv.Requests()
	require.Len(t, rec, 1)
	assert.Equal(t, "value", rec[0].Header.Get("X-Custom"))
}

func TestServer_RawMessageJSONBody(t *testing.T) {
	srv := mockopenai.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	expectedModel := "gpt-4o"
	srv.SetResponse(200, `{"id":"r1","choices":[{"message":{"content":"ok"}}]}`)

	reqBody := `{"model":"` + expectedModel + `","messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(reqBody))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	_ = resp.Body.Close()

	rec := srv.Requests()
	require.Len(t, rec, 1)
	assert.Contains(t, rec[0].Body, expectedModel)
}

// drain reads all remaining bytes from the reader.
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
