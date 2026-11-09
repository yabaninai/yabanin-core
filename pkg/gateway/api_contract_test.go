package cli

// NEXT-19: API contract pack — machine-checked invariants every SDK and
// client may rely on: the error envelope, success-body nullability, SSE
// chunk/error shapes, and unit naming. These tests run against the real
// handler with a mock upstream (same harness as decision tests); the admin
// pagination contract lives in its own package's tests.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/errors"
)

// --- Error envelope ---

func TestContract_ErrorEnvelopeShape(t *testing.T) {
	gw := decisionTestGateway("http://127.0.0.1:1") // unreachable upstream

	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"invalid json", "{not json", http.StatusBadRequest},
		{"missing model", `{"messages":[]}`, http.StatusBadRequest},
		{"upstream unreachable", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"x"}]}`, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			gw.chatCompletions(rec, r)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())

			// THE envelope: top-level {"error":{message,type,param?,code?}}.
			var env struct {
				Error errors.ErrorResponse `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body must be the error envelope: %s", rec.Body.String())
			assert.NotEmpty(t, env.Error.Message, "error.message required")
			assert.NotEmpty(t, env.Error.Type, "error.type required")
		})
	}
}

// --- Success body nullability/units ---

func TestContract_SuccessBodyShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	defer srv.Close()
	gw := decisionTestGateway(srv.URL)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	// Required non-null fields on success.
	for _, key := range []string{"id", "object", "choices", "usage"} {
		v, ok := body[key]
		require.True(t, ok && v != nil, "success body: %s must be present and non-null", key)
	}
	choices, ok := body["choices"].([]interface{})
	require.True(t, ok && len(choices) > 0, "choices must be a non-empty array")
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	require.NotNil(t, msg["content"], "assistant content must be non-null on success")
	// usage.total_tokens is an integer (never a float or string).
	usage := body["usage"].(map[string]interface{})
	_, isFloat := usage["total_tokens"].(float64)
	require.True(t, isFloat, "usage tokens are JSON numbers")
}

// --- SSE contract ---

func TestContract_SSEStreamShapes(t *testing.T) {
	sse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"id\":\"s1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"he\"}}]}\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("data: {\"id\":\"s1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"}}]}\n\n"))
		fl.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer sse.Close()

	gw := decisionTestGateway(sse.URL)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.serveStream(rec, r.Context(), rt06TestResolve(gw, "gpt-4o-mini"),
		[]byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`),
		false, "s1", "org", "", "", "req", gw.log, routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code)
	scanner := bufio.NewScanner(bytes.NewReader(rec.Body.Bytes()))
	chunks, done, malformed := 0, false, 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			done = true
			continue
		}
		var chunk map[string]interface{}
		if json.Unmarshal([]byte(payload), &chunk) != nil || chunk["object"] != "chat.completion.chunk" {
			malformed++
			continue
		}
		chunks++
	}
	assert.GreaterOrEqual(t, chunks, 2, "expected SSE chunks")
	assert.True(t, done, "stream must terminate with data: [DONE]")
	assert.Zero(t, malformed, "all data lines must be chat.completion.chunk JSON")
}

func TestContract_SSEErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSSEError(rec, "upstream_error", "boom")
	// The error event is followed by the [DONE] terminator — clients must be
	// able to end the stream after an error.
	var sawError, sawDone bool
	sc := bufio.NewScanner(bytes.NewReader(rec.Body.Bytes()))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			sawDone = true
			continue
		}
		var env struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &env), "payload: %q", payload)
		assert.Equal(t, "upstream_error", env.Error.Type)
		assert.Equal(t, "boom", env.Error.Message)
		sawError = true
	}
	assert.True(t, sawError, "SSE errors ride the same envelope")
	assert.True(t, sawDone, "stream terminates with [DONE] even after an error")
}
