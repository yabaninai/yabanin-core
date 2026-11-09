package cli

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

type unknownModelPool struct{}

func (unknownModelPool) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return unknownModelRow{}
}

func (unknownModelPool) Close() {}

type unknownModelRow struct{}

func (unknownModelRow) Scan(...interface{}) error { return pgx.ErrNoRows }

func TestChat_UnknownModel_Reject404(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	gw.unknownModelPolicy = "reject"
	gw.res = resolver.NewResolver(unknownModelPool{}, "fb-model", 0, slog.Default())

	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "model_not_found")
	assert.Contains(t, rec.Body.String(), "claude-sonnet-4-6")
	assert.Empty(t, rec.Header().Get("X-Yabanin-Model-Fallback"))
}

func TestChat_UnknownModel_FallbackHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.DecisionHeaderEnabled = true
	gw.unknownModelPolicy = "fallback"
	gw.res = resolver.NewResolver(unknownModelPool{}, "fb-model", 0, slog.Default())

	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "claude-sonnet-4-6->fb-model", rec.Header().Get("X-Yabanin-Model-Fallback"))
	assert.Contains(t, rec.Header().Get("X-Yabanin-Decision"), "unknown_model_fallback")
}
