package cli

// N06-P07-T03 acceptance: EVERY supported inference endpoint participates in
// request admission (the §5 gate is not optional anywhere), and the batch
// executor cannot bypass it — each line rides the gateway's own chat
// pipeline with the batch id as its task tag, so a malformed tag fails the
// line exactly like an interactive request.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// newAdmissionMatrixGateway builds the same hand-wired gateway the endpoint
// tests use: strict auth, one resolved model "m", a mock upstream that
// counts every hit, and an event counter.
func newAdmissionMatrixGateway(t *testing.T) (*gateway, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var hits, events atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(server.Close)

	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
	gw.eventNote = func(*eventpub.Event) { events.Add(1) }
	return gw, &hits, &events
}

func postMatrixRequest(t *testing.T, gw *gateway, path, contentType, body string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", contentType)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// assertTaskDenial checks the denial the same way for both envelopes: the
// OpenAI shape carries code invalid_task_id; the Anthropic group re-envelops
// the same 400 as invalid_request_error with the task-rule message intact.
func assertTaskDenial(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	// Both envelopes preserve the human message naming the header rule.
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	require.Contains(t, env.Error.Message, "X-Yabanin-Task", rec.Body.String())
	// The OpenAI group names the code in error.type; the Anthropic group
	// re-envelops to its own invalid_request_error taxonomy.
	if code := errorType(t, rec); code == "invalid_task_id" {
		require.Equal(t, "invalid_task_id", code)
	}
}

// TestEndpointAdmission_TaskTagDenialMatrix drives every admitted endpoint
// through the REAL route stack with a malformed X-Yabanin-Task: each one
// must answer 400 invalid_task_id before any upstream traffic or event.
func TestEndpointAdmission_TaskTagDenialMatrix(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		contentType string
		body        string
	}{
		{"chat_completions", "/v1/chat/completions", "application/json", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`},
		{"completions", "/v1/completions", "application/json", `{"model":"m","prompt":"hi"}`},
		{"embeddings", "/v1/embeddings", "application/json", `{"model":"m","input":"hi"}`},
		{"rerank", "/v1/rerank", "application/json", `{"model":"m","query":"q","documents":["d"]}`},
		{"moderations", "/v1/moderations", "application/json", `{"model":"m","input":"hi"}`},
		{"images_generations", "/v1/images/generations", "application/json", `{"model":"m","prompt":"p"}`},
		{"audio_speech", "/v1/audio/speech", "application/json", `{"model":"m","input":"hi","voice":"alloy"}`},
		{"messages_native", "/v1/messages", "application/json", `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`},
		{"responses_native", "/v1/responses", "application/json", `{"model":"m","input":"hi"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw, hits, events := newAdmissionMatrixGateway(t)
			rec := postMatrixRequest(t, gw, tc.path, tc.contentType, tc.body,
				map[string]string{"X-Yabanin-Task": "bad task!"})
			assertTaskDenial(t, rec)
			require.Zero(t, hits.Load(), "an admission denial must precede all upstream traffic")
			require.Zero(t, events.Load(), "an admission denial settles no spend event")
		})
	}

	// audio/transcriptions is the one multipart endpoint.
	t.Run("audio_transcriptions", func(t *testing.T) {
		gw, hits, events := newAdmissionMatrixGateway(t)
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		require.NoError(t, mw.WriteField("model", "m"))
		fw, err := mw.CreateFormFile("file", "a.wav")
		require.NoError(t, err)
		_, err = fw.Write([]byte("RIFF"))
		require.NoError(t, err)
		require.NoError(t, mw.Close())

		rec := postMatrixRequest(t, gw, "/v1/audio/transcriptions", mw.FormDataContentType(), buf.String(),
			map[string]string{"X-Yabanin-Task": "bad task!"})
		assertTaskDenial(t, rec)
		require.Zero(t, hits.Load())
		require.Zero(t, events.Load())
	})
}

// TestEndpointAdmission_ControlWithoutTaskHeader proves the matrix denial
// comes from the task check and not from broken wiring: the same bodies
// without the header reach the mock upstream.
func TestEndpointAdmission_ControlWithoutTaskHeader(t *testing.T) {
	tests := []struct {
		name, path, body string
	}{
		{"chat_completions", "/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`},
		{"completions", "/v1/completions", `{"model":"m","prompt":"hi"}`},
		{"embeddings", "/v1/embeddings", `{"model":"m","input":"hi"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw, hits, _ := newAdmissionMatrixGateway(t)
			rec := postMatrixRequest(t, gw, tc.path, "application/json", tc.body, nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, int64(1), hits.Load())
		})
	}
}

// TestBatchLineRunner_SettlesWithDeterministicRequestID pins the batch
// non-bypass shape: the line runs through CreditGuard + chatCompletions and
// the completion event carries the deterministic per-line request id.
func TestBatchLineRunner_SettlesWithDeterministicRequestID(t *testing.T) {
	gw, hits, _ := newAdmissionMatrixGateway(t)

	var ev *eventpub.Event
	// Chat's finisher never fires the gw.eventNote hook — observe at the
	// publish boundary instead.
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	b := &batchstore.Batch{ID: "batch_123", OrgID: "org-batch", APIKeyID: "key-batch"}
	ln := batchstore.Line{
		BatchID:     b.ID,
		LineNo:      1,
		CustomID:    "c1",
		RequestID:   "req_batch_line_1",
		RequestBody: []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`),
	}

	res := gw.batchLineRunner(context.Background(), b, ln)
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, int64(1), hits.Load())
	require.NotNil(t, ev)
	require.Equal(t, "request.completed", ev.EventType)
	require.Equal(t, "req_batch_line_1", ev.RequestID, "the deterministic per-line id must ride the settled event")
	require.Equal(t, "org-batch", ev.OrgID)
	require.Equal(t, "key-batch", ev.APIKeyID)
}

// TestBatchLineRunner_CannotBypassAdmission proves the executor synthesizes
// a REAL request: the batch id rides X-Yabanin-Task, so a malformed one
// fails the line with the same invalid_task_id denial an interactive caller
// gets — with zero upstream traffic.
func TestBatchLineRunner_CannotBypassAdmission(t *testing.T) {
	gw, hits, events := newAdmissionMatrixGateway(t)

	b := &batchstore.Batch{ID: "bad task!", OrgID: "org-batch"}
	ln := batchstore.Line{
		BatchID:     b.ID,
		LineNo:      1,
		CustomID:    "c1",
		RequestID:   "req_batch_line_2",
		RequestBody: []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`),
	}

	res := gw.batchLineRunner(context.Background(), b, ln)
	require.Equal(t, http.StatusBadRequest, res.Status)
	require.Contains(t, string(res.Body), "invalid_task_id")
	require.Zero(t, hits.Load(), "a bypassing executor would show upstream hits here")
	require.Zero(t, events.Load())
}
