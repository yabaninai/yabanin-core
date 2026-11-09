package cli

// Batch submit/process/results, org isolation, idempotent cancel and the
// D4 billing-through-admission proof (line events carry the deterministic
// per-line request ids through the real chat pipeline). Skips in -short.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/batchstore"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testOrgs derives unique org ids per test (the disposable stand is shared
// by the whole package run; shuffled order must not leak rows between
// tests).
func testOrgs(name string) (string, string) {
	return fmt.Sprintf("org-%s-a-%d", name, time.Now().UnixNano()),
		fmt.Sprintf("org-%s-b-%d", name, time.Now().UnixNano())
}

func filesBatchGateway(t *testing.T, upstreamURL string, pool *pgxpool.Pool) *gateway {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.res = stubModelResolver{
		"m":   {ModelName: "m", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true},
		"bad": {ModelName: "bad", Provider: "openai", UpstreamURL: "http://127.0.0.1:1", Enabled: true},
	}
	gw.batchStore = batchstore.NewStore(pool, nil)
	return gw
}

// batchTestRouter mounts the files/batches handlers chi-style so URL params
// resolve exactly as in production routing (identity headers are set
// directly — goldenPost convention).
func batchTestRouter(gw *gateway) *chi.Mux {
	r := chi.NewRouter()
	r.Post("/v1/files", gw.filesUpload)
	r.Get("/v1/files", gw.filesList)
	r.Get("/v1/files/{id}", gw.filesGet)
	r.Get("/v1/files/{id}/content", gw.filesContent)
	r.Delete("/v1/files/{id}", gw.filesDelete)
	r.Post("/v1/batches", gw.batchesCreate)
	r.Get("/v1/batches", gw.batchesList)
	r.Get("/v1/batches/{id}", gw.batchesGet)
	r.Post("/v1/batches/{id}/cancel", gw.batchesCancel)
	r.Get("/v1/batches/{id}/results", gw.batchesResults)
	return r
}

func uploadFile(t *testing.T, router *chi.Mux, org, filename, purpose string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, werr := fw.Write(content)
	require.NoError(t, werr)
	if purpose != "" {
		require.NoError(t, mw.WriteField("purpose", purpose))
	}
	require.NoError(t, mw.Close())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Org-Id", org)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func callJSON(t *testing.T, router *chi.Mux, method, path, org, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Org-Id", org)
	req.Header.Set("X-API-Key-Id", "key-1")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func fileID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var doc struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc), rec.Body.String())
	return doc.ID
}

func batchStatus(t *testing.T, rec *httptest.ResponseRecorder) (string, int, int, int) {
	t.Helper()
	var doc struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Counts struct {
			Total     int `json:"total"`
			Completed int `json:"completed"`
			Failed    int `json:"failed"`
		} `json:"request_counts"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc), rec.Body.String())
	return doc.Status, doc.Counts.Total, doc.Counts.Completed, doc.Counts.Failed
}

func lineFor(customID, model, content string) string {
	return fmt.Sprintf(`{"custom_id":%q,"method":"POST","url":"/v1/chat/completions","body":{"model":%q,"messages":[{"role":"user","content":%q}]}}`,
		customID, model, content)
}

func TestFilesEndpoints_UploadRetrieveDelete_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, orgB := testOrgs("crud")

	content := []byte(lineFor("c1", "m", "hi") + "\n")

	// Bad purpose is explicit, not silent.
	rec := uploadFile(t, router, orgA, "f.jsonl", "fine-tune", content)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	rec = uploadFile(t, router, orgA, "f.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	id := fileID(t, rec)
	assert.True(t, strings.HasPrefix(id, "file-"))
	var obj struct {
		Object  string `json:"object"`
		Bytes   int    `json:"bytes"`
		Purpose string `json:"purpose"`
		Status  string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &obj))
	assert.Equal(t, "file", obj.Object)
	assert.Equal(t, len(content), obj.Bytes)
	assert.Equal(t, "batch", obj.Purpose)
	assert.Equal(t, "uploaded", obj.Status)

	// List.
	rec = callJSON(t, router, http.MethodGet, "/v1/files", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), id)

	// Detail + content round-trip.
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+id, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+id+"/content", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, content, rec.Body.Bytes())

	// Foreign org: existence hidden (404 everywhere).
	for _, probe := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/files/" + id},
		{http.MethodGet, "/v1/files/" + id + "/content"},
		{http.MethodDelete, "/v1/files/" + id},
	} {
		rec := callJSON(t, router, probe.method, probe.path, orgB, "")
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", probe.method, probe.path, rec.Body.String())
	}

	// Delete by the owning org; repeated delete is a 404.
	rec = callJSON(t, router, http.MethodDelete, "/v1/files/"+id, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"deleted":true`)
	rec = callJSON(t, router, http.MethodDelete, "/v1/files/"+id, orgA, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

func TestFilesEndpoints_413Cap_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("cap")

	rec := uploadFile(t, router, orgA, "big.bin", "batch", make([]byte, batchstore.MaxFileSizeBytes+1))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "file_too_large")
	// Nothing persisted.
	files, err := gw.batchStore.ListFiles(context.Background(), orgA, 100)
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestBatchEndpoints_SubmitProcessResults_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	var upstreamBodies []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamBodies = append(upstreamBodies, string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("submit")

	var events []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "chat.completions" {
			events = append(events, e)
		}
	})
	t.Cleanup(restore)

	content := []byte(lineFor("c1", "m", "one") + "\n" + lineFor("c2", "m", "two") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)

	// Submit.
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA,
		`{"input_file_id":"`+fid+`","metadata":{"env":"test"}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, _, _ := batchStatus(t, rec)
	assert.Equal(t, "validating", status)
	assert.Equal(t, 2, total)
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	batchID := created.ID

	// Results before completion refuse explicitly.
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID+"/results", orgA, "")
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// The executor drains the batch through the REAL chat pipeline (D4):
	// each line rides admission + upstream + accounting.
	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, completed, failed := batchStatus(t, rec)
	assert.Equal(t, "completed", status)
	assert.Equal(t, 2, total)
	assert.Equal(t, 2, completed)
	assert.Equal(t, 0, failed)

	// Billing-through-admission proof: two chat events with the
	// deterministic per-line request ids, org-scoped.
	require.Len(t, events, 2)
	for _, ev := range events {
		assert.Equal(t, orgA, ev.OrgID)
		assert.Equal(t, "request.completed", ev.EventType)
		assert.True(t, strings.HasPrefix(ev.RequestID, batchID+"-l"), "request id %q must derive from the batch", ev.RequestID)
	}

	// Results JSONL: one entry per successful line with the response body.
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID+"/results", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	out := rec.Body.String()
	assert.Contains(t, out, `"custom_id":"c1"`)
	assert.Contains(t, out, `"custom_id":"c2"`)
	assert.Contains(t, out, "cmpl-ok")
	for _, body := range upstreamBodies {
		assert.Contains(t, body, `"model":"m"`)
	}

	// List shows the batch.
	rec = callJSON(t, router, http.MethodGet, "/v1/batches", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), batchID)
}

func TestBatchEndpoints_FailedLine_ErrorFile_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("failline")

	content := []byte(lineFor("ok", "m", "hi") + "\n" + lineFor("boom", "bad", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))

	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+created.ID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, completed, failed := batchStatus(t, rec)
	assert.Equal(t, "completed", status)
	assert.Equal(t, 2, total)
	assert.Equal(t, 1, completed)
	assert.Equal(t, 1, failed)

	var doc struct {
		ErrorFileID  string `json:"error_file_id"`
		OutputFileID string `json:"output_file_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.ErrorFileID)
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID+"/content", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"custom_id":"boom"`)
}

func TestBatchEndpoints_SubmitValidation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, orgB := testOrgs("validation")

	upload := func(body string) string {
		rec := uploadFile(t, router, orgA, "b.jsonl", "batch", []byte(body))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return fileID(t, rec)
	}

	cases := []struct {
		name string
		body string
		want string
	}{
		{"bad json", "{not json}\n", "invalid JSON"},
		{"missing custom_id", `{"method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}` + "\n", "custom_id is required"},
		{"wrong url", `{"custom_id":"c","method":"POST","url":"/v1/embeddings","body":{"model":"m"}}` + "\n", "only /v1/chat/completions"},
		{"stream refused", `{"custom_id":"c","method":"POST","url":"/v1/chat/completions","body":{"model":"m","stream":true,"messages":[]}}` + "\n", "streaming is not supported"},
		{"missing model", `{"custom_id":"c","method":"POST","url":"/v1/chat/completions","body":{"messages":[]}}` + "\n", "body.model is required"},
		{"empty file", "\n\n", "no request lines"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := upload(tc.body)
			rec := callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+id+`"}`)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.want)
		})
	}

	// Missing input_file_id.
	rec := callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// Foreign input file: 404 semantics.
	own := upload(lineFor("c", "m", "hi") + "\n")
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgB, `{"input_file_id":"`+own+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

func TestBatchEndpoints_TooManyLines_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("toomany")

	var b strings.Builder
	for i := 0; i <= batchstore.MaxBatchLines; i++ {
		b.WriteString(lineFor(fmt.Sprintf("c%d", i), "m", "hi") + "\n")
	}
	rec := uploadFile(t, router, orgA, "big.jsonl", "batch", []byte(b.String()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	id := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+id+`"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "too_many_requests_in_batch")
}

func TestBatchEndpoints_CancelIdempotent_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("cancel")

	content := []byte(lineFor("c1", "m", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))

	// Cancel before execution: terminal immediately.
	rec = callJSON(t, router, http.MethodPost, "/v1/batches/"+created.ID+"/cancel", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, _, _, _ := batchStatus(t, rec)
	assert.Equal(t, "cancelled", status)

	// «Повтор cancel»: idempotent — same object, no second side effect.
	rec = callJSON(t, router, http.MethodPost, "/v1/batches/"+created.ID+"/cancel", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, _, _, _ = batchStatus(t, rec)
	assert.Equal(t, "cancelled", status)

	// The executor never picks a cancelled batch up.
	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+created.ID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, _, completed, _ := batchStatus(t, rec)
	assert.Equal(t, "cancelled", status)
	assert.Equal(t, 0, completed)

	// Cancel on a COMPLETED batch is the explicit terminal-state refusal.
	rec = uploadFile(t, router, orgA, "b2.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid2 := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid2+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var created2 struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created2))
	require.NoError(t, exec.Tick(context.Background()))
	rec = callJSON(t, router, http.MethodPost, "/v1/batches/"+created2.ID+"/cancel", orgA, "")
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "batch_already_terminal")
}

func TestBatchEndpoints_OrgIsolation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, orgB := testOrgs("isol")

	content := []byte(lineFor("c1", "m", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))

	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	// Org B sees nothing of org A's batch surface: status, results, cancel
	// and the org-B file listing all miss (404).
	for _, probe := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/batches/" + created.ID},
		{http.MethodGet, "/v1/batches/" + created.ID + "/results"},
		{http.MethodPost, "/v1/batches/" + created.ID + "/cancel"},
	} {
		rec := callJSON(t, router, probe.method, probe.path, orgB, "")
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", probe.method, probe.path, rec.Body.String())
	}
	rec = callJSON(t, router, http.MethodGet, "/v1/batches", orgB, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), created.ID)
}
