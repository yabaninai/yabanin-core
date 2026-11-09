package cli

// Batch error export evidence (N07-P04-T04, in-fence slice): the executor
// writes every failed line to a purpose=batch.error JSONL file that the
// org-scoped files surface must expose exactly like any other file, while
// the batch wire object keeps error_file_id absent until errors exist.
// The all-failed export shape (response:null + per-line error.message),
// the batch.error metadata, foreign-org 404 semantics and the
// no-errors-no-error-file rule are pinned here; the happy-path mixed batch
// already has TestBatchEndpoints_FailedLine_ErrorFile_Integration.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errExportLine is one error-file JSONL entry (OpenAI batch error shape).
type errExportLine struct {
	ID       string          `json:"id"`
	CustomID string          `json:"custom_id"`
	Response json.RawMessage `json:"response"`
	Error    struct {
		Message string `json:"message"`
	} `json:"error"`
}

func TestBatchEndpoints_AllFailed_ErrorExport_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	// Model "bad" resolves to an unreachable upstream, so every line fails.
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("allfail")

	content := []byte(lineFor("c1", "bad", "hi") + "\n" + lineFor("c2", "bad", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	batchID := fileID(t, rec)

	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, completed, failed := batchStatus(t, rec)
	assert.Equal(t, "completed", status, "all-failed is still a completed batch")
	assert.Equal(t, 2, total)
	assert.Equal(t, 0, completed)
	assert.Equal(t, 2, failed)

	var doc struct {
		ErrorFileID  string `json:"error_file_id"`
		OutputFileID string `json:"output_file_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc), rec.Body.String())
	require.NotEmpty(t, doc.ErrorFileID)
	require.NotEmpty(t, doc.OutputFileID)

	// The error export carries every failed line, each with a null
	// response and a non-empty error message; ids derive from the batch.
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID+"/content", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rows := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	require.Len(t, rows, 2, "one error entry per failed line")
	seen := map[string]bool{}
	for _, row := range rows {
		var ln errExportLine
		require.NoError(t, json.Unmarshal([]byte(row), &ln), row)
		seen[ln.CustomID] = true
		assert.Equal(t, "null", string(ln.Response), "failed lines have no response payload")
		assert.NotEmpty(t, ln.Error.Message, "error.message explains the failure")
		assert.True(t, strings.HasPrefix(ln.ID, batchID+"-l"), "request id %q must derive from the batch", ln.ID)
	}
	assert.Equal(t, map[string]bool{"c1": true, "c2": true}, seen)

	// The output file still exists for an all-failed batch — zero bytes,
	// downloadable, never a missing id.
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID+"/results", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Body.String(), "zero successful lines: empty results body")
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.OutputFileID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The error file's metadata names the batch and its purpose.
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var meta struct {
		Filename string `json:"filename"`
		Purpose  string `json:"purpose"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &meta), rec.Body.String())
	assert.Equal(t, batchstore.PurposeBatchError, meta.Purpose)
	assert.Equal(t, batchID+"_errors.jsonl", meta.Filename)
}

func TestBatchEndpoints_ErrorFile_OrgIsolation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, orgB := testOrgs("erriso")

	content := []byte(lineFor("boom", "bad", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	batchID := fileID(t, rec)

	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var doc struct {
		ErrorFileID string `json:"error_file_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc), rec.Body.String())
	require.NotEmpty(t, doc.ErrorFileID)

	// The owner exports the error through the ordinary files surface.
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID+"/content", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"custom_id":"boom"`)

	// A foreign org gets 404 on metadata and content alike: the error
	// export never leaks another org's failures or the id's existence.
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID, orgB, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+doc.ErrorFileID+"/content", orgB, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// The foreign org's listing does not expose the error file either.
	rec = callJSON(t, router, http.MethodGet, "/v1/files", orgB, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), doc.ErrorFileID)
}

func TestBatchEndpoints_NoErrors_NoErrorFile_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("noerr")

	content := []byte(lineFor("c1", "m", "hi") + "\n" + lineFor("c2", "m", "hi") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	batchID := fileID(t, rec)

	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(context.Background()))

	// error_file_id stays off the wire when nothing failed (omitempty).
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+batchID, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), `"error_file_id"`)
	status, total, completed, failed := batchStatus(t, rec)
	assert.Equal(t, "completed", status)
	assert.Equal(t, 2, total)
	assert.Equal(t, 2, completed)
	assert.Equal(t, 0, failed)

	// And the org's file listing carries no batch.error artifact at all:
	// error files exist only when there are errors to export.
	rec = callJSON(t, router, http.MethodGet, "/v1/files", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), batchstore.PurposeBatchError)
	assert.Contains(t, rec.Body.String(), batchstore.PurposeBatchOutput)
}
