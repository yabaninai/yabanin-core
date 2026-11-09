package cli

// boundary matrix (DB-gated, skips in -short): the named negative
// scenarios at their exact edges — the 413 size cap at the byte boundary,
// malformed batch JSONL with line-number precision, executor crash resume
// with partial results preserved and re-execution not re-billed, and the
// retention sweep observed through the HTTP surface. Complements the -02
// suites (CRUD/isolation/submit-validation/cancel) with the boundary cases
// the failure card must reproduce.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/batchstore"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilesBoundary_ExactCap_Integration pins the 413 boundary at the byte:
// a file of exactly MaxFileSizeBytes is accepted (the part limit-reader
// must not off-by-one the cap), cap+1 stays 413 with nothing persisted.
func TestFilesBoundary_ExactCap_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("exactcap")

	rec := uploadFile(t, router, orgA, "exact.bin", "batch", make([]byte, batchstore.MaxFileSizeBytes))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	id := fileID(t, rec)
	assert.NotEmpty(t, id)

	// Cleanup keeps the shared stand lean (the 100 MiB payload is swept).
	rec = callJSON(t, router, http.MethodDelete, "/v1/files/"+id, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = uploadFile(t, router, orgA, "over.bin", "batch", make([]byte, batchstore.MaxFileSizeBytes+1))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "file_too_large")
	files, err := gw.batchStore.ListFiles(context.Background(), orgA, 100)
	require.NoError(t, err)
	assert.Empty(t, files, "the rejected upload must not persist anything")
}

// TestBatchBoundary_MalformedJSONL_Integration pins validation precision on
// MULTI-LINE files: the refusal names the offending line number (position,
// not just presence), the valid neighbours never execute, and no batch row
// is materialized from a rejected file.
func TestBatchBoundary_MalformedJSONL_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must never see a rejected batch: %s", r.URL.Path)
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("badjsonl")

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"invalid JSON on line 2",
			lineFor("c1", "m", "one") + "\n{not json}\n" + lineFor("c3", "m", "three") + "\n",
			"line 2: invalid JSON",
		},
		{
			"missing custom_id on line 2",
			lineFor("c1", "m", "one") + "\n" + `{"method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}` + "\n",
			"line 2: custom_id is required",
		},
		{
			"non-object body",
			lineFor("c1", "m", "one") + "\n" + `{"custom_id":"c2","method":"POST","url":"/v1/chat/completions","body":"a string"}` + "\n",
			"line 2: body must be a JSON object",
		},
		{
			"wrong method on line 3",
			lineFor("c1", "m", "one") + "\n" + lineFor("c2", "m", "two") + "\n" +
				`{"custom_id":"c3","method":"GET","url":"/v1/chat/completions","body":{"model":"m"}}` + "\n",
			"line 3: only POST requests are supported",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := uploadFile(t, router, orgA, "b.jsonl", "batch", []byte(tc.body))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			fid := fileID(t, rec)
			rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.want)
			assert.Contains(t, rec.Body.String(), "invalid_batch_file")
		})
	}

	// Nothing was materialized: the org has files but zero batches.
	batches, err := gw.batchStore.ListBatches(context.Background(), orgA, 100)
	require.NoError(t, err)
	assert.Empty(t, batches, "rejected submissions must not create batch rows")
}

// TestBatchBoundary_CrashResumePartialResults_Integration pins the E4
// boundary through the HTTP surface: an executor crash after line 1 leaves
// a durable partial state; the resumed executor finishes lines 2-3 only
// (same deterministic request ids, no re-billing of line 1), and the result
// file carries the pre-crash and post-crash lines together.
func TestBatchBoundary_CrashResumePartialResults_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"done ` +
			fmt.Sprintf("%d", len(raw)) + `"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`))
	}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("crashhttp")

	var events []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "chat.completions" {
			events = append(events, e)
		}
	})
	t.Cleanup(restore)

	content := []byte(lineFor("c1", "m", "one") + "\n" + lineFor("c2", "m", "two") + "\n" + lineFor("c3", "m", "three") + "\n")
	rec := uploadFile(t, router, orgA, "b.jsonl", "batch", content)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	fid := fileID(t, rec)
	rec = callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+fid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	bid := created.ID

	// The crash: the executor claimed the batch and durably completed line
	// 1, then died (lease expires with no terminal state).
	ctx := context.Background()
	claimed, err := gw.batchStore.ClaimBatch(ctx, 10*time.Minute, 5)
	require.NoError(t, err)
	require.Equal(t, bid, claimed.ID)
	require.NoError(t, gw.batchStore.CompleteLine(ctx, bid, 1, batchstore.LineDone, http.StatusOK,
		[]byte(`{"id":"cmpl-precrash"}`), nil))
	_, err = pool.Exec(ctx,
		"UPDATE batch_jobs SET lease_until = now() - interval '1 second' WHERE id = $1", bid)
	require.NoError(t, err)
	require.NoError(t, gw.batchStore.RecoverExpiredLeases(ctx, 5))
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+bid, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, completed, failed := batchStatus(t, rec)
	assert.Equal(t, "validating", status, "the crashed batch re-enters the queue")
	assert.Equal(t, 3, total)
	assert.Equal(t, 1, completed)
	assert.Equal(t, 0, failed)

	// Resume: a fresh executor drains the remainder through the real
	// pipeline (D4) — lines 2 and 3 only.
	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(ctx))

	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+bid, orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	status, total, completed, failed = batchStatus(t, rec)
	assert.Equal(t, "completed", status)
	assert.Equal(t, 3, total)
	assert.Equal(t, 3, completed)
	assert.Equal(t, 0, failed)

	// D4 no-re-billing: exactly two chat events (lines 2-3), deterministic
	// per-line request ids; the pre-crash line never re-executed.
	require.Len(t, events, 2)
	for _, ev := range events {
		assert.Equal(t, orgA, ev.OrgID)
		assert.True(t, ev.RequestID == batchstore.RequestIDForLine(bid, 2) ||
			ev.RequestID == batchstore.RequestIDForLine(bid, 3), "request id %q", ev.RequestID)
	}

	// Partial results survive: the output file has the pre-crash line 1
	// payload AND the post-crash lines.
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+bid+"/results", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	out := rec.Body.String()
	assert.Contains(t, out, "cmpl-precrash")
	assert.Contains(t, out, `"custom_id":"c2"`)
	assert.Contains(t, out, `"custom_id":"c3"`)
	assert.Contains(t, out, batchstore.RequestIDForLine(bid, 1))
	assert.NotContains(t, out, `"error":{"message"`)
}

// TestBatchBoundary_RetentionCleanup_Integration pins the D3 30-day window
// through the HTTP surface: rows created beyond the horizon vanish on the
// sweep (file 404, batch 404), fresh rows survive.
func TestBatchBoundary_RetentionCleanup_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	orgA, _ := testOrgs("retain")
	ctx := context.Background()

	// Old world: created 31 days ago (pinned store clock).
	past := time.Now().Add(-31 * 24 * time.Hour)
	gw.batchStore.SetClock(func() time.Time { return past })
	oldFile := uploadFile(t, router, orgA, "old.jsonl", "batch", []byte(lineFor("c1", "m", "hi")+"\n"))
	require.Equal(t, http.StatusOK, oldFile.Code, oldFile.Body.String())
	oldID := fileID(t, oldFile)
	rec := callJSON(t, router, http.MethodPost, "/v1/batches", orgA, `{"input_file_id":"`+oldID+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	oldBatch := struct {
		ID string `json:"id"`
	}{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &oldBatch))

	// Fresh world: back to the real clock.
	gw.batchStore.SetClock(time.Now)
	freshFile := uploadFile(t, router, orgA, "fresh.jsonl", "batch", []byte(lineFor("c1", "m", "hi")+"\n"))
	require.Equal(t, http.StatusOK, freshFile.Code, freshFile.Body.String())
	freshID := fileID(t, freshFile)

	// The executor's first tick runs the retention sweep (cadence-gated
	// from zero) — the expired rows go first, nothing is claimable after.
	exec := batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, nil)
	require.NoError(t, exec.Tick(ctx))

	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+oldID, orgA, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, "expired file must be swept")
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+oldID+"/content", orgA, "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = callJSON(t, router, http.MethodGet, "/v1/batches/"+oldBatch.ID, orgA, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, "expired batch must be swept")
	rec = callJSON(t, router, http.MethodGet, "/v1/files/"+freshID, orgA, "")
	assert.Equal(t, http.StatusOK, rec.Code, "fresh file survives the sweep")

	// The org's listing no longer leaks the swept ids either.
	rec = callJSON(t, router, http.MethodGet, "/v1/files", orgA, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), oldID)
	assert.Contains(t, rec.Body.String(), freshID)
	assert.NotContains(t, rec.Body.String(), oldBatch.ID)
}
