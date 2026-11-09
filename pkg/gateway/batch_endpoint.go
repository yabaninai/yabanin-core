package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/requestid"
)

// status, cancel idempotently, download results. Lines execute through the
// gateway's own chat pipeline (ratified D4: batch billing rides the same
// admission/reservation/settlement path as interactive traffic).

func (gw *gateway) batchesStoreOr503(w http.ResponseWriter, r *http.Request) (*batchstore.Store, string, bool) {
	if gw.batchStore == nil {
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"batch API requires a database-backed gateway")
		return nil, "", false
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "org resolution failed")
		return nil, "", false
	}
	return gw.batchStore, orgID, true
}

// batchJSONObject is the wire shape of a batch (OpenAI-compatible fields).
type batchJSONObject struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	Endpoint      string          `json:"endpoint"`
	Status        string          `json:"status"`
	RequestCounts batchCounts     `json:"request_counts"`
	InputFileID   string          `json:"input_file_id"`
	OutputFileID  string          `json:"output_file_id,omitempty"`
	ErrorFileID   string          `json:"error_file_id,omitempty"`
	CreatedAt     int64           `json:"created_at"`
	ExpiresAt     int64           `json:"expires_at"`
	CompletedAt   int64           `json:"completed_at,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type batchCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

func writeBatchObject(w http.ResponseWriter, b *batchstore.Batch) {
	obj := batchJSONObject{
		ID:       b.ID,
		Object:   "batch",
		Endpoint: b.Endpoint,
		Status:   b.Status,
		RequestCounts: batchCounts{
			Total:     b.TotalCount,
			Completed: b.CompletedCount,
			Failed:    b.FailedCount,
		},
		InputFileID:  b.InputFileID,
		OutputFileID: b.OutputFileID,
		ErrorFileID:  b.ErrorFileID,
		CreatedAt:    b.CreatedAt.Unix(),
		ExpiresAt:    b.ExpiresAt.Unix(),
		LastError:    b.LastError,
		Metadata:     b.Metadata,
	}
	if !b.CompletedAt.IsZero() {
		obj.CompletedAt = b.CompletedAt.Unix()
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "batch serialization failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

// batchesCreate handles POST /v1/batches: validates the org-owned input
// file (purpose=batch, parseable JSONL, ≤1000 lines, POST
// /v1/chat/completions bodies without streaming) and materializes the job.
// The D3 1000-line cap is enforced twice by construction: parseBatchJSONL
// stops at the first line past the cap (before validating the rest of an
// oversized file), and CreateBatch re-checks the materialized count.
func (gw *gateway) batchesCreate(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.batchesStoreOr503(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "unreadable request body")
		return
	}
	var req struct {
		InputFileID string          `json:"input_file_id"`
		Endpoint    string          `json:"endpoint"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.InputFileID == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"input_file_id is required")
		return
	}
	if req.Endpoint == "" {
		req.Endpoint = batchstore.EndpointChatCompletions
	}
	content, _, err := store.FileContent(r.Context(), orgID, req.InputFileID)
	if err != nil {
		writeBatchesStoreError(w, err, "")
		return
	}
	lines, perr := parseBatchJSONL(content)
	if perr != nil {
		if errors.Is(perr, batchstore.ErrTooManyLines) {
			// The D3 line cap tripped during parsing: answer with the same
			// shape as the store-level cap (400, too_many_requests_in_batch)
			// instead of the generic invalid_batch_file label.
			writeBatchesStoreError(w, perr, req.InputFileID)
			return
		}
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			perr.Error(), "invalid_batch_file")
		return
	}
	b, err := store.CreateBatch(r.Context(), orgID, r.Header.Get("X-API-Key-Id"),
		req.InputFileID, req.Endpoint, req.Metadata, lines)
	if err != nil {
		writeBatchesStoreError(w, err, req.InputFileID)
		return
	}
	writeBatchObject(w, b)
}

// parseBatchJSONL validates the OpenAI-shaped batch request file: every
// line must be {"custom_id","method":"POST","url":"/v1/chat/completions",
// "body":{model, ...}} with streaming refused explicitly. Parsing stops at
// the first line past the D3 MaxBatchLines cap with ErrTooManyLines, so a
// many-line file is rejected before per-line validation work continues
// (batchesCreate maps it to the store-level 400 shape).
func parseBatchJSONL(content []byte) ([]batchstore.LineInput, error) {
	var out []batchstore.LineInput
	for i, raw := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		lineNo := i + 1
		var doc struct {
			CustomID string          `json:"custom_id"`
			Method   string          `json:"method"`
			URL      string          `json:"url"`
			Body     json.RawMessage `json:"body"`
		}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": invalid JSON")
		}
		if doc.CustomID == "" {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": custom_id is required")
		}
		if !strings.EqualFold(doc.Method, http.MethodPost) {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": only POST requests are supported")
		}
		if !strings.EqualFold(strings.TrimSpace(doc.URL), batchstore.EndpointChatCompletions) {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": only /v1/chat/completions requests are supported")
		}
		var probe struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if len(doc.Body) == 0 || json.Unmarshal(doc.Body, &probe) != nil {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": body must be a JSON object")
		}
		if probe.Model == "" {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": body.model is required")
		}
		if probe.Stream {
			return nil, errors.New("line " + strconv.Itoa(lineNo) + ": streaming is not supported in batch requests")
		}
		if len(out) == batchstore.MaxBatchLines {
			return nil, fmt.Errorf("line %d: %w", lineNo, batchstore.ErrTooManyLines)
		}
		out = append(out, batchstore.LineInput{CustomID: doc.CustomID, RequestBody: doc.Body})
	}
	if len(out) == 0 {
		return nil, errors.New("the batch file contains no request lines")
	}
	return out, nil
}

func writeBatchesStoreError(w http.ResponseWriter, err error, fileID string) {
	switch {
	case errors.Is(err, batchstore.ErrNotFound):
		apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "file not found")
	case errors.Is(err, batchstore.ErrTooManyLines):
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"batch exceeds the maximum of 1000 requests", "too_many_requests_in_batch")
	case errors.Is(err, batchstore.ErrUnsupportedEndpoint):
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"only /v1/chat/completions batches are supported", "unsupported_endpoint")
	case errors.Is(err, batchstore.ErrBadLine):
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"input file is not a valid batch file for this endpoint", "invalid_batch_file")
	case errors.Is(err, batchstore.ErrBatchTerminal):
		apierrors.WriteWithCode(w, http.StatusConflict, apierrors.ErrorCodeInvalidRequest,
			"batch is already in a terminal state", "batch_already_terminal")
	default:
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "batch store unavailable")
	}
}

// batchesList handles GET /v1/batches.
func (gw *gateway) batchesList(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.batchesStoreOr503(w, r)
	if !ok {
		return
	}
	batches, err := store.ListBatches(r.Context(), orgID, listLimit(r))
	if err != nil {
		writeBatchesStoreError(w, err, "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"object":"list","data":[`))
	for i, b := range batches {
		if i > 0 {
			_, _ = w.Write([]byte(","))
		}
		var obj batchJSONObject
		obj.ID = b.ID
		obj.Object = "batch"
		obj.Endpoint = b.Endpoint
		obj.Status = b.Status
		obj.RequestCounts = batchCounts{Total: b.TotalCount, Completed: b.CompletedCount, Failed: b.FailedCount}
		obj.InputFileID = b.InputFileID
		obj.OutputFileID = b.OutputFileID
		obj.ErrorFileID = b.ErrorFileID
		obj.CreatedAt = b.CreatedAt.Unix()
		obj.ExpiresAt = b.ExpiresAt.Unix()
		if !b.CompletedAt.IsZero() {
			obj.CompletedAt = b.CompletedAt.Unix()
		}
		raw, merr := json.Marshal(obj)
		if merr != nil {
			continue
		}
		_, _ = w.Write(raw)
	}
	_, _ = w.Write([]byte("]}\n"))
}

// batchesGet handles GET /v1/batches/{id} (status).
func (gw *gateway) batchesGet(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.batchesStoreOr503(w, r)
	if !ok {
		return
	}
	b, err := store.GetBatch(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, batchstore.ErrNotFound) {
			apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "batch not found")
			return
		}
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "batch store unavailable")
		return
	}
	writeBatchObject(w, b)
}

// batchesCancel handles POST /v1/batches/{id}/cancel. Idempotency contract
// (ratified «повтор cancel»): cancelling/cancelled return the same object
// with no second side effect; terminal completed/failed/expired batches
// answer 409 with an explicit terminal-state error.
func (gw *gateway) batchesCancel(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.batchesStoreOr503(w, r)
	if !ok {
		return
	}
	b, err := store.CancelBatch(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		writeBatchesStoreError(w, err, "")
		return
	}
	writeBatchObject(w, b)
}

// batchesResults handles GET /v1/batches/{id}/results: the output JSONL of
// a finalized batch (failed lines live in the error file).
func (gw *gateway) batchesResults(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.batchesStoreOr503(w, r)
	if !ok {
		return
	}
	b, err := store.GetBatch(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, batchstore.ErrNotFound) {
			apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "batch not found")
			return
		}
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "batch store unavailable")
		return
	}
	if b.OutputFileID == "" {
		apierrors.WriteWithCode(w, http.StatusConflict, apierrors.ErrorCodeInvalidRequest,
			"batch results are available after the batch reaches a terminal state", "results_not_ready")
		return
	}
	content, _, err := store.FileContent(r.Context(), orgID, b.OutputFileID)
	if err != nil {
		if errors.Is(err, batchstore.ErrNotFound) {
			apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "results file not found")
			return
		}
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "batch store unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// batchLineRecorder captures one internal line execution (chat pipeline
// writes the JSON completion here).
type batchLineRecorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func newBatchLineRecorder() *batchLineRecorder { return &batchLineRecorder{header: http.Header{}} }

func (rec *batchLineRecorder) Header() http.Header { return rec.header }

// Write mirrors net/http's implicit status: a handler may write the body
// without WriteHeader (the JSON chat path does) — the first byte implies 200.
func (rec *batchLineRecorder) Write(p []byte) (int, error) {
	if rec.code == 0 {
		rec.code = http.StatusOK
	}
	return rec.body.Write(p)
}
func (rec *batchLineRecorder) WriteHeader(code int) { rec.code = code }
func (rec *batchLineRecorder) Flush()               {}

// batchLineRunner executes one batch line through the gateway's own chat
// pipeline (ratified D4): the synthesized server-side request carries the
// batch owner's identity (org + submitting API key), the wallet CreditGuard
// and every admission check (guards, resolution, whitelist, budgets,
// reservations) run exactly as for interactive traffic, and the finish
// event carries the deterministic per-line request id so crash-retried
// lines settle exactly once.
func (gw *gateway) batchLineRunner(ctx context.Context, b *batchstore.Batch, ln batchstore.Line) batchstore.LineResult {
	// The deterministic per-line request id rides the context (settlement
	// idempotency across crash retries).
	//
	// RATELIMIT-FALLBACK F1 (review 2026-11-02): the per-line cancel is
	// mandatory. requestid.NewContext is WithValue-only, so without it the
	// synthesized request's context never ends (the executor ctx is
	// long-lived), and fair admission anchors ticket release to the request
	// context (context.AfterFunc in admissionCore) — every processed batch
	// line would permanently occupy one admission slot, shedding all
	// traffic at Capacity. Real HTTP requests get this cancellation from
	// net/http on ServeHTTP return; the batch path is the only direct
	// ServeHTTP caller, so it must end its own context with the line.
	lineCtx, cancelLine := context.WithCancel(requestid.NewContext(ctx, requestid.ID(ln.RequestID)))
	defer cancelLine()
	req, err := http.NewRequestWithContext(lineCtx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(ln.RequestBody))
	if err != nil {
		return batchstore.LineResult{Err: err}
	}
	req.ContentLength = int64(len(ln.RequestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", b.OrgID)
	if b.APIKeyID != "" {
		req.Header.Set("X-API-Key-Id", b.APIKeyID)
	}
	if b.ID != "" {
		req.Header.Set("X-Yabanin-Task", b.ID)
	}
	req.RemoteAddr = "batch-executor:0"

	rec := newBatchLineRecorder()
	httpmw.CreditGuard(gw.creditStore)(http.HandlerFunc(gw.chatCompletions)).ServeHTTP(rec, req)
	if rec.code == 0 {
		return batchstore.LineResult{Status: http.StatusInternalServerError, Err: errors.New("chat pipeline produced no response")}
	}
	return batchstore.LineResult{Status: rec.code, Body: rec.body.Bytes()}
}
