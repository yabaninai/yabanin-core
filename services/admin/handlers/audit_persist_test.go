package handlers

// AF-10 handler-level acceptance: the journal is served from the durable
// store (not the process buffer), a store failure never creates the
// visibility of durable success (durable outbox intent + pending count), and
// the full sanitized record round-trips.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listAuditLogsResponse decodes the full list response.
type listAuditLogsResponse struct {
	AuditLogs []struct {
		ID        string          `json:"id"`
		Action    string          `json:"action"`
		Resource  string          `json:"resource"`
		Details   string          `json:"details"`
		AdminID   string          `json:"admin_id"`
		Timestamp string          `json:"timestamp"`
		Before    json.RawMessage `json:"before"`
		After     json.RawMessage `json:"after"`
		Reason    string          `json:"reason"`
	} `json:"audit_logs"`
	Total               int64 `json:"total"`
	PendingAuditEntries int64 `json:"pending_audit_entries"`
}

func callListAuditLogs(t *testing.T, h *AdminHandlers) listAuditLogsResponse {
	t.Helper()
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs", nil)
	h.ListAuditLogs()(rw, req)
	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
	var resp listAuditLogsResponse
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	return resp
}

// TestAuditPersist_JournalServedFromStoreNotBuffer: the recorded entry is
// persisted through the store and served from it; the process buffer stays
// empty (not the authority).
func TestAuditPersist_JournalServedFromStoreNotBuffer(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	req.Header.Set("X-Audit-Reason", "why not")
	h.auditLogActionDiff(req, "update", "api_key", "id=k",
		map[string]any{"id": "k", "active": true},
		map[string]any{"id": "k", "active": false})

	h.auditMu.RLock()
	buffered := len(h.auditLogBuffer)
	h.auditMu.RUnlock()
	assert.Zero(t, buffered, "the process buffer is not the journal authority")

	resp := callListAuditLogs(t, h)
	require.Len(t, resp.AuditLogs, 1)
	served := resp.AuditLogs[0]
	assert.Equal(t, "update", served.Action)
	assert.Equal(t, "why not", served.Reason)
	assert.Contains(t, string(served.Before), `"active":true`)
	assert.Contains(t, string(served.After), `"active":false`)
	assert.NotEmpty(t, served.Timestamp, "persisted rows carry their creation timestamp")
	assert.Zero(t, resp.PendingAuditEntries, "delivered entries are not pending")
	assert.EqualValues(t, 1, resp.Total)
}

// TestAuditPersist_DirectWriteFails_OutboxDelivers: when the direct append
// fails, the only way the entry can reach the journal is the durable outbox
// — the entry still ends up persisted (with its snapshots/reason) after the
// request.
func TestAuditPersist_DirectWriteFails_OutboxDelivers(t *testing.T) {
	ms := newMockStore()
	ms.insertAuditErr = assert.AnError // direct append fails for the whole test
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	req.Header.Set("X-Audit-Reason", "delivered via outbox")
	h.auditLogActionDiff(req, "update", "api_key", "id=k",
		map[string]any{"id": "k", "active": true},
		map[string]any{"id": "k", "active": false})

	// The direct insert failed, so the journal write happened through the
	// outbox delivery path.
	rec := ms.lastAuditRecord(t)
	assert.Equal(t, "delivered via outbox", rec.Reason)
	assert.Contains(t, rec.Before, `"active":true`)
	assert.Contains(t, rec.After, `"active":false`)

	resp := callListAuditLogs(t, h)
	require.Len(t, resp.AuditLogs, 1)
	assert.Equal(t, "delivered via outbox", resp.AuditLogs[0].Reason)
	assert.Zero(t, resp.PendingAuditEntries, "delivered outbox rows are not pending")
}

// TestAuditPersist_StoreAndOutboxDown_NoDurableSuccess: with both the direct
// append and the outbox down, the entry stays in the memory-pending queue
// and the response exposes it as pending — never as durable success. After
// the store recovers, the delivery loop drains it.
func TestAuditPersist_StoreAndOutboxDown_NoDurableSuccess(t *testing.T) {
	ms := newMockStore()
	ms.insertAuditErr = assert.AnError
	ms.enqueueOutboxErr = assert.AnError
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	h.auditLogAction(req, "create", "org", "id=o")

	assert.Zero(t, ms.auditRecordCount(), "nothing durable yet")
	resp := callListAuditLogs(t, h)
	assert.Empty(t, resp.AuditLogs)
	assert.Equal(t, int64(1), resp.PendingAuditEntries, "the undelivered entry is visible as pending")

	// Recovery: the delivery flush makes it durable.
	ms.insertAuditErr = nil
	ms.enqueueOutboxErr = nil
	h.flushAuditDelivery(t.Context())

	resp = callListAuditLogs(t, h)
	require.Len(t, resp.AuditLogs, 1)
	assert.Equal(t, "create", resp.AuditLogs[0].Action)
	assert.Zero(t, resp.PendingAuditEntries, "the entry is durable after recovery")
}

// TestAuditPersist_SanitizedSnapshotsPersisted: the DB receives the
// sanitized snapshots — the raw secret never reaches the store, and the
// served journal cannot leak it either.
func TestAuditPersist_SanitizedSnapshotsPersisted(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	req.Header.Set("X-Audit-Reason", "rotation")
	h.auditLogActionDiff(req, "update", "api_key", "id=k",
		map[string]any{"id": "k", "key_hash": "sha256-leak"},
		map[string]any{"id": "k", "key_hash": "sha256-new"})

	rec := ms.lastAuditRecord(t)
	assert.NotContains(t, rec.Before, "sha256-leak", "raw secret must not reach the store")
	assert.NotContains(t, rec.After, "sha256-new")
	assert.Contains(t, rec.Before, "[redacted]")

	resp := callListAuditLogs(t, h)
	require.Len(t, resp.AuditLogs, 1)
	assert.NotContains(t, serializeResp(t, resp), "sha256-leak")
}

// serializeResp is a tiny helper to serialize a response struct for substring asserts.
func serializeResp(t *testing.T, resp listAuditLogsResponse) string {
	t.Helper()
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return string(b)
}

// the single journal write path without a timestamp is stamped with now UTC
// — the durable record and the served entry never carry the zero time.
func TestAuditPersist_ZeroTimestampStampedOnWrite(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	before := time.Now().UTC()
	h.persistAudit(t.Context(), AuditLogEntry{ID: "zero-1", Action: "create", Resource: "org"})
	after := time.Now().UTC()

	rec := ms.lastAuditRecord(t)
	assert.False(t, rec.CreatedAt.IsZero(), "a zero-timestamp entry must be stamped on write")
	assert.WithinDuration(t, before, rec.CreatedAt, time.Minute, "the stamp is now UTC")

	resp := callListAuditLogs(t, h)
	require.Len(t, resp.AuditLogs, 1)
	served, err := time.Parse(time.RFC3339Nano, resp.AuditLogs[0].Timestamp)
	require.NoError(t, err, "served timestamp must parse: %q", resp.AuditLogs[0].Timestamp)
	assert.GreaterOrEqual(t, served.Year(), 2000, "the journal must never serve a pre-2000 timestamp")
	assert.WithinDuration(t, before, served, time.Minute)
	assert.WithinDuration(t, after, served, time.Minute)
}

// path (stores without the durable capability) stamps too — the buffer feeds
// the API directly, so a zero time would render as "Jan 1, 1".
func TestAuditBuffer_ZeroTimestampStampedOnWrite(t *testing.T) {
	h := New(nil, "", "", []string{}) // no store → legacy in-buffer path

	h.persistAudit(t.Context(), AuditLogEntry{ID: "zero-2", Action: "update", Resource: "api_key"})

	h.auditMu.RLock()
	defer h.auditMu.RUnlock()
	require.Len(t, h.auditLogBuffer, 1)
	stamped := h.auditLogBuffer[0].Timestamp
	assert.False(t, stamped.IsZero(), "buffered entries must carry a stamped time")
	assert.WithinDuration(t, time.Now().UTC(), stamped, time.Minute)
}

// path keeps stamping entries itself — existing behavior stays intact.
func TestAuditRecord_TimestampStampedRegression(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
	h.auditLogAction(req, "create", "org", "id=o")

	rec := ms.lastAuditRecord(t)
	assert.False(t, rec.CreatedAt.IsZero(), "recordAudit always stamps the entry")
	assert.WithinDuration(t, time.Now().UTC(), rec.CreatedAt, time.Minute)
}

// TestAuditPersist_ConcurrentRecords_AllPersisted: concurrent mutations each
// land exactly once in the journal (the shared append protocol serializes
// them; the DB-level chain proof lives in pkg/adminstore integration tests).
func TestAuditPersist_ConcurrentRecords_AllPersisted(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	defer h.Stop()

	const n = 32
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func(k int) {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil)
			req.Header.Set("X-Audit-Reason", "concurrent mutation")
			h.auditLogAction(req, "bulk", "journal", strings.Repeat("d", k+1))
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	assert.Equal(t, n, ms.auditRecordCount(), "every concurrent record persisted exactly once")

	resp := callListAuditLogs(t, h)
	assert.Equal(t, int64(n), resp.Total)
}
