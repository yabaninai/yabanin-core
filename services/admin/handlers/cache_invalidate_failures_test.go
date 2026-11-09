package handlers

// FIX-04 (CA-06): caller-honesty tests for the cache invalidation paths.
//
// Pre-fix behavior:
//   - FlushCache answered 200 {"status":"flushed"} even when the underlying
//     sweep silently swallowed SCAN/DEL failures (stale keys survived);
//   - UpdateOrgCacheSettings kept 200-by-design but had nothing to log
//     (the error never reached it);
//   - UpdateModel/DeleteModel discarded the invalidation error with `_ =`
//     and logged "cache invalidated" unconditionally — a false success in
//     the operational log.
//
// These tests pin the honest contract:
//   - FlushCache: failure ⇒ 5xx and the body never claims "flushed"
//     (the 5xx body itself stays generic per S01; the full error is in the
//     error log written by respondError);
//   - UpdateOrgCacheSettings: still 200 (settings mutation succeeded) but
//     the WARN log now carries the failure detail;
//   - UpdateModel/DeleteModel: the mutation stays 200/204 (existing API
//     contract — the mutation itself succeeded), but a failed invalidation
//     is never logged as success: warn log + a failed-invalidation audit
//     entry instead of the "cache invalidated" success line.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
)

// captureHandler records slog output so tests can assert what operators
// would actually see.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}

func (c *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(string) slog.Handler      { return c }

func (c *captureHandler) find(level slog.Level, msgSubstr string) (slog.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		if r.Level == level && strings.Contains(r.Message, msgSubstr) {
			return r, true
		}
	}
	return slog.Record{}, false
}

func (c *captureHandler) attr(rec slog.Record, key string) (slog.Value, bool) {
	found := false
	val := slog.AnyValue("")
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value, true
			return false
		}
		return true
	})
	return val, found
}

// deadRedisInvalidator builds a real Invalidator whose Redis client points
// at a closed port: every command fails fast with a transport error, which
// is exactly the "Redis unreachable mid-flush" class.
func deadRedisInvalidator() *cache.Invalidator {
	rdb := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  300 * time.Millisecond,
		ReadTimeout:  300 * time.Millisecond,
		WriteTimeout: 300 * time.Millisecond,
		MaxRetries:   0,
	})
	return cache.NewInvalidator(cache.NewRedisStore(rdb, 0), nil, rdb)
}

func noopInvalidator() *cache.Invalidator {
	// All backends nil: the sweep is a no-op and must report success.
	return cache.NewInvalidator(nil, nil, nil)
}

// auditEntries reads the audit journal the mock store persists into
// (mockStore implements AuditJournalStore, so handler audits go through the
// synchronous durable path — not the in-memory buffer).
func auditEntries(store *mockStore) []adminstore.AuditLogEntryRecord {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	return append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
}

// --- FlushCache -------------------------------------------------------------

func TestFlushCache_InvalidationFailureNeverClaimsFlushed(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	h.SetCacheInvalidator(deadRedisInvalidator())
	handler := h.FlushCache()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/cache/flush?org_id=org-1&reason=test", nil)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Post("/api/cache/flush", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code, "a failed flush must not answer 200")
	body := rec.Body.String()
	assert.NotContains(t, body, "flushed", "response must never claim a flush happened: %s", body)
}

func TestFlushCache_ModelTierInvalidationFailureNeverClaimsFlushed(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	h.SetCacheInvalidator(deadRedisInvalidator())
	handler := h.FlushCache()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/cache/flush?org_id=org-1&model_tier=smart", nil)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Post("/api/cache/flush", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "flushed")
}

func TestFlushCache_SuccessStillReportsFlushed(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	h.SetCacheInvalidator(noopInvalidator())
	handler := h.FlushCache()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/cache/flush?org_id=org-1", nil)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Post("/api/cache/flush", handler)
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "flushed", resp["status"], "a real success must still be reported as flushed")
}

// --- UpdateOrgCacheSettings ---------------------------------------------------

func TestUpdateOrgCacheSettings_FlushFailureKeepsOkButLogsDetail(t *testing.T) {
	store := newMockStore()
	store.orgs["org-flush-fail"] = &adminstore.Organization{ID: "org-flush-fail", Name: "O", Slug: "o", CacheEnabled: true, CacheMode: "semantic"}

	h := New(store, "session-secret", "localhost", nil)
	cap := &captureHandler{}
	h.logger = slog.New(cap)
	h.SetCacheInvalidator(deadRedisInvalidator())

	body := strings.NewReader(`{"cache_enabled":false,"cache_mode":"off"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/organizations/org-flush-fail/cache-settings", body)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Patch("/api/organizations/{id}/cache-settings", h.UpdateOrgCacheSettings())
	r.ServeHTTP(rec, req)

	// 200-by-design: the settings mutation succeeded; the flush is best-effort.
	require.Equal(t, http.StatusOK, rec.Code)

	// …but the failure must reach the operator log with the error detail.
	rec2, ok := cap.find(slog.LevelWarn, "flush")
	require.True(t, ok, "expected a WARN log mentioning the flush failure; captured %d records", len(cap.records))
	errVal, ok := cap.attr(rec2, "error")
	require.True(t, ok, "WARN log must carry the error detail")
	assert.NotEmpty(t, errVal.String())
}

func TestUpdateOrgCacheSettings_SuccessfulFlushStillOk(t *testing.T) {
	store := newMockStore()
	store.orgs["org-flush-ok"] = &adminstore.Organization{ID: "org-flush-ok", Name: "O", Slug: "o", CacheEnabled: true, CacheMode: "semantic"}

	h := New(store, "session-secret", "localhost", nil)
	cap := &captureHandler{}
	h.logger = slog.New(cap)
	h.SetCacheInvalidator(noopInvalidator())

	body := strings.NewReader(`{"cache_enabled":false,"cache_mode":"off"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/organizations/org-flush-ok/cache-settings", body)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Patch("/api/organizations/{id}/cache-settings", h.UpdateOrgCacheSettings())
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	_, ok := cap.find(slog.LevelWarn, "flush")
	assert.False(t, ok, "a successful flush must not log a flush warning")
}

// --- UpdateModel / DeleteModel ------------------------------------------------

func newModelFixture(t *testing.T) (*mockStore, *AdminHandlers, *captureHandler) {
	t.Helper()
	store := newMockStore()
	store.models["m-1"] = &adminstore.ModelRegistry{ID: "m-1", ModelName: "m-1", Tier: "smart", Enabled: true}
	h := New(store, "session-secret", "localhost", nil)
	cap := &captureHandler{}
	h.logger = slog.New(cap)
	return store, h, cap
}

func TestUpdateModel_InvalidationFailureNotLoggedAsSuccess(t *testing.T) {
	store, h, cap := newModelFixture(t)
	h.SetCacheInvalidator(deadRedisInvalidator())

	body := strings.NewReader(`{"upstream_url":"https://upstream.example"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/models/m-1", body)
	rec := httptest.NewRecorder()
	wrapWithParams(h.UpdateModel(), "/api/models/{name}")(rec, req)

	// Contract decision (documented in crud.go): the model mutation itself
	// succeeded, so the endpoint keeps its 200.
	require.Equal(t, http.StatusOK, rec.Code)

	// The unconditional success line must be gone…
	_, ok := cap.find(slog.LevelInfo, "cache invalidated after model update")
	assert.False(t, ok, "invalidation failure must not be logged as 'cache invalidated' success")

	// …replaced by an honest failure line carrying the error.
	warn, ok := cap.find(slog.LevelWarn, "cache invalidation failed after model update")
	require.True(t, ok, "expected a WARN log for the failed invalidation")
	errVal, ok := cap.attr(warn, "error")
	require.True(t, ok, "failure log must carry the error detail")

	// And an audit entry must record the failed invalidation (no false success).
	entries := auditEntries(store)
	var hasUpdateAudit, hasFailedInvalidateAudit bool
	for _, e := range entries {
		if e.Action == "update" && e.Resource == "model" {
			hasUpdateAudit = true
		}
		if e.Action == "invalidate" && e.Resource == "cache" && strings.Contains(e.Details, "result=failed") {
			hasFailedInvalidateAudit = true
			assert.Contains(t, e.Details, "m-1")
		}
	}
	assert.True(t, hasUpdateAudit, "the model update itself must still be audited")
	assert.True(t, hasFailedInvalidateAudit, "the failed cache invalidation must be audited as a failure")
	assert.NotEmpty(t, errVal.String())
}

func TestDeleteModel_InvalidationFailureNotLoggedAsSuccess(t *testing.T) {
	store, h, cap := newModelFixture(t)
	h.SetCacheInvalidator(deadRedisInvalidator())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/models/m-1", nil)
	rec := httptest.NewRecorder()
	wrapWithParams(h.DeleteModel(), "/api/models/{name}")(rec, req)

	// Mutation succeeded ⇒ 204 stays (existing API contract).
	require.Equal(t, http.StatusNoContent, rec.Code)

	_, ok := cap.find(slog.LevelInfo, "cache invalidated after model deletion")
	assert.False(t, ok, "invalidation failure must not be logged as 'cache invalidated' success")

	_, ok = cap.find(slog.LevelWarn, "cache invalidation failed after model deletion")
	require.True(t, ok, "expected a WARN log for the failed invalidation")

	entries := auditEntries(store)
	var hasDeleteAudit, hasFailedInvalidateAudit bool
	for _, e := range entries {
		if e.Action == "delete" && e.Resource == "model" {
			hasDeleteAudit = true
		}
		if e.Action == "invalidate" && e.Resource == "cache" && strings.Contains(e.Details, "result=failed") {
			hasFailedInvalidateAudit = true
		}
	}
	assert.True(t, hasDeleteAudit, "the model deletion itself must still be audited")
	assert.True(t, hasFailedInvalidateAudit, "the failed cache invalidation must be audited as a failure")
}

func TestUpdateModel_InvalidationSuccessStillLogsSuccess(t *testing.T) {
	store, h, cap := newModelFixture(t)
	h.SetCacheInvalidator(noopInvalidator())

	body := strings.NewReader(`{"upstream_url":"https://upstream.example"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/models/m-1", body)
	rec := httptest.NewRecorder()
	wrapWithParams(h.UpdateModel(), "/api/models/{name}")(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	_, ok := cap.find(slog.LevelInfo, "cache invalidated after model update")
	assert.True(t, ok, "a real invalidation success keeps its success log")

	entries := auditEntries(store)
	var hasFailedInvalidateAudit bool
	for _, e := range entries {
		if e.Action == "invalidate" && e.Resource == "cache" && strings.Contains(e.Details, "result=failed") {
			hasFailedInvalidateAudit = true
		}
	}
	assert.False(t, hasFailedInvalidateAudit, "a successful invalidation must not produce a failure audit entry")
}
