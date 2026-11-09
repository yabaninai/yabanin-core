package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- serveHandlerWithRouter helper (used by multiple test files) ----

func chiServe(pattern string, handler http.HandlerFunc, method, path string, body *bytes.Reader) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	var reader io.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = body
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	router := chi.NewRouter()

	chiCtx := &chi.Context{}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")
	for i, p := range patternParts {
		var key string
		switch {
		case strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}"):
			key = p[1 : len(p)-1]
		case strings.HasPrefix(p, ":") && len(p) > 1:
			key = p[1:]
		default:
			continue
		}
		if i < len(pathParts) {
			chiCtx.URLParams.Add(key, pathParts[i])
		}
	}

	router.Get(pattern, handler)
	router.Post(pattern, handler)
	router.Put(pattern, handler)
	router.Patch(pattern, handler)
	router.Delete(pattern, handler)
	router.ServeHTTP(rw, req)
	return rw
}

// ---- TestHandleCreateOrUpdateResalePricing ----

func TestHandleCreateOrUpdateResalePricing_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	body := bytes.NewReader([]byte(`{"org_id":"org-abc","markup_pct":10.0}`))
	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-abc/resale-pricing", body)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "database not configured")
}

func TestHandleCreateOrUpdateResalePricing_MalformedJSON_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	body := bytes.NewReader([]byte(`{bad json}`))
	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-abc/resale-pricing", body)

	// Pool check happens before JSON parsing in the handler.
	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

func TestHandleCreateOrUpdateResalePricing_NegativeMarkup_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	body := bytes.NewReader([]byte(`{"org_id":"org-abc","markup_pct":-5.0}`))
	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-abc/resale-pricing", body)

	// Handler checks pool first.
	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

// ---- TestHandleListResalePricing ----

func TestHandleListResalePricing_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/reseller-pricing", nil)
	router := chi.NewRouter()
	router.Get("/api/reseller-pricing", h.HandleListResalePricing)
	router.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "database not configured")
}

// ---- TestHandleGetResalePricing ----

func TestHandleGetResalePricing_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/reseller-pricing/1", nil)
	// Direct handler call — pool check runs first regardless of route.
	h.HandleGetResalePricing(rw, req)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

func TestHandleGetResalePricing_InvalidID_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/reseller-pricing/abc", nil)
	// Direct handler call — the pool check runs first regardless of route matching.
	h.HandleGetResalePricing(rw, req)

	// Pool is nil → 503 before ID parsing happens.
	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

// ---- TestHandleDeleteResalePricing ----

func TestHandleDeleteResalePricing_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/reseller-pricing/1", nil)
	// Direct handler call — pool check runs first regardless of route.
	h.HandleDeleteResalePricing(rw, req)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

// ---- TestHandleGetOrgResalePricing ----

func TestHandleGetOrgResalePricing_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleGetOrgResalePricing, "GET", "/api/orgs/org-abc/resale-pricing", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

func TestHandleGetOrgResalePricing_MissingOrgID_NilPool(t *testing.T) {
	h := NewResalePricingHandlers(nil, slog.Default())

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/orgs/resale-pricing", nil)
	// Direct handler call — pool check runs first.
	h.HandleGetOrgResalePricing(rw, req)

	assert.Equal(t, http.StatusServiceUnavailable, rw.Code)
}

// ---- Integration tests with testcontainers for real DB-backed behavior ----

func TestHandleCreateOrUpdateResalePricing_Integration(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	body := bytes.NewReader([]byte(`{"org_id":"org-int-1","model_name":"gpt-4","markup_pct":25.0}`))
	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-int-1/resale-pricing", body)

	assert.Equal(t, http.StatusCreated, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Equal(t, "org-int-1", resp["org_id"])
	assert.Equal(t, "gpt-4", resp["model_name"])
	assert.InDelta(t, float64(25.0), resp["markup_pct"], 1e-9)
}

func TestHandleListResalePricing_Integration(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	// Create two rules first.
	body1 := bytes.NewReader([]byte(`{"org_id":"org-list-1","model_name":"gpt-4","markup_pct":10.0}`))
	rw1 := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-list-1/resale-pricing", body1)
	assert.Equal(t, http.StatusCreated, rw1.Code)

	body2 := bytes.NewReader([]byte(`{"org_id":"org-list-1","model_name":"claude-3","markup_pct":15.0}`))
	rw2 := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-list-1/resale-pricing", body2)
	assert.Equal(t, http.StatusCreated, rw2.Code)

	// List all rules.
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/reseller-pricing", nil)
	router := chi.NewRouter()
	router.Get("/api/reseller-pricing", h.HandleListResalePricing)
	router.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, resp["count"], float64(2))
}

func TestHandleGetResalePricing_Integration(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	// Create a rule.
	body := bytes.NewReader([]byte(`{"org_id":"org-get-1","model_name":"gpt-4","markup_pct":20.0}`))
	rwCreate := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-get-1/resale-pricing", body)
	assert.Equal(t, http.StatusCreated, rwCreate.Code)

	// Get the rule by ID (idempotent: BIGSERIAL ids are global, so read back
	// the id the create step just returned instead of assuming 1).
	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(rwCreate.Body.Bytes(), &created))
	ruleID := fmt.Sprintf("%v", created["id"])
	rw := chiServe("/api/reseller-pricing/{id}", h.HandleGetResalePricing, "GET", "/api/reseller-pricing/"+ruleID, nil)

	assert.Equal(t, http.StatusOK, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Equal(t, created["id"], resp["id"])
	assert.Equal(t, "org-get-1", resp["org_id"])
}

func TestHandleGetResalePricing_Integration_NotFound(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	rw := chiServe("/api/reseller-pricing/:id", h.HandleGetResalePricing, "GET", "/api/reseller-pricing/9999", nil)

	assert.Equal(t, http.StatusNotFound, rw.Code)
}

func TestHandleDeleteResalePricing_Integration(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	// Create a rule.
	body := bytes.NewReader([]byte(`{"org_id":"org-del-1","markup_pct":10.0}`))
	rwCreate := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-del-1/resale-pricing", body)
	assert.Equal(t, http.StatusCreated, rwCreate.Code)

	// Delete it (read the id back from the create response: BIGSERIAL ids
	// are global, so a hardcoded 1 is only valid on a fresh sequence).
	var createdDel map[string]interface{}
	require.NoError(t, json.Unmarshal(rwCreate.Body.Bytes(), &createdDel))
	delID := fmt.Sprintf("%v", createdDel["id"])
	rw := chiServe("/api/reseller-pricing/{id}", h.HandleDeleteResalePricing, "DELETE", "/api/reseller-pricing/"+delID, nil)

	assert.Equal(t, http.StatusOK, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Equal(t, "deactivated", resp["status"])
}

func TestHandleDeleteResalePricing_Integration_NotFound(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	rw := chiServe("/api/reseller-pricing/:id", h.HandleDeleteResalePricing, "DELETE", "/api/reseller-pricing/9999", nil)

	assert.Equal(t, http.StatusNotFound, rw.Code)
}

func TestHandleGetOrgResalePricing_Integration(t *testing.T) {
	pool := setupTestDBForResale(t)

	ctx := context.Background()
	setupResaleTables(ctx, t, pool)
	defer teardownResaleTables(ctx, t, pool)

	h := NewResalePricingHandlers(pool, slog.Default())

	// Create two rules for same org.
	body1 := bytes.NewReader([]byte(`{"org_id":"org-org-1","model_name":"gpt-4","markup_pct":10.0}`))
	rw1 := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-org-1/resale-pricing", body1)
	assert.Equal(t, http.StatusCreated, rw1.Code)

	body2 := bytes.NewReader([]byte(`{"org_id":"org-org-1","model_name":"claude-3","markup_pct":15.0}`))
	rw2 := chiServe("/api/orgs/{id}/resale-pricing", h.HandleCreateOrUpdateResalePricing, "PUT", "/api/orgs/org-org-1/resale-pricing", body2)
	assert.Equal(t, http.StatusCreated, rw2.Code)

	// Get rules for org.
	rw := chiServe("/api/orgs/{id}/resale-pricing", h.HandleGetOrgResalePricing, "GET", "/api/orgs/org-org-1/resale-pricing", nil)

	assert.Equal(t, http.StatusOK, rw.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	assert.Equal(t, "org-org-1", resp["org_id"])
	assert.GreaterOrEqual(t, resp["count"], float64(2))
}

// ---- Test helpers for integration tests ----

// setupTestDBForResale returns the package-wide disposable Postgres stand
// (QG2-B3: Docker required for the tests gate). Never returns nil — a
// missing Docker fails the test instead of silently skipping.
func setupTestDBForResale(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Postgres(t)
}

func setupResaleTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS reseller_pricing (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT,
			model_name TEXT,
			markup_pct DOUBLE PRECISION NOT NULL DEFAULT 0,
			fixed_input_per_m DOUBLE PRECISION,
			fixed_output_per_m DOUBLE PRECISION,
			active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (org_id, model_name)
		);
	`)
	if err != nil {
		t.Logf("create reseller_pricing: %v", err)
	}
}

func teardownResaleTables(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, "DROP TABLE IF EXISTS reseller_pricing")
	if err != nil {
		t.Logf("teardown warning: %v", err)
	}
}
