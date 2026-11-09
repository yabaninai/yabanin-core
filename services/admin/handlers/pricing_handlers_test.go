package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pricing"
)

func TestCreatePricing_SnakeCaseBody(t *testing.T) {
	h := newTestAdminH(newMockStore())
	body := []byte(`{"provider":"openai","model":"gpt-4o","input_per_m":2.5,"output_per_m":10}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/pricing", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreatePricingHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	var got adminstore.PricingEntry
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "openai", got.Provider)
	assert.Equal(t, "gpt-4o", got.Model)
	assert.InDelta(t, 2.5, got.InputPerM, 1e-9)
	assert.InDelta(t, 10, got.OutputPerM, 1e-9)
}

func TestImportPricing_DryRunApplyAndRoot(t *testing.T) {
	store := newMockStore()
	var applies []bool
	active := map[string]*adminstore.PricingEntry{}
	store.pricingImport = func(catalog pricing.PriceFile, mappings []adminstore.CatalogPriceMap, onlyMapped, apply bool, updatedBy string) (adminstore.CatalogImportResult, error) {
		applies = append(applies, apply)
		result, ops := adminstore.PlanCatalogImport(catalog, mappings, active, onlyMapped, updatedBy)
		if apply {
			result.Mode = "apply"
			for _, op := range ops {
				row := op.Insert
				active[row.Provider+"\x00"+row.Model] = &adminstore.PricingEntry{
					Provider: row.Provider, Model: row.Model,
					InputPerM: row.InputPerM, OutputPerM: row.OutputPerM,
					CacheWritePerM: row.CacheWritePerM, CacheReadPerM: row.CacheReadPerM,
				}
			}
		} else {
			result.Mode = "dry_run"
		}
		return result, nil
	}
	h := newTestAdminH(store)
	router := chi.NewRouter()
	router.Use(adminauth.MustBeRoot())
	router.Post("/api/pricing/import", h.ImportPricingHandler())

	payload := []byte(`{"catalog":{"source":"src","date":"2026-09-30","currency":"USD","units":"per_1m_tokens","models":[{"provider":"openai","model":"gpt-4o","input":2.5,"output":10,"cache_w":0,"cache_r":0}]},"map":[{"registry_provider":"openai","registry_model":"gpt-4o","catalog_provider":"openai","catalog_model":"gpt-4o"}],"only_mapped":true}`)

	nonRoot := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/pricing/import?mode=apply", bytes.NewReader(payload))
	nonRootRec := httptest.NewRecorder()
	router.ServeHTTP(nonRootRec, nonRoot)
	assert.Equal(t, http.StatusForbidden, nonRootRec.Code)
	assert.Empty(t, applies)

	dry := rootPricingRequest(http.MethodPost, "/api/pricing/import?mode=dry_run", payload)
	dryRec := httptest.NewRecorder()
	router.ServeHTTP(dryRec, dry)
	require.Equal(t, http.StatusOK, dryRec.Code)
	assert.Equal(t, []bool{false}, applies)
	assert.Contains(t, dryRec.Body.String(), `"mode":"dry_run"`)

	first := rootPricingRequest(http.MethodPost, "/api/pricing/import?mode=apply", payload)
	firstRec := httptest.NewRecorder()
	router.ServeHTTP(firstRec, first)
	require.Equal(t, http.StatusOK, firstRec.Code)
	assert.Contains(t, firstRec.Body.String(), `"created":1`)

	second := rootPricingRequest(http.MethodPost, "/api/pricing/import?mode=apply", payload)
	secondRec := httptest.NewRecorder()
	router.ServeHTTP(secondRec, second)
	require.Equal(t, http.StatusOK, secondRec.Code)
	assert.Contains(t, secondRec.Body.String(), `"unchanged":1`)
	assert.Equal(t, []bool{false, true, true}, applies)
}

func rootPricingRequest(method, target string, body []byte) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyIsRoot{}, true)
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "root@example.com")
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, "root-1")
	return req.WithContext(ctx)
}
