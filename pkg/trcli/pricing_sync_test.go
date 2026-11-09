package trcli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

func TestBuildPricingSync_ExactCompatAmbiguousAndLocal(t *testing.T) {
	catalog := pricing.PriceFile{Models: []pricing.PriceFileModel{
		{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10},
		{Provider: "openai", Model: "shared", Input: 1, Output: 1},
		{Provider: "azure", Model: "shared", Input: 1, Output: 1},
		{Provider: "other", Model: "embed", Input: 0.1, Output: 0},
	}}
	registry := []RegistryModel{
		{Provider: "openai", ModelName: "gpt-4o"},
		{Provider: "openai-compat", ModelName: "embed"},
		{Provider: "openai-compat", ModelName: "shared"},
		{Provider: "ollama", ModelName: "llama"},
		{Provider: "anthropic", ModelName: "missing"},
	}
	rows, ambiguous := buildPricingSync(registry, catalog)
	require.Len(t, rows, 4)
	assert.Equal(t, "exact", rows[0].Note)
	assert.Equal(t, "openai", rows[0].CatalogProvider)
	assert.Equal(t, "model name", rows[1].Note)
	assert.Equal(t, "other", rows[1].CatalogProvider)
	assert.Equal(t, "skipped local provider", rows[2].Note)
	assert.Equal(t, "unmatched", rows[3].Note)
	require.Len(t, ambiguous, 1)
	assert.Equal(t, "shared", ambiguous[0].RegistryModel)
	assert.Equal(t, []string{"azure/shared", "openai/shared"}, ambiguous[0].Candidates)
}

func TestPricingSync_CLIUsesAdminModels(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin-Key") != "svc-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/models":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":       []RegistryModel{{Provider: "openai", ModelName: "gpt-4o"}},
				"pagination": map[string]int{"page": 1, "total_pages": 1},
			})
		case "/api/pricing/import":
			applied = true
			assert.Equal(t, "apply", r.URL.Query().Get("mode"))
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": "apply", "created": 1, "unchanged": 0, "unmatched": []string{}, "errors": []string{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "prices.json")
	raw, err := json.Marshal(pricing.PriceFile{
		Source: "src", Date: "2026-09-30", Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	out, err := runTr(t, "pricing", "sync", "--catalog", path, "--api-key", "svc-key", "--admin-url", srv.URL)
	require.NoError(t, err)
	assert.Contains(t, out, "exact")
	assert.Contains(t, out, "dry-run only")
	assert.False(t, applied)

	out, err = runTr(t, "pricing", "sync", "--catalog", path, "--apply", "--api-key", "svc-key", "--admin-url", srv.URL)
	require.NoError(t, err)
	assert.Contains(t, out, "applied created=1")
	assert.True(t, applied)
}
