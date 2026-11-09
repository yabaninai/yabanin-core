package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

func TestWhitelistModel_UsesTargetForAlias(t *testing.T) {
	assert.Equal(t, "qwen-coder", whitelistModel(resolver.ModelInfo{ModelName: "qwen-coder", Alias: "claude-sonnet-4-6"}, "claude-sonnet-4-6"))
	assert.Equal(t, "gpt-4o", whitelistModel(resolver.ModelInfo{ModelName: "gpt-4o"}, "gpt-4o"))
}

func TestListModels_AliasUsesTargetForWhitelist(t *testing.T) {
	gw := modelsGateway(staticModelLister{}, allowExcept("qwen-coder"))
	gw.models = sliceLister{entries: []modelEntry{
		{ID: "qwen-coder", DisplayName: "Qwen", Provider: "vllm", CreatedAt: time.Unix(10, 0).UTC()},
		{ID: "claude-sonnet-4-6", DisplayName: "qwen-coder", Provider: "vllm", CreatedAt: time.Unix(10, 0).UTC(), AliasOf: "qwen-coder"},
		{ID: "other", DisplayName: "Other", Provider: "openai", CreatedAt: time.Unix(10, 0).UTC()},
	}}
	rec := httptest.NewRecorder()
	modelsHTTP(gw).ServeHTTP(rec, authed(t, http.MethodGet, "/v1/models"))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	ids := make([]string, 0, len(body.Data))
	for _, row := range body.Data {
		ids = append(ids, row.ID)
	}
	assert.NotContains(t, ids, "qwen-coder")
	assert.NotContains(t, ids, "claude-sonnet-4-6")
	assert.Contains(t, ids, "other")
}

type sliceLister struct {
	entries []modelEntry
}

func (s sliceLister) ListEnabledModels(context.Context) ([]modelEntry, error) {
	return s.entries, nil
}
