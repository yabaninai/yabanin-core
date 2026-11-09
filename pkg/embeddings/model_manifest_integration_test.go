package embeddings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_EmbedderConfigBoundary_BindsManifestToClient exercises the
// consumer entry point named by the packet contract: Config.Model is what
// pkg/gateway wireCacheService puts into NewHTTPClient (gateway.go), and the
// id placed on the wire must be exactly the id ManifestFor resolves to
// confirmed rights (pinned revision, weights digest, LICENSE, AUP
// disposition) at the same configuration boundary. The embedder service is an
// isolated httptest stand with synthetic data.
func TestIntegration_EmbedderConfigBoundary_BindsManifestToClient(t *testing.T) {
	for _, id := range []string{
		"BAAI/bge-small-en-v1.5", // pkg/config embedder default (pkg/config/cache.go)
		"Xenova/bge-small-en-v1.5",
		"intfloat/multilingual-e5-small",
	} {
		var wireModel string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req EmbeddingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			wireModel = req.Model
			resp := EmbeddingResponse{
				Data:  []EmbeddingData{{Index: 0, Embedding: make([]float32, 384), Object: "embedding"}},
				Model: req.Model,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))

		cfg := Config{
			BaseURL:  server.URL,
			Model:    id,
			Timeout:  5,
			Endpoint: EndpointTEI,
		}
		client := NewHTTPClient(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		vec, err := client.Embed(ctx, "integration synthetic prompt")
		cancel()
		server.Close()
		require.NoError(t, err, "Embed against the isolated TEI stand must work for %q", id)
		assert.Len(t, vec, 384, "bge-family clients document a 384-dim vector for %q", id)
		assert.Equal(t, id, wireModel, "the model id sent on the wire must equal the configured id for %q", id)

		m, err := ManifestFor(cfg.Model)
		require.NoError(t, err, "the id the consumer is configured with must resolve to a manifest for %q", id)
		require.NoError(t, m.Validate(), "confirmed rights required at the consumer boundary for %q", id)
		assert.NotEmpty(t, m.License, id)
		assert.True(t, strings.TrimSpace(m.AUPURL) != "" || strings.TrimSpace(m.Note) != "",
			"an acceptable-use disposition must be recorded for %q", id)
		assert.Len(t, m.Revision, 40, id)
		assert.Len(t, m.SHA256, 64, id)
	}
}

// TestIntegration_EmbedderConfigBoundary_UnknownModelExcluded proves the
// acceptance at the same consumer boundary: a configured id with no manifest
// is unknown origin and is refused by the provenance lookup — the package
// must not enter a distribution. The HTTP client itself still functions;
// whether the gateway must hard-refuse at startup is owner decision D4,
// explicitly left open by the packet.
func TestIntegration_EmbedderConfigBoundary_UnknownModelExcluded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EmbeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := EmbeddingResponse{
			Data:  []EmbeddingData{{Index: 0, Embedding: make([]float32, 384), Object: "embedding"}},
			Model: req.Model,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		BaseURL:  server.URL,
		Model:    "some-vendor/mystery-embed",
		Timeout:  5,
		Endpoint: EndpointTEI,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, embedErr := NewHTTPClient(cfg).Embed(ctx, "integration synthetic prompt")
	cancel()
	require.NoError(t, embedErr, "the transport path is not the provenance gate; runtime refusal is D4 (open)")

	m, err := ManifestFor(cfg.Model)
	require.Error(t, err, "unknown origin must be refused at the configuration boundary")
	if m.ID != "" || m.Revision != "" || m.SHA256 != "" {
		t.Errorf("ManifestFor(unknown) = %+v, want zero value", m)
	}
	for _, want := range []string{"some-vendor/mystery-embed", "no provenance manifest", "must not enter the distribution"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ManifestFor(unknown) error = %v, want it to mention %q", err, want)
		}
	}
}
