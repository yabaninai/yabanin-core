package embeddings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient_Embed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EmbeddingRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		resp := EmbeddingResponse{
			Data: []EmbeddingData{
				{Index: 0, Embedding: []float32{0.1, 0.2, 0.3, 0.4}, Object: "embedding"},
			},
			Model: req.Model,
			Usage: Usage{PromptTokens: 5, TotalTokens: 5},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{
		BaseURL: server.URL,
		Model:   "bge-small-en",
		Timeout: 10,
	})

	vec, err := client.Embed(context.Background(), "hello world")
	require.NoError(t, err)
	assert.Equal(t, []float32{0.1, 0.2, 0.3, 0.4}, vec)
}

// TestHTTPClient_EmbedQueryPrefix proves the configured prefix reaches the
// upstream payload (e5-family models need "query: " style prefixes, identical
// on lookups and writes).
func TestHTTPClient_EmbedQueryPrefix(t *testing.T) {
	var gotInput string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EmbeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		gotInput, _ = req.Input.(string)
		resp := EmbeddingResponse{
			Data:  []EmbeddingData{{Index: 0, Embedding: []float32{1}, Object: "embedding"}},
			Model: req.Model,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{
		BaseURL:     server.URL,
		Model:       "intfloat/multilingual-e5-small",
		QueryPrefix: "query: ",
		MaxChars:    64, // prefix counts toward the truncation budget
	})

	_, err := client.Embed(context.Background(), "こんにちは世界")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(gotInput, "query: こんにちは世界"), "prefix must precede the prompt, got %q", gotInput)

	// Truncation budget includes the prefix: a long prompt is cut so that
	// prefix+prompt fits MaxChars bytes (7-byte "query: " + 57 bytes = 19
	// three-byte Japanese chars).
	_, err = client.Embed(context.Background(), strings.Repeat("あ", 100))
	require.NoError(t, err)
	assert.Equal(t, "query: "+strings.Repeat("あ", 19), gotInput, "prompt must be truncated to fit the prefix in the budget")
}

func TestHTTPClient_EmbedTruncatesLongText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EmbeddingRequest
		_ = json.NewDecoder(r.Body).Decode(&req) // test stub: body is fixed
		inputStr, _ := req.Input.(string)
		assert.LessOrEqual(t, len(inputStr), 100)

		resp := EmbeddingResponse{
			Data: []EmbeddingData{{Index: 0, Embedding: []float32{0.5}, Object: "embedding"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{
		BaseURL:  server.URL,
		Model:    "bge-small-en",
		MaxChars: 100,
	})

	longText := strings.Repeat("x", 200)
	vec, err := client.Embed(context.Background(), longText)
	require.NoError(t, err)
	assert.Equal(t, []float32{0.5}, vec)
}

func TestHTTPClient_EmbedErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	client := NewHTTPClient(Config{BaseURL: server.URL, Model: "bge"})
	_, err := client.Embed(context.Background(), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
}

func TestNoopClient_Embed(t *testing.T) {
	client := &NoopClient{}
	vec, err := client.Embed(context.Background(), "any text")
	require.NoError(t, err)
	assert.Empty(t, vec)
}

func TestStaticClient_Embed(t *testing.T) {
	fixed := []float32{0.9, 0.1, 0.5}
	client := &StaticClient{Embedding: fixed}

	vec, err := client.Embed(context.Background(), "hello")
	require.NoError(t, err)
	assert.Equal(t, fixed, vec)

	vec2, err := client.Embed(context.Background(), "world")
	require.NoError(t, err)
	assert.Equal(t, fixed, vec2)
}

func TestHTTPClient_EmbedWithAPIKey(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		resp := EmbeddingResponse{
			Data: []EmbeddingData{{Index: 0, Embedding: []float32{1.0}, Object: "embedding"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{
		BaseURL: server.URL,
		Model:   "bge",
		APIKey:  "secret-key-123",
	})
	_, err := client.Embed(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, "Bearer secret-key-123", receivedAuth)
}

func TestHTTPClient_EmbedNoData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := EmbeddingResponse{Data: []EmbeddingData{}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPClient(Config{BaseURL: server.URL, Model: "bge"})
	_, err := client.Embed(context.Background(), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no data")
}

func TestEmbedURL(t *testing.T) {
	// embedURL is unexported; verify behavior indirectly via HTTP path.
	resp := EmbeddingResponse{
		Data:  []EmbeddingData{{Index: 0, Embedding: []float32{1}, Object: "embedding"}},
		Model: "bge",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/embeddings", r.URL.Path)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client2 := NewHTTPClient(Config{BaseURL: server.URL + "/", Model: "bge"})
	vec, err := client2.Embed(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, []float32{1}, vec)
}

// TestHTTPClient_SpaceVersion pins the embedding-space identity contract
// (N03-P04-T02): the version is deterministic per configuration, changes
// exactly when the space changes (model or query prefix), and ignores
// properties that do not affect comparability (base URL, endpoint style,
// timeouts). The semantic cache refuses to compare vectors across different
// versions, so a false "same space" here would silently re-open the
// mixed-space false-hit defect, and a spurious difference would thrash the
// cache on every restart.
func TestHTTPClient_SpaceVersion(t *testing.T) {
	base := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5"})

	// Deterministic and stable across constructions.
	again := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5"})
	assert.Equal(t, base.SpaceVersion(), again.SpaceVersion())
	assert.NotEmpty(t, base.SpaceVersion())
	assert.True(t, strings.HasPrefix(base.SpaceVersion(), "emb1:"),
		"version must be namespaced, got %q", base.SpaceVersion())

	// A different model is a different space.
	otherModel := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "text-embedding-3-small"})
	assert.NotEqual(t, base.SpaceVersion(), otherModel.SpaceVersion())

	// A different query prefix is a different space (the prefix shifts
	// every input, so vectors are not comparable across the change).
	otherPrefix := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5", QueryPrefix: "query: "})
	assert.NotEqual(t, base.SpaceVersion(), otherPrefix.SpaceVersion())

	// Non-space properties must NOT change the version.
	otherURL := NewHTTPClient(Config{BaseURL: "http://elsewhere:9000/v1", Model: "BAAI/bge-small-en-v1.5", Timeout: 5})
	assert.Equal(t, base.SpaceVersion(), otherURL.SpaceVersion())
	teiStyle := NewHTTPClient(Config{BaseURL: "http://embedder:8000", Model: "BAAI/bge-small-en-v1.5", Endpoint: EndpointTEI})
	assert.Equal(t, base.SpaceVersion(), teiStyle.SpaceVersion())

	// The interface is satisfied by *HTTPClient only; test stubs stay
	// version-blind by design (asserted on the cache side).
	var _ SpaceVersioner = base
}
