// Package embeddings provides abstraction for text embedding services used by the semantic cache.
package embeddings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client abstracts a text embedding service that produces fixed-dimension float32 vectors.
type Client interface {
	// Embed converts text into a 384-dim embedding vector (for bge-small-en).
	Embed(ctx context.Context, text string) ([]float32, error)
}

// SpaceVersioner is implemented by embedders that can identify the vector
// space their configuration produces (N03-P04-T02: versioned embeddings).
// Cosine similarity is only meaningful between vectors from the SAME space:
// the same text embedded with a different model or query prefix yields
// incomparable vectors, and comparing them produced false semantic-cache
// hits. The semantic cache records the space version with every entry and
// serves an entry only when the stored version equals the current embedder's
// version; embedders that do not implement this interface are version-blind
// (empty version) and stay mutually compatible, which keeps test stubs and
// legacy entries working unchanged.
type SpaceVersioner interface {
	// SpaceVersion returns a stable identifier of the embedding space
	// produced by this client's current configuration.
	SpaceVersion() string
}

// EndpointStyle controls which API endpoint URL the client uses.
type EndpointStyle string

const (
	// EndpointOpenAI is the OpenAI-compatible embeddings path (/v1/embeddings).
	EndpointOpenAI EndpointStyle = "openai"
	// EndpointTEI is the HuggingFace TEI sidecar path (/embed).
	EndpointTEI EndpointStyle = "tei"
)

// Config holds the configuration for an embedding service client.
type Config struct {
	BaseURL     string        // e.g., "http://bge-embedder:8000" or "https://api.openai.com/v1"
	Model       string        // e.g., "BAAI/bge-small-en-v1.5" or "text-embedding-3-small"
	APIKey      string        // optional, for authenticated services
	Timeout     int           // per-request timeout in seconds (default 30)
	MaxChars    int           // max input chars per request (default 8191)
	Endpoint    EndpointStyle // "openai" or "tei" (default: openai)
	QueryPrefix string        // prepended to every embedded text (e.g., "query: " for e5 models); must be identical on lookups and writes so cosine comparisons stay valid
	// QualifyScripts enables multilingual qualifier separation
	// (N03-P04-T03): each input's dominant script becomes a qualifier tag
	// that is part of the embedding input (QualifierInputPrefix) and of the
	// per-input space identity the cache resolves through InputQualifierTag.
	// With it on, a Russian near-duplicate of an English question is a
	// DIFFERENT space — it can never hit an English entry no matter what
	// cosine similarity the embedder reports. Off by default: disabled
	// clients are qualifier-blind and keep the exact pre-T03 behavior.
	QualifyScripts bool
	// ContextQualifier is a static domain/context qualifier (N03-P04-T03),
	// e.g. "support-billing": it partitions entries by deployment context so
	// cross-domain reuse cannot alias one embedder model into one space. It
	// participates in the space identity (SpaceVersion) and in the
	// per-input qualifier tag; empty (default) keeps the SpaceVersion
	// byte-identical to the N03-P04-T02 format.
	ContextQualifier string
}

// HTTPClient implements Client by calling an embedding endpoint (OpenAI-compatible or TEI).
// It also implements SpaceVersioner and, when configured for multilingual
// qualification (N03-P04-T03), InputQualifier.
type HTTPClient struct {
	baseURL     string
	model       string
	apiKey      string
	timeout     int
	maxChars    int
	endpoint    EndpointStyle
	queryPrefix string
	// Qualifier configuration (N03-P04-T03); see Config.QualifyScripts and
	// Config.ContextQualifier.
	qualifyScripts   bool
	contextQualifier string
	httpc            *http.Client
}

// NewHTTPClient creates a new embedding client backed by an HTTP API.
func NewHTTPClient(cfg Config) *HTTPClient {
	t := 30 * time.Second
	if cfg.Timeout > 0 {
		t = time.Duration(cfg.Timeout) * time.Second
	}
	ep := cfg.Endpoint
	if ep == "" {
		ep = EndpointOpenAI // default to OpenAI-compatible
	}
	return &HTTPClient{
		baseURL:          cfg.BaseURL,
		model:            cfg.Model,
		apiKey:           cfg.APIKey,
		timeout:          cfg.Timeout,
		maxChars:         cfg.MaxChars,
		endpoint:         ep,
		queryPrefix:      cfg.QueryPrefix,
		qualifyScripts:   cfg.QualifyScripts,
		contextQualifier: cfg.ContextQualifier,
		httpc: &http.Client{
			Timeout: t,
		},
	}
}

// SpaceVersion returns a stable identifier of the embedding space this
// client's configuration produces: the model and the query prefix are the
// two inputs that change vector values incompatibly (a different prefix
// shifts every input, a different model changes the geometry). The endpoint
// style and base URL are deliberately excluded — the same model+prefix
// reached through a different URL or API shape is the same space. The value
// is derived, not configured, so a config change can never go unnoticed:
// lookups and writes record it and the cache refuses to compare vectors
// across different values.
//
// N03-P04-T03: a non-empty Config.ContextQualifier is part of the seed — a
// deployment that re-scopes the embedder to another domain starts a new
// space instead of silently comparing vectors across contexts. An empty
// ContextQualifier keeps the seed byte-identical to the N03-P04-T02
// format, so rolling this code out does not by itself invalidate existing
// spaces. Per-input multilingual qualifiers are NOT part of this static
// version: they are per-prompt and enter identity through
// InputQualifierTag + embeddings.QualifiedSpaceVersion on both cache paths.
func (c *HTTPClient) SpaceVersion() string {
	seed := "emb1\x00" + c.model + "\x00" + c.queryPrefix
	if c.contextQualifier != "" {
		seed += "\x00d:" + c.contextQualifier
	}
	h := sha256.Sum256([]byte(seed))
	return "emb1:" + hex.EncodeToString(h[:6])
}

// Embed sends a text string to the embedding service and returns the vector.
func (c *HTTPClient) Embed(ctx context.Context, text string) ([]float32, error) {
	// Prepend the configured prefix (e5-family models require "query: " /
	// "passage: " style prefixes; keeping it identical on lookups and writes
	// preserves symmetric cosine comparisons).
	if c.queryPrefix != "" {
		text = c.queryPrefix + text
	}

	// Truncate input if too long.
	if c.maxChars > 0 && len(text) > c.maxChars {
		text = text[:c.maxChars]
	}

	payload, err := json.Marshal(map[string]interface{}{
		"model": c.model,
		"input": text,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal embedding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.embedURL(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode embedding response: %w", err)
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("embedding response has no data")
	}

	return result.Data[0].Embedding, nil
}

func (c *HTTPClient) embedURL() string {
	base := strings.TrimSuffix(c.baseURL, "/")
	switch c.endpoint {
	case EndpointTEI:
		return base + "/embed"
	default:
		return base + "/v1/embeddings"
	}
}

// EmbeddingRequest matches the OpenAI-compatible embedding API request format.
type EmbeddingRequest struct {
	Model string      `json:"model"`
	Input interface{} `json:"input"`
}

// EmbeddingResponse matches the OpenAI-compatible embedding API response format.
type EmbeddingResponse struct {
	Data  []EmbeddingData `json:"data"`
	Model string          `json:"model"`
	Usage Usage           `json:"usage"`
}

// EmbeddingData holds a single embedding vector and its metadata.
type EmbeddingData struct {
	Index     int       `json:"index"`
	Embedding []float32 `json:"embedding"`
	Object    string    `json:"object"`
}

// Usage contains token usage information.
type Usage struct {
	PromptTokens        int `json:"prompt_tokens"`
	TotalTokens         int `json:"total_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// NoopClient is a testing stub that returns zero embeddings.
type NoopClient struct{}

// Embed returns the embedding vector for a single input text.
// Embed.
func (n *NoopClient) Embed(ctx context.Context, text string) ([]float32, error) {
	return []float32{}, nil
}

// StaticClient returns a fixed embedding regardless of input — useful for tests.
type StaticClient struct {
	Embedding []float32
}

// Embed returns the embedding vector for a single input text.
// Embed.
func (s *StaticClient) Embed(ctx context.Context, text string) ([]float32, error) {
	return s.Embedding, nil
}
