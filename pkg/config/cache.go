// Package config holds gateway configuration parameters.
package config

import (
	"fmt"
	"os"
	"strings"
)

// EmbedderConfig holds configuration for the semantic cache embedding service.
type EmbedderConfig struct {
	Enabled bool   // whether to enable semantic cache embeddings
	BaseURL string // e.g., "http://bge-embedder:6006" (env: YABANIN_EMBEDDER_BASE_URL)
	Model   string // e.g., "BAAI/bge-small-en-v1.5" (env: YABANIN_EMBEDDER_MODEL)
	// ModelExplicit records that the operator set YABANIN_EMBEDDER_MODEL
	// hard-refuses only the DISTRIBUTION default model; an explicitly
	// configured external model is the operator's own supply chain.
	ModelExplicit bool
	APIKey        string // auth token for the embedder (env: YABANIN_EMBEDDER_API_KEY)
	Timeout       int    // per-request timeout in seconds (default 30)
	MaxChars      int    // max input chars per request (default 8191)
	Endpoint      string // "openai" or "tei" (env: YABANIN_EMBEDDER_ENDPOINT)
	QueryPrefix   string // prepended to every embedded text, e.g. "query: " for e5 models (env: YABANIN_EMBEDDER_QUERY_PREFIX)
}

// NewEmbedderConfig reads embedder configuration from environment variables.
//
// Numeric fields (YABANIN_EMBEDDER_TIMEOUT, YABANIN_EMBEDDER_MAX_CHARS) use
// via envInt): a malformed value never partially parses — the historical
// fmt.Sscanf silently accepted the prefix "5x" as 5. Instead the field keeps
// its default and a warning naming the variable, the value and the expected
// kind ("integer") is emitted.
//
// These fields are read lazily via Gateway.Embedder, outside Load, so they
// always take the warn-and-default path: YABANIN_CONFIG_STRICT=1 does not
// gate them (strict enforcement requires the envDiag collected inside Load).
func NewEmbedderConfig() EmbedderConfig {
	d := &envDiag{}
	embedderModelEnv := os.Getenv("YABANIN_EMBEDDER_MODEL")
	cfg := EmbedderConfig{
		BaseURL:       os.Getenv("YABANIN_EMBEDDER_BASE_URL"),
		Model:         embedderModelEnv,
		ModelExplicit: embedderModelEnv != "",
		APIKey:        os.Getenv("YABANIN_EMBEDDER_API_KEY"),
		Timeout:       envInt(d, "YABANIN_EMBEDDER_TIMEOUT", 30),
		MaxChars:      envInt(d, "YABANIN_EMBEDDER_MAX_CHARS", 8191),
		Endpoint:      "openai",
	}

	if v := os.Getenv("YABANIN_EMBEDDER_ENABLED"); strings.EqualFold(v, "true") {
		cfg.Enabled = true
	}
	if v := os.Getenv("YABANIN_EMBEDDER_ENDPOINT"); v != "" {
		cfg.Endpoint = strings.ToLower(v)
	}
	cfg.QueryPrefix = os.Getenv("YABANIN_EMBEDDER_QUERY_PREFIX")

	return cfg
}

// Validate checks that required fields are set when enabled.
func (c *EmbedderConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.BaseURL == "" {
		return fmt.Errorf("embedder_config: YABANIN_EMBEDDER_BASE_URL is required when enabled")
	}
	if c.Model == "" {
		c.Model = "BAAI/bge-small-en-v1.5" // sensible default for TEI
	}
	return nil
}
