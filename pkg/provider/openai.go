package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// OpenAI is the adapter for OpenAI and any OpenAI-compatible upstream
// (vLLM, llama.cpp server, LM Studio, Together, Groq, ...). Request and
// response bodies pass through unchanged; auth is Bearer.
type OpenAI struct{}

// Name returns the provider identifier used in logs and metrics.
// Name.
func (OpenAI) Name() string { return "openai" }

// Path returns the upstream API path for this provider.
// Path.
func (OpenAI) Path(_ bool) string { return "/v1/chat/completions" }

// PrepareRequest adapts the gateway request for this provider's upstream.
// PrepareRequest.
func (OpenAI) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	// If baseURL already contains a version segment (e.g. /v4 for Z.ai),
	// strip the /v1 prefix from path to avoid double-versioning.
	if hasVersionSegment(baseURL) {
		path = strings.Replace(path, "/v1/", "/", 1)
	}
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build openai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

// TranslateRequest maps an Anthropic-style body to OpenAI-compatible fields.
// TranslateRequest.
func (OpenAI) TranslateRequest(body []byte) ([]byte, error) { return body, nil }

// TranslateResponse maps an Anthropic-style response back to OpenAI-compatible fields.
// TranslateResponse.
func (OpenAI) TranslateResponse(body []byte) ([]byte, error) { return body, nil }

// ParseUsage extracts token usage from an OpenAI-compatible response body.
// It delegates to the shared parser so streaming and non-streaming parse the
// same cache-read fields (prompt_tokens_details.cached_tokens with the
// legacy DeepSeek prompt_cache_hit_tokens fallback).
// ParseUsage.
func (OpenAI) ParseUsage(respBody []byte) Usage {
	return openAIParseUsage(respBody)
}

var versionRe = regexp.MustCompile(`/v\d+(/|$)`)

func hasVersionSegment(baseURL string) bool {
	return versionRe.MatchString(baseURL)
}
