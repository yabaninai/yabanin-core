package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Jais adapter for G42 / Inception (HQ Abu Dhabi, UAE). OpenAI-compatible at
// POST {base}/v1/chat/completions with Bearer auth. The upstream requires the
// "model" field to be one of its served names (jais-30b-chat); TranslateRequest
// rewrites the incoming model name to the canonical jais model.
// Sovereignty tier: open_weights (seed) / full (G42 cloud, GCC jurisdiction).
type Jais struct{}

// jaisModel is the canonical served-model name on the G42 endpoint.
const jaisModel = "jais-30b-chat"

func (Jais) Name() string { return "jais" }

func (Jais) Path(_ bool) string { return "/v1/chat/completions" }

func (Jais) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build jais request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

// TranslateRequest rewrites the "model" field to the canonical jais name so
// callers can pass any alias (e.g. the registry model_name "jais-30b").
func (Jais) TranslateRequest(body []byte) ([]byte, error) {
	return pinJaisModel(body)
}

// FinalizeModel implements ModelFinalizer: upstream.Client's per-hop model
// override runs after TranslateRequest and would otherwise clobber the
// canonical name with the registry alias, so it is re-asserted here.
func (Jais) FinalizeModel(body []byte, _ string) []byte {
	pinned, err := pinJaisModel(body)
	if err != nil {
		return body
	}
	return pinned
}

// pinJaisModel forces the "model" field to the canonical jais served name.
func pinJaisModel(body []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("jais: decode request body: %w", err)
	}
	m["model"] = jaisModel
	return json.Marshal(m)
}

func (Jais) TranslateResponse(b []byte) ([]byte, error) { return b, nil }

func (Jais) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }
