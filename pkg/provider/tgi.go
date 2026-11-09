package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TGI (Text-Generation-Inference) adapter. TGI does NOT use the /v1 prefix;
// non-streaming chat goes to /generate with {inputs, parameters}. We translate
// the OpenAI chat body into TGI's inputs format and translate the response back.
type TGI struct{}

// Name returns the provider name "tgi".
func (TGI) Name() string { return "tgi" }

// Path returns the TGI endpoint: /generate (non-streaming) or /v1/chat/completions (streaming).
func (TGI) Path(stream bool) string {
	if stream {
		return "/v1/chat/completions" // TGI also has an OpenAI-compat shim; use it for streaming
	}
	return "/generate"
}

// PrepareRequest builds a request for TGI. The chat→generate translation
// happens HERE, not in TranslateRequest: the TGI wire format is
// stream-dependent, so a TranslateRequest-time translation would be
// double-translated on the non-stream path (empty prompt) and sent to the
// OpenAI-compat streaming shim in the wrong schema.
func (TGI) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	payload := body
	if !stream {
		p, err := TranslateChatToTGI(body)
		if err != nil {
			return nil, err
		}
		payload = p
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return req, nil
}

// ParseUsage extracts token counts from a TGI response via the shared
// OpenAI-compat parser. TGI /generate returns {generated_text, ...} with no
// token counts by default; the streaming-openai-compat path reports usage
// normally.
func (TGI) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

// TranslateChatToTGI converts an OpenAI chat request into TGI's
// {"inputs": "...", "parameters": {...}} shape.
func TranslateChatToTGI(openaiBody []byte) ([]byte, error) {
	var chat struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
		Stream      bool    `json:"stream"`
	}
	if err := json.Unmarshal(openaiBody, &chat); err != nil {
		return nil, fmt.Errorf("tgi translate: parse openai body: %w", err)
	}
	// Flatten messages into a prompt string (role: content per line).
	var prompt string
	for _, m := range chat.Messages {
		prompt += m.Role + ": " + m.Content + "\n"
	}
	out := map[string]interface{}{
		"inputs": prompt,
		"parameters": map[string]interface{}{
			"max_new_tokens": chat.MaxTokens,
			"temperature":    chat.Temperature,
		},
	}
	if chat.Stream {
		out["stream"] = true
	}
	return json.Marshal(out)
}

// TranslateRequest is identity. The OpenAI→TGI translation is stream-dependent
// and therefore lives in PrepareRequest: upstream.Client runs TranslateRequest
// before the model override and before the stream/non-stream split, so a
// TranslateRequest-time translation would (a) be re-translated by
// PrepareRequest on the non-stream path, producing an empty prompt, and
// (b) corrupt the OpenAI-compat streaming shim payload.
func (TGI) TranslateRequest(b []byte) ([]byte, error) { return b, nil }

// TranslateResponse wraps TGI generated_text into OpenAI response shape.
func (TGI) TranslateResponse(providerBody []byte) ([]byte, error) {
	// Wrap TGI generated_text into an OpenAI-shaped choice.
	var r struct {
		GeneratedText string `json:"generated_text"`
	}
	if err := json.Unmarshal(providerBody, &r); err != nil {
		// Might already be openai-shaped (streaming shim); pass through with error so caller knows.
		return providerBody, fmt.Errorf("openai-shape parse: %w", err)
	}
	resp := map[string]interface{}{
		"choices": []map[string]interface{}{
			{"message": map[string]string{"role": "assistant", "content": r.GeneratedText}},
		},
	}
	return json.Marshal(resp)
}
