package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/openai"
)

// isRawBody reports whether the client request carries an upstream-native
// body that must be forwarded as-is (no schema translation, no fallback).
//
// Two triggers (P3.14):
//
//  1. Explicit opt-in header `X-Yabanin-Raw-Body: 1` — the caller asserts
//     "this body is already in my target provider's native format, don't
//     touch it". Useful when proxying native Anthropic-format requests
//     straight to the Anthropic upstream without going through the OpenAI
//     schema translation layer.
//
//  2. Non-JSON Content-Type — anything other than `application/json` (with
//     or without charset suffix) is treated as raw. application/json is the
//     default OpenAI shape; other content types are not.
//
// In raw mode the gateway:
//   - forwards the body verbatim (no `model` field rewriting),
//   - skips TranslateRequest for the bound adapter,
//   - disables the fallback chain (body is provider-specific).
func isRawBody(r *http.Request) bool {
	if v := r.Header.Get("X-Yabanin-Raw-Body"); v == "1" || strings.EqualFold(v, "true") {
		return true
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	// Strip ;charset=... before comparing.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return !strings.EqualFold(ct, "application/json")
}

// clientNoStore reports whether any Cache-Control field value of the request
// carries a no-store directive (CACHE-01, RFC 9111 §5.2): directive names are
// case-insensitive, the field value is a comma-separated list, and that list
// may be split across several header lines. A single Header.Get byte
// comparison sees none of those spellings and silently leaves the cache
// enabled for requests the client explicitly forbade storing. Only the
// directive NAME (everything up to '=' or the list separator) participates in
// the match, so "x-no-store" never matches, while an unusual parameter form
// such as `no-store=1` still fails safe toward the client's privacy intent.
func clientNoStore(r *http.Request) bool {
	for _, v := range r.Header.Values("Cache-Control") {
		for _, dir := range strings.Split(v, ",") {
			name := dir
			if eq := strings.IndexByte(dir, '='); eq >= 0 {
				name = dir[:eq]
			}
			if strings.EqualFold(strings.TrimSpace(name), "no-store") {
				return true
			}
		}
	}
	return false
}

// shouldCache returns true if the response body should be written to cache.
// It skips caching for error responses (5xx), responses with Cache-Control: no-store,
// and empty bodies. The check is done by parsing the JSON response for an "error" field
// or checking for common error status indicators.
//
// FIX-10 (N03-P02-T09): the gate only admits bodies that decode as a
// chat.completion document carrying at least one choice. Undecodable or
// truncated bytes can never serve from the cache (the read probe degrades
// them to a miss), and a semantically empty document (`{}`, `{"choices":[]}`)
// is already rejected by the streaming replay — writing either just poisons
// the entry for the next request.
func shouldCache(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Only decodable JSON objects are cacheable; an unmarshal failure here
	// means truncated or non-JSON bytes (HTML error pages, torn bodies).
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false
	}

	// Skip if body contains an error field (OpenAI-compatible API returns {"error": {...}}).
	if _, hasError := resp["error"]; hasError {
		return false
	}

	// Mirror the read contract: a completion document must carry at least
	// one choice, or it is semantically empty and must not be written.
	choices, _ := resp["choices"].([]interface{})
	if len(choices) == 0 {
		return false
	}

	// H3 (saw-terminal contract): every choice must carry a non-null
	// finish_reason. A stream cut before its terminal event never emits
	// the finish chunk, so a finish_reason-less document is the truncated
	// shape — writing it would poison the entry for every later read (the
	// read probe refuses it) and pin a partial answer in the cache.
	for _, raw := range choices {
		choice, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		if fr, present := choice["finish_reason"]; !present || fr == nil {
			return false
		}
	}

	// Skip Cache-Control: no-store — always go upstream.
	// Note: this check is applied to outgoing requests in the request handler,
	// not here. The gateway already skips cache lookup when the client sends
	// Cache-Control: no-store via a separate path (see chatCompletions before Lookup).

	return true
}

// extractUserPrompt returns the last message text as the actionable prompt.
func extractUserPrompt(messages []openai.ChatMessage) string {
	if len(messages) == 0 {
		return ""
	}
	return messages[len(messages)-1].Content
}

// extractAllMessages returns normalized text from all messages.
func extractAllMessages(messages []openai.ChatMessage) []string {
	out := make([]string, 0, len(messages))
	for _, m := range messages {
		if m.Content != "" {
			out = append(out, m.Content)
		}
	}
	return out
}

// estimateContextTokens approximates token count from message text (~4 chars per token).
func estimateContextTokens(messages []openai.ChatMessage) int {
	total := 0
	for _, m := range messages {
		total += len(m.Content) / 4
	}
	return total
}

// extractChatMessages extracts the messages array from a chat completion request body.
func extractChatMessages(body []byte) []map[string]interface{} {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	msgs, _ := parsed["messages"].([]interface{})
	result := make([]map[string]interface{}, 0, len(msgs))
	for _, m := range msgs {
		if mm, ok := m.(map[string]interface{}); ok {
			result = append(result, mm)
		}
	}
	return result
}

// extractSystemMessage returns the system prompt from messages (first message with role="system").
func extractSystemMessage(messages []openai.ChatMessage) string {
	for _, m := range messages {
		if strings.EqualFold(m.Role, "system") {
			return m.Content
		}
	}
	return ""
}

// patchLastMessageContent rewrites the content of the LAST entry of the
// top-level "messages" array in the raw JSON body (RT-04). The patch runs on
// the guarded raw JSON — never on a re-serialized typed projection — so
// unknown provider fields, tools and every other message survive unchanged;
// only the last message's content is replaced.
//
// String content is replaced directly. Multimodal (array) content keeps its
// shape: with exactly one text part only that part's "text" field is
// replaced (image and other parts are preserved); otherwise the whole
// content value becomes the plain text, matching the collapsed view of the
// content the vertical actually transformed.
func patchLastMessageContent(body []byte, content string) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse request body: %w", err)
	}
	rawMsgs, ok := root["messages"]
	if !ok {
		return nil, errors.New("request body has no messages array")
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(rawMsgs, &msgs); err != nil {
		return nil, fmt.Errorf("parse messages array: %w", err)
	}
	if len(msgs) == 0 {
		return nil, errors.New("messages array is empty")
	}
	textEnc, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("encode replacement content: %w", err)
	}
	patched, err := patchMessageContent(msgs[len(msgs)-1], textEnc)
	if err != nil {
		return nil, err
	}
	msgs[len(msgs)-1] = patched
	encMsgs, err := json.Marshal(msgs)
	if err != nil {
		return nil, fmt.Errorf("encode messages: %w", err)
	}
	root["messages"] = encMsgs
	out, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}
	return out, nil
}

// patchMessageContent returns the message with its content replaced by
// textEnc, preserving multimodal parts when the shape allows it.
func patchMessageContent(rawMsg, textEnc json.RawMessage) (json.RawMessage, error) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}
	content := textEnc
	if rawContent, ok := msg["content"]; ok && len(rawContent) > 0 && rawContent[0] == '[' {
		patched, err := patchSingleTextPart(rawContent, textEnc)
		if err != nil {
			return nil, err
		}
		if patched != nil {
			content = patched
		}
	}
	msg["content"] = content
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode message: %w", err)
	}
	return out, nil
}

// patchSingleTextPart rewrites the "text" of the only text part in a
// multimodal content array, preserving every other part. It returns
// (nil, nil) when the array does not carry exactly one text part; the caller
// then replaces the whole content value with the plain text.
func patchSingleTextPart(raw, textEnc json.RawMessage) (json.RawMessage, error) {
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("parse content parts: %w", err)
	}
	textIdx := -1
	textParts := 0
	for i, p := range parts {
		var typ string
		if t, ok := p["type"]; ok {
			if err := json.Unmarshal(t, &typ); err != nil {
				return nil, fmt.Errorf("parse content part type: %w", err)
			}
		}
		if typ == "" || typ == "text" {
			textParts++
			textIdx = i
		}
	}
	if textParts != 1 {
		return nil, nil
	}
	parts[textIdx]["text"] = textEnc
	out, err := json.Marshal(parts)
	if err != nil {
		return nil, fmt.Errorf("encode content parts: %w", err)
	}
	return out, nil
}
