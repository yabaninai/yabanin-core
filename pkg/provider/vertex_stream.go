// Package provider — Vertex :streamGenerateContent SSE → OpenAI chunk
// translation.
//
// With ?alt=sse the Vertex stream endpoint emits one JSON
// generateContentResponse event per SSE data frame. Each event carries zero
// or more candidate parts (text deltas, complete functionCall objects —
// Gemini does NOT split tool-call arguments across events), an optional
// finishReason, and usageMetadata on the terminal event. The handler
// translates each event into zero or more OpenAI chat.completion.chunk
// frames and always terminates the client stream with `data: [DONE]`,
// including when the upstream closes without a finishReason.
//
// The handler carries no per-request state from the wiring site (stream.go
// constructs handlers by provider name with no arguments), so chunk ids are
// generated here and the chunk "model" is the payload's modelVersion echo.
package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// vertexStreamTerminator is the StreamHandler installed for "vertex". The
// historical name is load-bearing: stream.go resolves the handler by provider
// name and constructs it as a zero-field value. It is now a translating
// handler — the Gemini SSE stream is never passed through verbatim.
type vertexStreamTerminator struct{}

// HandleStream implements StreamHandler. Usage comes from the terminal
// event's usageMetadata (canonical fold applied). A stream that ends without
// usageMetadata returns Usage with Source "none" (no request-bytes estimate
// is available at the handler without wiring state).
func (vertexStreamTerminator) HandleStream(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, resp *http.Response) (Usage, error) {
	if resp == nil || resp.Body == nil {
		return Usage{}, errors.New("vertex stream: nil upstream response")
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), maxStreamLineBytes)

	tr := newVertexStreamTranslator()
	for scanner.Scan() {
		// Surface client-disconnect / ctx cancellation promptly.
		if err := ctx.Err(); err != nil {
			return tr.usage, err
		}
		line := scanner.Bytes()
		if !startsWith(line, "data: ") {
			continue // SSE comments and non-data field lines carry no payload
		}
		payload := line[len("data: "):]
		if len(payload) == 0 {
			continue
		}
		chunks, done, terr := tr.translate(payload)
		if terr != nil {
			return tr.usage, terr
		}
		for _, chunk := range chunks {
			if _, werr := fmt.Fprintf(w, "data: %s\n\n", chunk); werr != nil {
				return tr.usage, fmt.Errorf("stream write failed: %w", werr)
			}
			flusher.Flush()
		}
		if done {
			if derr := writeDone(w, flusher); derr != nil {
				return tr.usage, derr
			}
			return tr.finishUsage(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return tr.usage, fmt.Errorf("stream read failed: %w", err)
	}

	// Upstream closed without a finishReason event (abrupt disconnect).
	// Emit [DONE] so OpenAI clients terminate cleanly.
	if derr := writeDone(w, flusher); derr != nil {
		return tr.usage, derr
	}
	return tr.finishUsage(), nil
}

// vertexStreamEvent is one SSE event's generateContentResponse shape (same
// candidate schema as the non-streaming response).
type vertexStreamEvent struct {
	Candidates     []vertexCandidate    `json:"candidates"`
	UsageMetadata  *vertexUsageMetadata `json:"usageMetadata"`
	ModelVersion   string               `json:"modelVersion"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// vertexStreamTranslator converts one event into zero or more OpenAI chunks.
// Event → chunk mapping:
//
//	text part (thought=false) → delta {"content": …}
//	text part (thought=true)  → delta {"reasoning_content": …}
//	functionCall part         → delta {"tool_calls":[complete fragment]}
//	finishReason              → delta chunk with finish_reason + usage-only chunk; done
//	usageMetadata             → accumulated for the terminal usage chunk
//	top-level error object    → error carrying the provider's message verbatim
//	blocked prompt            → error (no successful chunks are fabricated)
type vertexStreamTranslator struct {
	msgID     string
	model     string
	usage     Usage
	toolIndex int
	sawTool   bool
	started   bool
	sawFinish bool
}

func newVertexStreamTranslator() *vertexStreamTranslator {
	return &vertexStreamTranslator{msgID: "chatcmpl-vertex-" + vertexRandomHex(16)}
}

// translate processes one SSE event payload. done is true after the event
// that carried the finishReason; the caller then writes [DONE].
func (t *vertexStreamTranslator) translate(payload []byte) (chunks []string, done bool, err error) {
	var ev vertexStreamEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, false, fmt.Errorf("vertex stream: decode event: %w", err)
	}
	if ev.Error != nil {
		return nil, false, fmt.Errorf("vertex stream error (status %s): %s", ev.Error.Status, ev.Error.Message)
	}
	if ev.PromptFeedback != nil && ev.PromptFeedback.BlockReason != "" {
		return nil, false, fmt.Errorf("vertex: prompt blocked by the upstream safety filters (blockReason %s)", ev.PromptFeedback.BlockReason)
	}
	if ev.ModelVersion != "" {
		t.model = ev.ModelVersion
	}
	if ev.UsageMetadata != nil {
		t.usage = ev.UsageMetadata.toUsage()
	}

	finish := ""
	for _, cand := range ev.Candidates {
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				switch part.kind() {
				case "text":
					if *part.Text == "" {
						continue
					}
					if !t.started {
						chunks = append(chunks, t.roleChunk())
						t.started = true
					}
					delta := map[string]any{"content": *part.Text}
					if part.Thought {
						delta = map[string]any{"reasoning_content": *part.Text}
					}
					chunks = append(chunks, t.deltaChunk(delta, nil))
				case "functionCall":
					if !t.started {
						chunks = append(chunks, t.roleChunk())
						t.started = true
					}
					chunks = append(chunks, t.toolCallChunk(part.FunctionCall))
				case "":
					// Empty part object: nothing to map.
				default:
					return nil, false, fmt.Errorf("vertex stream: unsupported response part kind %q; refusing to map it to an OpenAI chunk", part.kind())
				}
			}
		}
		if cand.FinishReason != "" {
			finish = cand.FinishReason
		}
	}

	if finish != "" {
		t.sawFinish = true
		reason, ferr := vertexFinishReason(finish, t.sawTool)
		if ferr != nil {
			return nil, false, ferr
		}
		chunks = append(chunks, t.deltaChunk(map[string]any{}, &reason), t.usageChunk())
		done = true
	}
	return chunks, done, nil
}

func (t *vertexStreamTranslator) toolCallChunk(fc *vertexFunctionCall) string {
	idx := t.toolIndex
	t.toolIndex++
	t.sawTool = true
	// Gemini delivers the complete functionCall in one event, so the
	// OpenAI fragment carries the full arguments (a valid fragment stream:
	// name and arguments on a single index).
	delta := map[string]any{
		"tool_calls": []any{map[string]any{
			"index": idx,
			"id":    "call_" + vertexRandomHex(8),
			"type":  "function",
			"function": map[string]any{
				"name":      fc.Name,
				"arguments": vertexArgsString(fc.Args),
			},
		}},
	}
	return t.deltaChunk(delta, nil)
}

// finishUsage classifies a stream that ended without usageMetadata.
func (t *vertexStreamTranslator) finishUsage() Usage {
	if t.usage.Source == "" {
		t.usage.Source = UsageSourceNone
	}
	return t.usage
}

func (t *vertexStreamTranslator) roleChunk() string {
	return t.deltaChunk(map[string]any{"role": "assistant"}, nil)
}

func (t *vertexStreamTranslator) usageChunk() string {
	u := t.finishUsage()
	usage := map[string]any{
		"prompt_tokens":     u.PromptTokens,
		"completion_tokens": u.CompletionTokens,
		"total_tokens":      u.TotalTokens,
	}
	if u.CacheReadTokens > 0 {
		usage["prompt_tokens_details"] = map[string]any{"cached_tokens": u.CacheReadTokens}
	}
	chunk := map[string]any{
		"id":      t.msgID,
		"object":  "chat.completion.chunk",
		"model":   t.model,
		"choices": []any{},
		"usage":   usage,
	}
	b, _ := json.Marshal(chunk)
	return string(b)
}

func (t *vertexStreamTranslator) deltaChunk(delta map[string]any, finishReason *string) string {
	choice := map[string]any{
		"index":         0,
		"delta":         delta,
		"finish_reason": nil,
	}
	if finishReason != nil {
		choice["finish_reason"] = *finishReason
	}
	chunk := map[string]any{
		"id":      t.msgID,
		"object":  "chat.completion.chunk",
		"model":   t.model,
		"choices": []any{choice},
	}
	b, _ := json.Marshal(chunk)
	return string(b)
}
