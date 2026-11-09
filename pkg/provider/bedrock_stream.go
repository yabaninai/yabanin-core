// Package provider — Bedrock ConverseStream → OpenAI SSE translation
// (N08-P02-T02).
//
// ConverseStream does NOT speak SSE: a 200 response carries the binary AWS
// eventstream format (Content-Type application/vnd.amazon.eventstream), each
// frame a length-prefixed, CRC-checked message whose ":event-type" header
// names the event and whose payload is one JSON structure (messageStart,
// contentBlockDelta, messageStop, metadata, …). bedrockStreamHandler decodes
// those frames and re-emits OpenAI chat.completion.chunk SSE frames so an
// OpenAI client streams transparently (I49/I50). The OpenAI stream always
// terminates with `data: [DONE]` — the ConverseStream analogue of the
// terminator is the metadata event that follows messageStop.
//
// Mid-stream exceptions arrive as eventstream frames with the
// ":exception-type" header (e.g. ThrottlingException) and a JSON payload
// carrying the provider's precise message. That message is surfaced
// unrewritten in the returned error (I51: refusals pass through verbatim).
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	eventstream "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// Eventstream protocol headers (AWS event stream encoding spec).
const (
	bedrockHdrMessageType = ":message-type" // "event" | "exception"
	bedrockHdrEventType   = ":event-type"   // e.g. "contentBlockDelta"
	bedrockHdrException   = ":exception-type"
)

// ConverseStream event-type values (bedrockruntime ConverseStreamOutput
// union members; identical on the REST wire).
const (
	bedrockEvMessageStart      = "messageStart"
	bedrockEvContentBlockDelta = "contentBlockDelta"
	bedrockEvContentBlockStart = "contentBlockStart"
	bedrockEvContentBlockStop  = "contentBlockStop"
	bedrockEvMessageStop       = "messageStop"
	bedrockEvMetadata          = "metadata"
)

// bedrockStreamHandler drains a Bedrock ConverseStream response and writes
// OpenAI chat.completion.chunk SSE frames. Construction mirrors the
// anthropic handler (SuppressUsageOnlyChunk keeps the usage parse but drops
// the client-facing choices:[] chunk).
type bedrockStreamHandler struct {
	model     string
	emitUsage bool
}

// HandleStream implements StreamHandler. Usage comes from the metadata
// event's ConverseStream TokenUsage (canonical fold applied — cache reads
// and writes included in PromptTokens, same convention as non-streaming).
// A stream that ends without metadata returns Usage with Source set to
// "none" plus an error wrapping ErrStreamIncomplete (H3 saw-terminal
// contract); the caller-side estimate fallback applies as for other
// providers.
func (h *bedrockStreamHandler) HandleStream(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, resp *http.Response) (Usage, error) {
	tr := newBedrockStreamTranslator(h.model, h.emitUsage)

	dec := eventstream.NewDecoder()
	payloadBuf := make([]byte, 0, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return tr.usage, err
		}
		msg, err := dec.Decode(resp.Body, payloadBuf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return tr.usage, fmt.Errorf("bedrock stream: decode event frame: %w", err)
		}

		chunk, done, terr := tr.translate(msg)
		if terr != nil {
			return tr.usage, terr
		}
		if chunk != "" {
			if _, werr := fmt.Fprintf(w, "data: %s\n\n", chunk); werr != nil {
				return tr.usage, fmt.Errorf("stream write failed: %w", werr)
			}
			flusher.Flush()
		}
		if done {
			if derr := writeDone(w, flusher); derr != nil {
				return tr.usage, derr
			}
			return tr.usage, nil
		}
	}

	// Upstream closed without a metadata event (abnormal but seen with
	// abrupt disconnects). Emit [DONE] so OpenAI clients terminate cleanly
	// (H3 saw-terminal contract: the client-facing wire stays well-formed),
	// but report the run as incomplete — the gateway must not cache the
	// prefix and must not account it as a completed request. Usage parsed
	// so far is still returned; without metadata the source stays "none",
	// so the caller-side estimate fallback applies as for other providers.
	if derr := writeDone(w, flusher); derr != nil {
		return tr.usage, derr
	}
	return tr.finishUsage(), fmt.Errorf("bedrock stream ended without metadata event: %w", ErrStreamIncomplete)
}

// bedrockStreamTranslator converts one decoded eventstream message into
// zero or one OpenAI chunk. State: per-stream chunk id and accumulated
// usage. Event → chunk mapping:
//
//	messageStart      → delta chunk {"role":"assistant"}
//	contentBlockDelta → delta chunk {"content": text} (text deltas only)
//	contentBlockStart/Stop → nothing (tools are rejected at translate time)
//	messageStop       → delta chunk with finish_reason
//	metadata          → usage parsed; usage-only chunk when enabled; done
//	exception frame   → error carrying the provider's message verbatim
type bedrockStreamTranslator struct {
	model     string
	msgID     string
	emitUsage bool
	usage     Usage
	stopped   bool
}

func newBedrockStreamTranslator(model string, emitUsage bool) *bedrockStreamTranslator {
	return &bedrockStreamTranslator{
		model:     model,
		msgID:     "chatcmpl-bedrock-" + bedrockRandomHex(16),
		emitUsage: emitUsage,
	}
}

// translate processes one message. done is true after the terminal metadata
// event; the caller then writes [DONE].
func (t *bedrockStreamTranslator) translate(msg eventstream.Message) (chunk string, done bool, err error) {
	if msgType := headerString(msg.Headers, bedrockHdrMessageType); msgType == "exception" {
		return "", false, t.onException(msg)
	}
	eventType := headerString(msg.Headers, bedrockHdrEventType)
	switch eventType {
	case bedrockEvMessageStart:
		return t.onMessageStart(msg.Payload)
	case bedrockEvContentBlockDelta:
		return t.onDelta(msg.Payload)
	case bedrockEvMessageStop:
		return t.onMessageStop(msg.Payload)
	case bedrockEvMetadata:
		return t.onMetadata(msg.Payload)
	case bedrockEvContentBlockStart, bedrockEvContentBlockStop:
		// Text-only T02: block boundaries carry no OpenAI-visible payload.
		return "", false, nil
	default:
		// Unknown event types (service evolution) are skipped, not fatal.
		return "", false, nil
	}
}

func (t *bedrockStreamTranslator) onMessageStart(payload []byte) (string, bool, error) {
	var ev struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(payload, &ev); err != nil {
		return "", false, fmt.Errorf("bedrock stream: decode messageStart: %w", err)
	}
	return t.deltaChunk(map[string]any{"role": ev.Role}, nil), false, nil
}

func (t *bedrockStreamTranslator) onDelta(payload []byte) (string, bool, error) {
	var ev struct {
		ContentBlockIndex int `json:"contentBlockIndex"`
		Delta             struct {
			Text string `json:"text"`
		} `json:"delta"`
	}
	if err := json.Unmarshal(payload, &ev); err != nil {
		return "", false, fmt.Errorf("bedrock stream: decode contentBlockDelta: %w", err)
	}
	if ev.Delta.Text == "" {
		// reasoningContent / empty deltas have no OpenAI text chunk.
		return "", false, nil
	}
	return t.deltaChunk(map[string]any{"content": ev.Delta.Text}, nil), false, nil
}

func (t *bedrockStreamTranslator) onMessageStop(payload []byte) (string, bool, error) {
	var ev struct {
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(payload, &ev); err != nil {
		return "", false, fmt.Errorf("bedrock stream: decode messageStop: %w", err)
	}
	t.stopped = true
	reason := mapBedrockStop(ev.StopReason)
	return t.deltaChunk(map[string]any{}, &reason), false, nil
}

func (t *bedrockStreamTranslator) onMetadata(payload []byte) (string, bool, error) {
	var ev struct {
		Usage *bedrockTokens `json:"usage"`
	}
	if err := json.Unmarshal(payload, &ev); err != nil {
		return "", false, fmt.Errorf("bedrock stream: decode metadata: %w", err)
	}
	if ev.Usage != nil {
		t.usage = ev.Usage.toUsage()
	} else {
		t.usage = Usage{Source: UsageSourceNone}
	}
	if t.emitUsage {
		return t.usageChunk(), true, nil
	}
	return "", true, nil
}

// onException surfaces the provider's precise refusal text unrewritten
// (I51): the payload {"message": …} is embedded verbatim in the error. When
// the payload carries no JSON message, the raw bytes are used as-is.
func (t *bedrockStreamTranslator) onException(msg eventstream.Message) error {
	excType := headerString(msg.Headers, bedrockHdrException)
	var payload struct {
		Message string `json:"message"`
	}
	text := string(msg.Payload)
	if err := json.Unmarshal(msg.Payload, &payload); err == nil && payload.Message != "" {
		text = payload.Message
	}
	if excType == "" {
		return fmt.Errorf("bedrock stream exception: %s", text)
	}
	return fmt.Errorf("bedrock stream exception %s: %s", excType, text)
}

// finishUsage classifies a stream that ended without a metadata event.
func (t *bedrockStreamTranslator) finishUsage() Usage {
	if t.usage.Source == "" {
		t.usage.Source = UsageSourceNone
	}
	return t.usage
}

func (t *bedrockStreamTranslator) usageChunk() string {
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

func (t *bedrockStreamTranslator) deltaChunk(delta map[string]any, finishReason *string) string {
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

// headerString returns the string value of an eventstream header, or "" when
// absent or of a different value kind.
func headerString(headers eventstream.Headers, name string) string {
	v := headers.Get(name)
	if v == nil {
		return ""
	}
	if s, ok := v.(eventstream.StringValue); ok {
		return string(s)
	}
	return v.String()
}
