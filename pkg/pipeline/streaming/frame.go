package streaming

import (
	"bytes"
	"encoding/json"
	"time"
)

// sseDataTag / sseDonePayload are the SSE data-line marker and the OpenAI
// stream terminator payload.
var (
	sseDataTag     = []byte("data:")
	sseDonePayload = []byte("[DONE]")
)

// FrameProcessor applies a text transform (a ChunkProcessor) to
// OpenAI-compatible SSE data frames while preserving the event-stream
// structure:
//
//   - "data: [DONE]" and events without a data line pass through untouched;
//   - frames whose JSON has no string at choices[0].delta.content pass
//     through byte-identical (role-only, tool-call, usage and error frames);
//   - a mutated content re-encodes the whole frame: the event boundary
//     ("data: …\n\n") is rebuilt around the new length, so a frame whose
//     length changed never breaks the stream (unknown fields survive via
//     raw-JSON round-trip).
//
// Only choices[0] — the primary choice — is mutated: the text processor
// carries per-stream state, and secondary choices are separate streams.
//
// The middleware feeds one SSE event per ProcessFrame call (the gateway's
// stream handlers write whole events atomically) and mounts this processor
// BEFORE the cache RecordingWriter so client and semantic cache observe the
// same bytes (RT-05 consistency). Frames passed to FinalAggregate must be
// the same mutated frames — policies audit what the client received.
type FrameProcessor struct {
	text *ChunkProcessor
}

// NewFrameProcessor wraps a text-level ChunkProcessor for SSE frames.
func NewFrameProcessor(text *ChunkProcessor) *FrameProcessor {
	return &FrameProcessor{text: text}
}

// ProcessFrame rewrites one raw SSE event ("data: …\n\n") and returns the
// bytes to emit. The result may be shorter or longer than the input — the
// event boundary is rebuilt, never broken.
func (fp *FrameProcessor) ProcessFrame(frame []byte) []byte {
	if fp == nil || fp.text == nil || len(frame) == 0 {
		return frame
	}
	head, payload, tail, ok, done := splitSSEData(frame)
	if !ok || done {
		return frame
	}
	line, changed := fp.mutateChunkJSON(payload)
	if !changed {
		return frame
	}
	out := make([]byte, 0, len(head)+len(line)+len(tail)+len(sseDataTag)+1)
	out = append(out, head...)
	out = append(out, sseDataTag...)
	out = append(out, ' ')
	out = append(out, line...)
	out = append(out, tail...)
	return out
}

// FlushFrame renders one final synthetic data frame carrying whatever the
// text processor still holds (the stream ended, so the tail cannot extend
// into a match anymore). Returns nil when nothing is held; the middleware
// writes it right before the [DONE] passthrough.
func (fp *FrameProcessor) FlushFrame(id, model string) []byte {
	if fp == nil || fp.text == nil {
		return nil
	}
	tail := fp.text.Flush()
	if tail == "" {
		return nil
	}
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{"content": tail},
			"finish_reason": nil,
		}},
	}
	line, err := json.Marshal(chunk)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(sseDataTag)+1+len(line)+2)
	out = append(out, sseDataTag...)
	out = append(out, ' ')
	out = append(out, line...)
	out = append(out, '\n', '\n')
	return out
}

// mutateChunkJSON re-encodes the data payload with the mutated
// choices[0].delta.content. changed=false means byte-identical passthrough.
func (fp *FrameProcessor) mutateChunkJSON(payload []byte) (line []byte, changed bool) {
	if len(payload) == 0 || payload[0] != '{' {
		return nil, false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil, false
	}
	rawChoices, ok := top["choices"]
	if !ok {
		return nil, false
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil || len(choices) == 0 {
		return nil, false
	}
	var choice0 map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &choice0); err != nil {
		return nil, false
	}
	rawDelta, ok := choice0["delta"]
	if !ok {
		return nil, false
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(rawDelta, &delta); err != nil {
		return nil, false
	}
	rawContent, ok := delta["content"]
	if !ok {
		return nil, false
	}
	var content string
	if err := json.Unmarshal(rawContent, &content); err != nil {
		return nil, false // null / non-string content: nothing to mutate
	}
	mutated := fp.text.Process(content)
	if mutated == content {
		return nil, false // nothing emitted and nothing held: passthrough
	}
	enc, err := json.Marshal(mutated)
	if err != nil {
		return nil, false
	}
	delta["content"] = enc

	deltaEnc, err := json.Marshal(delta)
	if err != nil {
		return nil, false
	}
	choice0["delta"] = deltaEnc
	choiceEnc, err := json.Marshal(choice0)
	if err != nil {
		return nil, false
	}
	choices[0] = choiceEnc
	choicesEnc, err := json.Marshal(choices)
	if err != nil {
		return nil, false
	}
	top["choices"] = choicesEnc
	line, err = json.Marshal(top)
	if err != nil {
		return nil, false
	}
	return line, true
}

// splitSSEData splits one SSE event into (head, payload, tail) around its
// FIRST data line: head+payload+tail == frame, payload is the data field
// (one leading space after "data:" is consumed). ok=false when the event
// carries no data line; done=true when the payload is the [DONE]
// terminator. Multi-data-line events (SSE spec joins them) are not
// produced by the gateway handlers and pass through untouched.
func splitSSEData(frame []byte) (head, payload, tail []byte, ok, done bool) {
	lineStart := 0
	for lineStart <= len(frame) {
		lineEnd := lineStart + bytes.IndexByte(frame[lineStart:], '\n')
		if lineEnd < lineStart {
			lineEnd = len(frame)
		}
		line := frame[lineStart:lineEnd]
		if bytes.HasPrefix(line, sseDataTag) {
			p := lineStart + len(sseDataTag)
			if p < lineEnd && frame[p] == ' ' {
				p++
			}
			body := frame[p:lineEnd]
			return frame[:lineStart], body, frame[lineEnd:], true, bytes.Equal(body, sseDonePayload)
		}
		if lineEnd == len(frame) {
			break
		}
		lineStart = lineEnd + 1
	}
	return nil, nil, nil, false, false
}
