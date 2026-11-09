package cli

// FIX-20 RESPONSE-HISTORY: the processed, client-facing response capture.
//
// The gateway records what the client actually received — post tool gate,
// post policy — as a self-describing JSON envelope carried on the analytics
// event (eventBase.ProcessedResponse → wire field processed_response →
// request_logs.response). The envelope never replaces the raw provider
// captures (upstream_payload / upstream_response); it is the PROCESSED
// content class: scrubbed of inline media, dropped under the metadata-only
// profile, kept under original-retention OFF.
//
// Streaming capture rides the client-bound writer chain between the policy
// writer and the tool gate, so the recorded bytes are exactly the frames the
// client received after every mutating layer. The JSON path and cache hits
// parse the served completion document directly — no writer is involved.
//
// Contract (RESPONSE-HISTORY-FIX-20261101.md): full content + tool calls
// reassembled from ALL fragments (no 4000-char shortcut), an explicit
// completeness status with a reason on every partial outcome, and honest
// absence — a request whose content was never served (policy denial) or
// never parsed carries NO envelope rather than a fabricated one.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// responseHistoryCaptureLimit bounds the captured response: the combined
// content + reasoning + tool-call-argument bytes. A capture that exceeds it
// stops growing and reports truncated=true with reason capture_limit — the
// envelope stays honest about its own incompleteness.
const responseHistoryCaptureLimit = 512 * 1024

// responseHistoryPendingLimit bounds the incremental line-splitter buffer
// (a single SSE write larger than the capture budget must not grow memory
// without limit). Frames larger than this are dropped whole; the capture
// marks itself truncated and resumes at the next complete line.
const responseHistoryPendingLimit = responseHistoryCaptureLimit + 64*1024

// Envelope status values: the explicit completeness signal the contract
// requires.
const (
	responseHistoryStatusComplete = "complete"
	responseHistoryStatusPartial  = "partial"
)

// Envelope reasons: why the status is partial (open set, documented in the
// FIX-20 record and the admin API delta).
const (
	responseHistoryReasonCaptureLimit    = "capture_limit"
	responseHistoryReasonClientCancel    = "client_cancel"
	responseHistoryReasonIdleTimeout     = "idle_timeout"
	responseHistoryReasonUpstreamError   = "upstream_error"
	responseHistoryReasonMissingDoneFram = "missing_done_frame"
)

// responseHistoryKind is the envelope discriminator. Readers (loggerd
// mapper, adminstore parser) accept only objects carrying it — anything
// else in the storage column keeps its legacy meaning.
const responseHistoryKind = "model_response"

type responseHistoryEnvelope struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	// Reason explains a partial status (empty on complete). The truncated
	// flag is independent: a capture can hit the budget AND be interrupted.
	Reason string `json:"reason,omitempty"`
	// Model is the model that served the response (the completion
	// document's model field when present, else the routed model). It keeps
	// the dashboard's changed-model comparison working on envelope rows.
	Model string `json:"model,omitempty"`
	// Content is always present (possibly "" for tool-call-only responses):
	// explicit empty beats absent for machine readers.
	Content          string                    `json:"content"`
	ReasoningContent string                    `json:"reasoning_content,omitempty"`
	ToolCalls        []responseHistoryToolCall `json:"tool_calls,omitempty"`
	FinishReason     string                    `json:"finish_reason,omitempty"`
	Truncated        bool                      `json:"truncated,omitempty"`
}

type responseHistoryToolCall struct {
	Index     int    `json:"index"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// newResponseHistoryEnvelope assembles the envelope from an accumulator
// state; nil when nothing client-facing was captured (no parseable chunk, or
// no content/reasoning/tool-call payload — the same honest-empty rule the
// stream cache accumulator applies to its synthetic document).
func newResponseHistoryEnvelope(model string, content, reasoning strings.Builder, tools []*streamToolCallAcc, finish *string, status, reason string, truncated bool) *responseHistoryEnvelope {
	if content.Len() == 0 && reasoning.Len() == 0 && len(tools) == 0 {
		return nil
	}
	env := &responseHistoryEnvelope{
		Version:          1,
		Kind:             responseHistoryKind,
		Status:           status,
		Reason:           reason,
		Model:            model,
		Content:          content.String(),
		ReasoningContent: reasoning.String(),
		FinishReason:     stringDeref(finish),
		Truncated:        truncated,
	}
	if len(tools) > 0 {
		env.ToolCalls = make([]responseHistoryToolCall, 0, len(tools))
		for i, tc := range tools {
			env.ToolCalls = append(env.ToolCalls, responseHistoryToolCall{
				Index:     i,
				ID:        tc.id,
				Name:      tc.name,
				Arguments: tc.args.String(),
			})
		}
	}
	return env
}

// marshal renders the envelope as the wire/storage JSON; nil → "".
func (e *responseHistoryEnvelope) marshal() string {
	if e == nil {
		return ""
	}
	data, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return string(data)
}

// completionDocShape mirrors the chat.completion document the JSON path
// serves and a cache hit replays (choices[].message), narrow enough that a
// non-completion body fails to parse into an envelope.
type completionDocShape struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason *string `json:"finish_reason"`
		Message      struct {
			Content          *string `json:"content"`
			ReasoningContent *string `json:"reasoning_content"`
			ToolCalls        []struct {
				Index    *int   `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// envelopeFromCompletionDoc builds the envelope for a fully served
// chat.completion document (non-stream success path, cache-hit replay).
// Status is complete unless the extracted content exceeds the capture
// budget. A body that does not parse as a completion document yields nil —
// absence, never a fabricated answer.
func envelopeFromCompletionDoc(data []byte, fallbackModel string) *responseHistoryEnvelope {
	var doc completionDocShape
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Choices) == 0 {
		return nil
	}
	choice := doc.Choices[0]
	msg := choice.Message
	contentBudget := responseHistoryCaptureLimit
	truncated := false
	content := ""
	if msg.Content != nil {
		content = *msg.Content
		if len(content) > contentBudget {
			content = content[:contentBudget]
			truncated = true
		}
	}
	env := &responseHistoryEnvelope{
		Version:          1,
		Kind:             responseHistoryKind,
		Status:           responseHistoryStatusComplete,
		Model:            stringOr(doc.Model, fallbackModel),
		Content:          content,
		ReasoningContent: stringDeref(msg.ReasoningContent),
		FinishReason:     stringDeref(choice.FinishReason),
		Truncated:        truncated,
	}
	if truncated {
		env.Status = responseHistoryStatusPartial
		env.Reason = responseHistoryReasonCaptureLimit
	}
	if len(msg.ToolCalls) > 0 {
		env.ToolCalls = make([]responseHistoryToolCall, 0, len(msg.ToolCalls))
		for i, tc := range msg.ToolCalls {
			args := tc.Function.Arguments
			idx := i
			if tc.Index != nil {
				idx = *tc.Index
			}
			env.ToolCalls = append(env.ToolCalls, responseHistoryToolCall{
				Index:     idx,
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: args,
			})
		}
	}
	if env.Content == "" && env.ReasoningContent == "" && len(env.ToolCalls) == 0 {
		return nil
	}
	return env
}

// responseHistoryCapture records the client-bound SSE byte stream. It wraps
// the writer chain INSIDE the tool gate (outside the policy writer), so it
// sees exactly the frames the client receives after every mutating layer.
// All methods run on the drain goroutine — the accumulator is touched only
// there (Write during drain, envelope assembly after drain returns).
type responseHistoryCapture struct {
	http.ResponseWriter
	flusher  http.Flusher
	pending  []byte
	acc      streamCompletionAcc
	sawDone  bool
	dropped  bool
	envelope *responseHistoryEnvelope
}

// newResponseHistoryCapture wraps inner (the writer below the tool gate).
func newResponseHistoryCapture(inner http.ResponseWriter) *responseHistoryCapture {
	c := &responseHistoryCapture{ResponseWriter: inner}
	if f, ok := inner.(http.Flusher); ok {
		c.flusher = f
	}
	c.acc.budget = responseHistoryCaptureLimit
	return c
}

func (c *responseHistoryCapture) Write(p []byte) (int, error) {
	c.pending = append(c.pending, p...)
	if len(c.pending) > responseHistoryPendingLimit {
		// Pathological frame: drop the buffered bytes whole, mark the
		// capture incomplete, resume at the next line boundary. The client
		// stream is never told — this is a capture-side bound only.
		c.pending = c.pending[:0]
		c.dropped = true
	}
	for {
		idx := bytes.IndexByte(c.pending, '\n')
		if idx < 0 {
			break
		}
		line := c.pending[:idx]
		c.pending = c.pending[idx+1:]
		c.feedLine(line)
	}
	return c.ResponseWriter.Write(p)
}

// Flush keeps the streaming chain flushing through the capture.
func (c *responseHistoryCapture) Flush() {
	if c.flusher != nil {
		c.flusher.Flush()
	}
}

// feedLine consumes one complete SSE line: data:[DONE] marks the terminal
// frame, every other data: line is decoded as a chat.completion.chunk and
// fed to the accumulator (budget-guarded).
func (c *responseHistoryCapture) feedLine(line []byte) {
	line = bytes.TrimSuffix(line, []byte("\r"))
	if !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	payload := bytes.TrimSpace(line[len("data:"):])
	if bytes.Equal(payload, []byte("[DONE]")) {
		c.sawDone = true
		return
	}
	var ch streamCacheChunk
	if err := json.Unmarshal(payload, &ch); err != nil {
		return
	}
	c.acc.add(ch)
}

// finishEnvelope assembles and freezes the envelope from the accumulated
// capture. Called once, after the drain outcome is known; later calls
// return the frozen envelope. Status/reason come from the drain outcome:
// sawDone governs complete vs partial, the caller supplies the interrupt
// reason when the drain failed.
func (c *responseHistoryCapture) finishEnvelope(status, reason string) *responseHistoryEnvelope {
	if c == nil {
		return nil
	}
	if c.envelope == nil {
		truncated := c.acc.truncated || c.dropped
		if status == responseHistoryStatusComplete && truncated {
			status = responseHistoryStatusPartial
			reason = responseHistoryReasonCaptureLimit
		}
		// STREAM-02: the FIX-20 envelope schema is defined over the primary
		// choice (index 0) — non-primary choices stay a stream-cache concern.
		pc := c.acc.primary()
		c.envelope = newResponseHistoryEnvelope(c.acc.model, pc.content, pc.reasoning, pc.tools, pc.finish, status, reason, truncated)
	}
	return c.envelope
}

// wire returns the frozen envelope JSON ("" when nothing was captured).
func (c *responseHistoryCapture) wire() string {
	return c.finishEnvelope("", "").marshal()
}

// stringDeref / stringOr are tiny helpers shared by the envelope builders.
func stringDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func stringOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
