package adminstore

import (
	"encoding/json"
)

// FIX-20 RESPONSE-HISTORY: the request_logs.response column carries the
// processed, client-facing model response as a self-describing JSON
// envelope (produced by pkg/gateway/response_history.go, delivered on the
// processed_response wire field). Rows written before FIX-20 (or by a
// producer that supplied no envelope) hold the legacy request-payload
// snapshot or SQL NULL — readers distinguish them by the envelope kind.
//
// This file is the single canonical parser of that envelope on the read
// side: the admin API view projection and the loggerd mapper's validity
// check both route through ParseResponseEnvelope so the acceptance contract
// cannot drift between writer and reader.

// responseEnvelopeKind is the discriminator an object must carry to be an
// envelope; anything else in the column keeps its legacy meaning.
const responseEnvelopeKind = "model_response"

// responseEnvelopeV1 is the only envelope version this reader accepts.
const responseEnvelopeV1 = 1

// Envelope status values (mirror of the producer constants; the reader
// accepts exactly these).
const (
	ResponseStatusComplete = "complete"
	ResponseStatusPartial  = "partial"
)

// RequestResponseToolCall is one tool call reassembled from the served
// response (message tool_calls for non-stream bodies, delta fragments
// merged by index for streams).
type RequestResponseToolCall struct {
	Index     int    `json:"index"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// RequestResponseView is the parsed envelope of the processed response, as
// exposed on the request detail API (response_view). Content is the exact
// client-facing text ("" for tool-call-only answers); Status is the explicit
// completeness signal and Reason explains a partial capture.
type RequestResponseView struct {
	Status           string                    `json:"status"`
	Reason           string                    `json:"reason,omitempty"`
	Model            string                    `json:"model,omitempty"`
	Content          string                    `json:"content"`
	ReasoningContent string                    `json:"reasoning_content,omitempty"`
	ToolCalls        []RequestResponseToolCall `json:"tool_calls,omitempty"`
	FinishReason     string                    `json:"finish_reason,omitempty"`
	Truncated        bool                      `json:"truncated"`
}

// responseEnvelopeProbe is the minimal acceptance shape parsed first: an
// object that does not identify itself as a v1 envelope is legacy data.
type responseEnvelopeProbe struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
}

// ParseResponseEnvelope parses the stored `response` value into the view.
// It returns nil for everything that is not a v1 model-response envelope:
// SQL NULL ('null' jsonb for denied/absent), the legacy payload snapshot
// (object or JSON string), and malformed values — callers treat nil as "no
// stored processed response" and never invent one.
func ParseResponseEnvelope(raw json.RawMessage) *RequestResponseView {
	if len(raw) == 0 {
		return nil
	}
	var probe responseEnvelopeProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil
	}
	if probe.Version != responseEnvelopeV1 || probe.Kind != responseEnvelopeKind {
		return nil
	}
	if probe.Status != ResponseStatusComplete && probe.Status != ResponseStatusPartial {
		return nil
	}
	var view RequestResponseView
	if err := json.Unmarshal(raw, &view); err != nil {
		return nil
	}
	return &view
}
