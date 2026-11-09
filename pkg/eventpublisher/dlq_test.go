package eventpublisher

import (
	"encoding/json"
	"strings"
	"testing"
)

// W-LOGG contract: the DLQ envelope is the single definition of the
// producer(consumer)→CLI(replay) payload. Numbers must round-trip verbatim
// (json.Number, no float rounding) and an envelope without event values must
// be rejected — replaying it would silently drop the event.

func TestDLQEnvelope_RoundTripVerbatim(t *testing.T) {
	orig := DLQEnvelope{
		OriginalStream: "events:queue",
		EntryID:        "1717-0",
		RetryCount:     3,
		Error:          "db down",
		FailedAt:       "2026-10-04T12:00:00Z",
		Values: map[string]interface{}{
			"event_type":  "request.completed",
			"request_id":  "req-42",
			"latency_ms":  json.Number("123456789012345678"),
			"cache_hit":   true,
			"route":       nil,
			"model":       "gpt-4o",
			"nested_list": []interface{}{json.Number("1"), "x"},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	env, err := ParseDLQEnvelope(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if env.OriginalStream != orig.OriginalStream || env.EntryID != orig.EntryID ||
		env.RetryCount != orig.RetryCount || env.Error != orig.Error || env.FailedAt != orig.FailedAt {
		t.Fatalf("header fields not round-tripped: %+v", env)
	}
	if got := env.EventType(); got != "request.completed" {
		t.Errorf("EventType() = %q, want request.completed", got)
	}
	if got := env.RequestID(); got != "req-42" {
		t.Errorf("RequestID() = %q, want req-42", got)
	}

	// Large int64 survives as verbatim text (no float rounding).
	latency, ok := env.Values["latency_ms"].(json.Number)
	if !ok || latency.String() != "123456789012345678" {
		t.Errorf("latency_ms = %#v, want verbatim json.Number", env.Values["latency_ms"])
	}

	// StreamValues renders the wire format: strings verbatim, numbers as
	// text, bools as true/false, nil as "", nested values via %v.
	sv := env.StreamValues()
	want := map[string]string{
		"event_type":  "request.completed",
		"request_id":  "req-42",
		"latency_ms":  "123456789012345678",
		"cache_hit":   "true",
		"route":       "",
		"model":       "gpt-4o",
		"nested_list": "[1 x]",
	}
	for k, w := range want {
		got, ok := sv[k].(string)
		if !ok || got != w {
			t.Errorf("StreamValues[%q] = %#v, want %q", k, sv[k], w)
		}
	}
}

func TestDLQEnvelope_ParseRejections(t *testing.T) {
	if _, err := ParseDLQEnvelope([]byte("not json")); err == nil ||
		!strings.Contains(err.Error(), "decode dlq envelope") {
		t.Errorf("malformed payload: err = %v, want decode error", err)
	}
	if _, err := ParseDLQEnvelope([]byte(`{"original_stream":"events:queue"}`)); err == nil ||
		!strings.Contains(err.Error(), "no event values") {
		t.Errorf("valueless envelope: err = %v, want rejection", err)
	}
}
