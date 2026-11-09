package eventpublisher

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DLQEnvelope is the structured payload persisted with every dead-lettered
// stream entry (W-LOGG). The DLQ previously flattened the original fields
// through fmt.Sprintf("%v"), which destroyed types and made replay lossy;
// the envelope keeps every field value verbatim under Values so
// `yb dlq replay` can re-publish the exact original event. The consumer
// (services/loggerd/consumer) writes it; the yb CLI reads it — this struct
// is the single definition of that contract.
type DLQEnvelope struct {
	OriginalStream string                 `json:"original_stream"`
	EntryID        string                 `json:"entry_id"`
	RetryCount     int64                  `json:"retry_count"`
	Error          string                 `json:"error"`
	FailedAt       string                 `json:"failed_at"` // RFC3339 UTC
	Values         map[string]interface{} `json:"values"`
}

// ParseDLQEnvelope decodes a DLQ stream entry's `payload` field. Number
// values stay verbatim (json.Number) so re-publishing cannot float-round
// int64 fields. An envelope without event values is rejected: replaying it
// would silently drop the event.
func ParseDLQEnvelope(data []byte) (DLQEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var env DLQEnvelope
	if err := dec.Decode(&env); err != nil {
		return DLQEnvelope{}, fmt.Errorf("decode dlq envelope: %w", err)
	}
	if len(env.Values) == 0 {
		return DLQEnvelope{}, fmt.Errorf("dlq envelope carries no event values")
	}
	return env, nil
}

// StreamValues renders the envelope's original event fields back into Redis
// stream values. The Redis stream wire format only carries strings, so every
// scalar is rendered to its canonical text: strings verbatim, numbers
// verbatim (json.Number), bools as true/false.
func (env DLQEnvelope) StreamValues() map[string]interface{} {
	out := make(map[string]interface{}, len(env.Values))
	for k, v := range env.Values {
		out[k] = streamValueText(v)
	}
	return out
}

// EventType is the original event's type ("" when the envelope predates the
// field).
func (env DLQEnvelope) EventType() string {
	return streamValueText(env.Values["event_type"])
}

// RequestID is the original event's request id ("" when absent).
func (env DLQEnvelope) RequestID() string {
	return streamValueText(env.Values["request_id"])
}

func streamValueText(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", t)
	}
}
