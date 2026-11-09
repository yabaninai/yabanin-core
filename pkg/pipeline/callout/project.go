package callout

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// messageSeparator joins message contents for the detect messages
// projection; span byte offsets are continuous across the joined document.
const messageSeparator = "\n"

// projectContent builds the request content document for one Run per the
// configured projection. ok=false means the projection is empty — nothing
// to inspect or mutate — and the upstream call is skipped. err is a
// projection error (e.g. fields expose over a non-JSON body): a step error
// that follows on_error.
func projectContent(in *pipeline.Payload, cfg stepConfig, mutate bool) (content json.RawMessage, ok bool, err error) {
	switch cfg.expose {
	case exposeMessages:
		return projectMessages(in, mutate)
	case exposeBody:
		if len(in.Body) == 0 {
			return nil, false, nil
		}
		s, merr := contentString(string(in.Body))
		return s, true, merr
	case exposeFields:
		return projectFields(in.Body, cfg.fields)
	default:
		return nil, false, fmt.Errorf("callout: unknown expose kind %q", cfg.expose)
	}
}

// projectMessages renders the messages projection. Detect sends one joined
// document (continuous byte offsets for spans); mutate sends one array
// element per message so replacements stay per-message and can never add or
// drop messages.
func projectMessages(in *pipeline.Payload, mutate bool) (json.RawMessage, bool, error) {
	if len(in.Messages) == 0 {
		return nil, false, nil
	}
	if mutate {
		contents := make([]string, len(in.Messages))
		for i := range in.Messages {
			contents[i] = in.Messages[i].Content
		}
		b, err := json.Marshal(contents)
		return b, true, err
	}
	var joined bytes.Buffer
	for i := range in.Messages {
		if i > 0 {
			joined.WriteString(messageSeparator)
		}
		joined.WriteString(in.Messages[i].Content)
	}
	s, err := contentString(joined.String())
	return s, true, err
}

// projectFields extracts the configured top-level fields from a JSON-object
// Body. Missing fields are omitted from the projection; a Body that is not
// a JSON object is a step error; a Body with none of the fields present is
// an empty projection (skip).
func projectFields(body []byte, fields []string) (json.RawMessage, bool, error) {
	if len(body) == 0 {
		return nil, false, nil
	}
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, false, fmt.Errorf("callout: fields expose requires a JSON object body: %w", err)
	}
	if obj == nil {
		return nil, false, fmt.Errorf("callout: fields expose requires a JSON object body")
	}
	projected := make(map[string]json.RawMessage, len(fields))
	for _, f := range fields {
		if raw, ok := obj[f]; ok {
			projected[f] = raw
		}
	}
	if len(projected) == 0 {
		return nil, false, nil
	}
	b, err := json.Marshal(projected)
	return b, true, err
}

// decodeBodyObject decodes a JSON-object Body into ordered-raw form for the
// fields apply-back.
func decodeBodyObject(body []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("callout: fields expose requires a JSON object body: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("callout: fields expose requires a JSON object body")
	}
	return obj, nil
}
