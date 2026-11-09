package callout

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Mutate is the builtin/callout-mutate step: a Mutator that sends the
// projected content out and applies the mutated content back IN PLACE on
// the payload. Boundary invariant: the response can only replace the exact
// region that was projected — messages 1:1 (no added/dropped messages),
// the body wholesale, or exactly the projected field set (no added, no
// dropped fields; deletion is explicit null). A response that tries to
// expand its reach is a step error, never a partial apply.
type Mutate struct {
	pipeline.MutatorBase
	rt  *Runtime
	cfg stepConfig
}

// Name returns the registry name of the step implementation.
func (m *Mutate) Name() string { return "builtin/callout-mutate" }

// Run projects the payload, performs the one-shot deduplicated callout and
// applies the mutated content back. Errors — including out-of-boundary
// responses — leave the payload untouched (validate first, apply last) and
// follow the step's on_error mode.
func (m *Mutate) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	content, ok, err := projectContent(in, m.cfg, true)
	if err != nil || !ok {
		return err // empty projection: nothing to mutate, no call
	}
	env, err := json.Marshal(requestEnvelope{Expose: string(m.cfg.expose), Content: content})
	if err != nil {
		return fmt.Errorf("callout %s: marshal request: %w", m.cfg.endpoint, err)
	}
	resp, err := m.rt.call(ctx, m.cfg, env)
	if err != nil {
		return err
	}
	var wire struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(resp.body, &wire); err != nil {
		return fmt.Errorf("callout %s: decode mutate response: %w", m.cfg.endpoint, err)
	}
	if len(wire.Content) == 0 || string(wire.Content) == "null" {
		return fmt.Errorf("callout %s: mutate contract: content is required", m.cfg.endpoint)
	}
	return m.apply(in, wire.Content)
}

// apply writes the mutated content back per projection, validating the
// boundary before touching the payload.
func (m *Mutate) apply(in *pipeline.Payload, content json.RawMessage) error {
	switch m.cfg.expose {
	case exposeMessages:
		return m.applyMessages(in, content)
	case exposeBody:
		return m.applyBody(in, content)
	case exposeFields:
		return m.applyFields(in, content)
	default:
		return fmt.Errorf("callout %s: unknown expose kind %q", m.cfg.endpoint, m.cfg.expose)
	}
}

// applyMessages replaces message contents one-to-one: the response must be
// a string array with exactly len(messages) elements.
func (m *Mutate) applyMessages(in *pipeline.Payload, content json.RawMessage) error {
	var mutated []string
	if err := json.Unmarshal(content, &mutated); err != nil {
		return fmt.Errorf("callout %s: mutate contract: content must be a string array for the messages projection: %w", m.cfg.endpoint, err)
	}
	if len(mutated) != len(in.Messages) {
		return fmt.Errorf("callout %s: mutate boundary refused: response has %d messages, payload has %d (mutators cannot add or drop messages)", m.cfg.endpoint, len(mutated), len(in.Messages))
	}
	for i := range in.Messages {
		if in.Messages[i].Content != mutated[i] {
			in.Messages[i].Content = mutated[i]
		}
	}
	return nil
}

// applyBody replaces the Body wholesale with the response string.
func (m *Mutate) applyBody(in *pipeline.Payload, content json.RawMessage) error {
	var mutated string
	if err := json.Unmarshal(content, &mutated); err != nil {
		return fmt.Errorf("callout %s: mutate contract: content must be a string for the body projection: %w", m.cfg.endpoint, err)
	}
	if string(in.Body) != mutated {
		in.Body = []byte(mutated)
	}
	return nil
}

// applyFields merges the mutated fields back into the JSON-object Body.
// The response key set must EQUAL the projected set: no field expansion
// (the mutator cannot invent fields) and no silent field drops (deletion
// is explicit null). If every returned value is byte-identical to the
// original, the Body is left untouched so the engine does not report a
// mutation that never happened.
func (m *Mutate) applyFields(in *pipeline.Payload, content json.RawMessage) error {
	var mutated map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	if err := dec.Decode(&mutated); err != nil {
		return fmt.Errorf("callout %s: mutate contract: content must be an object for the fields projection: %w", m.cfg.endpoint, err)
	}
	if mutated == nil {
		return fmt.Errorf("callout %s: mutate contract: content must be an object for the fields projection", m.cfg.endpoint)
	}

	projected, err := decodeBodyObject(in.Body)
	if err != nil {
		return fmt.Errorf("callout %s: %w", m.cfg.endpoint, err)
	}

	allowed := make(map[string]bool, len(m.cfg.fields))
	for _, f := range m.cfg.fields {
		allowed[f] = true
	}
	for k := range mutated {
		if !allowed[k] {
			return fmt.Errorf("callout %s: mutate boundary refused: response field %q is outside the projected set (mutators cannot expand fields)", m.cfg.endpoint, k)
		}
	}
	for _, f := range m.cfg.fields {
		if _, ok := mutated[f]; !ok {
			return fmt.Errorf("callout %s: mutate boundary refused: response dropped projected field %q (delete explicitly with null)", m.cfg.endpoint, f)
		}
	}

	changed := false
	for _, f := range m.cfg.fields {
		orig, have := projected[f]
		if !have || !bytes.Equal(orig, mutated[f]) {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}

	merged := make(map[string]json.RawMessage, len(projected))
	for k, v := range projected {
		merged[k] = v
	}
	for k, v := range mutated {
		merged[k] = v
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("callout %s: re-encode body: %w", m.cfg.endpoint, err)
	}
	in.Body = out
	return nil
}
