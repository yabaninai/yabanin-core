package builtins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// JSON-schema dependency justification: the repo already depends on
// github.com/santhosh-tekuri/jsonschema/v6 as a direct module (pkg/agenteval)
// and the schema compiler must speak the full JSON Schema dialect to be
// useful for output gates. A hand-rolled "minimal validator" would fork the
// dialect (type/required/enum/properties/…), grow into a second
// implementation to maintain and drift from the admin-facing docs, so the
// existing dependency is used instead: compile-once at policy load,
// fail-closed on invalid schemas.

// jsonSchemaStep validates model OUTPUT documents against a JSON Schema.
// It is output-only by default: kinds default to response | stream_prefix |
// stream_final (a request/tool payload is skipped unless kinds says
// otherwise). An empty output is skipped (nothing to validate); a non-empty
// output that is not a single valid JSON document, or that fails the schema,
// is one finding.
type jsonSchemaStep struct {
	pipeline.DetectorBase
	kinds map[pipeline.PayloadKind]bool
	act   pipeline.Action
	sch   *jsonschema.Schema
}

// Name returns the step implementation name.
func (*jsonSchemaStep) Name() string { return "builtin/json-schema" }

// Run decodes the output text and validates it against the compiled schema.
func (s *jsonSchemaStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	text := strings.TrimSpace(jsonText(in))
	if text == "" {
		return nil
	}
	v, err := decodeSingleJSON(text)
	if err != nil {
		out.Findings = append(out.Findings, finding(
			p.StepID(), "json_schema", sevMedium,
			"", clipEvidence(err.Error(), maxEvidenceLong), s.act,
		))
		return nil
	}
	if err := s.sch.Validate(v); err != nil {
		out.Findings = append(out.Findings, finding(
			p.StepID(), "json_schema", sevMedium,
			"", clipEvidence(err.Error(), maxEvidenceLong), s.act,
		))
	}
	return nil
}

// NewJSONSchema builds builtin/json-schema.
//
// Params: "schema" (required — an inline JSON Schema as a YAML/JSON map;
// compiled once at policy load, so an invalid schema is a LOAD error),
// plus the common kinds (default: response | stream_prefix | stream_final)
// and action.
func NewJSONSchema(params map[string]any) (pipeline.Step, error) {
	raw, ok := params["schema"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("params.schema: required (inline JSON Schema map)")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("params.schema: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("params.schema: %w", err)
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("schema.json", doc); err != nil {
		return nil, fmt.Errorf("params.schema: %w", err)
	}
	sch, err := comp.Compile("schema.json")
	if err != nil {
		return nil, fmt.Errorf("params.schema: %w", err)
	}
	kinds, err := parseKinds(params,
		pipeline.KindResponse, pipeline.KindStreamPrefix, pipeline.KindStreamFinal)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	return &jsonSchemaStep{kinds: kinds, act: act, sch: sch}, nil
}

// decodeSingleJSON decodes exactly one JSON document (numbers preserved as
// json.Number so big integers survive validation); trailing content is an
// error.
func decodeSingleJSON(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid JSON: multiple documents")
	}
	return v, nil
}

// compile-time guard: json-schema is a read-only Detector.
var _ pipeline.Detector = (*jsonSchemaStep)(nil)

// jsonKeysStep checks the presence of top-level JSON object keys (dotted
// paths descend into nested objects) against the configured mode:
//
//	all  — violation when any required key is MISSING (default);
//	any  — violation when NONE of the keys is present;
//	none — violation when ANY key is present (forbidden keys).
//
// A non-empty payload that is not a single JSON object is a violation for
// all/any modes (nothing to find keys in) and passes for none (no key can
// be present). An empty payload is skipped.
type jsonKeysStep struct {
	pipeline.DetectorBase
	kinds map[pipeline.PayloadKind]bool
	act   pipeline.Action
	keys  []string
	mode  string
}

// Name returns the step implementation name.
func (*jsonKeysStep) Name() string { return "builtin/json-keys" }

// Run evaluates key presence over the JSON target text.
func (s *jsonKeysStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	text := strings.TrimSpace(jsonText(in))
	if text == "" {
		return nil
	}
	var obj map[string]any
	if err := json.NewDecoder(strings.NewReader(text)).Decode(&obj); err != nil {
		obj = nil
	}
	if obj == nil {
		// Not a JSON object (invalid JSON, array, scalar or multiple
		// documents — decoding into a map fails for all of these).
		if s.mode == containsNone {
			return nil
		}
		out.Findings = append(out.Findings, finding(
			p.StepID(), "json_keys", sevMedium,
			"", "payload is not a JSON object", s.act,
		))
		return nil
	}
	present := make([]string, 0, len(s.keys))
	missing := make([]string, 0, len(s.keys))
	for _, k := range s.keys {
		if lookupJSONPath(obj, k) {
			present = append(present, k)
		} else {
			missing = append(missing, k)
		}
	}
	fired := false
	switch s.mode {
	case containsAll:
		fired = len(missing) > 0
	case containsAny:
		fired = len(present) == 0
	case containsNone:
		fired = len(present) > 0
	}
	if !fired {
		return nil
	}
	ev := "present: " + strings.Join(present, ", ")
	if len(missing) > 0 {
		ev = "missing: " + strings.Join(missing, ", ")
	}
	out.Findings = append(out.Findings, finding(
		p.StepID(), "json_keys", sevMedium, "", clipEvidence(ev, maxEvidence), s.act,
	))
	return nil
}

// NewJSONKeys builds builtin/json-keys.
//
// Params: "keys" (required non-empty list; dotted paths descend into nested
// objects), "mode" (any|all|none, default all), plus the common kinds and
// action.
func NewJSONKeys(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	keys, err := paramStrings(params, "keys")
	if err != nil {
		return nil, err
	}
	mode := containsAll
	if raw, ok := params["mode"]; ok && raw != nil {
		s, err := anyToString(raw)
		if err != nil {
			return nil, fmt.Errorf("params.mode: %w", err)
		}
		switch s {
		case containsAny, containsAll, containsNone:
			mode = s
		default:
			return nil, fmt.Errorf("params.mode: %q: want any|all|none", s)
		}
	}
	return &jsonKeysStep{kinds: kinds, act: act, keys: keys, mode: mode}, nil
}

// lookupJSONPath resolves a dotted path ("a.b.c") through nested objects;
// the key counts as present when every segment resolves (a JSON null value
// still counts as present).
func lookupJSONPath(obj map[string]any, path string) bool {
	cur := obj
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		v, ok := cur[seg]
		if !ok {
			return false
		}
		if i == len(segs)-1 {
			return true
		}
		next, ok := v.(map[string]any)
		if !ok {
			return false
		}
		cur = next
	}
	return false
}

// compile-time guard: json-keys is a read-only Detector.
var _ pipeline.Detector = (*jsonKeysStep)(nil)
