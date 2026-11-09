package evalgate

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExampleSetContractConstants pins the interchange identity constants:
// they are the only values external runners may meet in a v1 bundle.
func TestExampleSetContractConstants(t *testing.T) {
	if ExampleSetSchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", ExampleSetSchemaVersion)
	}
	if ExampleSetKind != "yabanin.example-set" {
		t.Fatalf("kind = %q, want yabanin.example-set", ExampleSetKind)
	}
}

// TestExampleSetSchemaArtifactIsSelfContained guards the drift between the
// Go contract and the shipped JSON Schema: field sets, required lists and
// fixed constants must match exactly, and the artifact must stay a
// self-contained draft 2020-12 document an external runner can use offline.
func TestExampleSetSchemaArtifactIsSelfContained(t *testing.T) {
	var schema struct {
		Schema      string `json:"$schema"`
		ID          string `json:"$id"`
		Type        string `json:"type"`
		Required    []string
		Properties  map[string]json.RawMessage
		Definitions map[string]struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(ExampleSetSchemaV1, &schema); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %q, want draft 2020-12", schema.Schema)
	}
	if schema.Type != "object" {
		t.Fatalf("root type = %q, want object", schema.Type)
	}
	if len(schema.Definitions) != 4 {
		t.Fatalf("$defs = %d entries, want 4 (revision, sample, provenance, source)", len(schema.Definitions))
	}
	for name := range schema.Definitions {
		switch name {
		case "revision", "sample", "provenance", "source":
		default:
			t.Fatalf("unexpected $def %q", name)
		}
	}

	// Contract fields: exactly the six ExampleSet fields, all required, in
	// the documented set.
	want := map[string]bool{
		"schema_version": false, "kind": false, "set_id": false,
		"content_sha256": false, "revision_json": false, "provenance": false,
	}
	if len(schema.Properties) != len(want) {
		t.Fatalf("schema properties %v do not match the Go contract", keys(schema.Properties))
	}
	for _, r := range schema.Required {
		if _, ok := want[r]; !ok {
			t.Fatalf("required field %q is not part of the Go contract", r)
		}
		want[r] = true
	}
	for f, required := range want {
		if !required {
			t.Fatalf("contract field %q is not required by the schema", f)
		}
	}

	// Fixed constants inside the schema must equal the Go constants.
	var kindProp struct {
		Const string `json:"const"`
	}
	if err := json.Unmarshal(schema.Properties["kind"], &kindProp); err != nil || kindProp.Const != ExampleSetKind {
		t.Fatalf("kind const = %q (err %v), want %q", kindProp.Const, err, ExampleSetKind)
	}
	var versionProp struct {
		Const int `json:"const"`
	}
	if err := json.Unmarshal(schema.Properties["schema_version"], &versionProp); err != nil || versionProp.Const != ExampleSetSchemaVersion {
		t.Fatalf("schema_version const = %d (err %v), want %d", versionProp.Const, err, ExampleSetSchemaVersion)
	}

	// No external references: every $ref resolves inside the document, so
	// offline validators never fetch anything.
	var refs []string
	var walk func(v any)
	walk = func(v any) {
		switch tv := v.(type) {
		case map[string]any:
			if r, ok := tv["$ref"].(string); ok {
				refs = append(refs, r)
			}
			for _, vv := range tv {
				walk(vv)
			}
		case []any:
			for _, vv := range tv {
				walk(vv)
			}
		}
	}
	var doc any
	if err := json.Unmarshal(ExampleSetSchemaV1, &doc); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
	walk(doc)
	if len(refs) == 0 {
		t.Fatalf("schema uses no $refs; the $defs blocks are unreachable")
	}
	for _, r := range refs {
		if !strings.HasPrefix(r, "#/$defs/") {
			t.Fatalf("$ref %q points outside the document", r)
		}
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
