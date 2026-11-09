package ocsf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// Valid base record as decoded JSON (map form), derived from a real
// mapped event so the corpus never drifts from the mapper contract.
func baseRecordMap(t *testing.T) map[string]any {
	t.Helper()
	rec, err := MapEvent(fixture("policy.deny"))
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	return recordToMap(t, rec)
}

func recordToMap(t *testing.T, rec NormalizedRecord) map[string]any {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func marshalMap(t *testing.T, m map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func TestEmbeddedSchemaCompiles(t *testing.T) {
	if compileErr != nil {
		t.Fatalf("embedded schema must compile: %v", compileErr)
	}
	if recordDef() == nil || schemaRoot() == nil {
		t.Fatalf("embedded schema must expose root and $defs.record")
	}
}

// TestSchemaKeywordCoverage pins the validator's contract honesty: every
// keyword the embedded schema uses must be one the walker enforces (or
// an explicitly ignored annotation). A schema edit sneaking in an
// unaudited keyword must fail here rather than silently not applying.
func TestSchemaKeywordCoverage(t *testing.T) {
	enforced := map[string]bool{
		"type": true, "properties": true, "required": true, "items": true,
		"enum": true, "pattern": true, "minLength": true, "maxLength": true,
		"minimum": true, "$ref": true,
	}
	annotations := map[string]bool{
		"$schema": true, "$id": true, "title": true, "description": true,
		"$defs": true,
	}
	for kw := range keywordsSeen {
		if enforced[kw] || annotations[kw] {
			continue
		}
		t.Errorf("embedded schema uses keyword %q which the validator neither enforces nor documents as annotation", kw)
	}
}

// TestVersionConstantParity pins the record stamp to the exported
// version constant: version.go (W02-C01) and record.go (W01-C02) must
// never drift apart.
func TestVersionConstantParity(t *testing.T) {
	if recordSchemaVersion != ExportSchemaVersion {
		t.Fatalf("recordSchemaVersion = %d, ExportSchemaVersion = %d: drift", recordSchemaVersion, ExportSchemaVersion)
	}
}

// 1–6: every golden fixture validates (round-trip acceptance).
func TestGoldenFixturesValidate(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob golden fixtures: %v (%v)", err, files)
	}
	if len(files) != len(goldenCases) {
		t.Fatalf("golden files = %d, want %d (stale fixture on disk?)", len(files), len(goldenCases))
	}
	for _, path := range files {
		data, err := os.ReadFile(path) // #nosec G304 -- the path is this package's own pinned golden fixture directory
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := ValidateRecordJSON(data); err != nil {
			t.Errorf("%s does not validate against export-v1: %v", path, err)
		}
	}
}

// 7: unknown fields pass everywhere (forward compatibility acceptance).
func TestUnknownFieldsPass(t *testing.T) {
	t.Run("record", func(t *testing.T) {
		m := baseRecordMap(t)
		m["future_field"] = map[string]any{"anything": true}
		if err := ValidateRecordJSON(marshalMap(t, m)); err != nil {
			t.Fatalf("unknown record field must pass: %v", err)
		}
	})
	t.Run("envelope", func(t *testing.T) {
		env := map[string]any{
			"schema_version": json.Number("1"),
			"envelope_id":    "env-1",
			"issued_at":      json.Number("1794052800000"),
			"records":        []any{baseRecordMap(t)},
			"future_top":     json.Number("42"),
		}
		if err := ValidateEnvelopeJSON(marshalMap(t, env)); err != nil {
			t.Fatalf("unknown envelope field must pass: %v", err)
		}
	})
}

// 8: valid envelope with one record.
func TestValidEnvelope(t *testing.T) {
	env := map[string]any{
		"schema_version": json.Number("1"),
		"envelope_id":    "env-1",
		"issued_at":      json.Number("1794052800000"),
		"records":        []any{baseRecordMap(t)},
	}
	if err := ValidateEnvelopeJSON(marshalMap(t, env)); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

// 9–11: fail-closed version gate.
func TestVersionGate(t *testing.T) {
	build := func(version any) map[string]any {
		m := baseRecordMap(t)
		if version == nil {
			delete(m, "schema_version")
		} else {
			m["schema_version"] = version
		}
		return m
	}
	t.Run("missing", func(t *testing.T) {
		err := ValidateRecordJSON(marshalMap(t, build(nil)))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("err = %v, want ErrNoSchemaVersion", err)
		}
	})
	t.Run("zero", func(t *testing.T) {
		err := ValidateRecordJSON(marshalMap(t, build(json.Number("0"))))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("err = %v, want ErrNoSchemaVersion", err)
		}
	})
	// Negative versions are the same fail-closed class (review F1:
	// gateVersion used to accept them; the valid band is 1 <= v <=
	// ExportSchemaVersion — W02 versioning artifact §3 rule 3).
	t.Run("negative", func(t *testing.T) {
		for _, raw := range []string{"-1", "-3", "-2147483648"} {
			err := ValidateRecordJSON(marshalMap(t, build(json.Number(raw))))
			if !errors.Is(err, ErrNoSchemaVersion) {
				t.Fatalf("schema_version %s: err = %v, want ErrNoSchemaVersion", raw, err)
			}
		}
		err := ValidateEnvelopeJSON(marshalMap(t, map[string]any{
			"schema_version": json.Number("-2"),
			"envelope_id":    "env-1",
			"issued_at":      json.Number("1"),
			"records":        []any{},
		}))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("envelope schema_version -2: err = %v, want ErrNoSchemaVersion", err)
		}
	})
	t.Run("future", func(t *testing.T) {
		err := ValidateRecordJSON(marshalMap(t, build(json.Number("2"))))
		if !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Fatalf("err = %v, want ErrUnsupportedSchemaVersion", err)
		}
	})
	t.Run("envelope future", func(t *testing.T) {
		env := map[string]any{
			"schema_version": json.Number("7"),
			"envelope_id":    "env-1",
			"issued_at":      json.Number("1"),
			"records":        []any{},
		}
		err := ValidateEnvelopeJSON(marshalMap(t, env))
		if !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Fatalf("err = %v, want ErrUnsupportedSchemaVersion", err)
		}
	})
	t.Run("non numeric version", func(t *testing.T) {
		err := ValidateRecordJSON(marshalMap(t, build("1")))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("err = %v, want ErrNoSchemaVersion", err)
		}
	})
}

// 12: a missing required record field errors with a $-path.
func TestMissingRequiredField(t *testing.T) {
	m := baseRecordMap(t)
	delete(m, "mapped")
	err := ValidateRecordJSON(marshalMap(t, m))
	if err == nil || !strings.Contains(err.Error(), `$.mapped`) {
		t.Fatalf("err = %v, want $.mapped missing", err)
	}
}

// 13–15: enum, type and pattern enforcement with exact paths.
func TestScalarConstraints(t *testing.T) {
	t.Run("severity enum", func(t *testing.T) {
		m := baseRecordMap(t)
		m["severity_id"] = json.Number("7")
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.severity_id") {
			t.Fatalf("err = %v, want $.severity_id enum violation", err)
		}
	})
	t.Run("severity type", func(t *testing.T) {
		m := baseRecordMap(t)
		m["severity_id"] = "4"
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.severity_id") {
			t.Fatalf("err = %v, want $.severity_id type violation", err)
		}
	})
	t.Run("digest pattern", func(t *testing.T) {
		m := baseRecordMap(t)
		m["evidence"].([]any)[0].(map[string]any)["digest"] = "not-hex"
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.evidence[0].digest") {
			t.Fatalf("err = %v, want $.evidence[0].digest pattern violation", err)
		}
	})
	t.Run("source_event_type pattern", func(t *testing.T) {
		m := baseRecordMap(t)
		m["source_event_type"] = "Policy.Deny"
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.source_event_type") {
			t.Fatalf("err = %v, want $.source_event_type pattern violation", err)
		}
	})
	t.Run("idref state enum", func(t *testing.T) {
		m := baseRecordMap(t)
		m["identity"].(map[string]any)["agent"].(map[string]any)["state"] = "maybe"
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.identity.agent.state") {
			t.Fatalf("err = %v, want $.identity.agent.state enum violation", err)
		}
	})
	t.Run("metadata version pattern", func(t *testing.T) {
		m := baseRecordMap(t)
		m["metadata"].(map[string]any)["version"] = "1.9"
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.metadata.version") {
			t.Fatalf("err = %v, want $.metadata.version pattern violation", err)
		}
	})
	t.Run("time integer", func(t *testing.T) {
		m := baseRecordMap(t)
		m["time"] = json.Number("1.5")
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.time") {
			t.Fatalf("err = %v, want $.time integer violation", err)
		}
	})
	t.Run("exponent form integer passes", func(t *testing.T) {
		m := baseRecordMap(t)
		m["time"] = json.Number("2e9")
		if err := ValidateRecordJSON(marshalMap(t, m)); err != nil {
			t.Fatalf("2e9 is an integral JSON number, must pass: %v", err)
		}
	})
	t.Run("minimum", func(t *testing.T) {
		m := baseRecordMap(t)
		m["time"] = json.Number("-1")
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.time") {
			t.Fatalf("err = %v, want $.time minimum violation", err)
		}
	})
}

// 16: cost extension semantics.
func TestCostSchema(t *testing.T) {
	t.Run("state none rejected as enum", func(t *testing.T) {
		m := baseRecordMap(t)
		m["cost"] = map[string]any{"state": "none"}
		err := ValidateRecordJSON(marshalMap(t, m))
		if err == nil || !strings.Contains(err.Error(), "$.cost.state") {
			t.Fatalf("err = %v, want $.cost.state enum violation (none is expressed by field absence)", err)
		}
	})
	t.Run("known requires nothing else", func(t *testing.T) {
		m := baseRecordMap(t)
		m["cost"] = map[string]any{"state": "known"}
		if err := ValidateRecordJSON(marshalMap(t, m)); err != nil {
			t.Fatalf("state alone is declaratively valid: %v", err)
		}
	})
	t.Run("declarative boundary documented", func(t *testing.T) {
		// The state-conditional micro_usd rule (unknown ⇒ no number) is
		// NOT expressible in the enforced subset; the schema documents it
		// and the mapper tests pin it. This case records the boundary:
		// the schema alone accepts unknown-with-number.
		m := baseRecordMap(t)
		m["cost"] = map[string]any{"state": "unknown", "micro_usd": json.Number("5")}
		if err := ValidateRecordJSON(marshalMap(t, m)); err != nil {
			t.Fatalf("declarative subset cannot express the conditional rule; mapper tests own it: %v", err)
		}
	})
}

// 17: strict decoding rejects trailing garbage.
func TestStrictDecode(t *testing.T) {
	data := marshalMap(t, baseRecordMap(t))
	if err := ValidateRecordJSON(append(data, []byte(" {}")...)); err == nil {
		t.Fatalf("trailing garbage must be rejected")
	}
	if err := ValidateRecordJSON([]byte("not json")); err == nil {
		t.Fatalf("invalid JSON must be rejected")
	}
	if err := ValidateRecordJSON([]byte("[]")); err == nil || !errors.Is(err, ErrNotAnObject) {
		t.Fatalf("err = %v, want ErrNotAnObject", err)
	}
}

// 18: envelope records array errors carry the item index in the path.
func TestEnvelopeErrorPath(t *testing.T) {
	bad := baseRecordMap(t)
	delete(bad, "finding_info")
	env := map[string]any{
		"schema_version": json.Number("1"),
		"envelope_id":    "env-1",
		"issued_at":      json.Number("1"),
		"records":        []any{baseRecordMap(t), bad},
	}
	err := ValidateEnvelopeJSON(marshalMap(t, env))
	if err == nil || !strings.Contains(err.Error(), "$.records[1].finding_info") {
		t.Fatalf("err = %v, want $.records[1].finding_info missing", err)
	}
	env2 := map[string]any{
		"schema_version": json.Number("1"),
		"envelope_id":    "env-1",
		"issued_at":      json.Number("1"),
	}
	if err := ValidateEnvelopeJSON(marshalMap(t, env2)); err == nil || !strings.Contains(err.Error(), "$.records") {
		t.Fatalf("err = %v, want $.records missing", err)
	}
}

// 19: the reserved slots exist in the schema and accept their future
// shape (they stay optional so v1 payloads without them validate).
func TestReservedSlots(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal(embeddedSchemaJSON, &raw); err != nil {
		t.Fatalf("embedded schema: %v", err)
	}
	recordProps := raw["$defs"].(map[string]any)["record"].(map[string]any)["properties"].(map[string]any)
	if _, ok := recordProps["replay_id"]; !ok {
		t.Fatalf("record schema must reserve replay_id for E07-P01-W04")
	}
	envProps := raw["properties"].(map[string]any)
	if _, ok := envProps["attempt"]; !ok {
		t.Fatalf("envelope schema must reserve attempt")
	}

	t.Run("replay id slot validates", func(t *testing.T) {
		m := baseRecordMap(t)
		m["replay_id"] = "replay-42"
		if err := ValidateRecordJSON(marshalMap(t, m)); err != nil {
			t.Fatalf("reserved replay_id slot must validate a string: %v", err)
		}
	})
	t.Run("attempt slot validates", func(t *testing.T) {
		env := map[string]any{
			"schema_version": json.Number("1"),
			"envelope_id":    "env-1",
			"issued_at":      json.Number("1"),
			"records":        []any{},
			"attempt":        json.Number("3"),
		}
		if err := ValidateEnvelopeJSON(marshalMap(t, env)); err != nil {
			t.Fatalf("reserved attempt slot must validate an integer: %v", err)
		}
	})
}

// 20: mapped records of every event type validate against the schema
// (compositional round-trip: mapper output is schema-valid by
// construction).
func TestMappedRecordsValidate(t *testing.T) {
	for _, eventType := range []string{"policy.deny", "policy.mask", "policy.flag", "policy.allow", "policy.quarantine"} {
		rec, err := MapEvent(fixture(eventType))
		if err != nil {
			t.Fatalf("MapEvent(%s): %v", eventType, err)
		}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := ValidateRecordJSON(data); err != nil {
			t.Errorf("mapped %s record does not validate: %v", eventType, err)
		}
	}
}

// 21: minLength/maxLength are enforced (title bound).
func TestStringLengths(t *testing.T) {
	m := baseRecordMap(t)
	m["finding_info"].(map[string]any)["title"] = strings.Repeat("x", 1025)
	err := ValidateRecordJSON(marshalMap(t, m))
	if err == nil || !strings.Contains(err.Error(), "$.finding_info.title") {
		t.Fatalf("err = %v, want $.finding_info.title maxLength violation", err)
	}
}

// 22: empty evidence kind is rejected by minLength-derived pattern.
func TestEvidenceKindShape(t *testing.T) {
	m := baseRecordMap(t)
	m["evidence"].([]any)[0].(map[string]any)["kind"] = ""
	err := ValidateRecordJSON(marshalMap(t, m))
	if err == nil || !strings.Contains(err.Error(), "$.evidence[0].kind") {
		t.Fatalf("err = %v, want $.evidence[0].kind pattern violation", err)
	}
}

// 23: identity is required by the schema and always emitted by the
// mapper (non-omitempty struct field); absence must fail loudly rather
// than degrade to "no identity known".
func TestIdentityRequired(t *testing.T) {
	m := baseRecordMap(t)
	delete(m, "identity")
	err := ValidateRecordJSON(marshalMap(t, m))
	if err == nil || !strings.Contains(err.Error(), "$.identity") {
		t.Fatalf("err = %v, want $.identity missing", err)
	}
}

// 24: a mapped record with empty evidence list validates.
func TestEmptyEvidenceList(t *testing.T) {
	ev := fixture("policy.flag")
	ev.Evidence = nil
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	data, _ := json.Marshal(rec)
	if err := ValidateRecordJSON(data); err != nil {
		t.Fatalf("record without evidence must validate: %v", err)
	}
}

// 25: secevents cost-none records omit the cost field and still validate.
func TestCostNoneOmitted(t *testing.T) {
	ev := fixture("policy.allow")
	ev.Cost = secevents.Cost{State: secevents.CostNone}
	rec, err := MapEvent(ev)
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	data, _ := json.Marshal(rec)
	if err := ValidateRecordJSON(data); err != nil {
		t.Fatalf("cost-none record must validate without a cost object: %v", err)
	}
}
