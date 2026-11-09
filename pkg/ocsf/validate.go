package ocsf

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// The versioned export schema (W02-C01) is embedded at build time: the
// validator and the schema it enforces can never drift apart, and the
// package carries no external file dependency.
//
//go:embed schema/export-v1.json
var embeddedSchemaJSON []byte

// Version-gate sentinels (fail-closed discipline, version.go contract).
var (
	// ErrNoSchemaVersion: the payload carries no (or a zero) schema_version.
	ErrNoSchemaVersion = errors.New("ocsf: export payload has no schema_version")
	// ErrUnsupportedSchemaVersion: the payload's schema_version is newer
	// than ExportSchemaVersion; validating it would be a guess.
	ErrUnsupportedSchemaVersion = errors.New("ocsf: unsupported export schema_version")
	// ErrSchemaInvalid: the embedded schema itself failed to compile. It
	// can only happen on a build error (schema/ and validate.go drift);
	// validation then fails closed instead of guessing.
	ErrSchemaInvalid = errors.New("ocsf: embedded export schema is invalid")
	// ErrNotAnObject: the payload did not decode to a JSON object.
	ErrNotAnObject = errors.New("ocsf: export payload is not a JSON object")
)

// ValidateEnvelopeJSON decodes (strictly: no trailing garbage, numbers as
// json.Number) and validates one export envelope against the embedded
// schema. Version gating runs first (version.go): a missing or zero
// schema_version returns ErrNoSchemaVersion, a newer one
// ErrUnsupportedSchemaVersion; both wrap with the offending value.
func ValidateEnvelopeJSON(data []byte) error {
	v, err := decodeStrict(data)
	if err != nil {
		return err
	}
	return ValidateEnvelope(v)
}

// ValidateEnvelope validates an already-decoded envelope (map[string]any
// with json.Number numbers — what decodeStrict produces). Unknown fields
// are allowed everywhere: readers must ignore them (forward
// compatibility is a packet acceptance criterion).
func ValidateEnvelope(v any) error {
	if compileErr != nil {
		return compileErr // fail closed: never validate against a broken schema
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return ErrNotAnObject
	}
	if err := gateVersion(obj); err != nil {
		return err
	}
	return validateNode(schemaRoot(), "$", v)
}

// ValidateRecordJSON decodes (strictly) and validates one record against
// the record definition of the embedded schema. Golden fixtures are
// pinned through it (W01-C03/W02-C02 round-trip acceptance). A standalone
// record must carry its own schema_version (same fail-closed gate).
func ValidateRecordJSON(data []byte) error {
	if compileErr != nil {
		return compileErr // fail closed: never validate against a broken schema
	}
	v, err := decodeStrict(data)
	if err != nil {
		return err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return ErrNotAnObject
	}
	if err := gateVersion(obj); err != nil {
		return err
	}
	return validateNode(recordDef(), "$", v)
}

// gateVersion enforces the fail-closed version gate on a decoded object.
func gateVersion(obj map[string]any) error {
	raw, ok := obj["schema_version"]
	if !ok {
		return fmt.Errorf("%w: payload root", ErrNoSchemaVersion)
	}
	n, ok := raw.(json.Number)
	if !ok {
		return fmt.Errorf("%w: schema_version is not a number", ErrNoSchemaVersion)
	}
	version, err := n.Int64()
	if err != nil || version < 1 {
		// version < 1 covers zero AND negative schema_versions (review
		// F1): the valid band is 1 <= v <= ExportSchemaVersion (W02
		// versioning artifact §3 rule 3) — anything below 1 is the same
		// fail-closed "no usable version" class, never a silent parse.
		return fmt.Errorf("%w: schema_version %s", ErrNoSchemaVersion, n.String())
	}
	if version > ExportSchemaVersion {
		return fmt.Errorf("%w: payload %d > reader %d", ErrUnsupportedSchemaVersion, version, ExportSchemaVersion)
	}
	return nil
}

// decodeStrict decodes one JSON value with exact numbers and rejects
// trailing garbage.
func decodeStrict(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("ocsf: decode: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("ocsf: decode: trailing data after JSON value")
	}
	return v, nil
}

// --- embedded schema compiler and walker -----------------------------
//
// The validator implements a declarative subset of JSON Schema (draft
// 2020-12) exactly matching what schema/export-v1.json uses:
//
//	type (object, array, string, integer, number, boolean),
//	properties, required, items, enum, pattern, minLength, maxLength,
//	minimum, and local $ref (#/$defs/<name>).
//
// Annotation keywords (title, description, $schema, $id) are parsed and
// ignored. Any other keyword would be ignored too — the contract is that
// the embedded schema only uses the subset above, and the compile step
// below records which keywords it saw so tests can pin the coverage (a
// schema sneaking in an unaudited keyword fails the corpus test rather
// than silently not being enforced).

type schemaNode struct {
	kind       string // "", "object", "array", "string", "integer", "number", "boolean"
	properties map[string]*schemaNode
	required   map[string]struct{}
	enum       []any
	pattern    *regexp.Regexp
	items      *schemaNode
	ref        string // unresolved local ref, resolved lazily with a depth guard
	minLength  int
	maxLength  int // 0 = unset
	minimum    *float64
}

var (
	compileOnce sync.Once
	compiled    *schemaNode
	defs        map[string]*schemaNode
	compileErr  error
	// keywordsSeen records every keyword found in the embedded schema so
	// tests can assert the enforced subset matches the schema's actual
	// vocabulary.
	keywordsSeen map[string]struct{}
)

func schemaRoot() *schemaNode { return compiled }

func recordDef() *schemaNode {
	return defs["record"]
}

// compileSchema parses the embedded schema. It runs once (sync.Once);
// on failure every validation fails closed with ErrSchemaInvalid.
func compileSchema() {
	compileOnce.Do(func() {
		keywordsSeen = map[string]struct{}{}
		var raw any
		dec := json.NewDecoder(bytes.NewReader(embeddedSchemaJSON))
		dec.UseNumber()
		if err := dec.Decode(&raw); err != nil {
			compileErr = fmt.Errorf("%w: parse: %v", ErrSchemaInvalid, err)
			return
		}
		root, ok := raw.(map[string]any)
		if !ok {
			compileErr = fmt.Errorf("%w: root is not an object", ErrSchemaInvalid)
			return
		}
		rawDefs, ok := root["$defs"].(map[string]any)
		if !ok {
			compileErr = fmt.Errorf("%w: no $defs", ErrSchemaInvalid)
			return
		}
		defs = make(map[string]*schemaNode, len(rawDefs))
		for name, d := range rawDefs {
			node, err := parseNode(d, 0)
			if err != nil {
				compileErr = fmt.Errorf("%w: $defs.%s: %v", ErrSchemaInvalid, name, err)
				return
			}
			defs[name] = node
		}
		node, err := parseNode(root, 0)
		if err != nil {
			compileErr = fmt.Errorf("%w: root: %v", ErrSchemaInvalid, err)
			return
		}
		compiled = node
	})
}

// parseNode walks one schema object of the embedded schema.
func parseNode(raw any, depth int) (*schemaNode, error) {
	if depth > 64 {
		return nil, fmt.Errorf("schema nesting too deep")
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema node is not an object")
	}
	node := &schemaNode{}
	for key, val := range obj {
		keywordsSeen[key] = struct{}{}
		switch key {
		case "type":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("type is not a string")
			}
			node.kind = s
		case "properties":
			props, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("properties is not an object")
			}
			node.properties = make(map[string]*schemaNode, len(props))
			for name, p := range props {
				child, err := parseNode(p, depth+1)
				if err != nil {
					return nil, fmt.Errorf("property %s: %v", name, err)
				}
				node.properties[name] = child
			}
		case "required":
			list, ok := val.([]any)
			if !ok {
				return nil, fmt.Errorf("required is not an array")
			}
			node.required = make(map[string]struct{}, len(list))
			for _, r := range list {
				s, ok := r.(string)
				if !ok {
					return nil, fmt.Errorf("required entry is not a string")
				}
				node.required[s] = struct{}{}
			}
		case "enum":
			list, ok := val.([]any)
			if !ok {
				return nil, fmt.Errorf("enum is not an array")
			}
			node.enum = list
		case "pattern":
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("pattern is not a string")
			}
			re, err := regexp.Compile(s)
			if err != nil {
				return nil, fmt.Errorf("pattern %q: %v", s, err)
			}
			node.pattern = re
		case "items":
			child, err := parseNode(val, depth+1)
			if err != nil {
				return nil, fmt.Errorf("items: %v", err)
			}
			node.items = child
		case "$ref":
			s, ok := val.(string)
			if !ok || !strings.HasPrefix(s, "#/$defs/") {
				return nil, fmt.Errorf("only local #/$defs/... refs are supported, got %v", val)
			}
			node.ref = strings.TrimPrefix(s, "#/$defs/")
		case "minLength":
			n, err := intKeyword(val)
			if err != nil {
				return nil, fmt.Errorf("minLength: %v", err)
			}
			node.minLength = n
		case "maxLength":
			n, err := intKeyword(val)
			if err != nil {
				return nil, fmt.Errorf("maxLength: %v", err)
			}
			node.maxLength = n
		case "minimum":
			f, err := numberKeyword(val)
			if err != nil {
				return nil, fmt.Errorf("minimum: %v", err)
			}
			node.minimum = &f
		}
	}
	return node, nil
}

func intKeyword(val any) (int, error) {
	n, ok := val.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a number")
	}
	i, err := n.Int64()
	if err != nil || i < 0 {
		return 0, fmt.Errorf("not a non-negative integer")
	}
	return int(i), nil
}

func numberKeyword(val any) (float64, error) {
	n, ok := val.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a number")
	}
	return n.Float64()
}

// maxRefDepth bounds $ref resolution during validation. The embedded
// schema is not recursive; the guard exists so a future schema edit
// cannot hang validators in an infinite $ref cycle.
const maxRefDepth = 64

// validateNode walks a decoded value against a schema node, building
// $-rooted error paths.
func validateNode(node *schemaNode, path string, v any) error {
	if node == nil {
		return nil
	}
	if node.ref != "" {
		target := defs[node.ref]
		if target == nil {
			return fmt.Errorf("%s: unknown $ref target %q (schema defect)", path, node.ref)
		}
		return validateRef(target, 0, path, v)
	}
	switch node.kind {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			return typeErr(path, v, "object")
		}
		for _, name := range sortedKeys(node.required) {
			if _, has := obj[name]; !has {
				return fmt.Errorf("%s.%s: missing required property", path, name)
			}
		}
		// Unknown properties are deliberately allowed (forward compat).
		for _, name := range sortedNodeKeys(node.properties) {
			if raw, has := obj[name]; has {
				if err := validateNode(node.properties[name], path+"."+name, raw); err != nil {
					return err
				}
			}
		}
	case "array":
		list, ok := v.([]any)
		if !ok {
			return typeErr(path, v, "array")
		}
		if node.items != nil {
			for i, item := range list {
				if err := validateNode(node.items, fmt.Sprintf("%s[%d]", path, i), item); err != nil {
					return err
				}
			}
		}
	case "string":
		s, ok := v.(string)
		if !ok {
			return typeErr(path, v, "string")
		}
		if len(s) < node.minLength {
			return fmt.Errorf("%s: shorter than minLength %d", path, node.minLength)
		}
		if node.maxLength > 0 && len(s) > node.maxLength {
			return fmt.Errorf("%s: longer than maxLength %d", path, node.maxLength)
		}
		if node.pattern != nil && !node.pattern.MatchString(s) {
			return fmt.Errorf("%s: %q does not match pattern %q", path, s, node.pattern)
		}
	case "integer":
		if !isJSONInteger(v) {
			return typeErr(path, v, "integer")
		}
	case "number":
		if !isJSONNumber(v) {
			return typeErr(path, v, "number")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return typeErr(path, v, "boolean")
		}
	}
	if node.minimum != nil {
		if f, ok := numericValue(v); ok && f < *node.minimum {
			return fmt.Errorf("%s: %v is below minimum %v", path, v, *node.minimum)
		}
	}
	if len(node.enum) > 0 && !enumHas(node.enum, v) {
		return fmt.Errorf("%s: %v is not one of the allowed values", path, v)
	}
	return nil
}

// validateRef resolves a $ref with a depth guard (see maxRefDepth).
func validateRef(target *schemaNode, depth int, path string, v any) error {
	if depth > maxRefDepth {
		return fmt.Errorf("%s: $ref resolution too deep (schema defect)", path)
	}
	if target.ref != "" {
		next := defs[target.ref]
		if next == nil {
			return fmt.Errorf("%s: unknown $ref target %q (schema defect)", path, target.ref)
		}
		return validateRef(next, depth+1, path, v)
	}
	return validateNode(target, path, v)
}

func typeErr(path string, v any, want string) error {
	return fmt.Errorf("%s: value is %s, want %s", path, jsonKind(v), want)
}

// jsonKind names the JSON type of a decoded value for error messages.
func jsonKind(v any) string {
	switch t := v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		if isJSONInteger(t) {
			return "integer"
		}
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// isJSONInteger accepts json.Number values with integral value ("2" and
// "2e0" are integers; "2.5" is not) — the JSON Schema notion, kept
// honest for producers that emit exponent form.
func isJSONInteger(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	if _, err := n.Int64(); err == nil {
		return true
	}
	f, err := n.Float64()
	return err == nil && f == math.Trunc(f)
}

func isJSONNumber(v any) bool {
	_, ok := v.(json.Number)
	return ok
}

func numericValue(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// enumHas compares a decoded value against enum entries with exact
// number semantics (integers and floats compare numerically, never
// lexically).
func enumHas(enum []any, v any) bool {
	for _, e := range enum {
		if enumEq(e, v) {
			return true
		}
	}
	return false
}

func enumEq(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		af, aerr := an.Float64()
		bf, berr := bn.Float64()
		return aerr == nil && berr == nil && af == bf
	}
	if aok != bok {
		return false
	}
	return a == b
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNodeKeys(m map[string]*schemaNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func init() { compileSchema() }
