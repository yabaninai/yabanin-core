// Nested unknown-field retention (AUD-EVENT-02, owner audit 2026-11-02).
//
// The schema's structured sub-objects — identity, the four identity IDRefs,
// cost and each evidence element — evolve strictly additively within a
// schema version (see SchemaVersion). A newer producer may therefore add
// optional nested fields an older reader does not know. The top-level
// unknown fields are retained verbatim by Decode; before this file existed
// their NESTED counterparts were silently dropped by the struct unmarshal
// (reproduced on the unmodified baseline: five added fields vanished on the
// sink round-trip with an empty report), which is silent data loss against
// the package's own contract: tolerate, report, retain — never drop.
//
// captureNested collects the unknown keys of every structured sub-object
// verbatim at decode time; MarshalJSON merges them back (encoding/json
// sorts map keys, so the output stays deterministic). DecodeReport gains
// the dotted paths of everything retained, so an operator sees exactly what
// a newer producer added. Unknown keys never weaken validation: the schema
// rules run on the known fields exactly as before, and a future schema
// bump that promotes a retained key to known simply takes over the value.

package secevents

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// jsonFieldSet derives the JSON key set of a struct from its tags — the
// same derivation rule as knownSchemaFields — so the known nested key sets
// can never drift from the schema structs above.
func jsonFieldSet(t reflect.Type) map[string]struct{} {
	m := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		m[name] = struct{}{}
	}
	return m
}

var (
	knownIdentityFields = jsonFieldSet(reflect.TypeOf(Identity{}))    // agent, session, task, tool
	knownIDRefFields    = jsonFieldSet(reflect.TypeOf(IDRef{}))       // value, state
	knownCostFields     = jsonFieldSet(reflect.TypeOf(Cost{}))        // state, micro_usd
	knownEvidenceFields = jsonFieldSet(reflect.TypeOf(EvidenceRef{})) // kind, digest, location
)

// captureNested walks the decoded top-level object and collects the unknown
// keys of the structured sub-objects verbatim, together with their sorted
// dotted report names ("identity.<key>", "identity.<ref>.<key>",
// "cost.<key>", "evidence[<i>].<key>"). It returns nil names when nothing
// nested was unknown, so clean events keep their exact pre-fix wire form.
func captureNested(raw map[string]json.RawMessage) (*nestedUnknown, []string) {
	n := &nestedUnknown{}
	var names []string

	if id, ok := raw["identity"]; ok {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(id, &obj); err == nil {
			for k, v := range obj {
				if _, known := knownIdentityFields[k]; !known {
					if n.identity == nil {
						n.identity = map[string]json.RawMessage{}
					}
					n.identity[k] = v
					names = append(names, "identity."+k)
					continue
				}
				// A known IDRef container may itself carry unknown keys.
				var refObj map[string]json.RawMessage
				if err := json.Unmarshal(v, &refObj); err != nil {
					continue // not an object; the wire unmarshal surfaces the schema violation
				}
				for rk, rv := range refObj {
					if _, known := knownIDRefFields[rk]; !known {
						if n.refs == nil {
							n.refs = map[string]map[string]json.RawMessage{}
						}
						if n.refs[k] == nil {
							n.refs[k] = map[string]json.RawMessage{}
						}
						n.refs[k][rk] = rv
						names = append(names, "identity."+k+"."+rk)
					}
				}
			}
		}
	}

	if c, ok := raw["cost"]; ok {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(c, &obj); err == nil {
			for k, v := range obj {
				if _, known := knownCostFields[k]; !known {
					if n.cost == nil {
						n.cost = map[string]json.RawMessage{}
					}
					n.cost[k] = v
					names = append(names, "cost."+k)
				}
			}
		}
	}

	if ev, ok := raw["evidence"]; ok {
		var arr []json.RawMessage
		if err := json.Unmarshal(ev, &arr); err == nil {
			for i, elem := range arr {
				var obj map[string]json.RawMessage
				if err := json.Unmarshal(elem, &obj); err != nil {
					continue // not an object; the wire unmarshal surfaces the schema violation
				}
				for k, v := range obj {
					if _, known := knownEvidenceFields[k]; !known {
						for len(n.evidence) <= i {
							n.evidence = append(n.evidence, nil)
						}
						if n.evidence[i] == nil {
							n.evidence[i] = map[string]json.RawMessage{}
						}
						n.evidence[i][k] = v
						names = append(names, fmt.Sprintf("evidence[%d].%s", i, k))
					}
				}
			}
		}
	}

	if n.empty() {
		return nil, nil
	}
	sort.Strings(names)
	return n, names
}

// nestedUnknown retains verbatim the unknown keys of the schema's
// structured sub-objects so nested evolution survives the decode/encode
// round-trip losslessly, exactly like top-level unknown fields do.
type nestedUnknown struct {
	identity map[string]json.RawMessage
	refs     map[string]map[string]json.RawMessage // "agent"|"session"|"task"|"tool" -> unknown keys
	cost     map[string]json.RawMessage
	evidence []map[string]json.RawMessage // index-aligned with Evidence; entries nil when the element had no unknown keys
}

// empty reports whether nothing nested was retained.
func (n *nestedUnknown) empty() bool {
	return len(n.identity) == 0 && len(n.refs) == 0 && len(n.cost) == 0 && len(n.evidence) == 0
}

// mergeNested re-attaches the retained nested unknown keys to the canonical
// marshal of the wire struct. m is MarshalJSON's top-level map; every merge
// goes through a map[string]json.RawMessage re-marshal, and encoding/json
// sorts map keys, so the result stays deterministic. Known values win: a
// retained key is only merged when the known shape does not already carry
// it (a future reader that promoted the key parses it into the struct).
func mergeNested(m map[string]json.RawMessage, n *nestedUnknown) error {
	if len(n.identity) > 0 || len(n.refs) > 0 {
		b, err := mergeIntoObject(m["identity"], n.identity, func(key string, current json.RawMessage) ([]byte, error) {
			extra, ok := n.refs[key]
			if !ok {
				return nil, nil
			}
			return mergeIntoObject(current, extra, nil, "identity."+key)
		}, "identity")
		if err != nil {
			return err
		}
		m["identity"] = b
	}

	if len(n.cost) > 0 {
		b, err := mergeIntoObject(m["cost"], n.cost, nil, "cost")
		if err != nil {
			return err
		}
		m["cost"] = b
	}

	for i, extra := range n.evidence {
		if len(extra) == 0 {
			continue
		}
		rawEv, ok := m["evidence"]
		if !ok {
			return fmt.Errorf("secevents: marshal merge: evidence[%d]: evidence missing on marshal", i)
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(rawEv, &arr); err != nil {
			return fmt.Errorf("secevents: marshal merge: evidence: %w", err)
		}
		if i >= len(arr) {
			return fmt.Errorf("secevents: marshal merge: evidence[%d]: index out of range on marshal", i)
		}
		b, err := mergeIntoObject(arr[i], extra, nil, fmt.Sprintf("evidence[%d]", i))
		if err != nil {
			return err
		}
		arr[i] = b
		bAll, err := json.Marshal(arr)
		if err != nil {
			return fmt.Errorf("secevents: marshal merge: evidence: %w", err)
		}
		m["evidence"] = bAll
	}
	return nil
}

// mergeIntoObject merges extra unknown keys into the object at raw (missing
// raw starts empty). recurse, when non-nil, is invoked for each current key
// with its bytes and may return replacement bytes for nested sub-objects
// (used for the identity IDRefs); returning nil bytes leaves the key as is.
func mergeIntoObject(raw json.RawMessage, extra map[string]json.RawMessage, recurse func(key string, current json.RawMessage) ([]byte, error), what string) (json.RawMessage, error) {
	obj := map[string]json.RawMessage{}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("secevents: marshal merge: %s: %w", what, err)
		}
	}
	for k, v := range extra {
		if _, exists := obj[k]; !exists {
			obj[k] = v
		}
	}
	if recurse != nil {
		// Snapshot the keys first: recurse merges into current bytes and
		// must not see keys it adds itself.
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			inner, err := recurse(k, obj[k])
			if err != nil {
				return nil, err
			}
			if inner != nil {
				obj[k] = inner
			}
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("secevents: marshal merge: %s: %w", what, err)
	}
	return b, nil
}
