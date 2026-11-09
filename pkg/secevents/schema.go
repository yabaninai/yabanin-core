// Package secevents implements the common security-events schema (packet
// E01-P03). It is the single definition of the enterprise-facing security
// event contract:
//
//   - typed agent/session/task/tool identifiers with explicit
//     known/unknown/absent states (E01-P03-W01),
//
//   - an integer schema version with fail-closed decode rules and
//     lossless unknown-field retention (E01-P03-W02),
//
//   - redacted evidence references that cannot carry content by type
//     (E01-P03-W03, evidence.go),
//
//   - a versioned adapter from the core request-event shapes
//     (E01-P03-W04, adapter.go),
//
//   - an idempotent ingest path whose replay, skew and cost semantics are
//     the packet acceptance invariant (E01-P03-W05, ingest.go):
//
//     redelivery does not double-count events; timestamp skew and
//     unknown cost never collapse into success or zero.
//
// The package is additive core SPI. It never modifies the existing event
// pipeline (pkg/events, pkg/eventpublisher are read-only dependencies of
// the adapter) and introduces no proprietary boundary: the Apache/enterprise
// module split is owned by E01-P02, which is a separate packet. Enterprise
// integrations plug in through the Adapter interface with a stable contract
// version; core keeps a reference implementation.
package secevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SchemaVersion is the current security-event schema version. Producers
// MUST stamp it on every event. Decode rules (E01-P03-W02):
//
//   - a missing or zero schema_version is a protocol violation (an
//     unversioned record must not be guessed into the current schema),
//   - version <= SchemaVersion decodes: evolution within a version is
//     strictly additive optional fields, so older readers of the same
//     version stay compatible,
//   - version > SchemaVersion is rejected (fail closed): an unknown
//     schema must never be silently zero-decoded into a valid-looking
//     security event.
const SchemaVersion = 1

// Sentinel errors. Callers should classify with errors.Is; wrapped
// variants carry the offending value in the message.
var (
	// ErrNoSchemaVersion is returned when an event carries no (or a zero)
	// schema version.
	ErrNoSchemaVersion = errors.New("secevents: event has no schema_version")
	// ErrUnknownSchemaVersion is returned when an event's schema version is
	// newer than SchemaVersion; decoding it would be a guess.
	ErrUnknownSchemaVersion = errors.New("secevents: unknown schema_version")
	// ErrInvalidEvent is returned for structural violations (bad
	// identifiers, cost-state contradictions, malformed evidence refs).
	ErrInvalidEvent = errors.New("secevents: invalid event")
)

// IDState distinguishes the three security-relevant states of an
// identifier (E01-P03-W01). The distinction is the point: an UNKNOWN tool
// (present, value not determinable — e.g. stripped by redaction) must not
// be conflated with an ABSENT tool (no tool was involved), and neither may
// be reported as a known identifier.
type IDState string

const (
	// IDKnown means the identifier is present and its value is authoritative.
	IDKnown IDState = "known"
	// IDUnknown means the identity exists but its value could not be determined.
	// Value must be empty; a value plus unknown is a contradiction.
	IDUnknown IDState = "unknown"
	// IDAbsent means no such identity is involved in the event.
	IDAbsent IDState = "absent"
)

// IDRef is one typed identifier reference. When decoded with an empty
// State the reference is normalized: a non-empty Value means known, an
// empty Value means absent. An explicit unknown State must not carry a
// value.
type IDRef struct {
	Value string  `json:"value,omitempty"`
	State IDState `json:"state,omitempty"`
}

// normalize resolves the default state and reports contradictions.
func (r *IDRef) normalize(what string) error {
	switch r.State {
	case "":
		if r.Value != "" {
			r.State = IDKnown
		} else {
			r.State = IDAbsent
		}
	case IDKnown:
		if r.Value == "" {
			return fmt.Errorf("%w: %s: known identifier requires a value", ErrInvalidEvent, what)
		}
	case IDUnknown:
		if r.Value != "" {
			return fmt.Errorf("%w: %s: unknown identifier must not carry a value", ErrInvalidEvent, what)
		}
	case IDAbsent:
		if r.Value != "" {
			return fmt.Errorf("%w: %s: absent identifier must not carry a value", ErrInvalidEvent, what)
		}
	default:
		return fmt.Errorf("%w: %s: unknown identifier state %q", ErrInvalidEvent, what, r.State)
	}
	return nil
}

// Identity is the agent/session/task/tool identifier block of a security
// event (E01-P03-W01). Agent references the issuing agent principal,
// Session the conversation session, Task the client task tag, Tool the
// tool involved in the security signal (absent for non-tool events).
type Identity struct {
	Agent   IDRef `json:"agent"`
	Session IDRef `json:"session"`
	Task    IDRef `json:"task"`
	Tool    IDRef `json:"tool"`
}

func (id *Identity) normalize() error {
	for _, f := range []struct {
		what string
		ref  *IDRef
	}{
		{"identity.agent", &id.Agent},
		{"identity.session", &id.Session},
		{"identity.task", &id.Task},
		{"identity.tool", &id.Tool},
	} {
		if err := f.ref.normalize(f.what); err != nil {
			return err
		}
	}
	return nil
}

// CostState makes "no cost dimension", "cost known" and "cost unknown"
// explicitly distinct (acceptance: an unknown cost must never collapse
// into zero).
type CostState string

const (
	// CostNone means the event has no cost dimension (N/A).
	CostNone CostState = "none"
	// CostKnown means MicroUSD is authoritative (0 is a legal known-free cost,
	// e.g. a cache-served request).
	CostKnown CostState = "known"
	// CostUnknown means the cost could not be determined. It must stay unknown:
	// MicroUSD must be 0 and consumers must not treat the event as free.
	CostUnknown CostState = "unknown"
)

// Cost carries the cost dimension of a security event.
type Cost struct {
	State    CostState `json:"state,omitempty"`
	MicroUSD int64     `json:"micro_usd,omitempty"`
}

func (c *Cost) normalize() error {
	switch c.State {
	case "":
		if c.MicroUSD != 0 {
			return fmt.Errorf("%w: cost: micro_usd requires an explicit state", ErrInvalidEvent)
		}
		c.State = CostNone
	case CostNone:
		if c.MicroUSD != 0 {
			return fmt.Errorf("%w: cost: state none must not carry micro_usd", ErrInvalidEvent)
		}
	case CostKnown:
		// any MicroUSD, including 0 (known-free)
	case CostUnknown:
		if c.MicroUSD != 0 {
			return fmt.Errorf("%w: cost: unknown cost must not carry a value (it would collapse unknown into a number)", ErrInvalidEvent)
		}
	default:
		return fmt.Errorf("%w: cost: unknown cost state %q", ErrInvalidEvent, c.State)
	}
	return nil
}

// wire is the canonical v1 JSON shape of a security event. Event embeds it
// so the exported surface stays flat while MarshalJSON can re-attach
// unknown fields retained by Decode.
type wire struct {
	SchemaVersion int           `json:"schema_version"`
	EventID       string        `json:"event_id"`
	EventType     string        `json:"event_type"`
	OrgID         string        `json:"org_id"`
	OccurredAt    time.Time     `json:"occurred_at"`
	Identity      Identity      `json:"identity"`
	Summary       string        `json:"summary,omitempty"`
	Cost          Cost          `json:"cost"`
	Evidence      []EvidenceRef `json:"evidence,omitempty"`
}

// knownSchemaFields is the set of v1 top-level JSON keys. Anything else on
// the wire is an unknown field (see Decode).
var knownSchemaFields = map[string]struct{}{}

func init() {
	// Derived from the wire struct tags so the set can never drift from
	// the schema definition above (a marshal probe would miss omitempty
	// fields).
	t := reflect.TypeOf(wire{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		knownSchemaFields[name] = struct{}{}
	}
}

// Event is one security event (E01-P03). Constructed events must set
// SchemaVersion = SchemaVersion; Validate enforces it. Events decoded from
// the wire additionally carry unknown fields, which Encode re-emits so a
// redelivered event re-decodes byte-faithfully (lossless replay).
type Event struct {
	wire
	// unknown holds top-level fields not present in the current schema,
	// retained verbatim by Decode. Key order is normalized on encode.
	unknown map[string]json.RawMessage
	// nested holds the unknown keys of the schema's structured
	// sub-objects (identity, its IDRefs, cost, evidence elements),
	// retained verbatim by Decode — nested schema evolution must not be
	// silently dropped (AUD-EVENT-02). nil when there is nothing to
	// retain, so clean events keep their exact pre-fix wire form.
	nested *nestedUnknown
}

// MarshalJSON implements the lossless wire form: known schema fields in
// canonical order, unknown retained fields merged in (encoding/json sorts
// map keys, so the output is deterministic).
func (e Event) MarshalJSON() ([]byte, error) {
	known, err := json.Marshal(e.wire)
	if err != nil {
		return nil, fmt.Errorf("secevents: marshal: %w", err)
	}
	if len(e.unknown) == 0 && e.nested == nil {
		return known, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(known, &m); err != nil {
		return nil, fmt.Errorf("secevents: marshal merge: %w", err)
	}
	for k, v := range e.unknown {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	if e.nested != nil {
		if err := mergeNested(m, e.nested); err != nil {
			return nil, err
		}
	}
	return json.Marshal(m)
}

// Encode renders the event to its canonical JSON wire form.
func (e Event) Encode() ([]byte, error) {
	return json.Marshal(e)
}

// DecodeReport reports what Decode had to do beyond the schema.
type DecodeReport struct {
	// UnknownFields lists the top-level wire fields not present in the
	// current schema, sorted. Their values are retained on the event and
	// re-emitted by Encode (tolerant reader, lossless round-trip).
	UnknownFields []string
	// NestedUnknownFields lists the unknown keys of the schema's
	// structured sub-objects as sorted dotted paths — "identity.<key>",
	// "identity.<ref>.<key>", "cost.<key>", "evidence[<i>].<key>". Their
	// values are likewise retained and re-emitted (AUD-EVENT-02): nested
	// evolution is tolerated, reported and retained, never silently
	// dropped. Top-level keys stay in UnknownFields only.
	NestedUnknownFields []string
}

// Decode parses one security event from its JSON wire form and applies the
// schema-version and unknown-field semantics of E01-P03-W02. See
// SchemaVersion for the version rules.
func Decode(data []byte) (Event, DecodeReport, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Event{}, DecodeReport{}, fmt.Errorf("%w: not a JSON object: %v", ErrInvalidEvent, err)
	}

	versionRaw, ok := raw["schema_version"]
	if !ok {
		return Event{}, DecodeReport{}, ErrNoSchemaVersion
	}
	var version int
	if err := strictInt(versionRaw, &version); err != nil {
		return Event{}, DecodeReport{}, fmt.Errorf("%w: schema_version: %v", ErrInvalidEvent, err)
	}
	if version == 0 {
		return Event{}, DecodeReport{}, ErrNoSchemaVersion
	}
	if version > SchemaVersion {
		return Event{}, DecodeReport{}, fmt.Errorf("%w: event %d > reader %d", ErrUnknownSchemaVersion, version, SchemaVersion)
	}

	var unknownNames []string
	unknown := make(map[string]json.RawMessage)
	for k, v := range raw {
		if _, isKnown := knownSchemaFields[k]; isKnown {
			continue
		}
		unknownNames = append(unknownNames, k)
		unknown[k] = v
	}
	sort.Strings(unknownNames)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(raw); err != nil {
		return Event{}, DecodeReport{}, fmt.Errorf("%w: re-encode: %v", ErrInvalidEvent, err)
	}
	var e Event
	// Unknown fields cannot break strict decoding because json.Unmarshal
	// into the wire struct ignores absent ones and tolerates extra keys;
	// the tolerant-reader contract (CORE-TRACE-05 precedent) is that they
	// are retained, which the map above already guarantees.
	if err := json.Unmarshal(buf.Bytes(), &e.wire); err != nil {
		return Event{}, DecodeReport{}, fmt.Errorf("%w: schema fields: %v", ErrInvalidEvent, err)
	}
	e.unknown = unknown
	nested, nestedNames := captureNested(raw)
	e.nested = nested
	if err := e.Validate(); err != nil {
		return Event{}, DecodeReport{}, err
	}
	return e, DecodeReport{UnknownFields: unknownNames, NestedUnknownFields: nestedNames}, nil
}

// strictInt decodes a JSON number that must be an integer.
func strictInt(raw json.RawMessage, out *int) error {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return fmt.Errorf("must be an integer, got %s", n.String())
	}
	*out = int(i)
	return nil
}

// Validate enforces the full v1 structural contract on a constructed or
// decoded event. It normalizes identifier and cost defaults in place.
func (e *Event) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema_version %d, want %d", ErrInvalidEvent, e.SchemaVersion, SchemaVersion)
	}
	if !validSlug(e.EventType) {
		return fmt.Errorf("%w: event_type %q", ErrInvalidEvent, e.EventType)
	}
	if err := validID("event_id", e.EventID); err != nil {
		return err
	}
	if e.OrgID == "" {
		return fmt.Errorf("%w: org_id is required (dedup keys are org-scoped)", ErrInvalidEvent)
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("%w: occurred_at is required", ErrInvalidEvent)
	}
	if err := e.Identity.normalize(); err != nil {
		return err
	}
	if err := e.Cost.normalize(); err != nil {
		return err
	}
	for _, ref := range e.Evidence {
		if err := ref.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validSlug accepts non-empty lowercase [a-z0-9._-] names up to 64 runes
// (event types, evidence kinds).
func validSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// validID accepts a non-empty identifier without control characters or
// whitespace, up to 256 bytes (event ids end up in dedup keys and logs).
func validID(what, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidEvent, what)
	}
	if len(s) > 256 || !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s length/encoding", ErrInvalidEvent, what)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: %s must not contain control characters or whitespace", ErrInvalidEvent, what)
		}
	}
	return nil
}

// TrimSummary bounds a producer-supplied summary to the schema maximum and
// strips control characters, so summaries stay single-line log-safe. The
// byte cut backs off to the last valid UTF-8 rune boundary, so the result
// is always a well-formed string for direct callers.
func TrimSummary(s string) string {
	const maxSummary = 1024
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxSummary {
		// b.String() is always valid UTF-8 (built rune-by-rune), so the
		// only possible defect is a rune split by the cut: walk the cut
		// back while it points into the middle of a rune, so out ends
		// exactly at a rune boundary.
		cut := maxSummary
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
		out = strings.TrimRight(out, " ")
	}
	return out
}
