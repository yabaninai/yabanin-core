package secevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// anchorOcc is the fixed producer timestamp every test uses: no test in
// this package may depend on wall-clock time (deterministic anchors).
var anchorOcc = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func validEvent() Event {
	e := Event{wire: wire{
		SchemaVersion: SchemaVersion,
		EventID:       "01JKLA-security-0001",
		EventType:     "tool.deny",
		OrgID:         "org-1",
		OccurredAt:    anchorOcc,
		Identity: Identity{
			Agent:   IDRef{Value: "agent-7", State: IDKnown},
			Session: IDRef{Value: "sess-42"},
			Task:    IDRef{State: IDAbsent},
			Tool:    IDRef{State: IDUnknown},
		},
		Cost: Cost{State: CostUnknown},
	}}
	return e
}

func mustEncode(t *testing.T, e Event) []byte {
	t.Helper()
	b, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func TestDecodeV1HappyPath(t *testing.T) {
	wireJSON := `{
		"schema_version": 1,
		"event_id": "01JKLA-security-0001",
		"event_type": "tool.deny",
		"org_id": "org-1",
		"occurred_at": "2026-11-02T12:00:00Z",
		"identity": {
			"agent": {"value": "agent-7", "state": "known"},
			"session": {"value": "sess-42"},
			"task": {"state": "absent"},
			"tool": {"state": "unknown"}
		},
		"summary": "policy deny by p1",
		"cost": {"state": "unknown"},
		"evidence": [{"kind": "payload_digest", "digest": "` + strings.Repeat("ab", 32) + `"}]
	}`
	e, report, err := Decode([]byte(wireJSON))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(report.UnknownFields) != 0 {
		t.Fatalf("unexpected unknown fields: %v", report.UnknownFields)
	}
	if e.EventID != "01JKLA-security-0001" || e.EventType != "tool.deny" || e.OrgID != "org-1" {
		t.Fatalf("scalar mismatch: %+v", e.wire)
	}
	if !e.OccurredAt.Equal(anchorOcc) {
		t.Fatalf("occurred_at = %v, want %v", e.OccurredAt, anchorOcc)
	}
	if e.Identity.Agent.Value != "agent-7" || e.Identity.Agent.State != IDKnown {
		t.Fatalf("agent = %+v", e.Identity.Agent)
	}
	if e.Identity.Session.State != IDKnown || e.Identity.Session.Value != "sess-42" {
		t.Fatalf("session default state should normalize to known: %+v", e.Identity.Session)
	}
	if e.Identity.Task.State != IDAbsent || e.Identity.Tool.State != IDUnknown {
		t.Fatalf("task/tool states: %+v %+v", e.Identity.Task, e.Identity.Tool)
	}
	if e.Cost.State != CostUnknown || e.Cost.MicroUSD != 0 {
		t.Fatalf("cost = %+v", e.Cost)
	}
	if len(e.Evidence) != 1 || e.Evidence[0].Kind != EvidencePayloadDigest {
		t.Fatalf("evidence = %+v", e.Evidence)
	}
}

func TestDecodeRejectsMissingOrZeroSchemaVersion(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		_, _, err := Decode([]byte(`{"event_id":"x","org_id":"o","event_type":"a.b","occurred_at":"2026-11-02T12:00:00Z"}`))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("err = %v, want ErrNoSchemaVersion", err)
		}
	})
	t.Run("zero", func(t *testing.T) {
		_, _, err := Decode([]byte(`{"schema_version":0,"event_id":"x","org_id":"o","event_type":"a.b","occurred_at":"2026-11-02T12:00:00Z"}`))
		if !errors.Is(err, ErrNoSchemaVersion) {
			t.Fatalf("err = %v, want ErrNoSchemaVersion", err)
		}
	})
	t.Run("non_integer", func(t *testing.T) {
		_, _, err := Decode([]byte(`{"schema_version":"1","event_id":"x","org_id":"o","event_type":"a.b","occurred_at":"2026-11-02T12:00:00Z"}`))
		if !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
	})
}

// M6 anchor: a future schema version must fail CLOSED — an unknown schema
// must never silently decode into a zero-valued valid-looking event.
func TestDecodeRejectsFutureSchemaVersion(t *testing.T) {
	e, _, err := Decode([]byte(`{"schema_version":2,"event_id":"x","org_id":"o","event_type":"a.b","occurred_at":"2026-11-02T12:00:00Z"}`))
	if !errors.Is(err, ErrUnknownSchemaVersion) {
		t.Fatalf("err = %v, want ErrUnknownSchemaVersion", err)
	}
	if e.EventType != "" || e.OrgID != "" || e.EventID != "" {
		t.Fatalf("future-version event must not be partially decoded: %+v", e.wire)
	}
}

func TestDecodeOlderVersionAccepted(t *testing.T) {
	// version 0 < v < current decodes (within-version evolution is
	// additive; today's floor is 1, so this exercises the rule boundary).
	_, _, err := Decode([]byte(`{"schema_version":1,"event_id":"x","org_id":"o","event_type":"a.b","occurred_at":"2026-11-02T12:00:00Z"}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
}

// Unknown-field semantics (W02): tolerate, report, retain — never drop.
func TestDecodeUnknownFieldsRetainedRoundTrip(t *testing.T) {
	in := []byte(`{
		"schema_version": 1,
		"event_id": "x1",
		"event_type": "a.b",
		"org_id": "o",
		"occurred_at": "2026-11-02T12:00:00Z",
		"future_nested": {"k": [1, 2, {"z": true}]},
		"future_scalar": "keep me"
	}`)
	e, report, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got, want := report.UnknownFields, []string{"future_nested", "future_scalar"}; !equalStrings(got, want) {
		t.Fatalf("UnknownFields = %v, want %v (sorted)", got, want)
	}
	out := mustEncode(t, e)
	for _, field := range report.UnknownFields {
		if !bytes.Contains(out, []byte(`"`+field+`"`)) {
			t.Fatalf("re-encode lost unknown field %q: %s", field, out)
		}
	}
	// The retained value must survive byte-faithfully.
	if !bytes.Contains(out, []byte(`{"k":[1,2,{"z":true}]}`)) {
		t.Fatalf("unknown nested value not verbatim: %s", out)
	}
	// Round-trip stability: decode(encode(x)) reports the same unknowns.
	e2, report2, err := Decode(out)
	if err != nil {
		t.Fatalf("re-Decode: %v", err)
	}
	if !equalStrings(report.UnknownFields, report2.UnknownFields) {
		t.Fatalf("round-trip unknowns differ: %v vs %v", report.UnknownFields, report2.UnknownFields)
	}
	out2 := mustEncode(t, e2)
	if !bytes.Equal(out, out2) {
		t.Fatalf("encode not stable:\n%s\n%s", out, out2)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	e := validEvent()
	e.Evidence = append(e.Evidence, EvidenceRef{Kind: EvidencePayloadDigest, Digest: strings.Repeat("cd", 32)})
	a, b := mustEncode(t, e), mustEncode(t, e)
	if !bytes.Equal(a, b) {
		t.Fatalf("encode not deterministic")
	}
	if !bytes.Contains(a, []byte(`"schema_version":1`)) {
		t.Fatalf("schema_version missing from wire: %s", a)
	}
	if !bytes.Contains(a, []byte(`"occurred_at":"2026-11-02T12:00:00Z"`)) {
		t.Fatalf("occurred_at not canonical RFC3339 UTC: %s", a)
	}
}

func TestValidateIdentityMatrix(t *testing.T) {
	cases := []struct {
		name    string
		ref     IDRef
		wantErr bool
	}{
		{"known_with_value", IDRef{Value: "a", State: IDKnown}, false},
		{"value_defaults_known", IDRef{Value: "a"}, false},
		{"empty_defaults_absent", IDRef{}, false},
		{"absent_explicit", IDRef{State: IDAbsent}, false},
		{"unknown_no_value", IDRef{State: IDUnknown}, false},
		{"known_without_value", IDRef{State: IDKnown}, true},
		{"unknown_with_value", IDRef{Value: "a", State: IDUnknown}, true},
		{"absent_with_value", IDRef{Value: "a", State: IDAbsent}, true},
		{"bogus_state", IDRef{State: "maybe"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			e.Identity.Agent = tc.ref
			err := e.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// M3 anchor: an unknown cost must stay unknown — the schema forbids any
// construction that would collapse unknown into a number.
func TestValidateCostMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cost    Cost
		wantErr bool
	}{
		{"none_default", Cost{}, false},
		{"none_explicit", Cost{State: CostNone}, false},
		{"known_zero_is_legal", Cost{State: CostKnown, MicroUSD: 0}, false},
		{"known_value", Cost{State: CostKnown, MicroUSD: 12300}, false},
		{"unknown_zero", Cost{State: CostUnknown}, false},
		{"unknown_with_value_collapses", Cost{State: CostUnknown, MicroUSD: 1}, true},
		{"none_with_value", Cost{State: CostNone, MicroUSD: 1}, true},
		{"value_without_state", Cost{MicroUSD: 1}, true},
		{"bogus_state", Cost{State: "cheap"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			e.Cost = tc.cost
			err := e.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateStructuralRules(t *testing.T) {
	t.Run("wrong_schema_version", func(t *testing.T) {
		e := validEvent()
		e.SchemaVersion = 7
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad_event_type", func(t *testing.T) {
		e := validEvent()
		e.EventType = "Tool Deny!"
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty_org", func(t *testing.T) {
		e := validEvent()
		e.OrgID = ""
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("zero_time", func(t *testing.T) {
		e := validEvent()
		e.OccurredAt = time.Time{}
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("event_id_control_char", func(t *testing.T) {
		e := validEvent()
		e.EventID = "x\ny"
		if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestTrimSummary(t *testing.T) {
	if got := TrimSummary("a\nb\tc"); got != "a b c" {
		t.Fatalf("TrimSummary control chars: %q", got)
	}
	long := strings.Repeat("x", 2000)
	got := TrimSummary(long)
	if len(got) != 1024 {
		t.Fatalf("TrimSummary length = %d, want 1024", len(got))
	}
	// A rune straddling the byte cut must not survive truncated: the
	// result backs off to the last valid rune boundary (review N2).
	straddle := "x" + strings.Repeat("α", 511) + strings.Repeat("日", 300)
	cut := TrimSummary(straddle)
	if len(cut) > 1024 {
		t.Fatalf("TrimSummary straddle length = %d, want <= 1024", len(cut))
	}
	if !utf8.ValidString(cut) {
		t.Fatalf("TrimSummary straddle produced invalid UTF-8: %q", cut)
	}
	if !utf8.ValidString(TrimSummary("日日日")) {
		t.Fatalf("TrimSummary broke plain multi-byte input")
	}

	// N2 boundary completion for the rune back-off.
	// 4-byte rune straddling the cut: 1021 ASCII bytes + one 4-byte rune
	// (total 1025) — the cut at 1024 lands inside the rune and must back
	// off to exactly 1021 bytes, never emitting a partial rune.
	fourByte := strings.Repeat("x", 1021) + "😀"
	got4 := TrimSummary(fourByte)
	if want := strings.Repeat("x", 1021); got4 != want {
		t.Fatalf("TrimSummary 4-byte straddle = %d bytes, want exactly %d (byte-equal prefix)", len(got4), len(want))
	}
	// Cut landing exactly ON a rune start: no back-off, no loss — the
	// result is the full 1024 bytes of well-formed runes.
	onBoundary := strings.Repeat("α", 512) + "日"
	gotB := TrimSummary(onBoundary)
	if want := strings.Repeat("α", 512); gotB != want || len(gotB) != 1024 {
		t.Fatalf("TrimSummary exact-rune-boundary cut = %d bytes, want exactly 1024 ending at the boundary", len(gotB))
	}
	// Exact-max multibyte input is not cut at all.
	if got := TrimSummary(strings.Repeat("😀", 256)); len(got) != 1024 || !utf8.ValidString(got) {
		t.Fatalf("TrimSummary exact-max 4-byte input altered: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	// Back-off that would strand only trailing spaces trims to empty
	// instead of leaving orphan bytes of the split rune.
	spaceTail := strings.Repeat(" ", 1022) + "日"
	gotS := TrimSummary(spaceTail)
	if gotS != "" {
		t.Fatalf("TrimSummary space-tail back-off = %q, want empty (spaces trimmed, no orphan rune bytes)", gotS)
	}
	if !utf8.ValidString(gotS) {
		t.Fatalf("TrimSummary space-tail produced invalid UTF-8: %q", gotS)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time guard: the wire struct must produce exactly the documented
// schema key set (guards a field rename from silently forking the schema).
func TestKnownSchemaFieldsMatchWire(t *testing.T) {
	want := []string{
		"schema_version", "event_id", "event_type", "org_id", "occurred_at",
		"identity", "summary", "cost", "evidence",
	}
	if len(want) != len(knownSchemaFields) {
		t.Fatalf("knownSchemaFields size = %d, want %d (%v)", len(knownSchemaFields), len(want), want)
	}
	for _, k := range want {
		if _, ok := knownSchemaFields[k]; !ok {
			t.Fatalf("schema key %q missing from knownSchemaFields", k)
		}
	}
	// And the wire struct tags must agree.
	raw, err := json.Marshal(validEvent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range present {
		if _, ok := knownSchemaFields[k]; !ok {
			t.Fatalf("wire emitted key %q that is not in knownSchemaFields", k)
		}
	}
}
