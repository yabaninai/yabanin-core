package secevents

// AUD-EVENT-02 acceptance tests (owner audit 2026-11-02): nested schema
// evolution must not silently drop data. A newer producer adds optional
// fields INSIDE the schema's structured sub-objects within the same schema
// version (strictly additive evolution, see SchemaVersion); the reader must
// tolerate, report and retain them verbatim — the sink round-trip
// (decode → encode → re-decode) is byte-faithful.
//
// Baseline evidence: all five probe fields below vanished from the
// re-encoded document with an empty report
// (artifacts/imp/audit-event/RED-baseline-evidence.log). These tests pin
// the fix; they are the schema-evolution table the card requires.
//
// Failing loudly (rejecting evolved events) was rejected: it would break
// the tolerant-reader contract the package already commits to (strictly
// additive optional fields within a version must decode; the CORE-TRACE-05
// precedent). Silent loss is the only unacceptable answer, and it is gone.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// aud02Base is the minimal valid v1 event; each table case adds one nested
// unknown field to a different structured sub-object.
var aud02Base = `{
	"schema_version": 1,
	"event_id": "01JKLA-security-9002",
	"event_type": "tool.deny",
	"org_id": "org-1",
	"occurred_at": "2026-11-02T12:00:00Z",
	"identity": {"agent": {"value": "agent-7", "state": "known"}, "session": {"value": "sess-42"}},
	"cost": {"state": "known", "micro_usd": 1200},
	"evidence": [
		{"kind": "payload_digest", "digest": "` + strings.Repeat("ab", 32) + `"},
		{"kind": "payload_digest", "digest": "` + strings.Repeat("cd", 32) + `"}
	]
}`

func TestDecodeNestedUnknownFieldsRetainedRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(string) string // JSON-string surgery on aud02Base
		wantPath  string              // DecodeReport.NestedUnknownFields entry
		wantProbe string              // verbatim fragment that must survive Encode
	}{
		{
			name: "identity_new_field",
			mutate: func(s string) string {
				return strings.Replace(s,
					`"identity": {"agent"`,
					`"identity": {"executor": {"id": "gx-9", "mode": [1, 2]}, "agent"`, 1)
			},
			wantPath:  "identity.executor",
			wantProbe: `"executor":{"id":"gx-9","mode":[1,2]}`,
		},
		{
			name: "identity_idref_new_field",
			mutate: func(s string) string {
				return strings.Replace(s,
					`"agent": {"value": "agent-7", "state": "known"}`,
					`"agent": {"value": "agent-7", "state": "known", "trace_id": "tr-42"}`, 1)
			},
			wantPath:  "identity.agent.trace_id",
			wantProbe: `"trace_id":"tr-42"`,
		},
		{
			name: "cost_new_field",
			mutate: func(s string) string {
				return strings.Replace(s,
					`"cost": {"state": "known", "micro_usd": 1200}`,
					`"cost": {"state": "known", "micro_usd": 1200, "quote_id": "q-77"}`, 1)
			},
			wantPath:  "cost.quote_id",
			wantProbe: `"quote_id":"q-77"`,
		},
		{
			name: "evidence_element_new_field",
			mutate: func(s string) string {
				return strings.Replace(s,
					`{"kind": "payload_digest", "digest": "`+strings.Repeat("ab", 32)+`"}`,
					`{"kind": "payload_digest", "digest": "`+strings.Repeat("ab", 32)+`", "source": {"uri": "file:///a"}}`, 1)
			},
			wantPath:  "evidence[0].source",
			wantProbe: `"source":{"uri":"file:///a"}`,
		},
		{
			name: "evidence_second_element_new_field",
			mutate: func(s string) string {
				return strings.Replace(s,
					`{"kind": "payload_digest", "digest": "`+strings.Repeat("cd", 32)+`"}`,
					`{"kind": "payload_digest", "digest": "`+strings.Repeat("cd", 32)+`", "note": ["keep", "me"]}`, 1)
			},
			wantPath:  "evidence[1].note",
			wantProbe: `"note":["keep","me"]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.mutate(aud02Base))

			e, report, err := Decode(in)
			require.NoError(t, err)
			require.Empty(t, report.UnknownFields, "top-level report must stay top-level only")
			require.Contains(t, report.NestedUnknownFields, tc.wantPath)

			out := mustEncode(t, e)
			require.Contains(t, string(out), tc.wantProbe,
				"nested unknown value must survive the encode verbatim")

			// Retention must not trade away decoding: the known fields
			// still parse and the event still validates.
			require.Equal(t, "01JKLA-security-9002", e.EventID)
			require.Equal(t, int64(1200), e.Cost.MicroUSD)
			require.NoError(t, e.Validate())

			// Round-trip stability: the re-decode reports identically and
			// the second encode is byte-stable with the first.
			e2, report2, err := Decode(out)
			require.NoError(t, err)
			require.Equal(t, report.NestedUnknownFields, report2.NestedUnknownFields)
			out2 := mustEncode(t, e2)
			require.Equal(t, string(out), string(out2))
		})
	}
}

// The scratch RED case verbatim: one event, every block evolved at once.
func TestDecodeNestedUnknownAllBlocksOneEvent(t *testing.T) {
	in := []byte(`{
		"schema_version": 1,
		"event_id": "01JKLA-security-9003",
		"event_type": "tool.deny",
		"org_id": "org-1",
		"occurred_at": "2026-11-02T12:00:00Z",
		"identity": {
			"agent": {"value": "agent-7", "state": "known", "trace_id": "tr-42"},
			"session": {"value": "sess-42"},
			"executor": {"id": "gx-9", "mode": [1, 2]}
		},
		"cost": {"state": "known", "micro_usd": 1200, "quote_id": "q-77"},
		"evidence": [
			{"kind": "payload_digest", "digest": "` + strings.Repeat("ab", 32) + `", "source": {"uri": "file:///a"}},
			{"kind": "payload_digest", "digest": "` + strings.Repeat("cd", 32) + `", "note": ["keep", "me"]}
		]
	}`)

	e, report, err := Decode(in)
	require.NoError(t, err)
	require.Equal(t, []string{
		"cost.quote_id",
		"evidence[0].source",
		"evidence[1].note",
		"identity.agent.trace_id",
		"identity.executor",
	}, report.NestedUnknownFields, "sorted dotted paths of every retained nested unknown")

	out := mustEncode(t, e)
	for _, probe := range []string{
		`"executor":{"id":"gx-9","mode":[1,2]}`,
		`"trace_id":"tr-42"`,
		`"quote_id":"q-77"`,
		`"source":{"uri":"file:///a"}`,
		`"note":["keep","me"]`,
	} {
		require.Contains(t, string(out), probe)
	}

	// The document remains a valid event: re-decode is byte-faithful.
	e2, _, err := Decode(out)
	require.NoError(t, err)
	out2 := mustEncode(t, e2)
	require.True(t, bytes.Equal(out, out2))
}

// Retention is scoped: an event with no nested unknowns keeps its exact
// pre-fix wire form and reports nothing.
func TestEncodeUnchangedWithoutNestedUnknowns(t *testing.T) {
	e := validEvent()
	e.Evidence = append(e.Evidence, EvidenceRef{Kind: EvidencePayloadDigest, Digest: strings.Repeat("ab", 32)})
	out := mustEncode(t, e)

	// Byte-identical to the plain wire marshal: no phantom keys, no
	// rewrite of the canonical form (summary is omitempty-empty).
	known, err := json.Marshal(e.wire)
	require.NoError(t, err)
	require.Equal(t, string(known), string(out))

	_, report, err := Decode(out)
	require.NoError(t, err)
	require.Empty(t, report.UnknownFields)
	require.Empty(t, report.NestedUnknownFields)
}

// Nested unknown keys never weaken validation: the schema rules on the
// known fields run exactly as before.
func TestDecodeNestedUnknownDoesNotWeakenValidation(t *testing.T) {
	t.Run("known_without_value_still_rejected", func(t *testing.T) {
		in := []byte(`{
			"schema_version": 1, "event_id": "x", "event_type": "a.b", "org_id": "o",
			"occurred_at": "2026-11-02T12:00:00Z",
			"identity": {"agent": {"state": "known", "executor": {"x": 1}}}
		}`)
		_, _, err := Decode(in)
		require.ErrorIs(t, err, ErrInvalidEvent,
			"an unknown nested key must not bypass the IDRef contract")
	})
	t.Run("bad_digest_with_unknown_key_still_rejected", func(t *testing.T) {
		in := []byte(`{
			"schema_version": 1, "event_id": "x", "event_type": "a.b", "org_id": "o",
			"occurred_at": "2026-11-02T12:00:00Z",
			"evidence": [{"kind": "payload_digest", "digest": "zz", "note": 1}]
		}`)
		_, _, err := Decode(in)
		require.ErrorIs(t, err, ErrInvalidEvent,
			"an unknown nested key must not bypass the evidence contract")
	})
	t.Run("future_version_still_rejected_with_nested_unknowns", func(t *testing.T) {
		in := []byte(`{
			"schema_version": 2, "event_id": "x", "event_type": "a.b", "org_id": "o",
			"occurred_at": "2026-11-02T12:00:00Z",
			"identity": {"executor": {"x": 1}}
		}`)
		_, _, err := Decode(in)
		require.ErrorIs(t, err, ErrUnknownSchemaVersion)
	})
}
