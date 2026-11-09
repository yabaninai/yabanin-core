package consumer

// G4 owner decision 2026-11-04 — consumer-side validation of the producer
// trace_completeness stamp on request_rows.labels. Valid stamps survive
// normalization with a reserved slot; uninterpretable stamps are stripped
// and counted, never stored; rows without a stamp (legacy) are untouched.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

func traceStampFailureValue(t *testing.T, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(
		metrics.SilentFailuresTotal.WithLabelValues("audit_ingest_trace_completeness", reason))
}

// traceStampFakeSKKey assembles the canonical fake "sk-live" key at runtime
// from two fragments. The public-export gate's source secret scan
// (scripts/public-export-gate.sh section b) greps exported source text for
// sk- shapes with no suffix requirement, so the fixture must never appear
// as a contiguous literal in source — including in comments. The runtime
// value is byte-identical to the literal it replaces;
// TestTraceStampFakeSKKeyGolden pins that shape with an independent split.
var traceStampFakeSKKey = "sk-li" + "ve-0123456789abcdef"

// TestTraceStampFakeSKKeyGolden is the golden equality pin for the
// runtime-assembled fixture above: the fragments must concatenate
// byte-identically to the canonical fake key (built here from a different
// split point), so any assembly drift fails loud instead of silently
// weakening the strip-table negative row that uses the value.
func TestTraceStampFakeSKKeyGolden(t *testing.T) {
	require.Equal(t, "sk-live-"+"0123456789abcdef", traceStampFakeSKKey)
	// sk- prefix + 21 body chars — the exact shape the export gate's
	// section-b pattern matches on, pinned so the fixture keeps exercising
	// the non-envelope credential-shaped class it was written for.
	require.Len(t, traceStampFakeSKKey, 24)
}

// TestTraceCompletenessLabelValidation pins the accept/strip table.
func TestTraceCompletenessLabelValidation(t *testing.T) {
	cases := []struct {
		name        string
		value       string
		wantOK      bool
		wantFailure string
	}{
		{
			name:   "unknown_envelope",
			value:  `{"v":1,"c":"unknown"}`,
			wantOK: true,
		},
		{
			name:   "full_envelope",
			value:  `{"v":1,"c":"full"}`,
			wantOK: true,
		},
		{
			name:   "absent_envelope",
			value:  `{"v":1,"c":"absent"}`,
			wantOK: true,
		},
		{
			name:   "partial_with_producer_reasons",
			value:  `{"v":1,"c":"partial","r":["drop:event_publish:backlog_full","truncated:policy_steps","reasons_truncated"]}`,
			wantOK: true,
		},
		{
			name:        "newer_version_stripped",
			value:       `{"v":2,"c":"partial","r":["drop:event_publish:backlog_full"]}`,
			wantFailure: "unknown_version",
		},
		{
			name:        "corrupt_json_stripped",
			value:       `{"v":1,"c":"partial"`,
			wantFailure: "invalid_value",
		},
		{
			name:        "not_envelope_at_all_stripped",
			value:       traceStampFakeSKKey,
			wantFailure: "invalid_value",
		},
		{
			name:        "unknown_vocabulary_stripped",
			value:       `{"v":1,"c":"Complete"}`,
			wantFailure: "invalid_value",
		},
		{
			name:        "reason_outside_grammar_stripped",
			value:       `{"v":1,"c":"partial","r":["Bearer eyJhbGciOiJIUzI1NiJ9"]}`,
			wantFailure: "invalid_value",
		},
		{
			name:        "reason_with_content_stripped",
			value:       `{"v":1,"c":"partial","r":["user said: hello"]}`,
			wantFailure: "invalid_value",
		},
		{
			name:        "too_many_reasons_stripped",
			value:       `{"v":1,"c":"partial","r":["a","b","c","d","e"]}`,
			wantFailure: "invalid_value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, ok, failure := traceCompletenessLabel(map[string]string{traceStampLabelKey: tc.value})
			if tc.wantOK {
				require.True(t, ok)
				require.Empty(t, failure)
				require.Equal(t, tc.value, value, "a valid stamp is stored verbatim")
				return
			}
			require.False(t, ok)
			require.Equal(t, tc.wantFailure, failure)
		})
	}

	// Absent stamp: the legacy normal case — no strip, no count.
	_, ok, failure := traceCompletenessLabel(map[string]string{"workload": "agent:agent-g1"})
	require.False(t, ok)
	require.Empty(t, failure)
}

// TestTraceStampProducerReasonContract: the producer's closed reason enum
// (pkg/gateway trace_completeness.go, duplicated by the identical-caps
// discipline — not imported) must satisfy this consumer's grammar, so the
// two sides cannot drift apart silently.
func TestTraceStampProducerReasonContract(t *testing.T) {
	producerReasonCodes := []string{
		"drop:event_publish:backlog_full",
		"drop:event_publish:publish_failed",
		"truncated:policy_steps",
		"truncated:policy_findings",
		"reasons_truncated",
	}
	for _, code := range producerReasonCodes {
		require.Regexp(t, traceStampReasonPattern, code,
			"producer reason %q must satisfy the consumer grammar", code)
	}
}

// TestLabelsJSONPreservesValidStamp: a valid stamp survives normalization,
// keeps sibling labels, and is never evicted by the label cap.
func TestLabelsJSONPreservesValidStamp(t *testing.T) {
	stamp := `{"v":1,"c":"partial","r":["drop:event_publish:backlog_full"]}`
	out := string(labelsJSON(map[string]interface{}{"labels": `{"workload":"agent:agent-g1","trace_completeness":` + fmt.Sprintf("%q", stamp) + `}`}))
	require.Contains(t, out, `"workload":"agent:agent-g1"`)
	require.Contains(t, out, `"trace_completeness":`+fmt.Sprintf("%q", stamp))

	// The stamped value round-trips as valid envelope JSON, not as a
	// normalized/escaped mutation of it.
	var stored map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &stored))
	require.Equal(t, stamp, stored[traceStampLabelKey])
}

// TestLabelsJSONStampWinsReservedSlot: the stamp reserves one deterministic
// slot, so a label-heavy row cannot evict it; client labels cap one lower.
// Which client labels survive the cap is map-iteration order (unspecified by
// design), so the assertions pin only the guaranteed facts: the stamp is
// always present, and exactly 31 client labels land alongside it.
func TestLabelsJSONStampWinsReservedSlot(t *testing.T) {
	obj := `{"trace_completeness":"{\"v\":1,\"c\":\"unknown\"}"`
	for i := 0; i < 40; i++ {
		obj += fmt.Sprintf(`,"k%02d":"v%02d"`, i, i)
	}
	obj += `}`
	out := string(labelsJSON(map[string]interface{}{"labels": obj}))

	var stored map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &stored))
	require.Len(t, stored, 32, "31 client labels + the reserved stamp slot")
	require.JSONEq(t, `{"v":1,"c":"unknown"}`, stored[traceStampLabelKey],
		"the stamp must survive a full label set")
}

// TestLabelsJSONStripsInvalidStamp: an uninterpretable stamp is dropped
// from the row and counted on the closed metric place — the row itself
// still lands.
func TestLabelsJSONStripsInvalidStamp(t *testing.T) {
	beforeInvalid := traceStampFailureValue(t, "invalid_value")
	out := string(labelsJSON(map[string]interface{}{"labels": `{"workload":"agent:agent-g1","trace_completeness":"not-a-stamp"}`}))
	require.NotContains(t, out, "trace_completeness")
	require.Contains(t, out, `"workload":"agent:agent-g1"`,
		"only the marker is stripped, not the row's labels")
	require.InDelta(t, beforeInvalid+1, traceStampFailureValue(t, "invalid_value"), 1e-9)

	beforeVersion := traceStampFailureValue(t, "unknown_version")
	out = string(labelsJSON(map[string]interface{}{"labels": `{"trace_completeness":"{\"v\":99,\"c\":\"full\"}"}`}))
	require.NotContains(t, out, "trace_completeness")
	require.InDelta(t, beforeVersion+1, traceStampFailureValue(t, "unknown_version"), 1e-9)
}

// TestLabelsJSONLegacyRowsUnchanged: rows without a stamp behave exactly as
// before the stamp existed (cap at 32, normalization, invalid keys filtered).
func TestLabelsJSONLegacyRowsUnchanged(t *testing.T) {
	out := string(labelsJSON(map[string]interface{}{"labels": `{"1bad":"x","workload":"agent:agent-g1","ci.pipeline":"42"}`}))
	require.NotContains(t, out, "1bad")
	require.Contains(t, out, `"workload":"agent:agent-g1"`)
	require.Contains(t, out, `"ci.pipeline":"42"`)

	empty := string(labelsJSON(map[string]interface{}{"labels": `{}`}))
	require.Equal(t, "{}", empty)
}
