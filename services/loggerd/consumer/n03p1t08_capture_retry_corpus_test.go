package consumer

// N03P1T08: interruption / retry / resume corpus at the loggerd capture
// parsers — the same packet aspects as
// pkg/gateway/n03p1t08_interruption_retry_corpus_test.go, at the offline
// analytics boundary where a captured response sample is re-parsed
// (extractToolCallNames / extractToolCallInvocations). The captures these
// tests feed are exactly what the gateway's drain-failure events carry:
// complete frames up to the interruption point, nothing after.
//
//   - CAP-01 truncated tool arguments: the interruption cut the arguments
//     fragment mid-JSON inside an otherwise decodable frame. The parsers
//     must neither fabricate a call nor lose the completed one — the raw
//     partial arguments string survives as-is, and no torn-frame decode
//     failure is counted (the SSE frame itself decoded fine — distinct from
//     T07 CAP-02's torn final frame).
//   - CAP-02 terminator-blind extraction: a drain-failure capture (no
//     [DONE]) parses to exactly the same tool facts as the same capture
//     would with the terminator appended — interrupted captures are
//     first-class analytics input, not second-class leftovers.
//   - CAP-03 the composite interrupted capture — a completed call, a
//     truncated-arguments call, and a torn final frame in one sample —
//     yields exactly two invocations (one with valid args, one with the raw
//     partial) and exactly one silent decode failure.
//
// Existing coverage cited instead of duplicated: CRLF samples, torn FINAL
// frame decode accounting, no-space data lines, cross-frame fragment
// interleaving with complete frames (N03P1T07-CAP-*); settlement-level
// redelivery dedupe (N06-P04); retention interruption (N02-P06 T08).
//
// Stable IDs: N03P1T08-CAP-*.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n03p1t08CallFrame renders one complete tool-call delta frame.
func n03p1t08CallFrame(idx int, callID, name, args string) string {
	return fmt.Sprintf(`data: {"id":"chatcmpl-t08","choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]}}]}`+"\n\n",
		idx, callID, name, args)
}

// TestN03P1T08_CaptureTruncatedToolArguments: the interrupted capture's last
// decodable frame carries arguments cut mid-JSON ("the upstream died while
// streaming the arguments fragment"). The call is surfaced with its raw
// partial arguments — never fabricated into a valid call, never dropped.
func TestN03P1T08_CaptureTruncatedToolArguments(t *testing.T) {
	complete := n03p1t08CallFrame(0, "call_1", "read_file", `{"path":"a.txt"}`)
	// The arguments STRING is truncated mid-JSON, but the SSE frame itself
	// (and the chunk JSON around it) is complete — the interruption cut the
	// provider's argument bytes, not the transport framing.
	tornArgs := `data: {"id":"chatcmpl-t08","choices":[{"index":0,"delta":{"tool_calls":[` +
		`{"index":1,"id":"call_2","type":"function","function":{"name":"web_search","arguments":"{\"q` +
		`"}}]}}]}` + "\n\n"
	sample := complete + tornArgs

	before := n03p1t07SilentFailures()
	names := extractToolCallNames(sample)
	assert.InDelta(t, float64(0), n03p1t07SilentFailures()-before, 1e-9,
		"both frames decode as SSE+JSON — no silent torn-frame failure may be counted")
	assert.Equal(t, []string{"read_file", "web_search"}, names,
		"both calls are visible — the interruption hides nothing that arrived")

	invocations := extractToolCallInvocations(sample)
	require.Len(t, invocations, 2, "exactly one invocation per arrived call — no fabrication")
	assert.Equal(t, "call_1", invocations[0].CallID)
	assert.JSONEq(t, `{"path":"a.txt"}`, invocations[0].Args)
	assert.Equal(t, "call_2", invocations[1].CallID)
	assert.Equal(t, "web_search", invocations[1].Name)
	assert.Equal(t, `{"q`, invocations[1].Args,
		"the partial arguments survive byte-exactly — the analytics layer records what arrived")
	assert.False(t, json.Valid([]byte(invocations[1].Args)),
		"precondition: the interrupted arguments are genuinely incomplete")
}

// TestN03P1T08_CaptureTerminatorBlindExtraction: the tool facts of a
// drain-failure capture (the connection died before [DONE]) are identical
// to the facts of the same bytes with the terminator appended — the parsers
// must not treat a missing [DONE] as an error or drop the prefix.
func TestN03P1T08_CaptureTerminatorBlindExtraction(t *testing.T) {
	interrupted := n03p1t08CallFrame(0, "call_1", "read_file", `{"path":"a.txt"}`) +
		n03p1t08CallFrame(1, "call_2", "web_search", `{"q":"go testing"}`)

	withDone := interrupted + "data: [DONE]\n\n"

	assert.Equal(t, extractToolCallNames(withDone), extractToolCallNames(interrupted),
		"names are terminator-blind")
	assert.Equal(t, extractToolCallInvocations(withDone), extractToolCallInvocations(interrupted),
		"invocations are terminator-blind — an interrupted capture is first-class input")
	require.Len(t, extractToolCallInvocations(interrupted), 2)
}

// TestN03P1T08_CaptureCompositeInterruptedSample: the realistic drain
// capture — one completed call, one call whose arguments were cut by the
// interruption, and one frame torn mid-write by the transport death.
// Exactly two invocations survive, the torn frame counts exactly one silent
// decode failure, and nothing is fabricated for it.
func TestN03P1T08_CaptureCompositeInterruptedSample(t *testing.T) {
	sample := n03p1t08CallFrame(0, "call_1", "read_file", `{"path":"a.txt"}`) +
		`data: {"id":"chatcmpl-t08","choices":[{"index":0,"delta":{"tool_calls":[` +
		`{"index":1,"id":"call_2","type":"function","function":{"name":"web_search","arguments":"{\"q` +
		`"}}]}}]}` + "\n\n" +
		`data: {"id":"chatcmpl-t08","choices":[{"index":0,"delta":{"tool_calls":[{"index":2` // torn mid-JSON

	before := n03p1t07SilentFailures()
	names := extractToolCallNames(sample)
	assert.InDelta(t, float64(1), n03p1t07SilentFailures()-before, 1e-9,
		"the torn frame registers exactly one silent decode failure")
	assert.Equal(t, []string{"read_file", "web_search"}, names,
		"the completed frames keep their calls — the interruption truncates, never erases")

	invocations := extractToolCallInvocations(sample)
	require.Len(t, invocations, 2, "two arrived calls, two invocations — the torn frame fabricates none")
	assert.JSONEq(t, `{"path":"a.txt"}`, invocations[0].Args)
	assert.Equal(t, `{"q`, invocations[1].Args)
}
