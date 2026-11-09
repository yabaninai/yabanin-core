package consumer

// N03P1T07: boundary corpus for the loggerd capture parsers — the same
// packet aspects as pkg/gateway/n03p1t07_boundary_corpus_test.go, at the
// offline analytics boundary where a captured response sample is re-parsed
// (extractToolCallNames / extractToolCallInvocations). Pins what survives
// CRLF captures, truncated final frames, non-data lines, the no-space data
// form (documented loss), and cross-frame fragment interleaving.
//
// Stable IDs: N03P1T07-CAP-*.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// n03p1t07ToolFrame renders one SSE tool-call delta frame: the fragment at
// the given provider index carrying name/call-id (first fragment) or an
// arguments extension.
func n03p1t07ToolFrame(idx int, callID, name, args string) string {
	return fmt.Sprintf(`data: {"id":"chatcmpl-cap","choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]}}]}`+"\n\n",
		idx, callID, name, args)
}

func n03p1t07ToolFrameArgsOnly(idx int, args string) string {
	return fmt.Sprintf(`data: {"id":"chatcmpl-cap","choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":%d,"function":{"arguments":%q}}]}}]}`+"\n\n",
		idx, args)
}

// n03p1t07SilentFailures snapshots the audit_ingest_decode tool_frame
// counter (the closed label set panics on unknown pairs, so this pair is
// production-real).
func n03p1t07SilentFailures() float64 {
	return testutil.ToFloat64(metrics.SilentFailuresTotal.WithLabelValues("audit_ingest_decode", "tool_frame"))
}

// TestN03P1T07_CaptureCRLFSample pins CRLF captures: the parsers TrimSpace
// every line, so a \r\n-framed capture yields the same tool facts as an
// LF-framed one (complements the gateway CS-02 normalization pin: CRLF
// reaches the capture either raw or normalized, both parse).
func TestN03P1T07_CaptureCRLFSample(t *testing.T) {
	sample := strings.ReplaceAll(
		n03p1t07ToolFrame(0, "call_1", "read_file", "{\"path\":\"a.txt\"}")+"data: [DONE]\n\n",
		"\n", "\r\n")

	names := extractToolCallNames(sample)
	require.Equal(t, []string{"read_file"}, names)

	invocations := extractToolCallInvocations(sample)
	require.Len(t, invocations, 1)
	assert.Equal(t, "call_1", invocations[0].CallID)
	assert.Equal(t, "read_file", invocations[0].Name)
	assert.JSONEq(t, "{\"path\":\"a.txt\"}", invocations[0].Args)
}

// TestN03P1T07_CaptureTruncatedFinalFrame pins the truncation boundary: a
// final frame cut mid-JSON (connection died mid-write) fails to decode,
// bumps the silent-failure counter, and everything before it still parses —
// nothing is fabricated, the partial prefix is kept.
func TestN03P1T07_CaptureTruncatedFinalFrame(t *testing.T) {
	complete := n03p1t07ToolFrame(0, "call_1", "read_file", "{\"path\":\"a.txt\"}")
	torn := `data: {"id":"chatcmpl-cap","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","function":{"name":"web_search","arguments":"{\"q`
	sample := complete + torn // no newline: the capture died mid-frame

	before := n03p1t07SilentFailures()
	names := extractToolCallNames(sample)
	assert.InDelta(t, float64(1), n03p1t07SilentFailures()-before, 1e-9,
		"the torn frame must register exactly one silent decode failure")
	assert.Equal(t, []string{"read_file"}, names,
		"frames before the truncation still yield their tool name")

	invocations := extractToolCallInvocations(sample)
	require.Len(t, invocations, 1)
	assert.Equal(t, "read_file", invocations[0].Name)
	assert.Equal(t, "call_1", invocations[0].CallID)
}

// TestN03P1T07_CaptureNonDataLinesSkipped pins that comments and non-data
// field lines interleaved into the capture never reach the JSON decoder.
func TestN03P1T07_CaptureNonDataLinesSkipped(t *testing.T) {
	sample := ": keepalive\n" +
		"event: ping\n\n" +
		n03p1t07ToolFrame(0, "call_1", "read_file", "{}") +
		"retry: 2500\n\n" +
		"id: 7\n\n" +
		"data: [DONE]\n\n"

	assert.Equal(t, []string{"read_file"}, extractToolCallNames(sample))
	require.Len(t, extractToolCallInvocations(sample), 1)
}

// TestN03P1T07_CaptureNoSpaceFramesDropped pins the documented loss: the
// capture parsers match the spaced "data: " form only, so SSE-legal
// no-space frames are silently skipped and the sample yields no tool facts.
// Pinned as prior behavior; the parser lives outside the card's entry
// paths, so a widening fix is handed off in the T07 record.
func TestN03P1T07_CaptureNoSpaceFramesDropped(t *testing.T) {
	compact := strings.ReplaceAll(n03p1t07ToolFrame(0, "call_1", "read_file", "{}"), "data: ", "data:")
	require.NotContains(t, compact, "data: ", "fixture precondition")

	assert.Nil(t, extractToolCallNames(compact),
		"no-space frames are silently dropped by the capture parsers")
	assert.Nil(t, extractToolCallInvocations(compact))
}

// TestN03P1T07_CaptureNonSampleInputs pins degenerate sample shapes: a bare
// JSON array (valid JSON, not a completion document), a [DONE]-only
// capture, and an empty sample all yield no tool facts and no counter
// noise.
func TestN03P1T07_CaptureNonSampleInputs(t *testing.T) {
	before := n03p1t07SilentFailures()

	assert.Nil(t, extractToolCallNames("[1,2]"), "a JSON array is not a completion document")
	assert.Nil(t, extractToolCallInvocations("[1,2]"))
	assert.Nil(t, extractToolCallNames("data: [DONE]\n\n"))
	assert.Nil(t, extractToolCallInvocations("data: [DONE]\n\n"))
	assert.Nil(t, extractToolCallNames(""))
	assert.Nil(t, extractToolCallInvocations(""))

	assert.InDelta(t, before, n03p1t07SilentFailures(), 1e-9,
		"degenerate-but-expected shapes must not count as silent decode failures")
}

// TestN03P1T07_CaptureInterleavedFragments pins cross-frame fragment
// reassembly: fragments for two provider indices interleaved across frames
// merge per index, keep first-appearance order, and late call-ids still
// attach.
func TestN03P1T07_CaptureInterleavedFragments(t *testing.T) {
	sample := n03p1t07ToolFrame(0, "", "read_file", "{\"a\"") +
		n03p1t07ToolFrame(1, "", "web_search", "{\"q\"") +
		n03p1t07ToolFrameArgsOnly(0, ":1}") +
		n03p1t07ToolFrame(1, "call_9", "", ":2}") + // call id on a later fragment
		"data: [DONE]\n\n"

	assert.Equal(t, []string{"read_file", "web_search"}, extractToolCallNames(sample),
		"names are distinct and ordered by first appearance")

	invocations := extractToolCallInvocations(sample)
	require.Len(t, invocations, 2)
	assert.Equal(t, 0, invocations[0].Seq)
	assert.Equal(t, "read_file", invocations[0].Name)
	assert.Equal(t, "{\"a\":1}", invocations[0].Args)
	assert.Equal(t, 1, invocations[1].Seq)
	assert.Equal(t, "web_search", invocations[1].Name)
	assert.Equal(t, "call_9", invocations[1].CallID,
		"a call id arriving on a later fragment attaches to its occurrence")
	assert.Equal(t, "{\"q\":2}", invocations[1].Args)
}
