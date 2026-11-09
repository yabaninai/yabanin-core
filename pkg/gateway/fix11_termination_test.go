package cli

// AUDIT-2026-10-28 FIX-11 (cards N03-P01-T09 / N03-P03-T09): corrupted SSE
// termination on a malformed upstream. When upstream omits an event's
// blank-line separator — or the terminator's own preceding newline — and
// sends `data: [DONE]` right after an unfinished data event, the
// sseStreamPolicyWriter assembly buffer (which splits only on "\n\n")
// delivers ONE fused frame; the whole-frame isDone check fails and the
// terminal reaches the client buried inside a multi-data-line event:
// no standalone terminator (the success path never re-terminates), and a
// late drain failure appends a second [DONE] after the buried one
// (ValidateChatStream: "data after [DONE]").
//
// The fix honors the embedded terminator: the unfinished head is dropped
// (its bytes never parsed as an event through the gate or the frame
// processor — forwarding them glued or re-framed would feed the client
// truncated JSON and leak unmutated content), the terminal tail is
// delivered standalone, and exactly-one-terminal semantics hold on both the
// success and the drain-failure path.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// fix11MalformedUpstream serves a stream whose final event is malformed: the
// unfinished data event is followed directly by the [DONE] terminator with
// no blank-line separator (glueLastLine) or with the terminator fused into
// the same line (no newline after the partial bytes). stall keeps the
// upstream silent past the idle watchdog after the tail.
func fix11MalformedUpstream(t *testing.T, prefixFrames []string, partialLine string, fuseSameLine bool, stall time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, frame := range prefixFrames {
			_, _ = fmt.Fprint(w, "data: "+frame+"\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}
		// The malformed tail: an unfinished data event (separator missing)
		// glued to the [DONE] terminator.
		if fuseSameLine {
			_, _ = fmt.Fprint(w, partialLine+"data: [DONE]\n\n")
		} else {
			_, _ = fmt.Fprint(w, partialLine+"\ndata: [DONE]\n\n")
		}
		if flusher != nil {
			flusher.Flush()
		}
		if stall > 0 {
			time.Sleep(stall) // real-timeout stall: the drain error must arrive only after the tail was relayed
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFix11_FusedDone_SuccessPathStandaloneTerminal: a malformed upstream
// glues an unfinished data event to the [DONE] terminator (blank separator
// missing). The client must not receive the glued event: the terminal is
// delivered standalone, exactly once, and the client's stream validates.
func TestFix11_FusedDone_SuccessPathStandaloneTerminal(t *testing.T) {
	c2 := streamChunkFrame("c2", "tail")
	up := fix11MalformedUpstream(t,
		[]string{streamChunkFrame("c1", "a")},
		"data: "+c2, false, 0)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML("never-matches")), up.URL)

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	assert.Contains(t, body, `"content":"a"`, "the complete prefix chunk reaches the client")
	assert.NotContains(t, body, `}}]}\ndata: [DONE]`,
		"the unfinished event must not reach the client glued to the terminator")
	assert.NotContains(t, body, "tail",
		"the unfinished event's bytes are dropped, not re-framed")
	assert.Equal(t, 1, strings.Count(body, "[DONE]"), "exactly one terminator, got %q", body)
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"the stream must end at a standalone [DONE], got %q", body)
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the client's stream must validate cleanly")
}

// TestFix11_FusedDone_LateDrainFailureNoSecondTerminal: the same malformed
// tail, then the upstream stalls past the idle watchdog. The delivered
// [DONE] must count as the terminal (no error frame, no second [DONE]
// after it) — the T08 handoff residue: the fused tail used to hide the
// delivery from the terminal watch, so the finisher appended an error
// frame plus a duplicate [DONE] (ValidateChatStream: "data after [DONE]").
func TestFix11_FusedDone_LateDrainFailureNoSecondTerminal(t *testing.T) {
	c2 := streamChunkFrame("c2", "tail")
	up := fix11MalformedUpstream(t,
		[]string{streamChunkFrame("c1", "a")},
		"data: "+c2, false, 400*time.Millisecond)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML("never-matches")), up.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	assert.NotContains(t, body, `}}]}\ndata: [DONE]`,
		"the unfinished event must not reach the client glued to the terminator")
	assert.Equal(t, 1, strings.Count(body, "[DONE]"),
		"exactly one terminator expected, got %q", body)
	assert.NotContains(t, body, `"error"`,
		"a late failure after the delivered [DONE] must not append an error frame")
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the client's stream must validate cleanly")
}

// TestFix11_FusedDone_MutatedStreamNoRawTailLeak: with an active prefix
// pseudonymize policy (FrameProcessor carry-map), the fused unfinished
// event's raw bytes must not reach the client through the processor's
// unparseable-frame passthrough — the head is dropped, the carry tail (if
// any) flushes before the standalone terminal.
func TestFix11_FusedDone_MutatedStreamNoRawTailLeak(t *testing.T) {
	const secret = "super-secret-value"
	up := fix11MalformedUpstream(t,
		[]string{
			`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
			streamChunkFrame("c1", "the "+secret+" in the prefix"),
		},
		`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"raw `+secret+` tail`, false, 0)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.URL)

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	assert.NotContains(t, body, secret, "the raw secret must never reach the client, not even from a malformed tail")
	assert.Contains(t, body, "{{YPP_1}}", "the pseudonym token replaces the secret in the released prefix")
	assert.Equal(t, 1, strings.Count(body, "[DONE]"), "exactly one terminator, got %q", body)
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"the stream must end at a standalone [DONE], got %q", body)
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the client's stream must validate cleanly")
}

// TestFix11_TerminatorBoundaryMatrix drives the sseStreamPolicyWriter
// assembly directly over the FIX-11 boundary matrix. Every fused case must
// deliver the standalone terminator only; every well-formed case —
// including content deltas merely MENTIONING "data: [DONE]" — must pass
// through byte-identical.
func TestFix11_TerminatorBoundaryMatrix(t *testing.T) {
	mentionFrame := "data: {\"choices\":[{\"delta\":{\"content\":\"say data: [DONE] to stop\"}}]}\n\n"
	mentionTailFrame := "data: {\"choices\":[{\"delta\":{\"content\":\"call data: [DONE]\"}}]}\n\n"
	utf8Frame := "data: {\"choices\":[{\"delta\":{\"content\":\"héllo🎉\"}}]}\n\n"
	// Split the UTF-8 frame INSIDE the é rune (after its first byte).
	utf8Cut := strings.Index(utf8Frame, "é")
	require.Positive(t, utf8Cut)

	cases := []struct {
		name    string
		fp      bool // mount an active FrameProcessor (carry map)
		writes  [][]byte
		finish  bool // call finishStream after the writes
		want    string
		wantNot []string
	}{
		{
			name:   "plain terminator unchanged",
			writes: [][]byte{[]byte("data: [DONE]\n\n")},
			want:   "data: [DONE]\n\n",
		},
		{
			name:   "plain no-space terminator unchanged",
			writes: [][]byte{[]byte("data:[DONE]\n\n")},
			want:   "data:[DONE]\n\n",
		},
		{
			name:    "fused: blank separator missing before terminator",
			writes:  [][]byte{[]byte("data: {\"id\":\"c\"}\n"), []byte("data: [DONE]\n\n")},
			want:    "data: [DONE]\n\n",
			wantNot: []string{`{"id":"c"}`},
		},
		{
			name:    "fused: partial line without newline then terminator",
			writes:  [][]byte{[]byte(`data: {"trunc`), []byte("data: [DONE]\n\n")},
			want:    "data: [DONE]\n\n",
			wantNot: []string{"trunc"},
		},
		{
			name:    "fused: complete chunk glued to terminator dropped, terminal honored",
			writes:  [][]byte{[]byte("data: {\"id\":\"c\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\ndata: [DONE]\n\n")},
			want:    "data: [DONE]\n\n",
			wantNot: []string{"ok"},
		},
		{
			name:   "content mention mid-frame passes through byte-identical",
			writes: [][]byte{[]byte(mentionFrame), []byte("data: [DONE]\n\n")},
			want:   mentionFrame + "data: [DONE]\n\n",
		},
		{
			name:   "content ending with mention passes through byte-identical",
			writes: [][]byte{[]byte(mentionTailFrame), []byte("data: [DONE]\n\n")},
			want:   mentionTailFrame + "data: [DONE]\n\n",
		},
		{
			name: "utf-8 rune split across writes stays intact",
			writes: [][]byte{
				[]byte(utf8Frame[:utf8Cut+1]), // inside é
				[]byte(utf8Frame[utf8Cut+1:]),
				[]byte("data: [DONE]\n\n"),
			},
			want: utf8Frame + "data: [DONE]\n\n",
		},
		{
			name:   "empty data event untouched",
			writes: [][]byte{[]byte("data: \n\n"), []byte("data: [DONE]\n\n")},
			want:   "data: \n\ndata: [DONE]\n\n",
		},
		{
			name:   "crlf head line fused, terminal honored",
			writes: [][]byte{[]byte("data: {\"x\":1}\r\n"), []byte("data: [DONE]\n\n")},
			want:   "data: [DONE]\n\n",
		},
		{
			name:    "no-space terminator fused, delivered standalone",
			writes:  [][]byte{[]byte("data: {\"x\":1}\n"), []byte("data:[DONE]\n\n")},
			want:    "data:[DONE]\n\n",
			wantNot: []string{`{"x":1}`},
		},
		{
			name: "fused with active frame processor drops raw head without passthrough leak",
			fp:   true,
			writes: [][]byte{
				[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"a SECRET b\"}}]}\n\n"),
				[]byte(`data: {"trunc SECRET`),
				[]byte("data: [DONE]\n\n"),
			},
			want:    "data: {\"choices\":[{\"delta\":{\"content\":\"a {{YPP_1}} b\"}}]}\n\ndata: [DONE]\n\n",
			wantNot: []string{"SECRET", "trunc"},
		},
		{
			name:   "tail without final separator dropped at finish, no invented terminal",
			writes: [][]byte{[]byte("data: {\"x\":1}\ndata: [DONE]\n")},
			finish: true,
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			pw := &sseStreamPolicyWriter{w: rec, state: &streamPolicyState{}}
			if tc.fp {
				cp, err := streaming.NewChunkProcessor(map[string]string{"SECRET": "{{YPP_1}}"}) //nolint:gosec // G101: fixture placeholder mapping, not a credential
				require.NoError(t, err)
				pw.fp = streaming.NewFrameProcessor(cp)
			}
			for _, p := range tc.writes {
				n, err := pw.Write(p)
				require.NoError(t, err)
				require.Equal(t, len(p), n)
			}
			if tc.finish {
				pw.finishStream()
			}
			assert.Equal(t, tc.want, rec.Body.String())
			for _, not := range tc.wantNot {
				assert.NotContains(t, rec.Body.String(), not)
			}
		})
	}
}
