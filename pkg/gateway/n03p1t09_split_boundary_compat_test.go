package cli

// N03-P01-T09 «Контракт SSE и границы сообщений: Совместимость потребителей»
// — the any-chunk-split acceptance through the NEW configuration. The
// consumer-compat corpus (n03p1t09_consumer_compat_corpus_test.go) walks the
// real consumers with the upstream emitting whole frames; the drain-level
// split property (stream_chunk_split_test.go) runs without policies; the
// joint scenario (n03p1t06_joint_scenario_test.go) runs the full gateway in
// the old configuration. This file closes the remaining cell: the FULL
// gateway with the policy writer chain active (PolicyModeEnforce +
// stream_prefix), upstream bytes torn at every awkward offset, judged by the
// same contract oracle.
//
// Boundary map:
//   SM-01 hold-to-end prefix policy: any upstream chunk composition (whole,
//         halves, event-boundary and data-line tears, byte-by-byte,
//         fixed-seed random) must deliver the byte-exact consumer wire for
//         the OpenCode-shaped and the Cline-shaped merge-by-index fixtures —
//         valid UTF-8, valid chat stream, exactly one [DONE], last frame.
//   SM-02 immediate-release prefix policy (the threshold fires on the first
//         content frame): the same split property through the mid-stream
//         hold→release→passthrough switch.
//   SM-03 transport death AFTER the complete stream with the hold active:
//         the end-of-stream release stays byte-exact, no second terminal is
//         appended (the terminal watch rides the outermost writer, so the
//         held [DONE] marks the delivery), and the drain failure stays a
//         ledger matter (request.failed, upstream_error, provider usage).
//   SM-04 watchdog abort mid-stream with the hold active: the unflushed gate
//         fail-closes on the dead stream context — the unverified held
//         buffer is dropped, the client sees the canonical idle-abort error
//         frame plus exactly one [DONE].
//   SM-05 deny word torn across the hold boundary: the end-of-stream
//         evaluation joins the buffered prefix and denies — the refusal wire
//         is the canonical abort frame plus one [DONE], zero content bytes.

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// --- split-composition builders -------------------------------------------------

// t09BoundaryCuts cuts between the two LFs of every "\n\n" event boundary and
// right after every "data: " field name, so chunks tear events apart at the
// SSE framing seams.
func t09BoundaryCuts(s string) []int {
	var cuts []int
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], "\n\n"):
			cuts = append(cuts, i+1)
		case strings.HasPrefix(s[i:], "data: "):
			cuts = append(cuts, i+5)
		}
	}
	return cuts
}

// t09EveryByteCuts cuts before every byte: the byte-by-byte composition.
func t09EveryByteCuts(s string) []int {
	cuts := make([]int, 0, len(s)-1)
	for i := 1; i < len(s); i++ {
		cuts = append(cuts, i)
	}
	return cuts
}

// t09RandomCuts draws count distinct deterministic cut positions.
func t09RandomCuts(s string, count int, seed int64) []int {
	rnd := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test sweep, not crypto
	seen := make(map[int]struct{}, count)
	cuts := make([]int, 0, count)
	for len(cuts) < count {
		at := rnd.Intn(len(s))
		if _, dup := seen[at]; dup || at == 0 {
			continue
		}
		seen[at] = struct{}{}
		cuts = append(cuts, at)
	}
	return cuts
}

// t09SplitUpstream serves the fixture torn into the given composition: every
// piece is its own flushed write (its own HTTP chunk), paced pieces make the
// gateway perform separate reads.
func t09SplitUpstream(t *testing.T, fixture string, cuts []int, pace time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, piece := range cutPieces([]byte(fixture), cuts) {
			if _, err := w.Write(piece); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			if pace > 0 {
				time.Sleep(pace)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// t09HijackDeathUpstream serves the fixture torn into the given composition
// over a raw chunked body and then closes the connection WITHOUT the
// terminal zero chunk — a transport death after the complete SSE payload.
func t09HijackDeathUpstream(t *testing.T, fixture string, cuts []int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Raw chunked framing: status head first, then every piece its own
		// body chunk, then the connection dies without the terminal 0-chunk.
		_, _ = fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/event-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n")
		for _, piece := range cutPieces([]byte(fixture), cuts) {
			_, _ = fmt.Fprintf(rw, "%x\r\n%s\r\n", len(piece), piece)
		}
		_ = rw.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- SM-01/SM-02: the any-chunk-split property under the new configuration ------

// TestN03P1T09_SM01_HoldToEnd_AnyChunkSplitByteExact: with a hold-to-end
// stream_prefix policy, every upstream chunk composition — including
// byte-by-byte delivery — yields the byte-exact consumer wire for both the
// OpenCode-shaped content fixture and the Cline-shaped merge-by-index
// fixture. The hold must be invisible: same bytes, same contract, one
// [DONE], last frame.
func TestN03P1T09_SM01_HoldToEnd_AnyChunkSplitByteExact(t *testing.T) {
	frames := []string{
		t09Chunk("sm1", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("sm1", "held prefix один ✓"),
		streamChunkFrame("sm1", " tail два 🌍"),
		t09UsageChunk("sm1"),
	}
	clineFrames := t09ClineFixtureFrames("sm1c")
	fixtures := []struct {
		name   string
		frames []string
		body   string
	}{
		{"opencode-content", frames, streamRequestBody},
		{"cline-merge-by-index", clineFrames, t09ClineRequestBody()},
	}

	for _, fx := range fixtures {
		fixture := t09Wire(fx.frames...)
		compositions := []struct {
			name string
			cuts []int
			pace time.Duration
		}{
			{"whole", nil, 0},
			{"halves", []int{len(fixture) / 2}, 0},
			{"event-boundaries", t09BoundaryCuts(fixture), 0},
			{"byte-by-byte", t09EveryByteCuts(fixture), time.Millisecond},
			{"random-12", t09RandomCuts(fixture, 12, 7), 0},
		}
		for _, comp := range compositions {
			t.Run(fx.name+"/"+comp.name, func(t *testing.T) {
				up := t09SplitUpstream(t, fixture, comp.cuts, comp.pace)
				gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.URL)

				rec := streamPolicyPost(t, gw, fx.body)

				assert.Equal(t, http.StatusOK, rec.code())
				assert.Equal(t, fixture, rec.body(),
					"the consumer wire must be byte-exact under the %s composition", comp.name)
				t09ValidateWire(t, rec.body())
			})
		}
	}
}

// TestN03P1T09_SM02_ReleasedPrefix_AnyChunkSplitByteExact: a prefix policy
// whose token threshold fires on the first content frame switches to
// passthrough mid-stream; the split compositions must stay byte-exact
// through the hold→release→passthrough switch.
func TestN03P1T09_SM02_ReleasedPrefix_AnyChunkSplitByteExact(t *testing.T) {
	frames := []string{
		t09Chunk("sm2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("sm2", "released prefix — passthrough follows"),
		streamChunkFrame("sm2", " tail after release"),
		t09UsageChunk("sm2"),
	}
	fixture := t09Wire(frames...)
	compositions := []struct {
		name string
		cuts []int
		pace time.Duration
	}{
		{"whole", nil, 0},
		{"halves", []int{len(fixture) / 2}, 0},
		{"event-boundaries", t09BoundaryCuts(fixture), 0},
		{"byte-by-byte", t09EveryByteCuts(fixture), time.Millisecond},
		{"random-12", t09RandomCuts(fixture, 12, 11), 0},
	}
	for _, comp := range compositions {
		t.Run(comp.name, func(t *testing.T) {
			up := t09SplitUpstream(t, fixture, comp.cuts, comp.pace)
			gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyPrefixYAML("never-matches-sm2")), up.URL)

			rec := streamPolicyPost(t, gw, streamRequestBody)

			assert.Equal(t, http.StatusOK, rec.code())
			assert.Equal(t, fixture, rec.body(),
				"the consumer wire must be byte-exact under the %s composition through the mid-stream release", comp.name)
			t09ValidateWire(t, rec.body())
		})
	}
}

// --- SM-03: transport death after the complete stream, hold active ---------------

// TestN03P1T09_SM03_TransportDeathAfterDone_HoldReleaseByteExact: the
// upstream delivers the complete stream (torn into pieces) and then dies
// without the terminal chunked-encoding zero block, while the hold-to-end
// policy still buffers everything. The end-of-stream release must hand the
// client the byte-exact stream ending at the held [DONE] — the outermost
// terminal watch marked the delivery during the relay, so the drain failure
// must not append a second terminal — and the ledger records the honest
// failure with the provider usage billed once.
func TestN03P1T09_SM03_TransportDeathAfterDone_HoldReleaseByteExact(t *testing.T) {
	frames := []string{
		t09Chunk("sm3", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("sm3", "fully delivered before the transport died"),
		streamChunkFrame("sm3", " and still held"),
		t09UsageChunk("sm3"),
	}
	fixture := t09Wire(frames...)
	up := t09HijackDeathUpstream(t, fixture, t09BoundaryCuts(fixture))
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, http.StatusOK, rec.code())
	assert.Equal(t, fixture, rec.body(),
		"the held release must be byte-exact even though the transport died after the terminator")
	assert.NotContains(t, rec.body(), `"error"`,
		"a late transport failure after the delivered [DONE] must not append an error frame")
	t09ValidateWire(t, rec.body())

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	ev := failed[0]
	assert.Equal(t, "upstream_error", ev.Termination)
	assert.True(t, strings.HasPrefix(ev.Error, "stream drain failed: "), "got %q", ev.Error)
	assert.Equal(t, "provider", ev.UsageSource, "the usage chunk arrived and is honored once")
	assert.Equal(t, int64(7), ev.TokensIn)
	assert.Equal(t, int64(3), ev.TokensOut)
}

// --- SM-04: watchdog abort mid-stream, hold active --------------------------------

// TestN03P1T09_SM04_WatchdogAbort_HoldFailClose_SingleTerminal: the upstream
// stalls past the idle watchdog while the hold-to-end gate is still
// buffering. The stream context is dead by the time the end-of-stream
// boundary runs, so the unflushed gate fail-closes — the unverified held
// buffer is dropped, never forwarded — and the client sees the canonical
// idle-abort error frame plus exactly one [DONE]: an honest, contract-valid
// termination with no fabricated continuation.
func TestN03P1T09_SM04_WatchdogAbort_HoldFailClose_SingleTerminal(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprint(w, "data: "+streamChunkFrame("sm4", "held-prefix-one")+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = fmt.Fprint(w, "data: "+streamChunkFrame("sm4", " held-prefix-two")+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(400 * time.Millisecond) // stall past the watchdog: no [DONE] ever
	}))
	t.Cleanup(up.Close)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	want := string(apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI, Message: "upstream stream idle timeout"})) +
		"data: [DONE]\n\n"
	assert.Equal(t, want, rec.body(),
		"the wire must be exactly the idle-abort error frame plus one [DONE]")
	assert.NotContains(t, rec.body(), "held-prefix",
		"the unverified held buffer must be dropped on the fail-close, never forwarded")
	assert.Equal(t, 1, strings.Count(rec.body(), "data: [DONE]"), "exactly one terminal frame")
	t09ValidateWire(t, rec.body())

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "upstream stream idle timeout", failed[0].Error)
}

// --- SM-05: deny word torn across the hold boundary --------------------------------

// TestN03P1T09_SM05_DenyWordTornAcrossHold_EndOfStreamDenial: the denied
// word never appears inside one frame — the hold-back boundary tears it —
// and the policy evaluates only at end-of-stream over the joined buffer.
// The evaluation must deny: the refusal wire is the canonical abort frame
// plus one [DONE], zero content bytes, policy_denied on the ledger.
func TestN03P1T09_SM05_DenyWordTornAcrossHold_EndOfStreamDenial(t *testing.T) {
	frames := []string{
		t09Chunk("sm5", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("sm5", "say forbidden-"),
		streamChunkFrame("sm5", "phrase now"),
	}
	fixture := t09Wire(frames...)
	denyHold := strings.Replace(t09HoldYAML(), "t09-never-matches", "forbidden-phrase", 1)
	compositions := []struct {
		name string
		cuts []int
		pace time.Duration
	}{
		{"event-boundaries", t09BoundaryCuts(fixture), 0},
		{"byte-by-byte", t09EveryByteCuts(fixture), time.Millisecond},
	}
	for _, comp := range compositions {
		t.Run(comp.name, func(t *testing.T) {
			up := t09SplitUpstream(t, fixture, comp.cuts, comp.pace)
			gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, denyHold), up.URL)
			events := captureEvents(t)

			rec := streamPolicyPost(t, gw, streamRequestBody)

			assert.Equal(t, http.StatusOK, rec.code())
			assert.Equal(t, string(streaming.AbortFrame("request blocked by organization policy")), rec.body(),
				"the refusal wire must be the canonical abort frame plus one [DONE]")
			assert.NotContains(t, rec.body(), "forbidden-", "no denied content may reach the client")
			t09ValidateWire(t, rec.body())

			failed := t09AwaitEvents(t, events, "request.failed")
			require.Len(t, failed, 1)
			assert.Equal(t, "policy_denied", failed[0].Termination)
		})
	}
}
