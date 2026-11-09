package cli

// N03-P01-T07: boundary corpus for the packet's three aspects — chunk
// splitting × SSE contract × prior-behavior pins. The corpus exists so every
// named boundary has a stable ID (N03P1T07-…), a committed golden, a
// validator verdict and an analytics observable, and can be re-executed
// without re-deriving expectations. Sibling records this corpus builds on
// (no duplication): T02 terminal watch shapes (stream_terminal_test.go),
// T04 cancel/close exactly-once (stream_cancel_close_test.go), T05 split
// property + late-error wire (stream_chunk_split_test.go,
// stream_late_error_wire_test.go), T06 joint concurrent scenario
// (n03p1t06_joint_scenario_test.go).
//
// Aspect map:
//   - N03P1T07-CS-*  chunk splitting: per-boundary GOLDEN bytes under split
//     compositions for fixtures T05's generic property does not carry
//     (CRLF upstream, field-line frames, no-space frames, usage
//     suppression, multi-byte content, anthropic reference).
//   - N03P1T07-SC-*  SSE contract: whole-stream shapes and their observable
//     errors (empty upstream, data after [DONE], [DONE] in comments or in
//     content, transport reset, anthropic EOF / translate-error / no-space
//     data loss), each pinned with exact client bytes, the
//     pkg/apiformat verdict and exactly one terminal.
//   - N03P1T07-PB-*  prior-behavior pins: the finisher error-frame wordings
//     (I45 honest-unknown, idle, transport interrupt, breaker) as exact
//     byte goldens — previously asserted only via Contains.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// ---------------------------------------------------------------------------
// Shared corpus fixtures
// ---------------------------------------------------------------------------

const (
	n03p1t07ContentFrame = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n"
	n03p1t07DoneFrame    = "data: [DONE]\n\n"
	// n03p1t07UsageFrame is the include_usage trailing chunk (spaced form).
	n03p1t07UsageFrame = "data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}\n\n"
	// n03p1t07NoSpaceUsageFrame is the same chunk in the compact no-space
	// data-line form (SSE-legal, validator-tolerated).
	n03p1t07NoSpaceUsageFrame = "data:{\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}\n\n"
)

// n03p1t07FieldLineFixture exercises non-data SSE field lines (comments,
// event:, id:, retry:) which the openai passthrough must relay verbatim.
func n03p1t07FieldLineFixture() []byte {
	return []byte(": keepalive comment\n" +
		"\n" +
		"event: ping\n" +
		"id: 42\n" +
		"retry: 2500\n" +
		n03p1t07ContentFrame +
		n03p1t07DoneFrame)
}

// n03p1t07AnthropicStart / Delta are minimal Anthropic events (spaced form).
const (
	n03p1t07AnthropicStart = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\"}}\n\n"
	n03p1t07AnthropicDelta = "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
)

// ---------------------------------------------------------------------------
// Rigs
// ---------------------------------------------------------------------------

// n03p1t07Drain drains the fixture through the production relay (same field
// set as drainSplit) but returns the raw outcome instead of requiring
// success, exposes the usage verdict and honors clientWantsUsage so the
// RM-03 suppression path is drivable at the split boundary.
func n03p1t07Drain(t *testing.T, fixture []byte, providerName, model string, cuts []int, clientWantsUsage bool) (string, provider.Usage, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := &streamRun{
		gw:        streamTestGateway("http://corpus-unused.invalid"),
		w:         rec,
		ctx:       context.Background(),
		streamCtx: context.Background(),
		l:         testLogger(),
		body:      []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`),
		sessionID: "sess",
		orgID:     "org",
		taskID:    "task",
		reqID:     "req",
		start:     time.Now(),
		streamResp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(&splitStream{pieces: cutPieces(fixture, cuts)}),
		},
		finalInfo:        resolver.ModelInfo{ModelName: model, Provider: providerName, Enabled: true},
		clientWantsUsage: clientWantsUsage,
	}
	usage, err := r.drain(rec)
	return rec.Body.String(), usage, err
}

// n03p1t07FailReader replays fixed pieces then fails: a deterministic
// mid-stream transport reset at any cut position (the wire-level analogue is
// T05's hijacked connection).
type n03p1t07FailReader struct {
	pieces [][]byte
	i, off int
	err    error
}

func (r *n03p1t07FailReader) Read(p []byte) (int, error) {
	for r.i < len(r.pieces) && r.off == len(r.pieces[r.i]) {
		r.i++
		r.off = 0
	}
	if r.i == len(r.pieces) {
		return 0, r.err
	}
	n := copy(p, r.pieces[r.i][r.off:])
	r.off += n
	return n, nil
}

// n03p1t07CaptureEvents installs an observeEvent capture for the test's
// lifetime and returns a snapshot accessor.
func n03p1t07CaptureEvents(t *testing.T) func() []*eventpub.Event {
	t.Helper()
	var (
		mu     sync.Mutex
		events []*eventpub.Event
	)
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	t.Cleanup(restore)
	return func() []*eventpub.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*eventpub.Event(nil), events...)
	}
}

// n03p1t07ServeStream runs the production serveStream against the test
// gateway (same call shape as the T02 wire tests).
func n03p1t07ServeStream(t *testing.T, gw *gateway, info resolver.ModelInfo, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)
	return rec
}

// n03p1t07SSEUpstream wraps a fixture-writing handler in an httptest server
// answering text/event-stream.
func n03p1t07SSEUpstream(t *testing.T, fixture func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fixture(w)
	}))
}

// n03p1t07ErrorFrame renders the exact terminal error frame the finishers
// emit (pkg/apierrors.SSEErrorFrame + the [DONE] terminator writeSSEError
// appends).
func n03p1t07ErrorFrame(errType, message string) string {
	return string(apierrs.SSEErrorFrame(&apierrs.E{Type: errType, Message: message})) + n03p1t07DoneFrame
}

// ---------------------------------------------------------------------------
// Aspect CS — chunk splitting (golden bytes under split compositions)
// ---------------------------------------------------------------------------

// n03p1t07SplitSeed is corpus-constant (not the T05 fuzz seed): changing it
// changes which random compositions every corpus case runs.
const n03p1t07SplitSeed = 20261026

type n03p1t07Composition struct {
	name string
	cuts []int
}

// n03p1t07Compositions returns the corpus split compositions for a fixture:
// single read, byte-by-byte, every LF boundary (before and after each
// newline — the frame separator is a cut surface), mid-token cuts inside
// every "data:" marker, and seeded random multi-cut compositions. The
// exhaustive exhaustive-sweep ownership stays with T05's property test; the
// corpus pins GOLDEN bytes on representative surfaces.
func n03p1t07Compositions(fixture []byte) []n03p1t07Composition {
	comps := []n03p1t07Composition{{name: "single_read"}}
	all := make([]int, 0, len(fixture)-1)
	for cut := 1; cut < len(fixture); cut++ {
		all = append(all, cut)
	}
	comps = append(comps, n03p1t07Composition{name: "byte_by_byte", cuts: all})

	var lfCuts []int
	for i, b := range fixture {
		if b == '\n' {
			lfCuts = append(lfCuts, i, i+1) // before and after each LF
		}
	}
	comps = append(comps, n03p1t07Composition{name: "lf_boundaries", cuts: lfCuts})

	fixtureStr := string(fixture)
	var tokenCuts []int
	// Walk absolute positions: idx from strings.Index is relative to the
	// current suffix, so slicing fixtureStr by it directly would move the
	// window backward and loop forever.
	for base := 0; ; {
		idx := strings.Index(fixtureStr[base:], "data:")
		if idx < 0 {
			break
		}
		tokenCuts = append(tokenCuts, base+idx+2) // inside the data marker
		base += idx + len("data:")
	}
	comps = append(comps, n03p1t07Composition{name: "data_token_interior", cuts: tokenCuts})

	// Seeded PRNG is intentional: corpus compositions must be deterministic
	// and reproducible, never security-sensitive (G404 false positive here).
	rnd := rand.New(rand.NewSource(n03p1t07SplitSeed)) //nolint:gosec // G404: deterministic corpus compositions, not crypto
	for i := 0; i < 32; i++ {
		k := 2 + rnd.Intn(7)
		seen := make(map[int]struct{}, k)
		cuts := make([]int, 0, k)
		for len(cuts) < k {
			p := 1 + rnd.Intn(len(fixture)-1)
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			cuts = append(cuts, p)
		}
		comps = append(comps, n03p1t07Composition{name: fmt.Sprintf("random_%02d", i), cuts: cuts})
	}
	return comps
}

// TestN03P1T07_ChunkSplitCorpus is aspect CS: every corpus fixture keeps its
// golden bytes, its validator verdict and its single-terminal watch verdict
// under every split composition. OpenAI passthrough goldens are the fixture
// itself (or its documented LF normalization); the anthropic case pins the
// deterministic translation via the unsplit reference.
func TestN03P1T07_ChunkSplitCorpus(t *testing.T) {
	cases := []struct {
		id               string // stable corpus ID
		note             string // why this boundary exists
		provider         string
		model            string
		fixture          func() []byte
		golden           func(fixture []byte) string
		clientWantsUsage bool
		wantUsageSource  string
	}{
		{
			id:               "N03P1T07-CS-01-field-lines-verbatim",
			note:             "comments and event:/id:/retry: field lines relay byte-exact; only data: lines are contract payloads",
			model:            "gpt-4",
			fixture:          func() []byte { return n03p1t07FieldLineFixture() },
			golden:           func(fixture []byte) string { return string(fixture) },
			clientWantsUsage: true,
			wantUsageSource:  provider.UsageSourceEstimated,
		},
		{
			id:    "N03P1T07-CS-02-crlf-normalized-to-lf",
			note:  "CRLF upstream: bufio ScanLines strips the CR, the relay re-writes each line with LF — the documented normalization, still validator-clean",
			model: "gpt-4",
			fixture: func() []byte {
				return []byte(strings.ReplaceAll(n03p1t07ContentFrame+n03p1t07UsageFrame+n03p1t07DoneFrame, "\n", "\r\n"))
			},
			golden:           func([]byte) string { return n03p1t07ContentFrame + n03p1t07UsageFrame + n03p1t07DoneFrame },
			clientWantsUsage: true,
			wantUsageSource:  provider.UsageSourceProvider,
		},
		{
			id:    "N03P1T07-CS-03-no-space-frames",
			note:  "no-space data lines (SSE-legal, validator-tolerated) relay byte-exact and the compact [DONE] still marks the terminal (T02 watch pin, drain level)",
			model: "gpt-4",
			fixture: func() []byte {
				return []byte(strings.ReplaceAll(n03p1t07ContentFrame, "data: ", "data:") +
					strings.ReplaceAll(n03p1t07DoneFrame, "data: ", "data:"))
			},
			golden:           func(fixture []byte) string { return string(fixture) },
			clientWantsUsage: true,
			wantUsageSource:  provider.UsageSourceEstimated,
		},
		{
			id:               "N03P1T07-CS-04-usage-suppression-under-splits",
			note:             "RM-03: with include_usage injected (client did not ask), the usage-only chunk and its blank separator are suppressed while usage is still parsed — at any split",
			model:            "gpt-4",
			fixture:          func() []byte { return []byte(n03p1t07ContentFrame + n03p1t07UsageFrame + n03p1t07DoneFrame) },
			golden:           func([]byte) string { return n03p1t07ContentFrame + n03p1t07DoneFrame },
			clientWantsUsage: false,
			wantUsageSource:  provider.UsageSourceProvider,
		},
		{
			id:               "N03P1T07-CS-05-no-space-usage-chunk-not-suppressed",
			note:             "the suppression and usage parsers match the spaced \"data: \" form only: a no-space usage chunk is relayed verbatim and usage falls back to estimated — documented accuracy boundary",
			model:            "gpt-4",
			fixture:          func() []byte { return []byte(n03p1t07ContentFrame + n03p1t07NoSpaceUsageFrame + n03p1t07DoneFrame) },
			golden:           func(fixture []byte) string { return string(fixture) },
			clientWantsUsage: false,
			wantUsageSource:  provider.UsageSourceEstimated,
		},
		{
			id:               "N03P1T07-CS-06-anthropic-translation-reference",
			note:             "anthropic translation is deterministic under any split: corpus goldens via the unsplit reference (cross-check of the T05 property with per-case goldens)",
			provider:         "anthropic",
			model:            "claude-3",
			fixture:          func() []byte { return anthropicSplitFixture() },
			golden:           nil, // resolved to the unsplit reference in the driver
			clientWantsUsage: true,
			wantUsageSource:  provider.UsageSourceProvider,
		},
		{
			id:    "N03P1T07-CS-07-multibyte-content",
			note:  "multi-byte (Cyrillic + emoji) content survives every split byte-exact; the validator's UTF-8 check covers torn-rune reassembly",
			model: "gpt-4",
			fixture: func() []byte {
				frame := strings.Replace(n03p1t07ContentFrame, "ok", "Привет 🌍", 1)
				return []byte(frame + n03p1t07DoneFrame)
			},
			golden:           func(fixture []byte) string { return string(fixture) },
			clientWantsUsage: true,
			wantUsageSource:  provider.UsageSourceEstimated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			fixture := tc.fixture()
			golden := ""
			if tc.golden != nil {
				golden = tc.golden(fixture)
			} else {
				ref, _, err := n03p1t07Drain(t, fixture, tc.provider, tc.model, nil, tc.clientWantsUsage)
				require.NoError(t, err)
				golden = ref
			}

			for _, comp := range n03p1t07Compositions(fixture) {
				t.Run(comp.name, func(t *testing.T) {
					out, usage, err := n03p1t07Drain(t, fixture, tc.provider, tc.model, comp.cuts, tc.clientWantsUsage)
					require.NoError(t, err, "composition %v: a healthy fixture must drain cleanly", comp.cuts)
					require.Equal(t, golden, out, "composition %v must deliver the corpus golden", comp.cuts)
					require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")),
						"composition %v: the delivered stream must validate", comp.cuts)
					assert.Equal(t, tc.wantUsageSource, usage.Source,
						"composition %v: usage source must match the corpus verdict", comp.cuts)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Aspect SC — SSE contract shapes, observable errors, single terminal
// ---------------------------------------------------------------------------

// TestN03P1T07_TerminalShapeCorpus is aspect SC over the production
// serveStream (wire level, single-shot — split invariance is aspect CS/T05).
// Every case pins exact client bytes, the pkg/apiformat verdict, exactly one
// gateway terminal and the analytics event.
func TestN03P1T07_TerminalShapeCorpus(t *testing.T) {
	t.Run("N03P1T07-SC-01-done-only-stream", func(t *testing.T) {
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, n03p1t07DoneFrame)
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL),
			resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			streamBody(t, "gpt-4", "hi"))

		assert.Equal(t, n03p1t07DoneFrame, rec.Body.String(),
			"the minimal stream is the lone terminator, byte-exact")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.completed", evs[0].EventType)
	})

	t.Run("N03P1T07-SC-02-empty-upstream-is-an-honest-failure", func(t *testing.T) {
		// A 200 upstream that closes with ZERO bytes. H3 supersession of the
		// prior "relay adds nothing, analytics completes cleanly" pin: an EOF
		// without [DONE] is an incomplete run — the (empty) prefix is kept
		// byte-faithful and the drain-failure terminal (error frame + [DONE])
		// closes the stream; analytics records request.failed. The old pin
		// codified exactly the silently-completed-truncation defect H3 closes.
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL),
			resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			streamBody(t, "gpt-4", "hi"))

		assert.Equal(t, n03p1t07ErrorFrame(apierrors.ErrorCodeAPI, "stream interrupted"), rec.Body.String(),
			"an empty upstream leaves no prefix: the failure terminal is the whole body")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")),
			"an error-terminated stream must still validate")
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.failed", evs[0].EventType)
	})

	t.Run("N03P1T07-SC-03-upstream-data-after-done-relayed-faithfully", func(t *testing.T) {
		// The upstream violates SSE-OpenAI contract (frames after [DONE]).
		// The relay is byte-faithful: it forwards everything and adds no
		// second terminal of its own — the oracle, not the relay, rejects.
		late := strings.Replace(n03p1t07ContentFrame, "\"1\"", "\"3\"", 1)
		fixture := n03p1t07ContentFrame + n03p1t07DoneFrame + late
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, fixture)
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL),
			resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			streamBody(t, "gpt-4", "hi"))

		assert.Equal(t, fixture, rec.Body.String(), "upstream bytes must relay verbatim, violation included")
		assert.Equal(t, 1, strings.Count(rec.Body.String(), n03p1t07DoneFrame),
			"exactly one terminator: the upstream's own, nothing appended")
		require.ErrorContains(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")),
			"data after [DONE]")
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.completed", evs[0].EventType,
			"the drain itself did not fail — the violation is the upstream's")
	})

	t.Run("N03P1T07-SC-04-done-inside-comment-not-a-terminator", func(t *testing.T) {
		fixture := n03p1t07ContentFrame + ": [DONE]\n\n" +
			strings.Replace(n03p1t07ContentFrame, "\"1\"", "\"2\"", 1) + n03p1t07DoneFrame
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, fixture)
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL),
			resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			streamBody(t, "gpt-4", "hi"))

		assert.Equal(t, fixture, rec.Body.String(), "comment lines relay byte-exact")
		assert.Equal(t, 1, strings.Count(rec.Body.String(), n03p1t07DoneFrame),
			"only the real terminator counts; the comment mention must not terminate")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.completed", evs[0].EventType)
	})

	t.Run("N03P1T07-SC-05-done-mention-in-content-no-terminal", func(t *testing.T) {
		// Drain-level complement of the T02 watch pins: a content delta that
		// merely mentions the terminator never marks delivery.
		content := strings.Replace(n03p1t07ContentFrame, "ok", "say data: [DONE] to stop", 1)
		fixture := content + n03p1t07DoneFrame
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, fixture)
		})
		defer srv.Close()

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL),
			resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			streamBody(t, "gpt-4", "hi"))

		assert.Equal(t, fixture, rec.Body.String())
		assert.Equal(t, 1, strings.Count(rec.Body.String(), n03p1t07DoneFrame))
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))
	})

	t.Run("N03P1T07-SC-06-mid-stream-transport-reset", func(t *testing.T) {
		// Deterministic transport reset (erroring reader, drain level — the
		// wire analogue is T05's hijack test): the failure lands BEFORE any
		// terminator, so the finisher must emit the transport error frame
		// («stream interrupted») followed by exactly one [DONE], and the
		// failure surfaces as request.failed.
		events := n03p1t07CaptureEvents(t)

		rec := httptest.NewRecorder()
		r := &streamRun{
			gw:        streamTestGateway("http://corpus-unused.invalid"),
			w:         rec,
			ctx:       context.Background(),
			streamCtx: context.Background(),
			l:         testLogger(),
			body:      []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`),
			sessionID: "sess",
			orgID:     "org",
			taskID:    "task",
			reqID:     "req",
			start:     time.Now(),
			streamResp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(&n03p1t07FailReader{
					pieces: cutPieces([]byte(n03p1t07ContentFrame), nil),
					err:    errors.New("connection reset by peer"),
				}),
			},
			finalInfo:        resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true},
			clientWantsUsage: true,
		}

		usage, drainErr := r.drain(rec)
		require.Error(t, drainErr, "the reset must surface as a drain error")
		require.ErrorContains(t, drainErr, "stream read failed")
		r.finishDrainFailure(usage, drainErr, 0, false)

		want := n03p1t07ContentFrame + n03p1t07ErrorFrame(apierrors.ErrorCodeAPI, "stream interrupted")
		assert.Equal(t, want, rec.Body.String(),
			"the prefix reaches the client, then the exact transport error frame + one [DONE]")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")),
			"an error-terminated stream must still validate")
		assert.False(t, r.clientSawDone)
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.failed", evs[0].EventType)
		require.ErrorContains(t, errors.New(evs[0].Error), "stream drain failed")
		assert.Equal(t, provider.UsageSourceEstimated, usage.Source,
			"consumed-prefix usage is the contract estimate, not zero")
	})
}

// TestN03P1T07_AnthropicContractCorpus is aspect SC for the translating
// handler: clean-EOF fabrication, translate-error surfacing and the no-space
// data-line drop, each with exact client bytes and the oracle verdict.
func TestN03P1T07_AnthropicContractCorpus(t *testing.T) {
	info := resolver.ModelInfo{ModelName: "claude-3", Provider: "anthropic", Enabled: true}

	t.Run("N03P1T07-SC-07-anthropic-eof-without-message-stop", func(t *testing.T) {
		// Clean EOF without message_stop: the translator's writeDone still
		// fires so OpenAI clients terminate cleanly (pkg/provider
		// anthropicStreamHandler — the client-compat half is pinned and
		// unchanged), and since the client already saw the terminator no
		// second error frame is appended. H3: the run itself is now honest —
		// the handler reports the missing message_stop and analytics records
		// request.failed instead of the prior silent clean completion.
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, n03p1t07AnthropicStart+n03p1t07AnthropicDelta)
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL), info, streamBody(t, "claude-3", "hi"))

		out := rec.Body.String()
		assert.True(t, strings.HasSuffix(out, n03p1t07DoneFrame),
			"a fabricated terminator must close the stream, got %q", out)
		assert.Equal(t, 1, strings.Count(out, n03p1t07DoneFrame))
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")))
		// The translated prefix is intact: role chunk, then the content chunk.
		assert.Contains(t, out, `"role":"assistant"`)
		assert.Contains(t, out, `"content":"Hello"`)
		assert.Contains(t, out, "chatcmpl-msg_x", "the chunk id derives from the anthropic message id")
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.failed", evs[0].EventType,
			"H3: an EOF without message_stop is an incomplete run, not a completion")
	})

	t.Run("N03P1T07-SC-08-anthropic-translate-error", func(t *testing.T) {
		// A malformed event payload aborts the drain (translate error): the
		// client gets the translated prefix, then «stream interrupted» + one
		// [DONE]; analytics records the translate failure.
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, n03p1t07AnthropicStart+
				"event: content_block_delta\ndata: {not json}\n\n")
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL), info, streamBody(t, "claude-3", "hi"))

		want := "" // prefix asserted structurally; the tail is exact
		out := rec.Body.String()
		want = n03p1t07ErrorFrame(apierrors.ErrorCodeAPI, "stream interrupted")
		assert.True(t, strings.HasSuffix(out, want),
			"the transport error frame must close the stream, got %q", out)
		assert.Equal(t, 1, strings.Count(out, n03p1t07DoneFrame))
		assert.Contains(t, out, `"role":"assistant"`, "frames translated before the failure reach the client")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")))
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.failed", evs[0].EventType)
		assert.ErrorContains(t, errors.New(evs[0].Error), "translate anthropic event")
	})

	t.Run("N03P1T07-SC-09-anthropic-no-space-lines-dropped", func(t *testing.T) {
		// SSE-legal no-space field lines (`event:X`, `data:{…}`) do not match
		// the handler's spaced prefixes: every event is silently skipped and
		// the fabricated [DONE] closes an EMPTY translation — the content is
		// lost. Pinned as prior behavior; pkg/provider is outside this
		// card's entry paths, so the fix is handed off in the T07 record.
		noSpace := strings.ReplaceAll(n03p1t07AnthropicStart+n03p1t07AnthropicDelta, ": ", ":")
		require.NotContains(t, noSpace, "data: ", "fixture precondition: compact form only")
		srv := n03p1t07SSEUpstream(t, func(w http.ResponseWriter) {
			_, _ = fmt.Fprint(w, noSpace)
		})
		defer srv.Close()
		events := n03p1t07CaptureEvents(t)

		rec := n03p1t07ServeStream(t, streamTestGateway(srv.URL), info, streamBody(t, "claude-3", "hi"))

		assert.Equal(t, n03p1t07DoneFrame, rec.Body.String(),
			"all no-space events are dropped; only the fabricated terminator ships")
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))
		evs := events()
		require.Len(t, evs, 1)
		assert.Equal(t, "request.failed", evs[0].EventType,
			"H3: the silent drop ends without message_stop, so the run reports failed — no more clean-completion-on-content-loss")
	})
}

// ---------------------------------------------------------------------------
// Aspect PB — prior-behavior pins (exact wordings)
// ---------------------------------------------------------------------------

// TestN03P1T07_FinisherErrorFrameWordings is aspect PB: the four stream
// failure wordings previously asserted only via Contains, now pinned as
// exact wire bytes (I45 honest-unknown included). A wording regression is a
// client-visible contract change; the goldens make it reviewable.
func TestN03P1T07_FinisherErrorFrameWordings(t *testing.T) {
	cases := []struct {
		id      string
		errType string
		message string
	}{
		{"N03P1T07-PB-01-connect-unknown-i45", apierrors.ErrorCodeAPI, "upstream outcome unknown; request was not retried"},
		{"N03P1T07-PB-02-idle-timeout", apierrors.ErrorCodeAPI, "upstream stream idle timeout"},
		{"N03P1T07-PB-03-transport-interrupt", apierrors.ErrorCodeAPI, "stream interrupted"},
		{"N03P1T07-PB-04-breaker-unavailable", apierrors.ErrorCodeServiceUnavailable, "upstream provider unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeSSEError(rec, tc.errType, tc.message)
			assert.Equal(t, n03p1t07ErrorFrame(tc.errType, tc.message), rec.Body.String(),
				"the error frame wording is a client-visible contract")
			require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")),
				"an error-terminated stream must validate")
		})
	}
}
