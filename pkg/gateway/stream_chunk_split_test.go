package cli

// N03-P01-T05 (review F1, deliverable 2): the chunk-splitting property test.
// A real SSE upstream never guarantees frame-aligned deliveries: proxies,
// TLS records, and kernel buffering split the byte stream at arbitrary
// offsets. Both relay handlers (the OpenAI identity passthrough and the
// Anthropic translator) are line-buffered bufio.Scanner loops, so the
// reassembled client stream must be byte-identical to the unsplit delivery
// for EVERY possible split of the upstream bytes.
//
// The test drives streamRun.drain directly (not through a paced httptest
// server) so each composition is exact: a splitting io.Reader delivers the
// fixture in deterministic pieces with no sleeps or timing races. Cover:
//
//   - the whole fixture in one read (the control),
//   - byte-by-byte delivery (the finest possible split),
//   - every single cut position (exhaustive boundary sweep),
//   - seeded random multi-cut compositions,
//   - a Go fuzz target over cut positions with boundary-focused seeds
//     (go test runs the seeds; go test -fuzz=FuzzDrainChunkSplits explores).
//
// For every composition the drain must deliver byte-identical bytes, mark
// sawDone exactly once via the terminal watch, and produce a stream that
// pkg/apiformat.ValidateChatStream accepts.

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// splitFuzzSeed pins the random composition sweep so failures reproduce.
const splitFuzzSeed = 20261026

// openAISplitFixture is a canonical passthrough stream: distinct content
// frames (so a dropped or duplicated piece cannot alias another), the
// [DONE] terminator, and no usage-only chunk (the relay is a pure copy).
func openAISplitFixture() []byte {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteString(chunkFrame("chatcmpl-split", fmt.Sprintf("tok-%02d ", i)))
	}
	b.WriteString("data: [DONE]\n\n")
	return []byte(b.String())
}

// anthropicSplitFixture is the translating variant: native Anthropic events
// (message_start, content_block_delta, message_delta, message_stop) the
// gateway converts to OpenAI chunks. The translator output is deterministic
// (the chunk id derives from the fixture's message id, no clock fields), so
// every split must reproduce the unsplit translation byte for byte.
func anthropicSplitFixture() []byte {
	return []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_split\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\", split world!\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":4}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n")
}

// splitStream replays data in fixed pieces: each Read returns exactly the
// next piece (or a suffix of it), so the composition's cut positions land
// exactly where the test puts them.
type splitStream struct {
	pieces [][]byte
	i, off int
}

func (s *splitStream) Read(p []byte) (int, error) {
	for s.i < len(s.pieces) && s.off == len(s.pieces[s.i]) {
		s.i++
		s.off = 0
	}
	if s.i == len(s.pieces) {
		return 0, io.EOF
	}
	n := copy(p, s.pieces[s.i][s.off:])
	s.off += n
	return n, nil
}

// cutPieces splits data before every position in cuts. Cut positions are
// deduplicated and bounded to (0, len(data)) so every piece is non-empty —
// a zero-length read is valid io but adds nothing to the property.
func cutPieces(data []byte, cuts []int) [][]byte {
	sorted := append([]int(nil), cuts...)
	sort.Ints(sorted)
	bounds := make([]int, 0, len(sorted)+2)
	bounds = append(bounds, 0)
	for _, c := range sorted {
		if c > 0 && c < len(data) && c != bounds[len(bounds)-1] {
			bounds = append(bounds, c)
		}
	}
	bounds = append(bounds, len(data))
	pieces := make([][]byte, 0, len(bounds)-1)
	for i := 0; i+1 < len(bounds); i++ {
		pieces = append(pieces, data[bounds[i]:bounds[i+1]])
	}
	return pieces
}

// drainSplit drains the fixture through the production relay with the given
// split composition and returns the delivered bytes plus the terminal
// watch's verdict. The pool URL is never dialed: drain consumes only the
// injected response body.
func drainSplit(t *testing.T, fixture []byte, provider, model string, cuts []int) (string, bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := &streamRun{
		gw:        streamTestGateway("http://split-unused.invalid"),
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
		finalInfo:        resolver.ModelInfo{ModelName: model, Provider: provider, Enabled: true},
		clientWantsUsage: true,
	}
	usage, err := r.drain(rec)
	require.NoError(t, err, "a fully delivered fixture must drain without error at any split")
	require.True(t, r.clientSawDone,
		"the [DONE] terminator must reach the client at any split (usage source %q)", usage.Source)
	return rec.Body.String(), r.clientSawDone
}

// TestDrain_AnyChunkSplitDeliversByteIdenticalValidStream is the card's
// acceptance "клиенты читают валидный поток при любом разбиении чанков" at
// the message-frame boundary: every split composition of a valid upstream
// stream yields the byte-identical, validator-clean client stream.
func TestDrain_AnyChunkSplitDeliversByteIdenticalValidStream(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		model    string
		fixture  func() []byte
	}{
		{"openai_passthrough", "", "gpt-4", openAISplitFixture},
		{"anthropic_translated", "anthropic", "claude-3", anthropicSplitFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.fixture()
			reference, _ := drainSplit(t, fixture, tc.provider, tc.model, nil)

			check := func(name string, cuts []int) {
				t.Run(name, func(t *testing.T) {
					out, sawDone := drainSplit(t, fixture, tc.provider, tc.model, cuts)
					require.True(t, sawDone)
					require.Equal(t, reference, out,
						"split composition %v must deliver byte-identical bytes", cuts)
					require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")),
						"the delivered stream must validate at any split")
				})
			}

			check("single_read", nil)
			allCuts := make([]int, 0, len(fixture)-1)
			for cut := 1; cut < len(fixture); cut++ {
				allCuts = append(allCuts, cut)
			}
			check("byte_by_byte", allCuts)

			// Exhaustive single-cut sweep: every boundary is a cut once.
			for cut := 1; cut < len(fixture); cut++ {
				check(fmt.Sprintf("single_cut_%04d", cut), []int{cut})
			}

			// Seeded random multi-cut compositions: 2..12 arbitrary pieces.
			rnd := rand.New(rand.NewSource(splitFuzzSeed)) //nolint:gosec // deterministic test sweep, not crypto
			for i := 0; i < 256; i++ {
				k := 2 + rnd.Intn(11)
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
				sort.Ints(cuts)
				check(fmt.Sprintf("random_%03d", i), cuts)
			}
		})
	}
}

// FuzzDrainChunkSplits is the fuzz counterpart of the property test: the
// fuzz input is the cut-position list, applied to both fixtures. go test
// executes the seed corpus (boundary-focused cuts); -fuzz explores beyond.
func FuzzDrainChunkSplits(f *testing.F) {
	openai := openAISplitFixture()
	anthropic := anthropicSplitFixture()
	f.Add([]byte(nil))                        // single read
	f.Add([]byte{1})                          // cut inside the leading "data: " prefix
	f.Add([]byte{6, 60})                      // cuts inside JSON keys
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7})        // re-slicing the frame start
	f.Add([]byte{90, 91, 92, 93, 94, 95, 96}) // dense cuts inside a content frame
	// The [DONE] tail sits beyond one byte's range, so the fuzz corpus
	// cannot target it directly; the exhaustive single-cut subtest above
	// covers every offset of both fixtures, including the terminator.
	f.Fuzz(func(t *testing.T, rawCuts []byte) {
		if len(rawCuts) > 64 {
			rawCuts = rawCuts[:64] // bound the composition size
		}
		for _, fx := range []struct {
			provider string
			model    string
			data     []byte
		}{
			{"", "gpt-4", openai},
			{"anthropic", "claude-3", anthropic},
		} {
			reference, _ := drainSplit(t, fx.data, fx.provider, fx.model, nil)
			out, sawDone := drainSplit(t, fx.data, fx.provider, fx.model, fuzzCutPositions(rawCuts, len(fx.data)))
			require.True(t, sawDone)
			require.Equal(t, reference, out)
			require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")))
		}
	})
}

// fuzzCutPositions maps fuzz bytes into valid cut positions of data:
// each byte b cuts before index 1+(b % (len-1)); duplicates collapse.
// A single byte value collides across different fixture lengths by design —
// the mapping only needs to be total and deterministic.
func fuzzCutPositions(raw []byte, dataLen int) []int {
	if dataLen <= 1 || len(raw) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(raw))
	cuts := make([]int, 0, len(raw))
	for _, b := range raw {
		p := 1 + int(b)%(dataLen-1)
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		cuts = append(cuts, p)
	}
	sort.Ints(cuts)
	return cuts
}
