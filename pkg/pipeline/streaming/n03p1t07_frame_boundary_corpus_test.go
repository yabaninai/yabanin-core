package streaming

// N03P1T07: boundary corpus for the FrameProcessor event parser — the same
// packet aspects as pkg/gateway/n03p1t07_boundary_corpus_test.go, at the
// middleware boundary where one COMPLETE SSE event enters ProcessFrame per
// call. The gateway corpus pins end-to-end drain behavior; this corpus pins
// the event-rewriter contract itself: what survives passthrough byte-exact,
// and what a mutation rebuild does to surrounding whitespace bytes.
//
// Stable IDs: N03P1T07-FR-*.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n03p1t07MutatingProcessor returns a FrameProcessor whose mask rewrites
// every occurrence of the package test secret, and a non-mutating one whose
// map matches nothing.
func n03p1t07MutatingProcessor(t *testing.T) *FrameProcessor {
	t.Helper()
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	require.NoError(t, err)
	return NewFrameProcessor(cp)
}

func n03p1t07PassthroughProcessor(t *testing.T) *FrameProcessor {
	t.Helper()
	cp, err := NewChunkProcessor(map[string]string{"nothing-matches-this": "x"})
	require.NoError(t, err)
	return NewFrameProcessor(cp)
}

// TestN03P1T07_FrameCRLFEvent pins CR-LF event framing: passthrough keeps
// the CRLF bytes byte-exact; a mutation rebuilds only the data LINE (its
// trailing CR is consumed by the JSON re-marshal) while the \r bytes in the
// event terminators survive untouched in the tail.
func TestN03P1T07_FrameCRLFEvent(t *testing.T) {
	crlf := []byte(strings.ReplaceAll(string(chunkFrame(t, "c1", "value is "+testSecretTrigger+" end")), "\n", "\r\n"))
	require.Contains(t, string(crlf), "\r\n\r\n", "fixture precondition")

	t.Run("passthrough_byte_exact", func(t *testing.T) {
		fp := n03p1t07PassthroughProcessor(t)
		assert.Equal(t, crlf, fp.ProcessFrame(crlf),
			"a non-mutating pipeline must not touch a single CR byte")
	})

	t.Run("mutation_rebuilds_line_keeps_tail_crlf", func(t *testing.T) {
		fp := n03p1t07MutatingProcessor(t)
		out := fp.ProcessFrame(crlf)

		content, ok := parseContent(t, out)
		require.True(t, ok)
		assert.Equal(t, "value is "+testSecretMask+" end", content)
		// The CR before the first LF belongs to the data LINE (the payload is
		// `{json}\r`), so the JSON re-marshal consumes it; the rebuilt event
		// ends with the MIXED terminator `\n\r\n` (first LF + second CRLF).
		// That is spec-valid for SSE parsers and validator-tolerated, but a
		// wording change here would be client-visible — hence the exact pin.
		assert.True(t, bytes.HasSuffix(out, []byte("\n\r\n")),
			"the rebuilt CRLF event ends LF + CRLF: %q", out)
		assert.False(t, bytes.HasSuffix(out, []byte("\r\n\r\n")),
			"the line's CR does not survive the re-marshal: %q", out)
		assert.False(t, bytes.Contains(out, []byte("}\r")),
			"the rebuilt data line itself carries no CR: %q", out)
		assert.True(t, bytes.HasPrefix(out, []byte("data: ")))
	})
}

// TestN03P1T07_FrameMultiDataLineEvent pins the first-data-line split: a
// multi-data-line event (never produced by the gateway handlers, but
// SSE-legal) is passed through untouched when non-mutating, and when the
// FIRST line mutates, only that line is rebuilt — the second line keeps its
// bytes AND its unmasked secret (the rewriter parses one payload per event).
func TestN03P1T07_FrameMultiDataLineEvent(t *testing.T) {
	line1 := bytes.TrimSuffix(chunkFrame(t, "m1", "first "+testSecretTrigger), []byte("\n\n"))
	line2 := bytes.TrimSuffix(chunkFrame(t, "m2", "second "+testSecretTrigger), []byte("\n\n"))
	event := append(append(append([]byte{}, line1...), '\n'), append(append([]byte{}, line2...), '\n', '\n')...)

	t.Run("passthrough_byte_exact", func(t *testing.T) {
		fp := n03p1t07PassthroughProcessor(t)
		assert.Equal(t, event, fp.ProcessFrame(event))
	})

	t.Run("mutation_rebuilds_first_line_only", func(t *testing.T) {
		fp := n03p1t07MutatingProcessor(t)
		out := fp.ProcessFrame(event)

		assert.Equal(t, 1, bytes.Count(out, []byte(testSecretMask)),
			"only the first data line's payload is parsed and masked: %q", out)
		assert.Equal(t, 1, bytes.Count(out, []byte(testSecretTrigger)),
			"the second data line keeps its raw bytes, secret included: %q", out)
		assert.True(t, bytes.HasSuffix(out, append(append([]byte{'\n'}, line2...), '\n', '\n')),
			"the second data line must survive byte-exact after the rebuilt first line: %q", out)
		// The rebuilt first line is still a standalone valid JSON payload.
		first := string(out)
		require.True(t, strings.HasPrefix(first, "data: "))
		payloadEnd := strings.Index(first, "\n")
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(first[len("data: "):payloadEnd]), &doc),
			"the rebuilt first data line must remain valid JSON")
	})
}

// TestN03P1T07_FrameNoSpaceDataEvent pins the no-space data form
// (SSE-legal, validator-tolerated): passthrough keeps it compact; a
// mutation normalizes the rebuilt line to the spaced "data: " form.
func TestN03P1T07_FrameNoSpaceDataEvent(t *testing.T) {
	compact := []byte(strings.Replace(string(chunkFrame(t, "n1", "value "+testSecretTrigger)), "data: ", "data:", 1))
	require.NotContains(t, string(compact), "data: ", "fixture precondition: compact form")

	t.Run("passthrough_byte_exact", func(t *testing.T) {
		fp := n03p1t07PassthroughProcessor(t)
		assert.Equal(t, compact, fp.ProcessFrame(compact))
	})

	t.Run("mutation_emits_spaced_form", func(t *testing.T) {
		fp := n03p1t07MutatingProcessor(t)
		out := fp.ProcessFrame(compact)

		assert.True(t, bytes.HasPrefix(out, []byte("data: ")),
			"a rebuilt line is emitted in the spaced form: %q", out)
		content, ok := parseContent(t, out)
		require.True(t, ok)
		assert.Equal(t, "value "+testSecretMask, content)
	})
}

// TestN03P1T07_FrameDoneWithTrailingCR pins the terminator boundary at the
// frame level: "data: [DONE]\r" is NOT the [DONE] payload byte-for-byte, so
// the rewriter passes the event through unchanged in both modes. (The drain
// relay, which normalizes CR per line, does treat it as terminal — the
// two-level asymmetry is intentional and covered on the drain side by T02.)
func TestN03P1T07_FrameDoneWithTrailingCR(t *testing.T) {
	doneCR := []byte("data: [DONE]\r\n\n")

	for _, mode := range []struct {
		name string
		fp   func(t *testing.T) *FrameProcessor
	}{
		{"passthrough", n03p1t07PassthroughProcessor},
		{"mutating", n03p1t07MutatingProcessor},
	} {
		t.Run(mode.name, func(t *testing.T) {
			assert.Equal(t, doneCR, mode.fp(t).ProcessFrame(doneCR),
				"[DONE] with a trailing CR is not rewritten and not consumed as a terminator")
		})
	}
}

// TestN03P1T07_FrameMissingTrailingBlank pins the unterminated-event
// boundary: the rewriter never fabricates an event terminator. A mutating
// rebuild of "data: {…}" (no trailing blank line) stays unterminated — the
// middleware contract feeds complete events.
func TestN03P1T07_FrameMissingTrailingBlank(t *testing.T) {
	open := bytes.TrimSuffix(chunkFrame(t, "u1", "tail "+testSecretTrigger), []byte("\n\n"))
	require.NotContains(t, string(open), "\n", "fixture precondition: no newline at all")

	t.Run("passthrough_byte_exact", func(t *testing.T) {
		fp := n03p1t07PassthroughProcessor(t)
		assert.Equal(t, open, fp.ProcessFrame(open))
	})

	t.Run("mutation_does_not_fabricate_terminator", func(t *testing.T) {
		fp := n03p1t07MutatingProcessor(t)
		out := fp.ProcessFrame(open)

		content, ok := parseContent(t, out)
		require.True(t, ok, "the unterminated event is still parsed as a data frame")
		assert.Equal(t, "tail "+testSecretMask, content)
		assert.False(t, bytes.HasSuffix(out, []byte("\n\n")),
			"the rewriter must not add a terminator the event did not have: %q", out)
	})
}

// TestN03P1T07_FrameEmptyInput pins the zero-length boundary: nil and empty
// input pass through as-is in both modes (no allocation, no panic).
func TestN03P1T07_FrameEmptyInput(t *testing.T) {
	for _, mode := range []struct {
		name string
		fp   func(t *testing.T) *FrameProcessor
	}{
		{"passthrough", n03p1t07PassthroughProcessor},
		{"mutating", n03p1t07MutatingProcessor},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fp := mode.fp(t)
			assert.Nil(t, fp.ProcessFrame(nil))
			assert.Empty(t, fp.ProcessFrame([]byte{}))
		})
	}
}
