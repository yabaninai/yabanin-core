package cli

// N03-P02-T09 acceptance: consumer compatibility of the exact semantic
// replay — every supported consumer shape (JSON chat completion, SSE stream)
// must receive exactly the bytes of its own shape on replay, in the old and
// the new stream-cache configuration, and unsupported shapes must be
// explicitly refused rather than served cache garbage.
//
// This file pins the two accepted write/serve-side residuals at the unit
// level so any behavior change is a conscious decision, not an accident:
//
//   1. shouldCache (the write-side admission probe) accepts response bodies
//      that do not parse as JSON at all — it only rejects empty bodies and
//      parseable {"error": ...} documents. An upstream that answers 200 with
//      HTML or truncated JSON passes the probe. End-to-end the consumer is
//      still protected (integration corpus): the cache service's provenance
//      seal fails closed on non-JSON bytes, so nothing is written to any
//      layer and the serve-side decode guard has nothing to serve.
//   2. The JSON serve guard and the SSE replay twin disagree on degenerate
//      documents: the JSON guard only requires the document to decode into
//      cachedCompletion, so {} and {"choices":[]} serve a JSON consumer with
//      live parity, while sseReplayFrames explicitly rejects a choices-less
//      document (a stream consumer can never be handed one). The asymmetry
//      is accepted: the JSON response is exactly what the upstream itself
//      served live for that prompt.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/openai"
)

// n03p2t09ValidCompletion is a minimal but complete chat.completion document
// both guards must accept.
func n03p2t09ValidCompletion() string {
	return `{"id":"n03p2t09-unit","object":"chat.completion","model":"n03p2t06-model","choices":[{"index":0,"message":{"role":"assistant","content":"n03t09 unit answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
}

// TestN03P2T09_ShouldCache_WriteSideAdmissionResiduals pins the write-side
// admission table. The residual rows (unparseable bodies admitted) are the
// documented accepted behavior: write-side admission is coarse, and the
// serve-side guards are the consumers' actual protection.
func TestN03P2T09_ShouldCache_WriteSideAdmissionResiduals(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty-body", "", false},
		{"parseable-error-document", `{"error":{"message":"boom","type":"server_error","code":"x"}}`, false},
		{"valid-completion", n03p2t09ValidCompletion(), true},
		{"degenerate-empty-object", `{}`, false},
		{"degenerate-empty-choices", `{"choices":[]}`, false},
		// Residual (re-pinned at batch-B merge per FIX-10 §5 axis C): admission
		// now rejects undecodable/truncated bodies outright (not cached);
		// decodable degenerates ({}, empty choices) are also rejected now (FIX-10 axis C full table).
		{"residual-html-body", "<html>bad gateway</html>", false},
		{"residual-truncated-json", `{"error":{"message":"trunc`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldCache([]byte(tc.body)))
		})
	}
}

// TestN03P2T09_ServeGuardTwinAsymmetry_EmptyChoicesResidual pins the exact
// disagreement between the two serve guards on degenerate documents. The
// JSON guard mirrors the production probe (decode into cachedCompletion);
// the SSE twin is sseReplayFrames itself. Accepted asymmetry: a JSON
// consumer may be handed a choices-less document (parity with what the
// upstream served live), a stream consumer never is.
func TestN03P2T09_ServeGuardTwinAsymmetry_EmptyChoicesResidual(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		jsonDecodable bool
		sseAccepted   bool
	}{
		{"valid-completion", n03p2t09ValidCompletion(), true, true},
		{"degenerate-empty-object", `{}`, true, false},
		{"degenerate-empty-choices", `{"choices":[]}`, true, false},
		{"unparseable-body", "<html>bad gateway</html>", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var probe cachedCompletion
			err := json.Unmarshal([]byte(tc.body), &probe)
			assert.Equal(t, tc.jsonDecodable, err == nil,
				"JSON serve guard (decode into cachedCompletion)")

			_, sseErr := sseReplayFrames([]byte(tc.body))
			assert.Equal(t, tc.sseAccepted, sseErr == nil,
				"SSE replay twin (sseReplayFrames document validation)")
		})
	}
}

// TestN03P2T09_SSETwinRejectsEveryDegenerateShape keeps the stream consumer
// guarantee explicit and future-proof: any document without a usable choices
// array must be refused by the twin, whatever way it is degenerate. H3 moved
// the field boundary: a choice without finish_reason is the truncated-stream
// accumulator shape and is refused too, while a choice that carries its
// terminal still replays with the cosmetic defaults filled (the
// MissingFieldsGetDefaults behavior is pinned in sse_replay_test.go).
func TestN03P2T09_SSETwinRejectsEveryDegenerateShape(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"choices":[]}`,
		`{"choices":null}`,
		`{"object":"chat.completion"}`,
		// H3: finish_reason-less choice = truncated accumulator shape.
		`{"choices":[{"index":0}]}`,
	} {
		_, err := sseReplayFrames([]byte(body))
		require.Error(t, err, "twin must refuse %s", body)
	}

	frames, err := sseReplayFrames([]byte(`{"choices":[{"index":0,"finish_reason":"stop"}]}`))
	require.NoError(t, err, "a present choice with a terminal replays with defaults")
	assert.NotEmpty(t, frames)

	// The openai response document type itself must stay decodable for the
	// replay serve path: a valid completion decodes through the same
	// production document type family the guards work on.
	var doc openai.ChatCompletionResponse
	require.NoError(t, json.Unmarshal([]byte(n03p2t09ValidCompletion()), &doc))
	assert.Len(t, doc.Choices, 1)
}
