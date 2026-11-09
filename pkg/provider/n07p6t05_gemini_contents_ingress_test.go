package provider

// N07-P06-T05 — provider-level pin: a native Gemini `contents` field riding
// an otherwise OpenAI-shaped body must never be interpreted by the
// Vertex/Bedrock adapters (packet negative; owner decisions I50/I51). The
// adapters decode requests through typed projections, so unknown fields are
// dropped, not reinterpreted: TranslateRequest output for a body carrying a
// native `contents` block is byte-identical to the same body without it,
// and neither the adapter-internal envelope nor the translated payload
// contains any trace of the injected block.

import (
	"bytes"
	"strings"
	"testing"
)

const t05OpenAIBase = `{"model":"gemini-2.0-flash-canon","messages":[{"role":"user","content":"hi"}]}`

// t05GeminiContentsInjected = t05OpenAIBase + a native Gemini generateContent
// block appended as unknown JSON fields.
const t05GeminiContentsInjected = `{"model":"gemini-2.0-flash-canon","messages":[{"role":"user","content":"hi"}],` +
	`"contents":[{"role":"user","parts":[{"text":"native-gemini-injection"}]}],` +
	`"generationConfig":{"temperature":0.5}}`

func TestN07P6T05GeminiContentsFieldNeverInterpreted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		adapter   string
		decode    func(t *testing.T, translated []byte) string // inner provider payload
		translate func([]byte) ([]byte, error)
	}{
		{
			name:    "vertex",
			adapter: "vertex",
			translate: func(body []byte) ([]byte, error) {
				return (*Vertex)(nil).TranslateRequest(body)
			},
			decode: func(t *testing.T, translated []byte) string {
				t.Helper()
				env, err := parseVertexEnvelope(translated)
				if err != nil {
					t.Fatalf("parseVertexEnvelope: %v", err)
				}
				return string(env.Gemini)
			},
		},
		{
			name:    "bedrock",
			adapter: "bedrock",
			translate: func(body []byte) ([]byte, error) {
				return (*Bedrock)(nil).TranslateRequest(body)
			},
			decode: func(t *testing.T, translated []byte) string {
				t.Helper()
				env, err := parseBedrockEnvelope(translated)
				if err != nil {
					t.Fatalf("parseBedrockEnvelope: %v", err)
				}
				return string(env.Converse)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := tc.translate([]byte(t05OpenAIBase))
			if err != nil {
				t.Fatalf("%s: TranslateRequest(base): %v", tc.adapter, err)
			}
			injected, err := tc.translate([]byte(t05GeminiContentsInjected))
			if err != nil {
				t.Fatalf("%s: TranslateRequest(injected): %v", tc.adapter, err)
			}

			// Byte-identical translation: the native Gemini fields were
			// dropped by the typed projection, never merged into the
			// provider payload.
			if !bytes.Equal(base, injected) {
				t.Fatalf("%s: TranslateRequest output differs when a native Gemini `contents` block rides the body:\nbase=%s\ninjected=%s",
					tc.adapter, base, injected)
			}

			// Defense in depth: no trace of the injected block's unique
			// payload in the inner provider body. (`contents` and
			// `generationConfig` themselves are legitimate Gemini wire
			// vocabulary — the legitimate translation emits them for plain
			// OpenAI messages — so the byte-identical pin above is the
			// load-bearing assertion, not marker-absence.)
			inner := tc.decode(t, injected)
			if strings.Contains(inner, "native-gemini-injection") {
				t.Fatalf("%s: inner provider payload contains the injected native Gemini text — block was interpreted:\n%s",
					tc.adapter, inner)
			}
		})
	}
}
