package cli

// N07-P01-T07 — boundary corpus, wire level (facets 1–3 and the effort
// field, through the full gateway pipeline).
//
// Card action: «Построить boundary corpus для трёх аспектов; проверить
// наблюдаемые ошибки и прежнее поведение». This file pins the end-to-end
// boundaries on the OpenAI-compatible surface and the translated surface:
//   - facet 3: extension values that abuse JSON representations (2^53+1
//     integers, unicode/emoji keys, null values, empty objects) and
//     per-message extensions on every role ride to the upstream verbatim —
//     the pass-through guarantee must hold at value boundaries, not only
//     for benign objects;
//   - facet 1: SSE edge frames (keep-alive comment lines, a stream that
//     ends without [DONE], a mid-stream error frame) pass byte-faithfully,
//     with the exact prior ledger behavior pinned per case;
//   - facets 2 + effort: the translated-surface boundary rejections
//     (tool_choice value space — the T07 fix — plus response_format and
//     effort refusals) render as typed 400s end-to-end, while the same
//     unknown values forward verbatim on the OpenAI-compatible route
//     (upstream-owned validation);
//   - effort: the empty reasoning_effort is indistinguishable from absent.
//
// The adapter-level half of the corpus lives in
// pkg/provider/n07p1t07_boundary_corpus_test.go; the pinned-SDK consumer
// decode boundary lives in sdks/go/compat_joint_boundary_test.go.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n07t07ErrorMessage decodes the gateway's error envelope and returns the
// "type" and "message" joined, so assertions survive JSON escaping on the
// wire.
func n07t07ErrorMessage(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "body: %s", string(body))
	return env.Error.Type + " | " + env.Error.Message
}

// TestN07P1T07_ExtensionBoundaries pushes the extension pass-through to its
// value boundaries: digit-exact big integers (2^53+1 must not collapse to a
// float64), unicode/emoji keys and values, null values, empty objects, and
// per-message extensions on every role — plus an unknown reasoning_effort
// forwarded verbatim (upstream-owned on this route).
func TestN07P1T07_ExtensionBoundaries(t *testing.T) {
	var hits atomic.Int64
	var mu sync.Mutex
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		mu.Lock()
		lastBody = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t07","object":"chat.completion","model":"m","x_provider_ext":{"back":true},"choices":[{"index":0,"message":{"role":"assistant","content":"ок"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()
	gw := compatGateway(t, srv.URL, "openai")

	restore, counts, _ := n07t06CountingEvents(t)
	defer restore()

	body := `{"model":"m",` +
		`"messages":[` +
		`{"role":"system","content":"sys","x_sys":{"n":null}},` +
		`{"role":"assistant","content":"prev","x_prev":{"emoji":"🚀"}},` +
		`{"role":"user","content":"Привет","x_part":{"ключ-🚀":"значение ✓"}}` +
		`],` +
		`"x_big_int":9007199254740993,` +
		`"x_null":null,` +
		`"x_empty":{},` +
		`"reasoning_effort":"ultra"}`
	rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", []byte(body), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	mu.Lock()
	sent := lastBody
	mu.Unlock()
	assert.Contains(t, sent, `"x_big_int":9007199254740993`, "2^53+1 must stay digit-exact (no float64 round-trip): %s", sent)
	assert.Contains(t, sent, `"x_null":null`, "a null extension value must ride verbatim")
	assert.Contains(t, sent, `"x_empty":{}`, "an empty-object extension must ride verbatim")
	assert.Contains(t, sent, `"ключ-🚀":"значение ✓"`, "unicode/emoji keys and values must ride verbatim")
	assert.Contains(t, sent, `"x_sys":{"n":null}`, "per-message extension on the system role must ride")
	assert.Contains(t, sent, `"x_prev":{"emoji":"🚀"}`, "per-message extension on the assistant role must ride")
	assert.Contains(t, sent, `"x_part":{"ключ-🚀":"значение ✓"}`, "per-message extension on the user role must ride")
	assert.Contains(t, sent, `"reasoning_effort":"ultra"`, "an unmapped effort value forwards verbatim on this route")

	out := rec.Body.String()
	assert.Contains(t, out, `"x_provider_ext":{"back":true}`, "response extensions ride back to the client")
	assert.Contains(t, out, `"ок"`)
	c := counts()
	assert.Equal(t, 1, c["request.completed"], "one ledger event for the boundary turn: %v", c)
	assert.EqualValues(t, 1, hits.Load())
}

// TestN07P1T07_SSEBoundaries pins the stream-edge frames byte-faithfully:
// keep-alive comment lines, a stream that ends without [DONE] (H3: the
// delivered bytes are kept and the drain-failure terminal closes the run as
// request.failed — no more silent clean completion), and a mid-stream error
// frame followed by [DONE] — the upstream frames are the upstream's
// business.
func TestN07P1T07_SSEBoundaries(t *testing.T) {
	stream := func(t *testing.T, sse string) (string, map[string]int) {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, sse)
		}))
		defer srv.Close()
		gw := compatGateway(t, srv.URL, "openai")
		restore, counts, _ := n07t06CountingEvents(t)
		rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
			[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`), true)
		restore()
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return rec.Body.String(), counts()
	}

	t.Run("keep-alive comments ride byte-faithfully", func(t *testing.T) {
		out, c := stream(t, "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\n"+
			": keep-alive\n\n"+
			"data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"b\"}}]}\n\n"+
			"data: [DONE]\n\n")
		assert.Contains(t, out, ": keep-alive\n\n", "comment lines are part of the stream bytes")
		assert.Contains(t, out, `"content":"a"`)
		assert.Contains(t, out, `"content":"b"`)
		assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]"))
		assert.Equal(t, 1, c["request.completed"], "comment lines do not disturb the ledger: %v", c)
	})

	t.Run("stream without [DONE] ends as an honest failure", func(t *testing.T) {
		sse := "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"до свидания\"}}]}\n\n"
		out, c := stream(t, sse)
		assert.True(t, strings.HasPrefix(out, sse),
			"the delivered bytes stay verbatim (no rewrite), got %q", out)
		assert.Contains(t, out, `"error"`, "H3: EOF without [DONE] is an incomplete run — the client is told")
		assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]"),
			"the failure terminal closes the stream")
		assert.Equal(t, 1, c["request.failed"], "H3 supersession: the ledger reports the incomplete run: %v", c)
		assert.Zero(t, c["request.completed"], "no clean completion for a stream without its terminator: %v", c)
	})

	t.Run("mid-stream error frame rides verbatim", func(t *testing.T) {
		out, c := stream(t, "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"+
			"data: {\"error\":{\"message\":\"upstream blew up mid-stream\",\"type\":\"server_error\"}}\n\n"+
			"data: [DONE]\n\n")
		assert.Contains(t, out, `"error":{"message":"upstream blew up mid-stream","type":"server_error"}`,
			"the error frame is the upstream's business — byte-faithful")
		assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]"))
		assert.Equal(t, 1, c["request.completed"], "prior behavior: one ledger event, upstream frames are not gateway failures: %v", c)
	})
}

// TestN07P1T07_TranslatedBoundaryRejections walks the translated-surface
// boundary values end-to-end (the T07 tool_choice fix plus the T03/T05
// refusal families): every unmapped modeled-field value renders a typed
// 400 with the exact reason, dials nothing and events nothing, while the
// same values on the OpenAI-compatible route forward verbatim and the
// empty effort boundary passes as absent.
func TestN07P1T07_TranslatedBoundaryRejections(t *testing.T) {
	var hits atomic.Int64
	anth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_t07","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"ок"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer anth.Close()
	gw := compatGateway(t, anth.URL, "anthropic")

	restore, counts, _ := n07t06CountingEvents(t)
	defer restore()

	const tools = `"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],`

	// tool_choice boundaries — the T07 fix, end-to-end (was: silent drop).
	for _, choice := range []struct {
		value string
		want  string
	}{
		{`"banana"`, `unsupported tool_choice "banana"`},
		{`"missing_fn"`, `unsupported tool_choice "missing_fn"`},
		{`{"type":"function"}`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`{"type":"function","function":{}}`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
		{`42`, `tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`},
	} {
		body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],` + tools + `"tool_choice":` + choice.value + `}`)
		rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", body, true)
		if !assert.Equal(t, http.StatusBadRequest, rec.Code, "tool_choice %s must reject", choice.value) {
			continue
		}
		msg := n07t07ErrorMessage(t, rec.Body.Bytes())
		assert.Contains(t, msg, "invalid_request_error", "tool_choice %s", choice.value)
		assert.Contains(t, msg, choice.want, "the exact boundary reason must reach the client")
	}

	// response_format boundary (T03 family): an unknown type rejects with
	// the field and value named.
	rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"banana"}}`), true)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, n07t07ErrorMessage(t, rec.Body.Bytes()), `unsupported response_format type "banana"`)

	// The empty effort boundary passes as absent; the clean turn completes.
	rec = serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":""}`), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"ок"`, "the translated answer must reach the client")

	// Ledger: every rejection produced nothing; only the clean turn events.
	c := counts()
	assert.Equal(t, 1, c["request.completed"], "only the clean turn events: %v", c)
	assert.Zero(t, c["request.failed"], "rejections are escrow-settled locally, never failures: %v", c)
	assert.EqualValues(t, 1, hits.Load(), "the refusals must not dial the upstream; only the clean turn does")

	// Same boundary values on the OpenAI-compatible route: forwarded
	// verbatim, validation owned by the upstream.
	var openHits atomic.Int64
	var mu sync.Mutex
	var lastOpen string
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openHits.Add(1)
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		mu.Lock()
		lastOpen = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t07","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ок"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer open.Close()
	ogw := compatGateway(t, open.URL, "openai")

	rec = serveGateway(t, ogw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],`+tools+`"tool_choice":"banana","response_format":{"type":"banana"}}`), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	mu.Lock()
	sent := lastOpen
	mu.Unlock()
	assert.Contains(t, sent, `"tool_choice":"banana"`, "unmapped values forward verbatim — the upstream owns validation")
	assert.Contains(t, sent, `"response_format":{"type":"banana"}`)
	assert.EqualValues(t, 1, openHits.Load())
}
