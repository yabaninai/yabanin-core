package cli

// STREAM-02 regressions: the stream-cache accumulator collapsed n>1 choice
// streams to choice 0 ("continue" dropped every non-zero choice), so a cached
// multi-choice completion replayed as a single-choice answer — content the
// client asked for (n=2) silently lost half its answers on the replay path.
// The accumulator now aggregates EVERY choice by index; the single-choice
// document shape is byte-compatible, the FIX-20 budget stays combined across
// choices, and the role-only nil guard covers all choices.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// stream02Frame builds one chat.completion.chunk SSE frame from raw choices JSON.
func stream02Frame(choicesJSON string) []byte {
	return []byte(`data: {"id":"c-mc","created":1700000000,"model":"m-1","choices":[` + choicesJSON + `]}` + "\n\n")
}

func stream02Delta(idx int, role, content string) string {
	d := `{"index":` + strconv.Itoa(idx) + `,"delta":{`
	if role != "" {
		d += `"role":"` + role + `"`
	}
	if content != "" {
		if role != "" {
			d += ","
		}
		d += `"content":"` + content + `"`
	}
	return d + `}}`
}

// stream02Decode decodes one recorded SSE frame into a streamCacheChunk.
func stream02Decode(t *testing.T, f []byte) streamCacheChunk {
	t.Helper()
	var ch streamCacheChunk
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(string(f), "data: "))), &ch))
	return ch
}

// stream02InterleavedFrames is the classic n=2 delta order: choices alternate
// 0,1,0,1 so naive first-choice-only aggregation provably drops interleaved
// halves.
func stream02InterleavedFrames() [][]byte {
	return [][]byte{
		stream02Frame(stream02Delta(0, "assistant", "Hello ")),
		stream02Frame(stream02Delta(1, "assistant", "ola ")),
		stream02Frame(stream02Delta(0, "", "world")),
		stream02Frame(stream02Delta(1, "", "mundo")),
		stream02Frame(`{"index":0,"delta":{},"finish_reason":"stop"}`),
		stream02Frame(`{"index":1,"delta":{},"finish_reason":"length"}`),
	}
}

func TestSTREAM02_MultiChoice_AllChoicesAggregated(t *testing.T) {
	a := &streamCompletionAcc{}
	for _, f := range stream02InterleavedFrames() {
		a.add(stream02Decode(t, f))
	}
	doc := a.document()
	require.NotNil(t, doc, "an n=2 stream with real content must produce a document")

	choices, ok := doc["choices"].([]interface{})
	require.True(t, ok)
	require.Len(t, choices, 2, "both streamed choices must survive aggregation")

	c0 := choices[0].(map[string]interface{})
	c1 := choices[1].(map[string]interface{})
	assert.Equal(t, 0, c0["index"])
	assert.Equal(t, 1, c1["index"])

	m0 := c0["message"].(map[string]interface{})
	m1 := c1["message"].(map[string]interface{})
	assert.Equal(t, "Hello world", m0["content"], "choice 0 deltas concatenated in arrival order")
	assert.Equal(t, "ola mundo", m1["content"], "choice 1 deltas concatenated — not dropped, not merged into choice 0")
	assert.Equal(t, "assistant", m0["role"])
	assert.Equal(t, "assistant", m1["role"])
	assert.Equal(t, "stop", c0["finish_reason"], "per-choice finish reason")
	assert.Equal(t, "length", c1["finish_reason"])
}

func TestSTREAM02_MultiChoice_SingleChoiceShapeUnchanged(t *testing.T) {
	a := &streamCompletionAcc{}
	a.add(stream02Decode(t, stream02Frame(`{"index":0,"delta":{"role":"assistant","content":"hi"}}`)))
	a.add(stream02Decode(t, stream02Frame(`{"index":0,"delta":{},"finish_reason":"stop"}`)))
	a.usage = map[string]interface{}{"total_tokens": 3.0}

	doc := a.document()
	require.NotNil(t, doc)
	// Identity/usage stay top-level; choices stay a 1-element array with the
	// historical field layout — cache consumers see no shape change.
	assert.Equal(t, "c-mc", doc["id"])
	assert.Equal(t, int64(1700000000), doc["created"])
	assert.Equal(t, "m-1", doc["model"])
	assert.Equal(t, "chat.completion", doc["object"])
	assert.Equal(t, map[string]interface{}{"total_tokens": 3.0}, doc["usage"])
	choices := doc["choices"].([]interface{})
	require.Len(t, choices, 1)
	c := choices[0].(map[string]interface{})
	assert.Equal(t, 0, c["index"])
	assert.Equal(t, map[string]interface{}{"role": "assistant", "content": "hi"}, c["message"])
	assert.Equal(t, "stop", c["finish_reason"])
}

func TestSTREAM02_MultiChoice_RoleOnlyStillNil(t *testing.T) {
	a := &streamCompletionAcc{}
	a.add(stream02Decode(t, stream02Frame(`{"index":0,"delta":{"role":"assistant"}}`)))
	a.add(stream02Decode(t, stream02Frame(`{"index":1,"delta":{"role":"assistant"}}`)))
	assert.Nil(t, a.document(),
		"role-only frames on ANY choice must stay a nil document — the P4 empty-answer defect must not return via n>1 streams")
}

func TestSTREAM02_MultiChoice_ToolCallsPerChoice(t *testing.T) {
	a := &streamCompletionAcc{}
	for _, f := range [][]byte{
		stream02Frame(stream02Delta(1, "assistant", "checking")),
		stream02Frame(`{"index":1,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}`),
		stream02Frame(`{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Oslo\"}"}}]}}`),
		stream02Frame(`{"index":1,"delta":{},"finish_reason":"tool_calls"}`),
	} {
		a.add(stream02Decode(t, f))
	}
	doc := a.document()
	require.NotNil(t, doc)
	choices := doc["choices"].([]interface{})
	require.Len(t, choices, 1)
	m := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	calls, ok := m["tool_calls"].([]interface{})
	require.True(t, ok, "tool-call fragments under choice 1 must aggregate into its message")
	require.Len(t, calls, 1)
	fn := calls[0].(map[string]interface{})["function"].(map[string]interface{})
	assert.Equal(t, "get_weather", fn["name"])
	assert.JSONEq(t, `{"city":"Oslo"}`, fn["arguments"].(string))
}

func TestSTREAM02_MultiChoice_BudgetStaysCombined(t *testing.T) {
	// FIX-20 semantics: one budget over the whole capture, shared across
	// choices — not per-choice budgets that multiply the retention ceiling.
	a := &streamCompletionAcc{budget: 10}
	add := func(choicesJSON string) {
		var ch streamCacheChunk
		require.NoError(t, json.Unmarshal([]byte(`{"choices":[`+choicesJSON+`]}`), &ch))
		a.add(ch)
	}
	add(`{"index":0,"delta":{"content":"12345"}}`)
	add(`{"index":1,"delta":{"content":"67890"}}`)
	add(`{"index":0,"delta":{"content":"X"}}`) // 11th byte: refused, truncated latches

	assert.True(t, a.truncated)
	assert.Equal(t, 10, a.charged, "the budget charges the combined bytes of all choices")
	doc := a.document()
	require.NotNil(t, doc, "text that fit the budget stays replayable")
	choices := doc["choices"].([]interface{})
	require.Len(t, choices, 2)
	m0 := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	m1 := choices[1].(map[string]interface{})["message"].(map[string]interface{})
	assert.Equal(t, "12345", m0["content"])
	assert.Equal(t, "67890", m1["content"], "the shared budget refuses further text but keeps what fit")
}

func TestSTREAM02_MultiChoice_CachedDocumentHasBothChoices(t *testing.T) {
	// End-to-end over the real write path: record the interleaved n=2 stream,
	// run the async cache write, read the stored entry back — both choices
	// must be in the cached document (baseline stores choice 0 only).
	up := newRT02Upstream(t)
	gw := streamTestGateway(up.srv.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c

	body := []byte(`{"model":"m","messages":[{"role":"user","content":"stream02-multi"}]}`)
	rec := cache.NewRecordingWriter(httptest.NewRecorder())
	for _, f := range stream02InterleavedFrames() {
		_, err := rec.Write(f)
		require.NoError(t, err)
	}
	r := &streamRun{
		gw:        gw,
		orgID:     "org-a",
		body:      body,
		rec:       rec,
		finalInfo: resolver.ModelInfo{ModelName: "m-1"},
	}
	r.writeStreamCacheAsync(provider.Usage{})

	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond)

	ri := rt05WarmRI(gw, "org-a", "m-1") // H1: the same pinned identity the async write stamped
	hit, err := c.LookupWithResult(context.Background(), ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the multi-choice document must be stored and verifiable")

	var stored map[string]interface{}
	require.NoError(t, json.Unmarshal(hit.Data, &stored))
	choices := stored["choices"].([]interface{})
	require.Len(t, choices, 2, "the cached entry must replay BOTH choices")
	m0 := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	m1 := choices[1].(map[string]interface{})["message"].(map[string]interface{})
	assert.Equal(t, "Hello world", m0["content"])
	assert.Equal(t, "ola mundo", m1["content"])
}
