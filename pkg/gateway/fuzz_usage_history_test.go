package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/stretchr/testify/require"
)

func FuzzUsageSettlementFacts(f *testing.F) {
	for i, size := range []uint32{0, 1, 999, 1000, 1001, 2500, 4096, 64000} {
		f.Add(uint8(i), size, int16(i-2))
	}
	f.Fuzz(func(t *testing.T, mode uint8, size uint32, count int16) {
		size &= 0x00ffffff // Keep generated quantities representable on 32-bit hosts.
		// A millisecond of encoded audio per byte under the documented 8 kbit/s bound.
		wantSeconds := math.Ceil(float64(size) / 1000)
		quantity := transcriptionReservationSeconds(int(size))
		require.InDelta(t, wantSeconds, quantity, 0)
		initial := budget.Request{OrgID: "org1", TeamID: "team1", InputBytes: int64(size)}
		demand := withUnitDemand(initial, pricing.UnitPerAudioSecond, quantity)
		want := initial
		want.UnitKind, want.UnitQty = pricing.UnitPerAudioSecond, &wantSeconds
		require.Equal(t, want, demand)
		n := int64(count)
		require.InDelta(t, float64(max(n, 1)), imagesRequestCount(&n), 0)
		require.InDelta(t, 1.0, imagesRequestCount(nil), 0)

		checkDurationFact(t, mode, size)
		checkCatalogFact(t, mode, count)
		checkUsageClassification(t, mode)
		checkLabelContextFacts(t, mode)
	})
}

// checkLabelContextFacts pins the request-label context accessors
// (critical-go wave 2: labels_ctx.go): nil contexts degrade to zero values
// instead of panicking, and the principal-source round trip stores exactly
// what withPrincipalLabelSources put in.
func checkLabelContextFacts(t *testing.T, mode uint8) {
	t.Helper()
	var nilCtx context.Context // nil on purpose: the degradation IS the pinned contract
	p, ok := principalFrom(nilCtx)
	require.False(t, ok)
	require.Empty(t, p.APIKeyID)
	require.Empty(t, labelsFrom(nilCtx))
	require.Nil(t, principalLabelSources(nilCtx))
	var sources []labels.Source
	if mode%2 == 0 {
		sources = []labels.Source{
			{Name: "request", Labels: labels.Set{"workload": "fuzz"}},
			{Name: "api_key", Labels: labels.Set{"team": "t1"}, Locked: true},
		}
	}
	ctx := withPrincipalLabelSources(context.Background(), sources)
	require.Equal(t, sources, principalLabelSources(ctx))
}

func checkDurationFact(t *testing.T, mode uint8, size uint32) {
	t.Helper()
	seconds := float64(size) / 8
	cases := []struct {
		doc  string
		want float64
		ok   bool
	}{
		{fmt.Sprintf(`{"duration":%g}`, seconds), seconds, true},
		{`{"duration":-1}`, 0, false}, {`{}`, 0, false}, {"plain transcript", 0, false},
	}
	tc := cases[int(mode)%len(cases)]
	actual, ok := transcriptionResponseDuration([]byte(tc.doc))
	require.Equal(t, tc.ok, ok)
	require.InDelta(t, tc.want, actual, 0)
}

func checkCatalogFact(t *testing.T, mode uint8, count int16) {
	t.Helper()
	amount := math.Abs(float64(count)) / 1024
	cases := []struct {
		unit, model string
		rate        float64
		ok          bool
	}{
		{"per_image", "demo", amount, true}, {"per_image", "demo", 0, true},
		{"per_character", "demo", amount, false}, {"per_image", "unknown", amount, false},
		{"per_image", "demo", -1, false}, {"per_image", "demo", math.Inf(1), false},
		{"per_image", "demo", math.NaN(), false},
	}
	tc := cases[int(mode)%len(cases)]
	entry := pricing.UnitEntry{Provider: "local", Model: "demo", Unit: tc.unit, Rate: tc.rate}
	gw := &gateway{}
	_, wired := gw.unitPrice("local", "demo", "per_image")
	require.False(t, wired)
	gw.unitPricer = stubUnitPricer{entries: map[string]pricing.UnitEntry{"local:demo": entry}}
	got, ok := gw.unitPrice("local", tc.model, "per_image")
	require.Equal(t, tc.ok, ok)
	if tc.ok {
		require.Equal(t, entry, got)
	} else {
		require.Equal(t, pricing.UnitEntry{}, got)
	}
}

func checkUsageClassification(t *testing.T, mode uint8) {
	t.Helper()
	cases := []struct {
		source, normalized string
		cached, known      bool
		read               int
		base, unit, header string
	}{
		{"", "none", false, false, 0, "no_usage", "priced", ""},
		{"none", "none", false, true, 0, "no_usage", "priced", ""},
		{"provider", "provider", false, false, 3, "unknown_price", "unknown_price", "hit"},
		{"provider", "provider", false, true, 0, "priced", "priced", "miss"},
		{"estimated", "estimated", false, true, 0, "priced", "priced", ""},
		{"", "none", true, false, 0, "cache_hit", "cache_hit", ""},
		{"provider", "provider", true, true, 2, "cache_hit", "cache_hit", "hit"},
	}
	tc := cases[int(mode)%len(cases)]
	require.Equal(t, tc.normalized, usageSourceOrNone(tc.source))
	actual := costStatus(tc.cached, tc.source, tc.known)
	require.Equal(t, tc.base, actual)
	require.Equal(t, tc.base, costStatusUnit(actual, false))
	require.Equal(t, tc.unit, costStatusUnit(actual, true))
	usage := provider.Usage{Source: tc.source, CacheReadTokens: int64(tc.read)}
	buffered := httptest.NewRecorder()
	setPromptCacheHeader(buffered, usage)
	buffered.WriteHeader(http.StatusOK)
	response := buffered.Result()
	t.Cleanup(func() { _ = response.Body.Close() })
	require.Equal(t, tc.header, response.Header.Get("X-Yabanin-Prompt-Cache"))
	stream := httptest.NewRecorder()
	stream.WriteHeader(http.StatusOK)
	setPromptCacheTrailer(stream, usage)
	end := stream.Result()
	t.Cleanup(func() { _ = end.Body.Close() })
	require.Empty(t, end.Header.Get("X-Yabanin-Prompt-Cache"))
	require.Equal(t, tc.header, end.Trailer.Get("X-Yabanin-Prompt-Cache"))
}

func historyJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	require.NoError(t, err)
	return string(b)
}

func FuzzResponseHistoryDelivery(f *testing.F) {
	for mode := uint8(0); mode < 8; mode++ {
		f.Add(mode, uint16(mode*3), "result ☕\nwith quotes \"")
	}
	f.Add(uint8(255), uint16(27), "end of long result")
	// Critical-go wave-2 frozen pin: two delta fragments sharing tool-call
	// index 0 must merge into one recorded call (the accumulator's map-hit
	// arm the single-fragment seeds never take).
	f.Add(uint8(9), uint16(0), "tool call delivered in two delta fragments")
	f.Fuzz(func(t *testing.T, mode uint8, split uint16, text string) {
		// Vary both the content and the SSE transport boundary independently.
		text = strings.ToValidUTF8(text[:min(len(text), 384)], "�")
		require.Empty(t, (*responseHistoryCapture)(nil).wire())
		require.Nil(t, envelopeFromCompletionDoc([]byte(`{"object":"error"}`), "local-model"))
		if mode == 255 {
			checkLongHistory(t, text)
		}
		if mode == 9 {
			checkRepeatedToolDelta(t, text)
			return
		}
		msg, expected := historyExample(t, mode, text)
		choice := map[string]any{"index": 0, "message": msg, "finish_reason": "stop"}
		doc := map[string]any{"choices": []any{choice}}
		if mode&1 != 0 {
			doc["model"] = "local-model"
		}
		got := envelopeFromCompletionDoc([]byte(historyJSON(t, doc)), "local-model")
		checkHistoryWire(t, expected, got.marshal())

		delete(choice, "message")
		choice["delta"] = msg
		doc["model"] = "local-model"
		frames := ": keepalive\r\ndata: not-json\r\ndata: " + historyJSON(t, doc) + "\r\n\r\ndata: [DONE]\n\n"
		cut := int(split) % (len(frames) + 1)
		out := httptest.NewRecorder()
		capture := newResponseHistoryCapture(out)
		for _, part := range []string{frames[:cut], frames[cut:]} {
			n, err := capture.Write([]byte(part))
			require.NoError(t, err)
			require.Equal(t, len(part), n)
		}
		capture.Flush()
		require.True(t, out.Flushed)
		require.True(t, capture.sawDone)
		require.Equal(t, frames, out.Body.String())
		capture.finishEnvelope("complete", "")
		checkHistoryWire(t, expected, capture.wire())
	})
}

func historyExample(t *testing.T, mode uint8, text string) (map[string]any, map[string]any) {
	t.Helper()
	msg := map[string]any{}
	expected := map[string]any{"v": 1, "kind": "model_response", "status": "complete", "model": "local-model", "content": "", "finish_reason": "stop"}
	if mode&1 != 0 {
		msg["content"] = "shown:" + text
		expected["content"] = "shown:" + text
	}
	if mode&2 != 0 {
		msg["reasoning_content"] = "summary:" + text
		expected["reasoning_content"] = "summary:" + text
	}
	if mode&4 != 0 {
		args := historyJSON(t, map[string]string{"note": text})
		msg["tool_calls"] = []any{map[string]any{"id": "id1", "index": 0, "type": "function",
			"function": map[string]any{"name": "demo", "arguments": args}}}
		expected["tool_calls"] = []any{map[string]any{"index": 0, "id": "id1", "name": "demo", "arguments": args}}
	}
	if len(msg) == 0 {
		return msg, nil
	}
	return msg, expected
}

func checkHistoryWire(t *testing.T, expected map[string]any, actual string) {
	t.Helper()
	if expected == nil {
		require.Empty(t, actual)
		return
	}
	require.JSONEq(t, historyJSON(t, expected), actual)
}

func checkLongHistory(t *testing.T, suffix string) {
	t.Helper()
	const storageLimit = 512 * 1024
	prefix := strings.Repeat("a", storageLimit)
	message := map[string]string{"content": prefix + "!" + suffix}
	doc := map[string]any{"choices": []any{map[string]any{"message": message}}}
	got := envelopeFromCompletionDoc([]byte(historyJSON(t, doc)), "long-model")
	require.NotNil(t, got)
	require.Equal(t, prefix, got.Content)
	require.True(t, got.Truncated)
	require.Equal(t, "partial", got.Status)
	require.Equal(t, "capture_limit", got.Reason)

	// A client can receive an entire long stream even when only a prefix
	// or later complete frames fit in the retained history.
	out := httptest.NewRecorder()
	capture := newResponseHistoryCapture(out)
	longFrame := ": " + prefix + strings.Repeat("a", 64*1024) + "\n"
	frame := "data: " + historyJSON(t, map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": "tail:" + suffix}}}}) + "\n\ndata: [DONE]\n"
	for _, part := range []string{longFrame, frame} {
		written, err := capture.Write([]byte(part))
		require.NoError(t, err)
		require.Equal(t, len(part), written)
	}
	require.Equal(t, longFrame+frame, out.Body.String())
	expect := map[string]any{"v": 1, "kind": "model_response", "status": "partial", "content": "tail:" + suffix, "reason": "capture_limit", "truncated": true}
	checkHistoryWire(t, expect, capture.finishEnvelope("complete", "").marshal())
}

// checkRepeatedToolDelta pins the stream accumulator's map-hit arm
// (critical-go wave 2: stream.go streamChoiceAcc.toolCall): two delta
// fragments sharing tool-call index 0 merge into ONE recorded call whose
// arguments are the byte-exact concatenation, with the id and name taken
// from the first fragment.
func checkRepeatedToolDelta(t *testing.T, text string) {
	t.Helper()
	// Keep every fragment a valid JSON string literal: strip the bytes that
	// could put an escape sequence across the split point.
	text = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	args := historyJSON(t, map[string]string{"note": text})
	if len(args) < 4 {
		args = `{"note":"fz"}`
	}
	frame := func(fragment string) string {
		doc := map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{
			"tool_calls": []any{map[string]any{"index": 0, "id": "call_fz9", "type": "function",
				"function": map[string]any{"name": "demo", "arguments": fragment}}},
		}}}}
		return "data: " + historyJSON(t, doc) + "\n\n"
	}
	out := httptest.NewRecorder()
	capture := newResponseHistoryCapture(out)
	cut := max(1, len(args)/2)
	for _, fragment := range []string{args[:cut], args[cut:]} {
		_, err := capture.Write([]byte(frame(fragment)))
		require.NoError(t, err)
	}
	_, err := capture.Write([]byte("data: [DONE]\n\n"))
	require.NoError(t, err)
	require.True(t, capture.sawDone)
	env := capture.finishEnvelope("complete", "")
	require.NotNil(t, env)
	require.Len(t, env.ToolCalls, 1)
	require.Equal(t, "call_fz9", env.ToolCalls[0].ID)
	require.Equal(t, "demo", env.ToolCalls[0].Name)
	require.Equal(t, args, env.ToolCalls[0].Arguments)
}
