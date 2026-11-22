package cli

import (
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
	"github.com/stretchr/testify/require"
)

// Critical-go wave 3 facts: the SSE prefix-gate rewrite helpers — fused
// [DONE] splitting, chunk identity memory, delta-content ingest, the policy
// prefix parameter resolution and the diff-based replacement carry map.
func TestStreamPolicyRewrite(t *testing.T) {
	for i := range uint8(7) {
		if i < 4 {
			streamPolicyEarlyCase(t, int(i))
			continue
		}
		streamPolicyLateCase(t, int(i))
	}
}

// streamPolicyEarlyCase covers cases 0-3.
func streamPolicyEarlyCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 0:
		// splitFusedTerminator: the plain terminator is not fused; a JSON
		// chunk fused with a trailing [DONE] splits into content + tail.
		term, ok := splitFusedTerminator([]byte("data: [DONE]"))
		require.False(t, ok)
		require.Equal(t, "data: [DONE]", string(term))
		_, ok = splitFusedTerminator([]byte("data:[DONE]"))
		require.False(t, ok)
		frame := []byte("data: {\"i\":1}\n\ndata: [DONE]\n\n")
		term, ok = splitFusedTerminator(frame)
		require.True(t, ok)
		require.Equal(t, "data: [DONE]\n\n", string(term))
		require.Equal(t, "data: {\"i\":1}\n\n", string(frame[:len(frame)-len(term)]))
		spaced := []byte("  data: {\"i\":1}\n\ndata: [DONE]")
		term, ok = splitFusedTerminator(spaced)
		require.True(t, ok)
		require.Equal(t, "data: [DONE]", string(term))
		plain := []byte("data: {\"i\":1}\n\n")
		term, ok = splitFusedTerminator(plain)
		require.False(t, ok)
		require.Equal(t, "data: {\"i\":1}\n\n", string(term))
	case 1:
		// rememberChunkIdentity keeps the last non-empty id/model so the
		// synthetic tail frame stays coherent; non-JSON shapes are ignored.
		pw := &sseStreamPolicyWriter{}
		pw.rememberChunkIdentity([]byte("data: {\"id\":\"c1\",\"created\":1,\"model\":\"m1\",\"choices\":[]}"))
		require.Equal(t, "c1", pw.lastID)
		require.Equal(t, "m1", pw.lastModel)
		pw.rememberChunkIdentity([]byte("data: {\"id\":\"c2\",\"choices\":[]}"))
		require.Equal(t, "c2", pw.lastID)
		require.Equal(t, "m1", pw.lastModel)
		pw.rememberChunkIdentity([]byte("data: {\"choices\":[]}"))
		require.Equal(t, "c2", pw.lastID)
		pw.rememberChunkIdentity([]byte("torn"))
		pw.rememberChunkIdentity([]byte("data: "))
		pw.rememberChunkIdentity([]byte("event: ping"))
		require.Equal(t, "c2", pw.lastID)
		require.Equal(t, "m1", pw.lastModel)
	case 2:
		// frameDeltaContent decodes choices[0].delta.content; every other
		// shape reads as "".
		require.Equal(t, "hi", frameDeltaContent([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}")))
		require.Empty(t, frameDeltaContent([]byte("data: {\"choices\":[{\"delta\":{}}]}")))
		require.Empty(t, frameDeltaContent([]byte("data: {\"choices\":[]}")))
		require.Empty(t, frameDeltaContent([]byte("torn")))
		require.Empty(t, frameDeltaContent([]byte("data: [DONE]")))
		require.Empty(t, frameDeltaContent([]byte("data: {\"choices\":[{\"delta\":{\"content\":5}}]}")))
	case 3:
		// streamPrefixParams: the first step carrying prefix parameters wins;
		// steps without them and empty plan lists fall back to the defaults;
		// invalid parameters are an error, not a silent default.
		plans := []policyPlan{
			{compiled: pipeline.Compiled{Policy: pipeline.Policy{Steps: []pipeline.StepSpec{
				{Params: map[string]any{"unrelated": 1}},
			}}}},
			{compiled: pipeline.Compiled{Policy: pipeline.Policy{Steps: []pipeline.StepSpec{
				{Params: map[string]any{streaming.ParamPrefixTokens: 128, streaming.ParamPrefixDelayMS: 250}},
			}}}},
		}
		tokens, delay, err := streamPrefixParams(plans)
		require.NoError(t, err)
		require.Equal(t, 128, tokens)
		require.Equal(t, 250*time.Millisecond, delay)
		tokens, delay, err = streamPrefixParams(nil)
		require.NoError(t, err)
		require.Equal(t, streaming.DefaultPrefixTokens, tokens)
		require.Equal(t, streaming.DefaultPrefixDelay, delay)
		bad := []policyPlan{{compiled: pipeline.Compiled{Policy: pipeline.Policy{Steps: []pipeline.StepSpec{
			{Params: map[string]any{streaming.ParamPrefixTokens: -1}},
		}}}}}
		tokens, delay, err = streamPrefixParams(bad)
		require.Error(t, err)
		require.Equal(t, streaming.DefaultPrefixTokens, tokens)
		require.Equal(t, streaming.DefaultPrefixDelay, delay)
	default:
		t.Fatalf("unknown early stream-policy case %d", index)
	}
}

// streamPolicyLateCase covers cases 4-6.
func streamPolicyLateCase(t *testing.T, index int) {
	t.Helper()
	switch index {
	case 4:
		// deriveReplacements pairs separated edits individually; degenerate
		// inputs (empty, identical) carry no map.
		require.Nil(t, deriveReplacements("", "x"))
		require.Nil(t, deriveReplacements("same", "same"))
		require.Nil(t, deriveReplacements("abc", ""))
		m := deriveReplacements("Hello SECRET World", "Hello REDACTED World")
		require.Equal(t, map[string]string{"SECRET": "REDACTED"}, m)
		// Edits followed by a >=4 byte shared run pair separately; the last
		// edit (no following run) closes at the end of both texts.
		m = deriveReplacements("AAAA_BBBB_CCCC_DDDD", "AAAA_XXXX_CCCC_YYYY")
		require.Equal(t, map[string]string{"BBBB": "XXXX", "DDDD": "YYYY"}, m)
		// Without a resync run the whole remainder is one edit.
		m = deriveReplacements("aXbYc", "a1b2c")
		require.Equal(t, map[string]string{"XbYc": "1b2c"}, m)
	case 5:
		// commonPrefixLen is the longest shared byte prefix.
		require.Equal(t, 2, commonPrefixLen("abc", "abd"))
		require.Equal(t, 0, commonPrefixLen("", "x"))
		require.Equal(t, 0, commonPrefixLen("x", ""))
		require.Equal(t, 3, commonPrefixLen("xyz", "xyz"))
		require.Equal(t, 1, commonPrefixLen("ab", "a"))
	case 6:
		// editExtent extends an edit start until the texts realign with a
		// resync run, or consumes the whole remainder.
		oe, me := editExtent("aa XX bb", "aa 11 bb", 3, 3, 2)
		require.Equal(t, 5, oe)
		require.Equal(t, 5, me)
		oe, me = editExtent("short", "shorter!", 1, 1, 8)
		require.Equal(t, 5, oe)
		require.Equal(t, 8, me)
		oe, me = editExtent("abc", "xyz", 0, 0, 3)
		require.Equal(t, 3, oe)
		require.Equal(t, 3, me)
	default:
		t.Fatalf("unknown late stream-policy case %d", index)
	}
}
