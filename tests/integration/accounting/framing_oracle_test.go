//go:build integration

package accounting

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRouteOracleRequiresCompleteTerminal(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n", "\r"} {
		prefix := ": heartbeat" + eol + "event: chunk" + eol + "data: first" + eol + "data:second" + eol + eol
		for _, tail := range []string{"data: [DONE]", "data: [DONE]" + eol} {
			frames, err := parseSSEFrames(prefix + tail)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			require.Equal(t, []sseFrame{{Event: "chunk", Data: "first\nsecond"}}, frames)
		}
		frames, err := parseSSEFrames(prefix + "data:[DONE]" + eol + eol)
		require.NoError(t, err)
		require.Equal(t, []sseFrame{{Event: "chunk", Data: "first\nsecond"}, {Data: "[DONE]"}}, frames)
	}
}

func TestLegacyCompletionStreamFixture(t *testing.T) {
	f := startFixture(t, t.TempDir(), "unit-token")
	t.Cleanup(f.stop)
	s := &stand{gatewayURL: f.baseURL(), apiKey: "unit-token", model: "legacy-model"}
	const rid = "fixture-legacy-stream"
	status, body, err := requestCompletionsSSE(t, s, rid)
	require.NoError(t, err)
	require.Equal(t, 200, status)
	validateCompletionsSSE(t, s, body)
	require.Equal(t, []string{"/v1/completions"}, f.ArrivalPaths(rid))
	a, d, r := f.Counts(rid)
	require.Equal(t, [3]int{1, 1, 1}, [3]int{a, d, r})
	f.VerifyEvidence()
}
