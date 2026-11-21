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
