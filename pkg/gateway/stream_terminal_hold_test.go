package cli

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPaidStreamTerminalDelivery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string
	}{
		{"single", []string{"data: [DONE]\n\n"}},
		{"fragmented", []string{"data: [DO", "NE]\n\n"}},
		{"duplicate_in_mixed_write", []string{"data: [DONE]\n\n", ": heartbeat\n\ndata: [DONE]\n\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := httptest.NewRecorder()
			watch := newSSETerminalWatch(client)
			watch.armDoneHold()
			for _, w := range tc.writes {
				_, err := watch.Write([]byte(w))
				require.NoError(t, err)
			}
			require.NotContains(t, client.Body.String(), "data: [DONE]\n\n", "complete SSE success reached client before terminal commit")
			watch.releaseDoneHold()
			require.Equal(t, 1, bytes.Count(client.Body.Bytes(), []byte("data: [DONE]\n\n")))
		})
	}
	t.Run("bounded_hold", func(t *testing.T) {
		watch := newSSETerminalWatch(httptest.NewRecorder())
		watch.armDoneHold()
		_, _ = watch.Write([]byte("data: [DONE]\n\n"))
		for range 256 {
			_, _ = watch.Write(bytes.Repeat([]byte("\n"), 32))
		}
		require.Less(t, len(watch.held), 128, "complete marker needs bounded storage regardless of trailing blank lines")
	})
	t.Run("zero_bytes_failed_delivery", func(t *testing.T) {
		client := &rejectTerminalWriter{httptest.NewRecorder()}
		watch := newSSETerminalWatch(client)
		watch.armDoneHold()
		_, _ = watch.Write([]byte("data: [DONE]\n\n"))
		watch.releaseDoneHold()
		require.False(t, watch.sawDone(), "failed zero-byte write must not mark a client terminal as delivered")
	})
}

type rejectTerminalWriter struct{ *httptest.ResponseRecorder }

func (*rejectTerminalWriter) Write([]byte) (int, error) { return 0, errors.New("closed test client") }

func TestPaidStreamTerminalAtEveryWriteBoundary(t *testing.T) {
	const prefix = "data: {\"choices\":[]}\r\n\r\n"
	for _, marker := range []string{"data: [DONE]\n\n", "data:[DONE]\r\n\r\n", "data: [DONE]\r\r"} {
		wire := prefix + marker
		for split := 0; split <= len(wire); split++ {
			client := httptest.NewRecorder()
			sw := newSSETerminalWatch(client)
			sw.armDoneHold()
			for _, part := range []string{wire[:split], wire[split:]} {
				n, err := sw.Write([]byte(part))
				require.NoError(t, err)
				require.Equal(t, len(part), n)
			}
			require.Equal(t, prefix, client.Body.String(), "split %d of %q", split, marker)
			sw.releaseDoneHold()
			require.True(t, sw.sawDone())
			require.Equal(t, 1, bytes.Count(client.Body.Bytes(), []byte("[DONE]")))
		}
	}
}

func TestPaidStreamOrdinaryFragmentedLines(t *testing.T) {
	const wire = "data: [DONE]ish\n\ndata:  [DONE]\n\n: keep data:[DONE]\r\n\r\ndata: [DO"
	raw := httptest.NewRecorder()
	sw := newSSETerminalWatch(raw)
	sw.armDoneHold()
	for _, b := range []byte(wire) {
		n, err := sw.Write([]byte{b})
		require.NoError(t, err)
		require.Equal(t, 1, n)
	}
	sw.releaseDoneHold()
	require.False(t, sw.sawDone())
	require.Equal(t, wire, raw.Body.String())
}
