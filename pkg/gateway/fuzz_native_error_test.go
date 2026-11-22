package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// A provider error carries no billable usage, even if its body contains a
// usage field. A provider's explicit retry refusal must survive both routes.
func FuzzNativeProviderError(f *testing.F) {
	for _, messages := range []bool{false, true} {
		f.Add(messages, true, true, uint8(0), "busy", uint16(31))
		f.Add(messages, false, true, uint8(1), "capacity", uint16(19))
		f.Add(messages, false, false, uint8(2), "unavailable", uint16(7))
	}
	f.Fuzz(func(t *testing.T, messages, stream, noRetry bool, statusIndex uint8, detail string, tokens uint16) {
		if len(detail) > 512 {
			detail = detail[:512]
		}
		statuses := [...]int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable}
		status := statuses[int(statusIndex)%len(statuses)]
		quoted, err := json.Marshal(detail)
		require.NoError(t, err)
		body := fmt.Sprintf(`{"type":"error","error":{"type":"api_error","message":%s},"usage":{"input_tokens":%d,"output_tokens":%d}}`, quoted, tokens, tokens)
		var contacts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			contacts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Private-Fixture", "internal")
			if noRetry {
				w.Header().Set("X-Should-Retry", "false")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		defer server.Close()

		store := &fakeInvocationStore{}
		capture := &bodyBoundsEvents{}
		var rec *httptest.ResponseRecorder
		if messages {
			gw := bodyBoundsMessagesGateway(t, server.URL, store, capture)
			req := fmt.Sprintf(`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":%t}`, stream)
			rec = postMessages(t, gw, req)
		} else {
			gw := bodyBoundsResponsesGateway(t, server.URL, store, capture)
			rec = postResponses(t, gw, fmt.Sprintf(`{"model":"m","input":"Hi","stream":%t}`, stream))
		}
		require.EqualValues(t, 1, contacts.Load())
		require.Equal(t, status, rec.Code)
		require.Equal(t, body, rec.Body.String())
		require.Empty(t, rec.Header().Get("X-Private-Fixture"))
		wantHint := ""
		if noRetry {
			wantHint = "false"
		}
		require.Equal(t, wantHint, rec.Header().Get("X-Should-Retry"))
		require.Len(t, store.admitted, 1)
		require.Len(t, store.facts, 1)
		fact := store.facts[0]
		require.Equal(t, store.admitted[0].InvocationID, fact.InvocationID)
		require.Equal(t, "request.failed", fact.Fields["event_type"])
		require.Equal(t, strconv.Itoa(status), fact.Fields["status_code"])
		require.Equal(t, "0", fact.Fields["tokens_in"])
		require.Equal(t, "0", fact.Fields["tokens_out"])
	})
}
