package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const goldenChatStreamBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"golden-chat"}],"stream":true}`

// TestReviewPaidChatStreamHTTP is the streaming half of the owner binding
// regression: the terminal [DONE] frame is held while the facts commit —
// a healthy stream releases it only after the durable write, and a failed
// terminal write replaces it with the accounting error frame (never a
// bare success terminator, never a 200-shaped body).
func TestReviewPaidChatStreamHTTP(t *testing.T) {
	const sse = "data: {\"id\":\"s1\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n" +
		"data: {\"id\":\"s1\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	for _, tc := range []struct {
		name     string
		store    *fakeInvocationStore
		wantDone bool
		wantErr  string
	}{
		{"healthy", &fakeInvocationStore{}, true, ""},
		{"terminal write failure", &fakeInvocationStore{factsErr: errors.New("terminal write unavailable")}, false, "accounting_commit_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				printSSEFixture(t, w, sse)
			}))
			defer server.Close()
			gw := goldenChatGateway(t, server.URL)
			gw.invocations = tc.store
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(goldenChatStreamBody))
			goldenIdentity(r)
			rec := httptest.NewRecorder()
			gw.chatCompletions(rec, r)
			require.Equal(t, int32(1), calls.Load())
			require.Len(t, tc.store.admitted, 1)
			require.Equal(t, invocationKindStream, tc.store.admitted[0].Kind)
			if tc.wantErr != "" {
				body := rec.Body.String()
				i := strings.Index(body, `"code":"`+tc.wantErr+`"`)
				require.GreaterOrEqual(t, i, 0, "accounting error frame missing: %s", body)
				// No SUCCESS terminator may precede the failure report:
				// after it, the SSE error contract terminates the stream.
				require.NotContains(t, body[:i], "data: [DONE]",
					"client observed a success terminator before the accounting failure was reported")
				require.Contains(t, body, "NOT safe to retry")
				require.Empty(t, tc.store.facts)
				return
			}
			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"),
				"held terminator must be released after the facts commit: %q", rec.Body.String())
			require.Len(t, tc.store.facts, 1)
			require.Equal(t, tc.store.admitted[0].InvocationID, tc.store.facts[0].InvocationID)
		})
	}
}
