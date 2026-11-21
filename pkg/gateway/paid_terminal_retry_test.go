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

// A client honoring the gateway retry header must not issue a second paid
// request when a 5xx follows a completed provider call.
func TestPaidTerminalErrorSuppressesClientRetry(t *testing.T) {
	for _, surface := range []struct {
		path   string
		body   string
		handle func(*gateway, http.ResponseWriter, *http.Request)
	}{
		{"/v1/chat/completions", goldenChatBody, (*gateway).chatCompletions},
		{"/v1/responses", `{"model":"gpt-4o","input":"retry control"}`, (*gateway).responses},
		{"/v1/messages", `{"model":"gpt-4o","max_tokens":12,"messages":[{"role":"user","content":"retry control"}]}`, (*gateway).messages},
	} {
		t.Run(surface.path, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = w.Write([]byte(goldenChatUsage))
			}))
			defer upstream.Close()
			gw := goldenChatGateway(t, upstream.URL)
			store := &fakeInvocationStore{factsErr: errors.New("terminal write unavailable")}
			gw.invocations = store
			var rec *httptest.ResponseRecorder
			for range 2 {
				rec = httptest.NewRecorder()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, surface.path, strings.NewReader(surface.body))
				goldenIdentity(req)
				req.Header.Set("X-Request-ID", "one-client-operation")
				surface.handle(gw, rec, req)
				require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), "accounting_commit_failed")
				if rec.Result().Header.Get("x-should-retry") == "false" {
					break
				}
			}
			require.EqualValues(t, 1, calls.Load(), "one operation caused repeated paid provider calls")
			require.Len(t, store.admitted, 1)
			require.Equal(t, []string{"false"}, rec.Result().Header.Values("x-should-retry"))
		})
	}
}
