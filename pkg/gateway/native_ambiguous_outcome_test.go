package cli

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func TestNativeAcceptedRequestWithoutResponseSuppressesRetry(t *testing.T) {
	runNativeOutcomeCases(t, func(t *testing.T, route string, stream bool) {
		t.Helper()
		var arrivals atomic.Int32
		server := httptest.NewServer(closeAfterNativeRequest(t, &arrivals))
		t.Cleanup(server.Close)

		store := &fakeInvocationStore{}
		capture := &bodyBoundsEvents{}
		rec := postNativeOutcome(t, route, stream, server.URL, store, capture)

		assertNativeGatewayError(t, rec, "false")
		require.EqualValues(t, 1, arrivals.Load(), "server accepted the complete provider request")
		assertNativeAdmissionOnly(t, store, capture)
	})
}

func TestNativeProvenDialFailureRemainsRetryable(t *testing.T) {
	endpoint := closedLoopbackURL(t)
	client, err := upstream.NewClientWithAdapter(upstream.Options{
		BaseURL: endpoint, AllowedUpstreams: []string{endpoint}, ProviderName: "anthropic",
	})
	require.NoError(t, err)
	resp, dialErr := client.Do(t.Context(), "/v1/messages", []byte(`{}`), "", false, nil)
	if resp != nil {
		require.NoError(t, resp.Body.Close())
	}
	require.True(t, retry.DefinitelyNotSent(dialErr), "closed-listener transport error proves no provider request was sent")

	runNativeOutcomeCases(t, func(t *testing.T, route string, stream bool) {
		t.Helper()
		store := &fakeInvocationStore{}
		capture := &bodyBoundsEvents{}
		rec := postNativeOutcome(t, route, stream, endpoint, store, capture)

		assertNativeGatewayError(t, rec, "true")
		assertNativeAdmissionOnly(t, store, capture)
	})
}

func TestNativeRedirectedDialFailureSuppressesRetry(t *testing.T) {
	childURL := closedLoopbackURL(t)
	runNativeOutcomeCases(t, func(t *testing.T, route string, stream bool) {
		t.Helper()
		var arrivals atomic.Int32
		server := httptest.NewServer(redirectAfterNativeRequest(t, &arrivals, childURL+"/after-redirect"))
		t.Cleanup(server.Close)

		store := &fakeInvocationStore{}
		capture := &bodyBoundsEvents{}
		rec := postNativeOutcome(t, route, stream, server.URL, store, capture)

		assertNativeGatewayError(t, rec, "false")
		require.EqualValues(t, 1, arrivals.Load(), "first provider hop accepted the complete request before redirect")
		assertNativeAdmissionOnly(t, store, capture)
	})
}

func runNativeOutcomeCases(t *testing.T, run func(*testing.T, string, bool)) {
	t.Helper()
	for _, route := range []string{"messages", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(route+"/stream="+map[bool]string{false: "false", true: "true"}[stream], func(t *testing.T) {
				run(t, route, stream)
			})
		}
	}
}

func postNativeOutcome(t *testing.T, route string, stream bool, endpoint string, store *fakeInvocationStore, capture *bodyBoundsEvents) *httptest.ResponseRecorder {
	t.Helper()
	if route == "messages" {
		gw := bodyBoundsMessagesGateway(t, endpoint, store, capture)
		return postMessages(t, gw, nativeMessagesOutcomeBody(stream))
	}
	gw := bodyBoundsResponsesGateway(t, endpoint, store, capture)
	return postResponses(t, gw, nativeResponsesOutcomeBody(stream))
}

func nativeMessagesOutcomeBody(stream bool) string {
	body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8}`
	if stream {
		return strings.TrimSuffix(body, "}") + `,"stream":true}`
	}
	return body
}

func nativeResponsesOutcomeBody(stream bool) string {
	body := `{"model":"m","input":"hello"}`
	if stream {
		return strings.TrimSuffix(body, "}") + `,"stream":true}`
	}
	return body
}

func closeAfterNativeRequest(t *testing.T, arrivals *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read complete paid request: %v", err)
			return
		}
		arrivals.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack response connection: %v", err)
			return
		}
		_ = conn.Close()
	}
}

func redirectAfterNativeRequest(t *testing.T, arrivals *atomic.Int32, location string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read complete paid request: %v", err)
			return
		}
		arrivals.Add(1)
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}

func assertNativeGatewayError(t *testing.T, rec *httptest.ResponseRecorder, retryHint string) {
	t.Helper()
	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
	require.Equal(t, retryHint, rec.Header().Get("X-Should-Retry"))
}

func assertNativeAdmissionOnly(t *testing.T, store *fakeInvocationStore, capture *bodyBoundsEvents) {
	t.Helper()
	require.Len(t, store.admitted, 1)
	require.Empty(t, store.facts)
	require.Zero(t, capture.len())
}

func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := listener.Addr().String()
	require.NoError(t, listener.Close())
	return "http://" + endpoint
}
