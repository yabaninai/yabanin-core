package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func TestNativeAcceptedRequestWithoutResponseSuppressesRetry(t *testing.T) {
	for _, route := range []string{"messages", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(route+"/stream="+map[bool]string{false: "false", true: "true"}[stream], func(t *testing.T) {
				var arrivals atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				}))
				defer server.Close()

				store := &fakeInvocationStore{}
				capture := &bodyBoundsEvents{}
				var rec *httptest.ResponseRecorder
				if route == "messages" {
					gw := bodyBoundsMessagesGateway(t, server.URL, store, capture)
					body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8}`
					if stream {
						body = `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":true}`
					}
					rec = postMessages(t, gw, body)
				} else {
					gw := bodyBoundsResponsesGateway(t, server.URL, store, capture)
					body := `{"model":"m","input":"hello"}`
					if stream {
						body = `{"model":"m","input":"hello","stream":true}`
					}
					rec = postResponses(t, gw, body)
				}

				if rec.Code != http.StatusBadGateway {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
				if got := rec.Header().Get("X-Should-Retry"); got != "false" {
					t.Fatalf("X-Should-Retry %q; request reached provider but response outcome is unknown", got)
				}
				if got := arrivals.Load(); got != 1 {
					t.Fatalf("provider received %d requests, want one", got)
				}
				if len(store.admitted) != 1 || len(store.facts) != 0 {
					t.Fatalf("admissions=%d terminal facts=%d; unknown dispatch must retain only its admission", len(store.admitted), len(store.facts))
				}
				if got := capture.len(); got != 0 {
					t.Fatalf("published %d events for unknown provider outcome", got)
				}
			})
		}
	}
}

func TestNativeProvenDialFailureRemainsRetryable(t *testing.T) {
	url := closedLoopbackURL(t)

	client, err := upstream.NewClient(url, []string{url})
	if err != nil {
		t.Fatal(err)
	}
	_, dialErr := client.Do(context.Background(), "/v1/messages", []byte(`{}`), "", false, nil)
	if !retry.DefinitelyNotSent(dialErr) {
		t.Fatalf("closed-listener error %T %v was not classified as definitely not sent", dialErr, dialErr)
	}

	for _, route := range []string{"messages", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(route+"/stream="+map[bool]string{false: "false", true: "true"}[stream], func(t *testing.T) {
				store := &fakeInvocationStore{}
				capture := &bodyBoundsEvents{}
				var rec *httptest.ResponseRecorder
				if route == "messages" {
					gw := bodyBoundsMessagesGateway(t, url, store, capture)
					body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8}`
					if stream {
						body = `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":true}`
					}
					rec = postMessages(t, gw, body)
				} else {
					gw := bodyBoundsResponsesGateway(t, url, store, capture)
					body := `{"model":"m","input":"hello"}`
					if stream {
						body = `{"model":"m","input":"hello","stream":true}`
					}
					rec = postResponses(t, gw, body)
				}

				if rec.Code != http.StatusBadGateway {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
				if got := rec.Header().Get("X-Should-Retry"); got != "true" {
					t.Fatalf("X-Should-Retry %q; proven pre-send dial failure should remain retryable", got)
				}
				if len(store.admitted) != 1 || len(store.facts) != 0 {
					t.Fatalf("admissions=%d terminal facts=%d", len(store.admitted), len(store.facts))
				}
				if got := capture.len(); got != 0 {
					t.Fatalf("published %d events for a request that could not reach the provider", got)
				}
			})
		}
	}
}

func TestNativeRedirectedDialFailureSuppressesRetry(t *testing.T) {
	childURL := closedLoopbackURL(t)
	for _, route := range []string{"messages", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(route+"/stream="+map[bool]string{false: "false", true: "true"}[stream], func(t *testing.T) {
				var arrivals atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Errorf("read complete paid request: %v", err)
						return
					}
					arrivals.Add(1)
					w.Header().Set("Location", childURL+"/after-redirect")
					w.WriteHeader(http.StatusTemporaryRedirect)
				}))
				defer server.Close()

				store := &fakeInvocationStore{}
				capture := &bodyBoundsEvents{}
				var rec *httptest.ResponseRecorder
				if route == "messages" {
					gw := bodyBoundsMessagesGateway(t, server.URL, store, capture)
					body := `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8}`
					if stream {
						body = `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":true}`
					}
					rec = postMessages(t, gw, body)
				} else {
					gw := bodyBoundsResponsesGateway(t, server.URL, store, capture)
					body := `{"model":"m","input":"hello"}`
					if stream {
						body = `{"model":"m","input":"hello","stream":true}`
					}
					rec = postResponses(t, gw, body)
				}

				if rec.Code != http.StatusBadGateway {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
				if got := rec.Header().Get("X-Should-Retry"); got != "false" {
					t.Fatalf("X-Should-Retry %q after a prior provider hop accepted the request", got)
				}
				if got := arrivals.Load(); got != 1 {
					t.Fatalf("provider received %d initial requests, want one", got)
				}
				if len(store.admitted) != 1 || len(store.facts) != 0 {
					t.Fatalf("admissions=%d terminal facts=%d", len(store.admitted), len(store.facts))
				}
			})
		}
	}
}

func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + endpoint
}
