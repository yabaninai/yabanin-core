package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client can finish its next SSE turn before the previous handler returns.
// Force that schedule rather than relying on timing or the installed CLI.
func TestRtripCapture_RequestOrderSurvivesReversedCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan struct{})
	capture, handler := newRtripCapture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn := r.Header.Get("X-Test-Turn")
		if turn == "first" {
			close(firstEntered)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
			}
		}
		w.Header().Set("X-Test-Turn", turn)
	}))
	first := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/responses", strings.NewReader("first request"))
	first.Header.Set("X-Test-Turn", "first")
	go func() {
		defer close(firstDone)
		handler.ServeHTTP(httptest.NewRecorder(), first)
	}()
	select {
	case <-firstEntered:
	case <-ctx.Done():
		t.Fatal("first request did not enter handler")
	}
	second := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/responses", strings.NewReader("second request"))
	second.Header.Set("X-Test-Turn", "second")
	handler.ServeHTTP(httptest.NewRecorder(), second)
	if got := capture.postCount(); got != 1 {
		t.Fatalf("completed POST count = %d, want 1 while first request is pending", got)
	}
	if posts := capture.posts(t); len(posts) != 1 || string(posts[0].reqBody) != "second request" {
		t.Fatalf("pending capture was published: %+v", posts)
	}
	if got := len(capture.summary()); got != 1 {
		t.Fatalf("completed summary count = %d, want 1", got)
	}
	close(releaseFirst)
	// Exercise summaries while the first request publishes its completion.
	for {
		_ = capture.summary()
		select {
		case <-firstDone:
			posts := capture.posts(t)
			if len(posts) != 2 {
				t.Fatalf("completed POST count = %d, want 2", len(posts))
			}
			for i, turn := range []string{"first", "second"} {
				if got := string(posts[i].reqBody); got != turn+" request" {
					t.Errorf("request %d body = %q, want %q", i+1, got, turn+" request")
				}
				if got := posts[i].respHdr.Get("X-Test-Turn"); got != turn {
					t.Errorf("request %d response header = %q, want %q", i+1, got, turn)
				}
			}
			return
		case <-ctx.Done():
			t.Fatal("first request did not complete")
		default:
		}
	}
}
