package main

import (
	"testing"
	"time"
)

func TestShouldAttachCredentials(t *testing.T) {
	for _, tc := range []struct {
		target string
		allow  bool
		want   bool
	}{
		{"http://localhost:8080", false, true},
		{"http://LOCALHOST:8080", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://[::1]:8080", false, true},
		{"https://example.com", false, false},
		{"https://example.com", true, true},
		{"not a URL", false, false},
	} {
		if got := shouldAttachCredentials(tc.target, tc.allow); got != tc.want {
			t.Errorf("shouldAttachCredentials(%q, %v) = %v, want %v", tc.target, tc.allow, got, tc.want)
		}
	}
}

// G3 timeout lift (N12-P04-T03): the historical hard-coded 30 s client
// timeout stays the DEFAULT (behavior-identical), and an explicit lift is
// possible so the 30 s/120 s long-response profiles can run through matched.
func TestRequestTimeoutDefaultAndLift(t *testing.T) {
	if defaultRequestTimeout != 30*time.Second {
		t.Errorf("defaultRequestTimeout = %v, want 30s (behavior-identical default)", defaultRequestTimeout)
	}
	if got := newClient(defaultRequestTimeout).Timeout; got != defaultRequestTimeout {
		t.Errorf("newClient(default) timeout = %v, want %v", got, defaultRequestTimeout)
	}
	// The contract's separate 120 s-response profile needs >120 s.
	if got := newClient(150 * time.Second).Timeout; got != 150*time.Second {
		t.Errorf("newClient(150s) timeout = %v, want 150s (lift must be honored)", got)
	}
}
