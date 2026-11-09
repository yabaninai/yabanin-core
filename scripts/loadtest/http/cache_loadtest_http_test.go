package main

import "testing"

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
