package labels

import (
	"strings"
	"testing"
)

func TestNormalizeKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Issue", "issue", true},
		{"  Git.Repo  ", "git.repo", true},
		{"a..b", "", false},
		{".a", "", false},
		{"a.", "", false},
		{"bad%key", "", false},
		{strings.Repeat("a", 64), "", false},
		{strings.Repeat("a", 63), strings.Repeat("a", 63), true},
		{"задача", "", false},
		{"", "", false},
		{"1abc", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeKey(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("%q -> %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeValue(t *testing.T) {
	cyr := "%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82"
	cases := []struct {
		in     string
		want   string
		reason DropReason
	}{
		{" PAY-123 ", "PAY-123", ""},
		{"a\nb", "", DropInvalidValue},
		{"a\x01b", "", DropInvalidValue},
		{strings.Repeat("a", 128), strings.Repeat("a", 128), ""},
		{strings.Repeat("a", 129), "", DropValueTooLong},
		{"%ZZ", "", DropInvalidValue},
		{cyr, "Привет", ""},
		{"", "", DropInvalidValue},
		{"payments%2Fbilling", "payments/billing", ""},
	}
	for _, tc := range cases {
		got, reason := NormalizeValue(tc.in)
		if got != tc.want || reason != tc.reason {
			t.Fatalf("%q -> %q %q, want %q %q", tc.in, got, reason, tc.want, tc.reason)
		}
	}
}
