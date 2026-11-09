package auditlog

// Unit tests for the PII scrubbing primitives (N13-P05-T03). Fixtures carry
// recognizable sentinels; the idempotency pins guarantee repeated scrubbing
// neither changes text nor inflates counts.

import (
	"strings"
	"testing"
)

func TestScrubPII_MasksPIIShapesAndCounts(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		present   []string // must survive scrubbing
		masks     int
		sentinels []string // must never survive
	}{
		{
			name:      "email in prose",
			input:     `owner alice.person+ops@example-corp.private reported the fault`,
			present:   []string{"owner ", " reported the fault"},
			masks:     1,
			sentinels: []string{"alice.person+ops@example-corp.private"},
		},
		{
			name:      "JWT three segments",
			input:     `auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NX0.c2VjcmV0c2lnbmF0dXJl failed`,
			present:   []string{"auth ", " failed"},
			masks:     1,
			sentinels: []string{"eyJhbGciOiJIUzI1NiJ9", "c2VjcmV0c2lnbmF0dXJl"},
		},
		{
			name:      "valid IPv4",
			input:     `upstream 10.42.7.193 refused the retry`,
			present:   []string{"upstream ", " refused the retry"},
			masks:     1,
			sentinels: []string{"10.42.7.193"},
		},
		{
			name:      "three-octet version string is not an IP",
			input:     `gateway version 2.11.4 deployed`,
			present:   []string{"2.11.4"},
			masks:     0,
			sentinels: nil,
		},
		{
			name:      "invalid octet is not masked",
			input:     `route 999.1.1.1 unknown`,
			present:   []string{"999.1.1.1"},
			masks:     0,
			sentinels: nil,
		},
		{
			name:      "international phone shapes",
			input:     `contact +7 (999) 123-45-67 or +14155551234`,
			present:   []string{"contact ", " or "},
			masks:     2,
			sentinels: []string{"+7 (999) 123-45-67", "+14155551234"},
		},
		{
			name:      "offset-like plus values survive",
			input:     `shifted by +2 hours, tz offset +05:30 kept`,
			present:   []string{"+2 hours", "+05:30 kept"},
			masks:     0,
			sentinels: nil,
		},
		{
			name:      "operational identifiers survive deliberately",
			input:     `request id 550e8400-e29b-41d4-a716-446655440000 trace abc123def456`,
			present:   []string{"550e8400-e29b-41d4-a716-446655440000", "abc123def456"},
			masks:     0,
			sentinels: nil,
		},
		{
			name:      "multiple shapes in one line",
			input:     `user jane@example.com from 192.168.0.5 bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyNDIzfQ.c2VjcmV0LXNpZ25hdHVyZQ tokens`,
			present:   []string{"user ", " from ", " tokens"},
			masks:     3,
			sentinels: []string{"jane@example.com", "192.168.0.5", "eyJhbGciOiJub25lIn0"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, hits := ScrubPII(test.input)
			if hits != test.masks {
				t.Errorf("ScrubPII() hits = %d, want %d (output %q)", hits, test.masks, got)
			}
			for _, keep := range test.present {
				if !strings.Contains(got, keep) {
					t.Errorf("scrubbed text lost %q: %q", keep, got)
				}
			}
			for _, sentinel := range test.sentinels {
				if strings.Contains(got, sentinel) {
					t.Errorf("scrubbed text kept sentinel %q: %q", sentinel, got)
				}
			}
			if test.masks > 0 && !strings.Contains(got, ScrubMaskedValue) {
				t.Errorf("masked output lacks the sentinel: %q", got)
			}
		})
	}
}

func TestScrubPII_OrdinaryProseUntouched(t *testing.T) {
	plain := "gateway restarted; sessions drained; queue depth back to zero"
	got, hits := ScrubPII(plain)
	if got != plain || hits != 0 {
		t.Fatalf("ScrubPII() = %q (%d hits), want unchanged prose", got, hits)
	}
}

func TestScrubPII_IdempotentAndEmptySafe(t *testing.T) {
	dirty := "mail ops@example.com via 10.0.0.7"
	once, firstHits := ScrubPII(dirty)
	if firstHits == 0 || !strings.Contains(once, ScrubMaskedValue) {
		t.Fatalf("first pass = %q (%d hits)", once, firstHits)
	}
	twice, secondHits := ScrubPII(once)
	if twice != once || secondHits != 0 {
		t.Fatalf("second pass changed output: %q (%d hits)", twice, secondHits)
	}
	if empty, hits := ScrubPII(""); empty != "" || hits != 0 {
		t.Fatalf("empty input = %q (%d hits)", empty, hits)
	}
	if blank, hits := ScrubPII("   \t"); blank != "   \t" || hits != 0 {
		t.Fatalf("blank input = %q (%d hits)", blank, hits)
	}
}

func TestScrubMaskedValue_MatchesCredentialSentinel(t *testing.T) {
	// One sentinel across credential (redact.go) and PII (scrub_pii.go)
	// scrubbing keeps bundle counters and consumer expectations aligned.
	if ScrubMaskedValue != "[REDACTED]" {
		t.Fatalf("ScrubMaskedValue = %q, want the shared sentinel", ScrubMaskedValue)
	}
}

func TestParseScrubProfile_FailClosed(t *testing.T) {
	tests := []struct {
		input string
		want  ScrubProfile
	}{
		{"", ScrubProfileStandard},
		{"standard", ScrubProfileStandard},
		{"  STANDARD  ", ScrubProfileStandard},
		{"minimal", ScrubProfileMinimal},
		{"Minimal", ScrubProfileMinimal},
		{"strict", ScrubProfileStrict},
		{"verbose", ScrubProfileStrict},
		{"metadata-only", ScrubProfileStrict},
		{"standard ", ScrubProfileStandard},
	}
	for _, test := range tests {
		if got := ParseScrubProfile(test.input); got != test.want {
			t.Errorf("ParseScrubProfile(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
