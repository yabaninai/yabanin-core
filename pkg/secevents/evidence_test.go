package secevents

import (
	"strings"
	"testing"
)

func TestEvidenceRefHappyPath(t *testing.T) {
	e := validEvent()
	e.Evidence = []EvidenceRef{
		{Kind: EvidencePayloadDigest, Digest: strings.Repeat("ab", 32)},
		{Kind: EvidencePolicyDecision, Digest: strings.Repeat("cd", 32), Location: "request_logs:policy:req-9"},
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	out := mustEncode(t, e)
	// Redacted-by-construction: the wire form is only kind/digest/location.
	for _, forbidden := range []string{"data:", "content", "payload_text"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("wire form carries content-bearing key %q: %s", forbidden, out)
		}
	}
}

func TestEvidenceRefValidationMatrix(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		ref     EvidenceRef
		wantErr bool
	}{
		{"digest_only", EvidenceRef{Kind: "payload_digest", Digest: digest}, false},
		{"with_location", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "logs:1"}, false},
		{"empty_kind", EvidenceRef{Digest: digest}, true},
		{"uppercase_kind", EvidenceRef{Kind: "PayloadDigest", Digest: digest}, true},
		{"empty_digest", EvidenceRef{Kind: "payload_digest"}, true},
		{"short_digest", EvidenceRef{Kind: "payload_digest", Digest: "abc"}, true},
		{"uppercase_digest", EvidenceRef{Kind: "payload_digest", Digest: strings.ToUpper(digest)}, true},
		{"non_hex_digest", EvidenceRef{Kind: "payload_digest", Digest: strings.Repeat("zz", 32)}, true},
		{"data_url_location", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "data:image/png;base64,AAAA"}, true},
		{"data_url_html_percent_encoded_not_base64", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "data:text/html,%3Cscript%3Ealert(1)%3C/script%3E"}, true},
		{"data_url_charset_plain_not_base64", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "data:text/html;charset=utf-8,<b>hi</b>"}, true},
		{"data_url_uppercase", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "DATA:image/png;base64,AAAA"}, true},
		{"whitespace_location", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: "logs 1"}, true},
		{"overlong_location", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: strings.Repeat("x", 257)}, true},
		{"location_at_limit", EvidenceRef{Kind: "payload_digest", Digest: digest, Location: strings.Repeat("x", 256)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("validate err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// A decoded event with a content-bearing location must be rejected at the
// boundary, not pass through to consumers.
func TestDecodeRejectsContentSmugglingLocation(t *testing.T) {
	wireJSON := `{
		"schema_version": 1,
		"event_id": "x1",
		"event_type": "a.b",
		"org_id": "o",
		"occurred_at": "2026-11-02T12:00:00Z",
		"evidence": [{"kind": "payload_digest", "digest": "` + strings.Repeat("ab", 32) + `",
			"location": "see data:text/plain;base64,SGVsbG8="}]
	}`
	if _, _, err := Decode([]byte(wireJSON)); err == nil {
		t.Fatalf("Decode accepted a data-URL evidence location")
	}
}

// N1 anchor: an envelope whose
// evidence location IS a data-URL — the prefix form itself, not merely a
// data-URL hidden mid-string — is rejected at the envelope boundary (Decode),
// not only at the field validator. Production guard: evidence.go dataURLLeak
// (case-insensitive, matches anywhere). This pin
// closes the dispatch's exact layer+form wording at the envelope layer.
func TestDecodeRejectsDataURLPrefixedEvidenceLocation(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		location string
	}{
		{"lowercase_prefix", "data:image/png;base64,AAAA"},
		{"uppercase_prefix", "DATA:text/html,<b>hi</b>"},
		{"mixed_case_prefix", "DaTa:application/pdf,%25PDF-1.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wireJSON := `{
				"schema_version": 1,
				"event_id": "x1",
				"event_type": "a.b",
				"org_id": "o",
				"occurred_at": "2026-11-02T12:00:00Z",
				"evidence": [{"kind": "payload_digest", "digest": "` + digest + `",
					"location": "` + tc.location + `"}]
			}`
			if _, _, err := Decode([]byte(wireJSON)); err == nil {
				t.Fatalf("Decode accepted a data-URL-prefixed evidence location %q", tc.location)
			}
		})
	}
}
