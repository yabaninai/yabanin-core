package consumer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestResponseForStorage_AlwaysValidJSON is a regression test for the
// "invalid input syntax for type json" failure: a truncated response body is
// not valid JSON, and inserting it into the request_logs.response JSONB column
// used to fail. ResponseForStorage must always return a value that is valid
// JSON (so the insert succeeds).
func TestResponseForStorage_AlwaysValidJSON(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace-only", "   "},
		{"valid-json-object", `{"id":"x","choices":[{"message":{"content":"hi"}}]}`},
		{"valid-json-short-string", `hello`},
		{"truncated-json-invalid", `{"id":"x","choices":[{"message":{"content":"a very long response that gets cut off mid-way and is definitely not clos`},
		{"truncated-with-suffix", `{"id":"x","choices":[{"message":{"content":"abcdefghij"}}]}... [truncated]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResponseForStorage(tc.input)
			// nil stores as SQL NULL, which is valid for the JSONB column.
			if got == nil {
				return
			}
			// The returned bytes must themselves be valid JSON — pgx writes them
			// verbatim into the JSONB column, so this is the invariant that keeps
			// the insert from failing with "invalid input syntax for type json".
			if !json.Valid(got) {
				t.Fatalf("ResponseForStorage(%q) returned invalid JSON bytes: %q", tc.input, got)
			}
		})
	}
}

// TestResponseForStorage_TruncatedIsValidJSONString ensures a truncated
// (invalid-JSON) body is stored as a valid JSON string, not dropped, so
// debugging visibility is kept and the JSONB insert succeeds.
func TestResponseForStorage_TruncatedIsValidJSONString(t *testing.T) {
	long := `{"id":"x","content":"` + string(make([]byte, 200)) + `"}`
	got := ResponseForStorage(TruncateResponse(long, maxResponseChars))
	if len(got) == 0 {
		t.Fatal("expected non-empty bytes for a truncated body")
	}
	if !json.Valid(got) {
		t.Fatalf("truncated body must be stored as valid JSON, got: %s", got)
	}
	// It must be a JSON *string* (the truncated text wrapped in quotes), not a
	// re-parsed object — that is the whole point of the fallback branch.
	var s string
	if err := json.Unmarshal(got, &s); err != nil {
		t.Fatalf("truncated body should be stored as a JSON string, got: %s", got)
	}
	// TruncateResponse appends "... [truncated]" (15 chars) after the first
	// maxResponseChars chars; the JSON string is that text plus two quotes.
	if len(s) > maxResponseChars+len("... [truncated]") {
		t.Errorf("truncated string not bounded: %d chars", len(s))
	}
}

// TestTruncateResponse_Boundary checks the truncation helper's boundary.
func TestTruncateResponse_Boundary(t *testing.T) {
	if got := TruncateResponse("short", 100); got != "short" {
		t.Errorf("short text should pass through, got %q", got)
	}
	long := "x" + string(make([]byte, 200))
	if got := TruncateResponse(long, 100); len(got) > 100+len("... [truncated]") {
		t.Errorf("long text should be truncated, got %d chars", len(got))
	}
}

func TestScrubSecrets_RedactsCredentialsAndPreservesUsefulText(t *testing.T) {
	marker := strings.Join([]string{"probe", "token", "123"}, "-")
	secret := `{"headers":{"X-Api-Key":"` + marker + `"},"query":"public status"}`
	got := ScrubSecrets(secret)
	if strings.Contains(got, marker) || !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "public status") {
		t.Fatalf("scrubbed JSON = %q", got)
	}
	plain := "upstream returned status unavailable; retry later"
	if got := ScrubSecrets(plain); got != plain {
		t.Fatalf("plain diagnostic changed: %q", got)
	}
	wrapped := base64.StdEncoding.EncodeToString([]byte(secret))
	if got := ScrubSecrets(wrapped); strings.Contains(got, "probe-token-123") {
		t.Fatalf("base64-wrapped secret survived: %q", got)
	}
	errorMarker := strings.Join([]string{"probe", "error", "token"}, "-")
	if got := ScrubSecrets("request failed: Authorization: Bearer " + errorMarker); strings.Contains(got, errorMarker) {
		t.Fatalf("bearer token survived: %q", got)
	}
}

func TestScrubSecrets_ExactSecretKeyNames(t *testing.T) {
	input := `{"token_count":3,"tokenizer":"byte-pair","access_token":"credential-value"}`
	got := ScrubSecrets(input)
	var value map[string]any
	if err := json.Unmarshal([]byte(got), &value); err != nil {
		t.Fatalf("scrubbed value is not valid JSON: %v", err)
	}
	if value["token_count"] != float64(3) || value["tokenizer"] != "byte-pair" {
		t.Fatalf("non-secret token-prefixed keys were altered: %s", got)
	}
	if value["access_token"] != "[REDACTED]" {
		t.Fatalf("access_token was not redacted: %s", got)
	}
}
