package adminstore

// MC-1 unit tests: the pure helpers of the MCP credential store — headers
// payload validation, display masking, and the fail-closed write posture
// without an encryptor. The DB-backed behavior lives in mcpcreds_int_test.go.

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/encryption"
)

func TestValidateMCPSecretHeaders(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"bearer header", `{"Authorization":"Bearer tok-1"}`, false},
		{"multi headers", `{"Authorization":"Bearer x","X-Api-Key":["a","b"]}`, false},
		{"empty object", `{}`, true},
		{"not an object", `["Authorization"]`, true},
		{"malformed json", `{"Authorization":`, true},
		{"no entries", `{"Authorization":""}`, true},
		{"header injection crlf", `{"Authorization":"Bearer x\r\nHost: evil"}`, true},
		{"unicode nul escape", "{\"Authorization\":\"a\\u0000b\"}", true},
		{"invalid header name", `{"Bad Header":"v"}`, true},
		{"non-string value", `{"Authorization":42}`, true},
		{"empty list value", `{"Authorization":[]}`, true},
		{"non-string list item", `{"Authorization":[1]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMCPSecretHeaders(tc.payload)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s", tc.payload)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	// A real NUL byte in a value must be rejected too (the \\u0000 JSON
	// escape above decodes to exactly that).
	if err := ValidateMCPSecretHeaders("{\"Authorization\":\"a\x00b\"}"); err == nil {
		t.Fatal("expected NUL byte in header value to be rejected")
	}
}

func TestMCPSecretLast4(t *testing.T) {
	cases := []struct {
		name string
		kind string
		in   string
		want string
	}{
		{"headers longest value", MCPCredKindHeaders, `{"X-Short":"ab","Authorization":"Bearer secret-token-9999"}`, "9999"},
		{"headers list value", MCPCredKindHeaders, `{"Authorization":["Bearer abcdef-7777"]}`, "7777"},
		{"oauth access token", MCPCredKindOAuth, `{"access_token":"at-abcdef-1234","refresh_token":"rt-xyz"}`, "1234"},
		{"oauth refresh fallback", MCPCredKindOAuth, `{"refresh_token":"rt-abcdef-5678"}`, "5678"},
		{"too short masks empty", MCPCredKindHeaders, `{"Authorization":"short"}`, ""},
		{"unparseable masks empty", MCPCredKindOAuth, `not-json`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mcpSecretLast4(tc.kind, tc.in); got != tc.want {
				t.Fatalf("mcpSecretLast4 = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateMCPCredKind(t *testing.T) {
	for _, kind := range []string{MCPCredKindHeaders, MCPCredKindOAuth} {
		if err := validateMCPCredKind(kind); err != nil {
			t.Fatalf("kind %q must be valid: %v", kind, err)
		}
	}
	if err := validateMCPCredKind("basic"); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestEncryptMCPCredSecret_FailClosedWithoutEncryptor(t *testing.T) {
	s := newForTest(nil, nil, nil) // no db, no logger, no encryptor

	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	if _, _, err := s.encryptMCPCredSecret(MCPCredKindHeaders, `{"Authorization":"Bearer x-123456"}`); err == nil {
		t.Fatal("expected refusal without an encryptor and without the dev plaintext allowance")
	} else if !strings.Contains(err.Error(), "encryption_key") {
		t.Fatalf("refusal must name the missing config: %v", err)
	}

	if _, _, err := s.encryptMCPCredSecret(MCPCredKindHeaders, ""); err == nil {
		t.Fatal("empty secret must be refused regardless of encryptor state")
	}
	if _, _, err := s.encryptMCPCredSecret(MCPCredKindHeaders, strings.Repeat("x", mcpSecretMaxBytes+1)); err == nil {
		t.Fatal("oversized secret must be refused")
	}
}

func TestIsHTTPHeaderValue(t *testing.T) {
	valid := []string{"Authorization", "X-Api-Key", "proxy-authorization", "A1", "!#$%&'*+-.^_`|~"}
	invalid := []string{"", "Bad Header", "héader", "x y"}
	for _, s := range valid {
		if !isHTTPHeaderValue(s) {
			t.Errorf("%q must be a valid token", s)
		}
	}
	for _, s := range invalid {
		if isHTTPHeaderValue(s) {
			t.Errorf("%q must be rejected", s)
		}
	}
}
