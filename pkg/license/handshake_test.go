package license

// Handshake contract tests (E01-P05-W01-C01): structural validation of the
// plugin-handshake envelope — the CONTRACT layer only, no negotiation (that
// is handshake_negotiate.go / W01-C02, pinned in its own file).
//
// Mandatory variants instantiated here:
//   - allowed scenario: a correct version pair (format "1" + entitlement
//     "2") plus a well-formed module id validates cleanly, on both envelope
//     sides (request and response);
//   - unknown CLIENT version: a well-formed but unknown format version is
//     structurally VALID here (version policy belongs to the negotiation
//     layer — pinned there, never half-accepted by the contract);
//   - malformed payload / empty-upstream: zero-value envelopes, whitespace
//     padding, control characters, oversized tokens and wrong-core
//     entitlement versions are rejected fail-closed;
//   - rights/cross-org, replay/delay, rollback: N/A — the contract layer is
//     a pure function with no authorization, clock or state dimension (the
//     handshake grants nothing; see handshake.go boundary notes).
//
// Determinism: no clocks, no I/O, no global state — table-driven only.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHandshakeRequestValidation(t *testing.T) {
	valid := HandshakeRequest{
		FormatVersion:      HandshakeFormatVersion,
		ModuleID:           "internal-loop",
		EntitlementVersion: ModuleEntitlementVersion,
	}
	if err := ValidateHandshakeRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(r *HandshakeRequest)
		want string
	}{
		{"empty upstream: zero value", func(r *HandshakeRequest) { *r = HandshakeRequest{} }, "format_version is required"},
		{"missing format version", func(r *HandshakeRequest) { r.FormatVersion = "" }, "format_version is required"},
		{"format version whitespace padding", func(r *HandshakeRequest) { r.FormatVersion = " 1" }, "leading/trailing whitespace"},
		{"format version control character", func(r *HandshakeRequest) { r.FormatVersion = "1\x00" }, "control characters"},
		{"format version oversized", func(r *HandshakeRequest) { r.FormatVersion = strings.Repeat("1", handshakeVersionMaxLen+1) }, "exceeds"},
		{"missing module id", func(r *HandshakeRequest) { r.ModuleID = "" }, "module_id is required"},
		{"module id whitespace padding", func(r *HandshakeRequest) { r.ModuleID = " internal-loop " }, "leading/trailing whitespace"},
		{"module id oversized", func(r *HandshakeRequest) { r.ModuleID = strings.Repeat("m", handshakeModuleIDMaxLen+1) }, "exceeds"},
		{"missing entitlement version", func(r *HandshakeRequest) { r.EntitlementVersion = "" }, "entitlement_version is required"},
		{"entitlement version whitespace padding", func(r *HandshakeRequest) { r.EntitlementVersion = "2\n" }, "leading/trailing whitespace"},
		{"entitlement version oversized", func(r *HandshakeRequest) { r.EntitlementVersion = strings.Repeat("2", handshakeVersionMaxLen+1) }, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mut(&r)
			err := ValidateHandshakeRequest(r)
			if err == nil {
				t.Fatalf("malformed request accepted: %+v", r)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// TestHandshakeUnknownClientVersionIsStructurallyValid pins the card's
// unknown-client-version cell AT THE CONTRACT LAYER: "3" is not a format
// version this core has ever spoken, but it is a well-formed version token —
// structural validation passes and the decision moves to the negotiation
// layer (which answers matrix-or-latest and never echoes the unknown value;
// pinned in handshake_negotiate_test.go).
func TestHandshakeUnknownClientVersionIsStructurallyValid(t *testing.T) {
	r := HandshakeRequest{
		FormatVersion:      "3",
		ModuleID:           "media-persistence",
		EntitlementVersion: "1",
	}
	if err := ValidateHandshakeRequest(r); err != nil {
		t.Fatalf("well-formed unknown versions must pass STRUCTURAL validation (policy belongs to negotiation): %v", err)
	}
}

func TestHandshakeResponseValidation(t *testing.T) {
	valid := HandshakeResponse{
		FormatVersion:      HandshakeFormatVersion,
		EntitlementVersion: ModuleEntitlementVersion,
	}
	if err := ValidateHandshakeResponse(valid); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(r *HandshakeResponse)
		want string
	}{
		{"empty upstream: zero value", func(r *HandshakeResponse) { *r = HandshakeResponse{} }, "format_version is required"},
		{"missing format version", func(r *HandshakeResponse) { r.FormatVersion = "" }, "format_version is required"},
		{"format version whitespace padding", func(r *HandshakeResponse) { r.FormatVersion = "\t1" }, "leading/trailing whitespace"},
		{"entitlement version skew vs core pin", func(r *HandshakeResponse) { r.EntitlementVersion = "1" }, `verifies "2" only`},
		{"entitlement version empty", func(r *HandshakeResponse) { r.EntitlementVersion = "" }, `verifies "2" only`},
		{"entitlement version future", func(r *HandshakeResponse) { r.EntitlementVersion = "3" }, `verifies "2" only`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mut(&r)
			err := ValidateHandshakeResponse(r)
			if err == nil {
				t.Fatalf("malformed response accepted: %+v", r)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// TestHandshakeEnvelopeJSONShape pins the wire shape: exact JSON field names
// (a connecting module is written against them) and full decodability of the
// canonical pair. A malformed JSON payload (truncated garbage bytes — the
// upstream-transport variant) fails decode before validation even runs.
func TestHandshakeEnvelopeJSONShape(t *testing.T) {
	req := `{"format_version":"1","module_id":"internal-loop","entitlement_version":"2"}`
	var got HandshakeRequest
	if err := json.Unmarshal([]byte(req), &got); err != nil {
		t.Fatalf("decode canonical request: %v", err)
	}
	if err := ValidateHandshakeRequest(got); err != nil {
		t.Fatalf("canonical request invalid: %v", err)
	}
	if got.FormatVersion != HandshakeFormatVersion || got.EntitlementVersion != ModuleEntitlementVersion {
		t.Fatalf("field mapping drifted: %+v", got)
	}

	for _, bad := range []string{`{"format_version":"1"`, ``, `not json at all`} {
		var r HandshakeRequest
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Fatalf("malformed payload %q decoded without error", bad)
		}
	}
}
