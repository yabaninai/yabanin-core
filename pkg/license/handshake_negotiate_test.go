package license

// Handshake negotiation tests (E01-P05-W01-C02). Names mirror the
// mcpserver negotiation battery (pkg/mcpserver/negotiate_test.go:59
// TestNegotiationMatrixWire → TestHandshakeNegotiationMatrix, :82
// TestUnknownVersionRejectedWithoutSilentDowngrade → same name under the
// Handshake prefix; :121 TestNewerRevisionOnlyClient → likewise), per the
// dispatch card «имена зеркалят negotiate_test.go:59/:82».
//
// This seam is a library call, not an HTTP endpoint, so the mcpserver wire
// harness is replaced by direct Handshake-door calls; every negotiation
// cell of the precedent battery is pinned:
//
//   - full matrix: every offered format is echoed exactly;
//   - unknown rejected without silent downgrade: unknown/newer/garbage/
//     whitespace versions are NEVER echoed — the answer is always a matrix
//     member (the core's latest), so no module is left believing it speaks
//     a format the core does not implement;
//   - newer-revision-only client: a module built against a future format
//     ("2") is told the truth ("1") and sees the skew explicitly, including
//     the entitlement-document version pin;
//   - malformed payloads fail closed before negotiation;
//   - repetition is idempotent (pure function — the replay/delay variant:
//     a delayed or repeated handshake answer never goes stale).
//
// Rights/cross-org and rollback variants: N/A — the seam carries no
// authorization decision (W02 separation) and no state (pure function).

import (
	"strings"
	"testing"
)

// TestHandshakeFormatMatrixWellFormed pins the matrix invariants
// (mcpserver TestProtocolMatrixWellFormed precedent): newest-first ordering,
// no duplicates, the const == matrix edge.
func TestHandshakeFormatMatrixWellFormed(t *testing.T) {
	if len(handshakeFormatMatrix) == 0 {
		t.Fatal("handshake format matrix is empty")
	}
	seen := make(map[string]bool, len(handshakeFormatMatrix))
	for i, v := range handshakeFormatMatrix {
		if v == "" {
			t.Fatalf("matrix[%d] is empty", i)
		}
		if seen[v] {
			t.Fatalf("matrix contains duplicate %q", v)
		}
		seen[v] = true
	}
	if handshakeFormatMatrix[0] != handshakeFormatLatest {
		t.Fatalf("matrix[0] = %q, want the latest const %q", handshakeFormatMatrix[0], handshakeFormatLatest)
	}
	if handshakeFormatLatest != HandshakeFormatVersion {
		t.Fatalf("latest const %q drifted from HandshakeFormatVersion %q", handshakeFormatLatest, HandshakeFormatVersion)
	}
}

// TestHandshakeNegotiationMatrix drives the full supported matrix through
// the seam door: every offered format is echoed exactly, and the response
// always validates and names the core's entitlement document version.
func TestHandshakeNegotiationMatrix(t *testing.T) {
	for _, want := range handshakeFormatMatrix {
		resp, err := Handshake(HandshakeRequest{
			FormatVersion:      want,
			ModuleID:           "internal-loop",
			EntitlementVersion: ModuleEntitlementVersion,
		})
		if err != nil {
			t.Fatalf("handshake(%q): %v", want, err)
		}
		if resp.FormatVersion != want {
			t.Fatalf("handshake(%q) → %q, want exact echo", want, resp.FormatVersion)
		}
		if err := ValidateHandshakeResponse(resp); err != nil {
			t.Fatalf("handshake(%q) response invalid: %v", want, err)
		}
		if !supportedHandshakeFormat(resp.FormatVersion) {
			t.Fatalf("handshake(%q) answered a non-matrix value %q", want, resp.FormatVersion)
		}
		if resp.EntitlementVersion != ModuleEntitlementVersion {
			t.Fatalf("entitlement version not pinned: %+v", resp)
		}
	}
}

// TestHandshakeUnknownVersionRejectedWithoutSilentDowngrade is the card's
// negative cell: an unknown requested format is never echoed and never
// claimed — the answer is always the core's latest matrix member, so a
// module cannot proceed under the false belief that its version is spoken.
func TestHandshakeUnknownVersionRejectedWithoutSilentDowngrade(t *testing.T) {
	for _, requested := range []string{"0", "2", "3", "99", "garbage", "1.0", "v1", " 1", "1 "} {
		resp, err := Handshake(HandshakeRequest{
			FormatVersion:      requested,
			ModuleID:           "media-persistence",
			EntitlementVersion: "1", // client entitlement skew: informational, answered below
		})
		if err != nil {
			// Whitespace/control tokens fail STRUCTURAL validation before
			// negotiation — also fail-closed, never a downgrade.
			if !strings.Contains(err.Error(), "handshake:") {
				t.Fatalf("handshake(%q): unexpected error shape: %v", requested, err)
			}
			continue
		}
		if resp.FormatVersion == requested {
			t.Fatalf("unknown %q was echoed (silent downgrade)", requested)
		}
		if resp.FormatVersion != handshakeFormatLatest || !supportedHandshakeFormat(resp.FormatVersion) {
			t.Fatalf("unknown %q answered %q, want the explicit latest matrix member %q", requested, resp.FormatVersion, handshakeFormatLatest)
		}
		// The entitlement pin is answered regardless of the client's own
		// entitlement version: the skew is explicit, at the seam.
		if resp.EntitlementVersion != ModuleEntitlementVersion {
			t.Fatalf("unknown %q: entitlement pin drifted: %+v", requested, resp)
		}
	}
}

// TestHandshakeNewerRevisionOnlyClient pins a module built against a FUTURE
// envelope format: it is told the truth (the core's latest) and sees both
// skews explicitly; adopting the answer yields a fully valid conversation.
func TestHandshakeNewerRevisionOnlyClient(t *testing.T) {
	const futureFormat = "2"
	resp, err := Handshake(HandshakeRequest{
		FormatVersion:      futureFormat,
		ModuleID:           "internal-loop",
		EntitlementVersion: "3",
	})
	if err != nil {
		t.Fatalf("future-format handshake must not error at the seam: %v", err)
	}
	if resp.FormatVersion != handshakeFormatLatest || resp.FormatVersion == futureFormat {
		t.Fatalf("future-only module got %q, want explicit latest %q", resp.FormatVersion, handshakeFormatLatest)
	}
	if resp.EntitlementVersion != ModuleEntitlementVersion {
		t.Fatalf("entitlement pin drifted for future-only module: %+v", resp)
	}
	if err := ValidateHandshakeResponse(resp); err != nil {
		t.Fatalf("answer for future-only module is not a valid core shape: %v", err)
	}
	// The module adopts the negotiated format → a re-handshake in that
	// format is a valid conversation (echo).
	adopted, err := Handshake(HandshakeRequest{
		FormatVersion:      resp.FormatVersion,
		ModuleID:           "internal-loop",
		EntitlementVersion: resp.EntitlementVersion,
	})
	if err != nil || adopted != resp {
		t.Fatalf("adopted-format re-handshake diverged: %v / %+v vs %+v", err, adopted, resp)
	}
}

// TestHandshakeMalformedFailsClosedBeforeNegotiation: structurally malformed
// envelopes never reach negotiation — the zero value of the response is
// returned together with the structural error (no partial answer exists).
func TestHandshakeMalformedFailsClosedBeforeNegotiation(t *testing.T) {
	for _, req := range []HandshakeRequest{
		{},                                      // empty upstream: zero envelope
		{FormatVersion: "1"},                    // missing module id + entitlement version
		{FormatVersion: "1", ModuleID: " x"},    // module id padding
		{FormatVersion: "", ModuleID: "m"},      // missing format version
		{FormatVersion: "1\x00", ModuleID: "m"}, // control character
	} {
		resp, err := Handshake(req)
		if err == nil {
			t.Fatalf("malformed %+v negotiated a response %+v", req, resp)
		}
		if resp != (HandshakeResponse{}) {
			t.Fatalf("malformed %+v produced a partial answer %+v", req, resp)
		}
	}
}

// TestHandshakeIdempotent pins the replay/repetition variant: the seam is a
// pure function — repeating the identical handshake (a re-connecting module,
// a retried delivery) yields the byte-identical answer; a delayed handshake
// cannot go stale because no clock participates.
func TestHandshakeIdempotent(t *testing.T) {
	req := HandshakeRequest{
		FormatVersion:      HandshakeFormatVersion,
		ModuleID:           "internal-loop",
		EntitlementVersion: ModuleEntitlementVersion,
	}
	first, err := Handshake(req)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	for i := 0; i < 3; i++ {
		again, err := Handshake(req)
		if err != nil {
			t.Fatalf("repeated handshake %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("repeated handshake %d diverged: %+v vs %+v", i, again, first)
		}
	}
}
