package license

// Handshake version negotiation (E01-P05-W01-C02): resolves which handshake
// envelope format a connection speaks, on the exact precedent of the MCP
// protocol-version negotiation (pkg/mcpserver/version.go:32/:44/:57 —
// matrix, membership, echo-or-latest):
//
//   - a requested format version that is IN the matrix is echoed back;
//   - anything else (unknown, older-than-supported, newer, missing, garbage)
//     is answered with the core's latest — the response always names a
//     format the core actually implements, never an echo of an unknown value
//     (no silent downgrade, no false claim); a module that cannot speak the
//     returned version must not proceed to entitlement verification;
//   - the entitlement DOCUMENT version is not negotiated: the response
//     carries exactly ModuleEntitlementVersion (the version-pin law), so a
//     document-format skew is visible at the seam instead of surfacing later
//     as a misparsed or silently-half-accepted document.
//
// The full seam door is Handshake: structural validation (handshake.go)
// followed by negotiation. It is a pure function of the request envelope —
// no clock, no I/O, no state — so a repeated handshake is byte-identical
// (idempotent) and a delayed handshake answer never goes stale.
//
// Connection posture: additive, currently unmounted SPI (the license.Server
// and pkg/ocsf precedents: the core defines the seam, consumers arrive in
// later cards). No core code grants anything by speaking the handshake.

// handshakeFormatMatrix lists the supported handshake envelope formats,
// newest first. Element [0] is the core's latest (the negotiation fallback).
// A future format bump edits HandshakeFormatVersion and this list together —
// TestHandshakeFormatMatrixWellFormed pins the invariants (newest-first
// ordering, no duplicates, const == matrix edge).
var handshakeFormatMatrix = []string{
	HandshakeFormatVersion, // latest — the only envelope format today
}

// handshakeFormatLatest is the core's newest supported envelope format
// (matrix element [0]; the negotiation fallback).
const handshakeFormatLatest = HandshakeFormatVersion

// supportedHandshakeFormat reports whether v is one of the offered envelope
// formats. Mirrors mcpserver.supportedProtocolVersion.
func supportedHandshakeFormat(v string) bool {
	for _, m := range handshakeFormatMatrix {
		if v == m {
			return true
		}
	}
	return false
}

// negotiateHandshakeFormat resolves the handshake envelope version: the
// requested version when it is supported (exact echo), otherwise the core's
// latest. The return value is always an element of handshakeFormatMatrix —
// the response never claims a format the core does not implement. Mirrors
// mcpserver.negotiateProtocolVersion.
func negotiateHandshakeFormat(requested string) string {
	if supportedHandshakeFormat(requested) {
		return requested
	}
	return handshakeFormatLatest
}

// Handshake is the connection seam door: it structurally validates the
// request envelope (fail-closed on malformed payloads — an unparseable or
// incomplete handshake never reaches negotiation) and answers with the
// negotiated envelope format plus this core's entitlement document version.
// Pure and idempotent: the same request always yields the same response.
func Handshake(req HandshakeRequest) (HandshakeResponse, error) {
	if err := ValidateHandshakeRequest(req); err != nil {
		return HandshakeResponse{}, err
	}
	return HandshakeResponse{
		FormatVersion:      negotiateHandshakeFormat(req.FormatVersion),
		EntitlementVersion: ModuleEntitlementVersion,
	}, nil
}
