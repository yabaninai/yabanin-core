// Supported MCP protocol version matrix — the single source of truth for
// every protocol-version decision on the native Streamable HTTP endpoint.
// The initialize negotiation, the follow-up
// MCP-Protocol-Version header check and the version consts all derive from
// this one list, so a future bump (e.g. adding 2025-11-25) is a one-point
// change: prepend the new revision here.
//
// Matrix (newest first):
//
//	2025-06-18  latest    current Streamable HTTP revision (offered)
//	2025-03-26  previous  clients pinned to the earlier revision (offered)
//
// Negotiation contract (spec 2025-06-18, basic/lifecycle):
//
//   - initialize: a requested version that is IN the matrix is echoed back;
//     anything else (unknown, older, newer, missing, garbage) gets the
//     server's latest. The response always names a version the server
//     implements — it never echoes a version outside the matrix (no silent
//     downgrade, no false claim); a client that cannot speak the returned
//     version disconnects and re-initializes.
//   - follow-ups: an MCP-Protocol-Version header value outside the matrix is
//     rejected with HTTP 400 (strict rejection point, server.go servePost);
//     an absent header is accepted for stateless clients.
package mcpserver

// protocolMatrix lists the supported MCP protocol versions, newest first.
// Element [0] is the server's latest (the negotiation fallback); elements
// are also exactly the values accepted in the MCP-Protocol-Version header.
// A future revision bump edits the two consts and this list together —
// TestProtocolMatrixWellFormed pins the invariants (newest-first ordering,
// no duplicates, consts == matrix edges).
var protocolMatrix = []string{
	"2025-06-18", // latest — current Streamable HTTP revision
	"2025-03-26", // previous — clients pinned to the earlier revision
}

// Protocol version consts (all other package code references these names).
const (
	protocolVersionLatest   = "2025-06-18"
	protocolVersionPrevious = "2025-03-26"
)

// supportedProtocolVersion reports whether v is one of the offered versions.
func supportedProtocolVersion(v string) bool {
	for _, m := range protocolMatrix {
		if v == m {
			return true
		}
	}
	return false
}

// negotiateProtocolVersion resolves the initialize handshake result: the
// requested version when it is supported (exact echo), otherwise the
// server's latest. The return value is always an element of protocolMatrix —
// the response never claims a version the endpoint does not implement.
func negotiateProtocolVersion(requested string) string {
	if supportedProtocolVersion(requested) {
		return requested
	}
	return protocolVersionLatest
}
