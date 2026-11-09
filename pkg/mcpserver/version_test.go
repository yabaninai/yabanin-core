package mcpserver

// Unit pins for the supported protocol version matrix. The matrix
// invariants + the negotiate decision table live here; the
// wire-level reproducibility pins live in negotiate_test.go.

import (
	"fmt"
	"slices"
	"testing"
)

// TestProtocolMatrixWellFormed pins the matrix invariants that the rest of
// the protocol layer relies on:
//   - non-empty, no duplicates;
//   - newest-first ordering (MCP versions are ISO-style dates, so the
//     lexicographic order is the chronological order);
//   - the consts equal the matrix edges (protocolVersionLatest = [0] is the
//     negotiation fallback; protocolVersionPrevious is the oldest offer).
func TestProtocolMatrixWellFormed(t *testing.T) {
	if len(protocolMatrix) == 0 {
		t.Fatal("protocolMatrix is empty")
	}
	seen := map[string]bool{}
	for i, v := range protocolMatrix {
		if v == "" {
			t.Fatalf("protocolMatrix[%d] is empty", i)
		}
		if seen[v] {
			t.Fatalf("duplicate matrix entry %q", v)
		}
		seen[v] = true
		if i > 0 && protocolMatrix[i-1] <= v {
			t.Fatalf("matrix not newest-first at %d: %q <= %q", i, protocolMatrix[i-1], v)
		}
	}
	if protocolMatrix[0] != protocolVersionLatest {
		t.Fatalf("protocolVersionLatest = %q, matrix[0] = %q", protocolVersionLatest, protocolMatrix[0])
	}
	if protocolMatrix[len(protocolMatrix)-1] != protocolVersionPrevious {
		t.Fatalf("protocolVersionPrevious = %q, matrix last = %q",
			protocolVersionPrevious, protocolMatrix[len(protocolMatrix)-1])
	}
	// Both surface consts must be matrix members themselves (they are the
	// advertised offers; a const outside the matrix would negotiate a
	// version the endpoint claims not to implement).
	for _, c := range []string{protocolVersionLatest, protocolVersionPrevious} {
		if !slices.Contains(protocolMatrix, c) {
			t.Fatalf("const %q is not a matrix member", c)
		}
	}
}

// TestSupportedProtocolVersion pins the membership check for every matrix
// entry and the rejection classes.
func TestSupportedProtocolVersion(t *testing.T) {
	for _, v := range protocolMatrix {
		if !supportedProtocolVersion(v) {
			t.Fatalf("matrix member %q not recognized as supported", v)
		}
	}
	for _, v := range []string{
		"2025-11-25", // newer than the offered set (SDK-side latest)
		"2024-11-05", // older spec revision, never offered natively
		"1999-01-01", // unknown
		"",           // missing
		"latest",     // not a date form
		"2025-6-18",  // wrong spelling of a supported version
		" 2025-06-18",
		"2025-06-18 ",
	} {
		if supportedProtocolVersion(v) {
			t.Fatalf("unsupported version %q accepted", v)
		}
	}
}

// TestNegotiateProtocolVersion pins the initialize decision table. The
// invariant under the card's negative cell: the result is ALWAYS a matrix
// member — the server never echoes a version it does not implement and
// never silently downgrades to an unoffered revision.
func TestNegotiateProtocolVersion(t *testing.T) {
	for _, tc := range []struct {
		requested string
		want      string
	}{
		// Exact echoes.
		{protocolVersionLatest, protocolVersionLatest},
		{protocolVersionPrevious, protocolVersionPrevious},
		// Everything else falls back to the server's latest — explicitly.
		{"2025-11-25", protocolVersionLatest}, // newer (SDK-side latest)
		{"2024-11-05", protocolVersionLatest}, // older spec revision
		{"1999-01-01", protocolVersionLatest}, // unknown
		{"", protocolVersionLatest},           // missing param
		{"garbage", protocolVersionLatest},
		{"2025-6-18", protocolVersionLatest}, // near-miss spelling
	} {
		got := negotiateProtocolVersion(tc.requested)
		if got != tc.want {
			t.Fatalf("negotiate(%q) = %q, want %q", tc.requested, got, tc.want)
		}
		if !slices.Contains(protocolMatrix, got) {
			t.Fatalf("negotiate(%q) returned %q which is outside the matrix (silent downgrade/false claim)", tc.requested, got)
		}
	}
}

// TestNegotiateNeverEchoesUnknownProperty: a property-style check over a
// spread of unknown inputs — negotiation output is closed over the matrix.
func TestNegotiateNeverEchoesUnknownProperty(t *testing.T) {
	unknowns := []string{
		"2025-12-25", "2026-01-01", "2024-11-05", "2023-06-01", "1970-01-01",
		"9999-09-09", "x", "2025-06-18-extra", "2025-03-26, 2025-06-18",
		fmt.Sprintf("%s\r\nX-Injected: yes", protocolVersionLatest), // header-injection shape
	}
	for _, u := range unknowns {
		if got := negotiateProtocolVersion(u); !slices.Contains(protocolMatrix, got) {
			t.Fatalf("negotiate(%q) = %q escapes the matrix", u, got)
		}
	}
}
