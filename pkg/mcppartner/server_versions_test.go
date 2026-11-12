package mcp

// Partner-bridge protocol version matrix pin. The partner server delegates
// protocol-version handling to mcp-go v1.5.0: ValidProtocolVersions =
// {2026-07-28, 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05}. The modern
// 2026-07-28 revision removed the initialize handshake (stateless core,
// reached via server/discover), so initialize negotiation is
// legacy-echo-or-capped: legacy valid versions echo exactly; modern or
// unknown non-empty requests cap at the SDK's LATEST_LEGACY_PROTOCOL_VERSION
// (2025-11-25); a missing version falls back to the spec's assumed
// 2025-03-26.
//
// Pinned here so the cross-surface interop invariant stays executable:
// every version the NATIVE gateway endpoint offers (pkg/mcpserver
// version.go matrix: 2025-06-18, 2025-03-26) must remain a member of the
// SDK's initialize-negotiable legacy set — a client negotiated to any
// native version speaks a version this bridge accepts. If the native
// matrix bumps to a revision outside that set, this test fails (the
// interop tripwire).

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// nativeOfferedVersions mirrors pkg/mcpserver's protocolMatrix (unexported
// there; the interop tripwire is the point of the duplication — keep the
// two lists in sync or this test fails by design).
var nativeOfferedVersions = []string{"2025-06-18", "2025-03-26"}

// partnerInitVersion drives one SDK-level initialize and returns the
// negotiated protocolVersion plus the serverInfo identity.
func partnerInitVersion(t *testing.T, requested string) (string, string) {
	t.Helper()
	srv := NewMCPHandlerWithDelegation(NewGatewayClient("", "", "", ""), nil)
	params := map[string]any{
		"clientInfo": map[string]any{"name": "pin", "version": "0"},
	}
	if requested != "" {
		params["protocolVersion"] = requested
	}
	msg, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params,
	})
	if err != nil {
		t.Fatalf("marshal initialize: %v", err)
	}
	raw := srv.HandleMessage(context.Background(), msg)
	// HandleMessage returns a typed mcp.JSONRPCMessage (JSONRPCResponse for
	// success); marshal it to the wire shape and decode the initialize
	// result out of it. A non-nil Error field means the handshake failed.
	rawBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("initialize(%q) response not marshalable: %v (%T)", requested, err, raw)
	}
	var resp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rawBytes, &resp); err != nil {
		t.Fatalf("initialize(%q) response not decodable: %v (%s)", requested, err, rawBytes)
	}
	if resp.Error != nil || resp.Result.ProtocolVersion == "" {
		t.Fatalf("initialize(%q) failed: error=%+v raw=%s", requested, resp.Error, rawBytes)
	}
	return resp.Result.ProtocolVersion, resp.Result.ServerInfo.Name
}

// partnerVersionRow is one initialize-negotiation oracle: requested in,
// negotiated protocolVersion out.
type partnerVersionRow struct {
	requested string
	want      string
}

// partnerMatrixRows derives the negotiation table from the SDK's own sets.
// Modern protocol revisions removed the initialize handshake (stateless
// core, reached via server/discover, which this bridge does not expose), so
// initialize never negotiates them: modern and unknown non-empty requests
// cap at the SDK's LATEST_LEGACY_PROTOCOL_VERSION. A MISSING version is
// different: the SDK applies the spec's header-assumption rule (assume
// 2025-03-26) — an intentional asymmetry versus the native endpoint, whose
// missing initialize param falls back to its latest.
func partnerMatrixRows() []partnerVersionRow {
	rows := make([]partnerVersionRow, 0, len(mcp.ValidProtocolVersions)+4)
	for _, v := range mcp.LegacyProtocolVersions() {
		rows = append(rows, partnerVersionRow{requested: v, want: v})
	}
	for _, v := range mcp.ValidProtocolVersions {
		if mcp.IsModernProtocol(v) {
			rows = append(rows, partnerVersionRow{requested: v, want: mcp.LATEST_LEGACY_PROTOCOL_VERSION})
		}
	}
	for _, v := range []string{"1999-01-01", "2030-01-01", "garbage"} {
		rows = append(rows, partnerVersionRow{requested: v, want: mcp.LATEST_LEGACY_PROTOCOL_VERSION})
	}
	return append(rows, partnerVersionRow{requested: "", want: "2025-03-26"})
}

// TestPartnerVersionMatrix pins the SDK-side negotiation: every legacy
// SDK-valid version echoes exactly; modern and unknown non-empty requests
// cap at the SDK's latest legacy version (explicit, never an echo of the
// requested value). The serverInfo identity is asserted on every row.
func TestPartnerVersionMatrix(t *testing.T) {
	// The initialize-negotiable ceiling must itself be a known version.
	if !slices.Contains(mcp.ValidProtocolVersions, mcp.LATEST_LEGACY_PROTOCOL_VERSION) {
		t.Fatalf("SDK latest legacy %q not a member of its own valid set", mcp.LATEST_LEGACY_PROTOCOL_VERSION)
	}
	for _, row := range partnerMatrixRows() {
		got, name := partnerInitVersion(t, row.requested)
		if got != row.want {
			t.Fatalf("initialize(%q) negotiated to %q, want %q", row.requested, got, row.want)
		}
		if name != "yabanin-mcp" {
			t.Fatalf("initialize(%q) serverInfo.name = %q, want yabanin-mcp", row.requested, name)
		}
	}
}

// TestPartnerAcceptsEveryNativeVersion is the cross-surface interop tripwire: the
// native gateway endpoint's offered matrix must stay inside the bridge's
// SDK valid set (see the file comment).
func TestPartnerAcceptsEveryNativeVersion(t *testing.T) {
	for _, v := range nativeOfferedVersions {
		// The native matrix must stay inside the bridge's initialize-
		// negotiable set: a native bump to a modern-only revision would be
		// valid to the SDK but silently downgraded by the bridge.
		if !slices.Contains(mcp.LegacyProtocolVersions(), v) {
			t.Fatalf("native-offered version %q is NOT in the partner SDK legacy set %v — native matrix bumped past the SDK (interop tripwire)", v, mcp.ValidProtocolVersions)
		}
		got, _ := partnerInitVersion(t, v)
		if got != v {
			t.Fatalf("native version %q not echoed by the bridge (got %q)", v, got)
		}
	}
}
