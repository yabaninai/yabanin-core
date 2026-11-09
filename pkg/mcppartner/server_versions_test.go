package mcp

// Partner-bridge protocol version matrix pin. The partner server delegates
// protocol-version handling to mcp-go v0.57.0: ValidProtocolVersions =
// {2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05}, negotiation =
// echo-or-latest (unknown/missing → the SDK's LATEST_PROTOCOL_VERSION,
// 2025-11-25).
//
// Pinned here so the cross-surface interop invariant stays executable:
// every version the NATIVE gateway endpoint offers (pkg/mcpserver
// version.go matrix: 2025-06-18, 2025-03-26) must remain a member of the
// SDK's valid set — a client negotiated to any native version speaks a
// version this bridge accepts. If the native matrix bumps to a revision
// outside the SDK set, this test fails (the interop tripwire).

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

// TestPartnerVersionMatrix pins the SDK-side negotiation: every SDK-valid
// version echoes exactly; unknown and missing requests fall back to the
// SDK's latest (explicit, never an echo of the unknown value).
func TestPartnerVersionMatrix(t *testing.T) {
	if !slices.Contains(mcp.ValidProtocolVersions, mcp.LATEST_PROTOCOL_VERSION) {
		t.Fatalf("SDK latest %q not a member of its own valid set", mcp.LATEST_PROTOCOL_VERSION)
	}
	for _, v := range mcp.ValidProtocolVersions {
		got, name := partnerInitVersion(t, v)
		if got != v {
			t.Fatalf("SDK-valid %q negotiated to %q, want exact echo", v, got)
		}
		if name != "yabanin-mcp" {
			t.Fatalf("serverInfo.name = %q, want yabanin-mcp", name)
		}
	}
	// Unknown non-empty requests fall back to the SDK's latest — explicit,
	// never an echo of the unknown value. A MISSING version is different:
	// the SDK applies the spec's header-assumption rule (no version
	// identifier available → assume 2025-03-26), an intentional asymmetry
	// versus the native endpoint, whose missing initialize param falls back
	// to its latest (pkg/mcpserver negotiateProtocolVersion).
	for _, requested := range []string{"1999-01-01", "2030-01-01", "garbage"} {
		got, _ := partnerInitVersion(t, requested)
		if got != mcp.LATEST_PROTOCOL_VERSION {
			t.Fatalf("unknown %q negotiated to %q, want explicit SDK latest %q", requested, got, mcp.LATEST_PROTOCOL_VERSION)
		}
	}
	if got, _ := partnerInitVersion(t, ""); got != "2025-03-26" {
		t.Fatalf("missing version negotiated to %q, want the spec's assumed %q", got, "2025-03-26")
	}
}

// TestPartnerAcceptsEveryNativeVersion is the cross-surface interop tripwire: the
// native gateway endpoint's offered matrix must stay inside the bridge's
// SDK valid set (see the file comment).
func TestPartnerAcceptsEveryNativeVersion(t *testing.T) {
	for _, v := range nativeOfferedVersions {
		if !slices.Contains(mcp.ValidProtocolVersions, v) {
			t.Fatalf("native-offered version %q is NOT in the partner SDK valid set %v — native matrix bumped past the SDK (interop tripwire)", v, mcp.ValidProtocolVersions)
		}
		got, _ := partnerInitVersion(t, v)
		if got != v {
			t.Fatalf("native version %q not echoed by the bridge (got %q)", v, got)
		}
	}
}
