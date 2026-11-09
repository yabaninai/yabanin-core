package license

import (
	"fmt"
	"strings"
)

// Plugin handshake contract (E01-P05-W01-C01): the versioned first exchange
// between the core and a connecting module (plugin). It is the connection
// seam for offline entitlement: BEFORE any entitlement document is verified
// or any module feature is consulted, both sides state which handshake
// envelope format and which entitlement document format they speak, so a
// version skew is detected at the seam instead of surfacing later as a
// misparsed document or a silently-ignored grant.
//
// Scope of this file (card boundary): the CONTRACT ONLY — envelope types,
// the format-version constant and structural validation. Version
// NEGOTIATION (the supported-format matrix and the echo-or-latest decision,
// mirroring the mcpserver protocol-version precedent) is a separate card and
// lives in handshake_negotiate.go; nothing here picks a version.
//
// Boundary posture (EntitlementSource and module_entitlement precedents):
//   - Pure data + pure functions: no clock, no network, no filesystem. The
//     handshake is offline by construction, exactly like every other
//     verification path in this package.
//   - Additive core-Apache SPI: no enterprise/ path is imported or activated;
//     a connecting module remains a consumer of this package, never the
//     reverse (importboundary sentinel).
//   - The handshake carries NO authorization decision. Entitlement (what is
//     issued) and authorization (what the caller may do) stay separated:
//     answering "which format do you speak" grants nothing (E01-P05-W02).
//
// Versioning law (ModuleEntitlementVersion precedent, module_entitlement.go):
// exactly one handshake envelope format exists today ("1"). A future format
// change bumps HandshakeFormatVersion and the negotiation matrix together as
// a one-point change; an envelope naming an unknown format version is never
// half-accepted — structural validation (here) passes it as well-formed, and
// the negotiation layer (handshake_negotiate.go) rejects/answers it without
// ever claiming an unimplemented version.

// HandshakeFormatVersion is the handshake envelope format version this core
// speaks: the only format the negotiation matrix offers today. It versions
// the HandshakeRequest/HandshakeResponse envelope itself (field semantics,
// validation rules) and is INDEPENDENT of ModuleEntitlementVersion, which
// versions the entitlement document carried behind the handshake. The two
// version constants evolve on their own schedules; the response names both.
const HandshakeFormatVersion = "1"

// Version field limits (fail-closed shape checks; a version is a short
// opaque token like "1", "2", never prose). Mirrors the tight limits of the
// secevents schema IDs: catch garbage early, keep envelopes small.
const (
	// handshakeVersionMaxLen bounds FormatVersion/EntitlementVersion.
	handshakeVersionMaxLen = 64
	// handshakeModuleIDMaxLen bounds ModuleID.
	handshakeModuleIDMaxLen = 256
)

// HandshakeRequest is the envelope a connecting module sends to the core at
// plugin-connection time. All fields are required and structurally validated
// by ValidateHandshakeRequest; version POLICY (known vs unknown) is decided
// by the negotiation layer, not here.
type HandshakeRequest struct {
	// FormatVersion is the handshake envelope format the client speaks
	// (HandshakeFormatVersion vocabulary).
	FormatVersion string `json:"format_version"`
	// ModuleID identifies the connecting module (vendor-issued vocabulary,
	// same naming discipline as PaidModuleEntitlement.Modules: exact
	// strings, membership is all a consumer may rely on). It identifies the
	// speaker for diagnostics and audit; it grants nothing by itself.
	ModuleID string `json:"module_id"`
	// EntitlementVersion is the module-entitlement DOCUMENT format the
	// client was built against (ModuleEntitlementVersion vocabulary). The
	// response echoes the core's own value so both sides see the skew.
	EntitlementVersion string `json:"entitlement_version"`
}

// HandshakeResponse is the core's answer. Built by the negotiation layer
// (handshake_negotiate.go); validated by ValidateHandshakeResponse.
type HandshakeResponse struct {
	// FormatVersion is the handshake envelope format the core speaks in
	// this conversation. The negotiation law guarantees it is a format the
	// core actually implements — never an echo of an unknown request value.
	FormatVersion string `json:"format_version"`
	// EntitlementVersion is the module-entitlement document format this
	// core verifies (ModuleEntitlementVersion). A client built against a
	// different document version sees the skew HERE, at the seam, instead
	// of misparsing documents later.
	EntitlementVersion string `json:"entitlement_version"`
}

// ValidateHandshakeRequest checks the STRUCTURAL validity of a request
// envelope: every field present, shaped and bounded. It performs no version
// policy (an unknown-but-well-formed FormatVersion validates OK here and is
// answered by the negotiation layer), no clock and no I/O. Fail-closed: the
// zero value and every malformed payload are rejected.
func ValidateHandshakeRequest(req HandshakeRequest) error {
	if err := validateHandshakeVersion("format_version", req.FormatVersion); err != nil {
		return err
	}
	if req.ModuleID == "" {
		return fmt.Errorf("handshake: module_id is required")
	}
	if len(req.ModuleID) > handshakeModuleIDMaxLen {
		return fmt.Errorf("handshake: module_id exceeds %d bytes", handshakeModuleIDMaxLen)
	}
	if strings.TrimSpace(req.ModuleID) != req.ModuleID {
		return fmt.Errorf("handshake: module_id must not have leading/trailing whitespace")
	}
	if err := validateHandshakeVersion("entitlement_version", req.EntitlementVersion); err != nil {
		return err
	}
	return nil
}

// ValidateHandshakeResponse checks the structural validity of a response
// envelope plus the two invariants that must hold for ANY honest core
// answer, whatever the negotiated format version turns out to be:
//   - the entitlement document version is exactly ModuleEntitlementVersion
//     (the version-pin law: this core verifies "2" and nothing else — a
//     response naming any other value is not a shape the core can produce);
//   - the format version is structurally valid (membership in the supported
//     matrix is the negotiation layer's contract, pinned there).
func ValidateHandshakeResponse(resp HandshakeResponse) error {
	if err := validateHandshakeVersion("format_version", resp.FormatVersion); err != nil {
		return err
	}
	if resp.EntitlementVersion != ModuleEntitlementVersion {
		return fmt.Errorf("handshake: entitlement_version %q: this core verifies %q only", resp.EntitlementVersion, ModuleEntitlementVersion)
	}
	return nil
}

// validateHandshakeVersion applies the shared version-token shape law:
// non-empty, bounded, no interior control characters or whitespace. This is
// deliberately stricter than "printable": a version token is an opaque
// vocabulary item like "1" — prose, padding and control bytes are garbage.
func validateHandshakeVersion(field, v string) error {
	if v == "" {
		return fmt.Errorf("handshake: %s is required", field)
	}
	if len(v) > handshakeVersionMaxLen {
		return fmt.Errorf("handshake: %s exceeds %d bytes", field, handshakeVersionMaxLen)
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("handshake: %s must not have leading/trailing whitespace", field)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("handshake: %s must not contain control characters", field)
		}
	}
	return nil
}
