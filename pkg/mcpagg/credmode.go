package mcpagg

// N05-P02-T04 (MCP: service credentials and delegated access — CHOOSE): the
// proxy consults a CredModePolicy per call and refuses to egress when the
// resolved credential layer violates the policy-selected mode. This is the
// enforcement half of "the choice is set by the connection setting AND the
// policy" (owner decision I54): the connection-config mode (migration 0016)
// remains the default; a policy row can pin service/delegated/auto for a
// (subject, server, tool) tuple, and the pin is ENFORCED — a delegated pin
// must never silently run on the org's (stronger) service credential and
// vice versa.
//
// Security invariants:
//   - Fail-closed on every unverifiable state: a selector error, an unknown
//     mode value, a credential source that cannot report the layer of its
//     resolved credential, or a resolved layer outside the closed
//     {"", user, server} vocabulary refuses the call. No silent fallback,
//     in either direction.
//   - A call with NO resolved credential (level "") is a miss, not a
//     violation: the legacy unauthenticated posture stands and the upstream
//     verdict decides (mcp_auth_required on 401/403) — the same boundary the
//     MC-2 resolver already draws. Gateway entry is not external-server
//     authorization (I54): no gateway principal material is ever forwarded
//     as an external credential; the external server's own verdict decides.
//   - No credential material crosses this layer: it only sees layer labels.
//
// N05-P02-T05 pins the packet negative («сбой пользовательской авторизации
// не переключается молча на более сильные service credentials») as a
// reproducible scenario suite: credmode_negative_test.go. Every behavioral
// claim there is mutation-verified (revert the enforcement → RED).

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// Credential layers: WHICH secured storage row produced the resolved
// credential (the adminstore credential tables are the secured storage —
// encrypted at rest, plaintext only inside the resolver for one attempt).
// A CredSource that cannot say which layer served the call reports "".
const (
	CredLevelUser   = "user"   // the agent principal's own (delegated) credential
	CredLevelServer = "server" // the org's service credential
)

// credModeConstrained reports whether a policy-selected mode constrains the
// call (auto and "" are explicit/implicit no-constraint).
func credModeConstrained(mode string) bool {
	return mode == CredModeService || mode == CredModeDelegated
}

// credModeViolation reports whether a credential resolved at the given
// layer violates the policy-selected mode. "" (no credential) is never a
// violation — that is the miss path, decided by the upstream verdict.
// N05-P02-T05: any OTHER unrecognized layer is a violation under a pin
// (fail-closed). T04's review (F-2) recorded the seam contract that a wired
// LevelAwareCredSource must report only {"", user, server}; the proxy no
// longer TRUSTS that contract — a source that reports an unrecognizable
// layer (e.g. the credential kind in the level slot) can never silently
// egress under a pin, so a wiring mistake fails loudly instead of passing.
func credModeViolation(mode, level string) bool {
	switch mode {
	case CredModeService:
		return level != "" && level != CredLevelServer
	case CredModeDelegated:
		return level != "" && level != CredLevelUser
	default:
		return false
	}
}

// CredModePolicy selects the credential mode for one call (N05-P02-T04).
// Returned mode: "", CredModeAuto (no constraint), CredModeService or
// CredModeDelegated. An error is fail-closed: the caller refuses the invoke
// rather than proceeding with the connection-config mode — a policy-store
// outage must not silently drop a delegated pin onto the service layer.
type CredModePolicy interface {
	SelectCredentialMode(ctx context.Context, orgID, server, tool, subject string) (mode string, err error)
}

// LevelAwareCredSource is the optional N05-P02-T04 extension of CredSource:
// resolution that also reports WHICH layer (CredLevelUser / CredLevelServer,
// "" = none) produced the credential. Sources that do not implement it keep
// working unchanged — but a CONSTRAINED call against such a source is
// refused fail-closed, because the layer constraint cannot be verified.
// Wired by the gateway credential source (T06 integration); until then the
// proxy enforces only when both a mode policy and a level-aware source are
// present, and every wired-but-unverifiable combination refuses.
type LevelAwareCredSource interface {
	CredSource

	// AuthHeadersLevel resolves like AuthHeaders and additionally reports
	// the layer that produced the credential.
	AuthHeadersLevel(ctx context.Context, orgID, serverName, agentID string) (headers map[string][]string, kind, level string, err error)

	// OnUpstreamUnauthorizedLevel is OnUpstreamUnauthorized with layer
	// reporting: the refreshed credential carries its layer so the retry is
	// held to the same policy constraint as the first attempt.
	OnUpstreamUnauthorizedLevel(ctx context.Context, orgID, serverName, agentID, credKind string) (headers map[string][]string, kind, level string, retry bool, err error)
}

// ToolpolicyCredModes adapts the shared toolpolicy engine to CredModePolicy:
// the specificity winner among mode-carrying policy rows matching
// (subject, server, tool). The gateway wires it via
// WithCredModePolicy(NewToolpolicyCredModes(engine)) (T06 integration).
type ToolpolicyCredModes struct {
	engine *toolpolicy.Engine
}

// NewToolpolicyCredModes builds a CredModePolicy over the toolpolicy engine.
func NewToolpolicyCredModes(engine *toolpolicy.Engine) *ToolpolicyCredModes {
	return &ToolpolicyCredModes{engine: engine}
}

// SelectCredentialMode implements CredModePolicy. Errors (loader outage,
// uncompilable matching row) propagate — the proxy fails closed on them.
func (t *ToolpolicyCredModes) SelectCredentialMode(ctx context.Context, orgID, server, tool, subject string) (string, error) {
	mode, _, err := t.engine.DecideCredMode(ctx, orgID, subject, server, tool)
	return mode, err
}

// normalizeCredMode validates the selector's answer against the closed
// vocabulary. An unknown value is an error (fail-closed), not a silent
// no-constraint.
func normalizeCredMode(mode string) (string, error) {
	switch mode {
	case "", CredModeAuto, CredModeService, CredModeDelegated:
		return mode, nil
	default:
		return "", fmt.Errorf("mcpagg: credential mode %q is not in the closed vocabulary", mode)
	}
}
