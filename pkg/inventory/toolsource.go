package inventory

// E02-P01 wiring card: the production ToolSource adapter promised by
// W02-C01 — *mcpagg.Proxy.ListServerTools behind the importer's narrow
// seam.
//
// ListServerTools enforces the proxy's own posture: the grant check
// (authorizeGrant "list") plus the delegation-chain allowance for the
// identity's agent, and the SSRF re-validation of the server URL.
// Identity here is the IMPORTER's posture, not an end user's: tool
// listing is a background sync, so a deployment that wants tool assets
// configures an importer agent with list grants. With the zero identity
// (today's default wiring) every listing misses — the delegation chain
// for an empty agent is empty — and the importer's per-server miss
// handling (ServerImportResult.Error, ToolsSynced=false) reports that
// instead of failing the import. No well-known identity is invented
// here: grants are operator decisions. The operator item "wire an
// importer identity with list grants" rides the delivery record.

import (
	"context"

	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// ProxyToolSource adapts *mcpagg.Proxy to the importer's ToolSource
// seam. Identity is the fixed importer posture used for every listing
// (see the file comment); a zero Identity degrades to per-server misses
// — visible in the import report, never fatal.
type ProxyToolSource struct {
	Proxy    *mcpagg.Proxy
	Identity mcpagg.Identity
}

// Compile-time seam check.
var _ ToolSource = (*ProxyToolSource)(nil)

// ListTools lists one server's advertised tools through the proxy under
// the adapter's identity. A wiring defect (nil proxy) surfaces as an
// error the importer reports per-server, not a panic.
func (p *ProxyToolSource) ListTools(ctx context.Context, orgID, server string) ([]mcpagg.ToolDescriptor, error) {
	if p == nil || p.Proxy == nil {
		return nil, ErrNilSource
	}
	return p.Proxy.ListServerTools(ctx, orgID, p.Identity, server)
}
