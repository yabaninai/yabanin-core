package run

import (
	"context"

	"github.com/reireirei/yabanin/pkg/license"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// E01-P05 W04-C02: admin entitlement diagnostics — the ONLY place the
// license Server meets the admin API. The admin plane sees the narrow
// snapshot interface (license_boundary_test.go stays green: the handlers
// package never imports pkg/license).
//
// Honest-dark semantics: in chain-only contours (a license file verified at
// startup but carrying no activation document) Server.State() is the zero
// State, and the snapshot reports configured=true with everything dark —
// that IS the truth: the activation plane is dark there. The chain gate is
// a startup fact (RunAdmin refuses to boot on an invalid chain), not a
// runtime state to serve.

// adminEntitlementDiagnostics adapts *license.Server (periodic
// re-verification, in-memory state) to the admin diagnostics interface.
type adminEntitlementDiagnostics struct {
	srv        *license.Server
	configured bool
}

// newAdminEntitlementDiagnostics starts the license server. An empty
// tokenPath is the unconfigured contour: NewServer keeps the zero State and
// the refresh loop is a no-op (no file reads), so the endpoint serves
// configured=false with the all-dark snapshot.
func newAdminEntitlementDiagnostics(tokenPath string) *adminEntitlementDiagnostics {
	return &adminEntitlementDiagnostics{
		srv:        license.NewServer(tokenPath),
		configured: tokenPath != "",
	}
}

// EntitlementDiagnostics implements handlers.EntitlementDiagnosticsSource.
func (a *adminEntitlementDiagnostics) EntitlementDiagnostics() handlers.EntitlementDiagnosticsSnapshot {
	return mapLicenseState(a.configured, a.srv.State())
}

// mapLicenseState is the pure State→snapshot mapper: 1:1, no derivation,
// no clock, no license semantics — the handler plane receives exactly what
// the server verified. Unit-tested with literal license.State values: in
// chain-only contours Server can only ever yield the zero State, so the
// non-zero arms are pinned here rather than through a live server.
func mapLicenseState(configured bool, st license.State) handlers.EntitlementDiagnosticsSnapshot {
	return handlers.EntitlementDiagnosticsSnapshot{
		Configured:  configured,
		Active:      st.Active,
		OrgID:       st.OrgID,
		Seats:       st.Seats,
		Features:    st.Features,
		Expired:     st.Expired,
		HardExpired: st.HardExpired,
		ExpiresAt:   st.ExpiresAt,
	}
}

// Close stops the license re-verification loop (idempotent; safe at
// shutdown alongside the other RunAdmin resources).
func (a *adminEntitlementDiagnostics) Close(ctx context.Context) { a.srv.Close(ctx) }
