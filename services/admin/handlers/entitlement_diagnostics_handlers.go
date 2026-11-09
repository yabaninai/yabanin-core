package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// E01-P05 W04-C02: root-only entitlement diagnostics for the admin API.
//
//	GET /api/entitlement/diagnostics
//
// The endpoint surfaces the SERVED license state (activation plane:
// active/grace/hard-expired, org, features, expiry instant) for operator
// observability. Strictly read-only: expiry posture is enforced in
// pkg/license and the service runners; this plane only reports, and an
// expiry verdict never gates the endpoint itself — a hard-expired
// deployment still answers 200 with its dark snapshot (operators need the
// diagnostics MOST when the entitlement is degraded).
//
// License boundary law (license_boundary_test.go, N04-P06): this package
// never imports pkg/license. The route reads the narrow snapshot interface
// below; services/run adapts *license.Server onto it (the single meeting
// point of the two packages).

// EntitlementDiagnosticsSnapshot is the wire shape of the served license
// state: a 1:1, derivation-free copy of the license State fields (handler
// casing), plus `configured` distinguishing «no license file armed» from
// «armed, but the activation plane is dark» (chain-only contours).
type EntitlementDiagnosticsSnapshot struct {
	Configured bool   `json:"configured"`
	Active     bool   `json:"active"`
	OrgID      string `json:"org_id"`
	// Seats mirrors the served state verbatim. It is inert legacy
	// metadata (cancelled by I22): read-only observability only — no UI,
	// API or enforcement may derive any account-count limit from it.
	Seats       int      `json:"seats"`
	Features    []string `json:"features"`
	Expired     bool     `json:"expired"`
	HardExpired bool     `json:"hard_expired"`
	ExpiresAt   string   `json:"expires_at"` // verbatim from the activation document; never parsed here
}

// EntitlementDiagnosticsSource is the capability the endpoint reads;
// implemented by services/run over *license.Server.
type EntitlementDiagnosticsSource interface {
	EntitlementDiagnostics() EntitlementDiagnosticsSnapshot
}

// SetEntitlementDiagnostics attaches the diagnostics source. nil/unset
// keeps the route mounted and answering 503 — honest absence (the route
// stays in the inventory either way).
func (h *AdminHandlers) SetEntitlementDiagnostics(src EntitlementDiagnosticsSource) {
	h.entitlementDiagnostics = src
}

// entitlementDiagnosticsAuditDetail is the audit journal payload. Always
// marshaled (never Sprintf'd) so values cannot corrupt the row. The
// snapshot's scalar verdicts ride the journal; features and org id do not
// (they are read back from the endpoint, not the log).
type entitlementDiagnosticsAuditDetail struct {
	Outcome     string `json:"outcome"`
	Configured  bool   `json:"configured"`
	Active      bool   `json:"active"`
	HardExpired bool   `json:"hard_expired"`
}

func (h *AdminHandlers) apiEntitlementDiagnostics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.entitlementDiagnostics == nil {
			h.respondError(w, r, errors.New("entitlement diagnostics unavailable"), http.StatusServiceUnavailable)
			return
		}
		snap := h.entitlementDiagnostics.EntitlementDiagnostics()
		if snap.Features == nil {
			snap.Features = []string{}
		}
		detail, err := json.Marshal(entitlementDiagnosticsAuditDetail{
			Outcome:     "allowed",
			Configured:  snap.Configured,
			Active:      snap.Active,
			HardExpired: snap.HardExpired,
		})
		if err != nil {
			// The struct is marshal-infallible; keep the journal write anyway.
			detail = []byte(`{"outcome":"allowed"}`)
		}
		h.auditLogAction(r, "entitlement_diagnostics", "license", string(detail))
		writeJSON(w, http.StatusOK, struct {
			Data EntitlementDiagnosticsSnapshot `json:"data"`
		}{Data: snap})
	}
}

// mountEntitlementDiagnostics registers the diagnostics route on the
// root-only group of mountRootAdmin (MustBeRoot chain). GET-only: there is
// deliberately no mutation on this plane.
func (h *AdminHandlers) mountEntitlementDiagnostics(r chi.Router) {
	r.Get("/api/entitlement/diagnostics", h.apiEntitlementDiagnostics())
}
