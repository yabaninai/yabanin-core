package handlers

// journal and the cross-org top-orgs aggregate).

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// mountAudit registers the audit journal and the cross-org aggregate views.
func (h *AdminHandlers) mountAudit(protected chi.Router) {
	// The audit journal is an org-AGGREGATE view: readable by root and
	// by the global security auditor (RequireGlobalAuditRead —
	// roles_authz.go). Any other org member stays at 403: a
	// non-root admin must not see other orgs' records).
	protected.Group(func(r chi.Router) {
		r.Use(h.RequireGlobalAuditRead())
		r.Get("/api/audit-logs", h.ListAuditLogs())
	})
	// The cross-org top-orgs aggregate stays root-only: it is spend data,
	// not an audit trail, so the security_auditor grant does not extend to
	// it; the security_auditor grant applies only to the audit route.
	protected.Group(func(r chi.Router) {
		r.Use(adminauth.MustBeRoot())
		r.Get("/api/analytics/top-orgs", h.apiTopOrgs())
	})
}
