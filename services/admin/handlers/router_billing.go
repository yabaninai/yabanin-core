package handlers

// the root-only money surface: spend alerts, pricing CRUD, reseller credits
// and resale pricing (PR1).

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// initBillingHandlers constructs the PR1 reseller-billing handler structs
// when their stores are wired. Called by SetupRouter before any mount
// registers routes, mirroring the original construction point.
func (h *AdminHandlers) initBillingHandlers() {
	// PR1: Initialize reseller billing handlers if credits store is available.
	if h.billing.creditStore != nil {
		h.billing.credit = NewCreditHandlers(h.billing.creditStore, h.logger)
		// The credit audit needs the full-record journal capability
		// (InsertAuditLogEntry) — the reason would be dropped by the legacy
		// v1 wrapper. Type-asserted like AuditJournalStore; stores without
		// the capability run with audit disabled (fireAuditLog no-ops).
		if aj, ok := h.store.(auditInsertLogger); ok {
			h.billing.credit.SetAuditLogger(aj, h.trustedProxies)
		}
		h.billing.lowBalance = h.billing.credit.HandleLowBalance
	}
	if h.billing.resalePricingPool != nil {
		h.billing.resale = NewResalePricingHandlers(h.billing.resalePricingPool, h.logger)
	}
}

// mountBilling registers the org-permission-gated billing routes.
func (h *AdminHandlers) mountBilling(protected chi.Router) {
	budgets := protected.With(h.RequireOrgPermission(adminstore.PermBudgetsManage))
	budgets.Get("/api/teams/{id}/budget", h.GetTeamBudget())
	budgets.Put("/api/teams/{id}/budget", h.UpsertTeamBudget())
	budgets.Delete("/api/teams/{id}/budget", h.DeleteTeamBudget())
	budgets.Get("/api/organizations/{id}/team-budgets", h.ListOrgTeamBudgets())

	// W-CRED: the org-scoped wallet reads move off the root-only surface to
	// the org-admin view (budgets.manage on the target org; foreign-org
	// wallets 404, members without the permission 403, root passes). The
	// top-up stays a root-only operator action below.
	if h.billing.credit != nil {
		creditsRead := protected.With(h.RequireOrgPermissionCreditsRead())
		creditsRead.Get("/api/orgs/{id}/credits/balance", h.billing.credit.HandleGetBalance)
		creditsRead.Get("/api/orgs/{id}/credits/transactions", h.billing.credit.HandleGetTransactions)
	}
}

// mountBillingRoot registers the root-only billing surface on the root CRUD
// group: spend alerts, pricing CRUD, reseller credits, low-balance report
// and resale pricing. The PR1 groups mount only when the corresponding
// handlers were constructed by initBillingHandlers.
func (h *AdminHandlers) mountBillingRoot(r chi.Router) {
	// Spend alerts per organization (root-only) — P6.9
	r.Get("/api/organizations/{id}/spend-alert", h.GetOrgSpendAlertSettings())
	r.Patch("/api/organizations/{id}/spend-alert", h.UpdateOrgSpendAlertSettings())

	// P6.4: Pricing CRUD (root-only)
	r.Get("/api/pricing", h.ListPricingHandler())
	r.Post("/api/pricing", h.CreatePricingHandler())
	r.Post("/api/pricing/import", h.ImportPricingHandler())
	r.Put("/api/pricing/{id}", h.UpdatePricingHandler())
	r.Delete("/api/pricing/{id}", h.DeletePricingHandler())
	r.Get("/api/pricing/export.csv", h.ExportPricingCSVHandler())

	// PR1: Reseller billing endpoints (root-only operator surface). The
	// wallet READS moved to the org-permission group (W-CRED, mountBilling).
	if h.billing.credit != nil {
		r.Post("/api/orgs/{id}/credits/topup", h.billing.credit.HandleTopUp)
	}
	if h.billing.lowBalance != nil {
		r.Get("/api/credits/low-balance", h.billing.lowBalance)
	}
	if h.billing.resale != nil {
		r.Put("/api/orgs/{id}/resale-pricing", h.billing.resale.HandleCreateOrUpdateResalePricing)
		r.Get("/api/reseller-pricing", h.billing.resale.HandleListResalePricing)
		r.Get("/api/reseller-pricing/{id}", h.billing.resale.HandleGetResalePricing)
		r.Delete("/api/reseller-pricing/{id}", h.billing.resale.HandleDeleteResalePricing)
		r.Get("/api/orgs/{id}/resale-pricing", h.billing.resale.HandleGetOrgResalePricing)
	}
}
