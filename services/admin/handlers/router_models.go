package handlers

// routing rules and the sovereign model marketplace.

import (
	"github.com/go-chi/chi/v5"
)

// mountModels registers the root-only model/routing surface on the root
// CRUD group.
func (h *AdminHandlers) mountModels(r chi.Router) {
	// Models
	r.Get("/api/models", h.ListModels())
	r.Post("/api/models", h.CreateModel())
	r.Get("/api/models/{name}", h.GetModel())
	r.Put("/api/models/{name}", h.UpdateModel())
	r.Delete("/api/models/{name}", h.DeleteModel())
	r.Get("/api/model-aliases", h.ListModelAliases())
	r.Post("/api/model-aliases", h.CreateModelAlias())
	r.Delete("/api/model-aliases/{alias}", h.DeleteModelAlias())

	// Routing Rules
	// AUX-19: read-only candidate preview — static path before /{id},
	// same root-only gate as every other rules route.
	r.Post("/api/rules/preview", h.PreviewRoutingRule())
	r.Get("/api/rules", h.ListRoutingRules())
	r.Post("/api/rules", h.CreateRoutingRule())
	r.Get("/api/rules/{id}", h.GetRoutingRule())
	r.Put("/api/rules/{id}", h.UpdateRoutingRule())
	r.Put("/api/rules/{id}/enable", h.UpdateRoutingRuleEnabled())
	r.Delete("/api/rules/{id}", h.DeleteRoutingRule())

	// Model version bump (P4.10 — root-only)
	r.Post("/api/models/{name}/bump-version", h.BumpModelVersion())

	// PB4.9: Sovereign model marketplace (root-only)
	if h.sovereignHandlers != nil {
		r.Get("/api/sovereign/models", h.sovereignHandlers.ListModels)
		r.Put("/api/sovereign/models/{name}", h.sovereignHandlers.ToggleModel)
		r.Get("/api/sovereign/policy/{org_id}", h.sovereignHandlers.GetPolicy)
		r.Put("/api/sovereign/policy/{org_id}", h.sovereignHandlers.UpdatePolicy)
	}
}

// mountRoutingViews registers the org-scoped read-only routing views
// org access inside the handlers via requireOrgRead (root passes for any
// org; a member needs routing.manage / analytics.read; anyone else gets the
// membership-blind 404), so they belong on the authenticated group, not the
// root-only CRUD group above.
func (h *AdminHandlers) mountRoutingViews(r chi.Router) {
	r.Get("/api/routing/map", h.RoutingMap())
	// Recorded requested→used paths (analytics.read in-handler) and the
	// point-in-time snapshot for simulation (routing.manage in-handler) —
	// UI-DEV routing-viz backend gaps, same in-handler org gates as above.
	r.Get("/api/routing/actual", h.RoutingActual())
	r.Get("/api/routing/snapshot", h.RoutingSnapshot())
	r.Get("/api/providers/health", h.ProviderHealth())
}
