package handlers

// the request explorer + lineage group (both RequireOrgPermission-gated),
// and the root-only analytics aggregates on the root CRUD group.

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mountAnalytics registers the org-scoped analytics endpoints and the
// label-policy read/test routes (analytics.read) plus the label-policy
// write routes (policies.manage).
func (h *AdminHandlers) mountAnalytics(protected chi.Router) {
	// Org-scoped analytics. analytics.read matches the old reader rank for
	// every current role, including security_auditor. Root bypasses.
	rb := protected.With(h.RequireOrgPermission(adminstore.PermAnalyticsRead))
	rb.Get("/api/analytics/stats", h.apiAnalyticsStats())
	rb.Get("/api/analytics/top-models", h.apiTopModels())
	rb.Get("/api/analytics/time-series", h.apiTimeSeries())
	rb.Get("/api/analytics/error-breakdown", h.apiErrorBreakdown())
	rb.Get("/api/analytics/tasks", h.apiTaskAnalytics())
	rb.Get("/api/analytics/latency", h.apiLatency())
	rb.Get("/api/analytics/recent-errors", h.apiRecentErrors())
	rb.Get("/api/analytics/query", h.apiAnalyticsQuery())
	rb.Get("/api/analytics/views", h.ListAnalyticsViews())
	rb.Post("/api/analytics/views", h.CreateAnalyticsView())
	rb.Put("/api/analytics/views/{id}", h.UpdateAnalyticsView())
	rb.Delete("/api/analytics/views/{id}", h.DeleteAnalyticsView())
	rb.Get("/api/analytics/label-keys", h.apiAnalyticsLabelKeys())
	rb.Get("/api/label-policy", h.GetLabelPolicy())
	rb.Post("/api/label-policy/test", h.TestLabelPolicy())
	protected.With(h.RequireOrgPermission(adminstore.PermPoliciesManage)).Put("/api/label-policy", h.PutLabelPolicy())
	protected.With(h.RequireOrgPermission(adminstore.PermPoliciesManage)).Delete("/api/label-policy", h.DeleteLabelPolicy())
}

// mountExplorer registers the unified request explorer (list/stats/detail)
// and the lineage query/verify routes, all org-permission-gated.
func (h *AdminHandlers) mountExplorer(protected chi.Router) {
	requests := protected.With(h.RequireOrgPermission(adminstore.PermRequestsRead))
	requests.Get("/api/organizations/{id}/requests", h.apiOrgRequests())
	requests.Get("/api/organizations/{id}/requests/stats", h.apiOrgRequestStats())
	requests.Get("/api/organizations/{id}/requests/export", h.apiOrgRequestExport())
	requests.Get("/api/organizations/{id}/requests/archive-search", h.apiOrgArchiveSearch())
	requests.Get("/api/organizations/{id}/requests/{request_id}", h.apiOrgRequestDetail())

	lineageRead := protected.With(h.RequireOrgPermission(adminstore.PermLineageRead))
	lineageRead.Get("/api/lineage/{request_id}", h.GetLineageByRequest())
	lineageRead.Get("/api/organizations/{id}/lineage", h.ListLineageByOrg())
	protected.With(h.RequireOrgPermission(adminstore.PermLineageVerify)).Post("/api/lineage/{request_id}/verify", h.VerifyLineage())
}

// mountAnalyticsRoot registers the root-only analytics aggregates on the
// root CRUD group: the tool-call rollup, per-org cache analytics and the
// cost/savings/shadow/quality reports.
func (h *AdminHandlers) mountAnalyticsRoot(r chi.Router) {
	// Tool-call aggregate stays root-only. Request list, detail, lineage,
	// and team budgets are registered above under RequireOrgPermission.
	r.Get("/api/organizations/{id}/tool-calls", h.apiOrgToolCalls())

	// P4.13: Cache analytics endpoint (hit-rate, savings_usd)
	r.Get("/api/analytics/{org_id}/cache", h.CacheAnalyticsHandler())

	// P6.2: Cost analytics endpoints
	r.Get("/api/analytics/{org_id}/cost", h.CostAnalyticsHandler())
	r.Get("/api/analytics/cost/global", h.GlobalCostStatsHandler())
	r.Get("/api/analytics/savings", h.SavingsReportHandler())
	// V9: primary vs shadow cost comparison (mirror traffic accounting).
	r.Get("/api/analytics/shadow", h.ShadowComparisonHandler())
	// ADL-04: quality closed-loop (evalgate verdicts → quality scores +
	// routing recommendation).
	r.Get("/api/analytics/quality", h.QualityScoresHandler())
}
