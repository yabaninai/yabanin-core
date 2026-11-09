package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// RoutingSnapshot hands the UI a point-in-time view of the routing state it
// can run what-if simulations against: the same data as /api/routing/map
// plus the ACTIVE override projection (the enabled rules in evaluation
// order). One store read feeds both sections, so map and overrides are
// mutually consistent — a snapshot, not two unrelated queries.

// RoutingActiveOverride is one enabled routing rule in evaluation order.
// It is the map's rule row minus the enabled flag (everything here is
// enabled by construction).
type RoutingActiveOverride struct {
	ID          string `json:"id"`
	MatchExpr   string `json:"match_expr"`
	TargetModel string `json:"target_model"`
	Priority    int    `json:"priority"`
}

// activeRuleOverrides projects the map's rules onto the active override
// view: enabled rules only, ordered the way the rule engine evaluates
// them — priority descending, stable. pkg/rulestore feeds the gateway the
// same enabled set ORDER BY priority DESC and the engine's selection is a
// stable sort on that input, so within one priority the gateway's tie
// order is DB heap order, while this projection pins ties to the map's
// deterministic created_at/id order. Disabled rules are inert (the
// gateway never sees them) and never appear here.
func activeRuleOverrides(rules []adminstore.RoutingMapRule) []RoutingActiveOverride {
	active := []RoutingActiveOverride{}
	for _, r := range rules {
		if r.Enabled {
			active = append(active, RoutingActiveOverride{
				ID:          r.ID,
				MatchExpr:   r.MatchExpr,
				TargetModel: r.TargetModel,
				Priority:    r.Priority,
			})
		}
	}
	sort.SliceStable(active, func(i, j int) bool { return active[i].Priority > active[j].Priority })
	return active
}

// RoutingSnapshot handles GET /api/routing/snapshot?org_id= — the routing
// map plus the active overrides at captured_at. Read-only; gated by
// routing.manage (same audience as the map: configuration state, not
// traffic). The store capability is deliberately RoutingMapStore: one read
// of GetRoutingMap feeds both the map section and the override projection.
func (h *AdminHandlers) RoutingSnapshot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.requireOrgRead(w, r, orgID, adminstore.PermRoutingManage) {
			return
		}
		store, ok := h.store.(RoutingMapStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("store does not support the routing snapshot"), http.StatusNotImplemented)
			return
		}
		mapping, err := store.GetRoutingMap(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"org_id":           orgID,
			"captured_at":      time.Now().UTC().Format(time.RFC3339),
			"map":              mapping,
			"active_overrides": activeRuleOverrides(mapping.Rules),
		}); err != nil && h.logger != nil {
			h.logger.ErrorContext(r.Context(), "encode routing snapshot", slog.String("error", err.Error()))
		}
	}
}
