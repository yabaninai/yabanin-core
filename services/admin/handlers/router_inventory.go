package handlers

import (
	"github.com/go-chi/chi/v5"
)

// E02-P01 (batch C wiring): the observable asset-registry SPI mounted on
// the root-only CRUD group — the registry read
// (GET /api/organizations/{id}/inventory), the MCP registry import
// (POST .../inventory/import/mcp) and the model/provider import
// (POST .../inventory/import/models). The org dimension of every operation
// is enforced by the handlers (requireOrgScope); the mount only adds the
// root gate and the org-scope middleware of the group.
//
// docs/api/admin.openapi.yaml is byte-frozen for the delivery window, so
// these routes are documented in docs/api/OPENAPI-DELTA.md and chain-pinned
// by the golden router (routes_golden_test.go wires SetInventory) instead
// of the spec lock-step walk — the same posture as the DB-gated groups:
// the no-DB route-inventory walk never sees them, so the frozen spec stays
// drift-free both directions.

// inventoryDeps groups the asset-registry seams (E02-P01): the read store
// and the two import runners. Wired as a unit by SetInventory; per-seam
// nils answer 503 at request time (handler-level guard).
type inventoryDeps struct {
	wired       bool
	lister      InventoryLister
	mcpRunner   InventoryImporter
	modelRunner InventoryModelImporter
}

// SetInventory wires the asset-registry seams as a unit: the read store and
// the two import runners. Wire-time, before SetupRouter (same ordering as
// the other DB-gated groups: the mount reads the seams at registration).
func (h *AdminHandlers) SetInventory(lister InventoryLister, mcpRunner InventoryImporter, modelRunner InventoryModelImporter) {
	h.inventory = inventoryDeps{
		wired:       true,
		lister:      lister,
		mcpRunner:   mcpRunner,
		modelRunner: modelRunner,
	}
}

// mountInventory registers the root-only inventory surface on the root CRUD
// group (mounted by mountRootAdmin in router.go). Unwired deployments never
// register the routes — the surface is dark, not 503, which is what keeps
// the no-DB spec walk in lock-step with the frozen OpenAPI file.
func (h *AdminHandlers) mountInventory(r chi.Router) {
	if !h.inventory.wired {
		return
	}
	r.Get("/api/organizations/{id}/inventory", h.ListInventory(h.inventory.lister))
	r.Post("/api/organizations/{id}/inventory/import/mcp", h.ImportMCPInventory(h.inventory.mcpRunner))
	r.Post("/api/organizations/{id}/inventory/import/models", h.ImportModelsInventory(h.inventory.modelRunner))
}
