package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/fleet"
)

// E03-P01 W04-C03: read-only fleet-registry endpoints for the admin API.
//
//	GET /api/organizations/{org_id}/fleet/installations              list
//	GET /api/organizations/{org_id}/fleet/installations/{deployment_id}
//
// Root-only (mountRootAdmin group — the MustBeRoot chain, same plane as
// the entitlement diagnostics): the registry is an operator surface and
// no org-permission for fleet exists — none is invented here. The
// non-root refusal arm is the middleware's 403.
//
// org_id is the LICENSE org coordinate (TEXT, identity-model §3 — the
// coordinate enrollments and heartbeats are signed for), not an
// adminstore uuid; the path carries it verbatim and the store's RLS
// scope (migration 0024) is the same coordinate. GET-only on purpose:
// mutations do not exist on this plane («N/A мутаций»); enrollment,
// heartbeats and revocation flow through their own signed seams.
//
// «отозванная помечена явно»: a revoked installation carries state
// "revoked" AND an explicit revoked:true marker with its revoked_at and
// reason — an operator skimming the list sees terminality without
// parsing state vocabulary.

// fleetStore is the store capability these handlers need — exactly the
// read surface of *fleet.CapsStore. The production delegate is built
// from the shared admin pool (fleetDelegate); tests implement it
// directly.
type fleetStore interface {
	List(ctx context.Context, orgID string) ([]fleet.StoredInstallation, error)
	Get(ctx context.Context, orgID, deploymentID string) (fleet.StoredInstallation, bool, error)
}

// fleetPoolStore is the pool capability the production adminstore.Store
// exposes. The admin pool session is not RLS-pinned, so the store takes
// its bypass path (caps_store.go writer/reader law) — the registry's RLS
// boundary protects the app-role plane, and the root-only admin plane is
// its own authorization story.
type fleetPoolStore interface {
	DB() *pgxpool.Pool
}

// fleetDelegate resolves the fleet store for this handler set: a store
// implementing the capability directly (tests), else the shared admin
// pool. False means the capability is absent (503).
func (h *AdminHandlers) fleetDelegate() (fleetStore, bool) {
	if st, ok := h.store.(fleetStore); ok {
		return st, true
	}
	if ps, ok := h.store.(fleetPoolStore); ok && ps.DB() != nil {
		return fleet.NewCapsStore(ps.DB()), true
	}
	return nil, false
}

// fleetCapsJSON is the wire shape of the stored negotiated document
// (handler-layer casing; pkg/fleet stays storage-shaped).
type fleetCapsJSON struct {
	FormatVersion string   `json:"format_version"`
	Capabilities  []string `json:"capabilities"`
	Unsupported   []string `json:"unsupported,omitempty"`
}

// fleetInstallationJSON is the wire shape of one installation.
type fleetInstallationJSON struct {
	OrgID        string `json:"org_id"`
	DeploymentID string `json:"deployment_id"`
	State        string `json:"state"`
	// Revoked is the EXPLICIT terminality marker (state "revoked" plus
	// this boolean, with revoked_at and reason when set).
	Revoked          bool          `json:"revoked"`
	RevokedAt        *time.Time    `json:"revoked_at,omitempty"`
	RevocationReason string        `json:"revocation_reason,omitempty"`
	Caps             fleetCapsJSON `json:"caps"`
	EnrolledAt       time.Time     `json:"enrolled_at"`
	CapsUpdatedAt    time.Time     `json:"caps_updated_at"`
	LastHeartbeatAt  *time.Time    `json:"last_heartbeat_at,omitempty"`
}

func newFleetInstallationJSON(inst fleet.StoredInstallation) fleetInstallationJSON {
	out := fleetInstallationJSON{
		OrgID:            inst.OrgID,
		DeploymentID:     inst.DeploymentID,
		State:            string(inst.State),
		Revoked:          inst.State == fleet.StateRevoked,
		RevokedAt:        inst.RevokedAt,
		RevocationReason: inst.RevocationReason,
		Caps: fleetCapsJSON{
			FormatVersion: inst.Caps.FormatVersion,
			Capabilities:  inst.Caps.Capabilities,
			Unsupported:   inst.Caps.Unsupported,
		},
		EnrolledAt:      inst.EnrolledAt,
		CapsUpdatedAt:   inst.CapsUpdatedAt,
		LastHeartbeatAt: inst.LastHeartbeatAt,
	}
	if out.Caps.Capabilities == nil {
		out.Caps.Capabilities = []string{}
	}
	if out.Caps.Unsupported == nil {
		out.Caps.Unsupported = []string{}
	}
	return out
}

// fleetAuditDetail is the audit journal payload. Always marshaled
// (never Sprintf'd) so values cannot corrupt the row.
type fleetAuditDetail struct {
	OrgID        string `json:"org_id"`
	DeploymentID string `json:"deployment_id,omitempty"`
	Outcome      string `json:"outcome"`
	Rows         int    `json:"rows,omitempty"`
}

func (h *AdminHandlers) auditFleet(r *http.Request, orgID, deploymentID, outcome string, rows int) {
	detail := fleetAuditDetail{
		OrgID:        orgID,
		DeploymentID: deploymentID,
		Outcome:      outcome,
		Rows:         rows,
	}
	action := "fleet_registry"
	if outcome == "denied" {
		action = "fleet_registry.denied"
	}
	b, err := json.Marshal(detail)
	if err != nil {
		// The struct is marshal-infallible; keep the journal write anyway.
		b = []byte(`{"outcome":"` + outcome + `"}`)
	}
	h.auditLogAction(r, action, "fleet:"+orgID, string(b))
}

// fleetOrg resolves the path org coordinate. It returns false after
// writing the error response.
func (h *AdminHandlers) fleetOrg(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := chi.URLParam(r, "org_id")
	if err := fleet.ValidateOrgID(raw); err != nil {
		h.respondError(w, r, errors.New("invalid organization id"), http.StatusBadRequest)
		return "", false
	}
	return raw, true
}

func (h *AdminHandlers) apiOrgFleetInstallations() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID, ok := h.fleetOrg(w, r)
		if !ok {
			return
		}
		st, ok := h.fleetDelegate()
		if !ok {
			h.respondError(w, r, errors.New("fleet registry is unavailable"), http.StatusServiceUnavailable)
			return
		}
		installations, err := st.List(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		rows := make([]fleetInstallationJSON, 0, len(installations))
		for _, inst := range installations {
			rows = append(rows, newFleetInstallationJSON(inst))
		}
		h.auditFleet(r, orgID, "", "allowed", len(rows))
		writeJSON(w, http.StatusOK, struct {
			Data []fleetInstallationJSON `json:"data"`
		}{Data: rows})
	}
}

func (h *AdminHandlers) apiOrgFleetInstallation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID, ok := h.fleetOrg(w, r)
		if !ok {
			return
		}
		deploymentID := chi.URLParam(r, "deployment_id")
		if err := fleet.ValidateDeploymentID(deploymentID); err != nil {
			h.respondError(w, r, errors.New("invalid deployment id"), http.StatusBadRequest)
			return
		}
		st, ok := h.fleetDelegate()
		if !ok {
			h.respondError(w, r, errors.New("fleet registry is unavailable"), http.StatusServiceUnavailable)
			return
		}
		inst, found, err := st.Get(r.Context(), orgID, deploymentID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if !found {
			// Foreign-org and missing installations are indistinguishable:
			// the store scopes by (org_id, deployment_id), so 404 without
			// leaking existence.
			h.auditFleet(r, orgID, deploymentID, "not_found", 0)
			h.respondError(w, r, errors.New("installation not found"), http.StatusNotFound)
			return
		}
		h.auditFleet(r, orgID, deploymentID, "allowed", 1)
		writeJSON(w, http.StatusOK, struct {
			Data fleetInstallationJSON `json:"data"`
		}{Data: newFleetInstallationJSON(inst)})
	}
}

// mountFleet registers the fleet-registry read API on the root-only
// group (mountRootAdmin). GET-only: there is deliberately no mutation on
// this plane — lifecycle changes flow through the signed enrollment,
// heartbeat and revocation seams.
func (h *AdminHandlers) mountFleet(r chi.Router) {
	r.Get("/api/organizations/{org_id}/fleet/installations", h.apiOrgFleetInstallations())
	r.Get("/api/organizations/{org_id}/fleet/installations/{deployment_id}", h.apiOrgFleetInstallation())
}
