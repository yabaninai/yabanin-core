package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/policystore"
)

// PolicyPackStore is the subset of policystore.Store used by the handlers.
// *policystore.Store satisfies it; tests pass a mock.
type PolicyPackStore interface {
	Upsert(ctx context.Context, c policystore.PackConfig) (policystore.PackConfig, error)
	GetByOrgRegion(ctx context.Context, orgID, region string) (*policystore.PackConfig, error)
	List(ctx context.Context, orgID string) ([]policystore.PackConfig, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// OrgResidencyStore reads/writes an org's residency_region.
// *adminstore.Store satisfies it.
type OrgResidencyStore interface {
	GetOrgResidencyRegion(ctx context.Context, orgID string) (string, error)
	UpdateOrgResidencyRegion(ctx context.Context, orgID string, region string) error
}

// SetPolicyPackStore attaches the policy-pack CRUD store.
func (h *AdminHandlers) SetPolicyPackStore(s PolicyPackStore) {
	h.org.policyPacks = s
}

// SetOrgResidencyStore attaches the org residency-region store.
func (h *AdminHandlers) SetOrgResidencyStore(s OrgResidencyStore) {
	h.org.residency = s
}

// ListPolicyPacks handles GET /api/organizations/{id}/policy-packs.
func (h *AdminHandlers) ListPolicyPacks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.org.policyPacks == nil {
			h.respondError(w, r, fmt.Errorf("policy-pack store not configured"), http.StatusServiceUnavailable)
			return
		}
		orgID := chi.URLParam(r, "id")
		list, err := h.org.policyPacks.List(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("list policy packs: %w", err), http.StatusInternalServerError)
			return
		}
		if list == nil {
			list = []policystore.PackConfig{}
		}
		writeJSON(w, http.StatusOK, list)
	}
}

// upsertPolicyPackBody is the JSON body for PUT.
// Config is required and must be a non-null JSON document; unknown fields
// are rejected before the store is touched.
type upsertPolicyPackBody struct {
	PackID  string          `json:"pack_id"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled,omitempty"`
}

// decodeStrictJSON decodes exactly one JSON object from the request body,
// rejecting unknown fields (package-wide convention for admin mutation
// bodies) and any trailing data after the object.
func decodeStrictJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data after JSON object")
	}
	return nil
}

// validPackConfig reports whether a decoded config field carries a usable
// JSON document: present and not the literal null. Missing keys and explicit
// null both leave RawMessage in one of these two shapes.
func validPackConfig(config json.RawMessage) bool {
	trimmed := bytes.TrimSpace(config)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// UpsertPolicyPack handles PUT /api/organizations/{id}/policy-packs/{region}.
func (h *AdminHandlers) UpsertPolicyPack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.org.policyPacks == nil {
			h.respondError(w, r, fmt.Errorf("policy-pack store not configured"), http.StatusServiceUnavailable)
			return
		}
		orgID := chi.URLParam(r, "id")
		region := chi.URLParam(r, "region")

		if !policystore.IsValidRegion(region) {
			h.respondError(w, r, fmt.Errorf("invalid region %q (valid: SG, IN, ID)", region), http.StatusBadRequest)
			return
		}

		var body upsertPolicyPackBody
		if err := decodeStrictJSON(r, &body); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}
		// The config column is NOT NULL; a missing or null config would turn
		// into a store-level SQL error (SQLSTATE 23502) surfaced as a 500.
		// Validate before touching the store.
		if !validPackConfig(body.Config) {
			h.respondError(w, r, fmt.Errorf("config is required and must be non-null JSON"), http.StatusBadRequest)
			return
		}
		if body.PackID == "" {
			body.PackID = defaultPackID(region)
		}

		orgUUID, err := uuid.Parse(orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("invalid org id"), http.StatusBadRequest)
			return
		}

		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}

		out, err := h.org.policyPacks.Upsert(r.Context(), policystore.PackConfig{
			OrgID:   &orgUUID,
			Region:  region,
			PackID:  body.PackID,
			Config:  body.Config,
			Enabled: enabled,
		})
		if err != nil {
			h.respondError(w, r, fmt.Errorf("upsert policy pack: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "upsert", "policy_pack",
			fmt.Sprintf("org=%s region=%s pack=%s", orgID, region, body.PackID))

		writeJSON(w, http.StatusOK, out)
	}
}

// DeletePolicyPack handles DELETE /api/organizations/{id}/policy-packs/{packID}.
func (h *AdminHandlers) DeletePolicyPack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.org.policyPacks == nil {
			h.respondError(w, r, fmt.Errorf("policy-pack store not configured"), http.StatusServiceUnavailable)
			return
		}
		packID := chi.URLParam(r, "packID")
		id, err := uuid.Parse(packID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("invalid pack id (must be UUID)"), http.StatusBadRequest)
			return
		}
		if err := h.org.policyPacks.Delete(r.Context(), id); err != nil {
			h.respondError(w, r, fmt.Errorf("delete policy pack: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditLogActionWithCtx(r.Context(), r, "delete", "policy_pack", fmt.Sprintf("id=%s", packID))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// GetOrgResidency handles GET /api/organizations/{id}/residency.
func (h *AdminHandlers) GetOrgResidency() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.org.residency == nil {
			h.respondError(w, r, fmt.Errorf("org residency store not configured"), http.StatusServiceUnavailable)
			return
		}
		orgID := chi.URLParam(r, "id")
		region, err := h.org.residency.GetOrgResidencyRegion(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("get residency: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"org_id":           orgID,
			"residency_region": region,
		})
	}
}

// UpdateOrgResidency handles PUT /api/organizations/{id}/residency.
// Body: {"residency_region": "SG"}  (empty string clears enforcement)
// Unknown fields are rejected (e.g. a typo'd {"region":"SG"} must not be
// silently decoded as an empty-region clear).
func (h *AdminHandlers) UpdateOrgResidency() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.org.residency == nil {
			h.respondError(w, r, fmt.Errorf("org residency store not configured"), http.StatusServiceUnavailable)
			return
		}
		orgID := chi.URLParam(r, "id")
		var body struct {
			Region string `json:"residency_region"`
		}
		if err := decodeStrictJSON(r, &body); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}
		if body.Region != "" && !policystore.IsValidRegion(body.Region) {
			h.respondError(w, r, fmt.Errorf("invalid residency_region %q (valid: SG, IN, ID, or empty)", body.Region), http.StatusBadRequest)
			return
		}
		if err := h.org.residency.UpdateOrgResidencyRegion(r.Context(), orgID, body.Region); err != nil {
			h.respondError(w, r, fmt.Errorf("update residency: %w", err), http.StatusInternalServerError)
			return
		}
		h.auditLogActionWithCtx(r.Context(), r, "update", "org_residency",
			fmt.Sprintf("org=%s region=%s", orgID, body.Region))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// defaultPackID returns the canonical pack id for a region.
func defaultPackID(region string) string {
	switch region {
	case "SG":
		return "sg_pdpa_mas"
	case "IN":
		return "in_dpdp_rbi"
	case "ID":
		return "id_pdp"
	default:
		return ""
	}
}
