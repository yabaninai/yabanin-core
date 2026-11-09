package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/labels"
)

// LabelPolicyStore is the organization label-policy table.
type LabelPolicyStore interface {
	GetLabelPolicy(ctx context.Context, orgID string) (adminstore.LabelPolicyRow, bool, error)
	UpsertLabelPolicy(ctx context.Context, orgID string, policy []byte, updatedBy string) error
	DeleteLabelPolicy(ctx context.Context, orgID string) error
}

// SetLabelPolicyStore wires the policy table. Nil answers 503.
func (h *AdminHandlers) SetLabelPolicyStore(s LabelPolicyStore) {
	h.analytics.labelPolicy = s
}

func (h *AdminHandlers) requireLabelPolicyStore(w http.ResponseWriter, r *http.Request) bool {
	if h.analytics.labelPolicy == nil {
		h.respondError(w, r, fmt.Errorf("label policy store not configured"), http.StatusServiceUnavailable)
		return false
	}
	return true
}

type labelPolicyResponse struct {
	Policy    labels.Policy `json:"policy"`
	IsDefault bool          `json:"is_default"`
	UpdatedAt time.Time     `json:"updated_at"`
	UpdatedBy string        `json:"updated_by"`
}

// GetLabelPolicy — GET /api/label-policy?org_id= (analytics.read).
func (h *AdminHandlers) GetLabelPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireLabelPolicyStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		row, ok, err := h.analytics.labelPolicy.GetLabelPolicy(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, http.StatusOK, labelPolicyResponse{Policy: labels.DefaultPolicy(), IsDefault: true})
			return
		}
		var policy labels.Policy
		if err := json.Unmarshal(row.Policy, &policy); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, labelPolicyResponse{
			Policy: policy, IsDefault: false, UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy,
		})
	}
}

// PutLabelPolicy — PUT /api/label-policy?org_id= (policies.manage).
func (h *AdminHandlers) PutLabelPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireLabelPolicyStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32*1024))
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				h.respondError(w, r, fmt.Errorf("policy body exceeds 32 KiB"), http.StatusRequestEntityTooLarge)
				return
			}
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		var policy labels.Policy
		if err := dec.Decode(&policy); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy", "message": err.Error()})
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy", "message": "trailing data"})
			return
		}
		if _, err := policy.Compile(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy", "message": err.Error()})
			return
		}
		raw, err := json.Marshal(policy)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		updatedBy := adminauth.ExtractAdminEmail(r)
		if err := h.analytics.labelPolicy.UpsertLabelPolicy(r.Context(), orgID, raw, updatedBy); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.dropLabelPolicyCache(r, orgID)
		h.auditLogAction(r, "update", "label_policy", "org="+orgID)
		writeJSON(w, http.StatusOK, labelPolicyResponse{Policy: policy, UpdatedBy: updatedBy, UpdatedAt: time.Now().UTC()})
	}
}

// DeleteLabelPolicy — DELETE /api/label-policy?org_id= (policies.manage).
func (h *AdminHandlers) DeleteLabelPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireLabelPolicyStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		if err := h.analytics.labelPolicy.DeleteLabelPolicy(r.Context(), orgID); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.dropLabelPolicyCache(r, orgID)
		h.auditLogAction(r, "delete", "label_policy", "org="+orgID)
		writeJSON(w, http.StatusOK, labelPolicyResponse{Policy: labels.DefaultPolicy(), IsDefault: true})
	}
}

type labelPolicyTestRequest struct {
	Policy    *labels.Policy    `json:"policy"`
	Headers   map[string]string `json:"headers"`
	KeyLabels map[string]string `json:"key_labels"`
	KeyLocked bool              `json:"key_locked"`
}

// TestLabelPolicy — POST /api/label-policy/test?org_id= (analytics.read).
// Nothing is stored.
func (h *AdminHandlers) TestLabelPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireLabelPolicyStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
		dec.DisallowUnknownFields()
		var req labelPolicyTestRequest
		if err := dec.Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		policy := labels.DefaultPolicy()
		if req.Policy != nil {
			policy = *req.Policy
		} else {
			row, ok, err := h.analytics.labelPolicy.GetLabelPolicy(r.Context(), orgID)
			if err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			if ok {
				if err := json.Unmarshal(row.Policy, &policy); err != nil {
					h.respondError(w, r, err, http.StatusInternalServerError)
					return
				}
			}
		}
		compiled, err := policy.Compile()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy", "message": err.Error()})
			return
		}
		header := http.Header{}
		for k, v := range req.Headers {
			header.Set(k, v)
		}
		set, dropped := labels.FromRequest(header)
		sources := []labels.Source{
			{Name: "key", Labels: req.KeyLabels, Locked: req.KeyLocked},
			{Name: "request", Labels: set},
		}
		res := labels.Resolve(compiled, sources, func(string) bool { return false })
		res.Dropped = append(dropped, res.Dropped...)
		writeJSON(w, http.StatusOK, map[string]any{
			"labels":   res.Labels,
			"dropped":  res.Dropped,
			"missing":  res.Missing,
			"rejected": res.Rejected,
		})
	}
}

func (h *AdminHandlers) dropLabelPolicyCache(r *http.Request, orgID string) {
	if h.resolverCache == nil {
		return
	}
	_ = h.resolverCache.Del(r.Context(), "yb:labelpolicy:"+orgID)
}
