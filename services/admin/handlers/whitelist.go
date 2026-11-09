package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// whitelistEntryBefore journals the current allow/deny state of (targetID,
// modelName) ahead of a removal (AUX-14b): the reverse action is an add, and
// it needs the `allowed` value the removed entry carried. Returns nil when
// the entry cannot be found — the removal is still journalled, just without
// a restorable snapshot.
func (h *AdminHandlers) whitelistEntryBefore(ctx context.Context, kind, targetID, modelName string) map[string]any {
	var (
		entries []*adminstore.WhitelistEntry
		err     error
	)
	if kind == "team" {
		entries, _, err = h.store.ListTeamWhitelist(ctx, targetID, adminstore.NewPageFilter(1, adminstore.MaxPageSize))
	} else {
		entries, _, err = h.store.ListKeyWhitelist(ctx, targetID, adminstore.NewPageFilter(1, adminstore.MaxPageSize))
	}
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry != nil && entry.ModelName == modelName {
			return map[string]any{
				"target_id":  targetID,
				"model_name": modelName,
				"allowed":    entry.Allowed,
			}
		}
	}
	return nil
}

// whitelistConflictBody renders the current entry (nil when absent) for a
// 409 body — the caller compares it against the recorded snapshot.
func whitelistConflictBody(targetID string, entry *adminstore.WhitelistEntry) map[string]any {
	if entry == nil {
		return nil
	}
	return map[string]any{"target_id": entry.TargetID, "model_name": entry.ModelName, "allowed": entry.Allowed}
}

func (h *AdminHandlers) listKeyWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		if targetID == "" {
			h.respondError(w, r, fmt.Errorf("target_id required"), http.StatusBadRequest)
			return
		}

		f := parsePage(r)
		items, total, err := h.store.ListKeyWhitelist(r.Context(), targetID, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, items, total)
	}
}

func (h *AdminHandlers) addKeyWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		if targetID == "" {
			h.respondError(w, r, fmt.Errorf("target_id required"), http.StatusBadRequest)
			return
		}

		var req struct {
			ModelName string `json:"model_name"`
			Allowed   bool   `json:"allowed"`
			// AF-09: expected_absent marks the rollback of an audited removal —
			// the add is applied only while the entry is still absent.
			ExpectedAbsent bool `json:"expected_absent,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.ModelName == "" {
			h.respondError(w, r, fmt.Errorf("model_name required"), http.StatusBadRequest)
			return
		}

		if req.ExpectedAbsent {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			entry, err := cs.AddKeyWhitelistPreconditioned(r.Context(), targetID, req.ModelName, req.Allowed)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, whitelistConflictBody(targetID, entry))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.invalidateWhitelistCache(r, "key", targetID)
			// CAS success proves the entry was absent — the journal's before
			// is honestly absent and after is the restored entry.
			after := map[string]any{"target_id": targetID, "model_name": req.ModelName, "allowed": req.Allowed}
			h.auditLogActionDiff(r, "add_key_whitelist", "key_whitelist", "target_id="+targetID+",model_name="+req.ModelName+",allowed="+fmt.Sprintf("%v", req.Allowed), nil, after)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(entry); err != nil {
				h.logger.ErrorContext(r.Context(), "encode whitelist entry", slog.String("error", err.Error()))
			}
			return
		}

		entry, err := h.store.AddKeyWhitelist(r.Context(), targetID, req.ModelName, req.Allowed)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Invalidate gateway whitelist cache so the new rule takes effect immediately.
		h.invalidateWhitelistCache(r, "key", targetID)

		// AUX-14b: journal the entry on both sides so the audit page can
		// offer the reverse call (remove for an add, add-back for a remove).
		after := map[string]any{"target_id": targetID, "model_name": req.ModelName, "allowed": req.Allowed}
		h.auditLogActionDiff(r, "add_key_whitelist", "key_whitelist", "target_id="+targetID+",model_name="+req.ModelName+",allowed="+fmt.Sprintf("%v", req.Allowed), nil, after)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(entry); err != nil {
			h.logger.ErrorContext(r.Context(), "encode whitelist entry", slog.String("error", err.Error()))
		}
	}
}

// invalidateWhitelistCache drops the gateway whitelist cache entry for the
// target; nil loader = TTL-only staleness bound.
func (h *AdminHandlers) invalidateWhitelistCache(r *http.Request, kind, targetID string) {
	if h.wlLoader == nil {
		return
	}
	if err := h.wlLoader.Invalidate(r.Context(), kind, targetID); err != nil {
		h.logger.Warn("whitelist cache invalidation failed", "target", targetID, "error", err)
	}
}

func (h *AdminHandlers) removeKeyWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		modelName := chi.URLParam(r, "model_name")
		if targetID == "" || modelName == "" {
			h.respondError(w, r, fmt.Errorf("target_id and model_name required"), http.StatusBadRequest)
			return
		}

		// AF-09: an optional expected_allowed makes the removal conditional —
		// the rollback of an audited add removes the entry only while it
		// still carries the added allowed value. An absent body (or empty
		// JSON object) keeps the plain unconditional removal.
		var req struct {
			ExpectedAllowed *bool `json:"expected_allowed,omitempty"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
				return
			}
		}
		if req.ExpectedAllowed != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			_, current, err := cs.DeleteKeyWhitelistPreconditioned(r.Context(), targetID, modelName, *req.ExpectedAllowed)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, whitelistConflictBody(targetID, current))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.invalidateWhitelistCache(r, "key", targetID)
			// CAS success proves the removed row held exactly the expected
			// allowed value — journal it as the removal's before snapshot.
			before := map[string]any{"target_id": targetID, "model_name": modelName, "allowed": *req.ExpectedAllowed}
			h.auditLogActionDiff(r, "remove_key_whitelist", "key_whitelist", "target_id="+targetID+",model_name="+modelName, before, nil)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// AUX-14b: the reverse of a removal is an add — journal the removed
		// entry's allowed value so the audit page can restore it.
		before := h.whitelistEntryBefore(r.Context(), "key", targetID, modelName)
		if err := h.store.DeleteKeyWhitelist(r.Context(), targetID, modelName); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Invalidate gateway whitelist cache.
		h.invalidateWhitelistCache(r, "key", targetID)

		h.auditLogActionDiff(r, "remove_key_whitelist", "key_whitelist", "target_id="+targetID+",model_name="+modelName, before, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AdminHandlers) listTeamWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		if targetID == "" {
			h.respondError(w, r, fmt.Errorf("target_id required"), http.StatusBadRequest)
			return
		}

		f := parsePage(r)
		items, total, err := h.store.ListTeamWhitelist(r.Context(), targetID, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, items, total)
	}
}

func (h *AdminHandlers) addTeamWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		if targetID == "" {
			h.respondError(w, r, fmt.Errorf("target_id required"), http.StatusBadRequest)
			return
		}

		var req struct {
			ModelName string `json:"model_name"`
			Allowed   bool   `json:"allowed"`
			// AF-09: expected_absent marks the rollback of an audited removal.
			ExpectedAbsent bool `json:"expected_absent,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.ModelName == "" {
			h.respondError(w, r, fmt.Errorf("model_name required"), http.StatusBadRequest)
			return
		}

		if req.ExpectedAbsent {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			entry, err := cs.AddTeamWhitelistPreconditioned(r.Context(), targetID, req.ModelName, req.Allowed)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, whitelistConflictBody(targetID, entry))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.invalidateWhitelistCache(r, "team", targetID)
			after := map[string]any{"target_id": targetID, "model_name": req.ModelName, "allowed": req.Allowed}
			h.auditLogActionDiff(r, "add_team_whitelist", "team_whitelist", "target_id="+targetID+",model_name="+req.ModelName+",allowed="+fmt.Sprintf("%v", req.Allowed), nil, after)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(entry); err != nil {
				h.logger.ErrorContext(r.Context(), "encode team whitelist entry", slog.String("error", err.Error()))
			}
			return
		}

		entry, err := h.store.AddTeamWhitelist(r.Context(), targetID, req.ModelName, req.Allowed)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Invalidate gateway whitelist cache so the new rule takes effect immediately.
		h.invalidateWhitelistCache(r, "team", targetID)

		// AUX-14b: journal the entry on both sides (see add_key_whitelist).
		after := map[string]any{"target_id": targetID, "model_name": req.ModelName, "allowed": req.Allowed}
		h.auditLogActionDiff(r, "add_team_whitelist", "team_whitelist", "target_id="+targetID+",model_name="+req.ModelName+",allowed="+fmt.Sprintf("%v", req.Allowed), nil, after)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(entry); err != nil {
			h.logger.ErrorContext(r.Context(), "encode team whitelist entry", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) removeTeamWhitelist() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		targetID := chi.URLParam(r, "target_id")
		modelName := chi.URLParam(r, "model_name")
		if targetID == "" || modelName == "" {
			h.respondError(w, r, fmt.Errorf("target_id and model_name required"), http.StatusBadRequest)
			return
		}

		// AF-09: optional expected_allowed — see removeKeyWhitelist.
		var req struct {
			ExpectedAllowed *bool `json:"expected_allowed,omitempty"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
				return
			}
		}
		if req.ExpectedAllowed != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			_, current, err := cs.DeleteTeamWhitelistPreconditioned(r.Context(), targetID, modelName, *req.ExpectedAllowed)
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, whitelistConflictBody(targetID, current))
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.invalidateWhitelistCache(r, "team", targetID)
			before := map[string]any{"target_id": targetID, "model_name": modelName, "allowed": *req.ExpectedAllowed}
			h.auditLogActionDiff(r, "remove_team_whitelist", "team_whitelist", "target_id="+targetID+",model_name="+modelName, before, nil)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// AUX-14b: the reverse of a removal is an add — journal the removed
		// entry's allowed value so the audit page can restore it.
		before := h.whitelistEntryBefore(r.Context(), "team", targetID, modelName)
		if err := h.store.DeleteTeamWhitelist(r.Context(), targetID, modelName); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Invalidate gateway whitelist cache.
		h.invalidateWhitelistCache(r, "team", targetID)

		h.auditLogActionDiff(r, "remove_team_whitelist", "team_whitelist", "target_id="+targetID+",model_name="+modelName, before, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}
