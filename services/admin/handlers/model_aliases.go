package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ListModelAliases returns the alias table. Access matches GET /api/models.
func (h *AdminHandlers) ListModelAliases() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		rows, err := h.store.ListModelAliases(r.Context())
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// CreateModelAlias binds an alias to a registry model.
func (h *AdminHandlers) CreateModelAlias() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var body struct {
			Alias       string `json:"alias"`
			TargetModel string `json:"target_model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if !adminstore.ValidModelAlias(body.Alias) || body.TargetModel == "" {
			h.respondError(w, r, fmt.Errorf("alias must match the model alias pattern and target_model is required"), http.StatusBadRequest)
			return
		}
		row, err := h.store.CreateModelAlias(r.Context(), body.Alias, body.TargetModel)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23505") {
				h.respondError(w, r, fmt.Errorf("alias rejected"), http.StatusBadRequest)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "model_alias", "alias="+body.Alias+",target="+body.TargetModel)
		writeJSON(w, http.StatusCreated, row)
	}
}

// DeleteModelAlias removes one alias.
func (h *AdminHandlers) DeleteModelAlias() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		alias := chi.URLParam(r, "alias")
		if err := h.store.DeleteModelAlias(r.Context(), alias); err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		h.auditLogAction(r, "delete", "model_alias", "alias="+alias)
		w.WriteHeader(http.StatusNoContent)
	}
}
