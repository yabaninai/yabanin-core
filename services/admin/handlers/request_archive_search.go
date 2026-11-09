package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

type requestArchiveSearchStore interface {
	SearchRequestArchive(context.Context, adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error)
}

// apiOrgArchiveSearch currently runs the shared hot request_logs search. The
// source marker makes the storage phase explicit until N10 adds archive data.
func (h *AdminHandlers) apiOrgArchiveSearch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		filters, err := parseRequestListFilters(r, chi.URLParam(r, "id"))
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		if !authorizeRequestList(h, r, &filters) {
			writeJSON(w, http.StatusForbidden, apiError{Error: "request history access denied"})
			return
		}
		archive, ok := h.store.(requestArchiveSearchStore)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "archive search is unavailable"})
			return
		}
		rows, total, err := archive.SearchRequestArchive(r.Context(), filters)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		for i := range rows {
			if filters.PayloadDenied || (!filters.PayloadGrant && !rows[i].PayloadOwned) {
				rows[i].ErrorMsg = ""
				rows[i].ToolCalls = nil
			}
		}
		writeJSON(w, http.StatusOK, struct {
			Source string                      `json:"source"`
			Total  int                         `json:"total"`
			Data   []adminstore.RequestListRow `json:"data"`
		}{Source: "hot", Total: total, Data: rows})
	}
}
