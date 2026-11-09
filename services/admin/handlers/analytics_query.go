package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

func (h *AdminHandlers) apiAnalyticsQuery() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		q, ok := h.parseAnalytics(w, r)
		if !ok {
			return
		}
		res, err := h.store.RunAnalyticsQuery(r.Context(), q)
		if err != nil {
			if errors.Is(err, adminstore.ErrAnalyticsTimeout) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"error":   "analytics_timeout",
					"code":    "analytics_timeout",
					"message": "narrow the query",
				})
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if q.Format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf(
				`attachment; filename="yabanin-analytics-%s-%s-%s.csv"`,
				csvName(q.OrgID), q.From.In(q.TZ).Format("20060102"), q.To.In(q.TZ).Format("20060102")))
			if err := res.WriteCSV(w); err != nil {
				h.logger.ErrorContext(r.Context(), "analytics csv", "error", err.Error())
			}
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func (h *AdminHandlers) apiAnalyticsLabelKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		q, ok := h.parseAnalytics(w, r)
		if !ok {
			return
		}
		keys, err := h.store.ListLabelKeys(r.Context(), q.OrgID, q.From, q.To)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, keys)
	}
}

func (h *AdminHandlers) parseAnalytics(w http.ResponseWriter, r *http.Request) (*adminstore.AnalyticsQuery, bool) {
	v := r.URL.Query()
	orgTZ := "UTC"
	if orgID := v.Get("org_id"); orgID != "" {
		org, err := h.store.GetOrganizationByID(r.Context(), orgID)
		if err != nil {
			if adminstore.IsNotFound(err) {
				h.respondError(w, r, err, http.StatusNotFound)
				return nil, false
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return nil, false
		}
		if org.Timezone != "" {
			orgTZ = org.Timezone
		}
	}
	if v.Get("metrics") == "" {
		v.Set("metrics", "requests")
	}
	q, err := adminstore.ParseAnalyticsQuery(v, orgTZ, time.Now())
	if err != nil {
		if ae, ok := err.(*adminstore.AnalyticsQueryError); ok {
			body := map[string]any{"error": ae.Error(), "code": ae.Code}
			if ae.HasPos {
				body["pos"] = ae.Pos
			}
			writeJSON(w, http.StatusBadRequest, body)
			return nil, false
		}
		h.respondError(w, r, err, http.StatusBadRequest)
		return nil, false
	}
	return q, true
}

func csvName(org string) string {
	out := make([]rune, 0, len(org))
	for _, r := range org {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "org"
	}
	return string(out)
}
