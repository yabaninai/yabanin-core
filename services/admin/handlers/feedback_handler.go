package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/logctx"
)

// SubmitFeedbackHandler handles POST /v1/feedback for user feedback on classifier decisions.
//
// NEXT-15-F2: the org is derived SERVER-SIDE from the caller's API key
// (org api_key or yag_ agent key). A client-supplied X-Org-Id no longer
// attributes feedback — an anonymous caller must not pollute another org's
// classifier training signal.
type SubmitFeedbackHandler struct {
	collector *feedback.Collector
	resolver  *auth.Resolver
}

// NewSubmitFeedbackHandler builds the public feedback submission endpoint.
// NewSubmitFeedbackHandler.
func NewSubmitFeedbackHandler(collector *feedback.Collector, resolver *auth.Resolver) *SubmitFeedbackHandler {
	return &SubmitFeedbackHandler{collector: collector, resolver: resolver}
}

func (h *SubmitFeedbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req feedback.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		http.Error(w, "invalid action: "+err.Error(), http.StatusBadRequest)
		return
	}

	// NEXT-15-F2: authenticate the caller and derive the org server-side.
	// The X-Org-Id header is intentionally NOT read anymore.
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || h.resolver == nil {
		http.Error(w, "authorization required: Bearer <api key>", http.StatusUnauthorized)
		return
	}
	res, err := h.resolver.Resolve(r.Context(), token)
	if err != nil || res == nil || res.OrgID == "" {
		http.Error(w, "invalid API key", http.StatusUnauthorized)
		return
	}
	orgID := res.OrgID

	requestID := r.Header.Get("X-Request-Id")
	promptHash := r.Header.Get("X-Prompt-Hash")

	if requestID == "" {
		http.Error(w, "X-Request-Id header is required", http.StatusBadRequest)
		return
	}

	// Determine the original class: use OverrideClass if provided (client override),
	// otherwise we'd need to look it up from the classifier cache/request_logs.
	// For now, require explicit class in the request body for simplicity.
	var originalClass string
	if req.OverrideClass != nil {
		originalClass = *req.OverrideClass
	} else {
		originalClass = r.Header.Get("X-Original-Class")
	}
	if originalClass == "" {
		http.Error(w, "override_class body field or X-Original-Class header is required", http.StatusBadRequest)
		return
	}

	err = h.collector.Record(r.Context(), orgID, requestID, promptHash, classifier.Class(originalClass), req.Action)
	if err != nil {
		logctx.From(r.Context(), nil).Error("feedback record failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// W-FEED: root-only owner surface over classifier_feedback (list + CSV
// export). The lister is wired by the starter only when the database is
// configured; unwired routes answer 503 like the other DB-gated groups.

// FeedbackLister is the read surface of pkg/feedback.Lister (interface so the
// handler is unit-testable without a database).
type FeedbackLister interface {
	ListFeedback(ctx context.Context, filter feedback.ListFilter) (feedback.ListPage, error)
}

// SetFeedbackLister wires the owner feedback list/export routes (nil = the
// routes stay unmounted).
func (h *AdminHandlers) SetFeedbackLister(l FeedbackLister) { h.feedback.lister = l }

// parseFeedbackListFilter reads the shared query contract of the list and
// export endpoints: org_id, rating (action), page, page_size.
func parseFeedbackListFilter(r *http.Request) (feedback.ListFilter, error) {
	q := r.URL.Query()
	filter := feedback.ListFilter{
		OrgID:    strings.TrimSpace(q.Get("org_id")),
		Action:   strings.TrimSpace(q.Get("rating")),
		Page:     1,
		PageSize: 0,
	}
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return filter, fmt.Errorf("invalid page")
		}
		filter.Page = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return filter, fmt.Errorf("invalid page_size")
		}
		filter.PageSize = n
	}
	if !filter.Valid() {
		return filter, fmt.Errorf("invalid rating: %s (want thumbs_up, thumbs_down or regenerate)", filter.Action)
	}
	return filter, nil
}

// requireFeedbackLister answers 503 when the lister is unwired.
func (h *AdminHandlers) requireFeedbackLister(w http.ResponseWriter, r *http.Request) bool {
	if h.feedback.lister == nil {
		h.respondError(w, r, fmt.Errorf("feedback list is not configured"), http.StatusServiceUnavailable)
		return false
	}
	return true
}

// ListFeedbackHandler — GET /api/feedback (root-only): the owner listing of
// /v1/feedback records with org/rating filters and page pagination.
func (h *AdminHandlers) ListFeedbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireFeedbackLister(w, r) {
			return
		}
		filter, err := parseFeedbackListFilter(r)
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		page, err := h.feedback.lister.ListFeedback(r.Context(), filter)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, page)
	}
}

// ExportFeedbackHandler — GET /api/feedback/export (root-only): the same
// filters as the list, rendered as an RFC 4180 CSV download. The page
// parameters do not apply — an export is always the full filtered set.
func (h *AdminHandlers) ExportFeedbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireFeedbackLister(w, r) {
			return
		}
		filter, err := parseFeedbackListFilter(r)
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		filter.Page = 1
		filter.PageSize = feedback.ListMaxPageSize
		page, err := h.feedback.lister.ListFeedback(r.Context(), filter)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=feedback-%s.csv", time.Now().UTC().Format("20060102")))
		w.WriteHeader(http.StatusOK)
		if err := feedback.WriteCSV(w, page.Entries); err != nil {
			h.logger.Error("feedback csv export failed", "error", err)
		}
	}
}
