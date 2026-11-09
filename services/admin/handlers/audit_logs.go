package handlers

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// auditSortKeys maps allowlisted audit-log sort columns (AUX-02) to a
// comparison key. These are handler-local literals; request values only
// look entries up here, never build a comparison expression. The timestamp
// key uses a fixed-width fraction so lexical order equals chronological
// order (RFC3339Nano strips trailing zeros and would misorder e.g.
// 10:00:01Z after 10:00:01.5Z). The same allowlist drives the DB-backed
// read (adminstore maps them to SQL columns; the store re-validates).
var auditSortKeys = map[string]func(*AuditLogEntry) string{
	"id":         func(e *AuditLogEntry) string { return e.ID },
	"action":     func(e *AuditLogEntry) string { return e.Action },
	"resource":   func(e *AuditLogEntry) string { return e.Resource },
	"admin_id":   func(e *AuditLogEntry) string { return e.AdminID },
	"admin_name": func(e *AuditLogEntry) string { return e.AdminName },
	"ip_address": func(e *AuditLogEntry) string { return e.IPAddress },
	"timestamp":  func(e *AuditLogEntry) string { return e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00") },
}

// auditListParams is the parsed list query shared by both read paths.
type auditListParams struct {
	column   string
	desc     bool
	sortSet  bool
	page     int
	pageSize int
}

// parseAuditListParams validates page/page_size/sort exactly as before; an
// unknown sort column answers 400 invalid_sort (the allowlist is the same
// for the DB-backed and the legacy in-buffer path).
func parseAuditListParams(rawQuery, pageStr, pageSizeStr string) (auditListParams, bool) {
	p := auditListParams{page: 1, pageSize: 50}

	if pageStr != "" {
		if v, err := strconv.Atoi(pageStr); err == nil && v > 0 {
			p.page = v
		}
	}
	if pageSizeStr != "" {
		if v, err := strconv.Atoi(pageSizeStr); err == nil && v > 0 && v <= 100 {
			p.pageSize = v
		}
	}

	column, desc, set, ok := parseSortParams(rawQuery, func(s string) bool {
		_, found := auditSortKeys[s]
		return found
	})
	if !ok {
		return p, false
	}
	p.column, p.desc, p.sortSet = column, desc, set
	return p, true
}

// ListAuditLogs returns paginated audit log entries. With the AF-10 durable
// audit capability the journal is read from the DB (persisted rows carry the
// full sanitized before/after/reason; a restart or a second admin instance
// returns the same journal) plus the pending_audit_entries counter that
// exposes undelivered entries — a store failure never masquerades as durable
// success. Without the capability the legacy in-memory buffer is served.
//
// Sorting: sort=<allowlisted column>&dir=<asc|desc>; the unique seq is the
// tie-breaker in the DB path, SliceStable keeps insertion order in the
// buffer path, so pagination stays stable either way.
func (h *AdminHandlers) ListAuditLogs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params, ok := parseAuditListParams(r.URL.RawQuery, r.URL.Query().Get("page"), r.URL.Query().Get("page_size"))
		if !ok {
			writeInvalidSort(w)
			return
		}

		if js := h.auditJournal(); js != nil {
			h.listAuditLogsFromStore(w, r, js, params)
			return
		}
		h.listAuditLogsFromBuffer(w, r, params)
	}
}

// listAuditLogsFromStore serves the persisted journal (AF-10).
func (h *AdminHandlers) listAuditLogsFromStore(w http.ResponseWriter, r *http.Request, js AuditJournalStore, params auditListParams) {
	sortColumn := params.column
	if !params.sortSet {
		sortColumn = "" // insertion (seq) order
	}
	items, total, pending, err := js.ListAuditLogEntries(r.Context(), adminstore.AuditLogQuery{
		Sort:     sortColumn,
		Desc:     params.desc,
		Page:     params.page,
		PageSize: params.pageSize,
	})
	if err != nil {
		h.auditLog().Error("audit journal read failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "failed to list audit logs"})
		return
	}

	entries := make([]AuditLogEntry, 0, len(items))
	entries = append(entries, items...)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"audit_logs":            entries,
		"total":                 total,
		"page":                  params.page,
		"page_size":             params.pageSize,
		"pending_audit_entries": pending + int64(h.pendingAuditCount()),
	})
}

// listAuditLogsFromBuffer is the legacy in-memory path (stores without the
// AF-10 capability).
func (h *AdminHandlers) listAuditLogsFromBuffer(w http.ResponseWriter, r *http.Request, params auditListParams) {
	var sortFn func(*AuditLogEntry) string
	if params.sortSet {
		sortFn = auditSortKeys[params.column]
	}

	h.auditMu.RLock()
	buffer := make([]AuditLogEntry, len(h.auditLogBuffer))
	copy(buffer, h.auditLogBuffer)
	h.auditMu.RUnlock()

	if sortFn != nil {
		sort.SliceStable(buffer, func(i, j int) bool {
			a, b := sortFn(&buffer[i]), sortFn(&buffer[j])
			if params.desc {
				return b < a
			}
			return a < b
		})
	}

	offset := (params.page - 1) * params.pageSize
	if offset > len(buffer) {
		offset = len(buffer)
	}
	end := offset + params.pageSize
	if end > len(buffer) {
		end = len(buffer)
	}
	pageItems := buffer[offset:end]

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"audit_logs":            pageItems,
		"total":                 len(buffer),
		"page":                  params.page,
		"page_size":             params.pageSize,
		"pending_audit_entries": h.pendingAuditCount(),
	})
}
