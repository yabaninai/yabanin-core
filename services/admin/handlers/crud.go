package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/apierrors"
	"github.com/reireirei/yabanin/pkg/cache"
)

func validateIssueURL(template string) error {
	if len(template) > 256 || !strings.HasPrefix(template, "https://") || !strings.Contains(template, "{issue}") {
		return fmt.Errorf("issue_url_template must start with https://, contain {issue}, and be at most 256 characters")
	}
	return nil
}

// writeConflict answers an AF-09 precondition mismatch: 409 with the
// entity's CURRENT relevant state (never a re-write of the recorded state).
// The audit page surfaces it verbatim so the operator can decide on the
// fresh state instead of blindly re-rolling.
func writeConflict(w http.ResponseWriter, current map[string]any) {
	writeJSON(w, http.StatusConflict, map[string]any{"error": "conflict", "current": current})
}

// derefBool renders an optional bool as the zero value for conflict bodies.
func derefBool(b *bool) bool {
	return b != nil && *b
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON encode error", "error", err)
	}
}

type apiError struct {
	Error string `json:"error"`
}

// paginatedResponse wraps list payloads with pagination metadata.
type paginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination pagination  `json:"pagination"`
}

type pagination struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// parsePage extracts page/page_size query params and returns a normalised PageFilter.
// Missing/invalid values fall back to defaults (page=1, page_size=50).
func parsePage(r *http.Request) adminstore.PageFilter {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	return adminstore.NewPageFilter(page, pageSize)
}

// writeInvalidSort rejects a sort/dir pair that is not in the endpoint's
// allowlist (AUX-02). The body is exactly {"error":"invalid_sort"}.
func writeInvalidSort(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid_sort"})
}

// rawQueryValues returns the raw (still percent-encoded) values of a query
// key. Unlike url.Query it never silently drops malformed pairs (Go rejects
// ';' separators), so smuggled values stay visible for validation.
func rawQueryValues(rawQuery, key string) []string {
	var vals []string
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, found := strings.Cut(pair, "=")
		if !found {
			if pair == key {
				vals = append(vals, "")
			}
			continue
		}
		if k == key {
			vals = append(vals, v)
		}
	}
	return vals
}

// parseSortParams validates sort/dir query params against isAllowed (an
// endpoint's sort-column allowlist). ok=false means the request must be
// rejected with {"error":"invalid_sort"}: an unknown column, a dir other
// than asc/desc, or any value that fails to decode. An absent sort yields
// set=false (the endpoint's default order); an absent dir means asc.
func parseSortParams(rawQuery string, isAllowed func(string) bool) (column string, desc, set, ok bool) {
	ok = true
	for _, raw := range rawQueryValues(rawQuery, "dir") {
		d, err := url.QueryUnescape(raw)
		if err != nil || (d != "" && d != "asc" && d != "desc") {
			return "", false, false, false
		}
		desc = d == "desc"
	}
	for _, raw := range rawQueryValues(rawQuery, "sort") {
		s, err := url.QueryUnescape(raw)
		if err != nil || (s != "" && !isAllowed(s)) {
			return "", false, false, false
		}
		if !set && s != "" {
			column, set = s, true
		}
	}
	return column, desc, set, ok
}

// parseListFilter parses page + sort query params. allowed is the endpoint's
// sort-column allowlist; ok=false means the request must be rejected with
// {"error":"invalid_sort"} (see parseSortParams).
func parseListFilter(r *http.Request, allowed adminstore.SortColumns) (adminstore.PageFilter, bool) {
	f := parsePage(r)
	column, desc, set, ok := parseSortParams(r.URL.RawQuery, func(s string) bool {
		_, found := allowed[s]
		return found
	})
	if !ok {
		return f, false
	}
	if set {
		f.Sort = &adminstore.Sort{Column: column, Set: true, Desc: desc}
	}
	return f, true
}

// writePaginated writes a 200 response with data + pagination metadata.
func writePaginated(w http.ResponseWriter, f adminstore.PageFilter, items interface{}, total int64) {
	writeJSON(w, http.StatusOK, paginatedResponse{
		Data: items,
		Pagination: pagination{
			Page:       f.Page,
			PageSize:   f.PageSize,
			Total:      total,
			TotalPages: f.TotalPages(total),
		},
	})
}

func (h *AdminHandlers) respondError(w http.ResponseWriter, r *http.Request, err error, status int) {
	if h.logger != nil {
		h.logger.ErrorContext(r.Context(), "admin handler error", slog.String("error", err.Error()), slog.Int("status", status))
	}
	// S01: client-facing errors stay generic. Raw storage/SQL errors must not
	// leave the API (they leak schema and driver details); the full error is
	// in the log line above. 4xx are usually self-inflicted and safe to echo.
	message := err.Error()
	if status >= 500 {
		message = "internal server error"
	}
	writeJSON(w, status, apierrors.Admin(&apierrors.E{Status: status, Message: message}))
}

// ListOrganizations returns the collection of organizations records visible to the caller.
func (h *AdminHandlers) ListOrganizations() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		f, ok := parseListFilter(r, adminstore.OrganizationSortColumns)
		if !ok {
			writeInvalidSort(w)
			return
		}
		orgs, total, err := h.store.ListOrganizations(r.Context(), f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, orgs, total)
	}
}

// CreateOrganization creates a new organization record.
func (h *AdminHandlers) CreateOrganization() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		org, err := h.store.CreateOrganization(r.Context(), req.Name, req.Slug)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "organization", "id="+org.ID+",name="+req.Name)
		h.GrantBetaStarterCredits(r, org.ID) // W-CRED: exactly-once beta starter grant (env BETA_STARTER_CREDITS_CENTS)
		writeJSON(w, http.StatusCreated, org)
	}
}

// GetOrganization returns the requested organization record.
func (h *AdminHandlers) GetOrganization() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		org, err := h.store.GetOrganizationByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, org)
	}
}

// UpdateOrganization updates an existing organization record.
func (h *AdminHandlers) UpdateOrganization() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var req struct {
			Name     string `json:"name"`
			Slug     string `json:"slug"`
			Currency string `json:"currency"`
			Timezone string `json:"timezone"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var present map[string]json.RawMessage
		if err := json.Unmarshal(body, &present); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var issueURL *string
		if raw, ok := present["issue_url_template"]; ok {
			var template string
			if err := json.Unmarshal(raw, &template); err != nil {
				h.respondError(w, r, fmt.Errorf("issue_url_template must be a string"), http.StatusBadRequest)
				return
			}
			if err := validateIssueURL(template); err != nil {
				h.respondError(w, r, err, http.StatusBadRequest)
				return
			}
			issueURL = &template
		}
		if err := h.store.UpdateOrganization(r.Context(), id, req.Name, req.Slug, req.Currency, req.Timezone, issueURL); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "organization", "id="+id+",name="+req.Name+",currency="+req.Currency+",timezone="+req.Timezone)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteOrganization removes the organization record.
func (h *AdminHandlers) DeleteOrganization() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if err := h.store.DeleteOrganization(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "delete", "organization", "id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListTeams returns the collection of teams records visible to the caller.
func (h *AdminHandlers) ListTeams() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id query param required"), http.StatusBadRequest)
			return
		}
		f := parsePage(r)
		teams, total, err := h.store.ListTeamsByOrg(r.Context(), orgID, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, teams, total)
	}
}

// CreateTeam creates a new team record.
func (h *AdminHandlers) CreateTeam() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			OrgID      string `json:"org_id"`
			Name       string `json:"name"`
			Slug       string `json:"slug"`
			ParentTeam string `json:"parent_team,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var parentTeam *string
		if req.ParentTeam != "" {
			parentTeam = &req.ParentTeam
		}
		t, err := h.store.CreateTeam(r.Context(), req.OrgID, req.Name, req.Slug, parentTeam)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "team", "id="+t.ID+",name="+req.Name)
		writeJSON(w, http.StatusCreated, t)
	}
}

// GetTeam returns the requested team record.
func (h *AdminHandlers) GetTeam() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		t, err := h.store.GetTeamByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

// UpdateTeam updates an existing team record.
func (h *AdminHandlers) UpdateTeam() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			Name       string `json:"name"`
			Slug       string `json:"slug"`
			ParentTeam string `json:"parent_team,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var parentTeam *string
		if req.ParentTeam != "" {
			parentTeam = &req.ParentTeam
		}
		if err := h.store.UpdateTeam(r.Context(), id, req.Name, req.Slug, parentTeam); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "team", "id="+id+",name="+req.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteTeam removes the team record.
func (h *AdminHandlers) DeleteTeam() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if err := h.store.DeleteTeam(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "delete", "team", "id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// APIKeyExpiryStore supports clearing an API key's expiry (expires_at; nil = never expires). It is
// type-asserted from StoreInterface like CASStore, so the hot router file
// stays untouched; a store without the capability answers 501 instead of
// silently dropping the requested change.
type APIKeyExpiryStore interface {
	UpdateAPIKeyExpiry(ctx context.Context, id string, expiresAt *time.Time) error
}

// apiKeyExpiryStore returns the store's expiry capability, or nil when
// unsupported.
func (h *AdminHandlers) apiKeyExpiryStore() APIKeyExpiryStore {
	es, _ := h.store.(APIKeyExpiryStore)
	return es
}

// set=false means "clear the column" (the field was "" or null: never
// expires); set=true carries the parsed instant. A malformed value is an
// error.
func parseAPIKeyExpiry(raw string) (exp time.Time, set bool, err error) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "null" {
		return time.Time{}, false, nil
	}
	t, perr := time.Parse(time.RFC3339, s)
	if perr != nil {
		return time.Time{}, false, fmt.Errorf("expires_at must be an RFC3339 timestamp or null")
	}
	return t, true, nil
}

// ListAPIKeys returns the collection of apikeys records visible to the caller.
func (h *AdminHandlers) ListAPIKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if sessionNonRoot(r) {
			// An empty filter used to list every org. Non-root callers are
			// pinned to the scope org; a different query org is rejected.
			scoped := h.requireOrgScope(w, r, orgID, adminstore.PermKeysManage)
			if scoped == "" {
				return
			}
			orgID = scoped
		}
		var orgIDPtr *string
		if orgID != "" {
			orgIDPtr = &orgID
		}
		f, ok := parseListFilter(r, adminstore.APIKeySortColumns)
		if !ok {
			writeInvalidSort(w)
			return
		}
		keys, total, err := h.store.ListAPIKeys(r.Context(), orgIDPtr, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, keys, total)
	}
}

// CreateAPIKey creates a new apikey record.
func (h *AdminHandlers) CreateAPIKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			Name      string `json:"name"`
			OrgID     string `json:"org_id"`
			KeyHash   string `json:"key_hash"`
			TeamID    string `json:"team_id,omitempty"`
			RulesMode string `json:"rules_mode,omitempty"`
			// ""/"null" = never expires; else RFC3339.
			ExpiresAt *string `json:"expires_at,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var exp *time.Time
		expiryRequested := false
		var expiryStore APIKeyExpiryStore
		if req.ExpiresAt != nil {
			expiryRequested = true
			parsed, set, perr := parseAPIKeyExpiry(*req.ExpiresAt)
			if perr != nil {
				h.respondError(w, r, perr, http.StatusBadRequest)
				return
			}
			if set {
				exp = &parsed
			}
			// Refuse before the insert so an unsupported store never leaves a
			// half-created key behind.
			expiryStore = h.apiKeyExpiryStore()
			if expiryStore == nil {
				h.respondError(w, r, fmt.Errorf("expiry updates not supported"), http.StatusNotImplemented)
				return
			}
		}
		if sessionNonRoot(r) {
			scoped := h.requireOrgScope(w, r, req.OrgID, adminstore.PermKeysManage)
			if scoped == "" {
				return
			}
			req.OrgID = scoped
		}
		orgIDPtr := &req.OrgID
		// NEXT-01 owner decision 2026-09-18: default-team fallback.
		// An omitted team_id resolves to the org's default team (slug='default',
		// created on first use); a provided team must exist and belong to this org.
		var team *adminstore.Team
		var err error
		if req.TeamID == "" {
			team, err = h.store.GetDefaultTeam(r.Context(), req.OrgID)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("could not resolve default team: %w", err), http.StatusInternalServerError)
				return
			}
			req.TeamID = team.ID
		} else {
			team, err = h.store.GetTeamByID(r.Context(), req.TeamID)
			if err != nil || team == nil {
				h.respondError(w, r, fmt.Errorf("unknown team_id"), http.StatusBadRequest)
				return
			}
			if team.OrgID != req.OrgID {
				h.respondError(w, r, fmt.Errorf("team_id does not belong to this organization"), http.StatusBadRequest)
				return
			}
		}
		teamIDPtr := &req.TeamID
		key, err := h.store.CreateAPIKey(r.Context(), req.KeyHash, req.Name, orgIDPtr, teamIDPtr)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		// any stale resolver entry for the (possibly reused) hash.
		if expiryRequested {
			if err := expiryStore.UpdateAPIKeyExpiry(r.Context(), key.ID, exp); err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.purgeResolverKeys(r.Context(), key.KeyHash)
			key.ExpiresAt = exp
		}
		h.auditLogAction(r, "create", "api_key", "id="+key.ID+",name="+req.Name)
		writeJSON(w, http.StatusCreated, key)
	}
}

// GetAPIKey returns the requested apikey record.
func (h *AdminHandlers) GetAPIKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		key, err := h.store.GetAPIKeyByID(r.Context(), id)
		if err != nil || key == nil {
			if err == nil {
				err = fmt.Errorf("api key not found")
			}
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if h.apiKeyHidden(w, r, key) {
			return
		}
		writeJSON(w, http.StatusOK, key)
	}
}

// UpdateAPIKeyActive updates an existing apikeyactive record.
//
// AF-09: an optional expected_active turns the toggle into an atomic
// compare-and-set (the audit journal's rollback carries the recorded after
// state here). On mismatch the handler answers 409 with the current state
// and applies NOTHING — no session revocation, no journal entry.
//
// expires_at no longer implicitly deactivates the key (a plain bool would
// decode an absent field as false). nil active = leave it untouched; a body
// must carry active or expires_at.
func (h *AdminHandlers) UpdateAPIKeyActive() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			Active *bool `json:"active,omitempty"`
			// clear (never expires); else RFC3339.
			ExpiresAt      *string `json:"expires_at,omitempty"`
			ExpectedActive *bool   `json:"expected_active,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Active == nil && req.ExpiresAt == nil {
			h.respondError(w, r, fmt.Errorf("active or expires_at is required"), http.StatusBadRequest)
			return
		}
		if req.Active == nil && req.ExpectedActive != nil {
			h.respondError(w, r, fmt.Errorf("expected_active requires active"), http.StatusBadRequest)
			return
		}
		var exp *time.Time
		var expiryStore APIKeyExpiryStore
		if req.ExpiresAt != nil {
			parsed, set, perr := parseAPIKeyExpiry(*req.ExpiresAt)
			if perr != nil {
				h.respondError(w, r, perr, http.StatusBadRequest)
				return
			}
			if set {
				exp = &parsed
			}
			expiryStore = h.apiKeyExpiryStore()
			if expiryStore == nil {
				h.respondError(w, r, fmt.Errorf("expiry updates not supported"), http.StatusNotImplemented)
				return
			}
		}
		active := req.Active != nil && *req.Active
		deactivate := req.Active != nil && !active
		// S02: fetch the hash before the update so a deactivation can purge.
		key, _ := h.store.GetAPIKeyByID(r.Context(), id)
		if key != nil && h.apiKeyHidden(w, r, key) {
			return
		}
		// AUX-14b: capture the pre-toggle state BEFORE the store mutates the
		// row pointer, so the journal records where the toggle started.
		var before any = map[string]any{"id": id}
		if key != nil {
			before = map[string]any{"id": id, "active": key.Active}
		}
		applyExpiry := func(ctx context.Context, after map[string]any) error {
			if expiryStore == nil {
				return nil
			}
			// purge so a newly past expiry rejects immediately (the
			// deactivation purge only runs for a deactivation).
			if err := expiryStore.UpdateAPIKeyExpiry(ctx, id, exp); err != nil {
				return err
			}
			if key != nil {
				h.purgeResolverKeys(ctx, key.KeyHash)
			}
			after["expires_at"] = req.ExpiresAt
			return nil
		}
		if req.ExpectedActive != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			current, err := cs.UpdateAPIKeyActivePreconditioned(r.Context(), id, active, req.ExpectedActive)
			if adminstore.IsNotFound(err) {
				h.respondError(w, r, fmt.Errorf("api key not found"), http.StatusNotFound)
				return
			}
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, map[string]any{"id": id, "active": derefBool(current)})
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			// Side effects only after the atomic state change won: a
			// conflicted rollback must not revoke live sessions.
			if deactivate && key != nil {
				hashes, rerr := h.store.RevokeSessionKeysByParent(r.Context(), id)
				if rerr != nil {
					h.respondError(w, r, rerr, http.StatusInternalServerError)
					return
				}
				h.purgeResolverKeys(r.Context(), append(hashes, key.KeyHash)...)
			}
			after := map[string]any{"id": id, "active": active}
			if err := applyExpiry(r.Context(), after); err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			h.auditLogActionDiff(r, "update", "api_key", "id="+id+",active="+fmt.Sprintf("%v", active), before, after)
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		var hashes []string
		if deactivate && key != nil {
			var rerr error
			hashes, rerr = h.store.RevokeSessionKeysByParent(r.Context(), id)
			if rerr != nil {
				h.respondError(w, r, rerr, http.StatusInternalServerError)
				return
			}
		}
		if req.Active != nil {
			if err := h.store.UpdateAPIKeyActive(r.Context(), id, active); err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
		}
		if deactivate && key != nil {
			h.purgeResolverKeys(r.Context(), append(hashes, key.KeyHash)...)
		}
		// AUX-14b: the enable toggle is safely reversible — journal both
		// states so the audit page can offer the inverse PUT.
		after := map[string]any{"id": id}
		if req.Active != nil {
			after["active"] = active
		}
		if err := applyExpiry(r.Context(), after); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		detail := "id=" + id
		if req.Active != nil {
			detail += ",active=" + fmt.Sprintf("%v", active)
		}
		if req.ExpiresAt != nil {
			detail += ",expires_at=" + *req.ExpiresAt
		}
		h.auditLogActionDiff(r, "update", "api_key", detail, before, after)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// RotateAPIKey replaces an API key's secret while keeping its identity and settings.
// RotateAPIKey.
func (h *AdminHandlers) RotateAPIKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			KeyHash string `json:"key_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		key, _ := h.store.GetAPIKeyByID(r.Context(), id)
		if key != nil && h.apiKeyHidden(w, r, key) {
			return
		}
		hashes, rerr := h.store.RevokeSessionKeysByParent(r.Context(), id)
		if rerr != nil {
			h.respondError(w, r, rerr, http.StatusInternalServerError)
			return
		}
		if err := h.store.RotateAPIKey(r.Context(), id, req.KeyHash); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if key != nil {
			h.purgeResolverKeys(r.Context(), append(hashes, key.KeyHash)...) // the OLD key dies now, not at TTL
		} else if len(hashes) > 0 {
			h.purgeResolverKeys(r.Context(), hashes...)
		}
		h.auditLogAction(r, "rotate_api_key", "api_key", "id="+id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteAPIKey removes the apikey record.
func (h *AdminHandlers) DeleteAPIKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		key, _ := h.store.GetAPIKeyByID(r.Context(), id)
		if key != nil && h.apiKeyHidden(w, r, key) {
			return
		}
		hashes, rerr := h.store.RevokeSessionKeysByParent(r.Context(), id)
		if rerr != nil {
			h.respondError(w, r, rerr, http.StatusInternalServerError)
			return
		}
		if err := h.store.DeleteAPIKey(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if key != nil {
			h.purgeResolverKeys(r.Context(), append(hashes, key.KeyHash)...)
		} else if len(hashes) > 0 {
			h.purgeResolverKeys(r.Context(), hashes...)
		}
		h.auditLogAction(r, "delete", "api_key", "id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// apiKeyHidden reports a foreign key as 404. A nil org on the row is treated
// as foreign for non-root so an unscoped key is not readable through an org.
func (h *AdminHandlers) apiKeyHidden(w http.ResponseWriter, r *http.Request, key *adminstore.APIKey) bool {
	if key == nil {
		return false
	}
	org := ""
	if key.OrgID != nil {
		org = *key.OrgID
	}
	return h.resourceHidden(w, r, org)
}

// redactedModel returns a copy of m that is safe for admin API responses
// key is configured. The value itself — plaintext or the store's decrypted
// read — never leaves the process.
func redactedModel(m *adminstore.ModelRegistry) *adminstore.ModelRegistry {
	if m == nil {
		return nil
	}
	cp := *m
	cp.HasUpstreamKey = m.UpstreamAPIKey != nil && *m.UpstreamAPIKey != ""
	cp.UpstreamAPIKey = nil
	return &cp
}

// redactedModels redacts a page of model rows (see redactedModel).
func redactedModels(models []*adminstore.ModelRegistry) []*adminstore.ModelRegistry {
	out := make([]*adminstore.ModelRegistry, 0, len(models))
	for _, m := range models {
		out = append(out, redactedModel(m))
	}
	return out
}

// ListModels returns the collection of models records visible to the caller.
func (h *AdminHandlers) ListModels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		f, ok := parseListFilter(r, adminstore.ModelSortColumns)
		if !ok {
			writeInvalidSort(w)
			return
		}
		models, total, err := h.store.ListModels(r.Context(), f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, redactedModels(models), total)
	}
}

// CreateModel creates a new model record.
func (h *AdminHandlers) CreateModel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			ModelName         string   `json:"model_name"`
			DisplayName       string   `json:"display_name"`
			Tier              string   `json:"tier"`
			UpstreamURL       string   `json:"upstream_url,omitempty"`
			UpstreamKey       string   `json:"upstream_api_key,omitempty"`
			Provider          string   `json:"provider,omitempty"`
			FallbackModel     string   `json:"fallback_model,omitempty"`
			FailoverModels    []string `json:"failover_models,omitempty"`
			TierPool          []string `json:"tier_pool,omitempty"`
			UpstreamTimeoutMs *int     `json:"upstream_timeout_ms,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var upsURL, upsKey *string
		if req.UpstreamURL != "" {
			upsURL = &req.UpstreamURL
		}
		if req.UpstreamKey != "" {
			upsKey = &req.UpstreamKey
		}
		m, err := h.store.CreateModelWithParams(r.Context(), adminstore.CreateModelParams{
			ModelName:         req.ModelName,
			DisplayName:       req.DisplayName,
			Tier:              req.Tier,
			UpstreamURL:       upsURL,
			UpstreamAPIKey:    upsKey,
			Provider:          req.Provider,
			FallbackModel:     stringPtr(req.FallbackModel),
			FailoverModels:    req.FailoverModels,
			TierPool:          req.TierPool,
			UpstreamTimeoutMs: req.UpstreamTimeoutMs,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "model", "name="+req.ModelName+",display_name="+req.DisplayName)
		writeJSON(w, http.StatusCreated, redactedModel(m))
	}
}

// stringPtr returns a pointer to the string value.
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GetModel returns the requested model record.
func (h *AdminHandlers) GetModel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		model, err := h.store.GetModelByName(r.Context(), name)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, redactedModel(model))
	}
}

// UpdateModel updates an existing model record.
func (h *AdminHandlers) UpdateModel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var req struct {
			DisplayName       string   `json:"display_name,omitempty"`
			Tier              string   `json:"tier,omitempty"`
			UpstreamURL       string   `json:"upstream_url,omitempty"`
			UpstreamKey       string   `json:"upstream_api_key,omitempty"`
			ClearUpstreamKey  bool     `json:"clear_upstream_key,omitempty"`
			Provider          *string  `json:"provider,omitempty"`
			FallbackModel     *string  `json:"fallback_model,omitempty"`
			FailoverModels    []string `json:"failover_models,omitempty"`
			TierPool          []string `json:"tier_pool,omitempty"`
			UpstreamTimeoutMs *int     `json:"upstream_timeout_ms,omitempty"`
			Enabled           *bool    `json:"enabled,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.ClearUpstreamKey && req.UpstreamKey != "" {
			h.respondError(w, r, fmt.Errorf("use either upstream_api_key or clear_upstream_key, not both"), http.StatusBadRequest)
			return
		}
		var displayName, tier, upsURL, upsKey *string
		if req.DisplayName != "" {
			displayName = &req.DisplayName
		}
		if req.Tier != "" {
			tier = &req.Tier
		}
		if req.UpstreamURL != "" {
			upsURL = &req.UpstreamURL
		}
		if req.UpstreamKey != "" {
			upsKey = &req.UpstreamKey
		}

		var displayNameStr string
		if displayName != nil {
			displayNameStr = *displayName
		}

		err := h.store.UpdateModelWithParams(r.Context(), adminstore.UpdateModelParams{
			ModelName:         name,
			DisplayName:       displayName,
			Tier:              tier,
			UpstreamURL:       upsURL,
			UpstreamAPIKey:    upsKey,
			ClearUpstreamKey:  req.ClearUpstreamKey,
			Provider:          req.Provider,
			FallbackModel:     req.FallbackModel,
			FailoverModels:    req.FailoverModels,
			TierPool:          req.TierPool,
			UpstreamTimeoutMs: req.UpstreamTimeoutMs,
			Enabled:           req.Enabled,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Auto-invalidate cache for this model on upstream_url/key changes.
		//
		// API contract decision (FIX-04, documented): the model mutation is
		// the contract of this endpoint and keeps its 200 even when the
		// cache invalidation fails — but a failed invalidation is never
		// reported as success. It surfaces as a warn log with the error and
		// an audit entry with result=failed (instead of the old unconditional
		// "cache invalidated" line), so the stale-entry window is visible to
		// operators and the journal.
		if h.inv != nil && (upsURL != nil || upsKey != nil || req.ClearUpstreamKey || req.Enabled != nil) {
			// Look up the model's tier and invalidate its cache entries.
			// Fallback: try invalidating by model name as tier.
			tier := name
			if modelInfo, err := h.store.GetModelByName(r.Context(), name); err == nil && modelInfo != nil && modelInfo.Tier != "" {
				tier = modelInfo.Tier
			}
			if err := h.inv.InvalidateModelByTier(r.Context(), tier); err != nil {
				h.logger.Warn("cache invalidation failed after model update; stale entries remain until TTL",
					"model", name, "tier", tier, "error", err,
					"retryable", cache.IsRetryable(r.Context(), err), "canceled", cache.IsCancellation(err))
				h.auditLogActionWithCtx(r.Context(), r, "invalidate", "cache",
					fmt.Sprintf("result=failed model=%s tier=%s error=%q retryable=%v",
						name, tier, err.Error(), cache.IsRetryable(r.Context(), err)))
			} else {
				h.logger.Info("cache invalidated after model update", "model", name, "tier", tier,
					"ups_url_changed", upsURL != nil, "key_changed", upsKey != nil)
			}
		}

		h.auditLogAction(r, "update", "model", "name="+name+",display_name="+displayNameStr)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// UpdateModelEnabled updates an existing modelenabled record.
func (h *AdminHandlers) UpdateModelEnabled() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		name := chi.URLParam(r, "name")
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if err := h.store.UpdateModelEnabled(r.Context(), name, req.Enabled); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "model", "name="+name+",enabled="+fmt.Sprintf("%v", req.Enabled))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteModel removes the model record.
func (h *AdminHandlers) DeleteModel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		name := chi.URLParam(r, "name")

		// Pre-delete: look up the model's tier for cache invalidation.
		var modelTier string
		if h.inv != nil {
			if modelInfo, err := h.store.GetModelByName(r.Context(), name); err == nil && modelInfo != nil {
				modelTier = modelInfo.Tier
			}
		}

		if err := h.store.DeleteModel(r.Context(), name); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		// Auto-invalidate cache for the deleted model's tier. Same FIX-04
		// contract as UpdateModel: the 204 deletion stands, but a failed
		// invalidation is logged and audited as a failure — never as a
		// "cache invalidated" success.
		if h.inv != nil && modelTier != "" {
			if err := h.inv.InvalidateModelByTier(r.Context(), modelTier); err != nil {
				h.logger.Warn("cache invalidation failed after model deletion; stale entries remain until TTL",
					"model", name, "tier", modelTier, "error", err,
					"retryable", cache.IsRetryable(r.Context(), err), "canceled", cache.IsCancellation(err))
				h.auditLogActionWithCtx(r.Context(), r, "invalidate", "cache",
					fmt.Sprintf("result=failed model=%s tier=%s error=%q retryable=%v",
						name, modelTier, err.Error(), cache.IsRetryable(r.Context(), err)))
			} else {
				h.logger.Info("cache invalidated after model deletion", "model", name, "tier", modelTier)
			}
		}

		h.auditLogAction(r, "delete", "model", "name="+name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListRoutingRules returns the collection of routingrules records visible to the caller.
func (h *AdminHandlers) ListRoutingRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id query param required"), http.StatusBadRequest)
			return
		}
		f, ok := parseListFilter(r, adminstore.RoutingRuleSortColumns)
		if !ok {
			writeInvalidSort(w)
			return
		}
		rules, total, err := h.store.ListRoutingRulesByOrg(r.Context(), orgID, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, rules, total)
	}
}

// CreateRoutingRule creates a new routingrule record.
func (h *AdminHandlers) CreateRoutingRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			OrgID       string `json:"org_id"`
			MatchExpr   string `json:"match_expr"`
			TargetModel string `json:"target_model"`
			Priority    int    `json:"priority"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		rule, err := h.store.CreateRoutingRule(r.Context(), req.OrgID, req.MatchExpr, req.TargetModel, req.Priority)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		// RT-06: new rules must be visible without waiting for the cache TTL.
		h.invalidateRuleCache(r, req.OrgID)
		h.auditLogAction(r, "create", "routing_rule", "id="+rule.ID+",match_expr="+req.MatchExpr+",target_model="+req.TargetModel)
		writeJSON(w, http.StatusCreated, rule)
	}
}

// GetRoutingRule returns the requested routingrule record.
func (h *AdminHandlers) GetRoutingRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		rule, err := h.store.GetRoutingRuleByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

// UpdateRoutingRule updates an existing routingrule record.
func (h *AdminHandlers) UpdateRoutingRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			MatchExpr   string `json:"match_expr,omitempty"`
			TargetModel string `json:"target_model,omitempty"`
			Priority    *int   `json:"priority,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		// RT-06: resolve the rule's org so the affected cache entry can be
		// invalidated (also turns a previously silent no-op update of a
		// missing id into an explicit 404).
		rule, err := h.store.GetRoutingRuleByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if err := h.store.UpdateRoutingRule(r.Context(), id, req.MatchExpr, req.TargetModel, req.Priority); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.invalidateRuleCache(r, rule.OrgID)
		h.auditLogAction(r, "update", "routing_rule", "id="+id+",match_expr="+req.MatchExpr+",target_model="+req.TargetModel)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// UpdateRoutingRuleEnabled updates an existing routingruleenabled record.
//
// AF-09: an optional expected_enabled makes the toggle an atomic
// compare-and-set for the audit rollback path; a stale rollback conflicts
// with 409 + current state and never cancels a newer enable decision.
func (h *AdminHandlers) UpdateRoutingRuleEnabled() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			Enabled         bool  `json:"enabled"`
			ExpectedEnabled *bool `json:"expected_enabled,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		// RT-06: resolve the rule's org for cache invalidation (also turns a
		// previously silent no-op enable toggle of a missing id into a 404).
		rule, err := h.store.GetRoutingRuleByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		// AUX-14b: capture the pre-toggle state BEFORE the store mutates the
		// rule pointer.
		before := map[string]any{"id": id, "enabled": rule.Enabled}
		var current *bool
		if req.ExpectedEnabled != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			current, err = cs.UpdateRoutingRuleEnabledPreconditioned(r.Context(), id, req.Enabled, req.ExpectedEnabled)
			if adminstore.IsNotFound(err) {
				h.respondError(w, r, fmt.Errorf("routing rule not found"), http.StatusNotFound)
				return
			}
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					writeConflict(w, map[string]any{"id": id, "enabled": derefBool(current)})
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
		} else if err = h.store.UpdateRoutingRuleEnabled(r.Context(), id, req.Enabled); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.invalidateRuleCache(r, rule.OrgID)
		// AUX-14b: the enable toggle is safely reversible — journal both
		// states so the audit page can offer the inverse PUT.
		after := map[string]any{"id": id, "enabled": req.Enabled}
		h.auditLogActionDiff(r, "update", "routing_rule", "id="+id+",enabled="+fmt.Sprintf("%v", req.Enabled), before, after)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteRoutingRule removes the routingrule record.
func (h *AdminHandlers) DeleteRoutingRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		// RT-06: resolve the rule's org before deleting so the cache entry
		// can be invalidated after the delete.
		rule, err := h.store.GetRoutingRuleByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if err := h.store.DeleteRoutingRule(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.invalidateRuleCache(r, rule.OrgID)
		h.auditLogAction(r, "delete", "routing_rule", "id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}
