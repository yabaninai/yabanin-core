package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// W-SECADM: admin credential policy. A password shorter than
// minAdminPasswordLength is rejected at every entry point (user creation and
// self-service change); the max mirrors bcrypt's 72-byte input limit so a
// too-long secret is a 400, not a store-level 500 (or silent truncation).
const (
	minAdminPasswordLength = 12
	maxAdminPasswordLength = 72
)

// validateAdminEmail enforces a plain RFC 5322 address: net/mail must parse
// it and the parse must round-trip, which rejects display names
// ("Boss <boss@x.test>"), comments and other exotic forms.
func validateAdminEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// validateAdminPassword enforces the admin password policy.
func validateAdminPassword(password string) error {
	if len(password) < minAdminPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minAdminPasswordLength)
	}
	if len(password) > maxAdminPasswordLength {
		return fmt.Errorf("password must be at most %d characters", maxAdminPasswordLength)
	}
	return nil
}

// ListAdminUsers returns the collection of adminusers records visible to the caller.
func (h *AdminHandlers) ListAdminUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		activeOnly := r.URL.Query().Get("active_only") == "true"
		f, ok := parseListFilter(r, adminstore.AdminUserSortColumns)
		if !ok {
			writeInvalidSort(w)
			return
		}
		users, total, err := h.store.ListAdminUsers(r.Context(), activeOnly, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, users, total)
	}
}

// CreateAdminUser creates a new adminuser record.
func (h *AdminHandlers) CreateAdminUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Name     string `json:"name"`
			IsRoot   bool   `json:"is_root"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		// W-SECADM: credential validation happens before any hashing so a bad
		// email or an under-length password is a 400 and never reaches the
		// store.
		req.Email = strings.TrimSpace(req.Email)
		if err := validateAdminEmail(req.Email); err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		if err := validateAdminPassword(req.Password); err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		hashed, err := adminauth.HashPassword(req.Password)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("failed to hash password"), http.StatusInternalServerError)
			return
		}
		user, err := h.store.CreateAdminUser(r.Context(), req.Email, req.Name, hashed, req.IsRoot)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "admin_user", "id="+user.ID+",email="+req.Email+",name="+req.Name)
		writeJSON(w, http.StatusCreated, user)
	}
}

// GetAdminUser returns the requested adminuser record.
func (h *AdminHandlers) GetAdminUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		user, err := h.store.GetAdminUserByID(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, user)
	}
}

// UpdateAdminUser updates an existing adminuser record.
func (h *AdminHandlers) UpdateAdminUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		var req struct {
			Name   *string `json:"name"`
			IsRoot *bool   `json:"is_root"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Name == nil && req.IsRoot == nil {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		if err := h.store.UpdateAdminUser(r.Context(), id, req.Name, req.IsRoot); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		var details []string
		if req.Name != nil {
			details = append(details, "name="+*req.Name)
		}
		if req.IsRoot != nil {
			details = append(details, "is_root="+fmt.Sprintf("%v", *req.IsRoot))
		}
		h.auditLogAction(r, "update", "admin_user", "id="+id+","+strings.Join(details, ","))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DeleteAdminUser removes the adminuser record.
func (h *AdminHandlers) DeleteAdminUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if err := h.store.DeleteAdminUser(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "delete", "admin_user", "id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}
