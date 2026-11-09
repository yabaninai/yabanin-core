package handlers

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
)

// PortalStore is the developer-portal subset of the admin store.

// portalSessionDuration is the PORTAL (developer) session lifetime. It keeps
// its own 7-day constant — deliberately separate from the ADMIN console's
// adminauth.SessionDuration, which W-SECADM shortened to 24h for the admin
// issuers only (admin sessions ≠ developer portal sessions).
const portalSessionDuration = 7 * 24 * time.Hour

// PortalStore is the developer-portal subset of the admin store.
type PortalStore interface {
	GetDeveloperByEmail(ctx context.Context, email string) (*adminstore.DeveloperUser, error)
	GetDeveloperByID(ctx context.Context, id string) (*adminstore.DeveloperUser, error)
	CreateDeveloper(ctx context.Context, u adminstore.DeveloperUser) (*adminstore.DeveloperUser, error)
	BindDeveloperSubject(ctx context.Context, id, subject string) error
	ListDevelopers(ctx context.Context, orgID string) ([]adminstore.DeveloperUser, error)
	SetDeveloperActive(ctx context.Context, id string, active bool) error
	CountActiveDeveloperKeys(ctx context.Context, userID string) (int, error)
	ListDeveloperKeys(ctx context.Context, userID string) ([]adminstore.DeveloperKey, error)
	CreateDeveloperKey(ctx context.Context, userID, orgID, teamID, name, keyHash string, expiresAt *time.Time) (*adminstore.DeveloperKey, error)
	DeactivateDeveloperKey(ctx context.Context, userID, keyID string) (string, error)
	DeactivateDeveloperKeys(ctx context.Context, userID string) ([]string, error)
}

// PortalOptions turns the developer portal on. Client may be nil when the
// OIDC tuple is incomplete; login then answers 404 and existing sessions
// still reach /api/me.
type PortalOptions struct {
	Enabled        bool
	Provisioning   string
	AllowedDomains []string
	DefaultOrg     string
	DefaultTeam    string
	MaxKeys        int
	KeyTTLDays     int
	GatewayURL     string
	Client         *adminauth.OIDCClient
	Store          PortalStore
}

// SetPortal wires the developer portal. Call it before SetupRouter.
func (h *AdminHandlers) SetPortal(opt PortalOptions) {
	h.portal.enabled = opt.Enabled
	h.portal.client = opt.Client
	h.portal.store = opt.Store
	h.portal.provisioning = opt.Provisioning
	if h.portal.provisioning != "domain" {
		h.portal.provisioning = "invite"
	}
	h.portal.domains = map[string]struct{}{}
	for _, d := range opt.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			h.portal.domains[d] = struct{}{}
		}
	}
	h.portal.defaultOrg = opt.DefaultOrg
	h.portal.defaultTeam = opt.DefaultTeam
	h.portal.maxKeys = opt.MaxKeys
	if h.portal.maxKeys <= 0 {
		h.portal.maxKeys = 5
	}
	h.portal.keyTTLDays = opt.KeyTTLDays
	h.portal.gatewayURL = strings.TrimRight(strings.TrimSpace(opt.GatewayURL), "/")
}

func (h *AdminHandlers) requirePortalStore(w http.ResponseWriter, r *http.Request) bool {
	if h.portal.store == nil {
		h.respondError(w, r, fmt.Errorf("portal store not configured"), http.StatusServiceUnavailable)
		return false
	}
	return true
}

// PortalLogin starts the developer OIDC flow.
func (h *AdminHandlers) PortalLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.portal.client == nil {
			http.NotFound(w, r)
			return
		}
		flow, err := adminauth.NewOIDCFlow()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		cookie, err := adminauth.NewPortalOIDCFlowCookie(flow)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, h.portal.client.AuthCodeURL(flow), http.StatusFound)
	}
}

// PortalCallback finishes the portal login. Invite mode requires an existing
// active developer. Domain mode creates one when the email domain is allowed.
func (h *AdminHandlers) PortalCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.portal.client == nil {
			http.NotFound(w, r)
			return
		}
		if !h.requirePortalStore(w, r) {
			return
		}
		flowCookie, err := r.Cookie(adminauth.PortalOIDCFlowCookieName)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		flow, err := adminauth.ParseOIDCFlowCookie(flowCookie.Value)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, adminauth.ClearPortalOIDCFlowCookie())

		q := r.URL.Query()
		if q.Get("error") != "" {
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		state := q.Get("state")
		if state == "" || !hmac.Equal([]byte(flow.State), []byte(state)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ident, err := h.portal.client.ExchangeAndVerify(r.Context(), code, flow.Nonce, flow.PKCEVerifier)
		if err != nil {
			h.logger.Warn("portal callback: verification failed", "error", err)
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		if !ident.EmailVerified {
			http.Error(w, "email not verified at the provider", http.StatusForbidden)
			return
		}
		user, err := h.admitPortalUser(r.Context(), ident)
		if err != nil || user == nil || !user.Active {
			h.logger.Warn("portal callback: login refused", "email_domain", domainOf(ident.Email))
			http.Error(w, "sso login refused", http.StatusForbidden)
			return
		}
		session := adminauth.PortalSession{
			UserID:    user.ID,
			Email:     user.Email,
			SessionID: generateSessionID(),
			ExpiresAt: time.Now().Add(portalSessionDuration),
		}
		cookie, err := adminauth.CreatePortalSessionCookie(session, h.sessionSecret)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("session error"), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		adminauth.GeneratePortalCSRFToken(w)
		http.Redirect(w, r, "/portal", http.StatusFound)
	}
}

func (h *AdminHandlers) admitPortalUser(ctx context.Context, ident adminauth.OIDCIdentity) (*adminstore.DeveloperUser, error) {
	email := strings.ToLower(strings.TrimSpace(ident.Email))
	if h.portal.provisioning == "domain" {
		return h.admitDomainUser(ctx, email, ident.Subject)
	}
	user, err := h.portal.store.GetDeveloperByEmail(ctx, email)
	if err != nil || user == nil || !user.Active {
		return nil, err
	}
	if err := h.portal.store.BindDeveloperSubject(ctx, user.ID, ident.Subject); err != nil {
		return nil, err
	}
	return user, nil
}

func (h *AdminHandlers) admitDomainUser(ctx context.Context, email, subject string) (*adminstore.DeveloperUser, error) {
	domain := domainOf(email)
	if _, ok := h.portal.domains[strings.ToLower(domain)]; !ok {
		return nil, fmt.Errorf("email domain is not allowed")
	}
	if h.portal.defaultOrg == "" || h.portal.defaultTeam == "" {
		return nil, fmt.Errorf("portal default org and team are required")
	}
	user, err := h.portal.store.GetDeveloperByEmail(ctx, email)
	if err != nil {
		if !adminstore.IsNotFound(err) {
			return nil, err
		}
		created, cerr := h.portal.store.CreateDeveloper(ctx, adminstore.DeveloperUser{
			Email:       email,
			OIDCSubject: subject,
			DisplayName: localPart(email),
			OrgID:       h.portal.defaultOrg,
			TeamID:      h.portal.defaultTeam,
			Active:      true,
		})
		return created, cerr
	}
	if !user.Active {
		return nil, fmt.Errorf("developer inactive")
	}
	if err := h.portal.store.BindDeveloperSubject(ctx, user.ID, subject); err != nil {
		return nil, err
	}
	return user, nil
}

func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// PortalLogout ends the portal session.
func (h *AdminHandlers) PortalLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, adminauth.ClearPortalSessionCookie())
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AdminHandlers) portalUser(w http.ResponseWriter, r *http.Request) *adminstore.DeveloperUser {
	if !h.requirePortalStore(w, r) {
		return nil
	}
	id := adminauth.PortalUserID(r)
	user, err := h.portal.store.GetDeveloperByID(r.Context(), id)
	if err != nil || user == nil || !user.Active {
		writeJSON(w, http.StatusForbidden, apiError{Error: "sso login refused"})
		return nil
	}
	return user
}

// PortalMe returns the signed-in developer.
func (h *AdminHandlers) PortalMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalUser(w, r)
		if user == nil {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"email":        user.Email,
			"display_name": user.DisplayName,
			"org_id":       user.OrgID,
			"team_id":      user.TeamID,
		})
	}
}

// PortalListKeys returns the caller's keys. Hashes are not included.
func (h *AdminHandlers) PortalListKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalUser(w, r)
		if user == nil {
			return
		}
		keys, err := h.portal.store.ListDeveloperKeys(r.Context(), user.ID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if keys == nil {
			keys = []adminstore.DeveloperKey{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": keys})
	}
}

var (
	errPortalKeyName  = errors.New("name is required")
	errPortalKeyLimit = errors.New("active key limit reached")
)

// mintPersonalKey creates one personal key for the developer. The plaintext
// is returned to the caller once and is not stored.
func (h *AdminHandlers) mintPersonalKey(ctx context.Context, user *adminstore.DeveloperUser, name string) (string, *adminstore.DeveloperKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errPortalKeyName
	}
	n, err := h.portal.store.CountActiveDeveloperKeys(ctx, user.ID)
	if err != nil {
		return "", nil, err
	}
	if n >= h.portal.maxKeys {
		return "", nil, errPortalKeyLimit
	}
	plain, err := auth.GeneratePersonalKey()
	if err != nil {
		return "", nil, err
	}
	var expires *time.Time
	if h.portal.keyTTLDays > 0 {
		t := time.Now().UTC().Add(time.Duration(h.portal.keyTTLDays) * 24 * time.Hour)
		expires = &t
	}
	key, err := h.portal.store.CreateDeveloperKey(ctx, user.ID, user.OrgID, user.TeamID, name, auth.HashKey(plain), expires)
	if err != nil {
		return "", nil, err
	}
	return plain, key, nil
}

// PortalCreateKey mints one personal key. The plaintext is returned once.
func (h *AdminHandlers) PortalCreateKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalUser(w, r)
		if user == nil {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		plain, key, err := h.mintPersonalKey(r.Context(), user, req.Name)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errPortalKeyName) {
				status = http.StatusBadRequest
			} else if errors.Is(err, errPortalKeyLimit) {
				status = http.StatusConflict
			}
			h.respondError(w, r, err, status)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         key.ID,
			"key":        plain,
			"expires_at": key.ExpiresAt,
		})
	}
}

// PortalDeleteKey deactivates one of the caller's keys and purges it.
func (h *AdminHandlers) PortalDeleteKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalUser(w, r)
		if user == nil {
			return
		}
		hash, err := h.portal.store.DeactivateDeveloperKey(r.Context(), user.ID, chi.URLParam(r, "id"))
		if err != nil {
			if adminstore.IsNotFound(err) {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.purgeResolverKeys(r.Context(), hash)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListDevelopers — GET /api/organizations/{id}/developers (members.manage).
func (h *AdminHandlers) ListDevelopers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requirePortalStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		users, err := h.portal.store.ListDevelopers(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if users == nil {
			users = []adminstore.DeveloperUser{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": users})
	}
}

// CreateDeveloper — POST /api/organizations/{id}/developers.
func (h *AdminHandlers) CreateDeveloper() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requirePortalStore(w, r) || !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		var req struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			TeamID      string `json:"team_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		if req.Email == "" || !strings.Contains(req.Email, "@") {
			h.respondError(w, r, fmt.Errorf("email is required"), http.StatusBadRequest)
			return
		}
		teamID := req.TeamID
		if teamID == "" {
			team, err := h.store.GetDefaultTeam(r.Context(), orgID)
			if err != nil || team == nil {
				h.respondError(w, r, fmt.Errorf("team_id is required"), http.StatusBadRequest)
				return
			}
			teamID = team.ID
		}
		user, err := h.portal.store.CreateDeveloper(r.Context(), adminstore.DeveloperUser{
			Email:       req.Email,
			DisplayName: req.DisplayName,
			OrgID:       orgID,
			TeamID:      teamID,
			Active:      true,
		})
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "already exists") {
				status = http.StatusConflict
			}
			h.respondError(w, r, err, status)
			return
		}
		writeJSON(w, http.StatusCreated, user)
	}
}

// UpdateDeveloper — PUT /api/organizations/{id}/developers/{userID}.
func (h *AdminHandlers) UpdateDeveloper() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requirePortalStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		userID := chi.URLParam(r, "userID")
		var req struct {
			Active *bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Active == nil {
			h.respondError(w, r, fmt.Errorf("active is required"), http.StatusBadRequest)
			return
		}
		if !h.developerInOrg(w, r, orgID, userID) {
			return
		}
		if !*req.Active {
			if !h.revokeDeveloperKeys(w, r, userID) {
				return
			}
		}
		if err := h.portal.store.SetDeveloperActive(r.Context(), userID, *req.Active); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": userID, "active": *req.Active})
	}
}

// DeleteDeveloper deactivates the account and its keys.
func (h *AdminHandlers) DeleteDeveloper() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requirePortalStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		userID := chi.URLParam(r, "userID")
		if !h.developerInOrg(w, r, orgID, userID) {
			return
		}
		if !h.revokeDeveloperKeys(w, r, userID) {
			return
		}
		if err := h.portal.store.SetDeveloperActive(r.Context(), userID, false); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AdminHandlers) developerInOrg(w http.ResponseWriter, r *http.Request, orgID, userID string) bool {
	user, err := h.portal.store.GetDeveloperByID(r.Context(), userID)
	if err != nil || user == nil || user.OrgID != orgID {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return false
	}
	return true
}

func (h *AdminHandlers) revokeDeveloperKeys(w http.ResponseWriter, r *http.Request, userID string) bool {
	hashes, err := h.portal.store.DeactivateDeveloperKeys(r.Context(), userID)
	if err != nil {
		h.respondError(w, r, err, http.StatusInternalServerError)
		return false
	}
	h.purgeResolverKeys(r.Context(), hashes...)
	return true
}
