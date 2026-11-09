package handlers

// (RFC 7644 subset) under /scim/v2, authenticated by org-scoped SCIM bearer
// tokens (NOT the admin session — mounted on the public router, its own
// bearer guard). Migration 0012_scim backs the store side
// (pkg/adminstore/scim.go).
//
//
//	A SCIM Group IS an org role within the token's org. There is no group
//	table: groups are stateless role aliases, so an IdP cannot drift them.
//	  id          = the canonical adminstore.OrgRole value
//	                ("org-admin", "operator", "reader", "security_auditor",
//	                "partner")
//	  displayName = the role name; input is normalized (trim, lowercase,
//	                '_' and ' ' → '-') so "Org Admin", "ORG_ADMIN" and
//	                "org-admin" all map to org-admin.
//	POST /Groups with a mapped displayName returns the (already existing)
//	role group with 201 — idempotent by construction. An unknown
//	displayName is a 400 invalidValue (the IdP admin renames the group).
//	PATCH /Groups/{id} add members   → upsert membership (user, token-org,
//	                                   role of the group).
//	PATCH /Groups/{id} replace members → converge the role's membership to
//	                                   exactly the listed set (Okta group
//	                                   push sends the full member list).
//	PATCH /Groups/{id} remove member → delete that membership.
//	DELETE /Groups/{id}              → strip the role from ALL its members
//	                                   in the token org; the group itself
//	                                   keeps existing (204).
//	Group members listed via SCIM are the org's scim_identities holding the
//	role — members provisioned outside SCIM are not SCIM-addressable.
//
// USER SEMANTICS: POST /Users is idempotent — an existing identity with the
// same (org, userName) or (org, externalId) is returned with 200 (no
// duplicate). A created user gets an EMPTY password hash (password login
// impossible; SSO is the login path) and a membership in the token org with
// the configured default role (reader). userName/email is IMMUTABLE
// (400). DELETE /Users deactivates (204) — never deletes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// scimBasePath is the mount point of the SCIM 2.0 server.
const scimBasePath = "/scim/v2"

const (
	scimDefaultRateLimit  = 1000
	scimDefaultRateWindow = time.Minute
)

// SCIM schema URNs (RFC 7644/7643).
const (
	scimSchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimSchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimSchemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimContentType = "application/scim+json"
)

// ScimStore is the narrow capability the SCIM surface consumes
// (*adminstore.Store satisfies it — compile-pinned below; without the pin a
// signature drift compiles fine until the lazy type-assertion returns nil at
type ScimStore interface {
	CreateScimToken(ctx context.Context, orgID, label, createdBy string) (*adminstore.ScimToken, string, error)
	ListScimTokens(ctx context.Context, orgID string) ([]*adminstore.ScimToken, error)
	RevokeScimToken(ctx context.Context, orgID, tokenID string) error
	FindScimTokenByHash(ctx context.Context, tokenHash string) (*adminstore.ScimToken, error)
	TouchScimToken(ctx context.Context, orgID, tokenID string) error
	ProvisionScimUser(ctx context.Context, orgID string, p adminstore.ScimUserParams) (*adminstore.ScimUser, bool, error)
	GetScimUser(ctx context.Context, orgID, scimUserID string) (*adminstore.ScimUser, error)
	ListScimUsers(ctx context.Context, orgID string) ([]*adminstore.ScimUser, error)
	SyncScimUser(ctx context.Context, orgID, scimUserID string, p adminstore.ScimUserParams) (*adminstore.ScimUser, error)
	DeactivateScimUser(ctx context.Context, orgID, scimUserID string) error
	ListScimRoleMembers(ctx context.Context, orgID string, role adminstore.OrgRole) ([]*adminstore.ScimGroupMember, error)
	SetScimMemberRole(ctx context.Context, orgID, scimUserID string, role adminstore.OrgRole) error
	RemoveScimMemberRole(ctx context.Context, orgID, scimUserID string, role adminstore.OrgRole) error
	RemoveScimRoleMembers(ctx context.Context, orgID string, role adminstore.OrgRole) (int64, error)
}

// compile-time pin: the real store must keep satisfying ScimStore. This is
// scimUserID accidentally typed OrgRole) left scimStore() nil in
// deployments while unit tests stayed green.
var _ ScimStore = (*adminstore.Store)(nil)

// scimDeps groups the SCIM surface state on AdminHandlers.
type scimDeps struct {
	// storeOverride pins a ScimStore explicitly (tests; nil = lazy
	// type-assertion of h.store, which the real store satisfies).
	storeOverride ScimStore
	// defaultRole is the membership role applied to SCIM-created users
	// (reader unless configured otherwise).
	defaultRole adminstore.OrgRole
	// lastTouch throttles last_used_at writes to one per minute per token
	// (off the request hot path).
	lastTouchMu sync.Mutex
	lastTouch   map[string]time.Time
	// limiter is per-process unless backed by the shared Redis adapter.
	limiter    adminLimiter
	rateWindow time.Duration
}

// SetScimStore pins the SCIM store capability explicitly (nil restores the
// lazy type-assertion of h.store).
func (h *AdminHandlers) SetScimStore(s ScimStore) {
	h.scim.storeOverride = s
}

// SetScimDefaultRole configures the membership role SCIM-created users get
// (must be a valid org role; the zero value keeps "reader").
func (h *AdminHandlers) SetScimDefaultRole(role adminstore.OrgRole) {
	if adminstore.ValidOrgRole(role) {
		h.scim.defaultRole = role
	}
}

// SetScimRateLimit configures the per-token in-process sliding-window limit.
// Invalid values are ignored; the default is 1000 requests per token/minute.
func (h *AdminHandlers) SetScimRateLimit(limit int, window time.Duration) {
	if limit < 1 || window <= 0 {
		return
	}
	h.scim.lastTouchMu.Lock()
	defer h.scim.lastTouchMu.Unlock()
	if h.scim.limiter != nil {
		h.scim.limiter.Stop()
	}
	h.scim.limiter = newRateLimiter(limit, window)
	h.scim.rateWindow = window
}

func (h *AdminHandlers) allowScimToken(tokenID string) (bool, time.Duration) {
	h.scim.lastTouchMu.Lock()
	if h.scim.limiter == nil {
		h.scim.limiter = newRateLimiter(scimDefaultRateLimit, scimDefaultRateWindow)
		h.scim.rateWindow = scimDefaultRateWindow
	}
	limiter, window := h.scim.limiter, h.scim.rateWindow
	h.scim.lastTouchMu.Unlock()
	return limiter.allow("scim:" + tokenID), window
}

// scimStore returns the SCIM capability, or nil when unsupported (the
// routes then answer 503 — the capability ships with the real store).
func (h *AdminHandlers) scimStore() ScimStore {
	if h.scim.storeOverride != nil {
		return h.scim.storeOverride
	}
	ss, _ := h.store.(ScimStore)
	return ss
}

// ---------------------------------------------------------------------------
// Bearer authentication (org-scoped).
// ---------------------------------------------------------------------------

type ctxKeyScimOrg struct{}
type ctxKeyScimToken struct{}

// scimOrgID returns the org scope the bearer token resolved to ("" outside
// the SCIM middleware).
func scimOrgID(r *http.Request) string {
	org, _ := r.Context().Value(ctxKeyScimOrg{}).(string)
	return org
}

// scimAuthMiddleware authenticates the request with a SCIM bearer token and
// pins the token's org scope into the request context. The lookup is by the
// token's sha256 (unique index — no secret comparison in SQL); the fetched
// row is then confirmed with a constant-time compare before the token is
// trusted. Refusals are 401 SCIM errors; the raw token and its hash never
// reach the logs (only the row's UUID).
func (h *AdminHandlers) scimAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store := h.scimStore()
		if store == nil {
			writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM provisioning is not available")
			return
		}
		raw := scimBearerToken(r)
		if raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeSCIMError(w, http.StatusUnauthorized, "", "authentication required")
			return
		}
		token, err := store.FindScimTokenByHash(r.Context(), adminstore.ScimTokenHash(raw))
		if err != nil || !adminstore.ScimTokenMatches(raw, token.TokenHash) {
			// Unknown token, or the (unreachable-by-construction) hash
			// mismatch: one uniform 401, no existence oracle.
			if h.logger != nil {
				h.logger.Warn("scim auth refused", "reason", "unknown_token")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeSCIMError(w, http.StatusUnauthorized, "invalidToken", "invalid or expired token")
			return
		}
		if token.Revoked() {
			if h.logger != nil {
				h.logger.Warn("scim auth refused", "reason", "revoked_token", "token_id", token.ID)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeSCIMError(w, http.StatusUnauthorized, "invalidToken", "invalid or expired token")
			return
		}
		if allowed, window := h.allowScimToken(token.ID); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(window.Seconds()))))
			writeSCIMError(w, http.StatusTooManyRequests, "tooMany", "SCIM request rate limit exceeded")
			return
		}
		h.touchScimToken(r.Context(), store, token.OrgID, token.ID)
		ctx := context.WithValue(r.Context(), adminauth.ContextKeyUserID{}, token.ID)
		ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "scim-token:"+token.ID)
		ctx = context.WithValue(ctx, ctxKeyScimOrg{}, token.OrgID)
		ctx = context.WithValue(ctx, ctxKeyScimToken{}, token.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scimAuditMiddleware journals successful SCIM state changes through the
// shared durable audit writer. The bearer token ID is the actor; request
// bodies and bearer material are deliberately never copied into audit data.
func (h *AdminHandlers) scimAuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &scimStatusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if recorder.status < http.StatusOK || recorder.status >= http.StatusMultipleChoices {
			return
		}
		action, resource := scimAuditAction(r)
		if action == "" {
			return
		}
		tokenID, _ := r.Context().Value(ctxKeyScimToken{}).(string)
		details := "actor=scim_token:" + tokenID
		h.auditLogActionWithCtx(r.Context(), r, action, resource, details)
	})
}

type scimStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *scimStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *scimStatusWriter) Write(p []byte) (int, error) {
	return w.ResponseWriter.Write(p)
}

func scimAuditAction(r *http.Request) (string, string) {
	path := strings.TrimPrefix(r.URL.Path, scimBasePath)
	resource := "scim:" + path
	switch {
	case strings.HasPrefix(path, "/Users"):
		switch r.Method {
		case http.MethodPost:
			return "create", resource
		case http.MethodPut, http.MethodPatch:
			return "update", resource
		case http.MethodDelete:
			return "deactivate", resource
		}
	case strings.HasPrefix(path, "/Groups"):
		switch r.Method {
		case http.MethodPost:
			return "group_sync", resource
		case http.MethodPatch:
			return "role_sync", resource
		case http.MethodDelete:
			return "role_revoke", resource
		}
	}
	return "", ""
}

// scimBearerToken extracts the raw token from "Authorization: Bearer <tok>".
// Anything else (empty, wrong scheme, whitespace-only) is "".
func scimBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, prefix)
	if !ok || strings.TrimSpace(token) == "" {
		return ""
	}
	return strings.TrimSpace(token)
}

// scimTouchInterval is the minimum gap between last_used_at writes for one
// asynchrony, provides that; the write itself is a single indexed UPDATE).
const scimTouchInterval = time.Minute

// touchScimToken refreshes last_used_at at most once per minute per token.
// A write failure is logged, never surfaced to the IdP.
func (h *AdminHandlers) touchScimToken(ctx context.Context, store ScimStore, orgID, tokenID string) {
	now := time.Now()
	h.scim.lastTouchMu.Lock()
	if h.scim.lastTouch == nil {
		h.scim.lastTouch = make(map[string]time.Time)
	}
	if last, ok := h.scim.lastTouch[tokenID]; ok && now.Sub(last) < scimTouchInterval {
		h.scim.lastTouchMu.Unlock()
		return
	}
	h.scim.lastTouch[tokenID] = now
	h.scim.lastTouchMu.Unlock()

	if err := store.TouchScimToken(ctx, orgID, tokenID); err != nil && h.logger != nil {
		h.logger.Warn("scim token touch failed", "token_id", tokenID, "error", err)
	}
}

// ---------------------------------------------------------------------------
// SCIM wire helpers (RFC 7644 responses and errors).
// ---------------------------------------------------------------------------

// writeSCIMJSON writes a SCIM payload with the scim+json content type.
func writeSCIMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && slog.Default() != nil {
		slog.Error("scim encode error", "error", err)
	}
}

// writeSCIMError writes a RFC 7644 §3.12 error response. scimType is the
// optional detailed error keyword (invalidValue, invalidFilter, …).
func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{
		"schemas": []string{scimSchemaError},
		"status":  fmt.Sprintf("%d", status),
		"detail":  detail,
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	writeSCIMJSON(w, status, body)
}

// scimMeta builds the resource meta block.
func scimMeta(resourceType, id string, created, modified time.Time) map[string]any {
	return map[string]any{
		"resourceType": resourceType,
		"created":      created.UTC().Format(time.RFC3339Nano),
		"lastModified": modified.UTC().Format(time.RFC3339Nano),
		"location":     scimBasePath + "/" + resourceType + "s/" + id,
	}
}

// scimUserResource renders a ScimUser as the RFC 7643 User resource.
func scimUserResource(u *adminstore.ScimUser) map[string]any {
	res := map[string]any{
		"schemas":  []string{scimSchemaUser},
		"id":       u.ID,
		"userName": u.UserName,
		"active":   u.Active,
		"meta":     scimMeta("User", u.ID, u.CreatedAt, u.UpdatedAt),
	}
	if u.ExternalID != "" {
		res["externalId"] = u.ExternalID
	}
	name := map[string]any{}
	if u.GivenName != "" {
		name["givenName"] = u.GivenName
	}
	if u.FamilyName != "" {
		name["familyName"] = u.FamilyName
	}
	if len(name) > 0 {
		res["name"] = name
	}
	display := u.DisplayName
	if display == "" {
		display = adminstore.ScimDisplayName(u.GivenName, u.FamilyName)
	}
	if display != "" {
		res["displayName"] = display
	}
	return res
}

// scimGroupResource renders a role group with its SCIM-visible members.
func scimGroupResource(role adminstore.OrgRole, members []*adminstore.ScimGroupMember) map[string]any {
	res := map[string]any{
		"schemas":     []string{scimSchemaGroup},
		"id":          string(role),
		"displayName": string(role),
		"meta":        scimMeta("Group", string(role), time.Time{}, time.Time{}),
	}
	if len(members) > 0 {
		ms := make([]map[string]any, 0, len(members))
		for _, m := range members {
			mm := map[string]any{"value": m.Value}
			if m.Display != "" {
				mm["display"] = m.Display
			}
			ms = append(ms, mm)
		}
		res["members"] = ms
	}
	return res
}

// Pagination bounds (RFC 7644 §3.4.2.2): count defaults to 100 and clamps
// into [1, scimMaxCount] — the same ceiling ServiceProviderConfig declares as
// filter.maxResults; startIndex is 1-based and clamped to ≥ 1. Windowing is
// in-memory after loading active identities; the store returns stable order
// and totalResults reports the full active result count.
const (
	scimDefaultCount = 100
	scimMaxCount     = 200
)

// scimPage is the parsed startIndex/count query pair of a list request.
type scimPage struct {
	startIndex int
	count      int
}

// parseScimPage reads the pagination query parameters. A non-integer value
// is a 400 (invalidValue); out-of-range values clamp per the bounds above.
func parseScimPage(query url.Values) (scimPage, error) {
	page := scimPage{startIndex: 1, count: scimDefaultCount}
	if raw := query.Get("startIndex"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return page, fmt.Errorf("startIndex must be an integer")
		}
		if n > 1 {
			page.startIndex = n
		}
	}
	if raw := query.Get("count"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return page, fmt.Errorf("count must be an integer")
		}
		switch {
		case n < 1:
			page.count = 1
		case n > scimMaxCount:
			page.count = scimMaxCount
		default:
			page.count = n
		}
	}
	return page, nil
}

// window selects the page's slice of the full (pre-pagination) item list.
func (p scimPage) window(items []any) []any {
	start := p.startIndex - 1
	if start >= len(items) {
		return nil
	}
	end := start + p.count
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// writeSCIMList writes a ListResponse envelope. items is the FULL result set
// (totalResults); the page window selects the returned Resources.
func writeSCIMList(w http.ResponseWriter, items []any, page scimPage) {
	if items == nil {
		items = []any{}
	}
	resources := page.window(items)
	if resources == nil {
		resources = []any{}
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimSchemaList},
		"totalResults": len(items),
		"Resources":    resources,
		"itemsPerPage": len(resources),
		"startIndex":   page.startIndex,
	})
}

// scimStoreGuard writes the 503 for a missing capability and returns false.
func (h *AdminHandlers) scimStoreGuard(w http.ResponseWriter, r *http.Request) (ScimStore, bool) {
	if !h.requireStore(w, r) {
		writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM provisioning is not available")
		return nil, false
	}
	store := h.scimStore()
	if store == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM provisioning is not available")
		return nil, false
	}
	return store, true
}

// writeScimStoreError maps store failures onto the SCIM contract: 404 for a
// missing identity/token, 409 for an unresolvable conflict, else a generic
// 500 (driver internals go to the log only).
func (h *AdminHandlers) writeScimStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminstore.ErrNotFound):
		writeSCIMError(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, adminstore.ErrScimConflict):
		writeSCIMError(w, http.StatusConflict, "uniqueness", err.Error())
	default:
		if h.logger != nil {
			h.logger.Error("scim store failure", "error", err.Error())
		}
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
	}
}

// decodeSCIMBody decodes a JSON request body (the router's MaxBody guard
// already bounds the size).
func decodeSCIMBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------------------------------------------------------------------------
// GET /ServiceProviderConfig (RFC 7644 §4) — static discovery document.
// ---------------------------------------------------------------------------

// SCIMServiceProviderConfig — GET /scim/v2/ServiceProviderConfig (RFC 7644
// §4): the static discovery document, inside the bearer guard.
func (h *AdminHandlers) SCIMServiceProviderConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeSCIMJSON(w, http.StatusOK, map[string]any{
			"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":          map[string]any{"supported": true},
			"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":         map[string]any{"supported": true, "maxResults": 200},
			"changePassword": map[string]any{"supported": false},
			"sort":           map[string]any{"supported": false},
			"etag":           map[string]any{"supported": false},
			"authenticationSchemes": []map[string]any{{
				"type":        "oauthbearertoken",
				"name":        "SCIM Bearer Token",
				"description": "Organization-scoped SCIM bearer token (POST /api/organizations/{id}/scim/tokens)",
				"primary":     true,
			}}},
		)
	}
}

// ---------------------------------------------------------------------------
// GET /Schemas + /ResourceTypes (RFC 7644 §4) — static discovery documents.
// ---------------------------------------------------------------------------

// scimAttribute is one attribute descriptor of a Schema document (RFC 7643
// §7). The documents describe EXACTLY the subset this server supports — the
// mutability flags state the enforced contract: userName IMMUTABLE, password
// writeOnly (accepted for compatibility, ignored — SCIM accounts carry an
// empty password hash and sign in via SSO only).
type scimAttribute struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	SubAttributes []scimAttribute `json:"subAttributes,omitempty"`
	MultiValued   bool            `json:"multiValued"`
	Description   string          `json:"description"`
	Required      bool            `json:"required"`
	CaseExact     bool            `json:"caseExact"`
	Mutability    string          `json:"mutability"`
	Returned      string          `json:"returned"`
	Uniqueness    string          `json:"uniqueness"`
}

// scimSchemaResource is one Schema document served by /Schemas.
type scimSchemaResource struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Attributes  []scimAttribute `json:"attributes"`
}

// scimUserSchemaDocument describes the supported User subset.
func scimUserSchemaDocument() scimSchemaResource {
	return scimSchemaResource{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		ID:          scimSchemaUser,
		Name:        "User",
		Description: "Admin console account provisioned via SCIM (SSO login; password is never settable)",
		Attributes: []scimAttribute{
			{
				Name: "userName", Type: "string",
				Description: "Login email address; matches an admin account and is immutable through SCIM",
				Required:    true, CaseExact: false,
				Mutability: "immutable", Returned: "default", Uniqueness: "server",
			},
			{
				Name: "name", Type: "complex",
				Description: "Components of the provisioned user's name",
				SubAttributes: []scimAttribute{
					{Name: "givenName", Type: "string", Description: "Given name", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
					{Name: "familyName", Type: "string", Description: "Family name", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
				},
				Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			},
			{
				Name: "displayName", Type: "string",
				Description: "Display name (derived from the name components; informational)",
				Mutability:  "readWrite", Returned: "default", Uniqueness: "none",
			},
			{
				Name: "active", Type: "boolean",
				Description: "Account gate: false deactivates the account and revokes its live sessions",
				Mutability:  "readWrite", Returned: "default", Uniqueness: "none",
			},
			{
				Name: "externalId", Type: "string",
				Description: "IdP-side identifier (Okta/Entra linkage)",
				Mutability:  "readWrite", Returned: "default", Uniqueness: "none",
			},
			{
				Name: "password", Type: "string",
				Description: "Accepted for schema compatibility and IGNORED — SCIM-provisioned accounts sign in via SSO only",
				Mutability:  "writeOnly", Returned: "never", Uniqueness: "none",
			},
		},
	}
}

// scimGroupSchemaDocument describes the supported Group subset (role aliases).
func scimGroupSchemaDocument() scimSchemaResource {
	return scimSchemaResource{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		ID:          scimSchemaGroup,
		Name:        "Group",
		Description: "Org role alias — a fixed platform role, not a free-form group",
		Attributes: []scimAttribute{
			{
				Name: "displayName", Type: "string",
				Description: "Role alias; must map to an org role (org-admin, operator, reader, security_auditor, partner)",
				Required:    true, CaseExact: false,
				Mutability: "immutable", Returned: "default", Uniqueness: "none",
			},
			{
				Name: "members", Type: "complex", MultiValued: true,
				Description: "SCIM-provisioned members holding the role (deactivated users are never listed)",
				SubAttributes: []scimAttribute{
					{Name: "value", Type: "string", Description: "SCIM id of the member", Required: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
					{Name: "display", Type: "string", Description: "userName of the member (server-assigned)", Mutability: "readOnly", Returned: "default", Uniqueness: "none"},
				},
				Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			},
		},
	}
}

// SCIMSchemas — GET /scim/v2/Schemas: the supported User/Group schema
// documents in a ListResponse (RFC 7644 §4 / RFC 7643 §7), behind the bearer
// guard like every /scim/v2 route.
func (h *AdminHandlers) SCIMSchemas() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resources := []any{scimUserSchemaDocument(), scimGroupSchemaDocument()}
		writeSCIMJSON(w, http.StatusOK, map[string]any{
			"schemas":      []string{scimSchemaList},
			"totalResults": len(resources),
			"Resources":    resources,
			"itemsPerPage": len(resources),
			"startIndex":   1,
		})
	}
}

// scimResourceTypeDocument is one ResourceType document (RFC 7644 §4.2).
type scimResourceTypeDocument struct {
	Schemas          []string `json:"schemas"`
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Endpoint         string   `json:"endpoint"`
	Schema           string   `json:"schema"`
	SchemaExtensions []any    `json:"schemaExtensions"`
}

// SCIMResourceTypes — GET /scim/v2/ResourceTypes: the User and Group
// resource types (no schema extensions).
func (h *AdminHandlers) SCIMResourceTypes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resources := []any{
			scimResourceTypeDocument{
				Schemas:          []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				ID:               "User",
				Name:             "User",
				Description:      "Admin console account (SSO login; deactivate-only delete)",
				Endpoint:         "/Users",
				Schema:           scimSchemaUser,
				SchemaExtensions: []any{},
			},
			scimResourceTypeDocument{
				Schemas:          []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				ID:               "Group",
				Name:             "Group",
				Description:      "Org role alias (stateless; members are role memberships)",
				Endpoint:         "/Groups",
				Schema:           scimSchemaGroup,
				SchemaExtensions: []any{},
			},
		}
		writeSCIMJSON(w, http.StatusOK, map[string]any{
			"schemas":      []string{scimSchemaList},
			"totalResults": len(resources),
			"Resources":    resources,
			"itemsPerPage": len(resources),
			"startIndex":   1,
		})
	}
}

// ---------------------------------------------------------------------------
// /Users (RFC 7644 §3 / RFC 7643 core user).
// ---------------------------------------------------------------------------

// scimUserRequest is the POST/PUT /Users payload subset we accept. The
// password field is deliberately ignored (never persisted, never logged).
type scimUserRequest struct {
	Schemas    []string `json:"schemas"`
	UserName   string   `json:"userName"`
	ExternalID string   `json:"externalId"`
	Name       *struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	DisplayName string `json:"displayName"`
	Active      *bool  `json:"active"`
}

// params renders the request into the store's profile params. roleOverride
// is applied on CREATE only (default role); active defaults to true for
// creates (SCIM-created users start enabled unless the IdP says otherwise).
func (req *scimUserRequest) params(roleOverride adminstore.OrgRole, activeDefault bool) adminstore.ScimUserParams {
	p := adminstore.ScimUserParams{
		UserName:   strings.TrimSpace(req.UserName),
		ExternalID: strings.TrimSpace(req.ExternalID),
		Active:     activeDefault,
		Role:       roleOverride,
	}
	if req.Name != nil {
		p.GivenName = strings.TrimSpace(req.Name.GivenName)
		p.FamilyName = strings.TrimSpace(req.Name.FamilyName)
	}
	if req.Active != nil {
		p.Active = *req.Active
	}
	return p
}

// SCIMListUsers — GET /scim/v2/Users[?filter=userName eq "..."][&startIndex=N][&count=M].
func (h *AdminHandlers) SCIMListUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := scimOrgID(r)
		page, err := parseScimPage(r.URL.Query())
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
		filter := r.URL.Query().Get("filter")
		if filter != "" {
			userName, ok, err := parseScimUserFilter(filter)
			if err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only 'userName eq \"value\"' is supported")
				return
			}
			if !ok {
				// A filter this implementation cannot match returns an empty
				// list (never everything — fail closed).
				writeSCIMList(w, nil, page)
				return
			}
			users, err := store.ListScimUsers(r.Context(), orgID)
			if err != nil {
				h.writeScimStoreError(w, r, err)
				return
			}
			var out []any
			for _, u := range users {
				if strings.EqualFold(u.UserName, userName) {
					out = append(out, scimUserResource(u))
				}
			}
			writeSCIMList(w, out, page)
			return
		}
		users, err := store.ListScimUsers(r.Context(), orgID)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		out := make([]any, 0, len(users))
		for _, u := range users {
			out = append(out, scimUserResource(u))
		}
		writeSCIMList(w, out, page)
	}
}

// parseScimUserFilter is the minimal RFC 7644 §3.4.2.2 filter parser:
// `userName eq "value"` (attribute/operator case-insensitive, quoted value).
// Returns ok=false for a well-formed filter this server cannot match
// (attribute != userName, operator != eq) — the caller answers an empty
// list; err=true for a MALFORMED filter (400).
func parseScimUserFilter(filter string) (userName string, ok bool, err error) {
	s := strings.TrimSpace(filter)
	attrib, rest, found := strings.Cut(s, " ")
	if !found {
		return "", false, fmt.Errorf("malformed filter")
	}
	op, value, found := strings.Cut(strings.TrimSpace(rest), " ")
	if !found || !strings.EqualFold(op, "eq") {
		if !found {
			return "", false, fmt.Errorf("malformed filter")
		}
		return "", false, nil // well-formed but unsupported operator
	}
	if !strings.EqualFold(attrib, "userName") {
		return "", false, nil // well-formed but unsupported attribute
	}
	value = strings.TrimSpace(value)
	if len(value) < 2 || !strings.HasPrefix(value, "\"") || !strings.HasSuffix(value, "\"") {
		return "", false, fmt.Errorf("filter value must be a quoted string")
	}
	inner := value[1 : len(value)-1]
	if strings.Contains(inner, "\"") {
		return "", false, fmt.Errorf("escaped quotes are not supported")
	}
	return inner, true, nil
}

// SCIMCreateUser — POST /scim/v2/Users. Idempotent: an existing identity
// with the same (org, userName) or (org, externalId) returns 200 with the
// EXISTING resource (no duplicate); a fresh profile returns 201.
func (h *AdminHandlers) SCIMCreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		var req scimUserRequest
		if err := decodeSCIMBody(r, &req); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "malformed request body")
			return
		}
		if strings.TrimSpace(req.UserName) == "" {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
			return
		}
		user, created, err := store.ProvisionScimUser(r.Context(), scimOrgID(r), req.params(h.scim.defaultRole, true))
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		status := http.StatusCreated
		if !created {
			status = http.StatusOK
		}
		w.Header().Set("Location", scimBasePath+"/Users/"+user.ID)
		writeSCIMJSON(w, status, scimUserResource(user))
	}
}

// SCIMGetUser — GET /scim/v2/Users/{id}.
func (h *AdminHandlers) SCIMGetUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		user, err := store.GetScimUser(r.Context(), scimOrgID(r), r.PathValue("id"))
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		writeSCIMJSON(w, http.StatusOK, scimUserResource(user))
	}
}

// SCIMPutUser — PUT /scim/v2/Users/{id}: full-profile sync. userName is
// immutable (a changed userName is a 400); every other supplied field syncs.
func (h *AdminHandlers) SCIMPutUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		orgID, scimUserID := scimOrgID(r), r.PathValue("id")
		current, err := store.GetScimUser(r.Context(), orgID, scimUserID)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		var req scimUserRequest
		if err := decodeSCIMBody(r, &req); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "malformed request body")
			return
		}
		if strings.TrimSpace(req.UserName) != "" && !strings.EqualFold(strings.TrimSpace(req.UserName), current.UserName) {
			writeSCIMError(w, http.StatusBadRequest, "mutability", "userName is immutable")
			return
		}
		user, err := store.SyncScimUser(r.Context(), orgID, scimUserID, req.params(adminstore.OrgRole(""), current.Active))
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		writeSCIMJSON(w, http.StatusOK, scimUserResource(user))
	}
}

// scimPatchRequest is the RFC 7644 §3.5.2 PATCH envelope.
type scimPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

// scimPatchOp is one PATCH operation. Value stays raw: depending on path it
// is a bool (active), a string (name fields) or an object (full profile).
type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// SCIMPatchUser — PATCH /scim/v2/Users/{id}: attribute-level sync (Okta and
// Entra profiles). Supported paths: "active" (bool), "name.givenName",
// "name.familyName", "externalId" (string), "name" (object), "displayName"
// (accepted, informational), "" / absent path with a user-object value.
// userName/email mutations are refused (400) — the login identity is
// immutable through SCIM.
func (h *AdminHandlers) SCIMPatchUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		orgID, scimUserID := scimOrgID(r), r.PathValue("id")
		current, err := store.GetScimUser(r.Context(), orgID, scimUserID)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		var patch scimPatchRequest
		if err := decodeSCIMBody(r, &patch); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "malformed request body")
			return
		}
		if len(patch.Operations) == 0 {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "no operations")
			return
		}

		p := adminstore.ScimUserParams{
			UserName:   current.UserName,
			ExternalID: current.ExternalID,
			GivenName:  current.GivenName,
			FamilyName: current.FamilyName,
			Active:     current.Active,
		}
		for _, op := range patch.Operations {
			if err := applyScimUserPatchOp(&p, op); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
		}
		user, err := store.SyncScimUser(r.Context(), orgID, scimUserID, p)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		writeSCIMJSON(w, http.StatusOK, scimUserResource(user))
	}
}

// applyScimUserPatchOp folds one PATCH operation into the profile params.
func applyScimUserPatchOp(p *adminstore.ScimUserParams, op scimPatchOp) error {
	switch strings.ToLower(strings.TrimSpace(op.Op)) {
	case "replace", "add", "remove":
	default:
		return fmt.Errorf("unsupported operation %q", op.Op)
	}
	path := strings.ToLower(strings.TrimSpace(op.Path))
	// Path-scoped value may be a bare literal; object-value ops carry the
	// attribute inside the object.
	switch path {
	case "active":
		var active bool
		if err := json.Unmarshal(op.Value, &active); err != nil {
			return fmt.Errorf("active must be a boolean")
		}
		if strings.EqualFold(strings.TrimSpace(op.Op), "remove") {
			return fmt.Errorf("active cannot be removed")
		}
		p.Active = active
		return nil
	case "externalid":
		if strings.EqualFold(strings.TrimSpace(op.Op), "remove") {
			p.ExternalID = ""
			return nil
		}
		var v string
		if err := json.Unmarshal(op.Value, &v); err != nil {
			return fmt.Errorf("externalId must be a string")
		}
		p.ExternalID = strings.TrimSpace(v)
		return nil
	case "name.givenname":
		if strings.EqualFold(strings.TrimSpace(op.Op), "remove") {
			p.GivenName = ""
			return nil
		}
		var v string
		if err := json.Unmarshal(op.Value, &v); err != nil {
			return fmt.Errorf("name.givenName must be a string")
		}
		p.GivenName = strings.TrimSpace(v)
		return nil
	case "name.familyname":
		if strings.EqualFold(strings.TrimSpace(op.Op), "remove") {
			p.FamilyName = ""
			return nil
		}
		var v string
		if err := json.Unmarshal(op.Value, &v); err != nil {
			return fmt.Errorf("name.familyName must be a string")
		}
		p.FamilyName = strings.TrimSpace(v)
		return nil
	case "displayname", "name.formatted":
		return nil // informational only — never persisted
	case "username", "emails", "emails.value", "emails[type eq \"work\"].value":
		return fmt.Errorf("userName is immutable")
	case "name", "":
		// Whole-profile replace: decode the subset we sync. An absent path
		// with a non-object value is a malformed request.
		var req scimUserRequest
		if err := json.Unmarshal(op.Value, &req); err != nil {
			return fmt.Errorf("operation value must be a user object")
		}
		if strings.TrimSpace(req.UserName) != "" && !strings.EqualFold(strings.TrimSpace(req.UserName), p.UserName) {
			return fmt.Errorf("userName is immutable")
		}
		np := req.params(adminstore.OrgRole(""), p.Active)
		p.ExternalID, p.GivenName, p.FamilyName = np.ExternalID, np.GivenName, np.FamilyName
		p.Active = np.Active
		return nil
	default:
		return nil // unknown attributes are ignored per RFC 7644 §3.5.2.3
	}
}

// SCIMDeleteUser — DELETE /scim/v2/Users/{id}: DEACTIVATE (RFC-compatible
// 204; the IdP treats it as removed while the account and its history stay)
// — never a hard delete.
func (h *AdminHandlers) SCIMDeleteUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		if err := store.DeactivateScimUser(r.Context(), scimOrgID(r), r.PathValue("id")); err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// /Groups — stateless role aliases (semantics documented in the file header).
// ---------------------------------------------------------------------------

// scimRoleFromGroupName maps a SCIM group displayName onto an org role:
// trimmed, lowercased, '_' and ' ' folded to '-'. Unknown names are NOT
// roles (the caller answers 400 invalidValue).
func scimRoleFromGroupName(name string) (adminstore.OrgRole, bool) {
	norm := strings.ToLower(strings.TrimSpace(name))
	norm = strings.ReplaceAll(norm, "_", "-")
	norm = strings.ReplaceAll(norm, " ", "-")
	switch norm {
	case "org-admin", "orgadmin":
		return adminstore.RoleOrgAdmin, true
	case "operator":
		return adminstore.RoleOperator, true
	case "reader":
		return adminstore.RoleReader, true
	case "security-auditor":
		return adminstore.RoleSecurityAuditor, true
	case "partner":
		return adminstore.RolePartner, true
	default:
		return "", false
	}
}

// scimRoleByID resolves a group path id (canonical role value or alias).
func scimRoleByID(id string) (adminstore.OrgRole, bool) {
	if adminstore.ValidOrgRole(adminstore.OrgRole(id)) {
		return adminstore.OrgRole(id), true
	}
	return scimRoleFromGroupName(id)
}

// SCIMListGroups — GET /scim/v2/Groups[?startIndex=N][&count=M]: the org's
// role groups with their SCIM-visible members.
func (h *AdminHandlers) SCIMListGroups() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		page, err := parseScimPage(r.URL.Query())
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
		orgID := scimOrgID(r)
		out := make([]any, 0, len(adminstore.AllOrgRoles()))
		for _, role := range adminstore.AllOrgRoles() {
			members, err := store.ListScimRoleMembers(r.Context(), orgID, role)
			if err != nil {
				h.writeScimStoreError(w, r, err)
				return
			}
			out = append(out, scimGroupResource(role, members))
		}
		writeSCIMList(w, out, page)
	}
}

// SCIMGetGroup — GET /scim/v2/Groups/{id}.
func (h *AdminHandlers) SCIMGetGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		role, ok := scimRoleByID(r.PathValue("id"))
		if !ok {
			writeSCIMError(w, http.StatusNotFound, "", "group not found")
			return
		}
		members, err := store.ListScimRoleMembers(r.Context(), scimOrgID(r), role)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		writeSCIMJSON(w, http.StatusOK, scimGroupResource(role, members))
	}
}

// SCIMCreateGroup — POST /scim/v2/Groups: idempotent — the displayName must
// map to a role; the (stateless) role group already exists, so the response
// is always 201 with the group resource. Unknown displayName → 400.
func (h *AdminHandlers) SCIMCreateGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		var req struct {
			DisplayName string `json:"displayName"`
		}
		if err := decodeSCIMBody(r, &req); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "malformed request body")
			return
		}
		role, ok := scimRoleFromGroupName(req.DisplayName)
		if !ok {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue",
				"displayName must map to one of the org roles: org-admin, operator, reader, security_auditor, partner")
			return
		}
		members, err := store.ListScimRoleMembers(r.Context(), scimOrgID(r), role)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		w.Header().Set("Location", scimBasePath+"/Groups/"+string(role))
		writeSCIMJSON(w, http.StatusCreated, scimGroupResource(role, members))
	}
}

// scimGroupPatchRequest is the PATCH envelope for groups.
type scimGroupPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

// SCIMPatchGroup — PATCH /scim/v2/Groups/{id}: add/remove members. Each
// member value is a scim_user_id; add upserts the (user, org, role)
// membership, remove deletes it. A member value that is not an identity of
// the token org fails the request with 404 (fail-closed: no cross-org
// membership can ever be created).
func (h *AdminHandlers) SCIMPatchGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := scimOrgID(r)
		role, ok := scimRoleByID(r.PathValue("id"))
		if !ok {
			writeSCIMError(w, http.StatusNotFound, "", "group not found")
			return
		}
		var patch scimGroupPatchRequest
		if err := decodeSCIMBody(r, &patch); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "malformed request body")
			return
		}
		for _, op := range patch.Operations {
			path := strings.ToLower(strings.TrimSpace(op.Path))
			if path != "" && path != "members" {
				// displayName/externalId renames are meaningless on a role
				// alias — accepted and ignored (RFC unknown-attribute rule).
				continue
			}
			members, err := decodeScimMemberValues(op.Value)
			if err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			switch strings.ToLower(strings.TrimSpace(op.Op)) {
			case "remove":
				for _, memberID := range members {
					if err := store.RemoveScimMemberRole(r.Context(), orgID, memberID, role); err != nil {
						if errors.Is(err, adminstore.ErrNotFound) {
							writeSCIMError(w, http.StatusNotFound, "", "member "+memberID+" is not a user of this organization")
							return
						}
						h.writeScimStoreError(w, r, err)
						return
					}
				}
			case "replace":
				// Okta group-push sends replace with the FULL member set:
				// converge the role's SCIM membership to exactly this list
				// (add the listed, remove the absent).
				current, err := store.ListScimRoleMembers(r.Context(), orgID, role)
				if err != nil {
					h.writeScimStoreError(w, r, err)
					return
				}
				want := make(map[string]bool, len(members))
				for _, id := range members {
					want[id] = true
				}
				for _, m := range current {
					if !want[m.Value] {
						if err := store.RemoveScimMemberRole(r.Context(), orgID, m.Value, role); err != nil && !errors.Is(err, adminstore.ErrNotFound) {
							h.writeScimStoreError(w, r, err)
							return
						}
					}
				}
				for _, memberID := range members {
					if err := store.SetScimMemberRole(r.Context(), orgID, memberID, role); err != nil {
						if errors.Is(err, adminstore.ErrNotFound) {
							writeSCIMError(w, http.StatusNotFound, "", "member "+memberID+" is not a user of this organization")
							return
						}
						h.writeScimStoreError(w, r, err)
						return
					}
				}
			default: // "add" (and any additive spelling)
				for _, memberID := range members {
					if err := store.SetScimMemberRole(r.Context(), orgID, memberID, role); err != nil {
						if errors.Is(err, adminstore.ErrNotFound) {
							writeSCIMError(w, http.StatusNotFound, "", "member "+memberID+" is not a user of this organization")
							return
						}
						h.writeScimStoreError(w, r, err)
						return
					}
				}
			}
		}
		members, err := store.ListScimRoleMembers(r.Context(), orgID, role)
		if err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		writeSCIMJSON(w, http.StatusOK, scimGroupResource(role, members))
	}
}

// decodeScimMemberValues extracts member scim_user_ids from a PATCH value:
// either a single {"value": id} object or an array of them.
func decodeScimMemberValues(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing member value")
	}
	type memberRef struct {
		Value string `json:"value"`
	}
	var single memberRef
	if err := json.Unmarshal(raw, &single); err == nil && single.Value != "" {
		return []string{single.Value}, nil
	}
	var many []memberRef
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("members must be {value} objects")
	}
	out := make([]string, 0, len(many))
	for _, m := range many {
		if m.Value == "" {
			return nil, fmt.Errorf("member value is required")
		}
		out = append(out, m.Value)
	}
	return out, nil
}

// SCIMDeleteGroup — DELETE /scim/v2/Groups/{id}: strip the role from ALL its
// members in the token org (204). The role group itself keeps existing
// (roles are platform objects, not deletable SCIM rows).
func (h *AdminHandlers) SCIMDeleteGroup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimStoreGuard(w, r)
		if !ok {
			return
		}
		role, ok := scimRoleByID(r.PathValue("id"))
		if !ok {
			writeSCIMError(w, http.StatusNotFound, "", "group not found")
			return
		}
		if _, err := store.RemoveScimRoleMembers(r.Context(), scimOrgID(r), role); err != nil {
			h.writeScimStoreError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
