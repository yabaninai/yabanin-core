package handlers

// W-BYOK-API: BYOK (bring-your-own-key) org provider credentials — the admin
// CRUD + connection-test surface.
//
// The real store is adminstore.OrgCredentialStore (W-BYOK-DB,
// pkg/adminstore/orgcredentials.go): the row type here is an alias of
// adminstore.OrgCredential and the OrgCredentialStore interface below is the
// narrow capability the handlers consume — *adminstore.Store satisfies it
// (compile pin), so production wiring is a one-liner in services/run/admin.go.
// The plaintext key exists only as a call argument into the store; the row
// type and every response shape carry the last-4 mask exclusively.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// OrgCredential aliases the frozen W-BYOK-DB row (adminstore.OrgCredential):
// one definition, no drift. It deliberately has NO plaintext field — the JSON
// wire format carries the last-4 mask only, so a plaintext key is
// structurally unable to reach a response through this type.
type OrgCredential = adminstore.OrgCredential

// OrgCredentialStore is the narrow store capability the credential handlers
// consume (exactly the frozen W-BYOK contract). ResolveKey is the only
// plaintext egress point and its value flows solely into the Authorization
// header of the connection test.
type OrgCredentialStore interface {
	List(ctx context.Context, orgID string) ([]OrgCredential, error)
	Create(ctx context.Context, orgID, name, provider, baseURL, plaintextKey string) (OrgCredential, error)
	// Update: newPlaintextKey "" keeps the stored key; non-empty rotates it
	// (the store bumps key_version).
	Update(ctx context.Context, orgID, id string, updated OrgCredential, newPlaintextKey string) (OrgCredential, error)
	Delete(ctx context.Context, orgID, id string) error
	ResolveKey(ctx context.Context, orgID, provider, baseURL string) (plaintext string, ok bool, err error)
}

// *adminstore.Store (W-BYOK-DB) is the production implementation.
var _ OrgCredentialStore = (*adminstore.Store)(nil)

// OrgCredsVersionBumper is the gateway cache-invalidation hook
// (W-BYOK-CORE): after a successful credentials CRUD the handlers bump the
// org's version so the gateway drops its negative lookups immediately
// (pkg/gateway.OrgCredsVersionStore satisfies this structurally). Failure to
// bump never fails the CRUD response — staleness is bounded by the gateway's
// 30s probe TTL.
type OrgCredsVersionBumper interface {
	SetOrgCredsVersion(ctx context.Context, orgID string, version int64) error
}

// credentialProviders is the BYOK provider whitelist — the canonical names
// accepted by pkg/provider's factory (provider.New). Declared locally instead
// of calling the factory at validation time because the factory CONSTRUCTS
// adapters (NewSber reads env and loads an mTLS keypair from disk — a
// validation-time side effect and a false negative when the cert files are
// absent). TestOrgCredentialProvidersMatchFactory pins every entry to the
// factory.
var credentialProviders = map[string]struct{}{
	"openai":        {},
	"openai-compat": {},
	"anthropic":     {},
	"sakana":        {},
	"sarvam":        {},
	"krutrim":       {},
	"naver":         {},
	"falcon":        {},
	"jais":          {},
	"mistral":       {},
	"yandex":        {},
	"sber":          {},
	"vllm":          {},
	"ollama":        {},
	"tgi":           {},
	"llamacpp":      {},
	"zai-coding":    {},
}

// Sizing and throttle bounds for the credential surface.
const (
	credBodyLimit       = 32 * 1024       // JSON body cap (key ≤ 5000 + overhead)
	credKeyMinLen       = 20              // plaintext key length floor
	credKeyMaxLen       = 5000            // plaintext key length ceiling
	credNameMaxLen      = 256             // display-name ceiling
	credTestTimeout     = 5 * time.Second // upstream dial+response budget
	credTestRateLimit   = 1               // connection tests per window per org
	credTestRateWindow  = 1 * time.Minute // throttle window
	credTestErrMaxLen   = 300             // upstream error text truncation
	credTestMaxBodyRead = 4 * 1024        // upstream body drained, never echoed
	// discovery): model catalogs run tens of KiB, so the 4 KiB drain cap
	// would truncate valid answers; 1 MiB bounds the parse buffer while
	// staying far above real catalogs. An over-cap body fails the parse and
	// is reported as models_list_unavailable, never partially echoed.
	credCatalogMaxBodyRead = 1024 * 1024
)

// ONLY from the upstream HTTP status and the parse outcome — the upstream
// body is never echoed and no heuristic reads it.
const (
	catalogReasonListUnavailable = "models_list_unavailable" // 404, other non-2xx, or a 2xx body that does not parse
	catalogReasonKeyForbidden    = "key_forbidden"           // upstream 403: key works, list permission missing
	catalogReasonKeyUnauthorized = "key_unauthorized"        // upstream 401: revoked/invalid key (rotate)
	catalogReasonTransport       = "transport_error"         // the request never completed (unreachable, refused, timeout)
	catalogReasonKeyUnavailable  = "key_unavailable"         // no enabled stored key resolved for this credential
)

// OrgCredentialHandlerOptions configures NewOrgCredentialHandlers.
type OrgCredentialHandlerOptions struct {
	// HTTPClient overrides the guarded upstream client. nil (production)
	// builds the SSRF-guarded client; non-nil is a hermetic test seam, the
	// same contract as ssrf's Lookup/Dial options.
	HTTPClient *http.Client
	// AllowHTTPPrivate admits http:// base URLs whose host is a LITERAL IP
	// inside ssrf.InternalCIDRs (on-prem local providers: vLLM, TGI, ...).
	// Hostname targets keep the https-only rule in every mode, and the
	// dial-time guard still applies: loopback, link-local (cloud metadata)
	// and every other reserved range stay forbidden. No config knob exists
	// yet; deployments run https-only by default.
	AllowHTTPPrivate bool
	// VersionBumper bumps the org's credential version for gateway cache
	// invalidation after successful CRUD (nil = skip; the gateway's 30s
	// probe TTL bounds staleness). Production wires
	// gateway.NewOrgCredsVersionStore over the shared Redis.
	VersionBumper OrgCredsVersionBumper
}

// OrgCredentialHandlers serves the BYOK provider-credential routes. The admin
// server wires it with SetOrgCredentialHandlers over *adminstore.Store.
type OrgCredentialHandlers struct {
	store OrgCredentialStore
	// client is the SSRF-guarded upstream client unless overridden by
	// OrgCredentialHandlerOptions.HTTPClient (hermetic tests only).
	client *http.Client
	// testRate throttles connection tests to credTestRateLimit per org per
	// credTestRateWindow (keyed by org id).
	testRate *rateLimiter
	logger   *slog.Logger
	// allowHTTPPrivate mirrors OrgCredentialHandlerOptions.AllowHTTPPrivate.
	allowHTTPPrivate bool
	// versions bumps the org credential version after successful CRUD; nil
	// disables the bump (bounded-staleness fallback).
	versions OrgCredsVersionBumper
}

// NewOrgCredentialHandlers builds the credential handlers over store.
// A nil logger falls back to slog.Default().
func NewOrgCredentialHandlers(store OrgCredentialStore, opts OrgCredentialHandlerOptions, logger *slog.Logger) *OrgCredentialHandlers {
	client := opts.HTTPClient
	if client == nil {
		client = newCredTestClient(opts.AllowHTTPPrivate)
	}
	if logger == nil {
		logger = slog.Default()
	}
	// The throttle has no cleanup goroutine on purpose: this is admin-plane
	// traffic (bounded by the org count), and tests construct handlers per
	// case — a goroutine per instance would leak across the suite.
	return &OrgCredentialHandlers{
		store:            store,
		client:           client,
		testRate:         newRateLimiter(credTestRateLimit, credTestRateWindow),
		logger:           logger,
		allowHTTPPrivate: opts.AllowHTTPPrivate,
		versions:         opts.VersionBumper,
	}
}

// newCredTestClient builds the upstream client for POST .../test. Every dial
// goes through ssrf.NewGuardedDialer: DNS answers are resolved and pinned at
// dial time and any reserved address refuses the connection — the base_url is
// admin-entered, i.e. untrusted input. With allowInternal, LITERAL private-
// range IPs additionally dial directly (on-prem local providers behind the
// deployment flag); resolved hostnames stay fully guarded in every mode.
// No proxy: admin-entered URLs must not be relayed through an operator proxy.
func newCredTestClient(allowInternal bool) *http.Client {
	guarded := ssrf.NewGuardedDialer(ssrf.DialerOptions{Timeout: credTestTimeout})
	dialCtx := guarded
	if allowInternal {
		plain := &net.Dialer{Timeout: credTestTimeout}
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, err := net.SplitHostPort(addr); err == nil {
				if ip := net.ParseIP(host); ip != nil && ssrf.IsInternalNetwork(ip) {
					return plain.DialContext(ctx, network, addr)
				}
			}
			return guarded(ctx, network, addr)
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialCtx,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       time.Minute,
			TLSHandshakeTimeout:   credTestTimeout,
			ResponseHeaderTimeout: credTestTimeout,
		},
		Timeout: credTestTimeout,
	}
}

// SetOrgCredentialHandlers attaches the BYOK credential handlers to the admin
// router. nil (the default) keeps the routes mounted but unwired: they answer
// 503 until the credential store (W-BYOK-DB) is wired by the admin server.
func (h *AdminHandlers) SetOrgCredentialHandlers(o *OrgCredentialHandlers) {
	h.orgCreds = o
}

// RequireOrgPermissionKeysManage is the credential-surface variant of
// RequireOrgPermission (roles_authz.go) for adminstore.PermKeysManage, with
// one org_settings-style difference (orgBudgetAccess): a caller with NO
// membership on the target org gets 404, not 403 — a foreign org must not be
// distinguishable from a nonexistent one (resourceHidden semantics). A member
// whose role lacks the permission is 403. Root always passes. The name keeps
// the "RequireOrgPermission" fragment so the route inventories classify the
// chain as an org gate.
func (h *AdminHandlers) RequireOrgPermissionKeysManage() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			orgID := targetOrgID(r)
			if orgID == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org target required"})
				return
			}
			role, ok := h.callerRoleOnOrg(r, orgID)
			if !ok {
				writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
				return
			}
			if !adminstore.RoleHas(string(role), adminstore.PermKeysManage) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, orgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// mountOrgCredentials registers the BYOK provider-credential routes under the
// org-permission gate. The {id} path param is the org; RequireOrgPermissionKeysManage
// resolves it (targetOrgID reads the /api/orgs/ prefix) and hides a foreign
// org (404) or 403s a member without keys.manage. Cross-org RESOURCE ids (a
// credId belonging to another org) are invisible too: the handlers look the
// row up through the org-scoped store reads and answer 404.
func (h *AdminHandlers) mountOrgCredentials(protected chi.Router) {
	creds := protected.With(h.RequireOrgPermissionKeysManage())
	creds.Get("/api/orgs/{id}/provider-credentials", h.orgCreds.handleList)
	creds.Post("/api/orgs/{id}/provider-credentials", h.orgCreds.handleCreate)
	creds.Put("/api/orgs/{id}/provider-credentials/{credId}", h.orgCreds.handleUpdate)
	creds.Delete("/api/orgs/{id}/provider-credentials/{credId}", h.orgCreds.handleRemove)
	creds.Post("/api/orgs/{id}/provider-credentials/{credId}/test", h.orgCreds.handleTest)
	creds.Post("/api/orgs/{id}/provider-credentials/{credId}/models", h.orgCreds.handleListModels)
}

// unwired reports whether the credential store is missing and, when it is,
// writes the 503. Nil-receiver safe: the routes are mounted unconditionally.
func (o *OrgCredentialHandlers) unwired(w http.ResponseWriter) bool {
	if o == nil || o.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "org credential store not configured"})
		return true
	}
	return false
}

// credTestResult is the POST .../test payload: ok mirrors the upstream 2xx,
// status is the upstream HTTP status (absent when the request never got one),
// and error carries a sanitized transport reason when the test could not run.
type credTestResult struct {
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// successful run is a snapshot only: discovered=true with the upstream's
// model ids and verified=false — the catalog is display-only evidence of what
// the provider listed at request time, never a usability mark and never
// written to any registry. A refusal carries count=0 with a machine-readable
// reason (catalogReason* constants) instead of data.
type credCatalogResult struct {
	Provider   string   `json:"provider"`
	BaseURL    string   `json:"base_url,omitempty"`
	Count      int      `json:"count"`
	Data       []string `json:"data,omitempty"`
	Discovered bool     `json:"discovered,omitempty"`
	// Verified is an explicit false on success ("discovery ≠ verified");
	// absent on refusals (the *bool keeps false from being dropped).
	Verified *bool  `json:"verified,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Status   int    `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

type orgCredentialCreateBody struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
}

type orgCredentialUpdateBody struct {
	Name     *string `json:"name"`
	Provider *string `json:"provider"`
	BaseURL  *string `json:"base_url"`
	Enabled  *bool   `json:"enabled"`
	APIKey   *string `json:"api_key"`
}

// handleList serves GET /api/orgs/{id}/provider-credentials.
func (o *OrgCredentialHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	creds, err := o.store.List(r.Context(), r.PathValue("id"))
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": creds, "count": len(creds)})
}

// handleCreate serves POST /api/orgs/{id}/provider-credentials. The plaintext
// key travels only into the store call; the response row carries the mask.
func (o *OrgCredentialHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	var body orgCredentialCreateBody
	if !decodeCredBody(w, r, &body) {
		return
	}
	name, prov, baseURL, ok := o.validateCredPayload(w, body.Name, body.Provider, body.BaseURL)
	if !ok {
		return
	}
	if !validateCredKey(body.APIKey, w) {
		return
	}
	cred, err := o.store.Create(r.Context(), r.PathValue("id"), name, prov, baseURL, body.APIKey)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.bumpCredsVersion(r, r.PathValue("id"))
	writeJSON(w, http.StatusCreated, cred)
}

// handleUpdate serves PUT /api/orgs/{id}/provider-credentials/{credId}.
// Nil fields keep the stored value; api_key rotates the key when present.
// The merged row is written back with OrgID pinned to the path org so the
// store can scope the UPDATE by (id, org) in depth.
func (o *OrgCredentialHandlers) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, credID := r.PathValue("id"), r.PathValue("credId")
	var body orgCredentialUpdateBody
	if !decodeCredBody(w, r, &body) {
		return
	}
	current, ok := o.visibleCred(w, r, orgID, credID)
	if !ok {
		return
	}
	merged := *current
	newKey := ""
	if body.Name != nil || body.Provider != nil || body.BaseURL != nil {
		name, prov, baseURL := current.Name, current.Provider, current.BaseURL
		if body.Name != nil {
			name = *body.Name
		}
		if body.Provider != nil {
			prov = *body.Provider
		}
		if body.BaseURL != nil {
			baseURL = *body.BaseURL
		}
		vName, vProv, vURL, ok := o.validateCredPayload(w, name, prov, baseURL)
		if !ok {
			return
		}
		merged.Name, merged.Provider, merged.BaseURL = vName, vProv, vURL
	}
	if body.Enabled != nil {
		merged.Enabled = *body.Enabled
	}
	if body.APIKey != nil {
		if !validateCredKey(*body.APIKey, w) {
			return
		}
		newKey = *body.APIKey
	}
	merged.OrgID = orgID
	cred, err := o.store.Update(r.Context(), orgID, credID, merged, newKey)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.bumpCredsVersion(r, orgID)
	writeJSON(w, http.StatusOK, cred)
}

// handleRemove serves DELETE /api/orgs/{id}/provider-credentials/{credId}.
func (o *OrgCredentialHandlers) handleRemove(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, credID := r.PathValue("id"), r.PathValue("credId")
	if _, ok := o.visibleCred(w, r, orgID, credID); !ok {
		return
	}
	if err := o.store.Delete(r.Context(), orgID, credID); err != nil {
		o.writeStoreError(w, err)
		return
	}
	o.bumpCredsVersion(r, orgID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleTest serves POST /api/orgs/{id}/provider-credentials/{credId}/test:
// a one-shot GET {base_url}/models with the stored key, 5s budget, dial-time
// SSRF guard, and a 1/min-per-org throttle. The response is {ok, status,
// error?} — the upstream body is drained, never echoed, and the plaintext
// key never leaves the Authorization header.
func (o *OrgCredentialHandlers) handleTest(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, credID := r.PathValue("id"), r.PathValue("credId")
	// Throttle first: an unknown credId must not become a free prober.
	if !o.testRate.allow(orgID) {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "credential test rate limit exceeded (1 per minute per organization)"})
		return
	}
	cred, ok := o.visibleCred(w, r, orgID, credID)
	if !ok {
		return
	}
	plaintext, hasKey, err := o.store.ResolveKey(r.Context(), orgID, cred.Provider, cred.BaseURL)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	if !hasKey || plaintext == "" {
		writeJSON(w, http.StatusOK, credTestResult{Error: "credential key is not available"})
		return
	}
	writeJSON(w, http.StatusOK, o.probeModels(r, cred.BaseURL, plaintext))
}

// probeModels issues the guarded GET {base_url}/models and maps the outcome
// onto credTestResult. The key is placed only in the request header — it is
// never logged, stored, or written to the response.
func (o *OrgCredentialHandlers) probeModels(r *http.Request, baseURL, plaintext string) credTestResult {
	target := strings.TrimRight(baseURL, "/") + "/models"
	ctx, cancel := context.WithTimeout(r.Context(), credTestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return credTestResult{Error: "invalid credential base_url"}
	}
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		// url.Error embeds the URL (admin-entered, no secrets) but never
		// request headers; still truncated to keep the payload bounded.
		return credTestResult{Error: truncateErrText(err.Error())}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, credTestMaxBodyRead))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return credTestResult{OK: true, Status: resp.StatusCode}
	}
	return credTestResult{Status: resp.StatusCode, Error: "upstream rejected the credential"}
}

// handleListModels serves POST /api/orgs/{id}/provider-credentials/{credId}/models
// throttle (shared counter, D-4 default), visibleCred, ResolveKey — but the
// upstream GET {base_url}/models body is parsed and returned as a
// display-only catalog snapshot. The response never carries the key and
// nothing discovered is written to any store (D-3 default: display-only).
func (o *OrgCredentialHandlers) handleListModels(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID, credID := r.PathValue("id"), r.PathValue("credId")
	// Throttle first, shared with /test: an unknown credId must not become a
	// free prober (D-4 default: one 1/min/org budget for both surfaces).
	if !o.testRate.allow(orgID) {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "credential test rate limit exceeded (1 per minute per organization)"})
		return
	}
	cred, ok := o.visibleCred(w, r, orgID, credID)
	if !ok {
		return
	}
	plaintext, hasKey, err := o.store.ResolveKey(r.Context(), orgID, cred.Provider, cred.BaseURL)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	if !hasKey || plaintext == "" {
		writeJSON(w, http.StatusOK, credCatalogResult{Provider: cred.Provider, Reason: catalogReasonKeyUnavailable})
		return
	}
	writeJSON(w, http.StatusOK, o.probeModelCatalog(r, cred.Provider, cred.BaseURL, plaintext))
}

// probeModelCatalog issues the guarded GET {base_url}/models with the stored
// key (Bearer — discovery supports openai-compat semantics only, D-2
// decision pending for x-api-key providers) and maps the outcome onto
// credCatalogResult. The refusal reason derives only from the upstream
// status and the parse outcome; the body is never echoed and the key never
// leaves the Authorization header (no logging, no storage).
func (o *OrgCredentialHandlers) probeModelCatalog(r *http.Request, provider, baseURL, plaintext string) credCatalogResult {
	target := strings.TrimRight(baseURL, "/") + "/models"
	ctx, cancel := context.WithTimeout(r.Context(), credTestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return credCatalogResult{Provider: provider, Reason: catalogReasonTransport, Error: "invalid credential base_url"}
	}
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		// url.Error embeds the URL (admin-entered, no secrets) but never
		// request headers; still truncated to keep the payload bounded.
		return credCatalogResult{Provider: provider, Reason: catalogReasonTransport, Error: truncateErrText(err.Error())}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return credCatalogResult{Provider: provider, Reason: catalogReasonKeyUnauthorized, Status: resp.StatusCode}
	case resp.StatusCode == http.StatusForbidden:
		// Listing refused ≠ credential broken: chat traffic with this key
		// may still work; the manual-entry fallback stays available.
		return credCatalogResult{Provider: provider, Reason: catalogReasonKeyForbidden, Status: resp.StatusCode}
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return parseModelCatalog(resp.Body, provider, baseURL, resp.StatusCode)
	default:
		// 404 (no list API) and every other upstream refusal: a property of
		// the provider's list endpoint, not a transport failure.
		return credCatalogResult{Provider: provider, Reason: catalogReasonListUnavailable, Status: resp.StatusCode}
	}
}

// parseModelCatalog extracts data[].id from an OpenAI-compat list body
// ({object:"list",data:[{id,…}]} — the same wire format the gateway emits).
// A body that fails to parse or exceeds credCatalogMaxBodyRead is the
// models_list_unavailable refusal, never a partial success.
func parseModelCatalog(body io.Reader, provider, baseURL string, status int) credCatalogResult {
	fail := func() credCatalogResult {
		return credCatalogResult{Provider: provider, Reason: catalogReasonListUnavailable, Status: status}
	}
	raw, err := io.ReadAll(io.LimitReader(body, credCatalogMaxBodyRead+1))
	if err != nil || len(raw) > credCatalogMaxBodyRead {
		return fail()
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fail()
	}
	ids := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	verified := false
	return credCatalogResult{
		Provider: provider, BaseURL: baseURL, Count: len(ids),
		Data: ids, Discovered: true, Verified: &verified,
	}
}

// visibleCred looks credID up within the PATH org only. A cred of another org
// (or a missing one) is the same 404 — cross-org resource ids stay invisible
// (the resourceHidden semantics for org-scoped rows).
func (o *OrgCredentialHandlers) visibleCred(w http.ResponseWriter, r *http.Request, orgID, credID string) (*OrgCredential, bool) {
	creds, err := o.store.List(r.Context(), orgID)
	if err != nil {
		o.writeStoreError(w, err)
		return nil, false
	}
	for i := range creds {
		if creds[i].ID == credID {
			return &creds[i], true
		}
	}
	writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
	return nil, false
}

// validateCredPayload validates the (name, provider, base_url) triple and
// writes the 400 itself (false = response written).
func (o *OrgCredentialHandlers) validateCredPayload(w http.ResponseWriter, rawName, rawProvider, rawBaseURL string) (name, prov, baseURL string, ok bool) {
	name, err := validateCredName(rawName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return "", "", "", false
	}
	prov, err = validateCredProvider(rawProvider)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return "", "", "", false
	}
	baseURL, err = validateCredBaseURL(rawBaseURL, o.allowHTTPPrivate)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return "", "", "", false
	}
	return name, prov, baseURL, true
}

// bumpCredsVersion invalidates the gateway's org-credential cache after a
// successful CRUD (W-BYOK-CORE contract: orgcreds:ver:<orgID>, nanos). A
// failed bump is a warning, never a failed response — the gateway's 30s
// probe TTL bounds the staleness either way.
func (o *OrgCredentialHandlers) bumpCredsVersion(r *http.Request, orgID string) {
	if o.versions == nil {
		return
	}
	if err := o.versions.SetOrgCredsVersion(r.Context(), orgID, time.Now().UnixNano()); err != nil {
		o.logger.Warn("org credential version bump failed; gateway negative cache expires via probe TTL",
			"org_id", orgID, "error", err.Error())
	}
}

// writeStoreError maps store failures: not-found → 404, an org-unique
// constraint violation (duplicate name) → 409, anything else → a generic 500
// (the store error text can carry driver internals; it goes to the log,
// never to the wire).
func (o *OrgCredentialHandlers) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, adminstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeJSON(w, http.StatusConflict, apiError{Error: "a credential with this name already exists in this organization"})
		return
	}
	if o != nil && o.logger != nil {
		o.logger.Error("org credential store call failed", "error", err.Error())
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal error"})
}

func validateCredName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > credNameMaxLen {
		return "", errors.New("name must be 1 to 256 characters")
	}
	return name, nil
}

func validateCredProvider(raw string) (string, error) {
	prov := strings.TrimSpace(raw)
	if prov == "" {
		return "", errors.New("provider is required")
	}
	if _, ok := credentialProviders[prov]; !ok {
		return "", errors.New("unknown provider (must be one of the pkg/provider factory names)")
	}
	return prov, nil
}

// validateCredBaseURL normalizes the base URL: https-only by default; http is
// admitted solely for literal private-range IPs when the deployment flag is
// on (on-prem local providers). Query and fragment are stripped and the URL
// is stored without userinfo — the test endpoint derives {base_url}/models.
func validateCredBaseURL(raw string, allowHTTPPrivate bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("base_url must be an absolute URL with a host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if !allowHTTPPrivate || ip == nil || !ssrf.IsInternalNetwork(ip) {
			return "", errors.New("base_url must use https (http only for literal private-range IPs when the deployment flag allows it)")
		}
	default:
		return "", errors.New("base_url must use https")
	}
	if u.User != nil {
		return "", errors.New("base_url must not embed credentials")
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

// validateCredKey enforces the 20..5000 plaintext length bound and writes the
// 400 itself (false = response written).
func validateCredKey(key string, w http.ResponseWriter) bool {
	if n := len(key); n < credKeyMinLen || n > credKeyMaxLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "api_key must be between 20 and 5000 characters"})
		return false
	}
	return true
}

// decodeCredBody reads a credential JSON body under the 32 KiB cap and
// rejects unknown fields — a typo'd payload 400s instead of silently
// dropping, say, a plaintext field under a different name.
func decodeCredBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, credBodyLimit))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	return true
}

func truncateErrText(s string) string {
	if len(s) > credTestErrMaxLen {
		return s[:credTestErrMaxLen]
	}
	return s
}
