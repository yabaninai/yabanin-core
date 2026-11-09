package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script/expr"
)

type contentAuthzInputKey struct{}

type contentAuthzInput struct {
	Denied bool
	Grant  bool
	Own    bool
	Role   bool
	// Delegation marks a live principal delegation (N04-P05 T03): the
	// marked agent/CI subject acts inside a scoped human delegation.
	Delegation bool
}

type contentAuthorizationEvaluator interface {
	EvaluateScopedAuthorization(context.Context, []pipeline.ScopedDenyRule, pipeline.ConditionProgram, pipeline.DecisionEnvironment) pipeline.AuthorizationVerdict
}

// contentAuthorizationPolicy holds the compiled authorization conditions
// (N04-P04-T04): scoped deny rules evaluated BEFORE any grant evidence, then
// the grant program. Both compile through the shared pipeline Expr engine —
// the same sandboxed, typed environment the gateway policies use.
var contentAuthorizationPolicy struct {
	sync.Once
	denyRules []pipeline.ScopedDenyRule
	program   pipeline.ConditionProgram
	err       error
}

// contentDenyRuleExplicit is the explicit policy deny input
// (Context["deny"]). It is a scoped deny RULE, not a term of the grant
// program: a match refuses absolutely, so grant/role evidence can never
// override it (pinned by TestAuthorizeContentUsesDenyGrantRolePrecedenceAndFailsClosed
// and the scoped-rule tests).
const contentDenyRuleExplicit = "explicit_policy_deny"

func defaultContentAuthorizationProgram() ([]pipeline.ScopedDenyRule, pipeline.ConditionProgram, error) {
	contentAuthorizationPolicy.Do(func() {
		engine := expr.New()
		deny, err := engine.Compile(`Context["deny"] == "true"`)
		if err != nil {
			contentAuthorizationPolicy.err = err
			return
		}
		program, err := engine.Compile(`Context["grant"] == "true" || Context["delegation"] == "true" || Context["own"] == "true" || Context["role"] == "true"`)
		if err != nil {
			contentAuthorizationPolicy.err = err
			return
		}
		contentAuthorizationPolicy.denyRules = []pipeline.ScopedDenyRule{
			{Name: contentDenyRuleExplicit, Condition: deny},
		}
		contentAuthorizationPolicy.program = program
	})
	return contentAuthorizationPolicy.denyRules, contentAuthorizationPolicy.program, contentAuthorizationPolicy.err
}

// newContentAuthorizationEvaluator is the evaluator seam: production always
// uses the shared pipeline.Evaluator; tests substitute a fake to prove the
// fail-closed wiring of unavailable mandatory checks (never for behavior).
var newContentAuthorizationEvaluator = func() contentAuthorizationEvaluator { return pipeline.Evaluator{} }

// AuthorizeContent is the single mandatory content decision boundary. Every
// policy attribute has trusted provenance; a missing evaluator/program or
// untrusted input is denied by pipeline.Evaluator. Scoped deny rules decide
// first and absolutely; the grant program (deny > grant > delegation > own >
// role evidence) decides only when no deny rule matched.
func (h *AdminHandlers) AuthorizeContent(principal pipeline.DecisionPrincipal, action pipeline.TrustedAttribute, resource pipeline.DecisionResource, ctx context.Context) pipeline.AuthorizationVerdict {
	deny := pipeline.UnavailableDeny("mandatory authorization evaluator unavailable", errors.New("authorization evaluator unavailable"))
	if ctx == nil {
		return deny
	}
	denyRules, program, err := defaultContentAuthorizationProgram()
	if err != nil || program == nil {
		if err == nil {
			err = errors.New("authorization condition unavailable")
		}
		return pipeline.UnavailableDeny("mandatory authorization evaluator unavailable", err)
	}
	evaluator := newContentAuthorizationEvaluator()
	input, _ := ctx.Value(contentAuthzInputKey{}).(contentAuthzInput)
	decision := pipeline.DecisionEnvironment{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context: map[string]pipeline.TrustedAttribute{
			"deny":       {Value: strconv.FormatBool(input.Denied), Source: "admin-policy-context"},
			"grant":      {Value: strconv.FormatBool(input.Grant), Source: "durable-request-grant"},
			"delegation": {Value: strconv.FormatBool(input.Delegation), Source: "principal-delegation"},
			"own":        {Value: strconv.FormatBool(input.Own), Source: "authenticated-principal"},
			"role":       {Value: strconv.FormatBool(input.Role), Source: "org-role-store"},
		},
	}
	return evaluator.EvaluateScopedAuthorization(ctx, denyRules, program, decision)
}

// authorizeRequestContent adapts the authenticated HTTP subject and its
// durable/org-scoped evidence to the shared evaluator. The store still checks
// ownership at row level, so a positive own-default decision cannot disclose
// another person's content. delegated marks a live principal delegation for a
// marked agent/CI subject (N04-P05 T03); it is deny-able like every other
// input and never affects a human subject.
func (h *AdminHandlers) authorizeRequestContent(r *http.Request, orgID, requestID string, grant, delegated bool) pipeline.AuthorizationVerdict {
	userID := requestUserID(r)
	subject, marked := adminstore.RequestPayloadSubjectFromContext(r.Context())
	kind := "human"
	if marked && subject.Type != "" {
		kind = string(subject.Type)
	}
	human := kind == string(adminstore.RequestPayloadHuman)
	role, member := h.callerRoleOnOrg(r, orgID)
	input := contentAuthzInput{
		Denied:     adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context()),
		Grant:      grant,
		Delegation: !human && delegated,
		Own:        human && userID != "",
		Role:       human && member && adminstore.RoleHas(string(role), adminstore.PermRequestsPayloads),
	}
	ctx := context.WithValue(r.Context(), contentAuthzInputKey{}, input)
	principal := pipeline.DecisionPrincipal{
		ID:   pipeline.TrustedAttribute{Value: userID, Source: "admin-session"},
		Kind: pipeline.TrustedAttribute{Value: kind, Source: "authenticated-subject"},
	}
	resource := pipeline.DecisionResource{
		Type:         pipeline.TrustedAttribute{Value: "request", Source: "admin-route"},
		ID:           pipeline.TrustedAttribute{Value: requestID, Source: "admin-route"},
		Organization: pipeline.TrustedAttribute{Value: orgID, Source: "admin-route"},
	}
	verdict := h.AuthorizeContent(principal,
		pipeline.TrustedAttribute{Value: "requests.read_payloads", Source: "admin-route"}, resource, ctx)
	if verdict.Class() == pipeline.DecisionClassUnavailable {
		auditContentAuthzUnavailable(h, r, orgID, requestID, verdict)
	}
	return verdict
}

// requestContentAuthzAuditDetail is the journal payload of one mandatory
// content-authorization check that could not run (N02-P03-T03, the authz
// twin of guardFailureAudit). It carries identifiers and the typed failure
// class only — never payload content, never principal material beyond the
// caller IDs the journal already stamps.
type requestContentAuthzAuditDetail struct {
	OrgID     string `json:"org_id"`
	RequestID string `json:"request_id"`
	Class     string `json:"class"`
	Reason    string `json:"reason"`
}

// auditContentAuthzUnavailable journals every mandatory content-authorization
// check that failed to run through the durable admin audit seam (AF-10). The
// operation itself stays denied (the verdict carries the reason), and the
// journal answers "why was content hidden" after the fact. Audit degradation
// (outbox / memory-pending) follows the shared journal path, so it never
// turns the denial into an allow.
func auditContentAuthzUnavailable(h *AdminHandlers, r *http.Request, orgID, requestID string, verdict pipeline.AuthorizationVerdict) {
	details, err := json.Marshal(requestContentAuthzAuditDetail{
		OrgID:     orgID,
		RequestID: requestID,
		Class:     string(verdict.Class()),
		Reason:    verdict.Reason,
	})
	if err != nil {
		// Unreachable for this all-scalar struct; fall back to a fixed,
		// valid-JSON marker rather than ever storing malformed JSON.
		details = []byte(`{"class":"unavailable","reason":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, "request_content_authz.unavailable", "organization:"+orgID, string(details))
}

// S01: route×role×org authorization matrix.
//
// The middleware layer (adminauth.ChiAuthMiddleware + MustBeRoot) already
// enforces: 401 without a session, 403 for non-root on root-only routes.
// This file adds the ORG dimension — the missing piece: an org-scoped
// mutation must be rejected with 403 when the target org does not match the
// one the request carries. The org ID is propagated out-of-band via the
// X-Yabanin-Org-Id header (set by the dashboard scope bar, U03/U04); the
// body/query/path value is what the client asks to mutate.
//
// Role matrix (enforced today, asserted by the tests):
//
//	role      auth        root-only CRUD    org-scoped ops
//	anon      401         —                 —
//	admin     200         403               200 when org matches header
//	root      200         200               200 (any org — operator role)
//
// Org dimension:
//
//	no header            → 400 (scope is mandatory for org-scoped routes)
//	header ≠ path/query  → 403 (cross-org access)
//	header == target     → handler runs

// OrgHeader is the out-of-band scope header for org-scoped mutations.
const OrgHeader = "X-Yabanin-Org-Id"

// ctxKeyOrgScope carries the request's org scope through the context.
type ctxKeyOrgScope struct{}

// isRoot reads the session's root flag (adminauth.ChiAuthMiddleware).
func isRoot(r *http.Request) bool {
	v, _ := r.Context().Value(adminauth.ContextKeyIsRoot{}).(bool)
	return v
}

func requestUserID(r *http.Request) string {
	id, _ := r.Context().Value(adminauth.ContextKeyUserID{}).(string)
	return id
}

// sessionNonRoot is an authenticated caller who is not the platform operator.
// Handlers invoked without a session (older unit tests, and nothing on the
// router — ChiAuthMiddleware always sets the user id) keep their previous
// behavior. Root may address any org.
func sessionNonRoot(r *http.Request) bool {
	return !isRoot(r) && requestUserID(r) != ""
}

// resourceHidden rejects a non-root caller when the row's org is not the
// request scope. The status is 404 so a foreign id does not reveal that the
// row exists. Root is the platform operator and may address any org.
func (h *AdminHandlers) resourceHidden(w http.ResponseWriter, r *http.Request, resourceOrg string) bool {
	if !sessionNonRoot(r) {
		return false
	}
	scope := targetOrgID(r)
	if scope == "" {
		scope = OrgScopeFromRequest(r)
	}
	if resourceOrg == "" || scope == "" || resourceOrg != scope {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return true
	}
	return false
}

// orgScopedPattern rewrites a concrete request path to its registered
// template so it can be compared against orgScopedPaths. Only the org
// parameter slot is rewritten — every org-scoped route has exactly one.
func orgScopedPattern(path string) string {
	const prefix = "/api/organizations/"
	if strings.HasPrefix(path, prefix) {
		rest := strings.TrimPrefix(path, prefix)
		first := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			first = rest[:i]
		}
		return prefix + "{id}" + strings.TrimPrefix(rest, first)
	}
	const orgsPrefix = "/api/orgs/"
	if strings.HasPrefix(path, orgsPrefix) {
		rest := strings.TrimPrefix(path, orgsPrefix)
		first := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			first = rest[:i]
		}
		return orgsPrefix + "{id}" + strings.TrimPrefix(rest, first)
	}
	return path
}

// isOrgScoped reports whether the request targets exactly one org's data.
// Org-AGGREGATE endpoints (low-balance, cost/global, audit-logs) are
// deliberately not here: they are cross-org by design and stay under the
// root-only middleware. Verb filtering happens in OrgScopeMiddleware (GET/
// HEAD/OPTIONS are read-only and pass through).
func isOrgScoped(r *http.Request) bool {
	pattern := orgScopedPattern(r.URL.Path)
	for _, p := range orgScopedPaths {
		if pattern == p {
			return true
		}
	}
	return false
}

// orgScopedPaths: the mutation routes that take an org ID in path or body.
// Mirrors the route table in router.go (the protected root-only group).
var orgScopedPaths = []string{
	"/api/organizations/{id}",
	"/api/organizations/{id}/cache-settings",
	"/api/organizations/{id}/original-retention",
	"/api/organizations/{id}/routing",
	"/api/organizations/{id}/policy-packs",
	"/api/organizations/{id}/residency",
	"/api/organizations/{id}/spend-alert",
	"/api/organizations/{id}/region",
	"/api/organizations/{id}/lineage",
	"/api/organizations/{orgID}/verticals",
	"/api/organizations/{orgID}/templates/export",
	"/api/orgs/{id}/credits/topup",
	"/api/orgs/{id}/resale-pricing",
	// PUT (subscribe) is the mutating verb of the templates route; GET export
	// stays aggregate and is covered by the root-only middleware.
	"/api/organizations/{orgID}/templates/{templateID}/subscribe",
	// MCP-02: external MCP server registry. The {name} slot is a literal
	// value (not the org parameter) — orgScopedPattern rewrites only the
	// first segment after the org prefix, so this matches the route table.
	"/api/organizations/{id}/mcp/servers",
	"/api/organizations/{id}/mcp/servers/{name}",
	// MC-1: the server-level MCP credential (PUT/DELETE mutate; GET passes).
	"/api/organizations/{id}/mcp/servers/{name}/credential",
}

// OrgScopeMiddleware enforces the org dimension of the authorization matrix.
// It must run AFTER ChiAuthMiddleware (it relies on the session context).
func OrgScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isOrgScoped(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Reads are not scope-gated: the role dimension (MustBeRoot) already
		// covers them, and a future org-scoped read can require the header
		// without breaking the mutation contract.
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if isRoot(r) {
			// Root is an operator: any org is in scope. A missing header
			// still resolves the scope to the TARGET org (the path param)
			// so handler-side requireOrgScope passes and the audit trail
			// records what was actually touched.
			// NOTE: orgTarget is NOT called for root — on PUT it would
			// consume the request body and starve the handler. The scope
			// value is only an audit hint; the handler reads its own id.
			scope := r.Header.Get(OrgHeader)
			if scope == "" {
				// Middleware runs before chi's route match, so PathValue is
				// empty here — parse the path the same way orgTarget does.
				// Never call orgTarget (it would consume the body on PUT).
				if rest, ok := strings.CutPrefix(r.URL.Path, "/api/organizations/"); ok {
					scope, _, _ = strings.Cut(rest, "/")
				} else if rest, ok := strings.CutPrefix(r.URL.Path, "/api/orgs/"); ok {
					scope, _, _ = strings.Cut(rest, "/")
				}
			}
			if scope != "" {
				ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, scope)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
			return
		}
		headerOrg := r.Header.Get(OrgHeader)
		if headerOrg == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "missing org scope: set the " + OrgHeader + " header"})
			return
		}
		target := orgTarget(r)
		if target == "" {
			// Route matches the pattern but no org parameter was extracted —
			// treat the whole request as out of scope (fail-closed).
			writeJSON(w, http.StatusForbidden, apiError{Error: "org scope does not match the request target"})
			return
		}
		if headerOrg != target {
			writeJSON(w, http.StatusForbidden, apiError{Error: "org scope does not match the request target"})
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, headerOrg)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// orgTarget extracts the org identifier the request actually targets:
// the {id}/{orgID} URL parameter when the route has one (chi v5 exposes
// route params through http.Request.PathValue), otherwise the org_id field
// of a JSON body. The body is read and re-wrapped so the handler can still
// decode it afterwards.
//
// IMPORTANT: PathValue is only populated AFTER chi's route match, which
// happens when the request reaches the terminal handler — NOT in
// middleware. So in OrgScopeMiddleware (which runs before the match)
// PathValue returns "". The middleware must parse the path itself.
func orgTarget(r *http.Request) string {
	if v := r.PathValue("id"); v != "" {
		return v
	}
	if v := r.PathValue("orgID"); v != "" {
		return v
	}
	// Middleware path: PathValue is empty, parse the URL directly.
	// /api/organizations/{id}/... or /api/orgs/{id}/...
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/organizations/"); ok {
		if id, _, _ := strings.Cut(rest, "/"); id != "" {
			return id
		}
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/orgs/"); ok {
		if id, _, _ := strings.Cut(rest, "/"); id != "" {
			return id
		}
	}
	if r.Method == http.MethodGet || r.Method == http.MethodDelete || r.Body == nil {
		return ""
	}
	var probe struct {
		OrgID string `json:"org_id"`
	}
	if err := decodeJSONBody(r, &probe); err != nil {
		// Unparseable body → the handler will 400 it; fail-closed here too.
		return ""
	}
	return probe.OrgID
}

// decodeJSONBody reads a JSON body of at most 1 MiB (the MaxBody limit) and
// leaves a fresh body on the request for the handler's own decode.
func decodeJSONBody(r *http.Request, v interface{}) error {
	limit := io.LimitReader(r.Body, 1024*1024)
	data, err := io.ReadAll(limit)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if len(data) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(data, v)
}

// OrgScopeFromRequest returns the resolved org scope for a request ("" when
// absent). Exported for white-box tests of OrgScopeMiddleware.
func OrgScopeFromRequest(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyOrgScope{}).(string)
	return v
}

// requireOrgScope resolves the org an org-scoped mutation targets. For root
// (an operator) any org is in scope, so the handler-provided org (from the
// body/query) is used. For an org-scoped admin, the middleware has already
// pinned the scope to the header org; if the handler's org differs (or is
// missing) the request is rejected cross-org. An optional permission, when
// set, must be held by the caller's role. Callers that omit it keep the
// previous membership-only check.
// It writes the error response and returns "" when the request is not
// allowed; otherwise it returns the org to operate on.
func (h *AdminHandlers) requireOrgScope(w http.ResponseWriter, r *http.Request, providedOrg string, perm ...adminstore.Permission) string {
	if isRoot(r) {
		if providedOrg == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id is required"})
			return ""
		}
		return providedOrg
	}
	scope := OrgScopeFromRequest(r)
	if scope == "" {
		writeJSON(w, http.StatusForbidden, apiError{Error: "org scope is not set for this request"})
		return ""
	}
	if providedOrg != "" && providedOrg != scope {
		writeJSON(w, http.StatusForbidden, apiError{Error: "org scope does not match the request target"})
		return ""
	}
	// ENT-02: a non-root caller must hold at least an org-admin role on the
	// target org to perform an org-scoped MUTATION (S01's 403 now resolves to a
	// specific, checkable requirement instead of a blanket "not root").
	if _, ok := h.callerRoleOnOrg(r, scope); !ok {
		writeJSON(w, http.StatusForbidden, apiError{Error: "you do not have a role on this organization"})
		return ""
	}
	if len(perm) > 0 {
		role, _ := h.callerRoleOnOrg(r, scope)
		if !adminstore.RoleHas(string(role), perm[0]) {
			writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
			return ""
		}
	}
	return scope
}
