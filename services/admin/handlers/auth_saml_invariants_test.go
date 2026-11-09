package handlers

// N04-P02-T10 independent verification corpus (test-only): SAML rights,
// data protection and resource bounds at the HTTP boundary.
//
// RIGHTS — the pre-auth SAML surface is exactly the five read-only /
// login-flow routes; no HTTP route anywhere can trigger trust refresh,
// rotation or reset, and mutating verbs never touch trust material.
// DATA — hostile refusals log no response material (verification failures
// log only the library's private reason), replay refusals log only a
// non-reversible assertion-ID hash, audit rows carry only the permitted
// triple, cookie attributes stay pinned on every SAML exit, and the served
// SP metadata publishes no IdP trust material.
// NEGATIVE — signature-wrapping and unsigned assertions never mint a
// session, and a wrapping replay after redemption yields nothing.
// RESOURCE cells live in auth_saml_resources_test.go; unit-level replay-cap
// and refresh-concurrency cells live in pkg/adminauth.

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ---- rights -------------------------------------------------------------------

// samlInvariantsRouter wires the full production router (mock store) so the
// probes below exercise chi routing, middleware and mounting, not handlers
// called directly.
func samlInvariantsRouter(t *testing.T) (*testAdminHandlers, *fakeSAMLIdP, http.Handler) {
	t.Helper()
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	return h, p, h.SetupRouter()
}

// samlRouterGet drives GET through the full router and returns the body.
func samlRouterGet(t *testing.T, router http.Handler, path string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "%s: unexpected status; body %s", path, rec.Body.String())
	return rec.Body.String()
}

// TestSAMLRights_ProductionRouteSurfaceIsFixed pins the complete production
// route table: the only routes carrying "saml" anywhere are the four pre-auth
// /auth/saml/* paths with their five methods. Any future admin endpoint that
// could trigger trust refresh/rotation/reset from HTTP would break this pin.
func TestSAMLRights_ProductionRouteSurfaceIsFixed(t *testing.T) {
	_, _, router := samlInvariantsRouter(t)

	want := map[string][]string{
		"/auth/saml/metadata": {"GET"},
		"/auth/saml/login":    {"GET"},
		"/auth/saml/acs":      {"POST"},
		"/auth/saml/slo":      {"GET", "POST"},
	}
	got := map[string][]string{}
	routes, ok := router.(chi.Routes)
	require.True(t, ok, "SetupRouter must return a chi-routable handler")
	require.NoError(t, chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == "" || !strings.Contains(route, "saml") {
			return nil
		}
		got[route] = append(got[route], method)
		return nil
	}), "route walk")
	require.Len(t, got, len(want), "unexpected saml routes: %v", got)
	for path, methods := range want {
		require.ElementsMatch(t, methods, got[path], "route %s methods", path)
	}
}

// samlNormalizeMetadata strips crewjam's moving validUntil timestamps so two
// fetches of unchanged SP metadata compare byte-equal on everything that
// matters (entity ID, certificates, endpoints).
func samlNormalizeMetadata(body string) string {
	return samlValidUntilRe.ReplaceAllString(body, "")
}

var samlValidUntilRe = regexp.MustCompile(`validUntil="[^"]*"`)

// TestSAMLRights_TrustMaterialNotWritableOverHTTP fires mutating verbs and
// guessed trust-management paths at the full router. Everything must land on
// 404/405 with no cookies minted, the served SP metadata must stay
// byte-identical, and a real login must still work afterwards.
func TestSAMLRights_TrustMaterialNotWritableOverHTTP(t *testing.T) {
	h, p, router := samlInvariantsRouter(t)

	metaBefore := samlRouterGet(t, router, "/auth/saml/metadata")

	hostileBody := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><HOSTILE-TRUST-SWAP/></EntityDescriptor>`
	probes := []struct{ method, path string }{
		{http.MethodPost, "/auth/saml/metadata"},
		{http.MethodPut, "/auth/saml/metadata"},
		{http.MethodDelete, "/auth/saml/metadata"},
		{http.MethodPost, "/auth/saml/login"},
		{http.MethodGet, "/auth/saml/acs"},
		{http.MethodPut, "/auth/saml/acs"},
		{http.MethodDelete, "/auth/saml/slo"},
		{http.MethodGet, "/auth/saml/refresh"},
		{http.MethodPost, "/auth/saml/refresh"},
		{http.MethodGet, "/auth/saml/rotate"},
		{http.MethodPost, "/auth/saml/rotate"},
		{http.MethodGet, "/auth/saml/reset"},
		{http.MethodPost, "/auth/saml/reset"},
	}
	for _, probe := range probes {
		req := httptest.NewRequestWithContext(t.Context(), probe.method, probe.path, strings.NewReader(hostileBody))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code,
			"%s %s: trust-management probe must not execute; body %s", probe.method, probe.path, rec.Body.String())
		require.Empty(t, rec.Header().Values("Set-Cookie"), "%s %s must not mint cookies", probe.method, probe.path)
		require.NotContains(t, rec.Body.String(), "HOSTILE-TRUST-SWAP", "refusal must not echo the payload")
	}

	require.Equal(t, samlNormalizeMetadata(metaBefore), samlNormalizeMetadata(samlRouterGet(t, router, "/auth/saml/metadata")),
		"probes must leave the served SP metadata byte-identical (modulo crewjam's moving validUntil)")

	w, _ := happySAMLFlow(t, h, p)
	require.Equal(t, http.StatusFound, w.Code, "real login must still work after the probes")
}

// TestSAMLRights_SSOStartBudgetEnforcedThroughRouter proves the per-IP
// sso-start budget is live on the mounted production router: exactly
// ssoStartLimit redirects per IP, then 429, while a second IP is unaffected.
func TestSAMLRights_SSOStartBudgetEnforcedThroughRouter(t *testing.T) {
	_, _, router := samlInvariantsRouter(t)

	const firstIP = "198.51.100.23:5555"
	for i := 1; i <= ssoStartLimit; i++ {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/login", nil)
		req.RemoteAddr = firstIP
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code, "request %d within budget: body %s", i, rec.Body.String())
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/login", nil)
	req.RemoteAddr = firstIP
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Contains(t, rec.Body.String(), "too many login attempts")

	other := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/login", nil)
	other.RemoteAddr = "198.51.100.99:5555"
	recOther := httptest.NewRecorder()
	router.ServeHTTP(recOther, other)
	require.Equal(t, http.StatusFound, recOther.Code, "a second IP must keep its own budget")
}

// ---- data protection ----------------------------------------------------------

// syncBuffer is a concurrency-safe io.Writer for the JSON log handler.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// samlCaptureLogs swaps the handlers logger for a captured one.
func samlCaptureLogs(h *testAdminHandlers) *syncBuffer {
	buf := &syncBuffer{}
	h.logger = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return buf
}

// TestSAMLData_HostileRefusalsLeakNoResponseMaterial drives signature
// failure, malformed XML and oversized junk through the ACS and asserts that
// neither the log stream nor the HTTP bodies ever echo response material
// (marker strings, base64 payloads, XML fragments or the NameID).
func TestSAMLData_HostileRefusalsLeakNoResponseMaterial(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	logs := samlCaptureLogs(h)

	// (a) A real response whose bytes are tampered with: signature
	// verification must fail and the injected marker must vanish.
	redirect, flowCookie := startSAMLFlow(t, h)
	realResponse := p.idpRespond(t, redirect)
	raw, err := base64.StdEncoding.DecodeString(realResponse)
	require.NoError(t, err)
	// Modify a SIGNED assertion value (comments would be stripped by
	// exc-c14n and would keep the signature valid): the digest must break,
	// verification must refuse, and the injected NameID-like material must
	// vanish. Known bounded exception, pinned here by documentation: for a
	// non-Success status crewjam surfaces the IdP-SIGNED StatusCode string
	// verbatim in its private error, which the refusal log carries — signed
	// IdP diagnostics, never unsigned assertion content.
	tampered := strings.Replace(string(raw),
		"<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"",
		"<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" HOSTILE-RESPONSE-MARKER=\"1\"", 1)
	require.NotEqual(t, string(raw), tampered, "marker injection must change the payload")
	wTampered := runACS(t, h, base64.StdEncoding.EncodeToString([]byte(tampered)), flowCookie)
	require.Equal(t, http.StatusUnauthorized, wTampered.Code)
	require.Equal(t, "sso login failed", strings.TrimSpace(wTampered.Body.String()))

	// (b) Truncated hostile XML: parse must fail with a generic refusal.
	redirect2, flowCookie2 := startSAMLFlow(t, h)
	_ = p.idpRespond(t, redirect2)
	wMalformed := runACS(t, h,
		base64.StdEncoding.EncodeToString([]byte("<samlp:Response HOSTILE-RESPONSE-MARKER")), flowCookie2)
	require.Equal(t, http.StatusUnauthorized, wMalformed.Code)
	require.Equal(t, "sso login failed", strings.TrimSpace(wMalformed.Body.String()))

	// (c) Oversized base64 junk (still under the router body ceiling so the
	// handler itself refuses it).
	_, flowCookie3 := startSAMLFlow(t, h)
	junk := strings.Repeat("A", 700_000)
	wJunk := runACS(t, h, junk, flowCookie3)
	require.Equal(t, http.StatusUnauthorized, wJunk.Code)

	captured := logs.String()
	require.Contains(t, captured, "saml acs: verification failed", "refusals must be logged at all")
	for _, forbidden := range []string{
		"HOSTILE-RESPONSE-MARKER",
		"<saml",
		"PRIVATE KEY",
		"root@test.io",
		"AAAAAAA", // oversized junk
	} {
		require.NotContains(t, captured, forbidden, "response material leaked into logs")
	}
	for _, resp := range []string{realResponse} {
		require.NotContains(t, captured, resp[:64], "base64 response material leaked into logs")
	}
}

// TestSAMLData_ReplayRefusalLogsOnlyHashedAssertionID extends the
// masked-attribution precedent: the replay refusal log line carries a
// non-reversible hash, never the raw assertion ID of the captured response.
func TestSAMLData_ReplayRefusalLogsOnlyHashedAssertionID(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	logs := samlCaptureLogs(h)

	redirect, flowCookie := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)
	first := runACS(t, h, resp, flowCookie)
	require.Equal(t, http.StatusFound, first.Code)

	second := runACS(t, h, resp, flowCookie)
	require.Equal(t, http.StatusUnauthorized, second.Code)
	require.Equal(t, "sso login failed", strings.TrimSpace(second.Body.String()))

	raw, err := base64.StdEncoding.DecodeString(resp)
	require.NoError(t, err)
	captured := logs.String()
	require.Contains(t, captured, "assertion replay refused", "replay refusal must be logged")
	require.Contains(t, captured, "assertion_id_hash", "the log must carry the hash attribute")
	idRe := regexp.MustCompile(`\bID="([^"]+)"`)
	ids := idRe.FindAllStringSubmatch(string(raw), -1)
	require.NotEmpty(t, ids, "fixture must contain assertion/response IDs")
	for _, m := range ids {
		require.NotContains(t, captured, m[1], "raw ID %q leaked into logs", m[1])
	}
}

// TestSAMLData_AuditRowCarriesOnlyPermittedFields pins the audit contract of
// a successful SAML login with a hostile role attribute: the asserted role is
// recorded verbatim (informational, IdP-signed, documented), while the
// NameID, response payload and XML fragments never enter the details.
func TestSAMLData_AuditRowCarriesOnlyPermittedFields(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	hostileRole := "viewer\"\n<not-a-role>"
	p.attrs = []saml.Attribute{{
		Name:       "role",
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []saml.AttributeValue{{
			Type:  "xs:string",
			Value: hostileRole,
		}},
	}}

	w, resp := happySAMLFlow(t, h, p)
	require.Equal(t, http.StatusFound, w.Code, "an unmapped informational role must not block login")

	h.store.auditMu.Lock()
	entries := append([]adminstore.AuditLogEntryRecord(nil), h.store.auditRecords...)
	h.store.auditMu.Unlock()
	var logins []adminstore.AuditLogEntryRecord
	for _, e := range entries {
		if e.Action == "login" {
			logins = append(logins, e)
		}
	}
	require.Len(t, logins, 1, "exactly one login audit row")
	details := logins[0].Details
	require.Contains(t, details, "sso=saml", "details: %q", details)
	require.Contains(t, details, "user=u-1", "details: %q", details)
	require.Contains(t, details, "asserted_role="+hostileRole, "documented informational contract")

	for _, forbidden := range []string{
		"root@test.io",
		"<saml",
		"PRIVATE KEY",
		"SESSION",
	} {
		require.NotContains(t, details, forbidden, "assertion material leaked into audit details")
	}
	require.NotContains(t, details, resp[:64], "base64 response material leaked into audit details")
}

// TestSAMLData_CookieAttributeParity pins the security attributes of every
// cookie the SAML flow can mint or clear: the flow cookie, the admin session
// issued by the ACS, the post-failure state and the SLO clears.
func TestSAMLData_CookieAttributeParity(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	// Flow cookie issued by the login start.
	wStart := httptest.NewRecorder()
	h.SAMLLogin()(wStart, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/login", nil))
	require.Equal(t, http.StatusFound, wStart.Code)
	var flow *http.Cookie
	for _, c := range wStart.Result().Cookies() {
		if c.Name == adminauth.SAMLFlowCookieName {
			flow = c
		}
	}
	require.NotNil(t, flow, "login start must issue the flow cookie")
	require.True(t, flow.HttpOnly, "flow cookie flags: %+v", flow)
	require.True(t, flow.Secure, "flow cookie flags: %+v", flow)
	require.Equal(t, http.SameSiteLaxMode, flow.SameSite, "flow cookie flags: %+v", flow)
	require.Equal(t, "/auth/saml", flow.Path, "flow cookie flags: %+v", flow)
	require.Equal(t, 600, flow.MaxAge, "flow cookie flags: %+v", flow)

	// Successful ACS: session issued with hardened flags, flow expired.
	redirect, flowValue := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)
	wACS := runACS(t, h, resp, flowValue)
	require.Equal(t, http.StatusFound, wACS.Code)
	var session, flowCleared *http.Cookie
	for _, c := range wACS.Result().Cookies() {
		switch c.Name {
		case "yabanin_admin_session":
			session = c
		case adminauth.SAMLFlowCookieName:
			flowCleared = c
		}
	}
	require.NotNil(t, session, "successful acs must mint the session cookie")
	require.True(t, session.HttpOnly, "session cookie flags: %+v", session)
	require.True(t, session.Secure, "session cookie flags: %+v", session)
	require.Equal(t, http.SameSiteStrictMode, session.SameSite, "session cookie flags: %+v", session)
	require.Equal(t, "/", session.Path, "session cookie flags: %+v", session)
	require.Positive(t, session.MaxAge, "session cookie flags: %+v", session)
	require.NotNil(t, flowCleared, "acs must expire the flow cookie")
	require.Negative(t, flowCleared.MaxAge, "cleared flow cookie: %+v", flowCleared)
	require.True(t, flowCleared.HttpOnly && flowCleared.Secure, "cleared flow cookie: %+v", flowCleared)
	require.Equal(t, http.SameSiteLaxMode, flowCleared.SameSite, "cleared flow cookie: %+v", flowCleared)

	// Failed ACS: no session, flow expired.
	redirectBad, flowBad := startSAMLFlow(t, h)
	_ = p.idpRespond(t, redirectBad)
	wFail := runACS(t, h, base64.StdEncoding.EncodeToString([]byte("not-xml")), flowBad)
	require.Equal(t, http.StatusUnauthorized, wFail.Code)
	for _, c := range wFail.Result().Cookies() {
		require.NotEqual(t, "yabanin_admin_session", c.Name, "failed acs must not mint a session")
		if c.Name == adminauth.SAMLFlowCookieName {
			require.Negative(t, c.MaxAge, "failed acs must expire the flow cookie: %+v", c)
		}
	}

	// SLO: session and csrf both expired with hardened flags.
	wSLO := httptest.NewRecorder()
	sloReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/slo", nil)
	sloReq.AddCookie(&http.Cookie{Name: "yabanin_admin_session", Value: "stale",
		Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	sloReq.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "stale",
		Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	h.SAMLSLO()(wSLO, sloReq)
	require.Equal(t, http.StatusFound, wSLO.Code)
	var sloSession, sloCSRF *http.Cookie
	for _, c := range wSLO.Result().Cookies() {
		switch c.Name {
		case "yabanin_admin_session":
			sloSession = c
		case "yabanin_csrf_token":
			sloCSRF = c
		}
	}
	require.NotNil(t, sloSession, "slo must expire the session cookie")
	require.NotNil(t, sloCSRF, "slo must expire the csrf cookie")
	for _, c := range []*http.Cookie{sloSession, sloCSRF} {
		require.Negative(t, c.MaxAge, "slo clear cookie: %+v", c)
		require.True(t, c.HttpOnly, "slo clear cookie: %+v", c)
		require.True(t, c.Secure, "slo clear cookie: %+v", c)
	}
}

// TestSAMLData_ServedSPMetadataPublishesNoIdPTrustMaterial: the metadata
// endpoint publishes the SP's own public certificate (public by design) and
// must never carry the IdP certificate, PEM wrappers or the IdP subject.
func TestSAMLData_ServedSPMetadataPublishesNoIdPTrustMaterial(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	router := h.SetupRouter()

	body := samlRouterGet(t, router, "/auth/saml/metadata")

	spKey, spCert := samlTestSPIdentity(t)
	_ = spKey
	require.Contains(t, body, base64.StdEncoding.EncodeToString(spCert.Raw),
		"the SP's own public certificate is part of its published metadata")

	idpCert := base64.StdEncoding.EncodeToString(p.idp.Certificate.Raw)
	for _, forbidden := range []string{
		idpCert,
		"-----BEGIN",
		"idp.test",
		"PRIVATE KEY",
	} {
		require.NotContains(t, body, forbidden, "IdP trust material leaked into served SP metadata")
	}
}

// ---- negative: wrapping and unsigned assertions --------------------------------

// samlDecodeResponseForm base64-decodes a captured SAMLResponse form value.
func samlDecodeResponseForm(t *testing.T, resp string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(resp)
	require.NoError(t, err)
	return string(raw)
}

var (
	samlAssertionRe = regexp.MustCompile(`<saml:Assertion\b.*</saml:Assertion>`)
	samlSignatureRe = regexp.MustCompile(`<ds:Signature\b.*?</ds:Signature>`)
	samlAssertIDRe  = regexp.MustCompile(`\bID="[^"]+"`)
)

// samlHostileWrap builds the classic XML-signature wrapping payload: an
// attacker-forged copy of the real assertion (re-IDed, signature stripped,
// NameID left at the privilege target) injected into the response envelope.
func samlHostileWrap(t *testing.T, resp, hostileID string) string {
	t.Helper()
	doc := samlDecodeResponseForm(t, resp)

	m := samlAssertionRe.FindString(doc)
	require.NotEmpty(t, m, "fixture must contain an assertion to wrap")
	hostile := m
	require.Len(t, samlAssertIDRe.FindAllString(hostile, -1), 1,
		"assertion copy must carry exactly one ID attribute")
	hostile = samlAssertIDRe.ReplaceAllLiteralString(hostile, `ID="`+hostileID+`"`)
	require.Len(t, samlSignatureRe.FindAllString(hostile, -1), 1,
		"assertion copy must carry exactly one signature to strip")
	hostile = samlSignatureRe.ReplaceAllString(hostile, "")

	require.Contains(t, doc, "</samlp:Response>")
	doc = strings.Replace(doc, "</samlp:Response>", hostile+"</samlp:Response>", 1)
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

// samlStripSignatureLayers removes the first n XML signatures from the
// captured response document (1 = the Response-level envelope signature,
// leaving the assertion's own signature as the anchor; 2 = fully unsigned).
func samlStripSignatureLayers(t *testing.T, resp string, layers int) string {
	t.Helper()
	doc := samlDecodeResponseForm(t, resp)
	for i := 0; i < layers; i++ {
		loc := samlSignatureRe.FindStringIndex(doc)
		require.NotEmpty(t, loc, "fixture must carry at least %d signature layers", i+1)
		doc = doc[:loc[0]] + doc[loc[1]:]
	}
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

// samlAssertNoSession requires that the recorder minted no admin session.
func samlAssertNoSession(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		require.NotEqual(t, "yabanin_admin_session", c.Name,
			"refused assertion must not mint a session cookie")
	}
}

// TestSAMLNegative_WrappedAndUnsignedYieldNoSession is the card's negative:
// signature-wrapping and unsigned assertions never yield a session, and a
// wrapping replay after redemption yields nothing. Every cell pins the
// refusal layer through the log marker and re-proves with an honest control
// that the refusal came from the document, not from a wedged SP.
func TestSAMLNegative_WrappedAndUnsignedYieldNoSession(t *testing.T) {
	t.Run("wrapped_extra_assertion_breaks_document_signature", func(t *testing.T) {
		p := newFakeSAMLIdP(t)
		h, _ := newSAMLTestHandlers(t, p)
		logs := samlCaptureLogs(h)

		redirect, flowCookie := startSAMLFlow(t, h)
		resp := p.idpRespond(t, redirect)
		wrapped := samlHostileWrap(t, resp, "_wrapped-hostile-1")

		w := runACS(t, h, wrapped, flowCookie)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, "sso login failed", strings.TrimSpace(w.Body.String()))
		samlAssertNoSession(t, w)
		require.Zero(t, samlAuditLoginCount(h), "a wrapped assertion must not write an audit row")
		require.Contains(t, logs.String(), "saml acs: verification failed",
			"the envelope signature (which covered the original bytes only) must be the refusing layer")

		// Positive control: the honest pair is unharmed — the wrap refusal
		// was about the tampered document, not a poisoned flow or SP.
		wOK := runACS(t, h, resp, flowCookie)
		require.Equal(t, http.StatusFound, wOK.Code)
		samlAudit := samlAuditLoginCount(h)
		require.Equal(t, 1, samlAudit, "exactly the honest control login lands")
	})

	t.Run("unsigned_assertion_refused_signed_anchor_still_works", func(t *testing.T) {
		p := newFakeSAMLIdP(t)
		h, _ := newSAMLTestHandlers(t, p)
		logs := samlCaptureLogs(h)

		redirect, flowCookie := startSAMLFlow(t, h)
		resp := p.idpRespond(t, redirect)

		// Fully unsigned document (envelope AND assertion signatures
		// stripped): crewjam demands a signature on one of the two — the
		// bare assertion is refused, no session, no audit row.
		unsigned := samlStripSignatureLayers(t, resp, 2)
		wUnsigned := runACS(t, h, unsigned, flowCookie)
		require.Equal(t, http.StatusUnauthorized, wUnsigned.Code)
		require.Equal(t, "sso login failed", strings.TrimSpace(wUnsigned.Body.String()))
		samlAssertNoSession(t, wUnsigned)
		require.Zero(t, samlAuditLoginCount(h))
		require.Contains(t, logs.String(), "saml acs: verification failed")

		// Anchor contract (mock twin of the live boundary cell): with only
		// the envelope signature stripped, the assertion's own IdP signature
		// is a sufficient anchor — the same flow completes. The refusal
		// above therefore came from the missing signature, nothing else.
		anchorOnly := samlStripSignatureLayers(t, resp, 1)
		wAnchor := runACS(t, h, anchorOnly, flowCookie)
		require.Equal(t, http.StatusFound, wAnchor.Code,
			"a signed assertion must remain a sufficient signature anchor")
		require.Equal(t, 1, samlAuditLoginCount(h))
	})

	t.Run("wrapping_replay_after_redemption_yields_nothing", func(t *testing.T) {
		p := newFakeSAMLIdP(t)
		h, _ := newSAMLTestHandlers(t, p)
		logs := samlCaptureLogs(h)

		redirect, flowCookie := startSAMLFlow(t, h)
		resp := p.idpRespond(t, redirect)

		wHonest := runACS(t, h, resp, flowCookie)
		require.Equal(t, http.StatusFound, wHonest.Code)
		var session string
		for _, c := range wHonest.Result().Cookies() {
			if c.Name == "yabanin_admin_session" && c.Value != "" {
				session = c.Value
			}
		}
		require.NotEmpty(t, session, "the honest redemption must mint a session")
		require.Equal(t, 1, samlAuditLoginCount(h))

		// Byte-for-byte repost of the captured pair (the capture-and-replay
		// attack): the replay guard refuses, no second session, audit flat.
		wReplay := runACS(t, h, resp, flowCookie)
		require.Equal(t, http.StatusUnauthorized, wReplay.Code)
		samlAssertNoSession(t, wReplay)
		require.Contains(t, logs.String(), "saml acs: assertion replay refused",
			"the replay guard must be the refusing layer for the verbatim repost")
		require.Equal(t, 1, samlAuditLoginCount(h))

		// Rewrapped repost: the same capture with a hostile extra assertion
		// injected. The document no longer matches the envelope signature,
		// so verification refuses before the replay guard is reached.
		wWrapped := runACS(t, h, samlHostileWrap(t, resp, "_wrapped-hostile-2"), flowCookie)
		require.Equal(t, http.StatusUnauthorized, wWrapped.Code)
		samlAssertNoSession(t, wWrapped)
		require.Contains(t, logs.String(), "saml acs: verification failed")
		require.Equal(t, 1, samlAuditLoginCount(h))

		// The one earned session keeps authenticating — refusals cost the
		// attacker nothing and the victim nothing.
		_, err := adminauth.ParseAdminSessionCookie(session, "test-secret")
		require.NoError(t, err, "the earned session must remain verifiable")
	})
}
