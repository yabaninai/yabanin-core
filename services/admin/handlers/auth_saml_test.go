package handlers

// the fake IdP serves its metadata, answers the redirect-bound AuthnRequest
// and returns signed, encrypted-free SAML responses the way production IdPs
// do. The SP side runs the full crewjam verification (signature against the
// IdP metadata, issuer, audience, recipient, timestamps, InResponseTo), so
// the failure matrix below exercises the real trust boundary, not stubs.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fake SAML IdP ----------------------------------------------------------

// Shared 2048-bit test identities. RSA keygen is the dominant SAML test cost
// (hundreds of ms to seconds each under -race + coverage), and the full
// handlers suite runs close to the default 10-minute go-test timeout — so
// every SAML test reuses one IdP identity, one mismatch-signing identity and
// one SP identity instead of burning fresh keys. The keys are signing
// material only: each test still builds its own IdP instance, SP instance,
// flow and assertions, so no test observes another test's state.
var (
	// samlTestIdentityOnce guards the shared test identities. There MUST be
	// exactly one Once for all accessors: a per-accessor Once would re-run
	// samlTestInitIdentities once per accessor, silently regenerating every
	// key/cert and leaving earlier holders (the fake IdP struct) with stale
	// generation-1 objects while callers read generation-2 globals — the
	// recovery corpus caught exactly that when "restore the original
	// signing identity" restored the wrong generation.
	samlTestIdentityOnce sync.Once
	samlTestIDPKey       *rsa.PrivateKey
	samlTestIDPCert      *x509.Certificate
	samlTestAltKey       *rsa.PrivateKey
	samlTestAltCert      *x509.Certificate
	samlTestThirdKey     *rsa.PrivateKey
	samlTestThirdCert    *x509.Certificate
	samlTestSPKey        *rsa.PrivateKey
	samlTestSPCert       *x509.Certificate
	samlTestIdentityErr  error
)

func samlTestIDPIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	samlTestIdentityOnce.Do(samlTestInitIdentities)
	if samlTestIdentityErr != nil {
		t.Fatalf("saml test identities: %v", samlTestIdentityErr)
	}
	return samlTestIDPKey, samlTestIDPCert
}

// samlTestAltIdentity is a second key for the bad-signature scenario: the IdP
// publishes the honest certificate but signs with this one.
func samlTestAltIdentity(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	samlTestIdentityOnce.Do(samlTestInitIdentities)
	if samlTestIdentityErr != nil {
		t.Fatalf("saml test identities: %v", samlTestIdentityErr)
	}
	return samlTestAltKey
}

func samlTestAltCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	samlTestIdentityOnce.Do(samlTestInitIdentities)
	if samlTestIdentityErr != nil {
		t.Fatalf("saml test identities: %v", samlTestIdentityErr)
	}
	return samlTestAltCert
}

// samlTestThirdIdentity is a third-party signing pair that NO IdP metadata in
// these tests ever publishes: it stands in for an unrelated signer trying to
// slip an assertion past the dual-trust window.
func samlTestThirdIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	samlTestIdentityOnce.Do(samlTestInitIdentities)
	if samlTestIdentityErr != nil {
		t.Fatalf("saml test identities: %v", samlTestIdentityErr)
	}
	return samlTestThirdKey, samlTestThirdCert
}

func samlTestSPIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	samlTestIdentityOnce.Do(samlTestInitIdentities)
	if samlTestIdentityErr != nil {
		t.Fatalf("saml test identities: %v", samlTestIdentityErr)
	}
	return samlTestSPKey, samlTestSPCert
}

func samlTestInitIdentities() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		samlTestIdentityErr = fmt.Errorf("idp keygen: %w", err)
		return
	}
	samlTestIDPKey = key
	samlTestIDPCert = mustTestCert(key, "idp.test")

	alt, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		samlTestIdentityErr = fmt.Errorf("alt keygen: %w", err)
		return
	}
	samlTestAltKey = alt
	samlTestAltCert = mustTestCert(alt, "idp-alt.test")

	third, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		samlTestIdentityErr = fmt.Errorf("third-party keygen: %w", err)
		return
	}
	samlTestThirdKey = third
	samlTestThirdCert = mustTestCert(third, "thirdparty.test")

	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		samlTestIdentityErr = fmt.Errorf("sp keygen: %w", err)
		return
	}
	samlTestSPKey = spKey
	samlTestSPCert = mustTestCert(spKey, "sp.test")
}

type fakeSAMLIdP struct {
	mu sync.Mutex

	server *httptest.Server
	idp    *saml.IdentityProvider

	// Per-test knobs.
	email       string
	nameIDCodec string           // NameID format (default: emailAddress)
	attrs       []saml.Attribute // CustomAttributes copied into the assertion
	clockShift  time.Duration    // shifts the IdP clock (positive = past)
	// signKeyMismatch makes the IdP sign with a key other than the one its
	// metadata publishes.
	signKeyMismatch bool
	// signWithThirdKey makes the IdP sign responses with an unrelated
	// third-party pair whose certificate no metadata ever publishes (the
	// third-party rejection scenario inside the dual-trust window).
	signWithThirdKey bool
	// scenarios).
	metadataFail bool
	dualCerts    bool
}

func newFakeSAMLIdP(t *testing.T) *fakeSAMLIdP {
	t.Helper()
	key, cert := samlTestIDPIdentity(t)
	p := &fakeSAMLIdP{
		email:       "root@test.io",
		nameIDCodec: string(saml.EmailAddressNameIDFormat),
	}
	p.idp = &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		Logger:      testSAMLLogger{},
	}
	mux := http.NewServeMux()
	mux.Handle("/sso", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		// The IdP clock shift (expired-assertion scenario) applies only
		// while the IdP mints the response; the SP validates with real time.
		// The package-level saml.TimeNow is touched ONLY while a shift is
		// active: shift-free tests (including the concurrent recovery
		// corpus) must not race the crewjam SP's own reads of that global.
		if p.clockShift != 0 {
			defer func(prev func() time.Time) { saml.TimeNow = prev }(saml.TimeNow)
			saml.TimeNow = func() time.Time { return time.Now().Add(-p.clockShift) }
		}
		if p.signWithThirdKey {
			key, cert := samlTestThirdIdentity(t)
			p.idp.Key = key
			p.idp.Certificate = cert
		}
		p.idp.ServeSSO(w, r)
	}))
	mux.Handle("/metadata", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.metadataFail {
			http.Error(w, "metadata unavailable", http.StatusInternalServerError)
			return
		}
		base := url.URL{Scheme: "http", Host: r.Host}
		p.idp.MetadataURL = *base.ResolveReference(&url.URL{Path: "/metadata"})
		p.idp.SSOURL = *base.ResolveReference(&url.URL{Path: "/sso"})
		p.idp.LoginURL = *base.ResolveReference(&url.URL{Path: "/login"})
		p.idp.LogoutURL = *base.ResolveReference(&url.URL{Path: "/logout"})
		if p.signKeyMismatch {
			// Publish the honest certificate but sign with a different key.
			p.idp.Key = samlTestAltIdentity(t)
		}
		if !p.dualCerts {
			p.idp.ServeMetadata(w, r)
			return
		}
		metadata := p.idp.Metadata()
		alternateCert := samlTestAltCertificate(t)
		certData := base64.StdEncoding.EncodeToString(alternateCert.Raw)
		metadata.IDPSSODescriptors[0].KeyDescriptors = append(metadata.IDPSSODescriptors[0].KeyDescriptors,
			saml.KeyDescriptor{
				Use:     "signing",
				KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: certData}}}},
			},
		)
		body, err := xml.Marshal(metadata)
		if err != nil {
			http.Error(w, "metadata encoding failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(body)
	}))
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// registerSP points the IdP at a service provider: spEntity "" keeps the SP's
// real metadata (happy path); any other value becomes the asserted audience.
func (p *fakeSAMLIdP) registerSP(t *testing.T, sp *adminauth.SAMLSP, spEntity string) {
	t.Helper()
	p.idp.ServiceProviderProvider = serviceProviderFunc(func(r *http.Request, id string) (*saml.EntityDescriptor, error) {
		meta := sp.SPMetadata()
		if spEntity != "" {
			meta.EntityID = spEntity
		}
		return meta, nil
	})
	p.idp.SessionProvider = sessionFunc(func(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
		return &saml.Session{
			ID:               "s1",
			CreateTime:       saml.TimeNow(),
			ExpireTime:       saml.TimeNow().Add(time.Hour),
			Index:            "idx-1",
			NameID:           p.email,
			NameIDFormat:     p.nameIDCodec,
			CustomAttributes: p.attrs,
		}
	})
}

type serviceProviderFunc func(r *http.Request, id string) (*saml.EntityDescriptor, error)

// cert-rollover scenario): subsequent responses are signed with the new key
// and /metadata publishes the new certificate. Reuses the shared alternate
// test identity so no extra RSA keygen burns suite time.
func (p *fakeSAMLIdP) rotateSigningIdentity(t *testing.T) {
	t.Helper()
	alt := samlTestAltIdentity(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idp.Key = alt
	p.idp.Certificate = mustTestCert(alt, "idp-rotated.test")
}

func (p *fakeSAMLIdP) restoreOriginalSigningIdentity(t *testing.T) {
	t.Helper()
	key, cert := samlTestIDPIdentity(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idp.Key = key
	p.idp.Certificate = cert
}

// useAlternatePublishedIdentity flips the IdP to the alternate signing pair
// carrying EXACTLY the alternate certificate the dual-trust metadata
// publishes — trust matching is byte-exact against the presented cert, so
// the window scenario must sign with the published cert itself (not merely
// the same key under a freshly minted certificate).
func (p *fakeSAMLIdP) useAlternatePublishedIdentity(t *testing.T) {
	t.Helper()
	key := samlTestAltIdentity(t)
	cert := samlTestAltCertificate(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idp.Key = key
	p.idp.Certificate = cert
}

func (p *fakeSAMLIdP) setMetadataFail(fail bool) {
	p.mu.Lock()
	p.metadataFail = fail
	p.mu.Unlock()
}

func (f serviceProviderFunc) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	return f(r, id)
}

type sessionFunc func(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session

func (f sessionFunc) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	return f(w, r, req)
}

// testSAMLLogger silences the fake IdP's log output.
type testSAMLLogger struct{}

func (testSAMLLogger) Printf(format string, v ...any) {}
func (testSAMLLogger) Print(v ...any)                 {}
func (testSAMLLogger) Println(v ...any)               {}
func (testSAMLLogger) Fatal(v ...any)                 {}
func (testSAMLLogger) Fatalf(format string, v ...any) {}
func (testSAMLLogger) Fatalln(v ...any)               {}
func (testSAMLLogger) Panic(v ...any)                 {}
func (testSAMLLogger) Panicf(format string, v ...any) {}
func (testSAMLLogger) Panicln(v ...any)               {}

var samlResponseRe = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

// samlFormActionRe extracts the auto-submit form's action (the ACS URL the
// SP metadata advertised to the IdP).
var samlFormActionRe = regexp.MustCompile(`action="([^"]+)"`)

// ---- harness ----------------------------------------------------------------

// newSAMLTestHandlers wires handlers + mock store + SP bound to the fake IdP.
func newSAMLTestHandlers(t *testing.T, p *fakeSAMLIdP) (*testAdminHandlers, *adminauth.SAMLSP) {
	t.Helper()
	store := newMockStore()
	store.adminUsers["u-1"] = &adminstore.AdminUser{
		ID: "u-1", Email: "root@test.io", DisplayName: "Root", IsRoot: true, Active: true,
	}
	h := &testAdminHandlers{
		AdminHandlers: New(store, "test-secret", "admin.test", []string{}),
		store:         store,
	}
	spKey, spCert := samlTestSPIdentity(t)
	sp, err := adminauth.NewSAMLSP(context.Background(), adminauth.SAMLOptions{
		IDPMetadataURL: p.server.URL + "/metadata",
		ACSURL:         "https://admin.test/auth/saml/acs",
		RoleAttribute:  "role",
		HTTPClient:     p.server.Client(),
		Key:            spKey,
		Certificate:    spCert,
	})
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	h.SetSAMLSP(sp)
	p.registerSP(t, sp, "")
	return h, sp
}

// startSAMLFlow drives GET /auth/saml/login and returns the IdP redirect URL
// and the flow cookie it issued (the request ID inside is the InResponseTo
// the IdP must echo).
func startSAMLFlow(t *testing.T, h *testAdminHandlers) (string, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.SAMLLogin()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("saml login: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	redirect := w.Header().Get("Location")
	if !strings.HasPrefix(redirect, "http") {
		t.Fatalf("saml login: redirect to IdP expected, got %q", redirect)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == adminauth.SAMLFlowCookieName {
			return redirect, c.Value
		}
	}
	t.Fatal("saml login: no flow cookie set")
	return "", ""
}

// idpRespond follows the AuthnRequest redirect at the fake IdP and returns
// the SAMLResponse form value the IdP posted back.
func (p *fakeSAMLIdP) idpRespond(t *testing.T, loginRedirect string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginRedirect, nil)
	if err != nil {
		t.Fatalf("idp request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("idp respond: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("idp respond: got %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	m := samlResponseRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("idp response carries no SAMLResponse: %s", body)
	}
	// The auto-post form is html/template-rendered: attribute values carry
	// entities (&#43; for '+'), unescape before base64.
	return html.UnescapeString(m[1])
}

// runACS drives POST /auth/saml/acs with the given response and flow cookie.
func runACS(t *testing.T, h *testAdminHandlers, samlResponse, flowCookie string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:1234"
	if flowCookie != "" {
		req.AddCookie(&http.Cookie{
			Name: adminauth.SAMLFlowCookieName, Value: flowCookie,
			Path: "/auth/saml", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	w := httptest.NewRecorder()
	h.SAMLACS()(w, req)
	return w
}

// happySAMLFlow performs login → IdP → ACS and returns the ACS recorder.
func happySAMLFlow(t *testing.T, h *testAdminHandlers, p *fakeSAMLIdP) (*httptest.ResponseRecorder, string) {
	t.Helper()
	redirect, flowCookie := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)
	return runACS(t, h, resp, flowCookie), resp
}

// ---- tests ------------------------------------------------------------------

func TestSAML_FullFlow_IssuesSessionAndAudit(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("acs: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("acs redirect: got %q, want %q", loc, "/")
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
		if c.Name == adminauth.SAMLFlowCookieName && c.MaxAge >= 0 {
			t.Fatal("flow cookie must be cleared on success")
		}
	}
	if session == nil {
		t.Fatal("acs: no session cookie issued")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	if sess.Email != "root@test.io" || !sess.IsRoot {
		t.Fatalf("session identity: got %+v", sess)
	}

	// Login audit trail (mockStore implements the durable journal).
	store := h.store
	store.auditMu.Lock()
	entries := append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
	store.auditMu.Unlock()
	if len(entries) != 1 {
		t.Fatalf("audit entries: got %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "login" || e.Resource != "admin_user" {
		t.Fatalf("audit action/resource: %q/%q", e.Action, e.Resource)
	}
	if !strings.Contains(e.Details, "sso=saml") {
		t.Fatalf("audit details missing sso marker: %q", e.Details)
	}
	if strings.Contains(e.Details, "root@test.io") {
		t.Fatal("audit details must not carry the raw email")
	}
	if !strings.Contains(e.Details, "user=u-1") {
		t.Fatalf("audit details must attribute the mapped user: %q", e.Details)
	}
}

func TestSAML_AssertedRoleRecordedInAudit(t *testing.T) {
	p := newFakeSAMLIdP(t)
	p.attrs = []saml.Attribute{{FriendlyName: "role", Name: "role", Values: []saml.AttributeValue{{Value: "admin"}}}}
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("acs: got %d", w.Code)
	}
	store := h.store
	store.auditMu.Lock()
	records := append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
	store.auditMu.Unlock()
	if len(records) != 1 || !strings.Contains(records[0].Details, "asserted_role=admin") {
		t.Fatalf("asserted role not audited: %+v", records)
	}
}

// W-SECADM parity: the SAML session carries the shared adminauth
// SessionDuration, same as the password and OIDC flows.
func TestSAML_SessionUsesConfiguredDuration(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
	if err != nil {
		t.Fatalf("session cookie: %v", err)
	}
	lifetime := time.Until(sess.ExpiresAt)
	if lifetime < adminauth.SessionDuration-time.Minute || lifetime > adminauth.SessionDuration+time.Minute {
		t.Fatalf("session lifetime %s, want ~%s", lifetime, adminauth.SessionDuration)
	}
}

// Regression for the N04-P01 T09 finding: the SAML ACS must stamp IssuedAt
// like the OIDC callback and password login. A session minted WITHOUT an
// issued-at parses back as the legacy zero marker, and sessionInvalidated
// rejects zero-issued-at sessions once ANY password change/SCIM transition
// has written the sessions_changed_at watermark — locking SAML users out
// until they re-login through another flow. A fresh SAML login AFTER a
// password change must be accepted by the guarded middleware (watermark
// predates the session), while a session issued BEFORE the watermark must
// stay rejected: the stamp never whitewashes pre-change sessions.
func TestSAML_SessionCarriesIssuedAt_WatermarkParity(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("acs: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("acs: no session cookie issued")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	if sess.IssuedAt.IsZero() {
		t.Fatal("SAML session must carry the issued-at watermark field used by password-change invalidation")
	}

	// Watermark recorded BEFORE this SAML login (e.g. an earlier password
	// change or SCIM deactivation/reactivation): the fresh assertion-built
	// session postdates it, so the guarded middleware must accept it.
	watermark := sess.IssuedAt.Add(-time.Minute)
	guard := adminauth.ChiAuthMiddlewareGuarded("test-secret", func(context.Context, string) (time.Time, error) {
		return watermark, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.AddCookie(session)
	fresh := httptest.NewRecorder()
	guard.ServeHTTP(fresh, req)
	if fresh.Code != http.StatusOK {
		t.Fatalf("fresh SAML session issued after password change: got %d, want 200; body %s", fresh.Code, fresh.Body.String())
	}

	// Fail-closed control: a session issued BEFORE the watermark (held
	// across the password change) must remain rejected.
	stale := *sess
	stale.IssuedAt = watermark.Add(-time.Second)
	stale.ExpiresAt = time.Now().Add(time.Hour)
	staleCookie, err := adminauth.CreateAdminSessionCookie(stale, "test-secret")
	if err != nil {
		t.Fatalf("create pre-change session cookie: %v", err)
	}
	staleReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	staleReq.AddCookie(staleCookie)
	staleRec := httptest.NewRecorder()
	guard.ServeHTTP(staleRec, staleReq)
	if staleRec.Code != http.StatusUnauthorized {
		t.Fatalf("pre-change SAML session: got %d, want 401 (fail-closed)", staleRec.Code)
	}
}

func TestSAML_BadSignature_Rejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	p.signKeyMismatch = true
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: got %d, want 401; body %s", w.Code, w.Body.String())
	}
}

// The explicit two-certificate transition configuration (N04-P02): during a
// rollover the IdP metadata publishes BOTH signing certificates, and every
// certificate in that published set is trusted for the length of the window —
// the outgoing one, the incoming one, nothing else:
//
//	(a) the OLD certificate is accepted while the window is open;
//	(b) the NEW certificate is accepted while the window is open;
//	(c) an unrelated third-party certificate is rejected even mid-window;
//	(d) once the IdP retires the old certificate and the SP refreshes, the
//	    old certificate stops validating — the window actually closed.
func TestSAML_DualCertificateTransitionWindow(t *testing.T) {
	p := newFakeSAMLIdP(t)
	p.dualCerts = true // metadata: original cert + alternate cert, both signing
	h, sp := newSAMLTestHandlers(t, p)

	// (a) Old certificate inside the window.
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("old cert during window: got %d, want 302; body %s", w.Code, w.Body.String())
	}

	// (b) New certificate inside the window: the IdP flips to the alternate
	// signing pair WITHOUT any SP-side refresh — the second published cert
	// already carries it.
	p.useAlternatePublishedIdentity(t)
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("new cert during window: got %d, want 302; body %s", w.Code, w.Body.String())
	}

	// (c) A third-party certificate that no metadata publishes is rejected
	// even with TWO certificates in the trust set — the window never widens
	// to "any valid signature". The alternate published identity is restored
	// afterwards (the third-party knob overwrote the IdP's pair).
	p.mu.Lock()
	p.signWithThirdKey = true
	p.mu.Unlock()
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusUnauthorized {
		t.Fatalf("third-party cert during window: got %d, want 401; body %s", w.Code, w.Body.String())
	}
	p.mu.Lock()
	p.signWithThirdKey = false
	p.mu.Unlock()
	p.useAlternatePublishedIdentity(t)

	// (d) Window expiry: the IdP publishes ONLY the rotated certificate and
	// the SP refreshes successfully — the retired original certificate no
	// longer validates, without a process restart.
	p.mu.Lock()
	p.dualCerts = false
	p.mu.Unlock()
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("RefreshMetadata: %v", err)
	}
	p.restoreOriginalSigningIdentity(t)
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusUnauthorized {
		t.Fatalf("retired certificate after refresh: got %d, want 401; body %s", w.Code, w.Body.String())
	}
}

func TestSAML_MalformedResponseRejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	_, flowCookie := startSAMLFlow(t, h)
	w := runACS(t, h, "not-base64", flowCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("malformed response: got %d, want 401", w.Code)
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "yabanin_admin_session" && cookie.Value != "" {
			t.Fatal("malformed response must not issue a session")
		}
	}
}

func TestSAML_EncryptedAssertionRejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	_, flowCookie := startSAMLFlow(t, h)
	response := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:EncryptedAssertion/></samlp:Response>`))
	w := runACS(t, h, response, flowCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("encrypted assertion: got %d, want 401", w.Code)
	}
}

func TestSAML_ExpiredAssertion_Rejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	// The IdP mints the assertion 10 minutes in the past; every
	// NotOnOrAfter/IssueInstant bound fails against the real SP clock.
	p.clockShift = 10 * time.Minute
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired assertion: got %d, want 401", w.Code)
	}
}

func TestSAML_WrongAudience_Rejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)
	// Re-register the IdP against a DIFFERENT SP entity: the assertion's
	// audience restriction no longer matches our entity ID.
	p.registerSP(t, sp, "https://someone-else.test")

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience: got %d, want 401", w.Code)
	}
}

func TestSAML_Replay_Rejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	// Capture one full exchange: cookie + response pair.
	redirect, flowCookie := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)

	first := runACS(t, h, resp, flowCookie)
	if first.Code != http.StatusFound {
		t.Fatalf("first acs: got %d, want 302; body %s", first.Code, first.Body.String())
	}
	// A byte-for-byte replay of the captured POST (cookies included) must
	// be refused even though the assertion is still cryptographically
	// valid and the InResponseTo matches the captured flow.
	second := runACS(t, h, resp, flowCookie)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replayed acs: got %d, want 401", second.Code)
	}
}

func TestSAML_MissingFlowCookie_Forbidden(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	redirect, _ := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)
	w := runACS(t, h, resp, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("no flow cookie: got %d, want 403", w.Code)
	}
	garbage := runACS(t, h, resp, "!!!not-a-cookie!!!")
	if garbage.Code != http.StatusForbidden {
		t.Fatalf("garbage flow cookie: got %d, want 403", garbage.Code)
	}
}

func TestSAML_UnexpectedRelayStateRejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	redirect, flowCookie := startSAMLFlow(t, h)
	response := p.idpRespond(t, redirect)
	form := url.Values{"SAMLResponse": {response}, "RelayState": {"/admin/other"}}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name: adminauth.SAMLFlowCookieName, Value: flowCookie, Path: "/auth/saml",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	rec := httptest.NewRecorder()
	h.SAMLACS().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected RelayState: got %d, want 401", rec.Code)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "yabanin_admin_session" && cookie.Value != "" {
			t.Fatal("invalid RelayState must not issue a session")
		}
	}
}

func TestSAML_UnknownEmail_Refused_NoJIT(t *testing.T) {
	p := newFakeSAMLIdP(t)
	p.email = "intruder@evil.io"
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown email: got %d, want 403", w.Code)
	}
	// The OIDC policy is fail-closed: no account is provisioned.
	if _, err := h.store.GetAdminUserByEmailWithHash(context.Background(), "intruder@evil.io"); err == nil {
		t.Fatal("unknown email must not be provisioned by SAML")
	}
	h.store.auditMu.Lock()
	entries := len(h.store.auditRecords)
	h.store.auditMu.Unlock()
	if entries != 0 {
		t.Fatalf("refused logins must not be audited as logins, got %d entries", entries)
	}
}

func TestSAML_DisabledUser_Refused(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	h.store.adminUsers["u-1"].Active = false

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disabled user: got %d, want 403", w.Code)
	}
}

func TestSAML_TransientNameID_Rejected(t *testing.T) {
	p := newFakeSAMLIdP(t)
	p.nameIDCodec = string(saml.TransientNameIDFormat)
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("transient NameID: got %d, want 401", w.Code)
	}
}

func TestSAML_Unconfigured_404(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store) // no SetSAMLSP
	ctx := context.Background()
	for _, tc := range []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{http.MethodGet, "/auth/saml/metadata", h.SAMLMetadata()},
		{http.MethodGet, "/auth/saml/login", h.SAMLLogin()},
		{http.MethodPost, "/auth/saml/acs", h.SAMLACS()},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, tc.method, tc.path, strings.NewReader("SAMLResponse=x"))
		if tc.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		tc.handler(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unconfigured %s %s: got %d, want 404", tc.method, tc.path, w.Code)
		}
	}
}

func TestSAML_Metadata_Served(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)

	w := httptest.NewRecorder()
	h.SAMLMetadata()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/metadata", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("metadata: got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("metadata content type: %q", ct)
	}
	var doc struct {
		EntityID         string `xml:"entityID,attr"`
		SPSSODescriptors []struct {
			KeyDescriptors []struct {
				Use string `xml:"use,attr"`
			} `xml:"KeyDescriptor"`
			ACS []struct {
				Location string `xml:"Location,attr"`
			} `xml:"AssertionConsumerService"`
		} `xml:"SPSSODescriptor"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("metadata xml: %v", err)
	}
	if doc.EntityID != sp.SP.EntityID {
		t.Fatalf("metadata entity: got %q, want %q", doc.EntityID, sp.SP.EntityID)
	}
	found := false
	for _, d := range doc.SPSSODescriptors {
		for _, acs := range d.ACS {
			if acs.Location == "https://admin.test/auth/saml/acs" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("metadata must advertise the ACS endpoint")
	}
	for _, descriptor := range doc.SPSSODescriptors {
		if len(descriptor.KeyDescriptors) != 1 || descriptor.KeyDescriptors[0].Use != "signing" {
			t.Fatalf("metadata must advertise signing only, not assertion encryption: %+v", descriptor.KeyDescriptors)
		}
	}
}

func TestSAML_LoginPage_Unaffected(t *testing.T) {
	// The SAML wiring must not change the password login page (the SSO
	// link stays OIDC's; SAML users start at /auth/saml/login directly).
	store := newMockStore()
	h := newTestAdminH(store)
	w := httptest.NewRecorder()
	h.LoginPage()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))
	if strings.Contains(w.Body.String(), "saml") {
		t.Fatal("login page must not mention saml")
	}
}

// no process restart. Until the SP refreshes, the new-key response is
// refused; after the refresh it validates again; a failing metadata
// endpoint leaves the cached (new) certificate serving (fail-open).
func TestSAML_MetadataRefresh_CertRotation_ACSWithoutRestart(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)

	// Baseline: login works against the original IdP certificate.
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("baseline acs: got %d, want 302", w.Code)
	}

	// The IdP rotates its signing pair. The SP still trusts the old
	// certificate, so the new-key response must be refused (401).
	p.rotateSigningIdentity(t)
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusUnauthorized {
		t.Fatalf("post-rotation acs before refresh: got %d, want 401", w.Code)
	}

	// RefreshMetadata swaps in the rotated certificate: login works again
	// without any restart.
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("RefreshMetadata: %v", err)
	}
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("post-refresh acs: got %d, want 302", w.Code)
	}

	// Fail-open: a failing metadata endpoint errors and the cached rotated
	// certificate keeps serving.
	p.setMetadataFail(true)
	if err := sp.RefreshMetadata(context.Background()); err == nil {
		t.Fatal("refresh against a failing endpoint must error")
	}
	p.setMetadataFail(false)
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("post-failed-refresh acs: got %d, want 302 (cached metadata)", w.Code)
	}
}

// cookies expire) and redirects to the login page — for the Redirect and the
// POST binding IdPs may use. Unconfigured SAML keeps the 404 parity.
func TestSAML_SLO_ClearsSessionAndRedirects(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequestWithContext(context.Background(), method, "/auth/saml/slo", nil)
		req.AddCookie(&http.Cookie{Name: "yabanin_admin_session", Value: "stale",
			Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "stale",
			Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w := httptest.NewRecorder()
		h.SAMLSLO()(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("%s slo: got %d, want 302", method, w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/auth/login" {
			t.Fatalf("%s slo redirect: got %q, want /auth/login", method, loc)
		}
		var sessionGone, csrfGone bool
		for _, c := range w.Result().Cookies() {
			if c.Name == "yabanin_admin_session" && c.MaxAge < 0 {
				sessionGone = true
			}
			if c.Name == "yabanin_csrf_token" && c.MaxAge < 0 {
				csrfGone = true
			}
		}
		if !sessionGone || !csrfGone {
			t.Fatalf("%s slo must expire session+csrf cookies: %+v", method, w.Result().Cookies())
		}
	}

	// Unconfigured: 404, the same parity as every other SAML route.
	plain := newTestAdminH(newMockStore())
	w := httptest.NewRecorder()
	plain.SAMLSLO()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/slo", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured slo: got %d, want 404", w.Code)
	}
}

func TestSAML_SLORevokesSessionServerSide(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	revocations := &captureRevocationStore{}
	h.sessionRevocations = revocations
	sessionID := "saml-slo-revoked-session"
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "u-1", SessionID: sessionID, ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/slo", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.SAMLSLO().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || revocations.sessionID != sessionID {
		t.Fatalf("SAML SLO status=%d durable revoked session=%q", rec.Code, revocations.sessionID)
	}
}

func TestSAML_SLOFailsClosedWhenDurableRevocationFails(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	revocations := &captureRevocationStore{err: errors.New("database unavailable")}
	h.sessionRevocations = revocations
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "u-1", SessionID: "saml-slo-revoke-failure", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, "test-secret")
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/slo", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.SAMLSLO().ServeHTTP(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Header().Values("Set-Cookie"), "yabanin_admin_session=")
}

func TestSAML_SLOFailsClosedWithoutDurableRevocationStore(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "u-1", SessionID: "saml-slo-no-store", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, "test-secret")
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/saml/slo", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.SAMLSLO().ServeHTTP(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Header().Values("Set-Cookie"), "yabanin_admin_session=")
}

// syncSAMLLogBuffer serializes log writes from the background refresh loop
// against reads from the test goroutine (a plain bytes.Buffer shared with a
// live logger is a data race under -race).
type syncSAMLLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncSAMLLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncSAMLLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ticks against a failing IdP metadata endpoint, a login in flight still
// completes against the CACHED metadata (fail-open) and every failed tick is
// logged; recovery restores live refreshes.
func TestSAML_RefreshFailureMidOperation_CachedServes(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)

	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("baseline acs: got %d, want 302", w.Code)
	}

	// The IdP metadata endpoint starts failing; the background loop ticks
	// against it and every tick fails.
	var logs syncSAMLLogBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.setMetadataFail(true)
	go sp.RunMetadataRefresh(ctx, 10*time.Millisecond, logger)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "serving cached metadata") {
		time.Sleep(5 * time.Millisecond)
	}

	// Mid-operation: a full login while refreshes keep failing completes
	// against the cached metadata.
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("mid-failure acs: got %d, want 302 (cached metadata)", w.Code)
	}
	if out := logs.String(); !strings.Contains(out, "admin saml metadata refresh failed") {
		t.Fatalf("refresh failure must be logged, got: %q", out)
	}
	cancel()

	// Recovery: the endpoint comes back and refreshes succeed again.
	p.setMetadataFail(false)
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("recovered refresh: %v", err)
	}
	if w, _ := happySAMLFlow(t, h, p); w.Code != http.StatusFound {
		t.Fatalf("post-recovery acs: got %d, want 302", w.Code)
	}
}

// the full SAML round trip over the REAL HTTP boundary
// — the admin router served by an TLS httptest server (Secure cookies must
// actually travel), a cookie-jar client acting as the browser, and the fake
// IdP as a second real HTTP server. The ACS the IdP form posts to is the
// live server URL (loopback https is the sanctioned test shape). Proves the
// rotation contract end to end: baseline login → IdP cert rotation breaks
// ACS (401 over real HTTP) → RefreshMetadata → login works again without
// restart; the session cookie lands in the jar only on success.
func TestSAML_Integration_RotatedCert_RealHTTPBoundary(t *testing.T) {
	p := newFakeSAMLIdP(t)

	// The server exists before the SP (the ACS URL must be the live URL);
	// swap in the real router once the handlers are wired.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	store := newMockStore()
	store.adminUsers["u-1"] = &adminstore.AdminUser{
		ID: "u-1", Email: "root@test.io", DisplayName: "Root", IsRoot: true, Active: true,
	}
	h := &testAdminHandlers{
		AdminHandlers: New(store, "test-secret", "admin.test", []string{}),
		store:         store,
	}
	spKey, spCert := samlTestSPIdentity(t)
	sp, err := adminauth.NewSAMLSP(context.Background(), adminauth.SAMLOptions{
		IDPMetadataURL: p.server.URL + "/metadata",
		ACSURL:         srv.URL + "/auth/saml/acs",
		RoleAttribute:  "role",
		HTTPClient:     p.server.Client(),
		Key:            spKey,
		Certificate:    spCert,
	})
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	h.SetSAMLSP(sp)
	p.registerSP(t, sp, "")
	srv.Config.Handler = h.SetupRouter()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// login drives browser-style: GET /login (302 to the IdP, flow cookie in
	// the jar) → GET the IdP SSO URL (200 auto-submit form) → POST the form
	// to its action URL — the real ACS the SP metadata advertises. Returns
	// the ACS status code.
	do := func(method, target string, body io.Reader) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, target, body)
		if err != nil {
			t.Fatalf("%s request: %v", method, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		return resp
	}
	login := func() int {
		t.Helper()
		resp := do(http.MethodGet, srv.URL+"/auth/saml/login", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("login: got %d, want 302", resp.StatusCode)
		}
		idpResp := do(http.MethodGet, resp.Header.Get("Location"), nil)
		defer idpResp.Body.Close()
		body := readAll(t, idpResp.Body)
		m := samlResponseRe.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("idp form carries no SAMLResponse: %s", body)
		}
		am := samlFormActionRe.FindStringSubmatch(body)
		if am == nil {
			t.Fatalf("idp form carries no action: %s", body)
		}
		form := url.Values{"SAMLResponse": {html.UnescapeString(m[1])}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			html.UnescapeString(am[1]), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("acs request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		acsResp, err := client.Do(req)
		if err != nil {
			t.Fatalf("acs post: %v", err)
		}
		defer acsResp.Body.Close()
		return acsResp.StatusCode
	}
	sessionInJar := func() bool {
		srvURL, _ := url.Parse(srv.URL)
		for _, c := range jar.Cookies(srvURL) {
			if c.Name == "yabanin_admin_session" && c.Value != "" {
				return true
			}
		}
		return false
	}

	// Baseline: full round trip over real HTTP → 302 + session cookie.
	if code := login(); code != http.StatusFound {
		t.Fatalf("baseline acs over http: got %d, want 302", code)
	}
	if !sessionInJar() {
		t.Fatal("successful login must leave the admin session cookie in the jar")
	}

	// Rotation: the IdP's new signing key is not yet trusted — the ACS
	// refuses over the real boundary, and no session is issued.
	p.rotateSigningIdentity(t)
	if code := login(); code != http.StatusUnauthorized {
		t.Fatalf("post-rotation acs over http: got %d, want 401", code)
	}

	// Refresh picks up the rotated certificate: login works again WITHOUT a
	// restart, over the same live server.
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("RefreshMetadata: %v", err)
	}
	if code := login(); code != http.StatusFound {
		t.Fatalf("post-refresh acs over http: got %d, want 302", code)
	}
	if !sessionInJar() {
		t.Fatal("post-refresh login must issue the session cookie")
	}
}

// readAll reads a response body (small helper so tests stay lean).
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(raw)
}

// mustTestCert issues a throwaway self-signed certificate for key. Used both
// directly and from the shared-identity initializers (which run inside
// sync.Once and report through samlTestIdentityErr, not a specific test).
// Certificate creation from a valid RSA key cannot fail in practice; the
// errors are folded into one for that reason.
func mustTestCert(key *rsa.PrivateKey, cn string) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}
