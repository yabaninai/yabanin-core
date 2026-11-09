package adminauth

// SAML SP construction tests: config parsing, fail-closed startup
// validation, the flow-cookie codec, the assertion replay guard and the XML
// hardening of the IdP metadata ingestion (entity expansion). The metadata
// fixtures come from a real crewjam IdentityProvider where possible, so the
// shapes the SP consumes are the shapes crewjam produces.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// serialNumber returns a random certificate serial.
func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

// pkixName builds a certificate subject.
func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

// base64url encodes raw bytes the way the flow cookies do.
func base64url(t *testing.T, raw []byte) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(raw)
}

// selfSignedTestCert issues a throwaway certificate for key.
func selfSignedTestCert(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkixName(cn),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// fakeIdPMetadataServer serves a crewjam IdentityProvider's metadata document
// (and its SSO endpoint, unused here). mutate adjusts the IdP before serving.
func fakeIDPMetadataServer(t *testing.T, mutate func(*saml.IdentityProvider)) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	cert := selfSignedTestCert(t, key, "idp.test")
	idp := &saml.IdentityProvider{Key: key, Certificate: cert}
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		if mutate != nil {
			mutate(idp)
		}
		base := &url.URL{Scheme: "http", Host: r.Host}
		idp.MetadataURL = *base.ResolveReference(&url.URL{Path: "/metadata"})
		idp.SSOURL = *base.ResolveReference(&url.URL{Path: "/sso"})
		idp.LoginURL = *base.ResolveReference(&url.URL{Path: "/login"})
		idp.LogoutURL = *base.ResolveReference(&url.URL{Path: "/logout"})
		buf, err := xml.Marshal(idp.Metadata())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(buf)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// rawMetadataServer serves an arbitrary byte body as the metadata document.
func rawMetadataServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func samlTestOptions(metadataURL string) SAMLOptions {
	return SAMLOptions{
		IDPMetadataURL: metadataURL,
		ACSURL:         "https://admin.test/auth/saml/acs",
		HTTPClient:     &http.Client{Timeout: 5 * time.Second},
	}
}

func TestSAML_NewSAMLSP_Happy(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	if sp.SP.EntityID != "https://admin.test" {
		t.Fatalf("default entity ID: got %q, want the ACS origin", sp.SP.EntityID)
	}
	if sp.SP.AcsURL.String() != "https://admin.test/auth/saml/acs" {
		t.Fatalf("ACS: got %q", sp.SP.AcsURL.String())
	}
	if sp.SP.IDPMetadata == nil || len(sp.SP.IDPMetadata.IDPSSODescriptors) == 0 {
		t.Fatal("IdP metadata not parsed")
	}
	if sp.SP.AllowIDPInitiated {
		t.Fatal("IDP-initiated flow must stay disabled")
	}
	if sp.SP.SignatureMethod == "" {
		t.Fatal("AuthnRequests must be signed (SignatureMethod unset)")
	}
	if sp.RoleAttribute != "" {
		t.Fatalf("role attribute: got %q, want empty", sp.RoleAttribute)
	}
	// Redirect binding from the crewjam metadata: login yields a redirect
	// URL to the IdP SSO endpoint and a flow with the request ID.
	authn, err := sp.NewAuthnRequest("")
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	if authn.RedirectURL == "" || authn.PostForm != nil {
		t.Fatalf("redirect binding expected: %+v", authn)
	}
	if authn.Flow.RequestID == "" {
		t.Fatal("flow carries no request ID")
	}
	if cookie, err := NewSAMLFlowCookie(authn.Flow); err != nil || cookie.Value == "" {
		t.Fatalf("flow cookie: %v", err)
	}
}

// An IdP that offers only the HTTP-POST SSO binding must produce the
// auto-submitting form fallback (no redirect): the form carries the signed
// AuthnRequest and the request ID still seals into the flow cookie.
func TestSAML_NewAuthnRequest_PostBindingFallback(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedTestCert(t, key, "idp.postonly.test").Raw})
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.postonly.test/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.postonly.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, base64.StdEncoding.EncodeToString(certPEM))
	server := rawMetadataServer(t, []byte(metadata))

	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	if loc := sp.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding); loc != "" {
		t.Fatalf("redirect binding unexpectedly present: %q", loc)
	}
	authn, err := sp.NewAuthnRequest("relay-1")
	if err != nil {
		t.Fatalf("NewAuthnRequest: %v", err)
	}
	if authn.RedirectURL != "" || authn.PostURL != "https://idp.postonly.test/sso" || len(authn.PostForm) == 0 {
		t.Fatalf("POST binding fallback expected: %+v", authn)
	}
	if !strings.Contains(string(authn.PostForm), `name="RelayState" value="relay-1"`) {
		t.Fatalf("form must carry the relay state: %s", authn.PostForm)
	}
	if authn.Flow.RequestID == "" {
		t.Fatal("flow carries no request ID")
	}
}

func TestSAML_NewSAMLSP_DefaultHTTPClient(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	opts := samlTestOptions(server.URL + "/metadata")
	opts.HTTPClient = nil
	if _, err := NewSAMLSP(context.Background(), opts); err != nil {
		t.Fatalf("NewSAMLSP with the default HTTP client: %v", err)
	}
}

// An injected key/certificate pair must be used verbatim (production gets an
// ephemeral pair; operators or tests may pin one).
func TestSAML_NewSAMLSP_InjectedSigningPair(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	key := nil2key(t)
	opts := samlTestOptions(server.URL + "/metadata")
	opts.Key = key
	opts.Certificate = selfSignedTestCert(t, key, "sp.injected.test")
	sp, err := NewSAMLSP(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	if sp.SP.Certificate != opts.Certificate {
		t.Fatal("injected certificate not used")
	}
}

// Metadata that carries an IDPSSODescriptor with no SSO binding at all is
// accepted at construction (the SP cannot know every binding an operator
// needs) but login must refuse — there is nothing to talk to.
func TestSAML_NewAuthnRequest_NoSSOBinding_Refused(t *testing.T) {
	metadata := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.nobinding.test/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`
	server := rawMetadataServer(t, []byte(metadata))
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	if _, err := sp.NewAuthnRequest(""); err == nil {
		t.Fatal("login against an IdP without any SSO binding must fail")
	}
}

// ParseACSResponse hands the POST body to crewjam; an ACS POST without a
// decodable SAMLResponse form value is refused (the wrapper surfaces
// InvalidResponseError, the handler logs its private reason only).
func TestSAML_ParseACSResponse_MissingResponse_Refused(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, SAMLACSPath, strings.NewReader("SAMLResponse="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := sp.ParseACSResponse(req, "req-1"); err == nil {
		t.Fatal("an ACS POST without a usable SAMLResponse must fail")
	}
}

func TestSAML_NewSAMLSP_ExplicitEntityIDAndRole(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	opts := samlTestOptions(server.URL + "/metadata")
	opts.EntityID = "urn:yabanin:admin"
	opts.RoleAttribute = "role"
	sp, err := NewSAMLSP(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	if sp.SP.EntityID != "urn:yabanin:admin" || sp.RoleAttribute != "role" {
		t.Fatalf("options not applied: %q / %q", sp.SP.EntityID, sp.RoleAttribute)
	}
}

func TestSAML_NewSAMLSP_FailClosed(t *testing.T) {
	if _, err := NewSAMLSP(context.Background(), SAMLOptions{ACSURL: "https://admin.test/auth/saml/acs"}); err == nil {
		t.Fatal("missing metadata URL must fail")
	}
	if _, err := NewSAMLSP(context.Background(), SAMLOptions{IDPMetadataURL: "http://idp.evil.test/metadata", ACSURL: "https://admin.test/auth/saml/acs"}); err == nil {
		t.Fatal("plain-http non-loopback metadata URL must fail")
	}
	if _, err := NewSAMLSP(context.Background(), samlTestOptions("not a url")); err == nil {
		t.Fatal("unparsable metadata URL must fail")
	}
	if _, err := NewSAMLSP(context.Background(), samlTestOptions("")); err == nil {
		t.Fatal("empty everything must fail")
	}
	// Plain-metadata failures.
	broken := rawMetadataServer(t, []byte("this is not xml at all"))
	if _, err := NewSAMLSP(context.Background(), samlTestOptions(broken.URL)); err == nil {
		t.Fatal("non-XML metadata must fail")
	}
	empty := rawMetadataServer(t, []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`))
	if _, err := NewSAMLSP(context.Background(), samlTestOptions(empty.URL)); err == nil {
		t.Fatal("metadata without IDPSSODescriptor must fail")
	}
	// ACS validation.
	noACS := samlTestOptions(fakeIDPMetadataServer(t, nil).URL + "/metadata")
	noACS.ACSURL = ""
	if _, err := NewSAMLSP(context.Background(), noACS); err == nil {
		t.Fatal("missing ACS must fail")
	}
	badACS := samlTestOptions(fakeIDPMetadataServer(t, nil).URL + "/metadata")
	badACS.ACSURL = "http://admin.evil.test/auth/saml/acs"
	if _, err := NewSAMLSP(context.Background(), badACS); err == nil {
		t.Fatal("plain-http non-loopback ACS must fail")
	}
	// An unparsable ACS URL is a wiring error too.
	unparsableACS := samlTestOptions(fakeIDPMetadataServer(t, nil).URL + "/metadata")
	unparsableACS.ACSURL = "http://[::1]:namedport"
	if _, err := NewSAMLSP(context.Background(), unparsableACS); err == nil {
		t.Fatal("unparsable ACS must fail")
	}
	// A loopback test IdP/ACS over plain http stays allowed.
	loopbackACS := samlTestOptions(fakeIDPMetadataServer(t, nil).URL + "/metadata")
	loopbackACS.ACSURL = "http://127.0.0.1:8890/auth/saml/acs"
	if _, err := NewSAMLSP(context.Background(), loopbackACS); err != nil {
		t.Fatalf("loopback http ACS must be accepted: %v", err)
	}
	// Key without certificate (and the reverse) is a wiring error.
	server := fakeIDPMetadataServer(t, nil)
	keyOnly := samlTestOptions(server.URL + "/metadata")
	keyOnly.Key, _ = rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewSAMLSP(context.Background(), keyOnly); err == nil {
		t.Fatal("key without certificate must fail")
	}
	certOnly := samlTestOptions(server.URL + "/metadata")
	certOnly.Certificate = selfSignedTestCert(t, nil2key(t), "x")
	if _, err := NewSAMLSP(context.Background(), certOnly); err == nil {
		t.Fatal("certificate without key must fail")
	}
}

func nil2key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return key
}

// Security requirement: entity-expansion (billion laughs) in the IdP
// metadata must be refused — Go's encoding/xml never resolves external or
// parameter entities, and crewjam round-trip-validates the document before
// parsing. Either way: an error, no expansion, no hang.
func TestSAML_Metadata_EntityExpansion_Refused(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<!DOCTYPE EntityDescriptor [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&d;">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`)
	server := rawMetadataServer(t, body)
	_, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL))
	if err == nil {
		t.Fatal("DOCTYPE/entity-laden metadata must be refused")
	}
}

func TestSAML_FlowCookie_Codec(t *testing.T) {
	flow := SAMLFlow{RequestID: "id-abc123"}
	cookie, err := NewSAMLFlowCookie(flow)
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}
	if cookie.Name != SAMLFlowCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags: %+v", cookie)
	}
	if cookie.Path != "/auth/saml" || cookie.MaxAge != 600 {
		t.Fatalf("cookie scope: path=%q maxAge=%d", cookie.Path, cookie.MaxAge)
	}
	back, err := ParseSAMLFlowCookie(cookie.Value)
	if err != nil || back != flow {
		t.Fatalf("round-trip: %v %+v", err, back)
	}
	if _, err := ParseSAMLFlowCookie("!!!not-base64!!!"); err == nil {
		t.Fatal("malformed cookie must fail")
	}
	if _, err := ParseSAMLFlowCookie(""); err == nil {
		t.Fatal("empty cookie must fail")
	}
	incomplete := base64url(t, []byte(`{"nope":1}`))
	if _, err := ParseSAMLFlowCookie(incomplete); err == nil {
		t.Fatal("cookie without request ID must fail")
	}
	cleared := ClearSAMLFlowCookie()
	if cleared.MaxAge != -1 || cleared.Path != "/auth/saml" {
		t.Fatalf("clear cookie: %+v", cleared)
	}
}

func TestSAML_ReplayGuard(t *testing.T) {
	sp := &SAMLSP{replay: make(map[string]time.Time)}
	if !sp.MarkAssertionSeen("a1") {
		t.Fatal("first sight must pass")
	}
	if sp.MarkAssertionSeen("a1") {
		t.Fatal("second sight of the same assertion must fail")
	}
	if !sp.MarkAssertionSeen("a2") {
		t.Fatal("a different assertion must pass")
	}
	// Expired entries stay refused until pruned (conservative) and pruning
	// must reclaim them once the cap churns: at worst the cache holds the
	// cap plus the one entry that triggered the prune.
	sp.replayMu.Lock()
	sp.replay["a1"] = time.Now().Add(-time.Second)
	sp.replayMu.Unlock()
	if sp.MarkAssertionSeen("a1") {
		t.Fatal("a recorded assertion stays refused while retained")
	}
	for i := 0; i < assertionReplayCap; i++ {
		sp.MarkAssertionSeen("churn-" + strconv.Itoa(i))
	}
	if len(sp.replay) > assertionReplayCap+1 {
		t.Fatalf("replay cache grew past the cap: %d", len(sp.replay))
	}
	_, a1Pruned := sp.replay["a1"]
	if a1Pruned {
		t.Fatal("expired entry must be pruned at the cap")
	}
}

func TestSAML_AssertionEmail(t *testing.T) {
	ok := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{
		Format: string(saml.EmailAddressNameIDFormat), Value: "root@test.io",
	}}}
	if email, err := AssertionEmail(ok); err != nil || email != "root@test.io" {
		t.Fatalf("emailAddress NameID: %q %v", email, err)
	}
	noFormat := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "root@test.io"}}}
	if email, err := AssertionEmail(noFormat); err != nil || email != "root@test.io" {
		t.Fatalf("format-less NameID: %q %v", email, err)
	}
	transient := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{
		Format: string(saml.TransientNameIDFormat), Value: "root@test.io",
	}}}
	if _, err := AssertionEmail(transient); err == nil {
		t.Fatal("transient NameID must be refused")
	}
	notEmail := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "opaque-id-42"}}}
	if _, err := AssertionEmail(notEmail); err == nil {
		t.Fatal("non-email NameID must be refused")
	}
	if _, err := AssertionEmail(&saml.Assertion{}); err == nil {
		t.Fatal("assertion without subject must be refused")
	}
	if _, err := AssertionEmail(nil); err == nil {
		t.Fatal("nil assertion must be refused")
	}
}

func TestSAML_AssertionAttribute(t *testing.T) {
	a := &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{
		Attributes: []saml.Attribute{
			{Name: "urn:oid:0.9.2342.19200300.100.1.3", Values: []saml.AttributeValue{{Value: "root@test.io"}}},
			{FriendlyName: "role", Values: []saml.AttributeValue{{Value: "admin"}}},
			{Name: "empty", Values: nil},
		},
	}}}
	if got := AssertionAttribute(a, "role"); got != "admin" {
		t.Fatalf("friendly-name lookup: %q", got)
	}
	if got := AssertionAttribute(a, "urn:oid:0.9.2342.19200300.100.1.3"); got != "root@test.io" {
		t.Fatalf("name lookup: %q", got)
	}
	if got := AssertionAttribute(a, "missing"); got != "" {
		t.Fatalf("missing attribute: %q", got)
	}
	if got := AssertionAttribute(a, "empty"); got != "" {
		t.Fatalf("valueless attribute: %q", got)
	}
	if got := AssertionAttribute(nil, "role"); got != "" {
		t.Fatalf("nil assertion: %q", got)
	}
}

// The NameID shape gate is deliberately strict: no whitespace or control
// characters, one @, non-empty parts, a resolvable domain shape and a sane
// length. IP-literal domains stay acceptable (mail systems on boxes).
func TestSAML_AssertionEmail_ShapeChecks(t *testing.T) {
	for _, nid := range []string{
		strings.Repeat("a", 128) + "@" + strings.Repeat("b", 128) + ".io", // > 254 chars
		"has space@test.io",
		"tab\t@test.io",
		"nul\x00@test.io",
		"a@",                // empty domain
		"@b.io",             // empty local part
		"a@b",               // no dot, not an IP literal
		"two@at@signs.test", // @ inside the domain
	} {
		a := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: nid}}}
		if _, err := AssertionEmail(a); err == nil {
			t.Fatalf("NameID %q must be refused", nid)
		}
	}
	ip := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "root@127.0.0.1"}}}
	if _, err := AssertionEmail(ip); err != nil {
		t.Fatalf("IP-literal domain must be accepted: %v", err)
	}
}

// unsupportedSigner trips x509.MarshalPKCS8PrivateKey so the PEM error path
// is exercised without depending on crypto internals.
type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return struct{}{} }

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signing is not part of this test")
}

func TestSAML_PEMPrivateKey_UnsupportedSigner(t *testing.T) {
	if _, err := PEMPrivateKey(unsupportedSigner{}); err == nil {
		t.Fatal("PEM of an unsupported signer must fail")
	}
}

func TestSAMLOptionsFromEnv(t *testing.T) {
	unset := func(keys ...string) {
		for _, k := range keys {
			t.Setenv(k, "")
		}
	}
	unset("YABANIN_SAML_IDP_METADATA_URL", "YABANIN_SAML_IDP_METADATA_URL_FILE",
		"YABANIN_SAML_ENTITY_ID", "YABANIN_SAML_ACS_URL", "YABANIN_SAML_ROLE_ATTR",
		"YABANIN_SAML_SP_KEY_FILE", "YABANIN_SAML_SP_CERT_FILE")

	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("no configuration must yield nil, got %+v", opts)
	}

	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "https://idp.test/metadata")
	t.Setenv("YABANIN_SAML_ENTITY_ID", "urn:yabanin")
	t.Setenv("YABANIN_SAML_ACS_URL", "https://adm.test/auth/saml/acs")
	t.Setenv("YABANIN_SAML_ROLE_ATTR", "role")
	opts := SAMLOptionsFromEnv()
	if opts == nil || opts.IDPMetadataURL != "https://idp.test/metadata" ||
		opts.EntityID != "urn:yabanin" || opts.ACSURL != "https://adm.test/auth/saml/acs" ||
		opts.RoleAttribute != "role" {
		t.Fatalf("direct env: %+v", opts)
	}

	// _FILE fallback (docker secret convention).
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "")
	f := filepath.Join(t.TempDir(), "metadata_url")
	if err := os.WriteFile(f, []byte("https://idp-file.test/metadata\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL_FILE", f)
	if opts := SAMLOptionsFromEnv(); opts == nil || opts.IDPMetadataURL != "https://idp-file.test/metadata" {
		t.Fatalf("_FILE fallback: %+v", opts)
	}

	// Direct wins over _FILE.
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "https://idp-direct.test/metadata")
	if opts := SAMLOptionsFromEnv(); opts == nil || opts.IDPMetadataURL != "https://idp-direct.test/metadata" {
		t.Fatalf("direct-over-_FILE precedence: %+v", opts)
	}

	// Unreadable _FILE with no direct value: no SAML (nil), not an error.
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "")
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL_FILE", filepath.Join(t.TempDir(), "missing"))
	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("unreadable _FILE must yield nil, got %+v", opts)
	}
}

// The stable SP signing pair env — YABANIN_SAML_SP_KEY_FILE +
// YABANIN_SAML_SP_CERT_FILE (both or neither; the key in the PEMPrivateKey
// PKCS8 form). Any problem yields nil (SAML unmounted) — never a silent
// fallback to an ephemeral key the IdP never imported.
func TestSAMLOptionsFromEnv_SPSigningPair(t *testing.T) {
	for _, k := range []string{
		"YABANIN_SAML_IDP_METADATA_URL", "YABANIN_SAML_IDP_METADATA_URL_FILE",
		"YABANIN_SAML_SP_KEY_FILE", "YABANIN_SAML_SP_CERT_FILE",
	} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	key := nil2key(t)
	keyPEM, err := PEMPrivateKey(key)
	if err != nil {
		t.Fatalf("PEMPrivateKey: %v", err)
	}
	keyPath := filepath.Join(dir, "sp.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cert := selfSignedTestCert(t, key, "sp.env.test")
	certPath := filepath.Join(dir, "sp.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "https://idp.test/metadata")

	// Half pairs (either side alone) are wiring errors → nil.
	t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("key without certificate must yield nil, got %+v", opts)
	}
	t.Setenv("YABANIN_SAML_SP_KEY_FILE", "")
	t.Setenv("YABANIN_SAML_SP_CERT_FILE", certPath)
	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("certificate without key must yield nil, got %+v", opts)
	}

	// The full pair loads verbatim and drives a real SP startup.
	t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
	opts := SAMLOptionsFromEnv()
	if opts == nil || opts.Key == nil || opts.Certificate == nil {
		t.Fatalf("env pair must load into Key/Certificate, got %+v", opts)
	}
	server := fakeIDPMetadataServer(t, nil)
	sp, err := NewSAMLSP(context.Background(), SAMLOptions{
		IDPMetadataURL: server.URL + "/metadata",
		ACSURL:         "https://admin.test/auth/saml/acs",
		Key:            opts.Key,
		Certificate:    opts.Certificate,
	})
	if err != nil {
		t.Fatalf("NewSAMLSP with the env-loaded pair: %v", err)
	}
	if sp.SP.Certificate != opts.Certificate {
		t.Fatal("the file-loaded certificate must be used verbatim")
	}

	// A garbage key file → nil (never an ephemeral fallback).
	badPath := filepath.Join(dir, "sp.bad")
	if err := os.WriteFile(badPath, []byte("not a pem at all"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	t.Setenv("YABANIN_SAML_SP_KEY_FILE", badPath)
	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("unparsable key must yield nil, got %+v", opts)
	}
	// A missing key file → nil as well.
	t.Setenv("YABANIN_SAML_SP_KEY_FILE", filepath.Join(dir, "missing.key"))
	if opts := SAMLOptionsFromEnv(); opts != nil {
		t.Fatalf("missing key file must yield nil, got %+v", opts)
	}
}

// YABANIN_SAML_METADATA_REFRESH_SECONDS — default hourly, 0/negative
// disables, unparsable keeps the default.
func TestSAMLMetadataRefreshInterval(t *testing.T) {
	t.Setenv("YABANIN_SAML_METADATA_REFRESH_SECONDS", "")
	if d := SAMLMetadataRefreshInterval(); d != time.Hour {
		t.Fatalf("default interval: got %s, want 1h", d)
	}
	t.Setenv("YABANIN_SAML_METADATA_REFRESH_SECONDS", "120")
	if d := SAMLMetadataRefreshInterval(); d != 2*time.Minute {
		t.Fatalf("explicit interval: got %s, want 2m", d)
	}
	t.Setenv("YABANIN_SAML_METADATA_REFRESH_SECONDS", "0")
	if d := SAMLMetadataRefreshInterval(); d != 0 {
		t.Fatalf("0 must disable, got %s", d)
	}
	t.Setenv("YABANIN_SAML_METADATA_REFRESH_SECONDS", "-5")
	if d := SAMLMetadataRefreshInterval(); d != 0 {
		t.Fatalf("negative must disable, got %s", d)
	}
	t.Setenv("YABANIN_SAML_METADATA_REFRESH_SECONDS", "garbage")
	if d := SAMLMetadataRefreshInterval(); d != time.Hour {
		t.Fatalf("unparsable must keep the default, got %s", d)
	}
}

func TestSAMLDeriveACSURL(t *testing.T) {
	for domain, want := range map[string]string{
		"admin.example.com":      "https://admin.example.com/auth/saml/acs",
		"admin.example.com:8443": "https://admin.example.com:8443/auth/saml/acs",
		"https://admin.test":     "https://admin.test/auth/saml/acs",
		"https://admin.test/":    "https://admin.test/auth/saml/acs",
	} {
		if got := SAMLDeriveACSURL(domain); got != want {
			t.Fatalf("derive(%q) = %q, want %q", domain, got, want)
		}
	}
	if got := SAMLDeriveACSURL(""); got != "" {
		t.Fatalf("empty domain: %q", got)
	}
}

func TestSAMLPEMPrivateKey(t *testing.T) {
	key := nil2key(t)
	pemBytes, err := PEMPrivateKey(key)
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("PEM block: %v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS8: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok || rsaKey.N.Cmp(key.N) != 0 {
		t.Fatal("PEM round-trip lost the key")
	}
}

// rotatableMetadataServer serves a crewjam IdP metadata document whose
// signing identity can be swapped mid-test (cert rollover), can be made to
// fail outright (refresh failure scenarios), or degraded to a descriptor-free
// document (refresh validation). fetchCount reports documents served.
func rotatableMetadataServer(t *testing.T) (server *httptest.Server, rotate func(newKey *rsa.PrivateKey, newCert *x509.Certificate), fail func(bool), degrade func(bool), fetchCount func() int32) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	idp := &saml.IdentityProvider{Key: key, Certificate: selfSignedTestCert(t, key, "idp.test")}
	var mu sync.Mutex
	var failing, degraded bool
	var fetches atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches.Add(1)
		if failing {
			http.Error(w, "metadata unavailable", http.StatusInternalServerError)
			return
		}
		if degraded {
			_, _ = w.Write([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`))
			return
		}
		base := &url.URL{Scheme: "http", Host: r.Host}
		idp.MetadataURL = *base.ResolveReference(&url.URL{Path: "/metadata"})
		idp.SSOURL = *base.ResolveReference(&url.URL{Path: "/sso"})
		idp.LoginURL = *base.ResolveReference(&url.URL{Path: "/login"})
		idp.LogoutURL = *base.ResolveReference(&url.URL{Path: "/logout"})
		buf, err := xml.Marshal(idp.Metadata())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(buf)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv,
		func(newKey *rsa.PrivateKey, newCert *x509.Certificate) {
			mu.Lock()
			defer mu.Unlock()
			idp.Key, idp.Certificate = newKey, newCert
		},
		func(on bool) {
			mu.Lock()
			defer mu.Unlock()
			failing = on
		},
		func(on bool) {
			mu.Lock()
			defer mu.Unlock()
			degraded = on
		},
		func() int32 { return fetches.Load() }
}

// idpCertB64 extracts the first signing certificate of the SP's cached IdP
// metadata as base64 DER (comparable against x509.Certificate.Raw).
func idpCertB64(t *testing.T, sp *SAMLSP) string {
	t.Helper()
	md := sp.currentSP().IDPMetadata
	if md == nil || len(md.IDPSSODescriptors) == 0 ||
		len(md.IDPSSODescriptors[0].KeyDescriptors) == 0 ||
		len(md.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates) == 0 {
		t.Fatal("IdP metadata carries no signing certificate")
	}
	return md.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data
}

// RefreshMetadata picks up a rotated IdP signing certificate
// without a process restart, and a failing re-fetch leaves the cached
// metadata in place (fail-open).
func TestSAML_RefreshMetadata_RotatesCertAndFailsOpen(t *testing.T) {
	server, rotate, fail, degrade, _ := rotatableMetadataServer(t)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}

	// Rotate the IdP signing identity; the refresh must surface the new cert.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	newCert := selfSignedTestCert(t, newKey, "idp-rotated.test")
	rotate(newKey, newCert)
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("RefreshMetadata: %v", err)
	}
	if got := idpCertB64(t, sp); got != base64.StdEncoding.EncodeToString(newCert.Raw) {
		t.Fatal("refreshed metadata must carry the rotated IdP certificate")
	}
	// The SP's own identity and endpoints survive the swap.
	if sp.currentSP().EntityID != "https://admin.test" || sp.currentSP().Certificate != sp.SP.Certificate {
		t.Fatal("refresh must not disturb the SP identity")
	}

	// A descriptor-free refreshed document is refused; cached metadata stays.
	degrade(true)
	if err := sp.RefreshMetadata(context.Background()); err == nil {
		t.Fatal("refreshed metadata without an IDPSSODescriptor must be refused")
	}
	if got := idpCertB64(t, sp); got != base64.StdEncoding.EncodeToString(newCert.Raw) {
		t.Fatal("a refused refresh must leave the cached metadata in place")
	}
	degrade(false)

	// Fail-open: a failing metadata endpoint returns an error and the cached
	// (rotated) certificate keeps serving.
	fail(true)
	if err := sp.RefreshMetadata(context.Background()); err == nil {
		t.Fatal("refresh against a failing endpoint must error")
	}
	if got := idpCertB64(t, sp); got != base64.StdEncoding.EncodeToString(newCert.Raw) {
		t.Fatal("a failed refresh must leave the cached metadata in place")
	}

	// A zero SAMLSP carries no refreshable URL: explicit error, no panic.
	if err := (&SAMLSP{}).RefreshMetadata(context.Background()); err == nil {
		t.Fatal("a non-refreshable SP must refuse RefreshMetadata")
	}
}

// The background loop re-fetches on the ticker and stops on ctx
// cancellation; failures keep it alive (fail-open) — the loop is still
// fetching after an error tick.
func TestSAML_RunMetadataRefresh_Loop(t *testing.T) {
	server, _, fail, _, fetchCount := rotatableMetadataServer(t)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sp.RunMetadataRefresh(ctx, 20*time.Millisecond, slog.New(slog.DiscardHandler))

	// A failing endpoint must not kill the loop; make it fail, then recover
	// and require the loop to fetch again afterwards.
	fail(true)
	time.Sleep(60 * time.Millisecond)
	fail(false)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && fetchCount() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := fetchCount(); n < 3 {
		t.Fatalf("refresh loop must keep fetching across failures, saw %d fetches", n)
	}

	// Cancellation stops the loop. A tick that fired concurrently with the
	// cancel may still land one straggler fetch, so the assertion is count
	// STABILITY across two windows of several tick intervals (20ms tick).
	cancel()
	time.Sleep(80 * time.Millisecond)
	first := fetchCount()
	time.Sleep(80 * time.Millisecond)
	if second := fetchCount(); second != first {
		t.Fatalf("loop kept fetching after ctx cancel: %d → %d", first, second)
	}

	// A non-positive interval is a synchronous no-op (refresh disabled).
	before := fetchCount()
	sp.RunMetadataRefresh(context.Background(), 0, nil)
	if after := fetchCount(); after != before {
		t.Fatalf("interval 0 must not fetch: %d → %d", before, after)
	}
}

// syncLogBuffer serializes log writes from the background refresh loop
// against reads from the test goroutine — a plain bytes.Buffer shared with
// a live logger is a data race under -race.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A refresh failure MID-OPERATION is logged with the operational
// contract and the cached metadata keeps serving — the loop never degrades a
// working SP, and recovery swaps live metadata back in.
func TestSAML_RunMetadataRefresh_FailureLogsCachedMetadataServes(t *testing.T) {
	server, _, fail, _, _ := rotatableMetadataServer(t)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	cached := idpCertB64(t, sp)

	var logs syncLogBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fail(true)
	go sp.RunMetadataRefresh(ctx, 15*time.Millisecond, logger)

	// The failure tick must land in the log: the warn message, the
	// fail-open contract ("serving cached metadata") and the error.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "serving cached metadata") {
		time.Sleep(5 * time.Millisecond)
	}
	if out := logs.String(); !strings.Contains(out, "admin saml metadata refresh failed") ||
		!strings.Contains(out, "serving cached metadata") ||
		!strings.Contains(out, "error") {
		t.Fatalf("refresh failure must be logged with the fail-open contract, got: %q", out)
	}
	cancel()

	// Mid-operation: the cached metadata is intact — authn requests and ACS
	// validation keep working against the last good document.
	if got := idpCertB64(t, sp); got != cached {
		t.Fatal("a failed refresh must leave the cached metadata serving")
	}
	if idp := sp.IDPEntityID(); idp == "" {
		t.Fatal("cached IdP entity must stay resolvable after failed refreshes")
	}

	// Recovery: the next successful fetch serves live metadata again.
	fail(false)
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("recovered refresh: %v", err)
	}
	if got := idpCertB64(t, sp); got != cached {
		t.Fatal("recovery refresh must re-serve the live metadata")
	}
}

// Concurrent-reader accessors over the refreshable SP.
func TestSAML_SPAccessors(t *testing.T) {
	server := fakeIDPMetadataServer(t, nil)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}
	md := sp.SPMetadata()
	if md == nil || md.EntityID != sp.currentSP().EntityID {
		t.Fatalf("SPMetadata must mirror the live SP metadata: %+v", md)
	}
	if idp := sp.IDPEntityID(); idp == "" || idp != sp.currentSP().IDPMetadata.EntityID {
		t.Fatalf("IDPEntityID must mirror the cached IdP entity: %q", idp)
	}
	// No metadata at all: empty entity, no panic.
	bare := &SAMLSP{SP: &saml.ServiceProvider{}}
	if idp := bare.IDPEntityID(); idp != "" {
		t.Fatalf("IDPEntityID without metadata must be empty, got %q", idp)
	}
}

// loadSPSigningPair branch matrix (the happy paths run via
// TestSAMLOptionsFromEnv_SPSigningPair).
func TestSAML_LoadSPSigningPair_Branches(t *testing.T) {
	dir := t.TempDir()
	key := nil2key(t)
	cert := selfSignedTestCert(t, key, "sp.branch.test")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	write := func(name string, body []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	pkcs8PEM, err := PEMPrivateKey(key)
	if err != nil {
		t.Fatalf("PEMPrivateKey: %v", err)
	}
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	goodKey := write("good.key", pkcs8PEM)
	goodCert := write("good.crt", certPEM)

	if _, _, err := loadSPSigningPair("", goodCert); err == nil {
		t.Fatal("empty key path must fail")
	}
	if _, _, err := loadSPSigningPair(goodKey, ""); err == nil {
		t.Fatal("empty cert path must fail")
	}
	if _, _, err := loadSPSigningPair(filepath.Join(dir, "missing.key"), goodCert); err == nil {
		t.Fatal("missing key file must fail")
	}
	if _, _, err := loadSPSigningPair(write("garbage.key", []byte("not pem")), goodCert); err == nil {
		t.Fatal("non-PEM key must fail")
	}
	if _, _, err := loadSPSigningPair(write("wrongtype.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})), goodCert); err == nil {
		t.Fatal("unsupported key PEM type must fail")
	}
	if _, _, err := loadSPSigningPair(write("badpkcs8.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})), goodCert); err == nil {
		t.Fatal("unparsable PKCS8 key must fail")
	}
	if _, _, err := loadSPSigningPair(write("badpkcs1.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})), goodCert); err == nil {
		t.Fatal("unparsable PKCS1 key must fail")
	}
	if _, _, err := loadSPSigningPair(goodKey, write("garbage.crt", []byte("not pem"))); err == nil {
		t.Fatal("non-PEM certificate must fail")
	}
	if _, _, err := loadSPSigningPair(goodKey, write("wrongtype.crt", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))); err == nil {
		t.Fatal("non-CERTIFICATE PEM block must fail")
	}
	if _, _, err := loadSPSigningPair(goodKey, write("badder.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))); err == nil {
		t.Fatal("unparsable certificate must fail")
	}

	// The legacy PKCS1 form loads the same key.
	signer, gotCert, err := loadSPSigningPair(write("pkcs1.key", pkcs1PEM), goodCert)
	if err != nil {
		t.Fatalf("PKCS1 pair: %v", err)
	}
	if rsaKey, ok := signer.(*rsa.PrivateKey); !ok || rsaKey.N.Cmp(key.N) != 0 {
		t.Fatal("PKCS1 key must round-trip")
	}
	if !gotCert.Equal(cert) {
		t.Fatal("certificate must parse to the issued one")
	}
}
