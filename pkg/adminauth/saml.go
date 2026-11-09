package adminauth

// SAML 2.0 SSO for the admin console, built on github.com/crewjam/saml
// as the service-provider implementation. Opt-in like the OIDC flow: the SP is
// constructed only when the deployment carries the IdP metadata URL
// (YABANIN_SAML_IDP_METADATA_URL, or the docker-secret _FILE variant); without
// it the handlers answer 404 and the console stays on the password flow.
//
// Trust boundary: crewjam's ServiceProvider.ParseResponse validates the
// response XML (round-trip checked, no DTD/entity expansion — Go's encoding/xml
// never resolves external entities), the signature against the certificates
// published in the IdP metadata, the issuer, the audience (SP entity ID), the
// ACS recipient, the InResponseTo binding and every timestamp
// (NotBefore/NotOnOrAfter/IssueInstant with bounded clock skew). On top of
// that: the AuthnRequest ID travels in a short-lived cookie (crewjam's
// InResponseTo check), and the assertion ID is deduplicated for the assertion
// lifetime — crewjam does not guard against a byte-for-byte replay of a
// still-valid response, this package does.
//
// User mapping is fail-closed, identical to the OIDC flow: the NameID must be
// an email matching an existing ACTIVE admin user; SAML never provisions
// accounts and never widens roles.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML flow cookie: carries the AuthnRequest ID through the IdP round-trip so
// the ACS can verify InResponseTo (crewjam checks it against this exact value;
// AllowIDPInitiated is false, so an assertion with no matching request ID is
// refused). Same discipline as the OIDC flow cookie: HttpOnly + Secure +
// SameSite=Lax (top-level navigation back from the IdP), 10 minutes, scoped to
// the /auth/saml routes.
const (
	SAMLFlowCookieName = "yabanin_saml_flow"

	SAMLMetadataPath = "/auth/saml/metadata"
	SAMLLoginPath    = "/auth/saml/login"
	SAMLACSPath      = "/auth/saml/acs"
	SAMLSLOPath      = "/auth/saml/slo"

	samlFlowCookiePath = "/auth/saml"
	samlFlowCookieTTL  = 10 * time.Minute

	// assertionReplayTTL bounds how long an assertion ID stays in the
	// replay cache. SAML assertions are minutes-lived (NotOnOrAfter plus
	// bounded clock skew); 15 minutes outlives any assertion crewjam would
	// still accept.
	assertionReplayTTL = 15 * time.Minute

	// assertionReplayCap bounds the cache; a churn past the cap prunes
	// expired entries instead of growing without bound.
	assertionReplayCap = 4096
)

// SAMLOptions is the startup configuration for the SAML SP. Only the IdP
// metadata URL is required; EntityID and ACSURL have deterministic defaults
// (ACS origin / https://<admin domain>/auth/saml/acs). Key and Certificate
// are the stable SP signing pair — production deployments inject them from
// YABANIN_SAML_SP_KEY_FILE/YABANIN_SAML_SP_CERT_FILE (SAMLOptionsFromEnv);
// without a pair the SP generates an ephemeral signing key per process (the
// IdP validates ASSERTIONS, not our requests; a stable key only matters for
// signed AuthnRequests and encrypted assertions against a metadata-importing
// IdP). Tests inject pairs directly.
type SAMLOptions struct {
	IDPMetadataURL string
	EntityID       string
	ACSURL         string
	RoleAttribute  string

	Key         crypto.Signer
	Certificate *x509.Certificate
	HTTPClient  *http.Client
}

// SAMLOptionsFromEnv reads the deployment knobs. nil (not an error) means "no
// SAML configuration" — the routes must not mount. The metadata URL is the
// only required value; the direct variable wins over the _FILE secret
// (pkg/config env convention). An operator-pinned SP signing pair
// (YABANIN_SAML_SP_KEY_FILE + YABANIN_SAML_SP_CERT_FILE, both or neither)
// loads here; any problem with the pair yields nil — SAML stays unmounted
// rather than silently falling back to an ephemeral key the IdP never
// imported.
func SAMLOptionsFromEnv() *SAMLOptions {
	metadataURL := strings.TrimSpace(os.Getenv("YABANIN_SAML_IDP_METADATA_URL"))
	if metadataURL == "" {
		if f := os.Getenv("YABANIN_SAML_IDP_METADATA_URL_FILE"); f != "" {
			raw, err := os.ReadFile(f) //nolint:gosec // G304: path comes from the operator's own env (_FILE docker-secret convention)
			if err != nil {
				return nil
			}
			metadataURL = strings.TrimSpace(string(raw))
		}
	}
	if metadataURL == "" {
		return nil
	}
	opts := &SAMLOptions{
		IDPMetadataURL: metadataURL,
		EntityID:       strings.TrimSpace(os.Getenv("YABANIN_SAML_ENTITY_ID")),
		ACSURL:         strings.TrimSpace(os.Getenv("YABANIN_SAML_ACS_URL")),
		RoleAttribute:  strings.TrimSpace(os.Getenv("YABANIN_SAML_ROLE_ATTR")),
	}
	if keyFile := strings.TrimSpace(os.Getenv("YABANIN_SAML_SP_KEY_FILE")); keyFile != "" ||
		strings.TrimSpace(os.Getenv("YABANIN_SAML_SP_CERT_FILE")) != "" {
		key, cert, err := loadSPSigningPair(
			strings.TrimSpace(os.Getenv("YABANIN_SAML_SP_KEY_FILE")),
			strings.TrimSpace(os.Getenv("YABANIN_SAML_SP_CERT_FILE")))
		if err != nil {
			return nil
		}
		opts.Key, opts.Certificate = key, cert
	}
	return opts
}

// loadSPSigningPair reads the operator-managed SP signing pair (both files or
// neither — a half pair is a wiring error). The key uses the PEMPrivateKey
// PKCS8 form ("PRIVATE KEY"; the legacy "RSA PRIVATE KEY" PKCS1 block stays
// accepted for operator convenience), the certificate a "CERTIFICATE" block.
func loadSPSigningPair(keyFile, certFile string) (crypto.Signer, *x509.Certificate, error) {
	if keyFile == "" || certFile == "" {
		return nil, nil, errors.New("adminauth: saml SP key and certificate files must be set together (YABANIN_SAML_SP_KEY_FILE / YABANIN_SAML_SP_CERT_FILE)")
	}
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // G304: operator's own env-provided path (docker-secret convention)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml SP key file: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, errors.New("adminauth: saml SP key file carries no PEM block")
	}
	var key crypto.Signer
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("adminauth: saml SP key (PKCS8): %w", err)
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New("adminauth: saml SP key is not a signing key")
		}
		key = signer
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("adminauth: saml SP key (PKCS1): %w", err)
		}
		key = rsaKey
	default:
		return nil, nil, fmt.Errorf("adminauth: saml SP key PEM type %q is not supported (use PRIVATE KEY)", block.Type)
	}
	certPEM, err := os.ReadFile(certFile) //nolint:gosec // G304: operator's own env-provided path (docker-secret convention)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml SP certificate file: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("adminauth: saml SP certificate file carries no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml SP certificate: %w", err)
	}
	return key, cert, nil
}

// defaultSAMLMetadataRefresh is the IdP metadata refresh cadence when
// YABANIN_SAML_METADATA_REFRESH_SECONDS is unset (hourly; the SP metadata
// contract clocks cert rollovers in days).
const defaultSAMLMetadataRefresh = time.Hour

// SAMLMetadataRefreshInterval reads YABANIN_SAML_METADATA_REFRESH_SECONDS:
// the background IdP metadata refresh cadence. Default one hour; 0 (or any
// negative value) disables the loop; an unparsable value keeps the default.
func SAMLMetadataRefreshInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("YABANIN_SAML_METADATA_REFRESH_SECONDS"))
	if raw == "" {
		return defaultSAMLMetadataRefresh
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return defaultSAMLMetadataRefresh
	}
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// SAMLDeriveACSURL is the fallback ACS when YABANIN_SAML_ACS_URL is unset:
// https://<admin domain>/auth/saml/acs. The domain is the deployment's
// YABANIN_ADMIN_DOMAIN (host or host:port).
func SAMLDeriveACSURL(adminDomain string) string {
	domain := strings.TrimSpace(adminDomain)
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return ""
	}
	return "https://" + domain + SAMLACSPath
}

// SAMLSP is the initialized SAML binding. Construct once at startup; every
// method is safe for concurrent use. The IdP metadata can rotate at runtime:
// RefreshMetadata swaps the whole embedded ServiceProvider under spMu, and
// reader paths go through currentSP so a swap is never observed half-applied
// (the previous SP object is left untouched for in-flight requests).
type SAMLSP struct {
	SP            *saml.ServiceProvider
	RoleAttribute string

	replayMu sync.Mutex
	replay   map[string]time.Time

	spMu        sync.RWMutex // guards SP swaps (metadata refresh)
	metadataURL *url.URL     // retained for RefreshMetadata (nil = not refreshable)
	httpClient  *http.Client // retained for RefreshMetadata
}

// NewSAMLSP fetches the IdP metadata and prepares the service provider.
// Every failure is a startup refusal — the caller logs and keeps the console
// on the password flow; there is no half-mounted SAML.
func NewSAMLSP(ctx context.Context, opts SAMLOptions) (*SAMLSP, error) {
	if opts.IDPMetadataURL == "" {
		return nil, errors.New("adminauth: saml requires an IdP metadata URL")
	}
	u, err := url.Parse(opts.IDPMetadataURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("adminauth: saml IdP metadata URL must be absolute: %q", opts.IDPMetadataURL)
	}
	// Production IdPs are https; plain http only for loopback test IdPs.
	if u.Scheme != "https" && !isLoopbackHost(u.Host) {
		return nil, fmt.Errorf("adminauth: saml IdP metadata URL must be https (or a loopback test IdP): %q", opts.IDPMetadataURL)
	}

	acs, err := parseACSURL(opts.ACSURL)
	if err != nil {
		return nil, err
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	idpMetadata, err := samlsp.FetchMetadata(ctx, hc, *u)
	if err != nil {
		return nil, fmt.Errorf("adminauth: saml IdP metadata fetch failed: %w", err)
	}
	if len(idpMetadata.IDPSSODescriptors) == 0 {
		return nil, errors.New("adminauth: saml IdP metadata carries no IDPSSODescriptor")
	}

	entityID := opts.EntityID
	if entityID == "" {
		// Crewjam defaults the audience to the metadata URL; an explicit
		// ACS-origin entity ID is the conventional, diffable choice.
		entityID = acs.Scheme + "://" + acs.Host
	}

	key, cert, err := signingPair(opts, entityID)
	if err != nil {
		return nil, err
	}

	metadataURL := *acs
	metadataURL.Path = SAMLMetadataPath
	sloURL := *acs
	sloURL.Path = "/auth/saml/slo"

	sp := &saml.ServiceProvider{
		EntityID:    entityID,
		Key:         key,
		Certificate: cert,
		MetadataURL: metadataURL,
		AcsURL:      *acs,
		SloURL:      sloURL,
		IDPMetadata: idpMetadata,
		// Sign AuthnRequests (POST binding) with the SP key; redirect
		// binding carries the signature in the query string the same way.
		SignatureMethod: dsig.RSASHA256SignatureMethod,
		// Ask IdPs to speak email-as-NameID; the mapping layer only
		// accepts an email-formatted NameID.
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		// Strictly SP-initiated: an assertion whose InResponseTo does not
		// match a request we issued is refused.
		AllowIDPInitiated:  false,
		DefaultRedirectURI: "/",
	}
	return &SAMLSP{
		SP:            sp,
		RoleAttribute: opts.RoleAttribute,
		replay:        make(map[string]time.Time),
		metadataURL:   u,
		httpClient:    hc,
	}, nil
}

// currentSP returns the live service provider. Callers that captured the
// returned pointer keep a consistent (pre- or post-refresh) view even while
// a concurrent RefreshMetadata swaps the field.
func (s *SAMLSP) currentSP() *saml.ServiceProvider {
	s.spMu.RLock()
	defer s.spMu.RUnlock()
	return s.SP
}

// SPMetadata renders the SP metadata document (the live post-refresh view —
// use this instead of reading the exported SP field from request paths).
func (s *SAMLSP) SPMetadata() *saml.EntityDescriptor {
	metadata := s.currentSP().Metadata()
	// crewjam advertises the SP certificate for assertion encryption by
	// default. This product contract does not implement encrypted assertions,
	// so publish only the signing key descriptor.
	for i := range metadata.SPSSODescriptors {
		descriptors := metadata.SPSSODescriptors[i].KeyDescriptors
		signing := descriptors[:0]
		for _, descriptor := range descriptors {
			if descriptor.Use == "signing" {
				signing = append(signing, descriptor)
			}
		}
		metadata.SPSSODescriptors[i].KeyDescriptors = signing
	}
	return metadata
}

// IDPEntityID returns the IdP entity ID of the currently cached metadata
// ("" when absent — never happens for a constructed SP).
func (s *SAMLSP) IDPEntityID() string {
	md := s.currentSP().IDPMetadata
	if md == nil {
		return ""
	}
	return md.EntityID
}

// RefreshMetadata re-fetches the IdP metadata and swaps it in wholesale — an
// IdP signing-cert rollover takes effect without a process restart. Every
// signing certificate published in the metadata is trusted, which IS the
// explicit two-certificate transition configuration: during a rollover the
// IdP publishes BOTH the outgoing and the incoming signing certificate (the
// dual-trust window), so assertions signed by either side validate; the IdP
// closes the window by dropping the retired certificate from the metadata,
// and the next successful refresh stops trusting it. A certificate that is
// not published — a third-party cert, or one the IdP already retired — never
// validates. A fetch/parse failure returns the error and leaves the CACHED
// metadata in place (fail-open: logins keep validating against the last good
// metadata until a later refresh succeeds).
func (s *SAMLSP) RefreshMetadata(ctx context.Context) error {
	if s.metadataURL == nil || s.httpClient == nil {
		return errors.New("adminauth: saml SP carries no refreshable metadata URL")
	}
	idpMetadata, err := samlsp.FetchMetadata(ctx, s.httpClient, *s.metadataURL)
	if err != nil {
		return fmt.Errorf("adminauth: saml IdP metadata refresh failed: %w", err)
	}
	if len(idpMetadata.IDPSSODescriptors) == 0 {
		return errors.New("adminauth: saml refreshed IdP metadata carries no IDPSSODescriptor")
	}
	s.spMu.Lock()
	next := *s.SP // shallow copy: same key/cert/URLs (ServiceProvider holds no locks or maps), fresh metadata
	next.IDPMetadata = idpMetadata
	s.SP = &next
	s.spMu.Unlock()
	return nil
}

// RunMetadataRefresh is the background refresh loop: every interval it
// re-fetches the IdP metadata; a failed refresh is logged and the cached
// metadata keeps serving (fail-open). Returns when ctx is done; an interval
// <= 0 disables the loop entirely (RunMetadataRefresh returns at once).
func (s *SAMLSP) RunMetadataRefresh(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.RefreshMetadata(ctx); err != nil {
				logger.Warn("admin saml metadata refresh failed — serving cached metadata", "error", err)
			}
		}
	}
}

// parseACSURL validates the Assertion Consumer Service URL: absolute, https
// (or loopback for tests).
func parseACSURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("adminauth: saml requires an ACS URL (YABANIN_SAML_ACS_URL or an admin domain to derive it)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("adminauth: saml ACS URL must be absolute: %q", raw)
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Host) {
		return nil, fmt.Errorf("adminauth: saml ACS URL must be https (or a loopback test host): %q", raw)
	}
	return u, nil
}

// signingPair returns the SP signing key and certificate: the injected pair
// (tests) or a fresh ephemeral pair with a self-signed certificate.
func signingPair(opts SAMLOptions, entityID string) (crypto.Signer, *x509.Certificate, error) {
	if opts.Key != nil && opts.Certificate != nil {
		return opts.Key, opts.Certificate, nil
	}
	if opts.Key != nil || opts.Certificate != nil {
		return nil, nil, errors.New("adminauth: saml key and certificate must be injected together")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml sp keygen: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml sp serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: entityID},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml sp self-signed certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("adminauth: saml sp parse certificate: %w", err)
	}
	return key, cert, nil
}

// SAMLAuthnRequest is a login initiation: exactly one of RedirectURL (HTTP-
// Redirect binding — issue a 302) or PostForm (HTTP-POST binding — serve an
// auto-submitting form) is set. Flow travels in the SAML flow cookie and must
// be presented at the ACS.
type SAMLAuthnRequest struct {
	Flow        SAMLFlow
	RedirectURL string
	PostURL     string
	PostForm    []byte // ready-made <form> HTML from crewjam (auto-submits)
}

// NewAuthnRequest builds the AuthnRequest for the best binding the IdP
// metadata offers (Redirect preferred, POST as the signed fallback). The flow
// carries the SAME request ID the IdP receives — InResponseTo must match it.
func (s *SAMLSP) NewAuthnRequest(relayState string) (*SAMLAuthnRequest, error) {
	sp := s.currentSP()
	if loc := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding); loc != "" {
		req, err := sp.MakeAuthenticationRequest(loc, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			return nil, fmt.Errorf("adminauth: saml authn request: %w", err)
		}
		u, err := req.Redirect(relayState, sp)
		if err != nil {
			return nil, fmt.Errorf("adminauth: saml authn redirect: %w", err)
		}
		return &SAMLAuthnRequest{Flow: SAMLFlow{RequestID: req.ID}, RedirectURL: u.String()}, nil
	}
	loc := sp.GetSSOBindingLocation(saml.HTTPPostBinding)
	if loc == "" {
		return nil, errors.New("adminauth: saml IdP metadata has no SSO binding")
	}
	req, err := sp.MakeAuthenticationRequest(loc, saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, fmt.Errorf("adminauth: saml authn request: %w", err)
	}
	return &SAMLAuthnRequest{
		Flow:     SAMLFlow{RequestID: req.ID},
		PostURL:  loc,
		PostForm: req.Post(relayState),
	}, nil
}

// ParseACSResponse validates the SAMLResponse POST: signature, issuer,
// audience, recipient, timestamps and InResponseTo against the tracked flow.
// InvalidResponseError intentionally hides the reason; use
// errors.As(...).PrivateErr for the server log only.
func (s *SAMLSP) ParseACSResponse(r *http.Request, requestID string) (*saml.Assertion, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("adminauth: saml response form is invalid")
	}
	responseXML, err := base64.StdEncoding.DecodeString(r.Form.Get("SAMLResponse"))
	if err != nil {
		return nil, fmt.Errorf("adminauth: saml response encoding is invalid")
	}
	// #nosec G709 -- token scanning rejects directives and does not resolve external entities; crewjam performs the authoritative signature validation next.
	decoder := xml.NewDecoder(bytes.NewReader(responseXML))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("adminauth: saml response XML is invalid")
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Space == "urn:oasis:names:tc:SAML:2.0:assertion" && element.Name.Local == "EncryptedAssertion" {
				return nil, errors.New("adminauth: encrypted SAML assertions are unsupported")
			}
		case xml.Directive:
			return nil, errors.New("adminauth: SAML response directives are unsupported")
		}
	}
	return s.currentSP().ParseResponse(r, []string{requestID})
}

// MarkAssertionSeen records an assertion ID and reports whether it was new.
// A second presentation of the same assertion (replay of the whole POST,
// flow cookie included) is refused for as long as the assertion could still
// be valid. No comparison here is secret-dependent: the ID is a random IdP
// identifier whose knowledge implies an already-verified signature.
func (s *SAMLSP) MarkAssertionSeen(id string) bool {
	now := time.Now()
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if _, seen := s.replay[id]; seen {
		return false
	}
	if len(s.replay) >= assertionReplayCap {
		for k, exp := range s.replay {
			if exp.Before(now) {
				delete(s.replay, k)
			}
		}
	}
	s.replay[id] = now.Add(assertionReplayTTL)
	return true
}

// AssertionEmail extracts the login email: the NameID when it is formatted as
// an email address (or carries no format — many IdPs omit it). Non-email
// NameIDs (transient/persistent opaque IDs) are refused — the mapping layer
// is email-based and fail-closed.
func AssertionEmail(a *saml.Assertion) (string, error) {
	if a == nil || a.Subject == nil || a.Subject.NameID == nil {
		return "", errors.New("adminauth: saml assertion carries no NameID")
	}
	nid := a.Subject.NameID
	if nid.Format != "" && nid.Format != string(saml.EmailAddressNameIDFormat) {
		return "", fmt.Errorf("adminauth: saml NameID format %q is not an email address", nid.Format)
	}
	if !isEmailLike(nid.Value) {
		return "", errors.New("adminauth: saml NameID is not an email address")
	}
	return nid.Value, nil
}

// AssertionAttribute returns the first value of the named assertion attribute
// (Name or FriendlyName match, crewjam semantics), or "" when absent. Used
// for the optional role attribute — informational, never authoritative.
func AssertionAttribute(a *saml.Assertion, name string) string {
	if a == nil || name == "" {
		return ""
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			if attr.Name != name && attr.FriendlyName != name {
				continue
			}
			if len(attr.Values) > 0 {
				return attr.Values[0].Value
			}
		}
	}
	return ""
}

// isEmailLike is the deliberately strict shape check for a login email: one
// @, non-empty local part and domain, no whitespace or control characters.
func isEmailLike(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n\x00") {
		return false
	}
	if strings.Contains(domain, "@") {
		return false
	}
	return strings.Contains(domain, ".") || net.ParseIP(strings.Trim(domain, "[]")) != nil
}

// SAMLFlow is the per-login one-time secret: the AuthnRequest ID this console
// issued. The IdP must echo it back as InResponseTo.
type SAMLFlow struct {
	RequestID string `json:"request_id"`
}

// NewSAMLFlowCookie seals the flow for the redirect round-trip.
func NewSAMLFlowCookie(f SAMLFlow) (*http.Cookie, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     SAMLFlowCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     samlFlowCookiePath,
		MaxAge:   int(samlFlowCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// ParseSAMLFlowCookie decodes the ACS flow cookie.
func ParseSAMLFlowCookie(value string) (SAMLFlow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return SAMLFlow{}, err
	}
	var f SAMLFlow
	if err := json.Unmarshal(raw, &f); err != nil {
		return SAMLFlow{}, err
	}
	if f.RequestID == "" {
		return SAMLFlow{}, errors.New("adminauth: saml flow cookie incomplete")
	}
	return f, nil
}

// ClearSAMLFlowCookie expires the one-time cookie (issued on every ACS
// outcome — the request ID is single-use by construction).
func ClearSAMLFlowCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SAMLFlowCookieName,
		Value:    "",
		Path:     samlFlowCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// PEMPrivateKey renders a private key for operators who want a stable SP key
// (the YABANIN_SAML_SP_KEY_FILE format — PKCS8 "PRIVATE KEY"). Kept tiny and
// tested so the format is pinned.
func PEMPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
