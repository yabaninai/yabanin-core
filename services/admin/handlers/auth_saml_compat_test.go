package handlers

// N04-P02-T09 [compatibility] mock corpus: old and new SAML configuration
// shapes walked through the REAL consumer chain — the exact wiring sequence
// services/run/admin.go executes (SAMLOptionsFromEnv → SAMLDeriveACSURL →
// NewSAMLSP → SetSAMLSP) and then the production request surface (login, SP
// metadata, audit trail, RefreshMetadata). Live companions for the same
// shapes run against real Keycloak in pkg/adminauth/
// keycloak_live_saml_compat_test.go.
//
// The contract pinned here:
//   - the OLD deployment shape (only YABANIN_SAML_IDP_METADATA_URL set, ACS
//     and entity ID derived, no SP pair files) keeps working end to end —
//     migration parity;
//   - the NEW shapes (docker-secret _FILE URL, explicit entity/ACS/role
//     knobs, stable PKCS8 SP pair, legacy PKCS1 SP pair) all work through the
//     same consumers;
//   - UNSUPPORTED shapes are refused loudly at the wiring step and the
//     consumer consequence is exact: no half-mounted SSO (all four SAML
//     routes 404) with the password console intact;
//   - a metadata swap (rotation) preserves the configured shape: entity ID,
//     ACS, SLO, role attribute, IdP identity and the SP signing pair
//     survive every refresh — a refresh may never silently re-key or
//     re-address a deployment the IdP already imported.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ---- env-shaped wiring (the services/run/admin.go consumer, verbatim) -------

// samlCompatClearEnv pins every SAML knob the corpus does not set, so a cell
// tests exactly the shape it names regardless of the machine's environment.
func samlCompatClearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"YABANIN_SAML_IDP_METADATA_URL", "YABANIN_SAML_IDP_METADATA_URL_FILE",
		"YABANIN_SAML_ENTITY_ID", "YABANIN_SAML_ACS_URL", "YABANIN_SAML_ROLE_ATTR",
		"YABANIN_SAML_SP_KEY_FILE", "YABANIN_SAML_SP_CERT_FILE",
		"YABANIN_SAML_METADATA_REFRESH_SECONDS",
	} {
		t.Setenv(k, "")
	}
}

// samlCompatTryWire runs the production wiring sequence against the current
// env and returns the wire result without failing the test — the
// unsupported-shape cells assert on the refusal itself. A nil
// SAMLOptionsFromEnv (the env never names a supported configuration) is
// reported as an error so both refusal classes flow through one contract.
func samlCompatTryWire(t *testing.T, p *fakeSAMLIdP, adminDomain string) (*adminauth.SAMLSP, *testAdminHandlers, error) {
	t.Helper()
	opts := adminauth.SAMLOptionsFromEnv()
	if opts == nil {
		return nil, nil, errors.New("SAMLOptionsFromEnv: nil — SAML would stay unmounted")
	}
	if opts.ACSURL == "" {
		opts.ACSURL = adminauth.SAMLDeriveACSURL(adminDomain)
	}
	sp, err := adminauth.NewSAMLSP(context.Background(), *opts)
	if err != nil {
		return nil, nil, err
	}
	store := newMockStore()
	store.adminUsers["u-1"] = &adminstore.AdminUser{
		ID: "u-1", Email: "root@test.io", DisplayName: "Root", IsRoot: true, Active: true,
	}
	h := &testAdminHandlers{
		AdminHandlers: New(store, "test-secret", "admin.test", []string{}),
		store:         store,
	}
	h.SetSAMLSP(sp)
	p.registerSP(t, sp, "")
	return sp, h, nil
}

func samlCompatWire(t *testing.T, p *fakeSAMLIdP, adminDomain string) (*adminauth.SAMLSP, *testAdminHandlers) {
	t.Helper()
	sp, h, err := samlCompatTryWire(t, p, adminDomain)
	if err != nil {
		t.Fatalf("wire SAML from env: %v", err)
	}
	return sp, h
}

// ---- consumer-surface assertions ---------------------------------------------

// samlCompatLogin drives one full login through the production handlers and
// asserts the complete consumer outcome: 302 home, a minted session cookie,
// the one-time flow cookie cleared, exactly one new login audit row.
func samlCompatLogin(t *testing.T, h *testAdminHandlers, p *fakeSAMLIdP) {
	t.Helper()
	before := samlAuditLoginCount(h)
	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("saml login: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	if samlSessionCookieValue(t, w) == "" {
		t.Fatal("saml login minted no session cookie")
	}
	if !samlRecorderClearedFlow(t, w) {
		t.Fatal("saml login did not clear the one-time flow cookie")
	}
	if got := samlAuditLoginCount(h); got != before+1 {
		t.Fatalf("login audit rows: got %d, want %d", got, before+1)
	}
}

// samlCompatRefusedLogin asserts the refused-login consumer outcome: 401, no
// session, no audit row — trust shape violations never leak a session.
func samlCompatRefusedLogin(t *testing.T, h *testAdminHandlers, p *fakeSAMLIdP) {
	t.Helper()
	before := samlAuditLoginCount(h)
	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("refused login: got %d, want 401; body %s", w.Code, w.Body.String())
	}
	if samlSessionCookieValue(t, w) != "" {
		t.Fatal("refused login minted a session cookie")
	}
	if got := samlAuditLoginCount(h); got != before {
		t.Fatalf("refused login wrote audit rows: got %d, want %d", got, before)
	}
}

// samlCompatUnmountedParity is the consumer consequence of every startup
// refusal: all four SAML routes answer 404 (never a half-mounted SSO) and
// the password console still serves its login page.
func samlCompatUnmountedParity(t *testing.T) {
	t.Helper()
	store := newMockStore()
	store.adminUsers["u-1"] = &adminstore.AdminUser{
		ID: "u-1", Email: "root@test.io", DisplayName: "Root", IsRoot: true, Active: true,
	}
	h := &testAdminHandlers{
		AdminHandlers: New(store, "test-secret", "admin.test", []string{}),
		store:         store,
	}
	for _, tc := range []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{http.MethodGet, "/auth/saml/metadata", h.SAMLMetadata()},
		{http.MethodGet, "/auth/saml/login", h.SAMLLogin()},
		{http.MethodPost, "/auth/saml/acs", h.SAMLACS()},
		{http.MethodGet, "/auth/saml/slo", h.SAMLSLO()},
	} {
		req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, strings.NewReader("SAMLResponse=x"))
		if tc.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		tc.handler(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unmounted %s %s after refusal: got %d, want 404", tc.method, tc.path, w.Code)
		}
	}
	page := httptest.NewRecorder()
	h.LoginPage()(page, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("password login page after refusal: got %d, want 200", page.Code)
	}
}

// ---- SP shape snapshot (what a metadata swap must preserve) -------------------

// samlCompatSPShape is everything the configured shape pins. All fields are
// comparable so a pre/post-refresh diff is a plain ==.
type samlCompatSPShape struct {
	entityID      string
	acs           string
	slo           string
	roleAttribute string
	idpEntity     string
	key           crypto.Signer
	certificate   *x509.Certificate
}

func samlCompatShapeOf(sp *adminauth.SAMLSP) samlCompatSPShape {
	return samlCompatSPShape{
		entityID:      sp.SP.EntityID,
		acs:           sp.SP.AcsURL.String(),
		slo:           sp.SP.SloURL.String(),
		roleAttribute: sp.RoleAttribute,
		idpEntity:     sp.IDPEntityID(),
		key:           sp.SP.Key,
		certificate:   sp.SP.Certificate,
	}
}

// samlCompatAssertSwapPreservesShape refreshes the metadata and proves the
// swap happened (new SP object) while the configured shape survived intact —
// including the SP signing pair, which the IdP imported at setup time and a
// silent re-key would invalidate.
func samlCompatAssertSwapPreservesShape(t *testing.T, sp *adminauth.SAMLSP, before samlCompatSPShape) {
	t.Helper()
	if err := sp.RefreshMetadata(context.Background()); err != nil {
		t.Fatalf("RefreshMetadata: %v", err)
	}
	if sp.SP == nil {
		t.Fatal("RefreshMetadata left no live SP")
	}
	if after := samlCompatShapeOf(sp); after != before {
		t.Fatalf("metadata swap changed the configured shape:\n before %+v\n after  %+v", before, after)
	}
}

// ---- supported shapes ----------------------------------------------------------

// TestSAMLCompat_OldShapeEnvWalkthrough walks the ORIGINAL deployment shape —
// only YABANIN_SAML_IDP_METADATA_URL, everything else derived — through the
// full consumer chain: env → derived ACS/entity → SP → handlers → real login
// round trip → served SP metadata → dual-certificate rotation swap. Old
// configurations must keep working unchanged (migration parity).
func TestSAMLCompat_OldShapeEnvWalkthrough(t *testing.T) {
	samlCompatClearEnv(t)
	p := newFakeSAMLIdP(t)
	t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")

	sp, h := samlCompatWire(t, p, "admin.test")

	// The derived addressing: ACS from the admin domain, entity ID from the
	// ACS origin — the exact values the IdP-side import pinned.
	if got := sp.SP.AcsURL.String(); got != "https://admin.test/auth/saml/acs" {
		t.Fatalf("derived ACS: got %q", got)
	}
	if got := sp.SP.EntityID; got != "https://admin.test" {
		t.Fatalf("derived entity ID: got %q", got)
	}
	if got := sp.RoleAttribute; got != "" {
		t.Fatalf("old shape sets no role attribute, got %q", got)
	}

	// The old shape logs in through the production handlers.
	samlCompatLogin(t, h, p)

	// The SP metadata an IdP operator imports: the derived entity ID and ACS,
	// signing-only key descriptor (no assertion-encryption offer).
	md := httptest.NewRecorder()
	h.SAMLMetadata()(md, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/metadata", nil))
	if md.Code != http.StatusOK || md.Header().Get("Content-Type") != "application/samlmetadata+xml" {
		t.Fatalf("served SP metadata: %d %q", md.Code, md.Header().Get("Content-Type"))
	}
	var doc struct {
		EntityID         string `xml:"entityID,attr"`
		SPSSODescriptors []struct {
			ACS []struct {
				Location string `xml:"Location,attr"`
			} `xml:"AssertionConsumerService"`
			KeyDescriptors []struct {
				Use string `xml:"use,attr"`
			} `xml:"KeyDescriptor"`
		} `xml:"SPSSODescriptor"`
	}
	if err := xml.Unmarshal(md.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served SP metadata xml: %v", err)
	}
	if doc.EntityID != "https://admin.test" {
		t.Fatalf("served entity: got %q", doc.EntityID)
	}
	acsFound := false
	for _, d := range doc.SPSSODescriptors {
		for _, acs := range d.ACS {
			if acs.Location == "https://admin.test/auth/saml/acs" {
				acsFound = true
			}
		}
		if len(d.KeyDescriptors) != 1 || d.KeyDescriptors[0].Use != "signing" {
			t.Fatalf("metadata must advertise signing only: %+v", d.KeyDescriptors)
		}
	}
	if !acsFound {
		t.Fatal("served metadata does not advertise the derived ACS")
	}

	// Rotation compat: the same old-shape deployment rides the dual-certificate
	// window and the swap, and every configured value survives.
	p.mu.Lock()
	p.dualCerts = true
	p.mu.Unlock()
	before := samlCompatShapeOf(sp)
	samlCompatLogin(t, h, p) // old cert still valid inside the window
	samlCompatAssertSwapPreservesShape(t, sp, before)
	samlCompatLogin(t, h, p) // post-swap login still works, same shape

	// The audit trail keeps naming the IdP entity after the swap (the login
	// detail line is the operator's rotation evidence).
	last := h.store.lastAuditRecord(t)
	if !strings.Contains(last.Details, "sso=saml,idp="+before.idpEntity) {
		t.Fatalf("post-swap audit details %q lost the IdP entity %q", last.Details, before.idpEntity)
	}
}

// TestSAMLCompat_NewShapesEnvWalkthrough walks the newer configuration shapes
// through the same consumers: the docker-secret _FILE URL, the explicit
// entity/ACS/role knobs, and both stable SP-pair encodings (PKCS8 and the
// legacy PKCS1 operators already hold).
func TestSAMLCompat_NewShapesEnvWalkthrough(t *testing.T) {
	t.Run("file_secret_metadata_url", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		secret := filepath.Join(t.TempDir(), "saml_metadata_url")
		if err := os.WriteFile(secret, []byte(p.server.URL+"/metadata\n"), 0o600); err != nil {
			t.Fatalf("write secret: %v", err)
		}
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL_FILE", secret)

		_, h := samlCompatWire(t, p, "admin.test")
		samlCompatLogin(t, h, p) // the _FILE URL pointed the SP at the fake IdP
	})

	t.Run("explicit_entity_acs_role", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
		t.Setenv("YABANIN_SAML_ENTITY_ID", "urn:yabanin:admin-compat")
		t.Setenv("YABANIN_SAML_ACS_URL", "https://sso-admin.test/auth/saml/acs")
		t.Setenv("YABANIN_SAML_ROLE_ATTR", "role")

		sp, h := samlCompatWire(t, p, "unused-domain.test")
		if got := sp.SP.EntityID; got != "urn:yabanin:admin-compat" {
			t.Fatalf("explicit entity: got %q", got)
		}
		if got := sp.SP.AcsURL.String(); got != "https://sso-admin.test/auth/saml/acs" {
			t.Fatalf("explicit ACS: got %q", got)
		}
		if got := sp.RoleAttribute; got != "role" {
			t.Fatalf("explicit role attribute: got %q", got)
		}
		samlCompatLogin(t, h, p)

		// The explicit entity ID is a hard audience binding: an assertion for
		// a different SP entity is refused (an explicit shape must not loosen
		// the audience to "anything").
		p.registerSP(t, sp, "urn:another:sp")
		samlCompatRefusedLogin(t, h, p)
	})

	t.Run("pkcs8_stable_pair", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
		key, cert := samlTestSPIdentity(t)
		keyPath, certPath := samlCompatWritePair(t, key, cert, false)
		t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
		t.Setenv("YABANIN_SAML_SP_CERT_FILE", certPath)

		sp, h := samlCompatWire(t, p, "admin.test")
		if !bytes.Equal(sp.SP.Certificate.Raw, cert.Raw) {
			t.Fatal("PKCS8 pair: the file certificate must be used verbatim")
		}
		samlCompatLogin(t, h, p)
	})

	t.Run("pkcs1_legacy_pair", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
		key, cert := samlTestSPIdentity(t)
		keyPath, certPath := samlCompatWritePair(t, key, cert, true)
		t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
		t.Setenv("YABANIN_SAML_SP_CERT_FILE", certPath)

		sp, h := samlCompatWire(t, p, "admin.test")
		if !bytes.Equal(sp.SP.Certificate.Raw, cert.Raw) {
			t.Fatal("PKCS1 legacy pair: the file certificate must be used verbatim")
		}
		samlCompatLogin(t, h, p) // operators on the legacy encoding keep logging in
	})
}

// samlCompatWritePair writes an operator-style SP signing pair (key + cert
// PEM files) and returns both paths. legacyPKCS1 renders the key in the
// "RSA PRIVATE KEY" encoding the load path keeps accepting for operators,
// otherwise the PKCS8 "PRIVATE KEY" form.
func samlCompatWritePair(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, legacyPKCS1 bool) (string, string) {
	t.Helper()
	var keyPEM []byte
	if legacyPKCS1 {
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	} else {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal PKCS8: %v", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "sp.key")
	certPath := filepath.Join(dir, "sp.crt")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return keyPath, certPath
}

// ---- unsupported shapes -----------------------------------------------------

// TestSAMLCompat_UnsupportedShapesRefusedLoudly walks configurations the
// product does not support through the wiring consumer: every one must be
// refused AT STARTUP with an explanatory error, and the deployment consequence
// is exactly "SAML unmounted, password console intact" — never a half-mounted
// SSO and never a silent fallback.
func TestSAMLCompat_UnsupportedShapesRefusedLoudly(t *testing.T) {
	// A metadata endpoint serving a document without any IDPSSODescriptor —
	// structurally valid SAML metadata for something that cannot log us in.
	noDescriptor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:hollow"></EntityDescriptor>`))
	}))
	t.Cleanup(noDescriptor.Close)
	// The realistic operator mistake: the metadata URL pointed at the IdP's
	// realm JSON document instead of the SAML descriptor.
	notMetadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"realm":"master","not":"saml metadata"}`))
	}))
	t.Cleanup(notMetadata.Close)

	cells := []struct {
		name    string
		domain  string // admin domain handed to the wiring ("" = none, like an unconfigured deployment)
		setup   func(t *testing.T, p *fakeSAMLIdP)
		wantErr string // substring of the loud refusal; "" = any refusal
	}{
		{
			name:   "plain_http_metadata_url",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "http://idp.example.test/metadata")
			},
			wantErr: "https",
		},
		{
			name:   "relative_metadata_url",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "idp.test/metadata")
			},
			wantErr: "absolute",
		},
		{
			name:   "metadata_without_idp_sso_descriptor",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", noDescriptor.URL)
			},
			wantErr: "IDPSSODescriptor",
		},
		{
			name:   "url_is_not_a_metadata_document",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", notMetadata.URL)
			},
			wantErr: "fetch",
		},
		{
			name: "acs_underivable_no_domain",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", "https://idp.example.test/metadata")
				// No ACS URL and an empty admin domain: the ACS cannot be
				// derived, so there is no supported configuration to mount.
			},
			wantErr: "ACS URL",
		},
		{
			name:   "half_sp_pair_key_only",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
				key, cert := samlTestSPIdentity(t)
				keyPath, _ := samlCompatWritePair(t, key, cert, false)
				t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
			},
			wantErr: "unmounted",
		},
		{
			name:   "unsupported_key_pem_type",
			domain: "admin.test",
			setup: func(t *testing.T, p *fakeSAMLIdP) {
				t.Helper()
				t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
				key, cert := samlTestSPIdentity(t)
				keyPath, certPath := samlCompatWritePair(t, key, cert, false)
				// Overwrite the key file with a PEM type the loader refuses
				// (a public key is not a signing key).
				pub, err := x509.MarshalPKIXPublicKey(key.Public())
				if err != nil {
					t.Fatalf("marshal public key: %v", err)
				}
				if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o600); err != nil {
					t.Fatalf("write public key: %v", err)
				}
				t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
				t.Setenv("YABANIN_SAML_SP_CERT_FILE", certPath)
			},
			wantErr: "unmounted",
		},
	}

	for _, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			samlCompatClearEnv(t)
			p := newFakeSAMLIdP(t)
			cell.setup(t, p)
			if _, _, err := samlCompatTryWire(t, p, cell.domain); err == nil {
				t.Fatal("unsupported configuration must be refused at the wiring step")
			} else if cell.wantErr != "" && !strings.Contains(err.Error(), cell.wantErr) {
				t.Fatalf("refusal must name the problem (want %q in %q)", cell.wantErr, err.Error())
			}
			// The consumer consequence of the refusal: SAML never mounts and
			// the console keeps the password flow.
			samlCompatUnmountedParity(t)
		})
	}
}

// TestSAMLCompat_MetadataSwapPreservesShape pins the compatibility invariant
// under rotation for BOTH shape families: a successful metadata swap replaces
// the trust document and nothing else — addressing, role attribute, IdP
// identity and (where configured) the SP signing pair are identical
// afterwards, and logins keep working through the same handlers.
func TestSAMLCompat_MetadataSwapPreservesShape(t *testing.T) {
	t.Run("old_shape_derived", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
		sp, h := samlCompatWire(t, p, "admin.test")

		samlCompatLogin(t, h, p)
		before := samlCompatShapeOf(sp)

		// Rotation: the IdP mints responses under a new key the cached trust
		// does not carry — refused until the refresh, accepted after, shape
		// untouched.
		p.rotateSigningIdentity(t)
		samlCompatRefusedLogin(t, h, p)
		samlCompatAssertSwapPreservesShape(t, sp, before)
		samlCompatLogin(t, h, p)
	})

	t.Run("new_shape_explicit_and_pinned_pair", func(t *testing.T) {
		samlCompatClearEnv(t)
		p := newFakeSAMLIdP(t)
		t.Setenv("YABANIN_SAML_IDP_METADATA_URL", p.server.URL+"/metadata")
		t.Setenv("YABANIN_SAML_ENTITY_ID", "urn:yabanin:admin-compat")
		t.Setenv("YABANIN_SAML_ACS_URL", "https://sso-admin.test/auth/saml/acs")
		t.Setenv("YABANIN_SAML_ROLE_ATTR", "role")
		key, cert := samlTestSPIdentity(t)
		keyPath, certPath := samlCompatWritePair(t, key, cert, false)
		t.Setenv("YABANIN_SAML_SP_KEY_FILE", keyPath)
		t.Setenv("YABANIN_SAML_SP_CERT_FILE", certPath)

		sp, h := samlCompatWire(t, p, "unused-domain.test")
		samlCompatLogin(t, h, p)
		before := samlCompatShapeOf(sp)

		p.rotateSigningIdentity(t)
		samlCompatRefusedLogin(t, h, p)
		samlCompatAssertSwapPreservesShape(t, sp, before)
		samlCompatLogin(t, h, p)
	})
}
