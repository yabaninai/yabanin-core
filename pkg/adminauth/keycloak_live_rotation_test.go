//go:build integration

package adminauth

// N04 live-IdP rotation evidence (N04-P01 T02 "discovery JWKS rotation
// claims" + N04-P02 T06 "real login and rotation"): the realm signing key is
// rotated INSIDE the running Keycloak while the consumers keep working, and
// the retired key stops trusting after the metadata refresh.
//
// Sequence (all against the same live realm, no process restarts):
//
//	phase 0  baseline: capture a real ID token (kid K1) and a real signed
//	         SAML response (signed by K1, unconsumed at the ACS);
//	phase 1  dual-publish window: a second realm RSA key is added; Keycloak
//	         publishes BOTH certificates (JWKS + SAML metadata); the SP's
//	         metadata refresh adopts both; the K1-signed artifacts validate;
//	phase 2  signer switch: the new key takes priority; fresh ID tokens
//	         carry the new kid and verify through the SAME live client
//	         (go-oidc refetches the keyset on the unknown kid); fresh SAML
//	         responses signed by the new certificate validate against the
//	         UN-refreshed SP (the alternate published certificate is already
//	         inside the dual trust set);
//	phase 3  retirement: the original key provider is deleted; JWKS and SAML
//	         metadata drop the certificate; after the SP's metadata refresh
//	         the K1-signed ID token is rejected by a freshly constructed
//	         client verifier and the K1-signed SAML response is rejected by
//	         ParseACSResponse; brand-new artifacts keep validating.
//
// This file runs after keycloak_live_e2e_test.go (file order) so the
// baseline flows see the pre-rotation realm.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
)

const kcRotationKeyName = "n04-rotation-key"

func TestKeycloakLiveCertRotationSequence(t *testing.T) {
	stand := KeycloakLiveStand(t)
	ctx := context.Background()

	// Defensive reset (a fresh realm never carries one; a retried run might).
	_ = stand.DeleteRSAKeyProvider(ctx, kcRotationKeyName)
	basePriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}

	// The SP used for the SAML half: ACS/entity on a discard endpoint — the
	// responses are validated directly through ParseACSResponse, no console.
	const captureACS = "http://localhost:9/auth/saml/acs"
	const captureEntity = "http://localhost:9"
	// The realm template ships a placeholder entity ID; the live client is
	// bound to the capture endpoints through the admin API (the same call the
	// console e2e uses for its random port).
	if err := stand.ConfigureSAMLClient(ctx, captureEntity, captureACS); err != nil {
		t.Fatalf("ConfigureSAMLClient: %v", err)
	}
	sp, err := NewSAMLSP(ctx, SAMLOptions{
		IDPMetadataURL: stand.RealmURL + "/protocol/saml/descriptor",
		EntityID:       captureEntity,
		ACSURL:         captureACS,
	})
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}

	keyDescriptors := func(theSP *SAMLSP) int {
		n := 0
		for _, d := range theSP.currentSP().IDPMetadata.IDPSSODescriptors {
			n += len(d.KeyDescriptors)
		}
		return n
	}

	// parseACSErr validates a captured response against the SP; the error
	// carries the crewjam PrivateErr reason when available.
	parseACSErr := func(theSP *SAMLSP, responseB64, requestID string) (*saml.Assertion, error) {
		form := url.Values{"SAMLResponse": {responseB64}}.Encode()
		req := httptest.NewRequest(http.MethodPost, captureACS, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assertion, err := theSP.ParseACSResponse(req, requestID)
		if err != nil {
			var invalid *saml.InvalidResponseError
			if errors.As(err, &invalid) && invalid.PrivateErr != nil {
				return nil, errors.New("reason: " + invalid.PrivateErr.Error())
			}
		}
		return assertion, err
	}

	assertAccepted := func(t *testing.T, theSP *SAMLSP, responseB64, requestID string) {
		t.Helper()
		assertion, err := parseACSErr(theSP, responseB64, requestID)
		if err != nil {
			t.Fatalf("ParseACSResponse must accept: %v", err)
		}
		email, err := AssertionEmail(assertion)
		if err != nil || email != "sso-root@test.io" {
			t.Fatalf("assertion identity: got (%q, err %v)", email, err)
		}
	}

	assertRejected := func(t *testing.T, theSP *SAMLSP, responseB64, requestID string, wantReason string) {
		t.Helper()
		_, err := parseACSErr(theSP, responseB64, requestID)
		if err == nil {
			t.Fatal("ParseACSResponse must reject")
		}
		if wantReason != "" && !strings.Contains(err.Error(), wantReason) {
			t.Fatalf("rejection reason %q does not mention %q", err.Error(), wantReason)
		}
	}

	captureSAMLResponse := func(t *testing.T) (responseB64, requestID string) {
		t.Helper()
		browser := NewKCBrowser()
		authn, err := sp.NewAuthnRequest("")
		if err != nil {
			t.Fatalf("NewAuthnRequest: %v", err)
		}
		hops := browser.DriveSSO(t, authn.RedirectURL, KCUserRoot, KCPassRoot, "")
		offer := browser.SAMLOffer(t, hops)
		return offer.SAMLResponse, authn.Flow.RequestID
	}

	// ---- phase 0: baseline captures (K1 signs everything) ------------------
	t.Run("phase0_baseline_captures", func(t *testing.T) {
		kids, err := stand.JWKSKids(ctx)
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		if len(kids) != 1 {
			t.Fatalf("pre-rotation JWKS must carry exactly one signing key, got %v", kids)
		}
		tok1, claims1 := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
		if got := claims1["iss"]; got != stand.RealmURL {
			t.Fatalf("id_token iss %v, want %v", got, stand.RealmURL)
		}
		if got := claims1["aud"]; got != KCLiveOIDCClientID {
			t.Fatalf("id_token aud %v, want %v", got, KCLiveOIDCClientID)
		}
		if got := claims1["email"]; got != "sso-root@test.io" {
			t.Fatalf("id_token email %v", got)
		}
		if groups, ok := claims1["groups"].([]any); !ok || len(groups) == 0 || groups[0] != "platform-team" {
			t.Fatalf("id_token groups %v, want [platform-team]", claims1["groups"])
		}
		kcRotationState.token1 = tok1
		kcRotationState.kid1 = kcJWTHeaderKid(t, tok1)
		if kcRotationState.kid1 == "" {
			t.Fatal("id_token header carries no kid")
		}
		kcRotationState.offer1, kcRotationState.requestID1 = captureSAMLResponse(t)
		kcRotationState.cert1 = kcResponseCert(kcRotationState.offer1)
		kcRotationState.captured1At = time.Now()
		if kcRotationState.cert1 == "" {
			t.Fatal("captured SAML response carries no signing certificate")
		}
	})

	// ---- phase 1: dual-publish window --------------------------------------
	t.Run("phase1_dual_publish_window", func(t *testing.T) {
		if err := stand.AddRSAKeyProvider(ctx, kcRotationKeyName, basePriority-10); err != nil {
			t.Fatalf("add rotation key: %v", err)
		}
		kids, err := stand.JWKSKids(ctx)
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		kcRotationState.kid2 = kcOtherKid(kids, kcRotationState.kid1)
		if kcRotationState.kid2 == "" {
			t.Fatalf("JWKS must publish BOTH keys during rotation, got %v", kids)
		}
		certs, err := stand.SAMLSigningCertCount(ctx)
		if err != nil {
			t.Fatalf("saml descriptor: %v", err)
		}
		if certs != 2 {
			t.Fatalf("SAML metadata must publish both signing certs during the window, got %d", certs)
		}
		// The SP adopts both certificates through the real metadata refresh.
		if err := sp.RefreshMetadata(ctx); err != nil {
			t.Fatalf("RefreshMetadata: %v", err)
		}
		if got := keyDescriptors(sp); got != 2 {
			t.Fatalf("SP trusts %d key descriptors after the dual-publish refresh, want 2", got)
		}
		// The K1-signed response validates inside the window.
		assertAccepted(t, sp, kcRotationState.offer1, kcRotationState.requestID1)
		// The K1-signed ID token verifies through the production client.
		verifier := kcLiveClientVerifier(t, stand)
		idTok, err := verifier.Verify(ctx, kcRotationState.token1)
		if err != nil {
			t.Fatalf("pre-rotation id_token must verify: %v", err)
		}
		var vc struct {
			Email  string   `json:"email"`
			Groups []string `json:"groups"`
		}
		if err := idTok.Claims(&vc); err != nil {
			t.Fatalf("verified claims: %v", err)
		}
		if vc.Email != "sso-root@test.io" || len(vc.Groups) == 0 || vc.Groups[0] != "platform-team" {
			t.Fatalf("verified claims: %+v", vc)
		}
	})

	// ---- phase 2: signer switch, forward transition -------------------------
	t.Run("phase2_signer_switch", func(t *testing.T) {
		if err := stand.SetRSAKeyPriority(ctx, kcRotationKeyName, basePriority+100); err != nil {
			t.Fatalf("bump rotation key priority: %v", err)
		}
		tok2, _ := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
		kid2 := kcJWTHeaderKid(t, tok2)
		if kid2 != kcRotationState.kid2 {
			t.Fatalf("signer did not switch: new token kid %q, want the rotation key %q", kid2, kcRotationState.kid2)
		}
		// The SAME production client construction (go-oidc remote keyset)
		// accepts the new kid by refetching the published keyset — the
		// rotation forward transition with no process restart and no console
		// reconfiguration.
		verifier := kcLiveClientVerifier(t, stand)
		if _, err := verifier.Verify(ctx, tok2); err != nil {
			t.Fatalf("post-switch id_token must verify through the live keyset refetch: %v", err)
		}
		// A fresh SAML response is now signed by the OTHER published cert and
		// validates against the UN-refreshed SP (still carrying the dual
		// trust set from phase 1) — the alternate-cert forward window.
		response2, requestID2 := captureSAMLResponse(t)
		cert2 := kcResponseCert(response2)
		if cert2 == "" || cert2 == kcRotationState.cert1 {
			t.Fatal("signer switch must be visible: the new response carries a different signing certificate")
		}
		assertAccepted(t, sp, response2, requestID2)
		kcRotationState.cert2 = cert2
	})

	// ---- phase 3: retirement → old artifacts rejected -----------------------
	t.Run("phase3_retire_old_key", func(t *testing.T) {
		if elapsed := time.Since(kcRotationState.captured1At); elapsed > 60*time.Second {
			t.Fatalf("phase timing budget blown (%s since the K1 response capture); the retirement rejection below would otherwise trip crewjam's IssueInstant window for the wrong reason", elapsed)
		}
		if err := stand.DeleteRSAKeyProvider(ctx, "rsa-generated"); err != nil {
			t.Fatalf("delete original key provider: %v", err)
		}
		kids, err := stand.JWKSKids(ctx)
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		for _, k := range kids {
			if k == kcRotationState.kid1 {
				t.Fatalf("retired kid %q still published in the JWKS: %v", k, kids)
			}
		}
		certs, err := stand.SAMLSigningCertCount(ctx)
		if err != nil {
			t.Fatalf("saml descriptor: %v", err)
		}
		if certs != 1 {
			t.Fatalf("SAML metadata must drop the retired cert, got %d signing certs", certs)
		}
		if err := sp.RefreshMetadata(ctx); err != nil {
			t.Fatalf("RefreshMetadata: %v", err)
		}
		if got := keyDescriptors(sp); got != 1 {
			t.Fatalf("SP trusts %d key descriptors after retirement, want 1", got)
		}

		// The retired-key ID token is rejected by a FRESHLY constructed
		// production client — exactly what a (re)started console uses. (The
		// in-process go-oidc keyset cache does not proactively re-fetch: a
		// long-lived process keeps cached keys until an unknown kid forces a
		// refetch; that cache strategy is go-oidc's documented behavior and
		// is recorded here as context, not silently claimed as a pass.)
		fresh, err := NewOIDCClient(ctx, stand.RealmURL, KCLiveOIDCClientID, KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback")
		if err != nil {
			t.Fatalf("fresh OIDC client: %v", err)
		}
		if _, err := fresh.verifier.Verify(ctx, kcRotationState.token1); err == nil {
			t.Fatal("a token signed by the RETIRED key must be rejected by the fresh client verifier")
		}
		// The retired-cert SAML response (still InResponseTo-consistent) is
		// rejected by the refreshed SP — trust left with the metadata.
		assertRejected(t, sp, kcRotationState.offer1, kcRotationState.requestID1, "")

		// And the rotation is over: brand-new artifacts validate.
		tok3, _ := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
		if _, err := fresh.verifier.Verify(ctx, tok3); err != nil {
			t.Fatalf("post-rotation id_token must verify: %v", err)
		}
		response3, requestID3 := captureSAMLResponse(t)
		assertAccepted(t, sp, response3, requestID3)
	})
}

// kcRotationState carries the captured real artifacts across the ordered
// subtests of one rotation run (one binary = one realm = one sequence).
var kcRotationState struct {
	token1      string // real pre-rotation ID token (kid1-signed)
	kid1        string
	kid2        string
	offer1      string    // base64 SAMLResponse signed by kid1's cert, unconsumed
	requestID1  string    // its AuthnRequest ID (InResponseTo)
	captured1At time.Time // IssueInstant freshness budget guard (crewjam 90s)
	cert1       string
	cert2       string
}

// kcLiveClientVerifier builds a verifier through the production entry point
// (NewOIDCClient) and returns its actual verifier object — the internal test
// package reaches the unexported field, so the evidence is the REAL consumer
// object, not a lookalike.
func kcLiveClientVerifier(t *testing.T, stand *KCStand) *oidc.IDTokenVerifier {
	t.Helper()
	client, err := NewOIDCClient(context.Background(), stand.RealmURL, KCLiveOIDCClientID, KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	return client.verifier
}

func kcJWTHeaderKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		t.Fatalf("decode id_token header: %v", err)
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("id_token header: %v", err)
	}
	return header.KID
}

func kcOtherKid(kids []string, except string) string {
	for _, k := range kids {
		if k != except {
			return k
		}
	}
	return ""
}

// kcResponseCert extracts the first signing certificate (base64 DER, with
// whitespace stripped) from a base64-encoded SAML response document.
func kcResponseCert(responseB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(responseB64)
	if err != nil {
		return ""
	}
	doc := string(raw)
	start := -1
	for _, tag := range []string{"<dsig:X509Certificate>", "<ds:X509Certificate>", "<X509Certificate>"} {
		if i := strings.Index(doc, tag); i >= 0 {
			start = i + len(tag)
			break
		}
	}
	if start < 0 {
		return ""
	}
	end := strings.Index(doc[start:], "<")
	if end < 0 {
		return ""
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '+', r == '/', r == '=':
			return r
		default:
			return -1
		}
	}, doc[start:start+end])
}
