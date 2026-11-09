//go:build integration

package adminauth_test

// Live boundary corpus for the supported SAML surface — the edges that
// depend on real IdP behavior and are therefore out of reach for the mock
// corpus in services/admin/handlers/auth_saml_boundary_test.go:
//
//   - signature anchor: Keycloak signs the response element, the assertion
//     element, or both (per-client flags). The SP must accept either single
//     anchor (crewjam v0.5.1: a signed response satisfies the signature
//     requirement; an unsigned response demands a signed assertion) and
//     refuse only when neither element carries a signature — the coarse
//     both-off negative lives in the matrix (unsigned_assertion);
//   - cross-instance wrapping replay: a real, fully valid offer captured at
//     one console instance and posted at another instance (fresh SP,
//     separate replay cache, its own flow cookie) is refused — replay
//     protection does not hinge on the per-process assertion cache alone.
//
// File order note: this file sorts between keycloak_live_rotation_test.go
// and keycloak_live_saml_matrix_test.go; the signing-flag cells restore both
// flags on cleanup so neighboring cells observe the pristine client.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// samlSigElementRe counts Signature and Assertion element opens regardless
// of the namespace prefix Keycloak binds them to.
var (
	samlSigElementRe       = regexp.MustCompile(`<(\w+:)?Signature[ >]`)
	samlAssertionElementRe = regexp.MustCompile(`<(\w+:)?Assertion[ >]`)
)

// TestKeycloakLive_SAML_Boundary_SignatureAnchor flips the real Keycloak
// client's per-element signing flags and drives a full login per cell. The
// cell also verifies placement in the captured offer, so a login that
// succeeds for the wrong reason (flags ignored, both elements signed) fails
// the corpus.
func TestKeycloakLive_SAML_Boundary_SignatureAnchor(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, _ := kcSAMLConsole(t, stand, pool)
	ctx := context.Background()

	t.Cleanup(func() { _ = stand.SetSAMLSignFlags(context.Background(), true, true) })

	for _, tc := range []struct {
		name                  string
		signDocs, signAsserts bool
	}{
		{"response_element_is_a_sufficient_anchor", true, false},
		{"assertion_element_is_a_sufficient_anchor", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := stand.SetSAMLSignFlags(ctx, tc.signDocs, tc.signAsserts); err != nil {
				t.Fatalf("set signing flags: %v", err)
			}

			browser := adminauth.NewKCBrowser()
			start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
			if start.status != http.StatusFound {
				t.Fatalf("saml login start: got %d; body %s", start.status, kcSnippet(start.body))
			}
			hops := browser.DriveSSO(t, start.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
			offer := browser.SAMLOffer(t, hops)

			// Placement: exactly one signature, on the element the flags
			// named. Anchor position in the raw response XML is the
			// contract under test, not an implementation detail.
			raw, err := base64.StdEncoding.DecodeString(offer.SAMLResponse)
			if err != nil {
				t.Fatalf("decode offer: %v", err)
			}
			sigs := samlSigElementRe.FindAllStringIndex(string(raw), -1)
			asserts := samlAssertionElementRe.FindAllStringIndex(string(raw), -1)
			if len(sigs) != 1 || len(asserts) != 1 {
				t.Fatalf("offer shape: %d signature(s), %d assertion(s); body %.400s", len(sigs), len(asserts), raw)
			}
			responseSigned := sigs[0][0] < asserts[0][0]
			if responseSigned != tc.signDocs {
				t.Fatalf("signature anchor misplaced: responseSigned=%v, want signDocuments=%v", responseSigned, tc.signDocs)
			}

			callback := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
			if callback.status != http.StatusFound || callback.location != "/" {
				t.Fatalf("acs under %s: got %d → %q; body %s", tc.name, callback.status, callback.location, kcSnippet(callback.body))
			}
			if sess := console.sessionOf(t, callback); sess == nil || sess.Email != kcAdminEmail {
				t.Fatalf("session under %s: got %+v", tc.name, sess)
			}
		})
	}
}

// TestKeycloakLive_SAML_Boundary_CrossInstanceReplayRefused replays a real,
// cryptographically valid offer captured at one console instance against a
// second instance with its own SP, replay cache and flow cookie. The realm
// carries exactly one SAML client (the stand retargets it in place), so the
// capture happens while the client points at console A and the replay lands
// after it points at console B — which is also why the signature still
// verifies (same realm keys) and the refusal must come from the flow
// pairing. Replay protection may not hinge on the per-process assertion
// cache alone; a restart must not reopen a replay window.
func TestKeycloakLive_SAML_Boundary_CrossInstanceReplayRefused(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	consoleA, _ := kcSAMLConsole(t, stand, pool)

	// Capture a valid offer at console A without submitting it.
	browserA := adminauth.NewKCBrowser()
	startA := consoleA.get(t, browserA, consoleA.base.String()+adminauth.SAMLLoginPath)
	if startA.status != http.StatusFound {
		t.Fatalf("console A login start: got %d; body %s", startA.status, kcSnippet(startA.body))
	}
	hopsA := browserA.DriveSSO(t, startA.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offerA := browserA.SAMLOffer(t, hopsA)

	// Bring up console B: the stand retargets the realm's single SAML
	// client to B's entity/ACS, so B is now the only valid flow partner.
	consoleB, _ := kcSAMLConsole(t, stand, pool)

	// Console B issues its flow cookie, but its IdP leg never runs: B has
	// minted no request the captured offer could answer.
	browserB := adminauth.NewKCBrowser()
	startB := consoleB.get(t, browserB, consoleB.base.String()+adminauth.SAMLLoginPath)
	if startB.status != http.StatusFound {
		t.Fatalf("console B login start: got %d; body %s", startB.status, kcSnippet(startB.body))
	}
	if browserB.Jar.Cookie(consoleB.base, adminauth.SAMLFlowCookieName) == "" {
		t.Fatal("console B did not set its flow cookie")
	}

	replay := consoleB.postForm(t, browserB, consoleB.base.String()+adminauth.SAMLACSPath,
		url.Values{"SAMLResponse": {offerA.SAMLResponse}})
	if replay.status != http.StatusUnauthorized {
		t.Fatalf("cross-instance replay: got %d, want 401; body %s", replay.status, kcSnippet(replay.body))
	}
	if consoleB.hasSession(browserB.Jar) {
		t.Fatal("cross-instance replay produced a session")
	}
}
