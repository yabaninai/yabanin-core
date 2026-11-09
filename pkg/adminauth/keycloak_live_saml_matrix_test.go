//go:build integration

package adminauth_test

// Joint-scenario live matrix for the supported SAML surface of the admin
// console, driven against the REAL local Keycloak stand over the full
// console round trip (production handlers, real signed assertions). Each
// cell pairs with a mock companion so the matrix stays legible on both
// levels — unit-verified shapes here validated against a live IdP:
//
//	sp_metadata_capability  — TestSAML_Metadata_Served (mock)
//	post_binding_login      — TestSAML_NewAuthnRequest_PostBindingFallback (mock)
//	mapping_unknown_email   — TestSAML_UnknownEmail_Refused_NoJIT (mock)
//	mapping_disabled_user   — TestSAML_DisabledUser_Refused (mock)
//	replay_with_flow_cookie — TestSAML_Replay_Rejected (mock)
//	unsigned_assertion      — TestSAML_BadSignature_Rejected (mock)
//	local_slo_after_login   — TestSAML_SLORevokesSessionServerSide (mock)
//	cert_rotation_login     — TestKeycloakLiveCertRotationSequence (live,
//	                          pinned to ParseACSResponse; this cell binds
//	                          the same rotation to live console logins)
//
// File order note: this file sorts after keycloak_live_rotation_test.go,
// whose exit state (the realm's original key provider deleted) this test
// inherits; every key priority below is therefore computed from the live
// PrimaryRSAPriority, never assumed.

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	kcMatrixKeyName       = "n04-matrix-key"
	kcMatrixPass          = "n04-matrix-pass-2026"
	kcMatrixNobodyEmail   = "nobody@test.io"
	kcMatrixOffEmail      = "off@test.io"
	kcMatrixSessionCookie = "yabanin_admin_session"
	kcMatrixCSRFCookie    = "yabanin_csrf_token"
)

// TestKeycloakLive_SAML_Matrix runs the ordered matrix cells on one console.
// The order matters only for readability; each cell seeds its own IdP state
// and restores the realm on exit.
func TestKeycloakLive_SAML_Matrix(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, _ := kcLiveWorld(t, pool)
	console, sp := kcSAMLConsole(t, stand, pool)
	ctx := context.Background()

	// Defensive reset: a retried run may still carry the rotation key.
	_ = stand.DeleteRSAKeyProvider(ctx, kcMatrixKeyName)
	t.Cleanup(func() { _ = stand.DeleteRSAKeyProvider(context.Background(), kcMatrixKeyName) })

	// fullLogin drives one complete SP-initiated login round trip and
	// returns the console ACS response plus the signing certificate the
	// IdP used for the assertion. It reports on the caller t so cells keep their own
	// failure attribution.
	fullLogin := func(t *testing.T, username, password string) (kcResp, string, *adminauth.KCBrowser) {
		t.Helper()
		browser := adminauth.NewKCBrowser()
		start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
		if start.status != http.StatusFound {
			t.Fatalf("saml login start: got %d, want 302; body %s", start.status, kcSnippet(start.body))
		}
		hops := browser.DriveSSO(t, start.location, username, password, "")
		offer := browser.SAMLOffer(t, hops)
		resp := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
		return resp, kcMatrixCert(t, offer), browser
	}

	t.Run("sp_metadata_capability", func(t *testing.T) {
		md := console.get(t, adminauth.NewKCBrowser(), console.base.String()+adminauth.SAMLMetadataPath)
		if md.status != http.StatusOK {
			t.Fatalf("sp metadata: got %d; body %s", md.status, kcSnippet(md.body))
		}
		if ct := md.body; !strings.Contains(ct, adminauth.SAMLACSPath) {
			t.Fatalf("sp metadata must advertise the ACS endpoint; body %s", kcSnippet(md.body))
		}
		if !strings.Contains(md.body, `use="signing"`) {
			t.Fatal("sp metadata must carry a signing key descriptor")
		}
		if strings.Contains(md.body, `use="encryption"`) {
			t.Fatal("sp metadata must not offer assertion encryption — the supported matrix is signature-only")
		}
	})

	t.Run("post_binding_login", func(t *testing.T) {
		// Narrow the console SP's view of the IdP to POST-only SSO
		// endpoints, so the production POST-binding fallback branch (signed
		// AuthnRequest in an auto-submitting form) must engage end to end
		// through the real IdP. The realm client ships without
		// WantAuthnRequestsSigned, and this Keycloak accepts the signed
		// request and moves on (validated request signatures are an IdP
		// policy, not part of the supported console matrix). RefreshMetadata
		// restores the unmodified metadata afterwards.
		narrowed := false
		for i := range sp.SP.IDPMetadata.IDPSSODescriptors {
			d := &sp.SP.IDPMetadata.IDPSSODescriptors[i]
			var postOnly []saml.Endpoint
			for _, svc := range d.SingleSignOnServices {
				if svc.Binding == saml.HTTPPostBinding {
					postOnly = append(postOnly, svc)
				}
			}
			if len(postOnly) == 0 {
				t.Fatal("IdP metadata carries no POST SSO endpoint; fixture mismatch")
			}
			if len(postOnly) != len(d.SingleSignOnServices) {
				narrowed = true
			}
			d.SingleSignOnServices = postOnly
		}
		if !narrowed {
			t.Fatal("expected a redirect binding to drop; fixture mismatch")
		}
		t.Cleanup(func() {
			if err := sp.RefreshMetadata(context.Background()); err != nil {
				t.Logf("restore IdP metadata after the POST-binding cell: %v", err)
			}
		})

		browser := adminauth.NewKCBrowser()
		start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
		if start.status != http.StatusOK {
			t.Fatalf("post-bound login start: got %d, want 200 auto-submit form; body %s", start.status, kcSnippet(start.body))
		}
		action, samlRequest := kcMatrixAutoSubmit(start.body)
		if action == "" || samlRequest == "" {
			t.Fatalf("auto-submit form incomplete: %s", kcSnippet(start.body))
		}
		if !strings.Contains(action, "/protocol/saml") {
			t.Fatalf("POST action %q is not the IdP SSO endpoint", action)
		}
		if browser.Jar.Cookie(console.base, adminauth.SAMLFlowCookieName) == "" {
			t.Fatal("the POST path did not set the flow cookie")
		}

		// Submit the signed POST AuthnRequest the way a browser would: a
		// form POST whose reply hands control to the IdP's login UI.
		idpResp, err := browser.Client.PostForm(action, url.Values{"SAMLRequest": {samlRequest}})
		if err != nil {
			t.Fatalf("SAMLRequest POST: %v", err)
		}
		idpBody, err := io.ReadAll(idpResp.Body)
		if err != nil {
			t.Fatalf("SAMLRequest POST body: %v", err)
		}
		idpResp.Body.Close()

		// Drive the interactive half from wherever the IdP put us: either a
		// redirect to the login UI or the login form rendered directly (its
		// action URL is GET-able and re-renders the form).
		target := idpResp.Header.Get("Location")
		if target == "" {
			if target = kcMatrixFormAction(string(idpBody), "kc-form-login"); target == "" {
				t.Fatalf("IdP answered %d without a redirect or login form: %s", idpResp.StatusCode, kcSnippet(string(idpBody)))
			}
		}
		hops := browser.DriveSSO(t, target, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
		offer := browser.SAMLOffer(t, hops)
		callback := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
		if callback.status != http.StatusFound || callback.location != "/" {
			t.Fatalf("acs after POST-bound request: got %d → %q; body %s", callback.status, callback.location, kcSnippet(callback.body))
		}
		if sess := console.sessionOf(t, callback); sess == nil || sess.Email != kcAdminEmail {
			t.Fatalf("POST-bound login session: got %+v", sess)
		}
		if !console.flowCookieCleared(t, callback, adminauth.SAMLFlowCookieName) {
			t.Fatal("acs did not clear the one-time flow cookie on the POST path")
		}
		if probe := console.get(t, browser, console.base.String()+"/api/me"); probe.status != http.StatusOK || !strings.Contains(probe.body, kcAdminEmail) {
			t.Fatalf("/api/me with a POST-bound SAML session: got %d; body %s", probe.status, kcSnippet(probe.body))
		}
	})

	t.Run("mapping_unknown_email", func(t *testing.T) {
		if err := stand.EnsureRealmUser(ctx, "sso-nobody", "N04 Nobody", kcMatrixNobodyEmail, kcMatrixPass); err != nil {
			t.Fatalf("seed unknown realm user: %v", err)
		}
		resp, _, browser := fullLogin(t, "sso-nobody", kcMatrixPass)
		if resp.status != http.StatusForbidden || !strings.Contains(resp.body, "sso login refused") {
			t.Fatalf("unknown IdP identity: got %d; body %s", resp.status, kcSnippet(resp.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatal("unknown IdP identity produced a session")
		}
		if !console.flowCookieCleared(t, resp, adminauth.SAMLFlowCookieName) {
			t.Fatal("refused login did not clear the one-time flow cookie")
		}
		// Refusal is not provisioning: no local account may appear.
		if _, err := store.GetAdminUserByEmail(ctx, kcMatrixNobodyEmail); err == nil {
			t.Fatal("unknown IdP identity was provisioned locally")
		}
	})

	t.Run("mapping_disabled_user", func(t *testing.T) {
		user, err := store.CreateAdminUser(ctx, kcMatrixOffEmail, "N04 Off", "unused-by-sso", false)
		if err != nil {
			t.Fatalf("seed disabled admin: %v", err)
		}
		if err := store.UpdateAdminUserActive(ctx, user.ID, false); err != nil {
			t.Fatalf("deactivate admin: %v", err)
		}
		if err := stand.EnsureRealmUser(ctx, "sso-off", "N04 Off", kcMatrixOffEmail, kcMatrixPass); err != nil {
			t.Fatalf("seed disabled realm user: %v", err)
		}

		resp, _, browser := fullLogin(t, "sso-off", kcMatrixPass)
		if resp.status != http.StatusForbidden || !strings.Contains(resp.body, "sso login refused") {
			t.Fatalf("disabled user: got %d; body %s", resp.status, kcSnippet(resp.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatal("disabled user produced a session")
		}

		// The refusal is exactly the active flag, nothing sticky: after
		// re-activation the same IdP identity logs in again.
		if err := store.UpdateAdminUserActive(ctx, user.ID, true); err != nil {
			t.Fatalf("re-activate admin: %v", err)
		}
		again, _, browser2 := fullLogin(t, "sso-off", kcMatrixPass)
		if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
			t.Fatalf("re-activated user login: got %d; body %s", again.status, kcSnippet(again.body))
		}
		if !console.hasSession(browser2.Jar) {
			t.Fatal("re-activated user login issued no session")
		}
	})

	t.Run("replay_with_flow_cookie", func(t *testing.T) {
		browser := adminauth.NewKCBrowser()
		start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
		if start.status != http.StatusFound {
			t.Fatalf("replay login start: got %d, want 302; body %s", start.status, kcSnippet(start.body))
		}
		flow := browser.Jar.Cookie(console.base, adminauth.SAMLFlowCookieName)
		if flow == "" {
			t.Fatal("replay precondition: no flow cookie after login start")
		}
		hops := browser.DriveSSO(t, start.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
		offer := browser.SAMLOffer(t, hops)
		first := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
		if first.status != http.StatusFound || console.sessionOf(t, first) == nil {
			t.Fatalf("replay first submit: got %d; body %s", first.status, kcSnippet(first.body))
		}

		// Re-plant the one-time flow cookie and repost the byte-identical
		// response: the refusal must come from the assertion replay guard
		// (401), not the weaker missing-cookie branch (403).
		browser.Jar.SetInjected(console.base, http.Cookie{Name: adminauth.SAMLFlowCookieName, Value: flow})
		replay := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
		if replay.status != http.StatusUnauthorized {
			t.Fatalf("replayed assertion: got %d, want 401; body %s", replay.status, kcSnippet(replay.body))
		}
		for _, ck := range replay.cookies {
			if ck.Name == kcMatrixSessionCookie {
				t.Fatal("replayed assertion set a session cookie")
			}
		}
	})

	t.Run("unsigned_assertion", func(t *testing.T) {
		// The IdP stops signing (document and assertion flags off through the
		// real admin API, as an operator misconfiguration would); the unsigned
		// response must fail closed with no session — the console never
		// accepts an assertion it could not verify.
		ctx := context.Background()
		if err := stand.SetSAMLSignFlags(ctx, false, false); err != nil {
			t.Fatalf("disable signing in Keycloak: %v", err)
		}
		t.Cleanup(func() {
			if err := stand.SetSAMLSignFlags(context.Background(), true, true); err != nil {
				t.Logf("restore IdP signing flags: %v", err)
			}
		})

		resp, _, browser := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if resp.status != http.StatusUnauthorized {
			t.Fatalf("unsigned assertion: got %d, want 401; body %s", resp.status, kcSnippet(resp.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatal("unsigned assertion produced a session")
		}
		for _, ck := range resp.cookies {
			if ck.Name == kcMatrixSessionCookie {
				t.Fatal("unsigned assertion set a session cookie")
			}
		}

		// The flags are the whole story: restored signing lets the same
		// identity straight back in (nothing sticky was created by the
		// refusal).
		if err := stand.SetSAMLSignFlags(ctx, true, true); err != nil {
			t.Fatalf("restore signing flags: %v", err)
		}
		again, _, browser2 := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
			t.Fatalf("login after signing restored: got %d; body %s", again.status, kcSnippet(again.body))
		}
		if !console.hasSession(browser2.Jar) {
			t.Fatal("login after signing restored issued no session")
		}
	})

	t.Run("local_slo_after_login", func(t *testing.T) {
		resp, _, browser := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if resp.status != http.StatusFound || console.sessionOf(t, resp) == nil {
			t.Fatalf("slo precondition login: got %d; body %s", resp.status, kcSnippet(resp.body))
		}
		sessionValue := browser.Jar.Cookie(console.base, kcMatrixSessionCookie)
		if sessionValue == "" {
			t.Fatal("slo precondition: no session cookie in the jar")
		}
		if probe := console.get(t, browser, console.base.String()+"/api/me"); probe.status != http.StatusOK || !strings.Contains(probe.body, kcAdminEmail) {
			t.Fatalf("/api/me before slo: got %d; body %s", probe.status, kcSnippet(probe.body))
		}

		slo := console.get(t, browser, console.base.String()+adminauth.SAMLSLOPath)
		if slo.status != http.StatusFound || !strings.HasSuffix(slo.location, "/auth/login") {
			t.Fatalf("slo: got %d → %q, want 302 → /auth/login", slo.status, slo.location)
		}
		if !console.flowCookieCleared(t, slo, kcMatrixSessionCookie) || !console.flowCookieCleared(t, slo, kcMatrixCSRFCookie) {
			t.Fatalf("slo must expire session and csrf cookies: %+v", slo.cookies)
		}

		// The revocation is server-side, not just a jar edit: planting the
		// captured session cookie back must not resurrect the session.
		browser.Jar.SetInjected(console.base, http.Cookie{Name: kcMatrixSessionCookie, Value: sessionValue})
		after := console.get(t, browser, console.base.String()+"/api/me")
		if after.status != http.StatusUnauthorized {
			t.Fatalf("revoked session still accepted: got %d; body %s", after.status, kcSnippet(after.body))
		}
	})

	t.Run("cert_rotation_login", func(t *testing.T) {
		topPriority, err := stand.PrimaryRSAPriority(ctx)
		if err != nil {
			t.Fatalf("primary key priority: %v", err)
		}
		before, err := stand.SAMLSigningCertCount(ctx)
		if err != nil {
			t.Fatalf("signing cert count: %v", err)
		}

		// Phase 1 — dual publish: the new key enters the IdP metadata while
		// the current signer stays primary. The production metadata refresh
		// picks both certificates up and logins keep working.
		if err := stand.AddRSAKeyProvider(ctx, kcMatrixKeyName, topPriority-10); err != nil {
			t.Fatalf("add rotation key: %v", err)
		}
		if n, err := stand.SAMLSigningCertCount(ctx); err != nil || n != before+1 {
			t.Fatalf("dual publish: got %d certs (err %v), want %d", n, err, before+1)
		}
		if err := sp.RefreshMetadata(ctx); err != nil {
			t.Fatalf("refresh metadata over the dual window: %v", err)
		}
		respA, certA, _ := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if respA.status != http.StatusFound || console.sessionOf(t, respA) == nil {
			t.Fatalf("login over the dual window: got %d; body %s", respA.status, kcSnippet(respA.body))
		}

		// Phase 2 — signer switch: the fresh key takes over signing and a
		// live console login must accept the new certificate.
		if err := stand.SetRSAKeyPriority(ctx, kcMatrixKeyName, topPriority+100); err != nil {
			t.Fatalf("promote rotation key: %v", err)
		}
		respB, certB, _ := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if respB.status != http.StatusFound || console.sessionOf(t, respB) == nil {
			t.Fatalf("login under the new signer: got %d; body %s", respB.status, kcSnippet(respB.body))
		}
		if certB == "" || certB == certA {
			t.Fatalf("signer did not switch: certB %q must differ from certA %q", certB, certA)
		}

		// Phase 3 — retire: the rotation key goes away, the production
		// refresh collapses the metadata back to one certificate and logins
		// keep working under the original signer.
		if err := stand.DeleteRSAKeyProvider(ctx, kcMatrixKeyName); err != nil {
			t.Fatalf("retire rotation key: %v", err)
		}
		if n, err := stand.SAMLSigningCertCount(ctx); err != nil || n != before {
			t.Fatalf("after retire: got %d certs (err %v), want %d", n, err, before)
		}
		if err := sp.RefreshMetadata(ctx); err != nil {
			t.Fatalf("refresh metadata after retire: %v", err)
		}
		respC, certC, _ := fullLogin(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
		if respC.status != http.StatusFound || console.sessionOf(t, respC) == nil {
			t.Fatalf("login after retire: got %d; body %s", respC.status, kcSnippet(respC.body))
		}
		if certC != certA {
			t.Fatalf("post-retire signer %q must be the original %q", certC, certA)
		}
	})
}

// kcMatrixAutoSubmit extracts the action URL and SAMLRequest value from the
// console's POST-binding auto-submit form (the only form on that page).
func kcMatrixAutoSubmit(page string) (action, samlRequest string) {
	chunk, _, _ := strings.Cut(strings.SplitN(page, "<form", 2)[1], "</form>")
	if m := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(chunk); m != nil {
		action = kcMatrixUnescape(m[1])
	}
	for _, inp := range regexp.MustCompile(`<input[^>]*>`).FindAllString(chunk, -1) {
		if !strings.Contains(inp, `name="SAMLRequest"`) {
			continue
		}
		if m := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(inp); m != nil {
			// The form is html/template-rendered, so the base64 payload
			// carries HTML-escaped "+" (as "&#43;"). A browser submits the
			// unescaped value; the test does the same.
			samlRequest = kcMatrixUnescape(m[1])
		}
	}
	return action, samlRequest
}

// kcMatrixFormAction extracts a form's action URL by its id attribute (used
// for the Keycloak login form the IdP may render directly).
func kcMatrixFormAction(page, formID string) string {
	for _, f := range strings.Split(page, "<form")[1:] {
		chunk, _, _ := strings.Cut(f, "</form>")
		if formID != "" && !regexp.MustCompile(`id="`+regexp.QuoteMeta(formID)+`"`).MatchString(chunk) {
			continue
		}
		if m := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(chunk); m != nil {
			return kcMatrixUnescape(m[1])
		}
	}
	return ""
}

// kcMatrixCert returns the base64-stripped X509Certificate of the first
// signature in a captured SAML response, or "" when the response carries no
// signature certificate (the unsigned_response cell submits exactly that).
// The element prefix is left open because IdPs differ (crewjam signs with
// "ds", Keycloak with "dsig").
func kcMatrixCert(t *testing.T, offer adminauth.SAMLOffer) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(offer.SAMLResponse)
	if err != nil {
		t.Fatalf("decode captured SAMLResponse: %v", err)
	}
	re := regexp.MustCompile(`(?s)<(?:[A-Za-z0-9_-]+:)?X509Certificate>([^<]+)</(?:[A-Za-z0-9_-]+:)?X509Certificate>`)
	m := re.FindStringSubmatch(string(raw))
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(m[1]), "")
}

// kcMatrixUnescape resolves the HTML entities the form attributes use. The
// console auto-submit form is html/template-rendered, which escapes "+"
// as "&#43;" inside attribute values; a browser decodes the entity when it
// parses the DOM, so the submitted form value is plain base64 — the test
// submits the same.
func kcMatrixUnescape(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&quot;", `"`, "&#39;", "'", "&#43;", "+", "&lt;", "<", "&gt;", ">")
	return r.Replace(s)
}
