//go:build integration

package adminauth_test

// N04-P02-T08 [recovery] live cells on the REAL Keycloak stand (mock
// companions in services/admin/handlers/auth_saml_recovery_test.go):
//
//	abandoned_offer_recovery — the browser that died before the ACS post
//	    recovers: a fresh login in the same browser works immediately, the
//	    abandoned (response, flow cookie) pair stays redeemable EXACTLY
//	    once, the second submission is refused by the assertion replay
//	    guard, and no refusal costs the already-earned session —
//	    interruption duplicates nothing and locks nobody out;
//	rotation_resume — interrupted metadata refreshes (canceled context)
//	    during certificate rotation lose nothing: the cached trust keeps
//	    logins green across the failed refresh, the retried refresh
//	    completes the rotation, and a SECOND consecutive rotation cycle
//	    (interrupt-refresh → retry → retire) proves resume-ability.
//
// File order note: sorts after the matrix test; key priorities are computed
// from the live PrimaryRSAPriority, never assumed.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const kcRecoveryKeyName = "n04-recovery-key"

func TestKeycloakLive_SAML_Recovery_AbandonedOfferSingleRedemption(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, _ := kcSAMLConsole(t, stand, pool)

	// Flow A is interrupted after the IdP leg: capture the offer the
	// browser never submits, together with its one-time flow cookie.
	browser := adminauth.NewKCBrowser()
	start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
	if start.status != http.StatusFound {
		t.Fatalf("flow A start: got %d; body %s", start.status, kcSnippet(start.body))
	}
	flowA := browser.Jar.Cookie(console.base, adminauth.SAMLFlowCookieName)
	if flowA == "" {
		t.Fatal("flow A precondition: no flow cookie after login start")
	}
	hopsA := browser.DriveSSO(t, start.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offerA := browser.SAMLOffer(t, hopsA)

	// Recovery: a fresh login in the same browser supersedes the abandoned
	// flow — nothing about flow A blocks flow B.
	startB := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
	if startB.status != http.StatusFound {
		t.Fatalf("flow B start: got %d; body %s", startB.status, kcSnippet(startB.body))
	}
	hopsB := browser.DriveSSO(t, startB.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offerB := browser.SAMLOffer(t, hopsB)
	callbackB := console.postForm(t, browser, offerB.PostURL, url.Values{"SAMLResponse": {offerB.SAMLResponse}})
	if callbackB.status != http.StatusFound || console.sessionOf(t, callbackB) == nil {
		t.Fatalf("flow B (fresh login after interruption): got %d; body %s", callbackB.status, kcSnippet(callbackB.body))
	}
	sessB := console.sessionOf(t, callbackB)
	if sessB.Email != kcAdminEmail {
		t.Fatalf("flow B session identity: got %+v", sessB)
	}

	// Resume: the abandoned pair itself is still redeemable — exactly once.
	// Flow B's login start overwrote the jar's flow cookie, so plant flow A's
	// back before its delayed submission.
	browser.Jar.SetInjected(console.base, http.Cookie{Name: adminauth.SAMLFlowCookieName, Value: flowA})
	callbackA := console.postForm(t, browser, offerA.PostURL, url.Values{"SAMLResponse": {offerA.SAMLResponse}})
	if callbackA.status != http.StatusFound || console.sessionOf(t, callbackA) == nil {
		t.Fatalf("late redemption of the abandoned offer: got %d; body %s", callbackA.status, kcSnippet(callbackA.body))
	}
	sessA := console.sessionOf(t, callbackA)
	if sessA.SessionID == sessB.SessionID {
		t.Fatal("two live logins produced a duplicated session identity")
	}

	// The redeemed pair is dead: the replay guard refuses the second
	// submission and mints no duplicate session.
	browser.Jar.SetInjected(console.base, http.Cookie{Name: adminauth.SAMLFlowCookieName, Value: flowA})
	replay := console.postForm(t, browser, offerA.PostURL, url.Values{"SAMLResponse": {offerA.SAMLResponse}})
	if replay.status != http.StatusUnauthorized {
		t.Fatalf("second redemption of the abandoned offer: got %d, want 401; body %s", replay.status, kcSnippet(replay.body))
	}
	for _, ck := range replay.cookies {
		if ck.Name == kcMatrixSessionCookie && ck.Value != "" {
			t.Fatal("second redemption set a duplicate session cookie")
		}
	}

	// No losses: the earned session still authenticates the console.
	if probe := console.get(t, browser, console.base.String()+"/api/me"); probe.status != http.StatusOK || !strings.Contains(probe.body, kcAdminEmail) {
		t.Fatalf("/api/me after the replay refusals: got %d; body %s", probe.status, kcSnippet(probe.body))
	}
}

func TestKeycloakLive_SAML_Recovery_RotationResumesAfterInterruptedRefresh(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, sp := kcSAMLConsole(t, stand, pool)
	ctx := context.Background()

	// Defensive reset: a retried run may still carry the rotation key.
	_ = stand.DeleteRSAKeyProvider(ctx, kcRecoveryKeyName)
	t.Cleanup(func() { _ = stand.DeleteRSAKeyProvider(context.Background(), kcRecoveryKeyName) })

	fullLogin := func(t *testing.T) (kcResp, string) {
		t.Helper()
		browser := adminauth.NewKCBrowser()
		start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
		if start.status != http.StatusFound {
			t.Fatalf("login start: got %d; body %s", start.status, kcSnippet(start.body))
		}
		hops := browser.DriveSSO(t, start.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
		offer := browser.SAMLOffer(t, hops)
		resp := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
		return resp, kcMatrixCert(t, offer)
	}

	topPriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}

	// Baseline: login under the inherited signer.
	resp0, certA := fullLogin(t)
	if resp0.status != http.StatusFound || console.sessionOf(t, resp0) == nil {
		t.Fatalf("baseline login: got %d; body %s", resp0.status, kcSnippet(resp0.body))
	}

	// A pre-rotation key enters the realm, but the metadata refresh dies
	// mid-flight (canceled context — the operator's network hiccup). The
	// refresh must report the failure and the cached trust must keep
	// logins green under the unchanged signer.
	if err := stand.AddRSAKeyProvider(ctx, kcRecoveryKeyName, topPriority-10); err != nil {
		t.Fatalf("add rotation key: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := sp.RefreshMetadata(canceled); err == nil {
		t.Fatal("canceled refresh must fail, not silently succeed")
	}
	resp1, cert1 := fullLogin(t)
	if resp1.status != http.StatusFound || console.sessionOf(t, resp1) == nil {
		t.Fatalf("login across a failed refresh: got %d; body %s", resp1.status, kcSnippet(resp1.body))
	}
	if cert1 != certA {
		t.Fatalf("failed refresh changed the effective signer: got %q, want %q", cert1, certA)
	}

	// The retried refresh completes the dual publish.
	if err := sp.RefreshMetadata(ctx); err != nil {
		t.Fatalf("refresh retry after the interruption: %v", err)
	}
	resp2, _ := fullLogin(t)
	if resp2.status != http.StatusFound || console.sessionOf(t, resp2) == nil {
		t.Fatalf("login after the refresh retry: got %d; body %s", resp2.status, kcSnippet(resp2.body))
	}

	// Signer switch inside the dual window — no refresh needed, the cached
	// metadata already trusts both certificates.
	if err := stand.SetRSAKeyPriority(ctx, kcRecoveryKeyName, topPriority+100); err != nil {
		t.Fatalf("promote rotation key: %v", err)
	}
	resp3, certB := fullLogin(t)
	if resp3.status != http.StatusFound || console.sessionOf(t, resp3) == nil {
		t.Fatalf("login under the promoted signer: got %d; body %s", resp3.status, kcSnippet(resp3.body))
	}
	if certB == "" || certB == certA {
		t.Fatalf("signer did not switch: got %q, want a new certificate", certB)
	}

	// Second interruption — the interrupted refresh would have carried the
	// rotated trust, but the cache already holds it: logins stay green and
	// the signer is unchanged.
	if err := sp.RefreshMetadata(canceled); err == nil {
		t.Fatal("second canceled refresh must fail")
	}
	resp4, cert4 := fullLogin(t)
	if resp4.status != http.StatusFound || console.sessionOf(t, resp4) == nil {
		t.Fatalf("login across the second failed refresh: got %d; body %s", resp4.status, kcSnippet(resp4.body))
	}
	if cert4 != certB {
		t.Fatalf("failed refresh changed the effective signer: got %q, want %q", cert4, certB)
	}

	// Resume-ability, cycle two: retire and rotate back with the same
	// interruption/retry pattern. The stale cached metadata still trusts
	// the returning original signer, and the final refresh collapses the
	// trust set cleanly.
	if err := stand.DeleteRSAKeyProvider(ctx, kcRecoveryKeyName); err != nil {
		t.Fatalf("retire rotation key: %v", err)
	}
	if err := sp.RefreshMetadata(canceled); err == nil {
		t.Fatal("canceled refresh after retire must fail")
	}
	resp5, cert5 := fullLogin(t)
	if resp5.status != http.StatusFound || console.sessionOf(t, resp5) == nil {
		t.Fatalf("login across the post-retire interrupted refresh: got %d; body %s", resp5.status, kcSnippet(resp5.body))
	}
	if cert5 != certA {
		t.Fatalf("post-retire signer %q must return to the original %q", cert5, certA)
	}
	if err := sp.RefreshMetadata(ctx); err != nil {
		t.Fatalf("final refresh: %v", err)
	}
	resp6, cert6 := fullLogin(t)
	if resp6.status != http.StatusFound || console.sessionOf(t, resp6) == nil {
		t.Fatalf("login after the final refresh: got %d; body %s", resp6.status, kcSnippet(resp6.body))
	}
	if cert6 != certA {
		t.Fatalf("clean-state signer %q must be the original %q", cert6, certA)
	}
}
