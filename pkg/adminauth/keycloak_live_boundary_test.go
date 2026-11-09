//go:build integration

package adminauth

// N04-P01-T07 live-IdP boundary regressions (N04-P01-T06 proved the
// lifecycle; this file pins the EDGES on the real Keycloak):
//
//	phase 0  baseline: the pristine realm signs with its default key K1;
//	         one real ID token is captured (the only published kid);
//	phase 1  dual-publish: a second realm RSA key joins the JWKS (K1 still
//	         signs); a second real token is captured after the signer
//	         switch, so two real tokens signed by DIFFERENT live kids exist
//	         while both kids are published;
//	phase 2  rotation race: both tokens are verified CONCURRENTLY through
//	         one production client construction — the exact "two unknown
//	         kids in flight" burst the console fleet can hit mid-rotation
//	         (go-oidc deduplicates the refetch; every token verifies);
//	phase 3  retirement: the second key is deleted, the JWKS drops its kid;
//	         a FRESHLY constructed production client rejects the
//	         retired-kid token (the card's "old key is rejected" negative,
//	         live) and accepts a brand-new K1-signed token.
//
// File order: this file sorts before keycloak_live_e2e_test.go and
// keycloak_live_rotation_test.go, so it runs on the pristine realm and
// restores it (the added key is deleted on cleanup) before those suites.

import (
	"context"
	"sync"
	"testing"
	"time"
)

const kcBoundaryKeyName = "n04-boundary-key"

func TestKeycloakLiveBoundary_RotationRaceAndRetiredKey(t *testing.T) {
	stand := KeycloakLiveStand(t)
	ctx := context.Background()

	// Defensive reset (a fresh realm never carries one; a retried run might).
	_ = stand.DeleteRSAKeyProvider(ctx, kcBoundaryKeyName)
	basePriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}
	t.Cleanup(func() { _ = stand.DeleteRSAKeyProvider(context.Background(), kcBoundaryKeyName) })

	// ---- phase 0: baseline capture on the default key ----------------------
	kids, err := stand.JWKSKids(ctx)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if len(kids) != 1 {
		t.Fatalf("baseline realm must carry exactly one signing key, got %v", kids)
	}
	tok1, claims1 := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
	kid1 := kcJWTHeaderKid(t, tok1)
	if kid1 == "" || kid1 != kids[0] {
		t.Fatalf("baseline token kid %q must be the only published kid %v", kid1, kids)
	}
	if claims1["email"] != "sso-root@test.io" {
		t.Fatalf("baseline claims: %v", claims1)
	}

	// ---- phase 1: dual-publish then signer switch --------------------------
	if err := stand.AddRSAKeyProvider(ctx, kcBoundaryKeyName, basePriority-10); err != nil {
		t.Fatalf("add boundary key: %v", err)
	}
	kids, err = stand.JWKSKids(ctx)
	if err != nil {
		t.Fatalf("jwks after add: %v", err)
	}
	if len(kids) != 2 {
		t.Fatalf("dual-publish window must serve both kids, got %v", kids)
	}
	if err := stand.SetRSAKeyPriority(ctx, kcBoundaryKeyName, basePriority+100); err != nil {
		t.Fatalf("bump boundary key priority: %v", err)
	}
	tok2, _ := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
	kid2 := kcJWTHeaderKid(t, tok2)
	if kid2 == "" || kid2 == kid1 {
		t.Fatalf("signer did not switch: new token kid %q, want the boundary key", kid2)
	}

	// ---- phase 2: concurrent verification, two kids in flight --------------
	verifier := kcLiveClientVerifier(t, stand)
	const burst = 8
	tokens := make([]string, 0, burst)
	for i := 0; i < burst; i++ {
		if i%2 == 0 {
			tokens = append(tokens, tok1)
		} else {
			tokens = append(tokens, tok2)
		}
	}
	errCh := make(chan error, burst)
	var wg sync.WaitGroup
	for _, tok := range tokens {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			if _, err := verifier.Verify(ctx, token); err != nil {
				errCh <- err
			}
		}(tok)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("mid-rotation concurrent verification failed: %v", err)
	}

	// ---- phase 3: retirement → fresh client rejects the old key ------------
	if err := stand.DeleteRSAKeyProvider(ctx, kcBoundaryKeyName); err != nil {
		t.Fatalf("delete boundary key: %v", err)
	}
	// The realm drops the kid from the JWKS asynchronously; wait it out so
	// the negative below fails for the RIGHT reason.
	deadline := time.Now().Add(30 * time.Second)
	for {
		kids, err = stand.JWKSKids(ctx)
		if err != nil {
			t.Fatalf("jwks after retire: %v", err)
		}
		gone := true
		for _, k := range kids {
			if k == kid2 {
				gone = false
			}
		}
		if gone || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, k := range kids {
		if k == kid2 {
			t.Fatalf("retired kid %q still published after the wait: %v", kid2, kids)
		}
	}

	fresh, err := NewOIDCClient(ctx, stand.RealmURL, KCLiveOIDCClientID, KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback")
	if err != nil {
		t.Fatalf("fresh OIDC client: %v", err)
	}
	if _, err := fresh.verifier.Verify(ctx, tok2); err == nil {
		t.Fatal("a token signed by the RETIRED live key must be rejected by a fresh client")
	}
	tok3, _ := stand.CaptureIDToken(t, KCUserRoot, KCPassRoot)
	if kcJWTHeaderKid(t, tok3) != kid1 {
		t.Fatalf("post-retirement token kid %q, want the surviving key %q", kcJWTHeaderKid(t, tok3), kid1)
	}
	if _, err := fresh.verifier.Verify(ctx, tok3); err != nil {
		t.Fatalf("post-retirement token must verify: %v", err)
	}
}
