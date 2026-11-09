//go:build integration

package adminauth_test

// N04-P02-T09 [compatibility] live corpus: the SAML configuration shapes
// walked against the REAL local Keycloak stand. Mock companions for the same
// shapes live in services/admin/handlers/auth_saml_compat_test.go; this file
// closes the live-IdP remainder:
//
//   - the OLD deployment shape — entity ID DERIVED from the ACS origin, the
//     pre-YABANIN_SAML_ENTITY_ID configuration — must log in against the real
//     IdP and ride a real key rotation (dual publish → signer switch →
//     retire) without losing its configured shape;
//   - the realistic unsupported metadata choices (the realm JSON root, a
//     nonexistent realm, plain-http non-loopback) are refused at SP startup.
//
// File order note: like the matrix file, this test inherits whatever key
// provider state the rotation/recovery files left behind; every key priority
// and cert count below is computed from the live stand, never assumed.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const kcCompatKeyName = "n04-compat-key"

// kcCompatConsole wires a console whose SP uses the OLD configuration shape:
// the entity ID is left empty and derived from the ACS origin inside
// NewSAMLSP (the pre-explicit-knob behavior). The IdP-side SAML client is
// registered with the console origin, so the derivation must land on exactly
// the entity the IdP knows — that agreement is the old-shape compatibility
// contract this file pins.
func kcCompatConsole(t *testing.T, stand *adminauth.KCStand, pool *pgxpool.Pool) (*kcConsole, *adminauth.SAMLSP) {
	t.Helper()
	ctx := context.Background()
	var sp *adminauth.SAMLSP
	console := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		acsURL := base + adminauth.SAMLACSPath
		if err := stand.ConfigureSAMLClient(ctx, base, acsURL); err != nil {
			return nil, err
		}
		provider, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: stand.RealmURL + "/protocol/saml/descriptor",
			EntityID:       "", // the old shape: derive from the ACS origin
			ACSURL:         acsURL,
		})
		if err != nil {
			return nil, err
		}
		if provider.SP.EntityID != base {
			t.Errorf("derived entity %q must equal the IdP-registered client entity %q", provider.SP.EntityID, base)
		}
		sp = provider
		return []func(*handlers.AdminHandlers){func(h *handlers.AdminHandlers) { h.SetSAMLSP(provider) }}, nil
	})
	return console, sp
}

// kcCompatLogin drives one full SP-initiated login round trip through the
// production console and returns the ACS response plus the certificate the
// IdP signed with (kcMatrixCert, the same observable the matrix uses).
func kcCompatLogin(t *testing.T, console *kcConsole, username, password string) (kcResp, string) {
	t.Helper()
	browser := adminauth.NewKCBrowser()
	start := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
	if start.status != http.StatusFound {
		t.Fatalf("saml login start: got %d, want 302; body %s", start.status, kcSnippet(start.body))
	}
	hops := browser.DriveSSO(t, start.location, username, password, "")
	offer := browser.SAMLOffer(t, hops)
	resp := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
	return resp, kcMatrixCert(t, offer)
}

// kcCompatShapeSnapshot captures the configured addressing of a live SP so a
// metadata swap can be diffed against it.
func kcCompatShapeSnapshot(sp *adminauth.SAMLSP) (entity, acs, slo string) {
	return sp.SP.EntityID, sp.SP.AcsURL.String(), sp.SP.SloURL.String()
}

func kcCompatShapeMustHold(t *testing.T, sp *adminauth.SAMLSP, entity, acs, slo string) {
	t.Helper()
	if e, a, s := kcCompatShapeSnapshot(sp); e != entity || a != acs || s != slo {
		t.Fatalf("metadata swap changed the configured shape: entity %q→%q acs %q→%q slo %q→%q",
			entity, e, acs, a, slo, s)
	}
}

// TestKeycloakLive_SAML_Compat_OldShapeDerivedEntity walks the old deployment
// shape through a real login and a real Keycloak signing-key rotation: derive
// → login → dual publish → login → signer switch → login → retire → login,
// with the configured shape asserted stable across every metadata refresh.
func TestKeycloakLive_SAML_Compat_OldShapeDerivedEntity(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, sp := kcCompatConsole(t, stand, pool)
	ctx := context.Background()

	// Defensive reset + cleanup: never inherit or leak the rotation key.
	_ = stand.DeleteRSAKeyProvider(ctx, kcCompatKeyName)
	t.Cleanup(func() { _ = stand.DeleteRSAKeyProvider(context.Background(), kcCompatKeyName) })

	topPriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}
	certsBefore, err := stand.SAMLSigningCertCount(ctx)
	if err != nil {
		t.Fatalf("signing cert count: %v", err)
	}
	entity, acs, slo := kcCompatShapeSnapshot(sp)

	// Baseline: the old shape logs in end to end.
	resp0, _ := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if resp0.status != http.StatusFound || console.sessionOf(t, resp0) == nil {
		t.Fatalf("old-shape login: got %d; body %s", resp0.status, kcSnippet(resp0.body))
	}

	// Phase 1 — dual publish: the rotation key enters the metadata beside the
	// current signer; the derived-shape SP refreshes and logins keep working.
	if err := stand.AddRSAKeyProvider(ctx, kcCompatKeyName, topPriority-10); err != nil {
		t.Fatalf("add rotation key: %v", err)
	}
	if n, err := stand.SAMLSigningCertCount(ctx); err != nil || n != certsBefore+1 {
		t.Fatalf("dual publish: got %d certs (err %v), want %d", n, err, certsBefore+1)
	}
	if err := sp.RefreshMetadata(ctx); err != nil {
		t.Fatalf("refresh over the dual window: %v", err)
	}
	kcCompatShapeMustHold(t, sp, entity, acs, slo)
	respA, certA := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if respA.status != http.StatusFound || console.sessionOf(t, respA) == nil || certA == "" {
		t.Fatalf("login over the dual window: got %d cert %q; body %s", respA.status, certA, kcSnippet(respA.body))
	}

	// Phase 2 — signer switch: the rotation key takes over signing; the
	// already-refreshed trust set accepts the new certificate without any
	// further SP action (the transition window doing its job), and a refresh
	// afterwards preserves the shape.
	if err := stand.SetRSAKeyPriority(ctx, kcCompatKeyName, topPriority+100); err != nil {
		t.Fatalf("promote rotation key: %v", err)
	}
	respB, certB := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if respB.status != http.StatusFound || console.sessionOf(t, respB) == nil {
		t.Fatalf("login under the new signer: got %d; body %s", respB.status, kcSnippet(respB.body))
	}
	if certB == "" || certB == certA {
		t.Fatalf("signer did not switch: certB %q must differ from certA %q", certB, certA)
	}
	if err := sp.RefreshMetadata(ctx); err != nil {
		t.Fatalf("refresh after the signer switch: %v", err)
	}
	kcCompatShapeMustHold(t, sp, entity, acs, slo)
	respB2, _ := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if respB2.status != http.StatusFound || console.sessionOf(t, respB2) == nil {
		t.Fatalf("login after post-switch refresh: got %d; body %s", respB2.status, kcSnippet(respB2.body))
	}

	// Phase 3 — retire: the rotation key goes away, the refresh collapses the
	// metadata back to the original certificate and the old shape keeps
	// logging in under the original signer.
	if err := stand.DeleteRSAKeyProvider(ctx, kcCompatKeyName); err != nil {
		t.Fatalf("retire rotation key: %v", err)
	}
	if n, err := stand.SAMLSigningCertCount(ctx); err != nil || n != certsBefore {
		t.Fatalf("after retire: got %d certs (err %v), want %d", n, err, certsBefore)
	}
	if err := sp.RefreshMetadata(ctx); err != nil {
		t.Fatalf("refresh after retire: %v", err)
	}
	kcCompatShapeMustHold(t, sp, entity, acs, slo)
	respC, certC := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if respC.status != http.StatusFound || console.sessionOf(t, respC) == nil {
		t.Fatalf("login after retire: got %d; body %s", respC.status, kcSnippet(respC.body))
	}
	if certC != certA {
		t.Fatalf("post-retire signer %q must be the original %q", certC, certA)
	}
}

// TestKeycloakLive_SAML_Compat_UnsupportedMetadataRefused pins the live
// startup refusals for the unsupported metadata choices, DB-free: the
// realistic operator mistake (the realm JSON root instead of the SAML
// descriptor), a nonexistent realm, and the plain-http non-loopback URL all
// fail NewSAMLSP — SAML never half-mounts.
func TestKeycloakLive_SAML_Compat_UnsupportedMetadataRefused(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	ctx := context.Background()
	acsURL := stand.BaseURL + adminauth.SAMLACSPath

	t.Run("realm_json_root_is_not_saml_metadata", func(t *testing.T) {
		// The operator mistake: the browser-visible realm document instead of
		// the protocol/saml/descriptor endpoint.
		_, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: stand.RealmURL,
			ACSURL:         acsURL,
		})
		if err == nil {
			t.Fatal("realm JSON root must be refused as IdP metadata")
		}
	})

	t.Run("nonexistent_realm_descriptor", func(t *testing.T) {
		_, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: stand.BaseURL + "/realms/does-not-exist/protocol/saml/descriptor",
			ACSURL:         acsURL,
		})
		if err == nil {
			t.Fatal("nonexistent realm descriptor must be refused")
		}
	})

	t.Run("plain_http_non_loopback", func(t *testing.T) {
		_, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: "http://idp.example.test/metadata",
			ACSURL:         acsURL,
		})
		if err == nil {
			t.Fatal("plain-http non-loopback metadata URL must be refused")
		}
		if !strings.Contains(err.Error(), "https") {
			t.Fatalf("refusal must name the https requirement: %v", err)
		}
	})
}
