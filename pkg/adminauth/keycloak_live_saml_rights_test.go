//go:build integration

package adminauth_test

// N04-P02-T10 [risk] live rights corpus: with the SAML routes mounted on the
// REAL production console against the REAL Keycloak stand, the trust surface
// stays isolated:
//
//   - the served SP metadata publishes the console's own public certificate
//     and never the IdP realm certificate, with or without a session;
//   - mutating verbs and guessed trust-management paths land on 404/405 (the
//     pre-auth ACS route without a flow cookie fails closed on 403), no
//     probed response mints cookies, and no trust state changes;
//   - the pre-auth console wall stays up (unauthenticated root redirects to
//     login) with the SAML routes mounted;
//   - a real login still works after every probe (the positive control the
//     whole corpus hangs on).
//
// Mock companions for the same invariants live in
// services/admin/handlers/auth_saml_invariants_test.go.

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func TestKeycloakLive_SAML_Rights_TrustSurfaceIsolation(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, _ := kcCompatConsole(t, stand, pool)

	base := console.base.String()

	// (1) The IdP realm descriptor's certificates must never appear in the
	// served SP metadata. Fetch the realm descriptor out-of-band, extract
	// every base64 certificate, then compare against the console's answer.
	descResp, err := http.Get(stand.RealmURL + "/protocol/saml/descriptor") //nolint:gosec,noctx // test-only GET of the local stand's realm descriptor
	require.NoError(t, err)
	descRaw, err := io.ReadAll(descResp.Body)
	require.NoError(t, err)
	require.NoError(t, descResp.Body.Close())
	require.Equal(t, http.StatusOK, descResp.StatusCode)

	certRe := regexp.MustCompile(`<ds:X509Certificate>([^<]+)</ds:X509Certificate>`)
	var realmCerts []string
	for _, m := range certRe.FindAllStringSubmatch(string(descRaw), -1) {
		realmCerts = append(realmCerts, strings.TrimSpace(m[1]))
	}
	require.NotEmpty(t, realmCerts, "the live realm descriptor must publish at least one certificate")

	// Anonymous metadata fetch — the SP metadata is public by design.
	browser := adminauth.NewKCBrowser()
	meta := console.get(t, browser, base+adminauth.SAMLMetadataPath)
	require.Equal(t, http.StatusOK, meta.status)
	require.Contains(t, meta.body, base, "the SP metadata must advertise the console entity")
	for _, cert := range realmCerts {
		require.NotContains(t, meta.body, cert,
			"the served SP metadata must never carry the IdP realm certificate")
	}
	require.NotContains(t, meta.body, "-----BEGIN", "no PEM blocks in served metadata")

	// (2) Rights probes through the live production router: trust material
	// is not writable over HTTP, guessed management paths do not exist, and
	// the ACS without a flow cookie fails closed.
	type samlProbe struct {
		method, path string
		want         int
	}
	probes := []samlProbe{
		{http.MethodPost, adminauth.SAMLMetadataPath, http.StatusMethodNotAllowed},
		{http.MethodPut, adminauth.SAMLMetadataPath, http.StatusMethodNotAllowed},
		{http.MethodDelete, adminauth.SAMLMetadataPath, http.StatusMethodNotAllowed},
		{http.MethodPost, adminauth.SAMLLoginPath, http.StatusMethodNotAllowed},
		// chi registers the ACS for POST only: a GET is method-refused at
		// the router (405) before any handler logic runs — fail-closed.
		{http.MethodGet, adminauth.SAMLACSPath, http.StatusMethodNotAllowed},
		{http.MethodPut, adminauth.SAMLACSPath, http.StatusMethodNotAllowed},
		{http.MethodDelete, adminauth.SAMLSLOPath, http.StatusMethodNotAllowed},
		{http.MethodGet, "/auth/saml/refresh", http.StatusNotFound},
		{http.MethodPost, "/auth/saml/refresh", http.StatusNotFound},
		{http.MethodGet, "/auth/saml/rotate", http.StatusNotFound},
		{http.MethodPost, "/auth/saml/rotate", http.StatusNotFound},
		{http.MethodGet, "/auth/saml/reset", http.StatusNotFound},
		{http.MethodPost, "/auth/saml/reset", http.StatusNotFound},
	}
	for _, probe := range probes {
		req, err := http.NewRequestWithContext(context.Background(), probe.method, base+probe.path, strings.NewReader("<EntityDescriptor/>"))
		require.NoError(t, err)
		resp, err := browser.Client.Do(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, probe.want, resp.StatusCode,
			"%s %s must be refused", probe.method, probe.path)
		require.Empty(t, resp.Cookies(), "%s %s must not mint cookies", probe.method, probe.path)
		require.NotContains(t, string(raw), "<EntityDescriptor", "refusal must not echo the payload")
	}

	// (3) The pre-auth wall stays up with the SAML routes mounted:
	// unauthenticated root is a 401 from the session middleware (no
	// redirect, no session minted).
	fresh := adminauth.NewKCBrowser()
	root := console.get(t, fresh, base+"/")
	require.Equal(t, http.StatusUnauthorized, root.status, "unauthenticated root must stay behind the wall")
	require.Contains(t, root.body, "unauthorized")
	require.False(t, console.hasSession(fresh.Jar), "the wall must not mint a session")

	// (4) Positive control: a real login through the SAME console after all
	// probes — the trust material was never touched.
	resp, _ := kcCompatLogin(t, console, adminauth.KCUserRoot, adminauth.KCPassRoot)
	require.Equal(t, http.StatusFound, resp.status, "the real login must survive the probe gauntlet")
	require.NotNil(t, console.sessionOf(t, resp), "the live login must mint a verifiable session cookie")
}
