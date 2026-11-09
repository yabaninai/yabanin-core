package handlers

// N04-P01-T07 boundary regressions at the handler edge (T06 covered the
// lifecycle and the deny-wins matrix; these pin the EDGE inputs):
//
//   - group-claim boundaries: an id_token whose groups claim is PRESENT but
//     EMPTY (`[]`) is an authoritative empty membership — it must strip a
//     mapping-held grant exactly like a dropped group, and must grant
//     nothing on a fresh login. A claim that is ABSENT behaves the same way
//     (JSON null is indistinguishable after unmarshal, so the absent cell
//     covers both shapes).
//
//   - logout edges: no cookie at all, a garbage cookie and an
//     expired-but-validly-signed cookie all end in the same observable
//     contract — 302 to the login page with the session cookie cleared —
//     while only the parseable cookies reach the durable revocation store.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// grantFixture builds a fixture with one grant rule and returns it together
// with its provider (for group mutations between logins).
func grantFixture(t *testing.T, groups []string) (*mappingFixture, *fakeOIDCProvider) {
	t.Helper()
	f := newMappingFixture(t,
		groups,
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	return f, f.p
}

func TestSSOBoundary_EmptyGroupsArrayStripsMappingGrant(t *testing.T) {
	// `groups: []` is not "unknown" — the IdP spoke and said: no groups.
	// The mapping-held grant must go the same way as on a dropped group.
	f, p := grantFixture(t, []string{"platform-team"})
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	p.groups = []string{}
	f.login(t)

	_, ok := f.membershipRole(t, orgA)
	assert.False(t, ok, "a present-but-empty groups claim must revoke the mapping-held grant")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev, "provenance must be cleared with the grant")
	require.Len(t, f.ssoAuditEntries(t, "sso_role_revoke"), 1)
}

func TestSSOBoundary_AbsentGroupsClaimStripsMappingGrant(t *testing.T) {
	// The claim disappears entirely (or arrives as JSON null — the two are
	// indistinguishable after unmarshal into []string): same revoke path.
	f, p := grantFixture(t, []string{"platform-team"})
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	p.groups = nil
	f.login(t)

	_, ok := f.membershipRole(t, orgA)
	assert.False(t, ok, "an absent groups claim must revoke the mapping-held grant")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev)
}

func TestSSOBoundary_EmptyGroupsFreshLoginGrantsNothing(t *testing.T) {
	// A fresh login with `groups: []` must not trip over the empty slice:
	// no grant, no crash, membership untouched.
	f, _ := grantFixture(t, []string{})
	f.login(t)

	assert.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA), "empty groups must leave the base role alone")
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
}

// ---- logout edges -------------------------------------------------------------

func logoutRecorder(t *testing.T, h *testAdminHandlers, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/logout", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.HandleLogout().ServeHTTP(rec, req)
	return rec
}

func sessionCookieCleared(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && (c.MaxAge < 0 || c.Value == "") {
			return true
		}
	}
	return false
}

func TestLogoutBoundary_NoCookieIsIdempotent(t *testing.T) {
	h, _ := newOIDCTestHandlers(t, newFakeOIDCProvider(t))
	rec := logoutRecorder(t, h, nil)

	require.Equal(t, http.StatusFound, rec.Code, "logout without a session must still land on the login page")
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/auth/login"))
	assert.True(t, sessionCookieCleared(rec), "logout must always clear the session cookie")
	assert.Empty(t, h.revocations.revoked, "no revocation may be attempted without a cookie")
}

func TestLogoutBoundary_GarbageCookieClearsAndSkipsRevocation(t *testing.T) {
	h, _ := newOIDCTestHandlers(t, newFakeOIDCProvider(t))
	rec := logoutRecorder(t, h, &http.Cookie{
		Name:     "yabanin_admin_session",
		Value:    "not-a-session-cookie",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, sessionCookieCleared(rec), "an unparsable cookie must still be cleared")
	assert.Empty(t, h.revocations.revoked, "no revocation may be recorded for an unparsable cookie")
}

func TestLogoutBoundary_ExpiredButSignedCookieRevokes(t *testing.T) {
	// The parse step ignores expiry by design (the middleware owns the expiry
	// check), so an expired-but-validly-signed logout still records the
	// durable revocation — belt and suspenders for replays of the stale
	// cookie on other replicas.
	h, _ := newOIDCTestHandlers(t, newFakeOIDCProvider(t))
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    "u-1",
		Email:     "root@test.io",
		SessionID: "boundary-expired-logout",
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}, "test-secret")
	require.NoError(t, err)

	rec := logoutRecorder(t, h, cookie)

	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, sessionCookieCleared(rec))
	assert.True(t, h.revocations.revoked["boundary-expired-logout"],
		"logout of an expired-but-signed cookie must record the durable revocation")
}
