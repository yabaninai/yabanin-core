package handlers

// W-INV: unit tests for the member-invite handlers over a scripted fake
// store. Token-state → status mapping (404/410/409), the self-invite and
// already-a-member rejections, the one-time-token exposure contract, and the
// public acceptance page (CSRF, credentials, provisioning) are pinned here;
// the SQL/RLS behavior lives in pkg/adminstore member invite integration
// tests.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inviteTimePtr is the test helper for optional-time fields.
func inviteTimePtr(v time.Time) *time.Time { return &v }

// fakeInviteStore is a scripted MemberInviteStore over the standard mock
// (so GetAdminUserByID / GetUserOrgRoles keep working for the create-time
// self-invite and already-a-member checks).
type fakeInviteStore struct {
	*mockStore

	createInvite *adminstore.MemberInvite
	createToken  string
	createErr    error

	listInvites []*adminstore.MemberInvite
	listErr     error

	resendInvite *adminstore.MemberInvite
	resendToken  string
	resendErr    error

	revokeErr error

	preview    *adminstore.InvitePreview
	previewErr error

	acceptResult *adminstore.AcceptInviteResult
	acceptErr    error

	acceptCalls int
	acceptToken string
	acceptHash  string
}

func (f *fakeInviteStore) CreateMemberInvite(_ context.Context, orgID, email string, role adminstore.OrgRole, _ string) (*adminstore.MemberInvite, string, error) {
	if f.createErr != nil {
		return nil, "", f.createErr
	}
	if f.createInvite == nil {
		f.createInvite = &adminstore.MemberInvite{
			ID: "inv-1", OrgID: orgID, Email: email, Role: role,
			ExpiresAt: time.Now().Add(adminstore.InviteTTL),
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	}
	return f.createInvite, f.createToken, nil
}

func (f *fakeInviteStore) ListMemberInvites(_ context.Context, _ string) ([]*adminstore.MemberInvite, error) {
	return f.listInvites, f.listErr
}

func (f *fakeInviteStore) ResendMemberInvite(_ context.Context, _, _ string, _ string) (*adminstore.MemberInvite, string, error) {
	if f.resendErr != nil {
		return nil, "", f.resendErr
	}
	if f.resendInvite == nil {
		f.resendInvite = &adminstore.MemberInvite{
			ID: "inv-1", OrgID: "org-1", Email: "new@example.com", Role: adminstore.RoleReader,
			ExpiresAt: time.Now().Add(adminstore.InviteTTL),
		}
	}
	return f.resendInvite, f.resendToken, nil
}

func (f *fakeInviteStore) RevokeMemberInvite(_ context.Context, _, _ string, _ string) error {
	return f.revokeErr
}

func (f *fakeInviteStore) PreviewMemberInvite(_ context.Context, _ string) (*adminstore.InvitePreview, error) {
	return f.preview, f.previewErr
}

func (f *fakeInviteStore) AcceptMemberInvite(_ context.Context, token, passwordHash string) (*adminstore.AcceptInviteResult, error) {
	f.acceptCalls++
	f.acceptToken = token
	f.acceptHash = passwordHash
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	if f.acceptResult == nil {
		f.acceptResult = &adminstore.AcceptInviteResult{
			Invite: &adminstore.MemberInvite{
				ID: "inv-1", OrgID: "org-1", Email: "new@example.com", Role: adminstore.RoleReader,
				ExpiresAt: time.Now().Add(adminstore.InviteTTL), AcceptedAt: inviteTimePtr(time.Now()),
				InvitedUserID: "user-9",
			},
			OrgName: "Org One", UserID: "user-9", UserCreated: true,
		}
	}
	return f.acceptResult, nil
}

// GetAdminUserByEmailWithHash overrides the mock's fixed hash so the
// existing-account acceptance path can verify a real password.
func (f *fakeInviteStore) GetAdminUserByEmailWithHash(ctx context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	if email == "existing@example.com" {
		hash, err := adminauth.HashPassword("correct horse battery")
		if err != nil {
			return nil, err
		}
		return &adminstore.AdminUserWithHash{ID: "user-7", Email: email, PasswordHash: hash, Active: true}, nil
	}
	return f.mockStore.GetAdminUserByEmailWithHash(ctx, email)
}

func newFakeInviteH(t *testing.T) (*AdminHandlers, *fakeInviteStore) {
	t.Helper()
	fs := &fakeInviteStore{mockStore: newMockStore()}
	return New(fs, "test-session-key", "invite.test", nil), fs
}

// inviteRouter mounts the invite routes exactly as the production routers do
// (a real chi Mux so chi's PathValue sync runs — wrapWithParams only fills
// chi.URLParam, which these handlers do not read).
func inviteRouter(h *AdminHandlers) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/organizations/{id}/members/invites", h.ListInvites())
	r.Post("/api/organizations/{id}/members/invite", h.CreateInvite())
	r.Post("/api/organizations/{id}/members/invites/{inviteID}/resend", h.ResendInvite())
	r.Post("/api/organizations/{id}/members/invites/{inviteID}/revoke", h.RevokeInvite())
	r.Get("/invite/{token}", h.InvitePage())
	r.Post("/invite/{token}", h.HandleInviteAccept())
	return r
}

// serveInvite routes req through the invite router and returns the recorder.
func serveInvite(tb testing.TB, h *AdminHandlers, r *http.Request) *httptest.ResponseRecorder {
	tb.Helper()
	w := httptest.NewRecorder()
	inviteRouter(h).ServeHTTP(w, r)
	return w
}

func TestCreateInvite(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.createToken = "018c2f3e-9c1a-7c34-9f2e-0d5a1b6c3e4f.4f0a80c4e1d94e2ba56cd0f71e92aa64"
	w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invite", `{"email":"New@Example.com","role":"operator"}`))
	require.Equal(t, http.StatusCreated, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, `"invite_path":"/invite/`+fs.createToken+`"`)
	// The raw token appears exactly once (the path), never inside the row.
	assert.Equal(t, 1, strings.Count(body, fs.createToken))
	assert.NotContains(t, body, "token_hash")
	assert.Equal(t, "new@example.com", fs.createInvite.Email, "email must be normalized")
	assert.Equal(t, adminstore.RoleOperator, fs.createInvite.Role)
}

func TestCreateInvite_Validation(t *testing.T) {
	h, _ := newFakeInviteH(t)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"empty email", `{"email":"","role":"reader"}`, http.StatusBadRequest},
		{"bad email", `{"email":"not-an-email","role":"reader"}`, http.StatusBadRequest},
		{"bad role", `{"email":"a@b.test","role":"superuser"}`, http.StatusBadRequest},
		{"bad body", `not-json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invite", tc.body))
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestCreateInvite_SelfInviteForbidden(t *testing.T) {
	h, _ := newFakeInviteH(t)
	// admin-root's email is root@example.com (mock seed).
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/organizations/org-1/members/invite", strings.NewReader(`{"email":"root@example.com","role":"reader"}`))
	ctx := context.WithValue(r.Context(), adminauth.ContextKeyIsRoot{}, true)
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, "admin-root")
	r = r.WithContext(ctx)
	w := serveInvite(t, h, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "own email")
}

func TestCreateInvite_AlreadyMember(t *testing.T) {
	h, fs := newFakeInviteH(t)
	// admin-1 (test@example.com) already holds a membership on org-1.
	fs.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{ID: "m1", UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleReader}
	w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invite", `{"email":"test@example.com","role":"reader"}`))
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreateInvite_DuplicateActive(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.createErr = adminstore.ErrInvitePending
	w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invite", `{"email":"new@example.com","role":"reader"}`))
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestInviteRoutes_NoCapability(t *testing.T) {
	// The plain mock does not implement MemberInviteStore: the routes answer
	// 501 instead of panicking.
	h := newTestAdminH(newMockStore())
	for _, tc := range []struct {
		name   string
		method string
		target string
		call   func(w http.ResponseWriter, r *http.Request)
	}{
		{"create", "POST", "/api/organizations/org-1/members/invite", h.CreateInvite().ServeHTTP},
		{"list", "GET", "/api/organizations/org-1/members/invites", h.ListInvites().ServeHTTP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusNotImplemented, serveInvite(t, h.AdminHandlers, rootRequest(tc.method, tc.target, "{}")).Code)
		})
	}
}

func TestListInvites(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.listInvites = []*adminstore.MemberInvite{{ID: "inv-1", OrgID: "org-1", Email: "a@b.test", Role: adminstore.RoleReader}}
	w := serveInvite(t, h, rootRequest("GET", "/api/organizations/org-1/members/invites", ""))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":1`)
	assert.NotContains(t, w.Body.String(), "token_hash")
}

func TestInviteStoreErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"not found", adminstore.ErrNotFound, http.StatusNotFound},
		{"expired", adminstore.ErrInviteExpired, http.StatusGone},
		{"accepted", adminstore.ErrInviteAccepted, http.StatusGone},
		{"pending dup", adminstore.ErrInvitePending, http.StatusConflict},
		{"transport", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, fs := newFakeInviteH(t)
			fs.resendErr = tc.err
			w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invites/inv-9/resend", ""))
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestResendInvite(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.resendToken = "tok.rotated"
	w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invites/inv-1/resend", ""))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/invite/"+fs.resendToken)
}

func TestRevokeInvite(t *testing.T) {
	h, fs := newFakeInviteH(t)
	w := serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invites/inv-1/revoke", ""))
	assert.Equal(t, http.StatusNoContent, w.Code)

	fs.revokeErr = adminstore.ErrInviteAccepted
	assert.Equal(t, http.StatusGone, serveInvite(t, h, rootRequest("POST", "/api/organizations/org-1/members/invites/inv-1/revoke", "")).Code)
}

// --- public page -------------------------------------------------------------

func TestInvitePage(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*fakeInviteStore)
		want   int
		marker string
	}{
		{
			name: "valid shows the form",
			setup: func(fs *fakeInviteStore) {
				fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
			},
			want:   http.StatusOK,
			marker: `name="password"`,
		},
		{
			name:   "unknown token 404",
			setup:  func(fs *fakeInviteStore) { fs.previewErr = adminstore.ErrNotFound },
			want:   http.StatusNotFound,
			marker: "not valid",
		},
		{
			name:   "expired 410",
			setup:  func(fs *fakeInviteStore) { fs.previewErr = adminstore.ErrInviteExpired },
			want:   http.StatusGone,
			marker: "expired",
		},
		{
			name:   "accepted 410",
			setup:  func(fs *fakeInviteStore) { fs.previewErr = adminstore.ErrInviteAccepted },
			want:   http.StatusGone,
			marker: "already used",
		},
		{
			name:   "transport 500",
			setup:  func(fs *fakeInviteStore) { fs.previewErr = fmt.Errorf("boom") },
			want:   http.StatusInternalServerError,
			marker: "unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, fs := newFakeInviteH(t)
			tc.setup(fs)
			w := serveInvite(t, h, rootRequest("GET", "/invite/some.token", ""))
			require.Equal(t, tc.want, w.Code)
			assert.Contains(t, strings.ToLower(w.Body.String()), tc.marker)
		})
	}
}

// postInviteForm builds a form POST against the public acceptance route with
// the CSRF cookie the GET render would have set.
func postInviteForm(tb testing.TB, target string, fields map[string]string, csrf string) *http.Request {
	tb.Helper()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	if csrf != "" {
		form.Set("_csrf", csrf)
	}
	r := httptest.NewRequestWithContext(context.Background(), "POST", target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		r.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	return r
}

func TestHandleInviteAccept_CSRFRequired(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	r := postInviteForm(t, "/invite/tok", map[string]string{"email": "new@example.com", "password": "long-enough-password"}, "")
	w := serveInvite(t, h, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, fs.acceptCalls, "a CSRF failure must not consume the invite")
}

func TestHandleInviteAccept_NewUser(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	fs.createToken = ""
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "new@example.com", "password": "long-enough-password"}, "csrf-value"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, fs.acceptCalls)
	assert.Equal(t, "tok", fs.acceptToken)
	assert.NotEmpty(t, fs.acceptHash, "a new account is provisioned with a hash")
	assert.Contains(t, w.Body.String(), "Org One")
}

func TestHandleInviteAccept_ExistingUser(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "existing@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "existing@example.com", "password": "correct horse battery"}, "csrf-value"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, fs.acceptCalls)
	assert.Empty(t, fs.acceptHash, "an existing account must never get a new hash from an invite")
}

func TestHandleInviteAccept_ExistingUserBadPassword(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "existing@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "existing@example.com", "password": "wrong password!!"}, "csrf-value"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Zero(t, fs.acceptCalls)
}

func TestHandleInviteAccept_EmailMismatch(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "someone@else.test", "password": "long-enough-password"}, "csrf-value"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, fs.acceptCalls)
}

func TestHandleInviteAccept_PasswordPolicy(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "new@example.com", "password": "short"}, "csrf-value"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, fs.acceptCalls)
}

func TestHandleInviteAccept_TokenGoneMidFlight(t *testing.T) {
	h, fs := newFakeInviteH(t)
	fs.preview = &adminstore.InvitePreview{OrgName: "Org One", Email: "new@example.com", Role: adminstore.RoleReader, ExpiresAt: time.Now().Add(time.Hour)}
	fs.acceptErr = adminstore.ErrInviteAccepted
	w := serveInvite(t, h, postInviteForm(t, "/invite/tok", map[string]string{"email": "new@example.com", "password": "long-enough-password"}, "csrf-value"))
	assert.Equal(t, http.StatusGone, w.Code)
}
