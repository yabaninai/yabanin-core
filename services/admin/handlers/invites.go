package handlers

// W-INV: org member invitations.
//
// API surface (org:members.manage gate, mounted in router_orgs.go):
//
//	GET  /api/organizations/{id}/members/invites                    — pending invites
//	POST /api/organizations/{id}/members/invite                     — create (returns the one-time link)
//	POST /api/organizations/{id}/members/invites/{inviteID}/resend  — rotate token + restart the 72h window
//	POST /api/organizations/{id}/members/invites/{inviteID}/revoke  — delete the pending invite
//
// Public surface (no session, mounted in router_public.go):
//
//	GET  /invite/{token} — the acceptance page (server-rendered, Astra tokens)
//	POST /invite/{token} — consume the invite: create the admin user when the
//	                       email is unknown (invited credentials), otherwise
//	                       verify the existing account's password and bind it.
//
// The raw token exists exactly once — in the create/resend response. The
// database (and every read path here) sees only its sha256. Token state maps
// to statuses: unknown/revoked → 404, expired/accepted → 410, duplicate
// active invite → 409. Every action writes an audit entry.

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// MemberInviteStore is the narrow capability the invite handlers consume
// (*adminstore.Store satisfies it — compile-pinned in pkg/adminstore).
// Handlers never see token hashes; the raw token exists only as the string
// paired with Create/Resend results.
type MemberInviteStore interface {
	CreateMemberInvite(ctx context.Context, orgID, email string, role adminstore.OrgRole, createdBy string) (*adminstore.MemberInvite, string, error)
	ListMemberInvites(ctx context.Context, orgID string) ([]*adminstore.MemberInvite, error)
	ResendMemberInvite(ctx context.Context, orgID, inviteID, actorID string) (*adminstore.MemberInvite, string, error)
	RevokeMemberInvite(ctx context.Context, orgID, inviteID, actorID string) error
	PreviewMemberInvite(ctx context.Context, token string) (*adminstore.InvitePreview, error)
	AcceptMemberInvite(ctx context.Context, token, passwordHash string) (*adminstore.AcceptInviteResult, error)
}

// inviteStore returns the store's invite capability, or nil when unsupported
// (the routes then answer 501 — the capability ships with the real store).
func (h *AdminHandlers) inviteStore() MemberInviteStore {
	is, _ := h.store.(MemberInviteStore)
	return is
}

// inviteStoreGuard writes the 501/500 for a missing store or capability and
// returns false (response already written).
func (h *AdminHandlers) inviteStoreGuard(w http.ResponseWriter, r *http.Request) (MemberInviteStore, bool) {
	if !h.requireStore(w, r) {
		return nil, false
	}
	is := h.inviteStore()
	if is == nil {
		h.respondError(w, r, fmt.Errorf("member invite store not available"), http.StatusNotImplemented)
		return nil, false
	}
	return is, true
}

// writeInviteStoreError maps store failures onto the invite contract:
// not-found → 404, consumed/expired → 410, duplicate active invite → 409,
// everything else → a generic 500 (driver internals go to the log only).
func (h *AdminHandlers) writeInviteStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminstore.ErrNotFound):
		h.respondError(w, r, fmt.Errorf("not found"), http.StatusNotFound)
	case errors.Is(err, adminstore.ErrInviteExpired), errors.Is(err, adminstore.ErrInviteAccepted):
		h.respondError(w, r, fmt.Errorf("invite is no longer valid"), http.StatusGone)
	case errors.Is(err, adminstore.ErrInvitePending):
		h.respondError(w, r, err, http.StatusConflict)
	default:
		h.respondError(w, r, err, http.StatusInternalServerError)
	}
}

// ListInvites — GET /api/organizations/{id}/members/invites.
func (h *AdminHandlers) ListInvites() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is, ok := h.inviteStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		invites, err := is.ListMemberInvites(r.Context(), orgID)
		if err != nil {
			h.writeInviteStoreError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": invites, "count": len(invites)})
	}
}

// CreateInvite — POST /api/organizations/{id}/members/invite. Body:
// {"email": "...", "role": "reader"}. The response carries the one-time
// invite PATH (the UI absolutizes it against its own origin) — the only
// time the raw token leaves the server. Inviting your own email is a 400;
// inviting an email that already holds a membership on the org is a 409.
func (h *AdminHandlers) CreateInvite() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is, ok := h.inviteStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		var req struct {
			Email string             `json:"email"`
			Role  adminstore.OrgRole `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		req.Email = adminstore.NormalizeInviteEmail(req.Email)
		if req.Email == "" {
			h.respondError(w, r, fmt.Errorf("email is required"), http.StatusBadRequest)
			return
		}
		if err := validateAdminEmail(req.Email); err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		if !adminstore.ValidOrgRole(req.Role) {
			h.respondError(w, r, fmt.Errorf("role must be one of: org-admin, operator, reader, security_auditor, partner"), http.StatusBadRequest)
			return
		}

		inviterID := requestUserID(r)
		if h.isSelfInvite(r, req.Email) {
			h.respondError(w, r, fmt.Errorf("cannot invite your own email"), http.StatusBadRequest)
			return
		}
		if h.rejectExistingMember(w, r, orgID, req.Email) {
			return
		}

		inv, token, err := is.CreateMemberInvite(r.Context(), orgID, req.Email, req.Role, inviterID)
		if err != nil {
			h.writeInviteStoreError(w, r, err)
			return
		}
		h.auditLogAction(r, "create", "member_invite",
			"org="+orgID+",invite="+inv.ID+",email="+req.Email+",role="+string(req.Role))
		writeJSON(w, http.StatusCreated, map[string]any{
			"invite":      inv,
			"invite_path": inviteURLPath(token),
			"expires_at":  inv.ExpiresAt,
		})
	}
}

// isSelfInvite reports whether the invite targets the session user's own
// email (card W-INV: self-invite is forbidden). A caller without a user id,
// or whose account cannot be resolved right now, is not blocked here — the
// route already required an admin session and the store arbitrates the write.
func (h *AdminHandlers) isSelfInvite(r *http.Request, email string) bool {
	selfID := requestUserID(r)
	if selfID == "" {
		return false
	}
	self, err := h.store.GetAdminUserByID(r.Context(), selfID)
	return err == nil && adminstore.NormalizeInviteEmail(self.Email) == email
}

// rejectExistingMember refuses invites for an email that already holds a
// membership on the org (409; response written). No membership → nil.
func (h *AdminHandlers) rejectExistingMember(w http.ResponseWriter, r *http.Request, orgID, email string) bool {
	existing, err := h.store.GetAdminUserByEmailWithHash(r.Context(), email)
	if err != nil || existing.ID == "" {
		return false // unknown email is the normal invite case
	}
	roles, err := h.store.GetUserOrgRoles(r.Context(), existing.ID)
	if err != nil {
		return false // unresolvable — let the invite proceed, accept is idempotent
	}
	if _, ok := roles[orgID]; ok {
		writeJSON(w, http.StatusConflict, apiError{Error: "this email is already a member of the organization"})
		return true
	}
	return false
}

// ResendInvite — POST /api/organizations/{id}/members/invites/{inviteID}/resend.
// Rotates the token and restarts the 72h window; the response carries the
// fresh one-time link.
func (h *AdminHandlers) ResendInvite() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is, ok := h.inviteStoreGuard(w, r)
		if !ok {
			return
		}
		orgID, inviteID := r.PathValue("id"), r.PathValue("inviteID")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		inv, token, err := is.ResendMemberInvite(r.Context(), orgID, inviteID, requestUserID(r))
		if err != nil {
			h.writeInviteStoreError(w, r, err)
			return
		}
		h.auditLogAction(r, "resend", "member_invite",
			"org="+orgID+",invite="+inv.ID+",email="+inv.Email+",role="+string(inv.Role))
		writeJSON(w, http.StatusOK, map[string]any{
			"invite":      inv,
			"invite_path": inviteURLPath(token),
			"expires_at":  inv.ExpiresAt,
		})
	}
}

// RevokeInvite — POST /api/organizations/{id}/members/invites/{inviteID}/revoke.
// The pending invite row is deleted, so the token stops resolving (404 on
// later use, indistinguishable from an unknown token).
func (h *AdminHandlers) RevokeInvite() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is, ok := h.inviteStoreGuard(w, r)
		if !ok {
			return
		}
		orgID, inviteID := r.PathValue("id"), r.PathValue("inviteID")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		if err := is.RevokeMemberInvite(r.Context(), orgID, inviteID, requestUserID(r)); err != nil {
			h.writeInviteStoreError(w, r, err)
			return
		}
		h.auditLogAction(r, "revoke", "member_invite", "org="+orgID+",invite="+inviteID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// inviteURLPath is the one-time acceptance path for a raw token.
func inviteURLPath(token string) string {
	return "/invite/" + token
}

// errText safely renders an error message (nil-safe).
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// --- public acceptance page --------------------------------------------------

// invitePageState carries the per-request state of the acceptance page.
type invitePageState struct {
	// Link states (mutually exclusive): exactly one renders.
	Preview    bool // valid invite — render the accept form
	Success    bool // accepted — render the confirmation
	NotFound   bool // unknown or revoked token
	Expired    bool // past the 72h window
	Accepted   bool // already consumed
	StoreError bool // transport failure — generic message, no reason leaked

	OrgName string
	Role    string
	Email   string // preserved on failure; prefilled from the invite
	ShowErr string // error copy key resolved by inviteErrStrings ("", badEmail, badCreds, badPassword)
}

// InvitePage — GET /invite/{token}: the public acceptance page. Token states
// map to statuses: unknown/revoked → 404, expired/accepted → 410.
func (h *AdminHandlers) InvitePage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is := h.inviteStore()
		if is == nil || h.store == nil {
			h.renderInvitePage(w, http.StatusServiceUnavailable, invitePageState{StoreError: true}, r)
			return
		}
		token := r.PathValue("token")
		preview, err := is.PreviewMemberInvite(r.Context(), token)
		if err != nil {
			h.renderInviteStoreState(w, r, err)
			return
		}
		h.renderInvitePage(w, http.StatusOK, invitePageState{
			Preview: true,
			OrgName: preview.OrgName,
			Role:    string(preview.Role),
			Email:   preview.Email,
		}, r)
	}
}

// renderInviteStoreState renders the terminal (non-form) states of a token
// with the matching HTTP status.
func (h *AdminHandlers) renderInviteStoreState(w http.ResponseWriter, r *http.Request, err error) {
	st := invitePageState{}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, adminstore.ErrNotFound):
		st.NotFound = true
		status = http.StatusNotFound
	case errors.Is(err, adminstore.ErrInviteExpired):
		st.Expired = true
		status = http.StatusGone
	case errors.Is(err, adminstore.ErrInviteAccepted):
		st.Accepted = true
		status = http.StatusGone
	default:
		st.StoreError = true
	}
	h.renderInvitePage(w, status, st, r)
}

// HandleInviteAccept — POST /invite/{token}: consume the invite. The form
// carries the invited email (must match), the account password (verified for
// an existing account, used to provision a new one) and the CSRF pair. Every
// failure re-renders the form page with one generic message; the reason goes
// to the server log only.
func (h *AdminHandlers) HandleInviteAccept() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		is := h.inviteStore()
		if is == nil || h.store == nil {
			h.renderInvitePage(w, http.StatusServiceUnavailable, invitePageState{StoreError: true}, r)
			return
		}
		token := r.PathValue("token")

		csrfCookie, err := r.Cookie("yabanin_csrf_token")
		if err != nil || csrfCookie.Value == "" || !hmac.Equal([]byte(csrfCookie.Value), []byte(r.PostFormValue("_csrf"))) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		preview, err := is.PreviewMemberInvite(r.Context(), token)
		if err != nil {
			h.renderInviteStoreState(w, r, err)
			return
		}

		email := adminstore.NormalizeInviteEmail(r.PostFormValue("email"))
		password := r.PostFormValue("password")
		fail := func(logReason, errKey string, status int) {
			if h.logger != nil {
				h.logger.Warn("member invite acceptance refused", "reason", logReason)
			}
			h.renderInvitePage(w, status, invitePageState{
				Preview: true,
				OrgName: preview.OrgName,
				Role:    string(preview.Role),
				Email:   email,
				ShowErr: errKey,
			}, r)
		}

		if email == "" || email != adminstore.NormalizeInviteEmail(preview.Email) {
			fail("email does not match the invite", "badEmail", http.StatusBadRequest)
			return
		}

		// Existing account → verify the password; unknown account → provision
		// one under the admin credential policy. The same generic error is
		// rendered for both failure classes (no account-existence oracle).
		var passwordHash string
		existing, err := h.store.GetAdminUserByEmailWithHash(r.Context(), email)
		switch {
		case err == nil:
			if adminauth.VerifyPassword(password, existing.PasswordHash) != nil || !existing.Active {
				fail("invalid credentials", "badCreds", http.StatusUnauthorized)
				return
			}
		case adminstore.IsNotFound(err) || containsText(errText(err), "not found"):
			// Unknown email: the invited person sets their initial password.
			// containsText mirrors roles_handlers.go — stores/tests without a
			// pgx-wrapped sentinel still classify as not-found.
			if err := validateAdminPassword(password); err != nil {
				fail("password policy", "badPassword", http.StatusBadRequest)
				return
			}
			hashed, herr := adminauth.HashPassword(password)
			if herr != nil {
				fail("hash failure", "badCreds", http.StatusInternalServerError)
				return
			}
			passwordHash = hashed
		default:
			if h.logger != nil {
				h.logger.Error("member invite user lookup failed", "error", err.Error())
			}
			h.renderInvitePage(w, http.StatusInternalServerError, invitePageState{StoreError: true}, r)
			return
		}

		res, err := is.AcceptMemberInvite(r.Context(), token, passwordHash)
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) || errors.Is(err, adminstore.ErrInviteExpired) || errors.Is(err, adminstore.ErrInviteAccepted) {
				h.renderInviteStoreState(w, r, err)
				return
			}
			if h.logger != nil {
				h.logger.Error("member invite acceptance failed", "error", err.Error())
			}
			h.renderInvitePage(w, http.StatusInternalServerError, invitePageState{StoreError: true}, r)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "accept", "member_invite",
			"org="+res.Invite.OrgID+",invite="+res.Invite.ID+",email="+res.Invite.Email+
				",user="+res.UserID+",user_created="+fmt.Sprint(res.UserCreated))
		h.renderInvitePage(w, http.StatusOK, invitePageState{
			Success: true,
			OrgName: res.OrgName,
			Role:    string(res.Invite.Role),
		}, r)
	}
}

// --- invite page rendering (Paper & Olive tokens, dashboard locales) --------

type inviteStrings struct {
	Title       string
	Heading     string
	InvitedAs   string
	Email       string
	Password    string
	NewPassword string
	NameHint    string
	Accept      string
	Success     string
	SuccessNext string
	SignIn      string
	LinkInvalid string
	LinkExpired string
	LinkUsed    string
	StoreError  string
	ErrEmail    string
	ErrCreds    string
	ErrPassword string
}

// #nosec G101 -- localized UI copy only; no credential material in this map.
var inviteTranslations = map[string]inviteStrings{
	"ar": {
		Title:       "دعوة — Yabanin Admin",
		Heading:     "دعوة إلى %s",
		InvitedAs:   "تمت دعوتك بدور %s.",
		Email:       "البريد الإلكتروني",
		Password:    "كلمة المرور",
		NewPassword: "كلمة مرور جديدة (12 حرفًا على الأقل)",
		NameHint:    "إذا كان لديك حساب بالفعل، فاستخدم كلمة المرور الحالية.",
		Accept:      "قبول الدعوة",
		Success:     "تم قبول الدعوة. لديك الآن صلاحية الوصول إلى %s.",
		SuccessNext: "يمكنك تسجيل الدخول إلى وحدة التحكم.",
		SignIn:      "تسجيل الدخول",
		LinkInvalid: "رابط الدعوة غير صالح.",
		LinkExpired: "انتهت صلاحية هذه الدعوة. اطلب رابطًا جديدًا.",
		LinkUsed:    "تم استخدام هذه الدعوة بالفعل.",
		StoreError:  "الخدمة غير متاحة حاليًا. حاول لاحقًا.",
		ErrEmail:    "البريد الإلكتروني لا يطابق الدعوة.",
		ErrCreds:    "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
		ErrPassword: "كلمة المرور غير صالحة.",
	},
	"en": {
		Title:       "Invitation — Yabanin Admin",
		Heading:     "You are invited to %s",
		InvitedAs:   "You were invited with the role %s.",
		Email:       "Email",
		Password:    "Password",
		NewPassword: "New password (at least 12 characters)",
		NameHint:    "Already have an account here? Use your current password.",
		Accept:      "Accept invitation",
		Success:     "Invitation accepted. You now have access to %s.",
		SuccessNext: "You can now sign in to the console.",
		SignIn:      "Sign in",
		LinkInvalid: "This invitation link is not valid.",
		LinkExpired: "This invitation has expired. Ask for a new link.",
		LinkUsed:    "This invitation was already used.",
		StoreError:  "The service is temporarily unavailable. Try again later.",
		ErrEmail:    "The email does not match the invitation.",
		ErrCreds:    "Invalid email or password.",
		ErrPassword: "Invalid password.",
	},
	"es": {
		Title:       "Invitación — Yabanin Admin",
		Heading:     "Has sido invitado a %s",
		InvitedAs:   "Fuiste invitado con el rol %s.",
		Email:       "Correo electrónico",
		Password:    "Contraseña",
		NewPassword: "Nueva contraseña (mínimo 12 caracteres)",
		NameHint:    "¿Ya tienes una cuenta? Usa tu contraseña actual.",
		Accept:      "Aceptar invitación",
		Success:     "Invitación aceptada. Ya tienes acceso a %s.",
		SuccessNext: "Ya puedes iniciar sesión en la consola.",
		SignIn:      "Iniciar sesión",
		LinkInvalid: "Este enlace de invitación no es válido.",
		LinkExpired: "Esta invitación ha caducado. Solicita un enlace nuevo.",
		LinkUsed:    "Esta invitación ya se utilizó.",
		StoreError:  "El servicio no está disponible temporalmente. Inténtalo más tarde.",
		ErrEmail:    "El correo no coincide con la invitación.",
		ErrCreds:    "Correo electrónico o contraseña no válidos.",
		ErrPassword: "Contraseña no válida.",
	},
	"hi": {
		Title:       "निमंत्रण — Yabanin Admin",
		Heading:     "आपको %s में आमंत्रित किया गया है",
		InvitedAs:   "आपको %s भूमिका के साथ आमंत्रित किया गया था।",
		Email:       "ईमेल",
		Password:    "पासवर्ड",
		NewPassword: "नया पासवर्ड (कम से कम 12 वर्ण)",
		NameHint:    "पहले से खाता है? अपना मौजूदा पासवर्ड उपयोग करें।",
		Accept:      "निमंत्रण स्वीकार करें",
		Success:     "निमंत्रण स्वीकार हो गया। अब आपकी %s तक पहुँच है।",
		SuccessNext: "अब आप कंसोल में साइन इन कर सकते हैं।",
		SignIn:      "साइन इन",
		LinkInvalid: "यह निमंत्रण लिंक मान्य नहीं है।",
		LinkExpired: "यह निमंत्रण समाप्त हो गया है। नया लिंक मांगें।",
		LinkUsed:    "यह निमंत्रण पहले ही उपयोग हो चुका है।",
		StoreError:  "सेवा अस्थायी रूप से उपलब्ध नहीं है। बाद में पुनः प्रयास करें।",
		ErrEmail:    "ईमेल निमंत्रण से मेल नहीं खाता।",
		ErrCreds:    "ईमेल या पासवर्ड अमान्य है।",
		ErrPassword: "पासवर्ड अमान्य है।",
	},
	"id": {
		Title:       "Undangan — Yabanin Admin",
		Heading:     "Anda diundang ke %s",
		InvitedAs:   "Anda diundang dengan peran %s.",
		Email:       "Email",
		Password:    "Kata sandi",
		NewPassword: "Kata sandi baru (minimal 12 karakter)",
		NameHint:    "Sudah punya akun? Gunakan kata sandi Anda saat ini.",
		Accept:      "Terima undangan",
		Success:     "Undangan diterima. Anda kini memiliki akses ke %s.",
		SuccessNext: "Anda dapat masuk ke konsol sekarang.",
		SignIn:      "Masuk",
		LinkInvalid: "Tautan undangan ini tidak valid.",
		LinkExpired: "Undangan ini telah kedaluwarsa. Minta tautan baru.",
		LinkUsed:    "Undangan ini sudah digunakan.",
		StoreError:  "Layanan sementara tidak tersedia. Coba lagi nanti.",
		ErrEmail:    "Email tidak cocok dengan undangan.",
		ErrCreds:    "Email atau kata sandi tidak valid.",
		ErrPassword: "Kata sandi tidak valid.",
	},
	"ja": {
		Title:       "招待 — Yabanin Admin",
		Heading:     "%s への招待",
		InvitedAs:   "ロール %s で招待されました。",
		Email:       "メールアドレス",
		Password:    "パスワード",
		NewPassword: "新しいパスワード（12文字以上）",
		NameHint:    "すでにアカウントをお持ちの場合は、現在のパスワードを使用してください。",
		Accept:      "招待を承認",
		Success:     "招待を承認しました。%s にアクセスできます。",
		SuccessNext: "コンソールにサインインできます。",
		SignIn:      "サインイン",
		LinkInvalid: "この招待リンクは無効です。",
		LinkExpired: "この招待は期限切れです。新しいリンクを依頼してください。",
		LinkUsed:    "この招待は既に使用されています。",
		StoreError:  "サービスは一時的に利用できません。後でもう一度お試しください。",
		ErrEmail:    "メールアドレスが招待と一致しません。",
		ErrCreds:    "メールアドレスまたはパスワードが正しくありません。",
		ErrPassword: "パスワードが無効です。",
	},
	"ko": {
		Title:       "초대 — Yabanin Admin",
		Heading:     "%s 초대",
		InvitedAs:   "%s 역할로 초대되었습니다.",
		Email:       "이메일",
		Password:    "비밀번호",
		NewPassword: "새 비밀번호 (12자 이상)",
		NameHint:    "이미 계정이 있나요? 현재 비밀번호를 사용하세요.",
		Accept:      "초대 수락",
		Success:     "초대를 수락했습니다. 이제 %s에 접근할 수 있습니다.",
		SuccessNext: "이제 콘솔에 로그인할 수 있습니다.",
		SignIn:      "로그인",
		LinkInvalid: "이 초대 링크는 유효하지 않습니다.",
		LinkExpired: "이 초대는 만료되었습니다. 새 링크를 요청하세요.",
		LinkUsed:    "이 초대는 이미 사용되었습니다.",
		StoreError:  "서비스를 일시적으로 사용할 수 없습니다. 나중에 다시 시도하세요.",
		ErrEmail:    "이메일이 초대와 일치하지 않습니다.",
		ErrCreds:    "이메일 또는 비밀번호가 올바르지 않습니다.",
		ErrPassword: "비밀번호가 올바르지 않습니다.",
	},
	"pt-BR": {
		Title:       "Convite — Yabanin Admin",
		Heading:     "Você foi convidado para %s",
		InvitedAs:   "Você foi convidado com o papel %s.",
		Email:       "E-mail",
		Password:    "Senha",
		NewPassword: "Nova senha (mínimo de 12 caracteres)",
		NameHint:    "Já tem uma conta? Use sua senha atual.",
		Accept:      "Aceitar convite",
		Success:     "Convite aceito. Você agora tem acesso a %s.",
		SuccessNext: "Você já pode entrar no console.",
		SignIn:      "Entrar",
		LinkInvalid: "Este link de convite não é válido.",
		LinkExpired: "Este convite expirou. Solicite um novo link.",
		LinkUsed:    "Este convite já foi utilizado.",
		StoreError:  "O serviço está temporariamente indisponível. Tente novamente mais tarde.",
		ErrEmail:    "O e-mail não corresponde ao convite.",
		ErrCreds:    "E-mail ou senha inválidos.",
		ErrPassword: "Senha inválida.",
	},
}

func inviteStringsFor(lang string) inviteStrings {
	if s, ok := inviteTranslations[lang]; ok {
		return s
	}
	return inviteTranslations["en"]
}

// inviteErrStrings resolves a ShowErr key onto its localized copy.
func inviteErrStrings(key string, s inviteStrings) string {
	switch key {
	case "badEmail":
		return s.ErrEmail
	case "badCreds":
		return s.ErrCreds
	case "badPassword":
		return s.ErrPassword
	}
	return ""
}

// renderInvitePage writes the acceptance page with a fresh CSRF token. The
// reason for a re-render is never part of the page beyond the generic
// localized error copy.
func (h *AdminHandlers) renderInvitePage(w http.ResponseWriter, status int, st invitePageState, r *http.Request) {
	token := adminauth.GenerateCSRFToken(w)
	if token == "" {
		return // GenerateCSRFToken already wrote the 500
	}
	lang := negotiateLoginLocale(r.Header.Get("Accept-Language"))
	str := inviteStringsFor(lang)
	errText := inviteErrStrings(st.ShowErr, str)
	data := struct {
		Lang    string
		Dir     string
		CSRF    string
		ErrText string
		Str     inviteStrings
		invitePageState
	}{
		Lang:            lang,
		Dir:             loginTextDirection(lang),
		CSRF:            token,
		ErrText:         errText,
		Str:             str,
		invitePageState: st,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := invitePageTemplate.Execute(w, data); err != nil && h.logger != nil {
		h.logger.Error("render invite page", "error", err)
	}
}

var invitePageTemplate = template.Must(template.New("invite").Parse(`<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Str.Title}}</title>
<style>
:root{--paper:#f2efe6;--surface:#faf8f1;--surface-muted:#e8e5d9;--ink:#292d24;--text-muted:#626657;--rule:#d2d3c4;--rule-strong:#808570;--action:#59633f;--action-hover:#465033;--on-action:#faf8f1;--danger:#9a4437;--danger-surface:#f5e7e0;--focus:#4c6236;--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--font-body:15px;--font-label:12px;--font-small:13px;--radius-control:4px;--radius-panel:6px;--height-control:44px;--space-4:16px;--space-5:24px;--space-6:32px;--duration:140ms}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font-ui);font-size:var(--font-body);background:var(--paper);color:var(--ink);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:var(--space-5)}
.card{background:var(--surface);border:1px solid var(--rule);border-radius:var(--radius-panel);padding:var(--space-6);width:100%;max-width:380px}
h1{font-size:20px;font-weight:600;margin-bottom:var(--space-4)}
p{margin-bottom:var(--space-4)}
.muted{color:var(--text-muted);font-size:var(--font-small)}
label{display:block;font-size:var(--font-label);color:var(--text-muted);margin-bottom:4px}
input[type=email],input[type=password]{width:100%;height:var(--height-control);padding:0 12px;margin-bottom:var(--space-4);border:1px solid var(--rule);border-radius:var(--radius-control);background:var(--surface);color:var(--ink);font:inherit;outline:none}
input:hover{border-color:var(--rule-strong)}
input:focus{border-color:var(--focus);box-shadow:0 0 0 1px var(--focus)}
button[type=submit]{width:100%;height:var(--height-control);background:var(--action);color:var(--on-action);border:none;border-radius:var(--radius-control);font:inherit;font-weight:600;cursor:pointer;transition:background var(--duration)}
button:hover{background:var(--action-hover)}
button:focus-visible,a:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.error{background:var(--danger-surface);color:var(--danger);border:1px solid var(--danger);border-radius:var(--radius-control);padding:12px;font-size:var(--font-small);margin-bottom:var(--space-4)}
.signin{display:block;text-align:center;margin-top:var(--space-4);padding:0 12px;height:var(--height-control);line-height:42px;border:1px solid var(--rule);border-radius:var(--radius-control);color:var(--action);text-decoration:none;font-size:var(--font-small);transition:border-color var(--duration)}
.signin:hover{border-color:var(--rule-strong);background:var(--surface-muted)}
</style>
</head>
<body>
<main class="card">
{{if .Success}}
<h1>%s</h1>
<p>{{printf .Str.Success .OrgName}}</p>
<p class="muted">{{.Str.SuccessNext}}</p>
<a class="signin" href="/auth/login">{{.Str.SignIn}}</a>
{{else if .NotFound}}
<h1>{{.Str.Title}}</h1>
<p class="error" role="alert">{{.Str.LinkInvalid}}</p>
{{else if .Expired}}
<h1>{{.Str.Title}}</h1>
<p class="error" role="alert">{{.Str.LinkExpired}}</p>
{{else if .Accepted}}
<h1>{{.Str.Title}}</h1>
<p class="error" role="alert">{{.Str.LinkUsed}}</p>
<a class="signin" href="/auth/login">{{.Str.SignIn}}</a>
{{else if .StoreError}}
<h1>{{.Str.Title}}</h1>
<p class="error" role="alert">{{.Str.StoreError}}</p>
{{else}}
<h1>{{printf .Str.Heading .OrgName}}</h1>
<p class="muted">{{printf .Str.InvitedAs .Role}}</p>
{{if .ErrText}}<p class="error" role="alert">{{.ErrText}}</p>{{end}}
<form method="post" action="">
<input type="hidden" name="_csrf" value="{{.CSRF}}">
<label for="email">{{.Str.Email}}</label>
<input type="email" id="email" name="email" value="{{.Email}}" required autocomplete="username" autocapitalize="none" spellcheck="false">
<label for="password">{{.Str.NewPassword}}</label>
<input type="password" id="password" name="password" required autocomplete="new-password" minlength="12">
<p class="muted">{{.Str.NameHint}}</p>
<button type="submit">{{.Str.Accept}}</button>
</form>
{{end}}
</main>
</body>
</html>`))
