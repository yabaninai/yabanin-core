package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// LoginPage serves the admin login page. The page is rendered in the Paper &
// Olive design tokens (design/astra-tokens.css, inlined — the page ships no
// external assets) and localized by Accept-Language across the dashboard
// locales with an "en" fallback.
func (h *AdminHandlers) LoginPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lang := negotiateLoginLocale(r.Header.Get("Accept-Language"))
		h.renderLoginPage(w, http.StatusOK, loginPageState{
			Next: safeRedirectTarget(r.URL.Query().Get("next")),
		}, lang)
	}
}

// CSRFToken returns the session CSRF cookie value, issuing one when absent.
// The cookie stays HttpOnly; the JSON body is how the dashboard learns the token.
func (h *AdminHandlers) CSRFToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie("yabanin_csrf_token"); err == nil {
			token = c.Value
		}
		if token == "" {
			token = adminauth.GenerateCSRFToken(w)
			if token == "" {
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"csrf_token": token})
	}
}

// HandleLogin serves the login request. Every failure — unknown user, wrong
// password, disabled account, missing fields — renders the same login page
// with a 401 and one generic message: the reason goes to the server log
// only, never to the client. The submitted email is preserved in the form;
// the password never is.
func (h *AdminHandlers) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		csrfCookie, err := r.Cookie("yabanin_csrf_token")
		if err != nil || csrfCookie.Value == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		givenCSRF := r.FormValue("_csrf")
		if givenCSRF == "" {
			givenCSRF = r.PostFormValue("_csrf")
		}
		if !hmac.Equal([]byte(csrfCookie.Value), []byte(givenCSRF)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		next := safeRedirectTarget(r.FormValue("next"))
		lang := negotiateLoginLocale(r.Header.Get("Accept-Language"))

		loginFailed := func(reason string) {
			if h.logger != nil {
				h.logger.Warn("admin login refused", "reason", reason)
			}
			h.renderLoginPage(w, http.StatusUnauthorized, loginPageState{
				Email:     email,
				Next:      next,
				ShowError: true,
			}, lang)
		}

		if email == "" || password == "" {
			loginFailed("missing credentials")
			return
		}

		user, err := h.store.GetAdminUserByEmailWithHash(r.Context(), email)
		if err != nil {
			// bcrypt work as a wrong password, or response time reveals
			// whether the account exists. The burn always fails.
			adminauth.BurnBcryptWork(password)
			loginFailed("invalid credentials")
			return
		}

		if adminauth.VerifyPassword(password, user.PasswordHash) != nil {
			loginFailed("invalid credentials")
			return
		}

		if !user.Active {
			loginFailed("account disabled")
			return
		}

		now := time.Now()
		session := adminauth.AdminSession{
			UserID: user.ID,
			Email:  user.Email,
			IsRoot: user.IsRoot,
			// The configured adminauth.SessionDuration (24h), not a hardcoded week.
			ExpiresAt: now.Add(adminauth.SessionDuration),
			// Issued-at anchors the invalidation watermark: a session must read
			// as issued AFTER the login that created it, or the guarded
			// middleware rejects it as legacy once any password change exists.
			IssuedAt:  now,
			SessionID: generateSessionID(),
		}
		cookie, err := adminauth.CreateAdminSessionCookie(session, h.sessionSecret)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("session error"), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)

		http.Redirect(w, r, next, http.StatusFound)
	}
}

// HandleLogout serves the logout request (GET for backward compatibility;
// the POST route is CSRF-validated in the router — see artifacts/imp/
func (h *AdminHandlers) HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("yabanin_admin_session")
		if err == nil && cookie.Value != "" {
			session, _, parseErr := adminauth.ParseAdminSessionCookieRotating(cookie.Value, h.sessionSecret, h.previousSessionSecret, h.sessionGraceStarted, h.sessionGrace, time.Now())
			if parseErr == nil {
				// Immediately reject replays on this process even if the durable
				// write fails; the shared store remains authoritative across replicas.
				adminauth.RevokeSessionID(session.SessionID, session.ExpiresAt)
				if h.sessionRevocations != nil {
					if err := h.sessionRevocations.Revoke(r.Context(), session.SessionID, session.ExpiresAt); err != nil {
						if h.logger != nil {
							h.logger.Error("admin session revocation failed", "error", err)
						}
						// Logout is confirmed only after the durable revocation write;
						// without it another replica may still accept this session.
						h.respondError(w, r, fmt.Errorf("could not complete logout"), http.StatusServiceUnavailable)
						return
					}
				}
			}
		}
		http.SetCookie(w, adminauth.ClearSessionCookie())
		http.SetCookie(w, &http.Cookie{
			Name:     "yabanin_csrf_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	}
}

// safeRedirectTarget validates a post-login redirect target. Only a relative
// path is accepted: it must start with "/", never with "//" or "/\"
// (protocol-relative URLs), and carry no scheme or backslash. Anything else —
// including "javascript:", absolute URLs and control characters — collapses
// to "/".
func safeRedirectTarget(next string) string {
	next = strings.TrimSpace(next)
	if !strings.HasPrefix(next, "/") {
		return "/"
	}
	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	if strings.ContainsAny(next, ":\\") {
		return "/"
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	return next
}

// --- login page rendering ---------------------------------------------------

// loginPageState carries the per-request form state across renders.
type loginPageState struct {
	Email     string // preserved on failure; the password never is
	Next      string // already validated via safeRedirectTarget
	ShowError bool   // one generic message, no failure reason
}

// renderLoginPage writes the login page with a fresh CSRF token (cookie +
// hidden field). The reason for a re-render is never part of the state.
func (h *AdminHandlers) renderLoginPage(w http.ResponseWriter, status int, st loginPageState, lang string) {
	token := adminauth.GenerateCSRFToken(w)
	if token == "" {
		return // GenerateCSRFToken already wrote the 500
	}
	str := loginStringsFor(lang)
	data := struct {
		Lang      string
		Dir       string
		CSRFToken string
		Next      string
		Email     string
		ShowError bool
		SSO       bool
		SSOURL    string
		Str       loginStrings
	}{
		Lang:      lang,
		Dir:       loginTextDirection(lang),
		CSRFToken: token,
		Next:      st.Next,
		Email:     st.Email,
		ShowError: st.ShowError,
		SSO:       h.oidcClient != nil,
		SSOURL:    oidcLoginURL(st.Next),
		Str:       str,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := loginPageTemplate.Execute(w, data); err != nil && h.logger != nil {
		h.logger.Error("render login page", "error", err)
	}
}

func oidcLoginURL(next string) string {
	next = safeOIDCReturnTarget(next)
	if next == "" || next == "/" {
		return "/auth/oidc/login"
	}
	return "/auth/oidc/login?" + url.Values{"next": {next}}.Encode()
}

// --- localization (dashboard locales: ar, en, es, hi, id, ja, ko, pt-BR) ----

const defaultLoginLocale = "en"

type loginStrings struct {
	Title    string
	Email    string
	Password string
	SignIn   string
	SSO      string
	Error    string
}

// #nosec G101 -- "Password" here is the localized form label rendered above
// the password input; no credential material appears in this map.
var loginTranslations = map[string]loginStrings{
	"ar": {
		Title:    "تسجيل الدخول — Yabanin Admin",
		Email:    "البريد الإلكتروني",
		Password: "كلمة المرور",
		SignIn:   "تسجيل الدخول",
		SSO:      "تسجيل الدخول عبر SSO",
		Error:    "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
	},
	"en": {
		Title:    "Sign in — Yabanin Admin",
		Email:    "Email",
		Password: "Password",
		SignIn:   "Sign in",
		SSO:      "Sign in with SSO",
		Error:    "Invalid email or password.",
	},
	"es": {
		Title:    "Iniciar sesión — Yabanin Admin",
		Email:    "Correo electrónico",
		Password: "Contraseña",
		SignIn:   "Iniciar sesión",
		SSO:      "Iniciar sesión con SSO",
		Error:    "Correo electrónico o contraseña no válidos.",
	},
	"hi": {
		Title:    "साइन इन — Yabanin Admin",
		Email:    "ईमेल",
		Password: "पासवर्ड",
		SignIn:   "साइन इन करें",
		SSO:      "SSO से साइन इन करें",
		Error:    "ईमेल या पासवर्ड अमान्य है.",
	},
	"id": {
		Title:    "Masuk — Yabanin Admin",
		Email:    "Email",
		Password: "Kata sandi",
		SignIn:   "Masuk",
		SSO:      "Masuk dengan SSO",
		Error:    "Email atau kata sandi tidak valid.",
	},
	"ja": {
		Title:    "サインイン — Yabanin Admin",
		Email:    "メールアドレス",
		Password: "パスワード",
		SignIn:   "サインイン",
		SSO:      "SSO でサインイン",
		Error:    "メールアドレスまたはパスワードが正しくありません。",
	},
	"ko": {
		Title:    "로그인 — Yabanin Admin",
		Email:    "이메일",
		Password: "비밀번호",
		SignIn:   "로그인",
		SSO:      "SSO로 로그인",
		Error:    "이메일 또는 비밀번호가 올바르지 않습니다.",
	},
	"pt-BR": {
		Title:    "Entrar — Yabanin Admin",
		Email:    "E-mail",
		Password: "Senha",
		SignIn:   "Entrar",
		SSO:      "Entrar com SSO",
		Error:    "E-mail ou senha inválidos.",
	},
}

func loginStringsFor(lang string) loginStrings {
	if s, ok := loginTranslations[lang]; ok {
		return s
	}
	return loginTranslations[defaultLoginLocale]
}

func loginTextDirection(lang string) string {
	if lang == "ar" {
		return "rtl"
	}
	return "ltr"
}

// negotiateLoginLocale picks the best dashboard locale from an
// Accept-Language header (RFC 9110 ranges with q-values). Exact matches beat
// prefix matches at the same q; earlier ranges win ties; unknown or zero-q
// ranges are skipped; anything unresolved falls back to "en".
func negotiateLoginLocale(header string) string {
	bestMatch := ""
	bestQ := -1.0
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag := part
		q := 1.0
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			tag = strings.TrimSpace(part[:semi])
			q = parseQualityValue(part[semi+1:])
			if q <= 0 {
				continue
			}
		}
		match := matchLoginLocale(tag)
		if match == "" {
			continue
		}
		if q > bestQ {
			bestMatch = match
			bestQ = q
		}
	}
	if bestMatch == "" {
		return defaultLoginLocale
	}
	return bestMatch
}

// parseQualityValue parses a single q parameter ("q=0.7"); a malformed value
// yields 0 so the range is skipped.
func parseQualityValue(params string) float64 {
	for _, p := range strings.Split(params, ";") {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(strings.ToLower(p), "q=") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64)
		if err != nil || v < 0 || v > 1 {
			return 0
		}
		return v
	}
	return 0
}

// matchLoginLocale matches one Accept-Language tag against the supported
// locales: case-insensitive exact match first (pt-br → pt-BR), then a
// primary-subtag match in both directions (pt → pt-BR, en-US → en).
// "*" and unknown tags match nothing here — the caller falls back to "en".
func matchLoginLocale(tag string) string {
	tag = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(tag), "_", "-"))
	if tag == "" || tag == "*" {
		return ""
	}
	locales := []string{"ar", "en", "es", "hi", "id", "ja", "ko", "pt-BR"}
	for _, locale := range locales {
		if tag == strings.ToLower(locale) {
			return locale
		}
	}
	primary := tag
	if dash := strings.IndexByte(tag, '-'); dash >= 0 {
		primary = tag[:dash]
	}
	for _, locale := range locales {
		if localePrimary, _, _ := strings.Cut(strings.ToLower(locale), "-"); primary == localePrimary {
			return locale
		}
	}
	return ""
}

// --- template ---------------------------------------------------------------

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Str.Title}}</title>
<style>
:root{--paper:#f2efe6;--surface:#faf8f1;--surface-muted:#e8e5d9;--ink:#292d24;--text-muted:#626657;--rule:#d2d3c4;--rule-strong:#808570;--action:#59633f;--action-hover:#465033;--on-action:#faf8f1;--danger:#9a4437;--danger-surface:#f5e7e0;--focus:#4c6236;--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--font-body:15px;--font-label:12px;--font-small:13px;--radius-control:4px;--radius-panel:6px;--height-control:44px;--space-4:16px;--space-5:24px;--space-6:32px;--duration:140ms}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font-ui);font-size:var(--font-body);background:var(--paper);color:var(--ink);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:var(--space-5)}
.card{background:var(--surface);border:1px solid var(--rule);border-radius:var(--radius-panel);padding:var(--space-6);width:100%;max-width:380px}
h1{font-size:20px;font-weight:600;margin-bottom:var(--space-5)}
label{display:block;font-size:var(--font-label);color:var(--text-muted);margin-bottom:4px}
input[type=email],input[type=password]{width:100%;height:var(--height-control);padding:0 12px;margin-bottom:var(--space-4);border:1px solid var(--rule);border-radius:var(--radius-control);background:var(--surface);color:var(--ink);font:inherit;outline:none}
input:hover{border-color:var(--rule-strong)}
input:focus{border-color:var(--focus);box-shadow:0 0 0 1px var(--focus)}
button[type=submit]{width:100%;height:var(--height-control);background:var(--action);color:var(--on-action);border:none;border-radius:var(--radius-control);font:inherit;font-weight:600;cursor:pointer;transition:background var(--duration)}
button:hover{background:var(--action-hover)}
button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.error{background:var(--danger-surface);color:var(--danger);border:1px solid var(--danger);border-radius:var(--radius-control);padding:12px;font-size:var(--font-small);margin-bottom:var(--space-4)}
.sso{display:block;text-align:center;margin-top:var(--space-4);padding:0 12px;height:var(--height-control);line-height:42px;border:1px solid var(--rule);border-radius:var(--radius-control);color:var(--action);text-decoration:none;font-size:var(--font-small);transition:border-color var(--duration)}
.sso:hover{border-color:var(--rule-strong);background:var(--surface-muted)}
.sso:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
</style>
</head>
<body>
<main class="card">
<h1>Yabanin Admin</h1>
{{if .ShowError}}<p class="error" role="alert">{{.Str.Error}}</p>{{end}}
<form method="post" action="/auth/login">
<input type="hidden" name="_csrf" value="{{.CSRFToken}}">
<input type="hidden" name="next" value="{{.Next}}">
<label for="email">{{.Str.Email}}</label>
<input type="email" id="email" name="email" value="{{.Email}}" required autocomplete="username" autocapitalize="none" spellcheck="false">
<label for="password">{{.Str.Password}}</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
<button type="submit">{{.Str.SignIn}}</button>
</form>
{{if .SSO}}<a class="sso" href="{{.SSOURL}}">{{.Str.SSO}}</a>{{end}}
</main>
</body>
</html>`))

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "sess_" + hex.EncodeToString(b)
}

// the admin_users.sessions_changed_at watermark for the user, or the zero
// time when none is recorded. Stores that predate the watermark accessor
// store exposes the accessor once migration 0024 is applied.
func (h *AdminHandlers) adminSessionsInvalidatedAt(ctx context.Context, userID string) (time.Time, error) {
	watermarked, ok := h.store.(interface {
		GetAdminUserSessionsInvalidatedAt(ctx context.Context, userID string) (time.Time, error)
	})
	if !ok {
		return time.Time{}, nil
	}
	return watermarked.GetAdminUserSessionsInvalidatedAt(ctx, userID)
}
