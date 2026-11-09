package handlers

import (
	"crypto/hmac"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/clientconfig"
)

// Portal page tokens are the Astra :root values from design/astra-tokens.css.
// The page embeds them so it does not load a stylesheet from another origin.
const portalPageCSS = `
:root {
  --astra-paper: #f2efe6;
  --astra-surface: #faf8f1;
  --astra-ink: #292d24;
  --astra-text-muted: #626657;
  --astra-rule: #d2d3c4;
  --astra-action: #59633f;
  --astra-action-hover: #465033;
  --astra-on-action: #faf8f1;
  --astra-warning: #755820;
  --astra-warning-surface: #f3ecd8;
  --astra-danger: #9a4437;
  --astra-code-surface: #e8e5d9;
  --astra-font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --astra-font-editorial: Georgia, "Times New Roman", serif;
  --astra-font-code: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  --astra-font-body: 15px;
  --astra-space-2: 8px;
  --astra-space-3: 12px;
  --astra-space-4: 16px;
  --astra-space-5: 24px;
  --astra-space-6: 32px;
  --astra-radius-control: 4px;
  --astra-height-control: 44px;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--astra-paper); color: var(--astra-ink); font-family: var(--astra-font-ui); font-size: var(--astra-font-body); }
main { max-width: 40rem; margin: var(--astra-space-6) auto; padding: 0 var(--astra-space-4); }
h1 { font-family: var(--astra-font-editorial); font-weight: normal; font-size: 2rem; }
h2 { font-size: 1.1rem; margin-top: var(--astra-space-6); }
p, li { line-height: 1.45; }
.muted { color: var(--astra-text-muted); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: var(--astra-space-2) var(--astra-space-2); border-bottom: 1px solid var(--astra-rule); vertical-align: top; }
button, .linkish { font: inherit; background: var(--astra-action); color: var(--astra-on-action); border: 0; border-radius: var(--astra-radius-control); min-height: var(--astra-height-control); padding: 0 var(--astra-space-4); }
button:hover { background: var(--astra-action-hover); }
input[type="text"] { font: inherit; width: 100%; min-height: var(--astra-height-control); padding: 0 var(--astra-space-3); border: 1px solid var(--astra-rule); border-radius: var(--astra-radius-control); background: var(--astra-surface); color: var(--astra-ink); }
label { display: block; margin-bottom: var(--astra-space-2); }
.row { display: flex; gap: var(--astra-space-3); align-items: end; flex-wrap: wrap; }
.row label { flex: 1 1 12rem; }
.warning { background: var(--astra-warning-surface); color: var(--astra-warning); padding: var(--astra-space-3); margin: var(--astra-space-4) 0; }
.danger { color: var(--astra-danger); }
pre, code { font-family: var(--astra-font-code); }
pre { background: var(--astra-code-surface); padding: var(--astra-space-3); overflow: auto; white-space: pre-wrap; }
.toolbar { display: flex; justify-content: space-between; align-items: center; gap: var(--astra-space-3); }
`

const portalPageSrc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My keys</title>
<style>` + portalPageCSS + `</style>
</head>
<body>
<main>
  <div class="toolbar">
    <h1>My keys</h1>
    <form method="post" action="/portal/logout">
      <input type="hidden" name="_csrf" value="{{.CSRF}}">
      <button type="submit">Sign out</button>
    </form>
  </div>
  <p class="muted">{{.Email}}</p>
  {{if .Error}}<p class="danger" role="alert">{{.Error}}</p>{{end}}
  {{if .RevealedKey}}
  <div class="warning" role="status">
    <p>This key is shown once. Copy it now. It will not be shown again.</p>
    <p><code id="new-key">{{.RevealedKey}}</code></p>
    <button type="button" data-copy="new-key">Copy key</button>
  </div>
  {{end}}
  <h2>Keys</h2>
  {{if .Keys}}
  <table>
    <thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Status</th><th></th></tr></thead>
    <tbody>
    {{range .Keys}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{.Created}}</td>
        <td>{{.Expires}}</td>
        <td>{{.Status}}</td>
        <td>
          {{if .CanRevoke}}
          <form method="post" action="/portal/keys/{{.ID}}/revoke">
            <input type="hidden" name="_csrf" value="{{$.CSRF}}">
            <button type="submit">Revoke</button>
          </form>
          {{end}}
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p>No keys yet.</p>
  {{end}}
  <h2>Create a key</h2>
  <form method="post" action="/portal/keys" class="row">
    <input type="hidden" name="_csrf" value="{{.CSRF}}">
    <label>Name <input type="text" name="name" required maxlength="128" autocomplete="off"></label>
    <button type="submit">Create</button>
  </form>
  <h2>Connect a client</h2>
  {{if .Snippets}}
  <p class="muted">Gateway {{.GatewayURL}}. The key stays in your environment. These snippets are not a live client check.</p>
  {{range .Snippets}}
    <h3>{{.Title}}</h3>
    <pre>{{.Body}}</pre>
  {{end}}
  {{else}}
  <p>The gateway address is not configured. Set YABANIN_PORTAL_GATEWAY_URL.</p>
  {{end}}
  <p class="muted">Notes: docs/clients/codex.md, docs/clients/claude-code.md, docs/clients/opencode.md, docs/clients/continue.md, docs/clients/cline.md.</p>
</main>
<script>
document.querySelectorAll("[data-copy]").forEach(function (button) {
  button.addEventListener("click", function () {
    var node = document.getElementById(button.getAttribute("data-copy"));
    if (!node) { return; }
    var text = node.textContent || "";
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
    }
  });
});
</script>
</body>
</html>
`

var portalPageTmpl = template.Must(template.New("portal").Parse(portalPageSrc))

type portalKeyView struct {
	ID        string
	Name      string
	Created   string
	Expires   string
	Status    string
	CanRevoke bool
}

type portalSnippet struct {
	Title string
	Body  string
}

type portalPageData struct {
	Email       string
	CSRF        string
	Error       string
	RevealedKey string
	GatewayURL  string
	Keys        []portalKeyView
	Snippets    []portalSnippet
}

// PortalHome serves the developer key page. A missing session redirects to login.
func (h *AdminHandlers) PortalHome() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.renderPortal(w, r, "", "")
	}
}

// PortalCreateKeyPage accepts the create form and shows the new key once.
func (h *AdminHandlers) PortalCreateKeyPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalPageUser(w, r)
		if user == nil {
			return
		}
		if !h.portalFormCSRF(w, r) {
			return
		}
		plain, _, err := h.mintPersonalKey(r.Context(), user, r.FormValue("name"))
		if err != nil {
			msg := "could not create the key"
			if err == errPortalKeyName || err == errPortalKeyLimit {
				msg = err.Error()
			}
			h.writePortal(w, r, user, "", msg)
			return
		}
		h.writePortal(w, r, user, plain, "")
	}
}

// PortalRevokeKeyPage deactivates one of the signed-in developer's keys.
func (h *AdminHandlers) PortalRevokeKeyPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.portalPageUser(w, r)
		if user == nil {
			return
		}
		if !h.portalFormCSRF(w, r) {
			return
		}
		hash, err := h.portal.store.DeactivateDeveloperKey(r.Context(), user.ID, chi.URLParam(r, "id"))
		if err != nil {
			if adminstore.IsNotFound(err) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			h.writePortal(w, r, user, "", "could not revoke the key")
			return
		}
		h.purgeResolverKeys(r.Context(), hash)
		http.Redirect(w, r, "/portal", http.StatusSeeOther)
	}
}

func (h *AdminHandlers) renderPortal(w http.ResponseWriter, r *http.Request, revealed, errMsg string) {
	user := h.portalPageUser(w, r)
	if user == nil {
		return
	}
	h.writePortal(w, r, user, revealed, errMsg)
}

func (h *AdminHandlers) portalPageUser(w http.ResponseWriter, r *http.Request) *adminstore.DeveloperUser {
	cookie, err := r.Cookie(adminauth.PortalSessionCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return nil
	}
	session, err := adminauth.ParsePortalSessionCookie(cookie.Value, h.sessionSecret)
	if err != nil || time.Now().After(session.ExpiresAt) {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return nil
	}
	if h.portal.store == nil {
		http.Error(w, "portal store not configured", http.StatusServiceUnavailable)
		return nil
	}
	user, err := h.portal.store.GetDeveloperByID(r.Context(), session.UserID)
	if err != nil || user == nil || !user.Active {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return nil
	}
	return user
}

func (h *AdminHandlers) portalFormCSRF(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("yabanin_portal_csrf")
	given := r.FormValue("_csrf")
	if err != nil || cookie.Value == "" || given == "" || !hmac.Equal([]byte(cookie.Value), []byte(given)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (h *AdminHandlers) writePortal(w http.ResponseWriter, r *http.Request, user *adminstore.DeveloperUser, revealed, errMsg string) {
	keys, err := h.portal.store.ListDeveloperKeys(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "could not load keys", http.StatusInternalServerError)
		return
	}
	data := portalPageData{
		Email:       user.Email,
		CSRF:        portalCSRFValue(w, r),
		Error:       errMsg,
		RevealedKey: revealed,
		GatewayURL:  h.portal.gatewayURL,
		Keys:        portalKeyViews(keys),
		Snippets:    portalClientSnippets(h.portal.gatewayURL),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := portalPageTmpl.Execute(w, data); err != nil {
		h.logger.Error("portal page", "error", err)
	}
}

func portalCSRFValue(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("yabanin_portal_csrf"); err == nil && c.Value != "" {
		return c.Value
	}
	return adminauth.GeneratePortalCSRFToken(w)
}

func portalKeyViews(keys []adminstore.DeveloperKey) []portalKeyView {
	out := make([]portalKeyView, 0, len(keys))
	for _, k := range keys {
		expires := "does not expire"
		if k.ExpiresAt != nil {
			expires = k.ExpiresAt.UTC().Format(time.RFC3339)
		}
		status := "revoked"
		if k.Active {
			status = "active"
		}
		created := ""
		if !k.CreatedAt.IsZero() {
			created = k.CreatedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, portalKeyView{
			ID:        k.ID,
			Name:      k.Name,
			Created:   created,
			Expires:   expires,
			Status:    status,
			CanRevoke: k.Active,
		})
	}
	return out
}

func portalClientSnippets(base string) []portalSnippet {
	if base == "" {
		return nil
	}
	p := clientconfig.Params{BaseURL: base}
	return []portalSnippet{
		{Title: "Codex", Body: clientconfig.Codex(p).RenderTOML()},
		{Title: "Claude Code", Body: clientconfig.ClaudeCode(p).RenderEnv()},
		{Title: "OpenCode", Body: clientconfig.OpenCode(p, nil).RenderJSON()},
		{Title: "Continue", Body: clientconfig.Continue(p).RenderYAML()},
		{Title: "Cline", Body: clientconfig.Cline(p)},
	}
}
