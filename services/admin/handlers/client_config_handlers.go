package handlers

// server-side render of a coding agent's gateway config over the EXISTING
// pkg/clientconfig renderers. pkg/clientconfig stays the single source of
// truth for every client format (its own suite pins the byte-level goldens);
// the dashboard's byte-for-byte TS mirror is retired in favor of this
// endpoint (the browser renders whatever the server says, drift becomes
// impossible by construction).
//
// Security posture (why this is a plain session route, no org gate):
//   - the endpoint reads NOTHING from the database — it is a pure render of
//     CALLER-SUPPLIED query params over stateless templates;
//   - the API key itself is never embedded (the Go contract: every renderer
//     emits an env NAME — env_key / ANTHROPIC_AUTH_TOKEN source / {env:…});
//     a key VALUE never enters this handler, so it cannot leak out of it;
//   - labels ride the canonical X-Yabanin-Labels grammar (pkg/labels):
//     invalid entries are DROPPED and reported in the response, never
//     silently accepted into the rendered config.
//
// indistinguishable from a typo, and the caller must not receive a
// made-up config for it).

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/labels"
)

// agents whose formats pkg/clientconfig renders and docs/clients documents.
// The FULL six-agent set (owner decision 2026-11-04 (b)): every client the
// CLI (`yb client-config --client …`) renders is rendered here too — parity
// by construction, both switch over the same pkg/clientconfig renderers.
// UI copy keys live in web/dashboard/src/i18n (agents.client*) and the web
// clientConfig.ts GUIDED_AGENTS list mirrors this map; the handler test and
// the web contract test pin the two sets.
var clientConfigAgents = map[string]struct {
	format string
	path   string
}{
	"claude-code": {format: "shell", path: "shell profile (or Claude Code settings.json env)"},
	"codex":       {format: "toml", path: "~/.codex/config.toml"},
	"opencode":    {format: "json", path: "opencode.json (provider object)"},
	"continue":    {format: "yaml", path: "~/.continue/config.yaml (models list)"},
	"cline":       {format: "text", path: "VS Code extension settings (manual setup)"},
	"aider":       {format: "yaml", path: "~/.aider.conf.yml + shell env export"},
}

// Sizing bounds for the render inputs.
const (
	clientConfigBaseURLMaxLen = 2048
	clientConfigModelMaxLen   = 256
)

// clientConfigKeyEnvPattern bounds the env NAME the renderers embed (it is
// template text, not a value: [A-Za-z_][A-Za-z0-9_]*, POSIX env grammar).
var clientConfigKeyEnvPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// clientConfigResponse is the render payload. Config is the exact text the
// operator copies; path/format/name it so the UI cannot mislabel it.
type clientConfigResponse struct {
	Agent   string           `json:"agent"`
	Format  string           `json:"format"`
	Path    string           `json:"path"`
	Config  string           `json:"config"`
	KeyEnv  string           `json:"key_env"`
	Dropped []labels.Dropped `json:"dropped_labels,omitempty"`
}

// ClientConfig answers GET /api/client-config/{agent} (session-authenticated;
// CSRF-exempt like every GET). Query params:
//
//	base_url (required) — the operator-entered gateway origin (http/https);
//	key_env  (optional) — the env var the client reads the key from
//	                      (default YABANIN_API_KEY);
//	model    (optional) — default model id rendered into the config;
//	labels   (optional) — scope labels in the canonical k=v,k=v form.
func (h *AdminHandlers) ClientConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agent := chi.URLParam(r, "agent")
		meta, ok := clientConfigAgents[agent]
		if !ok {
			writeJSON(w, http.StatusNotFound, apiError{Error: "unknown agent"})
			return
		}
		q := r.URL.Query()
		baseURL := strings.TrimSpace(q.Get("base_url"))
		if baseURL == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "base_url is required"})
			return
		}
		if len(baseURL) > clientConfigBaseURLMaxLen {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "base_url must be at most 2048 characters"})
			return
		}
		u, err := url.Parse(baseURL)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "base_url must be an absolute http(s) URL"})
			return
		}
		keyEnv := strings.TrimSpace(q.Get("key_env"))
		if keyEnv == "" {
			keyEnv = "YABANIN_API_KEY"
		}
		if len(keyEnv) > 64 || !clientConfigKeyEnvPattern.MatchString(keyEnv) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "key_env must be an environment variable name"})
			return
		}
		model := strings.TrimSpace(q.Get("model"))
		if len(model) > clientConfigModelMaxLen {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "model must be at most 256 characters"})
			return
		}
		set, dropped := labels.ParseHeaderValues([]string{q.Get("labels")})
		params := clientconfig.Params{
			BaseURL: baseURL,
			KeyEnv:  keyEnv,
			Model:   model,
			Labels:  set,
		}
		var config string
		switch agent {
		case "claude-code":
			config = clientconfig.ClaudeCode(params).RenderEnv()
		case "codex":
			config = clientconfig.Codex(params).RenderTOML()
		case "opencode":
			config = clientconfig.OpenCode(params, []string{model}).RenderJSON()
		// Same renderers the CLI mirrors (pkg/trcli/client_config.go) —
		// continue renders the models YAML, cline renders manual-setup
		// instructions (no editable config file exists), aider renders
		// the config YAML plus the key-env export line.
		case "continue":
			config = clientconfig.Continue(params).RenderYAML()
		case "cline":
			config = clientconfig.Cline(params)
		case "aider":
			cfg := clientconfig.Aider(params)
			config = cfg.RenderYAML() + cfg.RenderEnv()
		}
		writeJSON(w, http.StatusOK, clientConfigResponse{
			Agent:   agent,
			Format:  meta.format,
			Path:    meta.path,
			Config:  config,
			KeyEnv:  keyEnv,
			Dropped: dropped,
		})
	}
}
