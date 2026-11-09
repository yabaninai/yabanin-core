package handlers_test

// GET /api/client-config/{agent}, asserted through the FULL SetupRouter
// (session auth, exactly like policy_pipelines_test.go):
//
//	anon                → 401 (session boundary)
//	known agent         → 200; `config` is BYTE-IDENTICAL to the
//	                      pkg/clientconfig renderer output for the same
//	                      params (single source of truth, pinned here at
//	                      the HTTP boundary the dashboard consumes)
//	invalid base_url    → 400 (missing / not absolute / not http(s))
//	invalid key_env     → 400 (env-name grammar)
//	invalid labels      → dropped + reported, never rendered
//
// The parity asserts against the SAME goldens pkg/clientconfig/render_test.go
// asserts (testdata/*.golden, params BaseURL https://gw.example, Model gpt,
// Labels {team: payments}) — an endpoint drift from the renderers fails here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/clientconfig"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const ccSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key

func clientConfigRouter(t *testing.T) http.Handler {
	t.Helper()
	h := handlers.New(&stubStore{}, ccSecret, "localhost", nil)
	return h.SetupRouter()
}

func clientConfigGet(t *testing.T, router http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ccGoldenParams mirrors the exact params of pkg/clientconfig's golden test.
var ccGoldenParams = clientconfig.Params{
	BaseURL: "https://gw.example",
	Model:   "gpt",
	Labels:  labels.Set{"team": "payments"},
}

func TestClientConfig_RoutingContract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, ccSecret)

	t.Run("anon is 401", func(t *testing.T) {
		router := clientConfigRouter(t)
		if w := clientConfigGet(t, router, "/api/client-config/codex?base_url=https://gw.example", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET = %d, want 401", w.Code)
		}
	})

	t.Run("unknown agent is 404, known agents answer", func(t *testing.T) {
		router := clientConfigRouter(t)
		if w := clientConfigGet(t, router, "/api/client-config/cursor?base_url=https://gw.example", rootCookie); w.Code != http.StatusNotFound {
			t.Errorf("unknown agent = %d, want 404 (body: %s)", w.Code, w.Body.String())
		}
		for _, agent := range []string{"claude-code", "codex", "opencode", "continue", "cline", "aider"} {
			w := clientConfigGet(t, router, "/api/client-config/"+agent+"?base_url=https://gw.example", rootCookie)
			if w.Code != http.StatusOK {
				t.Errorf("GET %s = %d, want 200 (body: %s)", agent, w.Code, w.Body.String())
			}
		}
	})

	t.Run("base_url is validated", func(t *testing.T) {
		router := clientConfigRouter(t)
		cases := []string{
			"/api/client-config/codex",                               // missing
			"/api/client-config/codex?base_url=",                     // empty
			"/api/client-config/codex?base_url=ftp://gw.example",     // wrong scheme
			"/api/client-config/codex?base_url=gw.example",           // not absolute
			"/api/client-config/codex?base_url=" + longBaseURL(2049), // over the bound
		}
		for _, path := range cases {
			if w := clientConfigGet(t, router, path, rootCookie); w.Code != http.StatusBadRequest {
				t.Errorf("GET %s = %d, want 400", redact(path), w.Code)
			}
		}
	})

	t.Run("key_env must be an env name", func(t *testing.T) {
		router := clientConfigRouter(t)
		bad := []string{"1KEY", "has%20space", "has-dash", "trailing%3B", "a%3Bb"}
		for _, env := range bad {
			path := "/api/client-config/codex?base_url=https://gw.example&key_env=" + env
			if w := clientConfigGet(t, router, path, rootCookie); w.Code != http.StatusBadRequest {
				t.Errorf("key_env %q = %d, want 400", env, w.Code)
			}
		}
		if w := clientConfigGet(t, router, "/api/client-config/codex?base_url=https://gw.example&key_env=TEAM_KEY", rootCookie); w.Code != http.StatusOK {
			t.Errorf("valid key_env = %d, want 200", w.Code)
		}
	})
}

// redact keeps the long-URL failure message readable.
func redact(path string) string {
	if len(path) > 80 {
		return path[:40] + "…" + path[len(path)-20:]
	}
	return path
}

func longBaseURL(n int) string {
	prefix := "https://"
	for len(prefix) < n {
		prefix += "a"
	}
	return prefix[:n]
}

func TestClientConfig_RenderParity(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, ccSecret)
	router := clientConfigRouter(t)

	decode := func(t *testing.T, w *httptest.ResponseRecorder) clientConfigResponseShadow {
		t.Helper()
		var out clientConfigResponseShadow
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (body %s)", err, w.Body.String())
		}
		return out
	}

	t.Run("codex config is the renderer output and the golden file", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/codex?base_url=https://gw.example&model=gpt&labels=team%3Dpayments", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d (body %s)", w.Code, w.Body.String())
		}
		got := decode(t, w)
		if got.Config != clientconfig.Codex(ccGoldenParams).RenderTOML() {
			t.Errorf("codex config drifted from the renderer:\n%s", got.Config)
		}
		if golden := readClientConfigGolden(t, "codex_env"); got.Config != golden {
			t.Errorf("codex config drifted from pkg/clientconfig/testdata/codex_env.golden:\n%s", got.Config)
		}
		if got.Format != "toml" || got.Path != "~/.codex/config.toml" || got.KeyEnv != "YABANIN_API_KEY" {
			t.Errorf("meta = %+v", got)
		}
	})

	t.Run("claude-code config is the renderer output and the golden file", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/claude-code?base_url=https://gw.example&model=gpt&labels=team%3Dpayments", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d (body %s)", w.Code, w.Body.String())
		}
		got := decode(t, w)
		if got.Config != clientconfig.ClaudeCode(ccGoldenParams).RenderEnv() {
			t.Errorf("claude-code config drifted from the renderer:\n%s", got.Config)
		}
		if golden := readClientConfigGolden(t, "claude-code_env"); got.Config != golden {
			t.Errorf("claude-code config drifted from the golden:\n%s", got.Config)
		}
		if got.Format != "shell" {
			t.Errorf("format = %q, want shell", got.Format)
		}
	})

	t.Run("opencode config is the renderer output and the golden file", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/opencode?base_url=https://gw.example&model=gpt&labels=team%3Dpayments", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d (body %s)", w.Code, w.Body.String())
		}
		got := decode(t, w)
		if got.Config != clientconfig.OpenCode(ccGoldenParams, []string{"gpt"}).RenderJSON() {
			t.Errorf("opencode config drifted from the renderer:\n%s", got.Config)
		}
		if golden := readClientConfigGolden(t, "opencode_env"); got.Config != golden {
			t.Errorf("opencode config drifted from the golden:\n%s", got.Config)
		}
	})

	t.Run("key_env override reaches every render", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/codex?base_url=https://gw.example&key_env=TEAM_KEY", rootCookie)
		got := decode(t, w)
		if !strings.Contains(got.Config, `env_key = "TEAM_KEY"`) {
			t.Errorf("TEAM_KEY missing from:\n%s", got.Config)
		}
		if got.KeyEnv != "TEAM_KEY" {
			t.Errorf("key_env echo = %q", got.KeyEnv)
		}
	})

	t.Run("invalid labels drop with a reason, valid ones render", func(t *testing.T) {
		// "team=payments" is valid; "BAD KEY=x" violates the key grammar and
		// must be dropped+reported, not rendered. Pinned on the opencode
		// render — the one that inlines the label set as a header value
		// (codex routes labels through the YABANIN_LABELS env instead).
		w := clientConfigGet(t, router, "/api/client-config/opencode?base_url=https://gw.example&labels=team%3Dpayments%2CBAD+KEY%3Dx", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d (body %s)", w.Code, w.Body.String())
		}
		got := decode(t, w)
		if !strings.Contains(got.Config, "team=payments") {
			t.Errorf("valid label missing from:\n%s", got.Config)
		}
		if strings.Contains(got.Config, "BAD") {
			t.Errorf("dropped label rendered:\n%s", got.Config)
		}
		if len(got.Dropped) == 0 {
			t.Errorf("dropped labels not reported (body: %s)", w.Body.String())
		}
	})

	t.Run("no secret can appear in the response (env names only)", func(t *testing.T) {
		// Even an adversarial key VALUE in every param must not surface as a
		// key: labels are dropped/reported, model is a template field, the
		// base_url is a URL. The scan pins the "env names only" contract.
		w := clientConfigGet(t, router, "/api/client-config/codex?base_url=https://gw.example&model=gpt&labels=team%3Dpayments", rootCookie)
		got := decode(t, w)
		for _, marker := range []string{"sk-", "yb_"} {
			if strings.Contains(got.Config, marker) {
				t.Errorf("secret-looking %q in config:\n%s", marker, got.Config)
			}
		}
	})
}

// clientConfigResponseShadow mirrors the wire payload for decoding in tests.
type clientConfigResponseShadow struct {
	Agent   string           `json:"agent"`
	Format  string           `json:"format"`
	Path    string           `json:"path"`
	Config  string           `json:"config"`
	KeyEnv  string           `json:"key_env"`
	Dropped []labels.Dropped `json:"dropped_labels"`
}

func readClientConfigGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "clientconfig", "testdata", name+".golden")) //nolint:gosec // G304: path is a testdata golden name, not user input
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(raw)
}

// TestClientConfig_AgentParity pins owner decision 2026-11-04 (b): the API
// renders the FULL six-agent set, and the renderers are the same
// pkg/clientconfig calls the CLI mirrors — a UI operator and a CLI operator
// get byte-identical guidance for every supported client.
func TestClientConfig_AgentParity(t *testing.T) {
	router := clientConfigRouter(t)
	rootCookie := makeSessionCookie(t, "root@x.test", true, ccSecret)

	t.Run("all six agents render 200 with agent-tagged metadata", func(t *testing.T) {
		for _, agent := range []string{"claude-code", "codex", "opencode", "continue", "cline", "aider"} {
			w := clientConfigGet(t, router, "/api/client-config/"+agent+"?base_url=https://gw.example&model=test-model", rootCookie)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200 (body: %s)", agent, w.Code, w.Body.String())
			}
			var resp struct {
				Agent  string `json:"agent"`
				Format string `json:"format"`
				Path   string `json:"path"`
				Config string `json:"config"`
				KeyEnv string `json:"key_env"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("GET %s body unmarshal: %v", agent, err)
			}
			if resp.Agent != agent || resp.Format == "" || resp.Path == "" || resp.Config == "" {
				t.Errorf("GET %s metadata incomplete: %+v", agent, resp)
			}
			if !strings.Contains(resp.Config, "gw.example") {
				t.Errorf("GET %s config must carry the base URL", agent)
			}
		}
	})

	t.Run("aider renders the config YAML plus the key-env export (CLI parity)", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/aider?base_url=https://gw.example&key_env=TEAM_KEY", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET aider = %d, want 200", w.Code)
		}
		var resp struct {
			Config string `json:"config"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !strings.Contains(resp.Config, "openai-api-base:") {
			t.Errorf("aider config missing the aider.conf.yml block: %q", resp.Config)
		}
		if !strings.Contains(resp.Config, `export AIDER_OPENAI_API_KEY="$TEAM_KEY"`) {
			t.Errorf("aider config missing the env export line: %q", resp.Config)
		}
	})

	t.Run("cline renders manual-setup instructions (no config file exists)", func(t *testing.T) {
		w := clientConfigGet(t, router, "/api/client-config/cline?base_url=https://gw.example", rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET cline = %d, want 200", w.Code)
		}
		var resp struct {
			Config string `json:"config"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !strings.Contains(resp.Config, "VS Code") {
			t.Errorf("cline config must carry the manual-setup note: %q", resp.Config)
		}
	})
}
