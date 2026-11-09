package trcli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIExecSessionModes(t *testing.T) {
	clearCIEnv(t)
	var finish string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/v1/yabanin/session-keys" && r.Method == http.MethodPost:
			mode := r.Header.Get("X-Test-Mode")
			_ = mode
			body := map[string]string{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.Contains(auth, "deny") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if strings.Contains(auth, "missing") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sess-1", "key": "ybs_sessionkey", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"labels": map[string]string{}, "dropped": []any{},
			})
		case strings.HasSuffix(r.URL.Path, "/finish"):
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			finish, _ = payload["status"].(string)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	t.Setenv("YABANIN_GATEWAY_URL", srv.URL)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PIPELINE_ID", "4242")
	t.Setenv("CI_JOB_ID", "9")
	t.Setenv("YB_CI_HELPER", "1")
	exe, err := os.Executable()
	require.NoError(t, err)
	dir := t.TempDir()
	out := filepath.Join(dir, "child.txt")
	t.Setenv("YB_CI_OUT", out)

	t.Setenv("YABANIN_CI_KEY", "missing-key")
	text, err := runTr(t, "ci", "exec", "--dir", dir, "--session", "auto", "--report", filepath.Join(dir, "a.json"), "--", exe)
	require.NoError(t, err)
	assert.Contains(t, text, "session keys unavailable")
	child := readChild(t, out)
	assert.Contains(t, child, "YABANIN_API_KEY=missing-key")

	t.Setenv("YABANIN_CI_KEY", "deny-key")
	text, err = runTr(t, "ci", "exec", "--dir", dir, "--session", "auto", "--report", filepath.Join(dir, "b.json"), "--", exe)
	require.NoError(t, err)
	assert.Contains(t, text, "can_mint_sessions")
	child = readChild(t, out)
	assert.Contains(t, child, "YABANIN_API_KEY=deny-key")

	t.Setenv("YABANIN_CI_KEY", "ci-parent")
	text, err = runTr(t, "ci", "exec", "--dir", dir, "--session", "auto", "--report", filepath.Join(dir, "c.json"), "--", exe)
	require.NoError(t, err)
	assert.NotContains(t, text, "ybs_sessionkey")
	child = readChild(t, out)
	assert.Contains(t, child, "YABANIN_API_KEY=ybs_sessionkey")
	assert.NotContains(t, child, "ci-parent")
	assert.Contains(t, child, "YABANIN_SESSION_KEY_ID=sess-1")
	assert.Equal(t, "success", finish)
	assert.Equal(t, "Bearer ci-parent", auth)

	t.Setenv("YABANIN_CI_KEY", "missing-key")
	_, err = runTr(t, "ci", "exec", "--dir", dir, "--session", "on", "--report", filepath.Join(dir, "d.json"), "--", exe)
	var exit *cictx.ExitError
	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 5, exit.Code)
}

func TestHarnessKeyCacheAndFallback(t *testing.T) {
	home := t.TempDir()
	prev := credentialHome
	credentialHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { credentialHome = prev })
	t.Setenv("YABANIN_API_KEY", "parent-key")
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/v1/yabanin/session-keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "sess-h", "key": "ybs_fromserver", "expires_at": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer srv.Close()
	require.NoError(t, saveHarnessSession(home, []string{"codex"}, "8h"))
	cfg, err := loadConfig(home)
	require.NoError(t, err)
	cfg.Profiles["default"] = gatewayProfile{GatewayURL: srv.URL}
	require.NoError(t, writeConfig(home, cfg))

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	var errBuf strings.Builder
	cmd.SetErr(&errBuf)
	key, err := harnessKey(cmd, "codex")
	require.NoError(t, err)
	assert.Equal(t, "ybs_fromserver", key)
	assert.Equal(t, 1, hits)
	info, err := os.Stat(filepath.Join(home, ".yabanin", "sessions"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	matches, err := filepath.Glob(filepath.Join(home, ".yabanin", "sessions", "*.json"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	fileInfo, err := os.Stat(matches[0])
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	hits = 0
	key, err = harnessKey(cmd, "codex")
	require.NoError(t, err)
	assert.Equal(t, "ybs_fromserver", key)
	// The cache hit is proven behaviorally: zero HTTP calls to the session-key
	// endpoint. A wall-clock bound here was flaky under load (go-test-quality:
	// assert behavior, not timing).

	expired := cachedSession{ID: "old", Key: "ybs_old", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, writeSessionCache(matches[0], expired))
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadGateway)
	})
	key, err = harnessKey(cmd, "codex")
	require.NoError(t, err)
	assert.Equal(t, "parent-key", key)
	assert.Contains(t, errBuf.String(), "parent key")
	assert.NotContains(t, errBuf.String(), "ybs_")
}

func TestSessionCachePathFollowsLabels(t *testing.T) {
	dir := t.TempDir()
	a, err := sessionCachePath(dir, "codex", "http://gw", labels.Set{"git.ref": "main"})
	require.NoError(t, err)
	b, err := sessionCachePath(dir, "codex", "http://gw", labels.Set{"git.ref": "feature"})
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func readChild(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is a temp file created by this test
	require.NoError(t, err)
	return string(body)
}
