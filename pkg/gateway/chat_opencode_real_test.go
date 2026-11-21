package cli

// e2e for N07-P08-T03): a REAL OpenCode CLI binary drives the gateway end
// to end — the CLI's own @ai-sdk/openai-compatible client (opencode.json
// provider, {env:} key auth) talks to POST /v1/chat/completions on a live
// port, the gateway relays to the mock chat upstream behind it, and the CLI
// must print the mock's answer. Skips are LOUD (binary absence is an
// explicit prerequisite, never a green mask); the record file pins the
// exact binary version the matrix row cites.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// opencodeBinary resolves the real OpenCode CLI: explicit override first,
// then the owner-documented install path, then PATH.
func opencodeBinary() (string, error) {
	if p := strings.TrimSpace(os.Getenv("YABANIN_OPENCODE_BIN")); p != "" {
		if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: test-scoped explicit binary override, not client input
			return p, nil
		}
		return "", fmt.Errorf("YABANIN_OPENCODE_BIN=%s does not exist", p)
	}
	for _, p := range []string{
		filepath.Join(os.Getenv("HOME"), ".opencode", "bin", "opencode"),
	} {
		if p != "" && filepath.Base(p) == "opencode" {
			if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: test-scoped well-known install path, not client input
				return p, nil
			}
		}
	}
	return exec.LookPath("opencode")
}

const opencodeMagicAnswer = "MAGICMOCK-oc7d: the gateway relayed this answer."

// TestChatCompletions_OpenCodeCLI_RealE2E starts the gateway on a real
// port, points a real `opencode run` at it via isolated XDG dirs and a
// project opencode.json (the documented editor integration), and requires
// the full loop: CLI → POST /v1/chat/completions → gateway → chat upstream
// → SSE → CLI prints the mock's answer. Proxy env is scrubbed so corporate
// HTTP(S)_PROXY settings on the dev machine cannot blackhole localhost.
func TestChatCompletions_OpenCodeCLI_RealE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("real OpenCode CLI e2e is skipped in -short mode (external binary prerequisite)")
	}
	bin, err := opencodeBinary()
	if err != nil {
		t.Skipf("opencode CLI not available — the N07-P08-T03 client confirmation requires the real binary: %v", err)
	}

	// The mock OpenAI-compatible upstream behind the gateway: every chat
	// completion streams the same canned final answer.
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("upstream saw unexpected path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if len(raw) == 0 {
			t.Error("upstream saw an empty chat body")
		}
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":"+
			`"`+opencodeMagicAnswer+`"`+"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	gw.models = staticModelLister{entry: modelEntry{
		ID: "m", DisplayName: "m", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}

	var sawChat atomic.Bool
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "chat.completions" && e.EventType == "request.completed" {
			sawChat.Store(true)
		}
	})
	t.Cleanup(restore)

	// The gateway on a REAL port (the CLI is a separate process).
	router := chi.NewRouter()
	gw.routes(router)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	baseURL := "http://" + ln.Addr().String()

	// An isolated project: opencode.json in the CLI's own config format,
	// exactly as shipped by the admin console renderer (pkg/clientconfig):
	// @ai-sdk/openai-compatible, baseURL with /v1, {env:} key reference.
	workdir := t.TempDir()
	cfg := fmt.Sprintf(`{
  "$schema": "https://opencode.ai/config.json",
  "autoupdate": false,
  "share": "disabled",
  "provider": {
    "yabanin": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Yabanin",
      "options": {
        "baseURL": %q,
        "apiKey": "{env:YABANIN_API_KEY}"
      },
      "models": {
        "m": {"name": "m"}
      }
    }
  },
  "model": "yabanin/m"
}
`, baseURL+"/v1")
	if err := os.WriteFile(filepath.Join(workdir, "opencode.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Isolated XDG state: the run must not read the developer's own
	// opencode config or session store.
	xdg := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", //nolint:gosec // G204: the test's purpose is executing the resolved real opencode binary
		// Piped server logs keep failure forensics in the CombinedOutput
		// tail. NOTE(review 2026-11-02): the full loop was independently
		// completed WITHOUT these flags (opencode 1.19.5, clean env, fresh
		// XDG dirs, SSE mock) — the original UnknownError red was not
		// reproduced and is believed to be the inherited-env attach below;
		// the flags are NOT a necessity, they are kept as a harmless
		// forensic/logging aid for debuggability.
		"--print-logs", "--log-level", "DEBUG",
		"-m", "yabanin/m",
		"Reply with the exact text you are given. Do not run any commands.")
	cmd.Dir = workdir
	// The child env is built explicitly — nothing is inherited. An
	// inherited environment leaks the developer's live agent-session
	// markers into the CLI (OPENCODE=1/OPENCODE_PID, server discovery
	// state under the real HOME, PWD pointing at the repo the parent
	// test runs in): the CLI then attaches to the developer's running
	// opencode server (project dir = this repo) instead of spawning an
	// isolated instance for the temp project, and the live session's
	// provider set wins — Model not found: yabanin/m. The exact
	// allowlist below is the minimal set the CLI needs: the binary is
	// resolved absolutely in the parent, XDG*/HOME point into the temp
	// tree, proxies are pinned empty for deterministic loopback routing.
	cmd.Env = []string{
		"HOME=" + xdg,
		"PATH=/usr/bin:/bin:/usr/local/bin",
		"XDG_CONFIG_HOME=" + filepath.Join(xdg, "config"),
		"XDG_DATA_HOME=" + filepath.Join(xdg, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(xdg, "cache"),
		"XDG_STATE_HOME=" + filepath.Join(xdg, "state"),
		"OPENCODE_DISABLE_AUTOUPDATE=true",
		"YABANIN_API_KEY=test-key",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"NO_PROXY=",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		logTail := ""
		if b, rerr := os.ReadFile(filepath.Join(xdg, "data", "opencode", "log", "opencode.log")); rerr == nil { //nolint:gosec // test temp path
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) > 40 {
				lines = lines[len(lines)-40:]
			}
			logTail = "\n--- opencode server log tail (workdir=" + workdir + ") ---\n" + strings.Join(lines, "\n")
		}
		t.Fatalf("opencode run failed: %v\n--- opencode output ---\n%s%s", err, string(out), logTail)
	}
	if upstreamHits.Load() == 0 {
		t.Fatalf("the request never reached the upstream through the gateway\nopencode output:\n%s", string(out))
	}
	if !sawChat.Load() {
		t.Fatal("no request.completed(chat.completions) event observed at the gateway")
	}
	if !strings.Contains(string(out), "MAGICMOCK-oc7d") {
		t.Fatalf("the CLI's final message does not carry the mock answer:\n%s", string(out))
	}
	t.Logf("real opencode CLI loop confirmed: upstream hits=%d, answer printed", upstreamHits.Load())
}
