package cli

// e2e for the client-confirmed criterion): a REAL Codex CLI binary drives
// the gateway end to end — the CLI's own Responses client (config.toml
// wire_api="responses", env_key auth) talks to /v1/responses on a live
// port, the gateway translates to the mock chat upstream behind it, and
// the CLI must print the mock's answer. Skips are LOUD (binary/short-mode
// absence is an explicit prerequisite, never a green mask); the evidence
// file records the exact binary and versions.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// codexBinary resolves the real Codex CLI: explicit override first, then
// the owner-documented install path, then PATH.
func codexBinary() (string, error) {
	if p := strings.TrimSpace(os.Getenv("YABANIN_CODEX_BIN")); p != "" {
		if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: test-scoped explicit binary override, not client input
			return p, nil
		}
		return "", fmt.Errorf("YABANIN_CODEX_BIN=%s does not exist", p)
	}
	for _, p := range []string{
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "codex"),
	} {
		if p != "" && filepath.Base(p) == "codex" {
			if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: test-scoped well-known install path, not client input
				return p, nil
			}
		}
	}
	return exec.LookPath("codex")
}

const codexMagicAnswer = "MAGICMOCK-4b1c: the gateway relayed this answer."

// TestResponses_CodexCLI_RealE2E starts the gateway on a real port, points
// a real `codex exec` at it via an isolated CODEX_HOME, and requires the
// full loop: CLI → POST /v1/responses → gateway → translated chat upstream
// → translated SSE → CLI prints the mock's answer.
func TestResponses_CodexCLI_RealE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("real Codex CLI e2e is skipped in -short mode (external binary prerequisite)")
	}
	bin, err := codexBinary()
	if err != nil {
		t.Skipf("codex CLI not available — the R046 client-confirmation requires the real binary: %v", err)
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
			`"`+codexMagicAnswer+`"`+"}}]}\n\n")
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

	var sawResponses atomic.Bool
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint == "responses" && e.EventType == "request.completed" {
			sawResponses.Store(true)
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

	// An isolated CODEX_HOME: the CLI's own config format, exactly as
	// documented in docs/clients/codex.md.
	home := t.TempDir()
	cfg := fmt.Sprintf(`
model = "m"
model_provider = "yabanin"
approval_policy = "never"
sandbox_mode = "read-only"

[model_providers.yabanin]
name = "yabanin"
base_url = %q
env_key = "YABANIN_API_KEY"
wire_api = "responses"
`, baseURL+"/v1")
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	workdir := t.TempDir()
	lastMsg := filepath.Join(workdir, "last-message.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "exec", //nolint:gosec // G204: the test's purpose is executing the resolved real codex binary

		"--skip-git-repo-check",
		"--ephemeral",
		"-C", workdir,
		"--color", "never",
		"-o", lastMsg,
		"Reply with the exact text you are given. Do not run any commands.")
	cmd.Env = append(os.Environ(),
		"CODEX_HOME="+home,
		"YABANIN_API_KEY=test-key",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex exec failed: %v\n--- codex output ---\n%s", err, string(out))
	}
	if upstreamHits.Load() == 0 {
		t.Fatalf("the request never reached the upstream through the gateway\ncodex output:\n%s", string(out))
	}
	// The settlement publishes on the gateway goroutine after the upstream
	// EOF, which races the CLI's exit: poll instead of asserting on arrival.
	waitFor(t, 5*time.Second, sawResponses.Load,
		"no request.completed(responses) event observed at the gateway")
	final, err := os.ReadFile(lastMsg) //nolint:gosec // test temp file
	if err != nil {
		t.Fatalf("read last message: %v\ncodex output:\n%s", err, string(out))
	}
	if !strings.Contains(string(final), "MAGICMOCK-4b1c") {
		t.Fatalf("the CLI's final message does not carry the mock answer:\n%q\ncodex output:\n%s", string(final), string(out))
	}
	t.Logf("real codex CLI loop confirmed: upstream hits=%d, final=%q", upstreamHits.Load(), strings.TrimSpace(string(final)))
}

// --- N07-P03-T04: real pinned Codex CLI, tools + capability errors + cancel ---
//
// The baseline loop above proves relay + translation. This card pins the
// harder scenarios on the real installed binary at a pinned version:
//   - the tool loop (exec_command executed by the CLI, output riding the
//     stateless full-history resend through the gateway);
//   - capability errors (an unsupported tool call surfaced verbatim, never
//     swallowed into a fake success);
//   - client cancel (SIGINT mid-stream: honest CLI death, exactly one
//     terminal gateway event, upstream relay torn down);
//   - the wire contract the real client actually speaks (store=false,
//     previous_response_id null, reasoning.effort downgrade disclosed via
//     X-Yabanin-Unsupported), and the minted-id refusal on a real session id.
//
// Evidence base (2026-11-03, codex-cli 0.166.0; re-verified 2026-11-09 on
// 0.167.0 with request-order capture): store=false and
// previous_response_id=null on every turn with a custom provider; no config
// lever exists in 0.166.0 to force previous_response_id on custom providers;
// the CLI advertises exec_command (not the legacy shell tool) and feeds an
// unregistered tool call back verbatim as "unsupported call: <name>"; SIGINT
// exits 1 fast with no last-message file.

// codexExpectedVersion is the version this card's evidence was gathered on.
// Bumping the pin requires re-running the scenarios and updating the record.
const codexExpectedVersion = "0.167.0"

// requirePinnedCodex resolves the real binary and gates it on the pinned
// version (YABANIN_CODEX_EXPECT_VERSION overrides the pin for a re-pin
// ceremony). A missing binary or a version mismatch skips LOUDLY: the suite
// never silently runs an unpinned binary and claims the pin.
func requirePinnedCodex(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("real Codex CLI e2e is skipped in -short mode (external binary prerequisite)")
	}
	bin, err := codexBinary()
	if err != nil {
		t.Skipf("codex CLI not available: %v", err)
	}
	out, err := exec.CommandContext(t.Context(), bin, "--version").CombinedOutput() //nolint:gosec // G204: test-scoped resolved binary, fixed flag
	if err != nil {
		t.Skipf("codex --version failed for %s: %v\n%s", bin, err, out)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 2 || fields[0] != "codex-cli" {
		t.Skipf("unparseable codex version output %q from %s", strings.TrimSpace(string(out)), bin)
	}
	want := strings.TrimSpace(os.Getenv("YABANIN_CODEX_EXPECT_VERSION"))
	if want == "" {
		want = codexExpectedVersion
	}
	if fields[1] != want {
		t.Skipf("codex version mismatch: binary %s reports %s, card pin is %s "+
			"(re-run the pinned scenarios and update the record, or set YABANIN_CODEX_EXPECT_VERSION=%s)",
			bin, fields[1], want, fields[1])
	}
	t.Logf("pinned codex binary: %s (%s)", bin, fields[1])
	return bin
}

// writeCodexHome renders an isolated CODEX_HOME in the documented config
// format (docs/clients/codex.md). extraLines are appended verbatim before
// the provider table (model overrides like reasoning effort).
func writeCodexHome(t *testing.T, baseURL, model, sandbox, extraLines string) string {
	t.Helper()
	home := t.TempDir()
	cfg := `
model = "` + model + `"
model_provider = "yabanin"
approval_policy = "never"
sandbox_mode = "` + sandbox + `"
` + extraLines + `
[model_providers.yabanin]
name = "yabanin"
base_url = ` + fmt.Sprintf("%q", baseURL+"/v1") + `
env_key = "YABANIN_API_KEY"
wire_api = "responses"
`
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// startCodexExec builds a codex exec command wired to the isolated home;
// the caller drives its lifecycle (CombinedOutput vs signal tests).
func startCodexExec(ctx context.Context, bin, home, workdir, lastMsg, prompt string, extraArgs ...string) *exec.Cmd {
	args := append([]string{
		"exec",
		"--skip-git-repo-check",
		"--ephemeral",
		"-C", workdir,
		"--color", "never",
		"-o", lastMsg,
	}, extraArgs...)
	args = append(args, prompt)
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the test's purpose is executing the resolved real codex binary
	cmd.Env = append(os.Environ(),
		"CODEX_HOME="+home,
		"YABANIN_API_KEY=test-key",
	)
	return cmd
}

// rtripCapture is the wire recorder between the real CLI and the gateway:
// request bodies and response headers of the client leg, so assertions run
// against what the real client actually sent and received (not what a
// fixture claims). The writer is passed through untouched — wrapping it
// breaks the real CLI's transport — only the body is read (and restored)
// and the header map is snapshotted after the handler returns.
type rtripCapture struct {
	mu           sync.Mutex
	nextSequence atomic.Uint64
	entries      []rtripEntry
}

type rtripEntry struct {
	sequence uint64
	method   string
	path     string
	reqBody  []byte
	respHdr  http.Header
}

const rtripCapLimit = 1 << 20 // per body; codex envelopes are tens of KB

func newRtripCapture(next http.Handler) (*rtripCapture, http.Handler) {
	rc := &rtripCapture{}
	return rc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SSE clients can start their next turn before this handler returns.
		// Reserve arrival order now, but publish only completed captures.
		sequence := rc.nextSequence.Add(1)
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, rtripCapLimit))
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		next.ServeHTTP(w, r)
		hdr := http.Header{}
		for k, v := range w.Header() {
			hdr[k] = append([]string(nil), v...)
		}
		rc.mu.Lock()
		rc.entries = append(rc.entries, rtripEntry{
			sequence: sequence, method: r.Method, path: r.URL.Path, reqBody: reqBody, respHdr: hdr,
		})
		rc.mu.Unlock()
	})
}

func (c *rtripCapture) postCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.entries {
		if e.method == http.MethodPost && e.path == "/v1/responses" {
			n++
		}
	}
	return n
}

func (c *rtripCapture) posts(t *testing.T) []rtripEntry {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []rtripEntry
	for _, e := range c.entries {
		if e.method == http.MethodPost && e.path == "/v1/responses" {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no POST /v1/responses captured; entries: %+v", c.summaryLocked())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].sequence < out[j].sequence })
	return out
}

func (c *rtripCapture) summary() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.summaryLocked()
}

func (c *rtripCapture) summaryLocked() []string {
	var out []string
	for _, e := range c.entries {
		out = append(out, fmt.Sprintf("%s %s (%dB)", e.method, e.path, len(e.reqBody)))
	}
	return out
}

// chatResponsesStateless pins the stateless wire envelope the real CLI
// speaks on every turn: store=false, no continuation id, streaming.
func chatResponsesStateless(t *testing.T, entries []rtripEntry) {
	t.Helper()
	for i, e := range entries {
		var doc map[string]any
		if err := json.Unmarshal(e.reqBody, &doc); err != nil {
			t.Fatalf("turn %d body not JSON: %v\n%s", i+1, err, e.reqBody)
		}
		if doc["store"] != false {
			t.Fatalf("turn %d: store=%v, want explicit false (stateless contract)", i+1, doc["store"])
		}
		if v, ok := doc["previous_response_id"]; ok && v != nil {
			t.Fatalf("turn %d: previous_response_id=%v, want null/absent — the real client must never send a continuation id", i+1, v)
		}
		if doc["stream"] != true {
			t.Fatalf("turn %d: stream=%v, want true", i+1, doc["stream"])
		}
	}
}

// captureChatBodies records the translated chat bodies at the upstream leg.
type chatBodies struct {
	mu     sync.Mutex
	bodies []string
}

func (c *chatBodies) add(raw []byte) {
	c.mu.Lock()
	c.bodies = append(c.bodies, string(raw))
	c.mu.Unlock()
}

func (c *chatBodies) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

// toolMessageContent returns the content of the first role:tool chat message
// in a translated body (the function_call_output translation).
func toolMessageContent(t *testing.T, body string) string {
	t.Helper()
	var doc struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("upstream chat body not JSON: %v\n%s", err, body)
	}
	for _, m := range doc.Messages {
		if m.Role != "tool" {
			continue
		}
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			return s
		}
		return string(m.Content)
	}
	return ""
}

// TestResponses_CodexCLI_RealE2E_ToolsLoop runs the REAL pinned codex CLI
// through a function-tool loop: the mock upstream calls exec_command, the
// CLI executes it locally, and its output rides the stateless full-history
// resend through the gateway. Pins on the live wire: the stateless envelope
// (store=false, previous_response_id null, stream=true), the reasoning
// downgrade disclosed via X-Yabanin-Unsupported (D2), the tool output
// arriving in the translated role:tool message, exactly two upstream turns
// (no internal-loop turns minted by the gateway), and the minted-id refusal
// on the real session id (a real session id unlocks no history).
func TestResponses_CodexCLI_RealE2E_ToolsLoop(t *testing.T) {
	bin := requirePinnedCodex(t)

	chat := &chatBodies{}
	upstreamHits := atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		chat.add(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if !strings.Contains(string(raw), `"stream":true`) {
			// Direct test probe (no CLI involvement): the gateway forwarded
			// stream:false, so answer with a plain JSON completion the
			// gateway can mint a response id from.
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"c0","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"DIRECT-PROBE"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
			return
		}
		if !strings.Contains(string(raw), `"tools"`) {
			// CLI turn without tool history (defensive tooth): a plain SSE
			// turn whose text fails the final-message pin.
			_, _ = io.WriteString(w, "data: {\"id\":\"c0\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"TOOLS-BAD-no tools sent\"}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c0\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		if !strings.Contains(string(raw), `"role":"tool"`) {
			// Turn 1 — the CLI's advertised function tools must have ridden
			// the translation; the model calls exec_command with an argument
			// whose OUTPUT (37*11) never appears in the argument text, so a
			// lost/mangled tool output cannot fake the turn-2 check.
			if !strings.Contains(string(raw), "exec_command") {
				_, _ = io.WriteString(w, "data: {\"id\":\"c0\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"TOOLS-BAD-CLI tools not translated\"}}]}\n\n")
				flusher.Flush()
				_, _ = io.WriteString(w, "data: {\"id\":\"c0\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
				flusher.Flush()
				_, _ = io.WriteString(w, "data: [DONE]\n\n")
				return
			}
			upstreamHits.Add(1)
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_exec\",\"type\":\"function\",\"function\":{\"name\":\"exec_command\",\"arguments\":\"\"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"cmd\\\":\\\"echo $((37*11))\\\"}\"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		// Turn 2 — the executed output must be present in the tool message.
		upstreamHits.Add(1)
		answer := "TOOLS-E2E-2f8a loop verified"
		if !strings.Contains(toolMessageContent(t, string(raw)), "407") {
			answer = "TOOLS-BAD-exec output lost"
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\""+answer+"\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"gpt-5-codex": {ModelName: "gpt-5-codex", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	gw.models = staticModelLister{entry: modelEntry{
		ID: "gpt-5-codex", DisplayName: "gpt-5-codex", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}

	router := chi.NewRouter()
	gw.routes(router)
	capture, mux := newRtripCapture(router)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	home := writeCodexHome(t, "http://"+ln.Addr().String(), "gpt-5-codex", "danger-full-access",
		"\nmodel_reasoning_effort = \"low\"\n")
	workdir := t.TempDir()
	lastMsg := filepath.Join(workdir, "last-message.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := startCodexExec(ctx, bin, home, workdir, lastMsg,
		"Run exec_command with cmd \"echo $((37*11))\" and report its exact output.")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex exec failed: %v\n--- codex output ---\n%s", err, string(out))
	}

	// The executed output reached the upstream translation (role:tool), and
	// the CLI relayed the verified answer.
	final, rerr := os.ReadFile(lastMsg) //nolint:gosec // test temp file
	if rerr != nil {
		t.Fatalf("read last message: %v\ncodex output:\n%s", rerr, string(out))
	}
	if !strings.Contains(string(final), "TOOLS-E2E-2f8a") {
		t.Fatalf("tool loop did not complete honestly:\n%q\ncodex output:\n%s", string(final), string(out))
	}

	// Wire pins on the client leg. The capture entry lands after the
	// gateway's SSE handler observes the upstream EOF — later than the CLI's
	// exit — so wait for both turns to settle before asserting.
	deadline := time.Now().Add(5 * time.Second)
	for capture.postCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("want exactly 2 POST /v1/responses (one per turn), got %d: %v",
				capture.postCount(), capture.summary())
		}
		time.Sleep(20 * time.Millisecond)
	}
	posts := capture.posts(t)
	if len(posts) != 2 {
		t.Fatalf("want exactly 2 POST /v1/responses (one per turn), got %d", len(posts))
	}
	chatResponsesStateless(t, posts)
	var turn1 struct {
		Reasoning struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
		Input []map[string]any `json:"input"`
	}
	if err := json.Unmarshal(posts[0].reqBody, &turn1); err != nil {
		t.Fatalf("turn-1 body: %v", err)
	}
	if turn1.Reasoning.Effort != "low" {
		t.Fatalf("turn-1 reasoning.effort=%q, want low (the downgrade the gateway must disclose)", turn1.Reasoning.Effort)
	}
	if got := posts[0].respHdr.Get("X-Yabanin-Unsupported"); !strings.Contains(got, "reasoning") {
		t.Fatalf("D2 on the real client: reasoning drop not announced, header %q", got)
	}

	// Turn 2 is a full-history stateless resend: user turn, assistant tool
	// call, tool output — never a continuation id.
	var turn2 struct {
		Input []map[string]any `json:"input"`
	}
	if err := json.Unmarshal(posts[1].reqBody, &turn2); err != nil {
		t.Fatalf("turn-2 body: %v", err)
	}
	if len(turn2.Input) < 3 {
		t.Fatalf("turn-2 input has %d items, want the full resend (user + tool call + tool output):\n%s", len(turn2.Input), posts[1].reqBody)
	}
	types := map[string]bool{}
	for _, it := range turn2.Input {
		if tt, _ := it["type"].(string); tt != "" {
			types[tt] = true
		}
	}
	if !types["function_call"] || !types["function_call_output"] {
		t.Fatalf("turn-2 resend missing the tool exchange items: %v\n%s", types, posts[1].reqBody)
	}

	// The translated upstream bodies carry no continuation semantics and the
	// gateway minted no internal-loop turns: exactly two model turns.
	bodies := chat.snapshot()
	if len(bodies) != 2 {
		t.Fatalf("upstream saw %d chat turns, want exactly 2 (no internal loop)", len(bodies))
	}
	for i, b := range bodies {
		if strings.Contains(b, "previous_response_id") {
			t.Fatalf("translated chat body %d leaks continuation semantics:\n%s", i+1, b)
		}
	}

	// A response id the gateway minted (here: via a direct non-stream call on
	// the same live server) unlocks nothing: continuation with it is refused
	// before any upstream call. The real session never sent one — every turn
	// above re-sent full history with store=false (T03 canon re-verified on a
	// live server under a real client).
	probeReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+ln.Addr().String()+"/v1/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":"Direct probe","store":false}`))
	if err != nil {
		t.Fatal(err)
	}
	probeReq.Header.Set("Authorization", "Bearer test-key")
	probeReq.Header.Set("Content-Type", "application/json")
	probe, err := http.DefaultClient.Do(probeReq)
	if err != nil {
		t.Fatal(err)
	}
	probeBody, _ := io.ReadAll(probe.Body)
	_ = probe.Body.Close()
	if probe.StatusCode != http.StatusOK {
		t.Fatalf("direct probe: %d: %s", probe.StatusCode, probeBody)
	}
	var minted struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(probeBody, &minted); err != nil || minted.ID == "" {
		t.Fatalf("direct probe: no response id: %v: %s", err, probeBody)
	}
	contReq := fmt.Sprintf(`{"model":"gpt-5-codex","input":"Continue","previous_response_id":%q,"store":false}`, minted.ID)
	contHTTP, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+ln.Addr().String()+"/v1/responses", strings.NewReader(contReq))
	if err != nil {
		t.Fatal(err)
	}
	contHTTP.Header.Set("Authorization", "Bearer test-key")
	contHTTP.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(contHTTP)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "previous_response_not_supported") {
		t.Fatalf("minted id %s must be refused with 400 previous_response_not_supported, got %d: %s", minted.ID, res.StatusCode, raw)
	}
	if n := chat.snapshot(); len(n) != 3 {
		t.Fatalf("the refusal consulted the upstream (%d chat turns after the direct probe), must refuse before routing", len(n))
	}
	t.Logf("real codex tool loop confirmed: upstream turns=%d, minted=%s refused, final=%q",
		upstreamHits.Load(), minted.ID, strings.TrimSpace(string(final)))
}

// TestResponses_CodexCLI_RealE2E_UnsupportedToolCall pins the capability
// error path on the real client: the upstream emits a tool call the CLI does
// not register ("shell" — 0.166.0 advertises exec_command). The CLI surfaces
// the capability error verbatim as the tool output, the error text crosses
// the gateway inside the stateless resend, and the run completes honestly —
// no swallowed call, no fake tool success.
func TestResponses_CodexCLI_RealE2E_UnsupportedToolCall(t *testing.T) {
	bin := requirePinnedCodex(t)

	chat := &chatBodies{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		chat.add(raw)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if !strings.Contains(string(raw), `"role":"tool"`) {
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_shell\",\"type\":\"function\",\"function\":{\"name\":\"shell\",\"arguments\":\"\"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"command\\\":[\\\"echo\\\",\\\"hi\\\"]}\"}}]}}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		answer := "CAPERR-BAD-unsupported swallowed"
		if strings.Contains(toolMessageContent(t, string(raw)), "unsupported call: shell") {
			answer = "CAPERR-OK-9f3e surfaced"
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\""+answer+"\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"c2\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"gpt-5-codex": {ModelName: "gpt-5-codex", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	gw.models = staticModelLister{entry: modelEntry{
		ID: "gpt-5-codex", DisplayName: "gpt-5-codex", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}

	router := chi.NewRouter()
	gw.routes(router)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	home := writeCodexHome(t, "http://"+ln.Addr().String(), "gpt-5-codex", "read-only", "")
	workdir := t.TempDir()
	lastMsg := filepath.Join(workdir, "last-message.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := startCodexExec(ctx, bin, home, workdir, lastMsg,
		"Run the shell tool with command [\"echo\",\"hi\"].")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex exec failed: %v\n--- codex output ---\n%s", err, string(out))
	}

	final, rerr := os.ReadFile(lastMsg) //nolint:gosec // test temp file
	if rerr != nil {
		t.Fatalf("read last message: %v\ncodex output:\n%s", rerr, string(out))
	}
	if !strings.Contains(string(final), "CAPERR-OK-9f3e") {
		t.Fatalf("capability error not surfaced honestly:\n%q\ncodex output:\n%s", string(final), string(out))
	}

	bodies := chat.snapshot()
	if len(bodies) != 2 {
		t.Fatalf("upstream saw %d chat turns, want exactly 2", len(bodies))
	}
	// The capability error text crossed the gateway inside the resend: the
	// translated tool message carries it verbatim — not swallowed.
	if got := toolMessageContent(t, bodies[1]); !strings.Contains(got, "unsupported call: shell") {
		t.Fatalf("capability error text missing from the translated tool message: %q\n%s", got, bodies[1])
	}
	t.Logf("real codex capability-error loop confirmed: turns=%d, final=%q", len(bodies), strings.TrimSpace(string(final)))
}

// TestResponses_CodexCLI_RealE2E_ClientCancel pins the cancel path on the
// real client: the upstream streams deltas forever and holds the connection
// open (no mid-relay EOF), the test SIGINTs the CLI mid-stream. The CLI dies
// fast with a non-zero exit and NO last-message file (no false success); the
// gateway records exactly one terminal event for the responses endpoint —
// request.failed, the adapted-route canon — and the upstream relay is torn
// down (the held upstream handler observes the disconnect).
func TestResponses_CodexCLI_RealE2E_ClientCancel(t *testing.T) {
	bin := requirePinnedCodex(t)

	upstreamGone := make(chan struct{}, 1)
	// release unblocks the upstream handler after the assertions. The handler
	// must NEVER close the upstream connection mid-relay: a clean upstream
	// EOF can win the drain race against the client-cancel classification and
	// flip the settled canon to request.completed. With the connection held
	// open there is no terminal upstream frame to consume, so the only way
	// the drain can end is the canceled client context — request.failed,
	// deterministically.
	release := make(chan struct{})
	var relOnce sync.Once
	closeRelease := func() { relOnce.Do(func() { close(release) }) }
	var chatHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		flusher.Flush()
		for i := 0; ; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := fmt.Fprintf(w, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%d\"}}]}\n\n", i); err != nil {
				select {
				case upstreamGone <- struct{}{}:
				default:
				}
				<-release // hold the upstream open — see the canon note above
				return
			}
			flusher.Flush()
			if i == 0 {
				chatHits.Add(1)
			}
		}
	}))
	// Defers run at function return in LIFO order — BEFORE any t.Cleanup —
	// so the held upstream handler must be released by a defer registered
	// after upstream.Close, never by a cleanup: parking the handler while
	// httptest.Server.Close waits would deadlock the return path.
	defer upstream.Close()
	defer closeRelease()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"gpt-5-codex": {ModelName: "gpt-5-codex", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	gw.models = staticModelLister{entry: modelEntry{
		ID: "gpt-5-codex", DisplayName: "gpt-5-codex", Provider: "openai", CreatedAt: time.Now().UTC(),
	}}

	// Only request.* events on the responses endpoint count as terminal for
	// this pin; the observer records — it never logs (it runs on gateway
	// goroutines that may outlive the test).
	var evMu sync.Mutex
	var terminal []eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "responses" || !strings.HasPrefix(e.EventType, "request.") {
			return
		}
		evMu.Lock()
		terminal = append(terminal, *e)
		evMu.Unlock()
	})
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	home := writeCodexHome(t, "http://"+ln.Addr().String(), "gpt-5-codex", "read-only", "")
	workdir := t.TempDir()
	lastMsg := filepath.Join(workdir, "last-message.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := startCodexExec(ctx, bin, home, workdir, lastMsg,
		"Count upward forever, one number per message.")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start codex exec: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	// Wait until the stream is flowing (deltas delivered), then SIGINT.
	deadline := time.Now().Add(30 * time.Second)
	for chatHits.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the stream never started within 30s")
		}
		if cmd.Process.Signal(syscall.Signal(0)) != nil {
			t.Fatalf("codex exited before the stream started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // settle: SIGINT lands mid-stream (the held upstream cannot end first)
	sigErr := cmd.Process.Signal(os.Interrupt)
	if sigErr != nil {
		t.Fatalf("SIGINT: %v", sigErr)
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case err := <-waitCh:
		if err == nil {
			t.Fatal("SIGINT must not yield a clean exit — the CLI died honestly, exit non-zero")
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("unexpected wait error: %v", err)
		}
		t.Logf("codex exited on SIGINT with code %d", ee.ExitCode())
	case <-time.After(10 * time.Second):
		t.Fatal("codex did not exit within 10s of SIGINT")
	}

	if _, statErr := os.Stat(lastMsg); !os.IsNotExist(statErr) {
		t.Fatalf("last-message file exists after cancel — false success:\n%s", lastMsg)
	}

	// Exactly one terminal gateway event, and it is the adapted-route canon.
	var ev *eventpub.Event
	evDeadline := time.Now().Add(10 * time.Second)
	for ev == nil && time.Now().Before(evDeadline) {
		evMu.Lock()
		if len(terminal) > 0 {
			ev = &terminal[0]
		}
		evMu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	if ev == nil {
		t.Fatal("no terminal event recorded after the real client cancel")
	}
	if ev.EventType != "request.failed" {
		evMu.Lock()
		dump := fmt.Sprintf("%+v", terminal)
		evMu.Unlock()
		t.Fatalf("adapted-route cancel canon is request.failed, got %s (term=%s err=%q in=%d out=%d); terminal events: %s",
			ev.EventType, ev.Termination, ev.Error, ev.TokensIn, ev.TokensOut, dump)
	}
	// No double billing: a short grace window must stay silent.
	time.Sleep(1500 * time.Millisecond)
	evMu.Lock()
	n := len(terminal)
	evMu.Unlock()
	if n != 1 {
		t.Fatalf("exactly one terminal event expected, got %d", n)
	}

	select {
	case <-upstreamGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled upstream never observed the relay teardown")
	}
	t.Logf("real codex client cancel confirmed: one terminal event (%s), relay torn down", ev.EventType)
}
