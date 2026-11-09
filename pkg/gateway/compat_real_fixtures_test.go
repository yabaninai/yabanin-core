package cli

// N07-P08-T04: fixtures from anonymized REAL client protocols.
//
// The files under testdata/compat/real are anonymized derivatives of wire
// bodies actually sent by real client binaries (opencode 1.19.5,
// codex-cli 0.166.0, captured 2026-11-03 against a loopback capture
// server). Anonymization is a security boundary: request headers were
// never recorded (no key can leak), machine paths and all client-generated
// session identifiers were replaced with fixed placeholders, and the rest
// of each body is byte-for-byte the captured protocol shape — so gateway
// behavior against the fixture is behavior against the real client
// request. The manifest subtest pins the card acceptance (every fixture
// carries tested version, capture date, endpoint and limitations), and the
// anonymization subtest re-runs the scrub scan so a future fixture that
// leaks identifiers fails loud here instead of entering the repository.
//
// These fixtures do NOT refresh the live-binary e2e rows in
// docs/compatibility.md: a fixture-level capture pins the wire shape of
// exactly the recorded client version (client_version + captured_at); a
// client update invalidates the row until it is recaptured.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/apiformat"
)

type realFixtureMeta struct {
	File          string   `json:"file"`
	Client        string   `json:"client"`
	ClientVersion string   `json:"client_version"`
	Endpoint      string   `json:"endpoint"`
	Streaming     bool     `json:"streaming"`
	CapturedAt    string   `json:"captured_at"`
	WhatItPins    string   `json:"what_it_pins"`
	MatrixRow     string   `json:"matrix_row"`
	Limitations   []string `json:"limitations"`
	ScrubStats    struct {
		PathsReplaced int `json:"paths_replaced"`
		UuidsReplaced int `json:"uuids_replaced"`
	} `json:"scrub_stats"`
}

type realManifest struct {
	SchemaVersion string            `json:"schema_version"`
	Fixtures      []realFixtureMeta `json:"fixtures"`
}

func readRealManifest(t *testing.T) realManifest {
	t.Helper()
	raw, err := os.ReadFile("testdata/compat/real/manifest.json")
	if err != nil {
		t.Fatalf("real-protocol fixture manifest: %v", err)
	}
	var m realManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json is not valid JSON: %v", err)
	}
	if len(m.Fixtures) == 0 {
		t.Fatal("manifest lists no fixtures")
	}
	return m
}

// scrubRule is one anonymization boundary rule over the real-fixture
// corpus: a pattern plus an allow-filter for the fixed placeholder or
// documented protocol values that must pass (Go regexp has no negative
// lookahead, so raw hits are re-filtered instead).
type scrubRule struct {
	name  string
	re    *regexp.Regexp
	allow func(match string) bool
}

// realFixtureScrubRules is the single source of truth for the
// real-fixture anonymization scan. Both the corpus scan (anonymization
// subtest) and the per-class defeat teeth (scrubber_teeth subtest) run
// exactly these rules: a rule that is removed or narrowed immediately
// turns the teeth RED, so a scanner that silently passes a planted class
// cannot return without failing loud first.
func realFixtureScrubRules() []scrubRule {
	return []scrubRule{
		{name: "foreign /home/... path", re: regexp.MustCompile(`/home/[A-Za-z0-9._-]+`), allow: func(m string) bool { return m == "/home/agent" }},
		{name: "capture machine path", re: regexp.MustCompile(`/tmp/opencode/capture`), allow: func(string) bool { return false }},
		{name: "internal hostname", re: regexp.MustCompile(`ip-\d+-\d+-\d+-\d+|compute\.internal`), allow: func(string) bool { return false }},
		{name: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), allow: func(m string) bool { return strings.HasSuffix(m, "opencode.ai") || strings.HasSuffix(m, "github.com") }},
		{name: "OpenAI-style key", re: regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`), allow: func(string) bool { return false }},
		{name: "Yabanin gateway key", re: regexp.MustCompile(`yb_[A-Za-z0-9_-]{6,}`), allow: func(string) bool { return false }},
		{name: "Yabanin agent key", re: regexp.MustCompile(`yag_[A-Za-z0-9_-]{6,}`), allow: func(string) bool { return false }},
		{name: "bearer token", re: regexp.MustCompile(`(?i)bearer[ =]+[A-Za-z0-9._-]{10,}`), allow: func(string) bool { return false }},
		{name: "non-anonymized UUID", re: regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), allow: func(m string) bool {
			return strings.HasPrefix(m, "00000000-0000-4000-8000-")
		}},
		{name: "long credential-like hex", re: regexp.MustCompile(`\b[0-9a-f]{40,}\b`), allow: func(string) bool { return false }},
		// Base64 blobs of real data virtually always carry digits; a
		// digit-free long run is a hand-written slash enumeration
		// (e.g. the manifest's tool list), not a credential.
		{name: "long credential-like b64", re: regexp.MustCompile(`\b[A-Za-z0-9+/]{60,}={0,2}\b`), allow: func(m string) bool {
			return !strings.ContainsAny(m, "0123456789")
		}},
		// Classes that a rule-deletion mutation proved the 11-rule set
		// above passed silently: prefixed token families, JWT shapes,
		// bare IP literals and non-/home absolute path fragments.
		{name: "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})`), allow: func(string) bool { return false }},
		{name: "AWS access key id (AKIA...)", re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), allow: func(string) bool { return false }},
		{name: "Slack token (xox...)", re: regexp.MustCompile(`\bxox[baprs][-_][A-Za-z0-9_-]{10,}`), allow: func(string) bool { return false }},
		{name: "JWT eyJ... three-segment token", re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`), allow: func(string) bool { return false }},
		{name: "bare IPv4 literal", re: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), allow: func(string) bool { return false }},
		// /Users/name is opencode's own generic example placeholder in its
		// public tool documentation, embedded in the captured system
		// prompt: protocol content, not a capture-machine identity. Any
		// other /Users/<name> home fragment is a violation.
		{name: "/Users/... path fragment", re: regexp.MustCompile(`/Users/[A-Za-z0-9._-]+`), allow: func(m string) bool { return m == "/Users/name" }},
		// /root (bare or nested) is a capture-machine path fragment (the
		// agent_name capture shape below is the concrete instance
		// present in the fixture). The [^<] guard keeps XML closing
		// tags like
		// </root> out of the class: they are captured protocol markup,
		// not paths.
		{name: "/root path fragment", re: regexp.MustCompile(`(?:^|[^<])/root\b(?:/[A-Za-z0-9._-]+)*`), allow: func(string) bool { return false }},
		// Generic machine-local absolute path family. This rule is what
		// makes the manifest's machine-paths sentence true ("the
		// anonymization scanner fails loud on any surviving absolute
		// path fragment outside the /home/agent tree"): the per-root
		// rules above name specific capture shapes, while this family
		// covers every standard machine-local root (opt, var, mnt, etc,
		// usr, srv, media, boot, snap, tmp, root, home, Users), so a
		// residue under /opt, /var or /mnt fails loud even though no
		// narrower rule names it. The [^<\w] guard keeps XML markup
		// (</root>) and word-internal slashes out of the class.
		// Documented protocol placeholders embedded in the clients' own
		// public prompts pass unchanged — bare /tmp/opencode
		// (opencode's workspace-temp placeholder) and /Users/name...
		// (opencode's home example) carry no capture-machine identity,
		// same category as the placeholder allowances above; anything
		// nested below them (e.g. a surviving capture path) is still a
		// violation.
		{name: "machine-local absolute path fragment", re: regexp.MustCompile(`(?:^|[^<\w])/(?:opt|var|mnt|etc|usr|srv|media|boot|snap|tmp|root|home|Users)\b(?:/[A-Za-z0-9._-]+)*`), allow: func(m string) bool {
			// The leading guard character is part of the match; drop it
			// so the filters below see the path itself.
			if len(m) > 0 && m[0] != '/' {
				m = m[1:]
			}
			return m == "/Users/name" || strings.HasPrefix(m, "/Users/name/") ||
				m == "/tmp/opencode" ||
				m == "/home/agent" || strings.HasPrefix(m, "/home/agent/")
		}},
	}
}

// TestClientCompatRealProtocolFixtures drives anonymized real-protocol
// captures through the gateway and pins the matrix metadata contract.
// Slack bot-token teeth-row fixtures, assembled at RUNTIME from fragments:
// the public-export gate's source secret scan (scripts/public-export-gate.sh
// section b) greps exported source text for the Slack bot-token prefix with
// no suffix requirement, so the assembled shape must never appear as a
// contiguous literal in this file — the class label included. The repo-side
// scan and gosec G101 note in the planted table below applies to every
// other prefixed family the same way (suffix-required patterns are safe as
// fragments). Runtime values are byte-identical to the literals they
// replace; TestCompatSlackTeethRowGolden pins both with independent splits.
var (
	compatXoxbRowClass  = "xox" + "b- Slack bot token"
	compatXoxbRowSample = `"token":"xox` + "b-" + strings.Repeat("a0Z9-", 4) + `"`
)

func TestClientCompatRealProtocolFixtures(t *testing.T) {
	t.Run("manifest", func(t *testing.T) {
		m := readRealManifest(t)
		dateRe := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
		for _, f := range m.Fixtures {
			if f.File == "" || f.Client == "" || f.ClientVersion == "" {
				t.Errorf("%s: client/client_version/file must be present", f.File)
			}
			if !dateRe.MatchString(f.CapturedAt) {
				t.Errorf("%s: captured_at %q is not YYYY-MM-DD — the matrix date column rests on it", f.File, f.CapturedAt)
			}
			if f.Endpoint == "" || !strings.HasPrefix(f.Endpoint, "POST /v1/") {
				t.Errorf("%s: endpoint %q must name the inbound API route", f.File, f.Endpoint)
			}
			if f.WhatItPins == "" || f.MatrixRow == "" {
				t.Errorf("%s: what_it_pins/matrix_row must say what the fixture is evidence for", f.File)
			}
			if len(f.Limitations) == 0 {
				t.Errorf("%s: limitations must be recorded — a fixture row without limitations is not a matrix row", f.File)
			}
			if _, err := os.Stat(filepath.Join("testdata", "compat", "real", f.File)); err != nil {
				t.Errorf("%s: fixture file missing: %v", f.File, err)
			}
		}
	})

	t.Run("anonymization", func(t *testing.T) {
		// Security boundary: every file in the real/ directory must stay
		// scrubbed. Any violation below is a loud failure, never a silent
		// pass. The rules (and their allow-filters for the scrubber's own
		// placeholders) live in realFixtureScrubRules, shared with the
		// scrubber_teeth defeat subtest.
		rules := realFixtureScrubRules()
		entries, err := os.ReadDir("testdata/compat/real")
		if err != nil {
			t.Fatalf("real fixture dir: %v", err)
		}
		if len(entries) < 2 {
			t.Fatal("real fixture directory is empty")
		}
		for _, e := range entries {
			raw, rerr := os.ReadFile(filepath.Join("testdata", "compat", "real", e.Name()))
			if rerr != nil {
				t.Fatalf("%s: %v", e.Name(), rerr)
			}
			for _, s := range rules {
				for _, hit := range s.re.FindAllString(string(raw), -1) {
					if s.allow(hit) {
						continue
					}
					t.Errorf("%s: anonymization violation (%s): %q", e.Name(), s.name, hit)
				}
			}
		}
	})

	t.Run("scrubber_teeth", func(t *testing.T) {
		// Per-class defeat teeth. Every row plants one class that a
		// rule-deletion mutation proved the previous 11-rule scanner
		// passed silently: ghp_/AKIA/xoxb_ token families, JWT eyJ...
		// shapes, bare IPv4 literals, /Users/ and /root path fragments,
		// machine-local absolute path residues (/opt, /var, /mnt);
		// plus one row per pre-existing
		// rule, and requires the named violation from the SAME rules the
		// corpus scan uses. If a rule is deleted or narrowed, this
		// subtest goes RED — the scanner cannot silently pass a planted
		// class again without failing here first.
		rules := realFixtureScrubRules()
		// Credential-shaped samples are assembled at runtime: the SOURCE
		// must never carry a literal token shape, or the repo-side
		// secret scan (scripts/quality/secret_scan.py) and gosec G101
		// would flag the teeth themselves. The runtime strings are
		// exactly the shapes the rules must catch; the Repeat tails have
		// the character classes and lengths of the real families.
		planted := []struct {
			class  string
			sample string
			rule   string
		}{
			// New classes: one defeat sample per class.
			{class: "ghp_ GitHub user PAT", sample: `"token":"ghp_` + strings.Repeat("a1B", 12) + `"`, rule: "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)"},
			{class: "gho_ GitHub app OAuth token", sample: `"token":"gho_` + strings.Repeat("c2D", 12) + `"`, rule: "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)"},
			{class: "github_pat_ fine-grained PAT", sample: `"token":"github_pat_` + strings.Repeat("x9_", 8) + `"`, rule: "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)"},
			{class: "AKIA AWS access key id", sample: `"key":"AKIA` + strings.Repeat("B4C8F2D6", 2) + `"`, rule: "AWS access key id (AKIA...)"},
			{class: compatXoxbRowClass, sample: compatXoxbRowSample, rule: "Slack token (xox...)"},
			{class: "xoxb_ Slack token sibling shape", sample: `"token":"xoxb_` + strings.Repeat("b1Y8-", 4) + `"`, rule: "Slack token (xox...)"},
			{class: "JWT eyJ... three-segment shape", sample: `"id_token":"eyJ` + strings.Repeat("hbGciOiJ", 5) + "." + strings.Repeat("c2VudCI6", 5) + "." + strings.Repeat("c2ln", 12) + `"`, rule: "JWT eyJ... three-segment token"},
			{class: "bare IPv4 literal", sample: `"host":"10.42.7.199"`, rule: "bare IPv4 literal"},
			{class: "/Users/ home path fragment", sample: `"cwd":"/Users/bobsmith/project"`, rule: "/Users/... path fragment"},
			{class: "/root path fragment (fixture agent_name shape)", sample: `"agent_name":"/root"`, rule: "/root path fragment"},
			{class: "/root nested path fragment", sample: `cd /root/.ssh/id_rsa`, rule: "/root path fragment"},
			{class: "/opt machine path residue", sample: `"bin":"/opt/router/bin/gateway"`, rule: "machine-local absolute path fragment"},
			{class: "/var machine path residue", sample: `"log_path":"/var/log/agent-runner.log"`, rule: "machine-local absolute path fragment"},
			{class: "/mnt machine path residue", sample: `"cwd":"/mnt/work/checkout"`, rule: "machine-local absolute path fragment"},
			// Pre-existing rule set: the original RED classes stay pinned
			// here too, so removing an old rule also fails loud.
			{class: "foreign /home path", sample: `cd /home/alice && make`, rule: "foreign /home/... path"},
			{class: "capture machine path", sample: `see /tmp/opencode/capture/dump.json`, rule: "capture machine path"},
			{class: "internal hostname", sample: `node ip-10-0-123-45.aws.internal`, rule: "internal hostname"},
			{class: "email identity", sample: `contact carol@examplecorp.io`, rule: "email"},
			{class: "OpenAI-style key", sample: `"key":"sk-` + strings.Repeat("k3y", 7) + `"`, rule: "OpenAI-style key"},
			{class: "Yabanin gateway key", sample: `"key":"yb_live_9f8e7d6c5b4a"`, rule: "Yabanin gateway key"},
			{class: "Yabanin agent key", sample: `"key":"yag_agent_1a2b3c4d5e"`, rule: "Yabanin agent key"},
			{class: "bearer token", sample: `Authorization: Bearer tok_1234567890abcdef`, rule: "bearer token"},
			{class: "non-anonymized UUID", sample: `"id":"550e8400-e29b-41d4-a716-446655440000"`, rule: "non-anonymized UUID"},
			{class: "long credential-like hex", sample: `"digest":"0123456789abcdef0123456789abcdef01234567"`, rule: "long credential-like hex"},
			{class: "long credential-like b64", sample: `"blob":"c2VjcmV0` + strings.Repeat("aB3dEf7h", 9) + `"`, rule: "long credential-like b64"},
		}
		for _, p := range planted {
			var caught []string
			for _, r := range rules {
				for _, hit := range r.re.FindAllString(p.sample, -1) {
					if r.allow(hit) {
						continue
					}
					caught = append(caught, r.name)
				}
			}
			named := false
			for _, name := range caught {
				if name == p.rule {
					named = true
					break
				}
			}
			if !named {
				t.Errorf("defeat tooth %q: scanner did not raise the named %q violation (caught: %v) — rule missing or narrowed", p.class, p.rule, caught)
			}
		}

		// Placeholder passage: the scrubber's own fixed values (and the
		// documented protocol placeholders) must never be violations —
		// rules so broad that legit fixtures fail would make the teeth
		// unusable noise.
		passing := []string{
			"/home/agent",
			"/Users/name",
			"00000000-0000-4000-8000-000000000005",
			"ops@opencode.ai",
			"read/edit/glob/grep/task/write/webfetch/agentskill/bash-command-env-inspector-todo-planner-runner",
			"</root>",
			"<root>/home/agent/project</root>",
			// Documented protocol placeholders and protocol routes that
			// the generic machine-local path family must keep passing.
			"/tmp/opencode",
			"/Users/name/My Documents",
			"/v1/chat/completions",
		}
		for _, p := range passing {
			for _, r := range rules {
				for _, hit := range r.re.FindAllString(p, -1) {
					if !r.allow(hit) {
						t.Errorf("placeholder passage %q: unexpected %q violation on %q — scanner rules reject the scrubber's own placeholder values", p, r.name, hit)
					}
				}
			}
		}
	})

	t.Run("opencode_title_probe", func(t *testing.T) {
		// Real opencode 1.19.5 secondary thread-title request: system-only
		// probe, no tools, stream+include_usage. The gateway must forward
		// the probe unchanged to the OpenAI-compatible upstream and relay
		// a valid streaming title back.
		body := readCompat(t, "real/opencode_title_probe.json")
		if strings.Contains(string(body), `"tools"`) {
			t.Fatal("title-probe fixture unexpectedly carries tools — recapture")
		}
		var sawToolsKey bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			sawToolsKey = strings.Contains(string(raw), `"tools"`)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Protocol capture\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
		}))
		defer upstream.Close()
		rec, ev := serveCompat(t, upstream.URL, "openai", http.MethodPost, "/v1/chat/completions", body, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if sawToolsKey {
			t.Fatal("title probe must not gain a tools field in transit")
		}
		if err := apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		if !strings.Contains(string(body), "stream_options") {
			t.Fatal("fixture lost stream_options — the real opencode probe asks for usage")
		}
		assertUsage(t, ev, "chat.completions")
	})

	t.Run("opencode_main_turn", func(t *testing.T) {
		// Real opencode 1.19.5 main turn: opencode's own system prompt and
		// its ten real tool definitions must reach the upstream intact
		// (OpenAI-compatible provider: content arrays forward as content
		// parts; tools forward as chat tools).
		body := readCompat(t, "real/opencode_main_turn.json")
		var upstreamTools string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			upstreamTools = string(raw)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Protocol capture\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
		}))
		defer upstream.Close()
		rec, ev := serveCompat(t, upstream.URL, "openai", http.MethodPost, "/v1/chat/completions", body, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if err := apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		for _, tool := range []string{"bash", "edit", "glob", "grep", "read", "skill", "task", "todowrite", "webfetch", "write"} {
			if !strings.Contains(upstreamTools, `"name":"`+tool+`"`) {
				t.Fatalf("upstream did not receive opencode's real %q tool definition", tool)
			}
		}
		if !strings.Contains(upstreamTools, `"tool_choice":"auto"`) {
			t.Fatal("upstream lost tool_choice=auto from the real opencode body")
		}
		if !strings.Contains(upstreamTools, `"max_tokens":32000`) {
			t.Fatal("upstream lost max_tokens=32000 from the real opencode body")
		}
		assertUsage(t, ev, "chat.completions")
	})

	t.Run("codex_responses_turn", func(t *testing.T) {
		// Real codex-cli 0.166.0 Responses body: client_metadata,
		// prompt_cache_key, store=false, reasoning.summary, include and
		// the namespace/web_search tool types go through the translation
		// path. Unrepresentable fields must be announced, never dropped
		// silently, and the client stream must be a valid Responses SSE.
		body := readCompat(t, "real/codex_responses_turn.json")
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Protocol capture\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
		}))
		defer upstream.Close()
		rec, ev := serveCompat(t, upstream.URL, "openai", http.MethodPost, "/v1/responses", body, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if err := apiformat.ValidateResponsesStream(apiformat.ParseSSE(rec.Body.Bytes())); err != nil {
			t.Fatalf("%v\n%s", err, rec.Body.String())
		}
		// Pin the exact dropped set for THIS capture: codex 0.166.0 sends
		// client_metadata plus namespace/web_search tool types the
		// translation cannot represent. They must be announced on the
		// response header, never dropped silently. If a gateway change
		// stops dropping one of these (or starts dropping more), this pin
		// fires loud — the compatibility row must be re-dated then.
		const wantDropped = "client_metadata,tool:namespace,tool:web_search"
		if dropped := rec.Header().Get("X-Yabanin-Unsupported"); dropped != wantDropped {
			t.Fatalf("dropped-fields announcement changed for codex 0.166.0: got %q, want %q — re-date the matrix row if this is a real contract change", dropped, wantDropped)
		}
		if !strings.Contains(rec.Body.String(), "Protocol capture") {
			t.Fatalf("canned answer missing from the client stream:\n%s", rec.Body.String())
		}
		assertUsage(t, ev, "responses")
	})
}

// TestCompatSlackTeethRowGolden is the golden equality pin for the
// runtime-assembled Slack teeth-row fixtures above: both golden values are
// built from DIFFERENT split points than the assembly, so a fragment edit
// that drifts the runtime shape fails loud instead of silently weakening
// the planted scanner-teeth class (the scrubber_teeth subtest re-proves
// the rule still catches the assembled sample at runtime).
func TestCompatSlackTeethRowGolden(t *testing.T) {
	wantClass := "xoxb" + `- Slack bot token`
	if got := compatXoxbRowClass; got != wantClass {
		t.Fatalf("slack teeth-row class drifted: got %q, want %q", got, wantClass)
	}
	wantSample := `"token":"xoxb` + `-` + strings.Repeat("a0Z9-", 4) + `"`
	if got := compatXoxbRowSample; got != wantSample {
		t.Fatalf("slack teeth-row sample drifted: got %q, want %q", got, wantSample)
	}
}
