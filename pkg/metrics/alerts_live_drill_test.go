package metrics_test

// N13-P04-T06 part 2 — the REAL half: live Telegram sink drill on the owner
// bot (card «Алерты и runbooks: Совместный пользовательский сценарий»).
//
// The card's stage acceptance requires the joint packet scenario to run on
// an agreed environment with REAL and MOCK checks explicitly distinguished.
// This file is the real leg; it is env-gated (T06_LIVE=1) and skips loudly
// in routine gate passes — the deterministic carry is
// alerts_live_sink_test.go (mock wire contract + token-redaction error
// paths), TestN13P04T06_GoldenBuilder_FormatPins below, and the N13-P04-T05
// battery (alerts_negative_test.go, alerts_secrets_test.go).
//
// What the armed drill does (ONE execution, ≤5 real messages, all labeled
// "TEST drill"):
//
//  1. Loads owner-approved credentials from a 0600 env file
//     (T06_LIVE_ENV, default /tmp/opencode/t06-live.env):
//     T06_TELEGRAM_BOT_TOKEN + CHAT_ID. Armed-but-missing credentials FAIL
//     loudly — never a skip.
//  2. Starts the pinned alertmanager (same digest as
//     deploy/docker-compose.prod.yml) with the VERBATIM compose entrypoint
//     render script (sed placeholders → env) and the prod posture
//     (read-only rootfs, user 65534, cap-drop ALL, no-new-privileges,
//     tmpfs /tmp + /data), on the host network with an ephemeral loopback
//     web port, and ALERT_WEBHOOK_URL pointed at a drill-local webhook
//     listener — so the webhook integration succeeds and the group can
//     never re-notify at group_interval (real-message budget protection).
//  3. POSTs four synthetic alerts to /api/v2/alerts: three critical
//     "TEST drill" alerts (routing: severity=critical fan-out = webhook +
//     telegram) and one warning (routing contrast: webhook receiver only —
//     no telegram send may appear for it).
//  4. Waits for the alertmanager debug log line "Telegram message
//     successfully published message_id=N chat_id=M" — alertmanager's
//     parsing of the Telegram API response — exactly 3 times; every chat_id
//     must equal the owner chat. Log lines are redacted in memory: only
//     message ids survive into test output.
//  5. Proves the render pipeline live: amtool check-config OK on the
//     rendered config and zero unrendered __ALERT_*__ placeholders (the
//     T04 machine check, now executed inside the drill container).
//  6. Sends the golden-format message DIRECTLY through the same client the
//     mock battery pins: the alertmanager v0.27.0 telegram.default.message
//     template, embedded byte-exact and executed through html/template
//     (notify.TmplHTML semantics — ExecuteHTMLString contextual escaping),
//     over sorted pairs (alertname first, per template.KV.SortedPairs).
//     The API echo must equal the html-unescaped golden with message_id > 0
//     and chat.id == owner chat: same template path, same wire format,
//     real vs mock distinguished by construction.
//  7. Tears the container down before resolve_timeout (5m) so no resolved
//     messages exist. Real-message budget: full mode (default) = 3
//     alertmanager-driven + 1 direct golden send = 4; minimal mode
//     (T06_LIVE_MINIMAL=1, for re-runs on a partially-consumed budget)
//     = 1 alertmanager-driven + 1 direct golden send = 2. Both modes keep
//     the routing contrast (critical fans out, warning stays webhook-only).
//
// Secrets fence: the bot token and the chat id never appear in repo files,
// records, log lines, test output or error strings (the client redacts the
// token; chat ids are compared, never printed). Evidence JSON (message ids,
// counts, booleans — no secrets) goes to
// /tmp/opencode/t06-live-drill-evidence.json, outside the repository.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	drillEnvFlag        = "T06_LIVE"
	drillEnvFilePath    = "T06_LIVE_ENV"
	drillEnvFileDefault = "/tmp/opencode/t06-live.env"

	// Same image + digest the production stack runs
	// (deploy/docker-compose.prod.yml, pinned 2026-10-25); the drill must
	// not drift from the composed sink.
	alertmanagerDrillImage = "prom/alertmanager:v0.27.0@sha256:e13b6ed5cb929eeaee733479dce55e10eb3bc2e9c4586c705a4e8da41e5eacf5"

	drillContainerName = "t06live-am-n13p04t06"

	// Template mount point mirrors the compose volume mapping
	// (./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml.tmpl:ro).
	drillTemplateMount = "/etc/alertmanager/alertmanager.yml.tmpl"

	drillEvidencePath = "/tmp/opencode/t06-live-drill-evidence.json"

	// alertmanager v0.27.0 template/default.tmpl, lines 7-12 and 115-123,
	// byte-exact: the two defines the telegram integration uses. The message
	// define is the notifier's defaultMessageTemplate; alertname sorts first
	// inside __text_alert_list because template.KV.SortedPairs pins it there.
	amV27TelegramTemplate = `{{ define "__text_alert_list" }}{{ range . }}Labels:
{{ range .Labels.SortedPairs }} - {{ .Name }} = {{ .Value }}
{{ end }}Annotations:
{{ range .Annotations.SortedPairs }} - {{ .Name }} = {{ .Value }}
{{ end }}Source: {{ .GeneratorURL }}
{{ end }}{{ end }}

{{ define "telegram.default.message" }}
{{ if gt (len .Alerts.Firing) 0 }}
Alerts Firing:
{{ template "__text_alert_list" .Alerts.Firing }}
{{ end }}
{{ if gt (len .Alerts.Resolved) 0 }}
Alerts Resolved:
{{ template "__text_alert_list" .Alerts.Resolved }}
{{ end }}
{{ end }}`
)

// drillPair mirrors a template.LabelPair/AnnotationPair for the golden
// builder.
type drillPair struct {
	Name  string
	Value string
}

type drillPairs []drillPair

// SortedPairs lets the embedded template range over the pairs exactly like
// alertmanager's template data does ({{ range .Labels.SortedPairs }}).
func (p drillPairs) SortedPairs() drillPairs { return p }

type drillTemplateAlert struct {
	Labels       drillPairs
	Annotations  drillPairs
	GeneratorURL string
}

type drillAlerts struct {
	Firing   []drillTemplateAlert
	Resolved []drillTemplateAlert
}

type drillTemplateData struct {
	Alerts drillAlerts
}

// drillSortedPairs pins template.KV.SortedPairs semantics (alertmanager
// v0.27.0 template/template.go): alertname first, remaining names
// lexicographic. Annotation pairs contain no alertname, so plain
// lexicographic order covers them (alertnameFirst=false).
func drillSortedPairs(values map[string]string, alertnameFirst bool) drillPairs {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	if alertnameFirst {
		for i, name := range names {
			if name == "alertname" {
				copy(names[1:i+1], names[0:i])
				names[0] = "alertname"
				break
			}
		}
	}
	pairs := make(drillPairs, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, drillPair{Name: name, Value: values[name]})
	}
	return pairs
}

// drillGoldenMessage executes the embedded v0.27.0 template through
// html/template — the exact engine alertmanager's notify.TmplHTML selects
// for parse_mode=HTML (ExecuteHTMLString: contextual escaping over the
// shared parse tree). Interpolated values are escaped; template literals
// pass through.
func drillGoldenMessage(t *testing.T, firing []drillTemplateAlert) string {
	t.Helper()
	tmpl := template.Must(template.New("amv27-telegram").Parse(amV27TelegramTemplate))
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "telegram.default.message", drillTemplateData{Alerts: drillAlerts{Firing: firing}}); err != nil {
		t.Fatalf("golden template execution: %v", err)
	}
	return buf.String()
}

// The four synthetic drill alerts, all clearly labeled "TEST drill".
// runbook_url mirrors the documented test-fire procedure
// (docs/runbooks/alerts.md, https://example.com/test). The A2 description
// carries a literal template construct: API-posted annotation values are
// DATA, never re-executed by alertmanager, so it must reach the message
// verbatim — a template-injection negative on the live sink (pinned
// deterministically by TestN13P04T06_GoldenBuilder_FormatPins).
func drillAlertDelivery() drillTemplateAlert {
	return drillTemplateAlert{
		Labels: drillSortedPairs(map[string]string{
			"alertname": "TestFireDrillDelivery",
			"severity":  "critical",
			"job":       "t06-live-drill",
		}, true),
		Annotations: drillSortedPairs(map[string]string{
			"summary":     "TEST drill A1: telegram sink delivery check (N13-P04-T06)",
			"description": "TEST drill synthetic critical alert A1: verify alertmanager to telegram delivery; ignore",
			"runbook_url": "https://example.com/test",
		}, false),
	}
}

func drillAlertFormatParity() drillTemplateAlert {
	return drillTemplateAlert{
		Labels: drillSortedPairs(map[string]string{
			"alertname": "TestFireDrillFormatParity",
			"severity":  "critical",
			"job":       "t06-live-drill",
		}, true),
		Annotations: drillSortedPairs(map[string]string{
			"summary":     "TEST drill A2: golden format parity check",
			"description": "TEST drill literal probe: {{ $labels.alertname }} must stay unexpanded in the message",
			"runbook_url": "https://example.com/test",
		}, false),
	}
}

func drillAlertRouting() drillTemplateAlert {
	return drillTemplateAlert{
		Labels: drillSortedPairs(map[string]string{
			"alertname": "TestFireDrillRouting",
			"severity":  "critical",
			"job":       "t06-live-drill",
		}, true),
		Annotations: drillSortedPairs(map[string]string{
			"summary":     "TEST drill A3: critical fan-out routing probe",
			"description": "TEST drill synthetic critical alert A3: webhook and telegram fan-out; ignore",
			"runbook_url": "https://example.com/test",
		}, false),
	}
}

func drillAlertWebhookOnly() drillTemplateAlert {
	return drillTemplateAlert{
		Labels: drillSortedPairs(map[string]string{
			"alertname": "TestFireDrillWebhookOnly",
			"severity":  "warning",
			"job":       "t06-live-drill",
		}, true),
		Annotations: drillSortedPairs(map[string]string{
			"summary":     "TEST drill W1: warning stays webhook-only (no telegram)",
			"description": "TEST drill synthetic warning alert W1: routing contrast probe; ignore",
			"runbook_url": "https://example.com/test",
		}, false),
	}
}

// TestN13P04T06_GoldenBuilder_FormatPins pins the golden-format builder
// deterministically (every gate pass): byte-exact default.tmpl semantics
// (header line, sorted pairs, Source trailer, html-escaped interpolation)
// and the no-re-execution property of posted annotation values.
func TestN13P04T06_GoldenBuilder_FormatPins(t *testing.T) {
	golden := drillGoldenMessage(t, []drillTemplateAlert{drillAlertDelivery()})
	want := "\n\nAlerts Firing:\n" +
		"Labels:\n" +
		" - alertname = TestFireDrillDelivery\n" +
		" - job = t06-live-drill\n" +
		" - severity = critical\n" +
		"Annotations:\n" +
		" - description = TEST drill synthetic critical alert A1: verify alertmanager to telegram delivery; ignore\n" +
		" - runbook_url = https://example.com/test\n" +
		" - summary = TEST drill A1: telegram sink delivery check (N13-P04-T06)\n" +
		"Source: \n" +
		"\n\n\n"
	if golden != want {
		t.Fatalf("golden format drifted from the embedded v0.27.0 template bytes;\ngot:  %q\nwant: %q", golden, want)
	}

	// parse_mode=HTML means notify.TmplHTML → html/template: interpolated
	// values escape, literals do not.
	escaped := drillGoldenMessage(t, []drillTemplateAlert{{
		Labels:      drillSortedPairs(map[string]string{"alertname": "T<X>", "job": "j"}, true),
		Annotations: drillSortedPairs(map[string]string{"summary": "a & b"}, false),
	}})
	if !strings.Contains(escaped, " - alertname = T&lt;X&gt;") || !strings.Contains(escaped, " - summary = a &amp; b") {
		t.Fatalf("expected html-escaped interpolation (parse_mode=HTML), got %q", escaped)
	}

	// posted annotation values are never re-executed as templates
	literal := drillGoldenMessage(t, []drillTemplateAlert{drillAlertFormatParity()})
	if !strings.Contains(literal, " - description = TEST drill literal probe: {{ $labels.alertname }} must stay unexpanded in the message") {
		t.Fatalf("posted annotation value was altered; sinks must not re-execute posted templates, got %q", literal)
	}
}

// TestN13P04T06_GoldenBuilder_Parity_Run2Echo pins the LIVE wire echo of
// the direct golden send from armed run 2 (2026-11-05, minimal mode) as a
// deterministic, free-forever regression test: the byte-exact text Telegram
// echoed for the golden-format message (message delivered to the owner
// chat, API-verified in-run) must equal the golden builder's output modulo
// Telegram's server-side leading/trailing whitespace trim. Every gate pass
// therefore re-proves the format that actually reached the owner chat
// without spending a real message.
func TestN13P04T06_GoldenBuilder_Parity_Run2Echo(t *testing.T) {
	const liveEchoRun2 = "Alerts Firing:\n" +
		"Labels:\n" +
		" - alertname = TestFireDrillDelivery\n" +
		" - job = t06-live-drill\n" +
		" - severity = critical\n" +
		"Annotations:\n" +
		" - description = TEST drill synthetic critical alert A1: verify alertmanager to telegram delivery; ignore\n" +
		" - runbook_url = https://example.com/test\n" +
		" - summary = TEST drill A1: telegram sink delivery check (N13-P04-T06)\n" +
		"Source:"
	golden := strings.TrimSpace(drillGoldenMessage(t, []drillTemplateAlert{drillAlertDelivery()}))
	if liveEchoRun2 != golden {
		t.Fatalf("live run-2 echo no longer matches the golden builder;\necho:   %q\ngolden: %q", liveEchoRun2, golden)
	}
}

type drillCredentials struct {
	token  string
	chatID int64
}

// drillLoadCredentials reads the owner-provisioned drill env file. Values
// are never logged; failure messages carry the path and key names only.
func drillLoadCredentials(t *testing.T, envPath string) drillCredentials {
	t.Helper()
	//nolint:gosec // G703: drill env-contract path (T06_LIVE_ENV, default under /tmp/opencode), owner-provisioned, mode asserted 0600 below
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("drill credentials file %s is missing while armed with %s=1: %v — arming expects the owner-provisioned file; its values are never committed or echoed", envPath, drillEnvFlag, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("drill credentials file %s must be mode 0600, got %o", envPath, perm)
	}
	//nolint:gosec // G304: the path comes from the drill's own env contract (T06_LIVE_ENV, default /tmp/opencode/t06-live.env), mode verified 0600 above
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read %s: %v", envPath, err)
	}
	creds := drillCredentials{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "T06_TELEGRAM_BOT_TOKEN":
			creds.token = strings.TrimSpace(value)
		case "CHAT_ID":
			id, perr := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if perr != nil {
				t.Fatalf("%s: CHAT_ID is not an integer", envPath)
			}
			creds.chatID = id
		}
	}
	if creds.token == "" {
		t.Fatalf("%s: missing T06_TELEGRAM_BOT_TOKEN — an armed drill fails loud, it never skips", envPath)
	}
	if creds.chatID <= 0 {
		t.Fatalf("%s: missing or malformed CHAT_ID — an armed drill requires a positive chat id", envPath)
	}
	return creds
}

// drillDockerRun shells the pinned docker CLI. Callers treat errors as
// drill failures; the docker CLI cannot surface credential VALUES (the
// token rides --env-file into the container env, never argv), so the error
// text is safe to embed in test failures.
func drillDockerRun(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // G204: the drill shells the pinned docker CLI with drill-contract arguments (container name, env-file path, template path, loopback ports); no shell interpolation, credentials ride --env-file, never argv
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), err
}

// drillContainerLogs merges the container's stdout and stderr streams:
// without a TTY, `docker logs` demultiplexes container stderr to the CLI's
// stderr, and alertmanager logs to stderr — parsing only stdout silently
// yields zero evidence lines (the exact bug this helper exists to prevent).
func drillContainerLogs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", drillContainerName)
	var merged bytes.Buffer
	cmd.Stdout, cmd.Stderr = &merged, &merged
	err := cmd.Run()
	return merged.String(), err
}

func drillEnsureImage(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := drillDockerRun(ctx, "image", "inspect", alertmanagerDrillImage); err == nil {
		return
	}
	if _, err := drillDockerRun(ctx, "pull", alertmanagerDrillImage); err != nil {
		t.Fatalf("docker pull %s failed: %v (egress is required for the armed drill)", alertmanagerDrillImage, err)
	}
}

func drillReserveLoopbackPort(t *testing.T, ctx context.Context) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// drillWriteContainerEnv renders the container env file (0600, temp dir):
// exactly the three placeholders the compose service defines.
func drillWriteContainerEnv(t *testing.T, creds drillCredentials, webhookPort int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t06-live.env")
	content := strings.Join([]string{
		"ALERT_WEBHOOK_URL=http://127.0.0.1:" + strconv.Itoa(webhookPort) + "/webhook",
		"ALERT_TG_BOT_TOKEN=" + creds.token,
		"ALERT_TG_CHAT_ID=" + strconv.FormatInt(creds.chatID, 10),
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write drill container env file: %v", err)
	}
	return path
}

// drillEntrypointScript returns the compose alertmanager entrypoint script
// (deploy/docker-compose.prod.yml alertmanager service, with compose's $$
// un-escaped for direct docker use) plus drill-only flags: an ephemeral
// loopback web port (prod binds 9093; the drill must never collide with a
// running stack), --cluster.listen-address= (drill-only deviation: the
// prod compose runs exactly one alertmanager so the default *:9094 cluster
// bind is fine there, but the drill starts a SECOND alertmanager on the
// same host network — an unconfigured cluster bind would collide with any
// other alertmanager on 9094 or gossip alerts to a peer's dispatcher,
// silently diverting the drill's notifications), and debug logging (the
// telegram success evidence lives at debug level).
func drillEntrypointScript(amPort int) string {
	script := `WEBHOOK_URL=$(printf '%s' "$ALERT_WEBHOOK_URL" | sed -e 's/[\\&|]/\\&/g'); \
TG_TOKEN=$(printf '%s' "$ALERT_TG_BOT_TOKEN" | sed -e 's/[\\&|]/\\&/g'); \
TG_CHAT=$(printf '%s' "$ALERT_TG_CHAT_ID" | sed -e 's/[\\&|]/\\&/g'); \
sed -e "s|__ALERT_WEBHOOK_URL__|${WEBHOOK_URL}|g" \
    -e "s|__ALERT_TG_BOT_TOKEN__|${TG_TOKEN}|g" \
    -e "s|__ALERT_TG_CHAT_ID__|${TG_CHAT}|g" \
/etc/alertmanager/alertmanager.yml.tmpl > /tmp/alertmanager.yml \
&& exec /bin/alertmanager --config.file=/tmp/alertmanager.yml --storage.path=/data --web.listen-address=127.0.0.1:__DRILL_AM_PORT__ --cluster.listen-address= --log.level=debug`
	return strings.ReplaceAll(script, "__DRILL_AM_PORT__", strconv.Itoa(amPort))
}

func drillRunContainer(t *testing.T, ctx context.Context, envFile string, amPort int) {
	t.Helper()
	tmplSrc := filepath.Join("..", "..", "deploy", "alertmanager", "alertmanager.yml")
	tmplAbs, err := filepath.Abs(tmplSrc)
	if err != nil {
		t.Fatalf("resolve alertmanager template path: %v", err)
	}
	if _, err := os.Stat(tmplAbs); err != nil {
		t.Fatalf("alertmanager template missing relative to pkg/metrics: %v", err)
	}
	if _, err := drillDockerRun(ctx,
		"run", "-d", "--name", drillContainerName,
		"--network", "host",
		"--read-only",
		"--user", "65534:65534",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--tmpfs", "/tmp", "--tmpfs", "/data",
		"--env-file", envFile,
		"-v", tmplAbs+":"+drillTemplateMount+":ro",
		"--entrypoint", "/bin/sh",
		alertmanagerDrillImage,
		"-c", drillEntrypointScript(amPort),
	); err != nil {
		t.Fatalf("docker run of the drill alertmanager failed: %v", err)
	}
}

func drillWaitReady(t *testing.T, ctx context.Context, port int) {
	t.Helper()
	ready := fmt.Sprintf("http://127.0.0.1:%d/-/ready", port)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ready, nil)
		if err == nil {
			resp, doErr := http.DefaultClient.Do(req)
			if doErr == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("drill context expired waiting for alertmanager readiness: %v", ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatalf("alertmanager never became ready on 127.0.0.1:%d", port)
}

type drillAPIAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
}

func drillAlertSet(startsAt time.Time, alerts []drillTemplateAlert) []drillAPIAlert {
	build := func(alert drillTemplateAlert) (map[string]string, map[string]string) {
		labels := map[string]string{}
		for _, p := range alert.Labels {
			labels[p.Name] = p.Value
		}
		annotations := map[string]string{}
		for _, p := range alert.Annotations {
			annotations[p.Name] = p.Value
		}
		return labels, annotations
	}
	set := make([]drillAPIAlert, 0, len(alerts))
	for _, alert := range alerts {
		labels, annotations := build(alert)
		set = append(set, drillAPIAlert{Labels: labels, Annotations: annotations, StartsAt: startsAt.Format(time.RFC3339)})
	}
	return set
}

func drillPostAlerts(t *testing.T, ctx context.Context, port int, alerts []drillAPIAlert) {
	t.Helper()
	raw, err := json.Marshal(alerts)
	if err != nil {
		t.Fatalf("marshal drill alerts: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/v2/alerts", port), bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build alert POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("alert POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alert POST failed: status %d body %q", resp.StatusCode, string(body))
	}
}

type drillTelegramSend struct {
	MessageID int64
	ChatID    int64
}

// telegramSuccessLine matches alertmanager's debug confirmation of the
// parsed Telegram API response (integration log for the telegram receiver).
var telegramSuccessLine = regexp.MustCompile(`message_id=(\d+) chat_id=(\d+)`)

// drillWaitTelegramEvidence polls the container logs for the telegram
// success lines. Raw log text is never printed: only the parsed message ids
// and the owner-chat comparison survive into test output.
func drillWaitTelegramEvidence(t *testing.T, ctx context.Context, creds drillCredentials, want int) []drillTelegramSend {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	var sends []drillTelegramSend
	for {
		logs, err := drillContainerLogs(ctx)
		if err != nil {
			t.Fatalf("docker logs failed: %v", err)
		}
		sends = sends[:0]
		for _, m := range telegramSuccessLine.FindAllStringSubmatch(logs, -1) {
			id, _ := strconv.ParseInt(m[1], 10, 64)
			chat, _ := strconv.ParseInt(m[2], 10, 64)
			sends = append(sends, drillTelegramSend{MessageID: id, ChatID: chat})
		}
		if len(sends) >= want || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("drill context expired waiting for telegram evidence: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	if len(sends) != want {
		t.Fatalf("telegram success lines: got %d, want exactly %d (a higher count would mean re-notification — real-message budget violation)", len(sends), want)
	}
	for _, s := range sends {
		if s.ChatID != creds.chatID {
			t.Fatalf("telegram delivery reached chat %d, not the owner chat — the drill may only reach the owner chat", s.ChatID)
		}
		if s.MessageID <= 0 {
			t.Fatalf("telegram send with non-positive message id %+v", s)
		}
	}
	return sends
}

type drillWebhookPost struct {
	Alertname string
	At        time.Time
}

type drillWebhookCapture struct {
	mu    sync.Mutex
	posts []drillWebhookPost
}

func (c *drillWebhookCapture) snapshot() []drillWebhookPost {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]drillWebhookPost(nil), c.posts...)
}

// drillStartWebhookListener is the drill-local webhook receiver. Because the
// webhook integration succeeds against it, alertmanager's group logic never
// re-notifies at group_interval — the real-message budget stays fixed.
func drillStartWebhookListener(t *testing.T, ctx context.Context) (*drillWebhookCapture, int) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("webhook listener listen: %v", err)
	}
	capture := &drillWebhookCapture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		// alertmanager's webhook integration posts an OBJECT:
		// {"receiver":..., "alerts":[{"labels":{...}}, ...]} — decoding it
		// as a bare array fails silently and the drill would starve for
		// evidence while the sink side logs success (the exact bug class
		// this capture exists to catch). Decode failures append a loud
		// marker entry so the want-count mismatch points here.
		var payload struct {
			Alerts []struct {
				Labels map[string]string `json:"labels"`
			} `json:"alerts"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			capture.mu.Lock()
			capture.posts = append(capture.posts, drillWebhookPost{Alertname: "<decode-error>", At: time.Now()})
			capture.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		capture.mu.Lock()
		for _, a := range payload.Alerts {
			capture.posts = append(capture.posts, drillWebhookPost{Alertname: a.Labels["alertname"], At: time.Now()})
		}
		capture.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return capture, ln.Addr().(*net.TCPAddr).Port
}

func drillWaitWebhookPosts(t *testing.T, ctx context.Context, capture *drillWebhookCapture, want int) []drillWebhookPost {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		posts := capture.snapshot()
		if len(posts) >= want || time.Now().After(deadline) {
			if len(posts) == want {
				return posts
			}
			names := map[string]int{}
			for _, p := range posts {
				names[p.Alertname]++
			}
			t.Fatalf("webhook posts: got %d, want exactly %d (per-alertname counts: %v)", len(posts), want, names)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("drill context expired waiting for webhook posts: %v", ctx.Err())
		case <-time.After(1 * time.Second):
		}
	}
}

// assertRenderedConfig proves the T04 render pipeline live inside the drill
// container: amtool accepts the rendered config and no __ALERT_*__
// placeholder survived the sed render. Neither check prints config content.
func assertRenderedConfig(t *testing.T, ctx context.Context) {
	t.Helper()
	grepOut, err := drillDockerRun(ctx, "exec", drillContainerName, "/bin/sh", "-c", "grep -c '__ALERT_' /tmp/alertmanager.yml || true")
	if err != nil {
		t.Fatalf("placeholder grep inside the drill container failed: %v", err)
	}
	if got := strings.TrimSpace(grepOut); got != "0" {
		t.Fatalf("rendered config still contains unrendered placeholders (count %q), want 0", got)
	}
	amtoolOut, err := drillDockerRun(ctx, "exec", drillContainerName, "/bin/amtool", "check-config", "/tmp/alertmanager.yml")
	if err != nil || !strings.Contains(amtoolOut, "SUCCESS") { // v0.27.0 prints "Checking '...'  SUCCESS"
		t.Fatalf("amtool check-config failed on the rendered config: err=%v out=%q", err, strings.TrimSpace(amtoolOut))
	}
}

func drillDirectGoldenSend(t *testing.T, ctx context.Context, creds drillCredentials) *telegramSentMessage {
	t.Helper()
	client := &telegramSinkClient{
		baseURL: "https://api.telegram.org",
		token:   creds.token,
		chatID:  creds.chatID,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
	golden := drillGoldenMessage(t, []drillTemplateAlert{drillAlertDelivery()})
	sent, err := client.sendMessage(ctx, golden) // error text is token-redacted by construction
	if err != nil {
		t.Fatalf("direct golden send failed: %s", err)
	}
	if sent.MessageID <= 0 || sent.ChatID != creds.chatID {
		t.Fatalf("direct send verification failed: message_id=%d owner-chat-match=%v", sent.MessageID, sent.ChatID == creds.chatID)
	}
	// log the direct-send ledger immediately (before any later assertion
	// can abort the run)
	t.Logf("LIVE drill: direct golden send verified (message_id=%d, owner-chat-match=true)", sent.MessageID)
	// Telegram's server trims leading/trailing whitespace from message
	// text before echoing (observed live, N13-P04-T06 run 2: golden with
	// "\n\n" prefix and " \n\n\n" suffix echoed trimmed); everything
	// between is byte-exact. Parity law: trimmed echo == trimmed
	// html-unescaped golden.
	want := strings.TrimSpace(html.UnescapeString(golden))
	if strings.TrimSpace(sent.Text) != want {
		t.Fatalf("golden parity drift on the live wire;\nsent: %q\nwant: %q", sent.Text, want)
	}
	if len(sent.Entities) != 0 {
		t.Fatalf("unexpected markup artifacts for the plain TEST text: %+v", sent.Entities)
	}
	t.Logf("LIVE golden message text (as sent to the owner chat):\n%s", want)
	return sent
}

type drillEvidence struct {
	Card                 string  `json:"card"`
	Lane                 string  `json:"lane"`
	Mode                 string  `json:"mode"`
	StartedAt            string  `json:"started_at"`
	FinishedAt           string  `json:"finished_at"`
	AlertmanagerImage    string  `json:"alertmanager_image"`
	TelegramMessageIDs   []int64 `json:"alertmanager_telegram_message_ids"`
	DirectGoldenID       int64   `json:"direct_golden_message_id"`
	OwnerChatVerified    bool    `json:"owner_chat_verified"`
	WebhookPosts         int     `json:"webhook_posts"`
	WarningWebhookOnly   bool    `json:"warning_webhook_only"`
	AMToolOK             bool    `json:"amtool_check_config_ok"`
	UnrenderedContainers int     `json:"unrendered_placeholders"`
	GoldenBytes          int     `json:"golden_bytes"`
	RealMessagesTotal    int     `json:"real_messages_total"`
}

func TestN13P04T06_LiveTelegramSink_Drill(t *testing.T) {
	if os.Getenv(drillEnvFlag) != "1" {
		t.Skipf("REAL-credential live drill (N13-P04-T06): armed only with %s=1 on a networked stand holding owner-approved bot credentials in the drill env file — it sends real messages to the owner chat. Routine gate passes carry the contract deterministically via TestN13P04T06_MockSink_* and TestN13P04T06_GoldenBuilder_FormatPins plus the N13-P04-T05 battery; arming procedure: artifacts/internal-delivery-program/imp-t06live-2026-11-05.md", drillEnvFlag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	startedAt := time.Now().UTC()

	envPath := os.Getenv(drillEnvFilePath)
	if envPath == "" {
		envPath = drillEnvFileDefault
	}
	creds := drillLoadCredentials(t, envPath)
	drillEnsureImage(t, ctx)

	capture, webhookPort := drillStartWebhookListener(t, ctx)
	amPort := drillReserveLoopbackPort(t, ctx)
	envFile := drillWriteContainerEnv(t, creds, webhookPort)
	// the env file holds the live token: remove it as soon as the container
	// has consumed it (t.TempDir cleans the directory afterwards regardless)
	t.Cleanup(func() { _ = os.Remove(envFile) })

	drillRunContainer(t, ctx, envFile, amPort)
	t.Cleanup(func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		if _, err := drillDockerRun(rmCtx, "rm", "-f", drillContainerName); err != nil {
			t.Logf("drill container cleanup: %v", err)
		}
	})

	drillWaitReady(t, ctx, amPort)

	// Budget modes. Full (default): 4 alerts → 3 critical groups → 3
	// telegram sends + 1 direct golden = 4 real messages. Minimal
	// (T06_LIVE_MINIMAL=1): one critical + the warning → 1 telegram send +
	// 2 webhook posts + 1 direct golden = 2 real messages, for re-runs that
	// must fit a partially-consumed real-message budget. The routing
	// contrast (critical fans out, warning stays webhook-only) holds in
	// both modes; the no-re-execution pin for A2 lives in the deterministic
	// golden builder, so minimal mode loses no pinned property — only
	// fan-out breadth.
	minimal := os.Getenv("T06_LIVE_MINIMAL") == "1"
	wantSends, wantPosts := 3, 4
	alertSet := []drillTemplateAlert{drillAlertDelivery(), drillAlertFormatParity(), drillAlertRouting(), drillAlertWebhookOnly()}
	expectedNames := []string{"TestFireDrillDelivery", "TestFireDrillFormatParity", "TestFireDrillRouting", "TestFireDrillWebhookOnly"}
	mode := "full"
	if minimal {
		mode = "minimal"
		wantSends, wantPosts = 1, 2
		alertSet = []drillTemplateAlert{drillAlertDelivery(), drillAlertWebhookOnly()}
		expectedNames = []string{"TestFireDrillDelivery", "TestFireDrillWebhookOnly"}
	}
	drillPostAlerts(t, ctx, amPort, drillAlertSet(startedAt, alertSet))

	// REAL evidence, alertmanager-driven: telegram sends, owner chat only.
	// Log the ids immediately — every later assertion failure must leave
	// the real-message ledger in the transcript (run 2's ids were lost to
	// a late assert before the evidence write; never again).
	sends := drillWaitTelegramEvidence(t, ctx, creds, wantSends)
	t.Logf("LIVE drill: AM-driven telegram sends verified (count=%d, message_ids=%v, owner-chat-match=true)", len(sends), func() []int64 {
		ids := make([]int64, 0, len(sends))
		for _, s := range sends {
			ids = append(ids, s.MessageID)
		}
		return ids
	}())
	assertRenderedConfig(t, ctx)

	// Routing contrast: exactly wantPosts webhook posts — the critical
	// fan-outs plus the warning (default route). Combined with exactly
	// wantSends telegram sends above, the warning demonstrably stayed
	// webhook-only.
	posts := drillWaitWebhookPosts(t, ctx, capture, wantPosts)
	postedNames := map[string]int{}
	for _, p := range posts {
		postedNames[p.Alertname]++
	}
	for _, name := range expectedNames {
		if postedNames[name] != 1 {
			t.Fatalf("webhook posts for %s: got %d, want exactly 1 (counts: %v)", name, postedNames[name], postedNames)
		}
	}

	// REAL evidence, direct: the golden-format message through the same
	// client the mock battery pins.
	sent := drillDirectGoldenSend(t, ctx, creds)

	ids := make([]int64, 0, len(sends))
	for _, s := range sends {
		ids = append(ids, s.MessageID)
	}
	evidence := drillEvidence{
		Card:                 "N13-P04-T06",
		Lane:                 "imp-n05p05t06",
		Mode:                 mode,
		StartedAt:            startedAt.Format(time.RFC3339),
		FinishedAt:           time.Now().UTC().Format(time.RFC3339),
		AlertmanagerImage:    alertmanagerDrillImage,
		TelegramMessageIDs:   ids,
		DirectGoldenID:       sent.MessageID,
		OwnerChatVerified:    true,
		WebhookPosts:         len(posts),
		WarningWebhookOnly:   true,
		AMToolOK:             true,
		UnrenderedContainers: 0,
		GoldenBytes:          len(sent.Text),
		RealMessagesTotal:    len(sends) + 1,
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("marshal drill evidence: %v", err)
	}
	if err := os.WriteFile(drillEvidencePath, raw, 0o600); err != nil {
		t.Fatalf("write drill evidence: %v", err)
	}

	t.Logf("LIVE drill evidence: mode=%s alertmanager telegram sends=%d message_ids=%v owner-chat-verified=true", mode, len(ids), ids)
	t.Logf("LIVE drill evidence: warning stayed webhook-only (webhook_posts=%d incl. TestFireDrillWebhookOnly; telegram sends stay %d)", len(posts), len(ids))
	t.Logf("LIVE drill evidence: amtool check-config OK, unrendered placeholders=0")
	t.Logf("LIVE drill evidence: direct golden send message_id=%d text_bytes=%d echo==unescaped-golden=true", sent.MessageID, len(sent.Text))
	t.Logf("LIVE drill evidence: real_messages_total=%d (budget ≤5), evidence JSON at %s", evidence.RealMessagesTotal, drillEvidencePath)
}
