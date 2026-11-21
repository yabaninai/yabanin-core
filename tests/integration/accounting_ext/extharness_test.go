//go:build integration

package accountingext

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// extStand mirrors the production clean-install topology from
// deploy/quickstart (compose ordering, owner/app role split) with two seeded
// tenant orgs, and adds loggerd stop/start for lost-ACK recovery cases.
//
// Ordering (production): pg+redis up -> migrate(owner) -> bootstrap app role
// (deploy/quickstart/bootstrap-app-role.sql, owner, one-shot) -> seed each org
// (owner login; API keys printed once) -> loggerd+gateway on the app-role DSN.
// No product process ever uses a superuser connection; the oracle's owner
// connection exists for observation/injection only (DR-drill parity).

const (
	pgOwnerUser = "yabanin"
	pgOwnerPass = "yabanin"
	pgDatabase  = "yabanin"
	pgAppUser   = "yabanin_app"
	pgAppPass   = "yabanin_app"

	pgImage = "pgvector/pgvector:pg16@sha256:0dd3149a06e4579a0d70d8fef9945636cd514005e7237deb27f9b67886f8dc4f"
	//nolint:gosec // acceptance-test fixture credential, not a secret.
	redisImage = "redis:7.2-alpine@sha256:2f66de68111e64c3927859f158f8e666066dae2b97d9f82770a6f37a5aa1c335"

	modelA = "acceptance-ext-a"
	modelB = "acceptance-ext-b"

	pollEvery = 2 * time.Second
)

type extStand struct {
	t *testing.T

	runID  string
	tmpDir string
	binDir string
	owner  *sql.DB

	pgHost string
	pgPort string
	redis  string

	appDSN  string
	fixture *providerFixture

	gwBaseURL  string
	loggerdURL string

	// process handles (nil when stopped)
	gwCmd      *exec.Cmd
	loggerdCmd *exec.Cmd

	apiKeyA string
	orgIDA  string
	apiKeyB string
	orgIDB  string

	gwEnv      []string
	loggerdEnv []string

	containerNames []string
}

var extRunCounter int64

func startExtStand(t *testing.T) *extStand {
	t.Helper()
	runID := fmt.Sprintf("accext%d-%d", time.Now().UnixNano(), atomic.AddInt64(&extRunCounter, 1))
	s := &extStand{
		t:      t,
		runID:  runID,
		tmpDir: filepath.Join("/tmp", "yabanin-accounting-ext", runID),
	}
	if err := os.MkdirAll(s.tmpDir, 0o750); err != nil {
		t.Fatalf("stand: tmpdir: %v", err)
	}
	s.buildBinaries(t)
	s.startPostgres(t)
	s.startRedis(t)
	s.migrate(t)
	s.bootstrapAppRole(t)
	s.verifyAppRoleLogin(t)
	s.apiKeyA, s.orgIDA = s.seedOrg(t, "acceptance-ext-org-a", "admin-a@"+runID+".test", modelA)
	s.apiKeyB, s.orgIDB = s.seedOrg(t, "acceptance-ext-org-b", "admin-b@"+runID+".test", modelB)
	s.insertPricing(t, modelA)
	s.insertPricing(t, modelB)
	s.fixture = newProviderFixture(t)

	s.appDSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgAppUser, pgAppPass, s.pgHost, s.pgPort, pgDatabase)
	s.gwEnv = s.baseAppEnv()
	s.loggerdEnv = s.baseAppEnv()

	s.startLoggerdProcess(t)
	s.startGatewayProcess(t)

	t.Cleanup(func() {
		s.stopProcess(&s.gwCmd, false)
		s.stopProcess(&s.loggerdCmd, false)
		_ = s.owner.Close()
		for _, name := range s.containerNames {
			_ = exec.Command("docker", "rm", "-f", name).Run()
		}
	})
	return s
}

// ---------- infrastructure ----------

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeport: %v", err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

func (s *extStand) buildBinaries(t *testing.T) {
	t.Helper()
	s.binDir = filepath.Join(s.tmpDir, "bin")
	if err := os.MkdirAll(s.binDir, 0o750); err != nil {
		t.Fatalf("stand: bindir: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(s.binDir, "yabanin"), "./services/run")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stand: build services/run: %v\n%s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("stand: wd: %v", err)
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(wd))) // tests/integration/accounting_ext -> root
}

func (s *extStand) startPostgres(t *testing.T) {
	t.Helper()
	name := "accext-" + s.runID + "-pg"
	s.pgPort = freePort(t)
	s.containerNames = append(s.containerNames, name)
	if out, err := exec.Command("docker", "run", "-d", "--name", name,
		"-e", "POSTGRES_USER="+pgOwnerUser,
		"-e", "POSTGRES_PASSWORD="+pgOwnerPass,
		"-e", "POSTGRES_DB="+pgDatabase,
		"-p", s.pgPort+":5432", pgImage).CombinedOutput(); err != nil {
		t.Fatalf("stand: postgres start: %v\n%s", err, out)
	}
	s.pgHost = "127.0.0.1"
	ownerDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgOwnerUser, pgOwnerPass, s.pgHost, s.pgPort, pgDatabase)
	deadline := time.Now().Add(60 * time.Second)
	for {
		db, err := sql.Open("pgx", ownerDSN)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = db.PingContext(ctx)
			cancel()
			if err == nil {
				s.owner = db
				return
			}
			_ = db.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("stand: postgres never became ready: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *extStand) startRedis(t *testing.T) {
	t.Helper()
	name := "accext-" + s.runID + "-redis"
	port := freePort(t)
	s.containerNames = append(s.containerNames, name)
	if out, err := exec.Command("docker", "run", "-d", "--name", name,
		"-p", port+":6379", redisImage).CombinedOutput(); err != nil {
		t.Fatalf("stand: redis start: %v\n%s", err, out)
	}
	s.redis = "127.0.0.1:" + port
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", s.redis, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stand: redis never became ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (s *extStand) ownerDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgOwnerUser, pgOwnerPass, s.pgHost, s.pgPort, pgDatabase)
}

func (s *extStand) runProduct(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(s.binDir, "yabanin"), args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("stand: yabanin %s: %v\n%s", args[0], err, out.String())
	}
	return out.String()
}

func (s *extStand) migrate(t *testing.T) {
	t.Helper()
	s.runProduct(t, nil, "migrate", "--dsn", s.ownerDSN())
}

// splitSQLStatements splits the production bootstrap SQL on ';' boundaries,
// honoring dollar-quoted blocks ($$...$$) so DO blocks stay whole.
func splitSQLStatements(sqlText string) []string {
	var stmts []string
	var cur strings.Builder
	inDollar := false
	i := 0
	for i < len(sqlText) {
		if !inDollar && strings.HasPrefix(sqlText[i:], "$$") {
			inDollar = true
			cur.WriteString("$$")
			i += 2
			continue
		}
		if inDollar && strings.HasPrefix(sqlText[i:], "$$") {
			inDollar = false
			cur.WriteString("$$")
			i += 2
			continue
		}
		c := sqlText[i]
		cur.WriteByte(c)
		if c == ';' && !inDollar {
			stmts = append(stmts, cur.String())
			cur.Reset()
		}
		i++
	}
	if strings.TrimSpace(cur.String()) != "" {
		stmts = append(stmts, cur.String())
	}
	return stmts
}

func (s *extStand) bootstrapAppRole(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "quickstart", "bootstrap-app-role.sql"))
	if err != nil {
		t.Fatalf("stand: read bootstrap-app-role.sql: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, stmt := range splitSQLStatements(string(raw)) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := s.owner.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("stand: bootstrap-app-role statement failed: %v\nstatement: %s", err, stmt)
		}
	}
}

// verifyAppRoleLogin proves the app role is a working non-superuser login
// before any product process uses it.
func (s *extStand) verifyAppRoleLogin(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgAppUser, pgAppPass, s.pgHost, s.pgPort, pgDatabase)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("app role login: open: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user string
	var super bool
	if err := db.QueryRowContext(ctx, "SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&user, &super); err != nil {
		t.Fatalf("app role login: identity probe: %v", err)
	}
	if user != pgAppUser || super {
		t.Fatalf("app role login: current_user=%s super=%v, want %s non-superuser", user, super, pgAppUser)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM organizations").Scan(&n); err != nil {
		t.Fatalf("app role login: schema read probe: %v", err)
	}
	t.Logf("app role verified: %s (non-superuser) can read schema (%d orgs at verify time)", user, n)
}

func (s *extStand) seedOrg(t *testing.T, orgName, adminEmail, model string) (apiKey, orgID string) {
	t.Helper()
	keyFile := filepath.Join(s.tmpDir, "upstream-"+model+".key")
	if err := os.WriteFile(keyFile, []byte("fixture-upstream-key"), 0o600); err != nil {
		t.Fatalf("seed %s: upstream key file: %v", orgName, err)
	}
	cmd := exec.Command(filepath.Join(s.binDir, "yabanin"), "seed",
		"--profile", "provider",
		"--admin-email", adminEmail,
		"--admin-password-stdin",
		"--upstream-url", s.fixture.URL(),
		"--upstream-key-file", keyFile,
		"--model", model,
		"--org-name", orgName)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(),
		"YABANIN_PG_URI="+s.ownerDSN(),
		"YABANIN_ADMIN_SEED_PASSWORD=acceptance-admin-password")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = bytes.NewReader([]byte("acceptance-admin-password\n"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("seed %s: %v\n%s", orgName, err, out.String())
	}
	const marker = "API key (shown once, store it now): "
	for _, line := range strings.Split(out.String(), "\n") {
		if idx := strings.Index(line, marker); idx >= 0 {
			apiKey = strings.TrimSpace(line[idx+len(marker):])
			break
		}
	}
	if apiKey == "" {
		t.Fatalf("seed %s: no API key in seed output:\n%s", orgName, out.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.owner.QueryRowContext(ctx,
		`SELECT id::text FROM organizations WHERE name = $1`, orgName).Scan(&orgID); err != nil {
		t.Fatalf("seed %s: resolve org id: %v", orgName, err)
	}
	t.Logf("seeded %s: org=%s", orgName, orgID)
	return apiKey, orgID
}

func (s *extStand) insertPricing(t *testing.T, model string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.owner.ExecContext(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source)
		VALUES ('openai-compat', $1, 2.0, 6.0, 'manual')`, model); err != nil {
		t.Fatalf("pricing insert for %s: %v", model, err)
	}
}

// ---------- product processes ----------

func (s *extStand) randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func (s *extStand) baseAppEnv() []string {
	key := s.randHex(s.t, 32) // 64 hex chars
	return []string{
		"YABANIN_PG_URI=" + s.appDSN,
		"YABANIN_REDIS_ADDR=" + s.redis,
		"YABANIN_ENCRYPTION_KEY=" + key,
		"YABANIN_CACHE_HMAC_SECRET=" + key,
		"YABANIN_AUTH_MODE=header",
		"YABANIN_PROVIDER_ADDR=" + s.fixture.URL(),
		"YABANIN_REGION=test",
		"YABANIN_LOG_LEVEL=debug",
		"YABANIN_LOG_FORMAT=json",
		"YABANIN_EVENT_STREAM=yabanin:events",
	}
}

func (s *extStand) startLoggerdProcess(t *testing.T) {
	t.Helper()
	if s.loggerdCmd != nil {
		t.Fatalf("loggerd already running")
	}
	port := freePort(t)
	logPath := filepath.Join(s.tmpDir, fmt.Sprintf("loggerd-%d.log", time.Now().Unix()))
	env := append(append([]string{}, s.loggerdEnv...), "YABANIN_LOGGERD_LISTEN=127.0.0.1:"+port)
	cmd := exec.Command(filepath.Join(s.binDir, "yabanin"), "loggerd")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	s.spawnWithLog(cmd, logPath)
	s.loggerdCmd = cmd
	s.loggerdURL = "http://127.0.0.1:" + port
}

func (s *extStand) startGatewayProcess(t *testing.T) {
	t.Helper()
	if s.gwCmd != nil {
		t.Fatalf("gateway already running")
	}
	port := freePort(t)
	logPath := filepath.Join(s.tmpDir, fmt.Sprintf("gateway-%d.log", time.Now().Unix()))
	env := append(append([]string{}, s.gwEnv...), "YABANIN_GATEWAY_LISTEN=127.0.0.1:"+port)
	cmd := exec.Command(filepath.Join(s.binDir, "yabanin"), "gateway")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	s.spawnWithLog(cmd, logPath)
	s.gwCmd = cmd
	s.gwBaseURL = "http://127.0.0.1:" + port
}

func (s *extStand) spawnWithLog(cmd *exec.Cmd, logPath string) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		s.t.Fatalf("spawn %s: log file: %v", cmd.Args, err)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		f.Close()
		s.t.Fatalf("spawn %s: %v", cmd.Args, err)
	}
	go func() { _ = cmd.Wait(); _ = f.Close() }()
	s.t.Logf("spawned %s (pid %d, log %s)", cmd.Args, cmd.Process.Pid, logPath)
}

// stopProcess terminates a product process; kill=true uses SIGKILL (crash
// semantics: no shutdown hooks, no flush).
func (s *extStand) stopProcess(p **exec.Cmd, kill bool) {
	cmd := *p
	if cmd == nil || cmd.Process == nil {
		*p = nil
		return
	}
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	_ = cmd.Process.Signal(sig)
	if !kill {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if cmd.ProcessState != nil {
				break
			}
			// ProcessState is only set after Wait returns; poll signalability.
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if cmd.ProcessState == nil {
			_ = cmd.Process.Signal(syscall.SIGKILL)
		}
	}
	*p = nil
}

func (s *extStand) killGateway(t *testing.T) {
	t.Helper()
	s.stopProcess(&s.gwCmd, true)
	t.Logf("gateway SIGKILLed (crash semantics)")
}

func (s *extStand) restartGateway(t *testing.T) {
	t.Helper()
	s.stopProcess(&s.gwCmd, false)
	s.startGatewayProcess(t)
	s.waitGatewayHealthy(t)
}

func (s *extStand) stopLoggerd(t *testing.T) {
	t.Helper()
	s.stopProcess(&s.loggerdCmd, false)
	t.Logf("loggerd stopped (TERM)")
}

func (s *extStand) startLoggerd(t *testing.T) {
	t.Helper()
	s.startLoggerdProcess(t)
}

func (s *extStand) waitGatewayHealthy(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(s.gwBaseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("gateway did not become healthy at %s", s.gwBaseURL)
}

// ---------- client ----------

type chatResult struct {
	StatusCode int
	Body       []byte // buffered: full JSON; streamed: nil
	Content    string
	Usage      *chatUsage
	Err        error
}

// chatFor issues one chat completion through the gateway for a given tenant
// key/model, buffered or SSE-streamed. The returned error (if any) is a
// transport-level failure; HTTP status and body are always populated when a
// response arrived.
func (s *extStand) chatFor(ctx context.Context, apiKey, model, rid string, stream bool) chatResult {
	payload := chatRequest{
		Model:    model,
		Stream:   stream,
		Messages: []chatMessage{{Role: "user", Content: "Say Hi"}},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.gwBaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return chatResult{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Request-ID", rid)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return chatResult{Err: err}
	}
	defer resp.Body.Close()
	res := chatResult{StatusCode: resp.StatusCode}
	if !stream {
		res.Body, _ = io.ReadAll(resp.Body)
		var cr chatResponse
		if json.Unmarshal(res.Body, &cr) == nil && len(cr.Choices) > 0 {
			res.Content = cr.Choices[0].Message.Content
			u := cr.Usage
			res.Usage = &u
		}
		return res
	}
	// SSE: accumulate deltas; require exactly one usage-bearing chunk
	// before [DONE].
	var content strings.Builder
	usageChunks := 0
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 512)
	for {
		n, rerr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := bytes.IndexByte(buf, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimSpace(string(buf[:idx]))
				buf = buf[idx+1:]
				if line == "" {
					continue
				}
				data, ok := stripDataPrefix(line)
				if !ok {
					continue
				}
				if data == "[DONE]" {
					res.Content = content.String()
					if usageChunks != 1 {
						res.Err = fmt.Errorf("stream: %d usage chunks, want exactly 1", usageChunks)
					}
					return res
				}
				var c chatChunk
				if json.Unmarshal([]byte(data), &c) == nil {
					for _, ch := range c.Choices {
						content.WriteString(ch.Delta.Content)
					}
					if c.Usage != nil {
						usageChunks++
						u := *c.Usage
						res.Usage = &u
					}
				}
			}
		}
		if rerr != nil {
			res.Content = content.String()
			res.Err = fmt.Errorf("stream ended before [DONE]: %w (usage chunks=%d)", rerr, usageChunks)
			return res
		}
	}
}

func (s *extStand) chat(ctx context.Context, rid string, stream bool) chatResult {
	return s.chatFor(ctx, s.apiKeyA, modelA, rid, stream)
}

// controlRequest is a healthy paid request proving end-to-end chargeability:
// response, ledger delta 1/1/1, billed row, exactly one signed wallet debit.
func (s *extStand) controlRequest(t *testing.T, label string, apiKey, model, orgID string, stream bool) chatResult {
	t.Helper()
	rid := "control-" + label + "-" + s.runID
	before := s.fixture.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := s.chatFor(ctx, apiKey, model, rid, stream)
	if res.Err != nil {
		t.Fatalf("control %s: client error: %v", label, res.Err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("control %s: status %d, want 200", label, res.StatusCode)
	}
	if res.Usage == nil || res.Usage.PromptTokens != extPromptTokens || res.Usage.CompletionTokens != extCompletionTokens {
		t.Fatalf("control %s: usage = %+v, want %d/%d", label, res.Usage, extPromptTokens, extCompletionTokens)
	}
	if res.Content != "Hi" {
		t.Fatalf("control %s: content %q, want %q", label, res.Content, "Hi")
	}
	dArr, dDisp, dRecv := s.fixture.Since(before)
	if dArr != 1 || dDisp != 1 || dRecv != 1 {
		t.Fatalf("control %s: provider ledger delta arr/disp/recv = %d/%d/%d, want 1/1/1", label, dArr, dDisp, dRecv)
	}
	s.fixture.VerifyEvidence(t, rid, stream)
	s.requireBilledRow(t, orgID, rid, "control "+label)
	s.requireWalletChargedExactlyOnce(t, orgID, rid, extCostMicroUSD, "control "+label)
	t.Logf("control %s (%s): billed + wallet charged exactly once (-%d micro-USD)",
		label, modeName(stream), extCostMicroUSD)
	return res
}

func modeName(stream bool) string {
	if stream {
		return "streamed"
	}
	return "buffered"
}
