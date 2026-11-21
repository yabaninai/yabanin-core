//go:build integration

package accounting

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver (oracle + app-role checks)
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// Stand topology. Every acceptance test in this package drives the real
// product only through its published surfaces: the yabanin binary built
// from this worktree, its gateway HTTP API, PostgreSQL and Redis as real
// containers, and a controllable provider fixture standing in for the
// external model provider. The fixture's ledgers and read-only database
// queries are the independent oracles; nothing is inferred from the
// gateway's own response content beyond the documented client contract.
//
// The database posture mirrors the production clean-install entrypoint
// (deploy/quickstart/docker-compose.yml) exactly: the container runs with
// the yabanin owner login, migrations and seed run on the owner login (the
// controlled-elevation path), the yabanin_app role is bootstrapped from
// the production bootstrap-app-role.sql after migrations, and only the
// long-running product processes (gateway, loggerd) connect as the
// non-owner, non-superuser yabanin_app login with forced row-level
// security in effect. No product process ever runs on a superuser
// connection.
//
// Prerequisites are not skippable: a missing Docker daemon, unbuildable
// binary or unseedable stand is a reported failure, never a green skip.
const (
	// Pinned to the quickstart stand's digests so the acceptance
	// environment matches the documented deployment environment.
	pgImage    = "pgvector/pgvector:pg16@sha256:0dd3149a06e4579a0d70d8fef9945636cd514005e7237deb27f9b67886f8dc4f"
	redisImage = "redis:7.2-alpine@sha256:2f66de68111e64c3927859f158f8e666066dae2b97d9f82770a6f37a5aa1c335"

	// Production role topology from the quickstart stack.
	pgOwnerUser = "yabanin"
	pgOwnerPass = "yabanin"
	pgDatabase  = "yabanin"
	pgAppUser   = "yabanin_app"
	pgAppPass   = "yabanin_app"
)

// stand is one isolated run of the real product. Every stand owns a unique
// run id that namespaces its temp directory, Redis stream, organization
// name and request ids, so concurrent or repeated runs cannot observe each
// other's state.
type stand struct {
	t *testing.T

	runID     string
	reqPrefix string
	tempDir   string

	pg        *testpostgres.PostgresContainer
	ownerDSN  string // owner login: migrate, seed, oracle (fault injection)
	appDSN    string // yabanin_app login: gateway, loggerd only
	redis     *testredis.RedisContainer
	redisAddr string

	oracleDB *oracle

	binary     string
	gatewayURL string
	apiKey     string
	orgName    string
	model      string

	// Operator-installed per-million rates for the seeded model. Billed
	// rows are validated against these known inputs and the fixture's
	// fixed usage, never against gateway-reported values.
	pricingInputPerM  float64
	pricingOutputPerM float64

	fixture    *fixture
	fixtureTok string

	gatewayCmd *exec.Cmd
	loggerdCmd *exec.Cmd

	gatewayEnv []string
	loggerdEnv []string
}

// newRunID mints a collision-free run identifier.
func newRunID(t *testing.T) string {
	t.Helper()
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("harness: run id entropy: %v", err)
	}
	return fmt.Sprintf("acc-%d-%s", time.Now().UnixNano(), hex.EncodeToString(raw[:]))
}

// freePort reserves a loopback TCP port for a child process.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("harness: reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("harness: release reserved port: %v", err)
	}
	return port
}

// repoRoot locates the product module root from this test package's
// directory. The test binary always runs with its working directory set to
// the package source directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("harness: getwd: %v", err)
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(wd)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("harness: module root not found at %s: %v", root, err)
	}
	return root
}

// startStand brings the whole isolated product stand up, mirroring the
// quickstart clean-install ordering: postgres → redis → build → fixture →
// migrate (owner) → db-app-role bootstrap (owner, production SQL) → app
// role login verification → seed (owner) → pricing → loggerd + gateway
// (yabanin_app). Cleanup for each resource is registered at acquisition
// time and is nil-safe, so a failure partway through releases exactly what
// this stand already acquired. Any failure inside is a harness failure
// (the product has not been asked anything yet); all fatal errors here
// carry the "harness:" prefix.
func startStand(t *testing.T) *stand {
	t.Helper()

	s := &stand{t: t}
	s.runID = newRunID(t)
	s.reqPrefix = s.runID + "-req-"
	s.orgName = "acc-org-" + s.runID
	s.model = "acc-model-" + s.runID
	s.pricingInputPerM = 2.0
	s.pricingOutputPerM = 6.0

	// Runtime temp outside every Git worktree: the acceptance standard
	// requires that repository metadata is not discoverable from the
	// stand's directories.
	base := os.Getenv("YABANIN_ACC_TMP")
	if base == "" {
		base = filepath.Join(os.TempDir(), "yabanin-accounting")
	}
	s.tempDir = filepath.Join(base, s.runID)
	if err := os.MkdirAll(s.tempDir, 0o750); err != nil {
		t.Fatalf("harness: temp dir: %v", err)
	}
	if err := exec.Command("git", "-C", s.tempDir, "rev-parse", "--show-toplevel").Run(); err == nil {
		t.Fatalf("harness: temp dir %s unexpectedly resolves as a Git worktree", s.tempDir)
	}
	t.Logf("harness: run %s temp dir %s", s.runID, s.tempDir)

	ctx := context.Background()

	// Real PostgreSQL with the quickstart's owner credentials, pinned to
	// the quickstart digest.
	pg, err := testpostgres.Run(ctx, pgImage,
		testpostgres.WithDatabase(pgDatabase),
		testpostgres.WithUsername(pgOwnerUser),
		testpostgres.WithPassword(pgOwnerPass),
	)
	if err != nil {
		t.Fatalf("harness: postgres container (Docker must be running; a missing prerequisite is a failure, not a skip): %v", err)
	}
	s.pg = pg
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = pg.Terminate(cctx)
	})
	pgHost, err := pg.Host(ctx)
	if err != nil {
		t.Fatalf("harness: postgres host: %v", err)
	}
	pgPort, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("harness: postgres port: %v", err)
	}
	pgHostPort := net.JoinHostPort(pgHost, pgPort.Port())
	s.ownerDSN = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgOwnerUser, pgOwnerPass, pgHostPort, pgDatabase)
	s.appDSN = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgAppUser, pgAppPass, pgHostPort, pgDatabase)

	// Real Redis, pinned to the quickstart digest.
	rd, err := testredis.Run(ctx, redisImage)
	if err != nil {
		t.Fatalf("harness: redis container: %v", err)
	}
	s.redis = rd
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = rd.Terminate(cctx)
	})
	rdHost, err := rd.Host(ctx)
	if err != nil {
		t.Fatalf("harness: redis host: %v", err)
	}
	rdPort, err := rd.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("harness: redis port: %v", err)
	}
	s.redisAddr = net.JoinHostPort(rdHost, rdPort.Port())

	// The actual product binary, built from this worktree.
	root := repoRoot(t)
	s.binary = filepath.Join(s.tempDir, "bin", "yabanin")
	if err := os.MkdirAll(filepath.Dir(s.binary), 0o750); err != nil {
		t.Fatalf("harness: bin dir: %v", err)
	}
	build := exec.Command("go", "build", "-o", s.binary, "./cmd/yabanin")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("harness: build product binary: %v\n%s", err, out)
	}

	// Controllable provider fixture and its bearer token.
	tokRaw := make([]byte, 18)
	if _, err := rand.Read(tokRaw[:]); err != nil {
		t.Fatalf("harness: fixture token entropy: %v", err)
	}
	s.fixtureTok = hex.EncodeToString(tokRaw)
	s.fixture = startFixture(t, s.tempDir, s.fixtureTok)
	t.Cleanup(s.fixture.stop)

	// 32-byte hex encryption key for the seeded provider credential.
	keyRaw := make([]byte, 32)
	if _, err := rand.Read(keyRaw[:]); err != nil {
		t.Fatalf("harness: encryption key entropy: %v", err)
	}
	encKey := hex.EncodeToString(keyRaw)

	// Owner login env: used by migrate and seed exactly like the
	// quickstart's one-shot services (the controlled-elevation path).
	ownerEnv := []string{
		"YABANIN_PG_URI=" + s.ownerDSN,
		"YABANIN_REDIS_ADDR=" + s.redisAddr,
		"YABANIN_ENCRYPTION_KEY=" + encKey,
		"YABANIN_REGION=test",
	}
	// yabanin_app login env: used only by the long-running product
	// processes. This connection is non-owner and non-superuser, with
	// forced row-level security in effect — the production app posture.
	appEnv := []string{
		"YABANIN_PG_URI=" + s.appDSN,
		"YABANIN_REDIS_ADDR=" + s.redisAddr,
		"YABANIN_ENCRYPTION_KEY=" + encKey,
		"YABANIN_REGION=test",
	}

	// The privileged observer/injector connection (same privilege class
	// as the DR drill's operator connection) opens before anything else
	// so it can apply the role bootstrap and later fault controls.
	s.oracleDB = newOracle(t, s)
	t.Cleanup(s.oracleDB.close)

	// Apply the real embedded migrations on the owner login.
	if out, err := s.runCmd(60*time.Second, ownerEnv, nil, "migrate"); err != nil {
		t.Fatalf("harness: migrate: %v\n%s", err, out)
	}

	// Bootstrap yabanin_app from the production SQL, exactly like the
	// quickstart's db-app-role one-shot that runs after migrate, then
	// prove the app role actually works before anything uses it.
	s.bootstrapAppRole(t, filepath.Join(root, "deploy", "quickstart", "bootstrap-app-role.sql"))
	s.verifyAppRoleLogin(t)

	// Seed one organization whose model routes at the fixture, then
	// install the operator-known pricing the billed-row oracle uses.
	keyFile := filepath.Join(s.tempDir, "upstream.key")
	if err := os.WriteFile(keyFile, []byte(s.fixtureTok+"\n"), 0o600); err != nil {
		t.Fatalf("harness: upstream key file: %v", err)
	}
	seedStdin := strings.NewReader("acc-admin-password-" + s.runID + "\n")
	seedOut, err := s.runCmd(120*time.Second, ownerEnv, seedStdin,
		"seed", "--profile", "provider",
		"--admin-email", "admin@"+s.runID+".test",
		"--admin-password-stdin",
		"--upstream-url", s.fixture.baseURL(),
		"--upstream-key-file", keyFile,
		"--model", s.model,
		"--org-name", s.orgName,
	)
	if err != nil {
		t.Fatalf("harness: seed: %v\n%s", err, seedOut)
	}
	for _, line := range strings.Split(string(seedOut), "\n") {
		if strings.HasPrefix(line, "API key (shown once, store it now): ") {
			s.apiKey = strings.TrimPrefix(line, "API key (shown once, store it now): ")
		}
	}
	if s.apiKey == "" {
		t.Fatalf("harness: seed output did not contain the API key:\n%s", seedOut)
	}

	// Bind the oracle to this stand's organization (after seed) and
	// install the operator-known rates for the seeded model.
	s.oracleDB.resolveOrg(t, s)
	s.oracleExec(t, "install model pricing",
		`INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source)
		 VALUES ('openai-compat', $1, $2, $3, 'manual')`,
		s.model, s.pricingInputPerM, s.pricingOutputPerM)

	// Run-unique Redis stream so this stand's event traffic is isolated.
	stream := "events:" + s.runID
	gwPort := freePort(t)
	ldPort := freePort(t)
	s.gatewayURL = fmt.Sprintf("http://127.0.0.1:%d", gwPort)
	s.gatewayEnv = append([]string{
		"YABANIN_GATEWAY_LISTEN=127.0.0.1:" + fmt.Sprint(gwPort),
		"YABANIN_AUTH_MODE=header",
		"YABANIN_PROVIDER_ADDR=" + s.fixture.baseURL(),
		"YABANIN_EVENT_STREAM=" + stream,
		"YABANIN_CACHE_HMAC_SECRET=" + hex.EncodeToString(keyRaw),
		"YABANIN_LOG_LEVEL=info",
		"YABANIN_LOG_FORMAT=text",
	}, appEnv...)
	s.loggerdEnv = append([]string{
		"YABANIN_LOGGERD_LISTEN=127.0.0.1:" + fmt.Sprint(ldPort),
		"YABANIN_LOGGERD_STREAM=" + stream,
		"YABANIN_LOGGERD_LOG_LEVEL=info",
	}, appEnv...)

	s.startLoggerd()
	s.startGateway()
	return s
}

// bootstrapAppRole applies the production quickstart role bootstrap over
// the owner connection, statement by statement (the SQL file's own
// dollar-quoted DO block is honored by the splitter). This mirrors
// deploy/quickstart/docker-compose.yml's db-app-role one-shot with
// ON_ERROR_STOP semantics: any failing statement fails the stand.
func (s *stand) bootstrapAppRole(t *testing.T, sqlPath string) {
	t.Helper()
	data, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("harness: read bootstrap-app-role.sql: %v", err)
	}
	for i, stmt := range splitSQLStatements(string(data)) {
		s.oracleExec(t, fmt.Sprintf("bootstrap-app-role statement %d", i+1), stmt)
	}
	t.Logf("harness: yabanin_app bootstrapped from production %s", filepath.Base(sqlPath))
}

// splitSQLStatements splits a SQL script on statement-terminating
// semicolons while honoring $$ dollar-quoted bodies, which may contain
// semicolons. Empty statements are dropped.
func splitSQLStatements(script string) []string {
	var stmts []string
	var cur strings.Builder
	inDollar := false
	for i := 0; i < len(script); i++ {
		if !inDollar && strings.HasPrefix(script[i:], "$$") {
			inDollar = true
			cur.WriteString("$$")
			i++
			continue
		}
		if inDollar && strings.HasPrefix(script[i:], "$$") {
			inDollar = false
			cur.WriteString("$$")
			i++
			continue
		}
		if !inDollar && script[i] == ';' {
			if stmt := strings.TrimSpace(cur.String()); stmt != "" {
				stmts = append(stmts, stmt)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(script[i])
	}
	if stmt := strings.TrimSpace(cur.String()); stmt != "" {
		stmts = append(stmts, stmt)
	}
	return stmts
}

// verifyAppRoleLogin proves the yabanin_app login works and is the
// production posture: non-superuser, able to read the migrated schema.
// The product processes later run exclusively on this connection class.
func (s *stand) verifyAppRoleLogin(t *testing.T) {
	t.Helper()
	db, err := sql.Open("pgx", s.appDSN)
	if err != nil {
		t.Fatalf("harness: app role connect: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("harness: app role ping (bootstrap incomplete): %v", err)
	}
	var user string
	var super bool
	if err := db.QueryRow(`SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&user, &super); err != nil {
		t.Fatalf("harness: app role attributes: %v", err)
	}
	if user != pgAppUser {
		t.Fatalf("harness: app login resolved to %q, want %q", user, pgAppUser)
	}
	if super {
		t.Fatalf("harness: app login %s must not be superuser", user)
	}
	var orgs int
	if err := db.QueryRow(`SELECT count(*) FROM organizations`).Scan(&orgs); err != nil {
		t.Fatalf("harness: app role schema read (grants from bootstrap): %v", err)
	}
	t.Logf("harness: app role login verified (user=%s superuser=false, organizations readable)", user)
}

// runCmd runs the product binary once and waits for it.
func (s *stand) runCmd(timeout time.Duration, env []string, stdin *strings.Reader, args ...string) ([]byte, error) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.binary, args...)
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	return cmd.CombinedOutput()
}

// startLoggerd launches the loggerd process and registers its cleanup.
func (s *stand) startLoggerd() {
	s.t.Helper()
	if s.loggerdCmd != nil {
		s.t.Fatal("harness: loggerd already running")
	}
	logFile := filepath.Join(s.tempDir, "loggerd.log")
	s.loggerdCmd = s.spawn("loggerd", s.loggerdEnv, logFile)
	t := s.t
	t.Cleanup(func() { s.stopProc("loggerd", s.loggerdCmd) })
}

// startGateway launches the gateway process, registers its cleanup, and
// waits for /healthz.
func (s *stand) startGateway() {
	s.t.Helper()
	if s.gatewayCmd != nil {
		s.t.Fatal("harness: gateway already running")
	}
	logFile := filepath.Join(s.tempDir, "gateway.log")
	s.gatewayCmd = s.spawn("gateway", s.gatewayEnv, logFile)
	t := s.t
	t.Cleanup(func() { s.stopProc("gateway", s.gatewayCmd) })
	s.waitHealthz(s.gatewayCmd, logFile)
}

// spawn starts one product subcommand with stdout/stderr captured to a log
// file under the stand temp dir.
func (s *stand) spawn(sub string, env []string, logFile string) *exec.Cmd {
	s.t.Helper()
	logFH, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		s.t.Fatalf("harness: open %s log: %v", sub, err)
	}
	cmd := exec.Command(s.binary, sub)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = logFH
	cmd.Stderr = logFH
	if err := cmd.Start(); err != nil {
		logFH.Close()
		s.t.Fatalf("harness: start %s: %v", sub, err)
	}
	s.t.Logf("harness: %s started (pid %d, log %s)", sub, cmd.Process.Pid, logFile)
	return cmd
}

// stopProc terminates one product child process nil-safely, escalating to
// SIGKILL after a grace period.
func (s *stand) stopProc(sub string, cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Signal(syscall.SIGKILL)
		<-done
	}
}

// waitHealthz polls the gateway's readiness endpoint, failing with the
// process log on timeout.
func (s *stand) waitHealthz(cmd *exec.Cmd, logFile string) {
	s.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := cmdProcessAlive(cmd); err != nil {
			s.dumpLog(logFile)
			s.t.Fatalf("harness: gateway exited during startup: %v", err)
		}
		resp, err := httpGet(2*time.Second, s.gatewayURL+"/healthz")
		if err == nil && resp.StatusCode == httpOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.dumpLog(logFile)
	s.t.Fatalf("harness: gateway never became healthy at %s", s.gatewayURL)
}

// dumpLog prints a captured process log for harness diagnosis.
func (s *stand) dumpLog(logFile string) {
	s.t.Helper()
	if data, err := os.ReadFile(logFile); err == nil {
		s.t.Logf("harness: --- %s ---\n%s", logFile, data)
	}
}

// killGatewaySIGKILL terminates only the gateway process. loggerd, the
// fixture, PostgreSQL and Redis keep running — the crash is scoped to the
// stateless process exactly as the acceptance case requires.
func (s *stand) killGatewaySIGKILL() {
	s.t.Helper()
	cmd := s.gatewayCmd
	if cmd == nil || cmd.Process == nil {
		s.t.Fatal("harness: gateway not running")
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		s.t.Fatalf("harness: kill gateway: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.t.Fatal("harness: gateway did not exit after SIGKILL")
	}
	s.gatewayCmd = nil
	s.t.Logf("harness: gateway killed; storage and loggerd untouched")
}

// restartGateway starts a fresh gateway process against the same storage
// and waits for readiness.
func (s *stand) restartGateway() {
	s.t.Helper()
	if s.gatewayCmd != nil {
		s.t.Fatal("harness: gateway still running")
	}
	s.startGateway()
}

// chat sends one authenticated chat completion through the gateway. The
// request id is run-namespaced for ledger/database filtering; window-level
// provider-contact detection uses whole-ledger totals, not this id.
func (s *stand) chat(t *testing.T, rid string, timeout time.Duration) (status int, body string, err error) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"accounting acceptance probe"}]}`, s.model)
	return httpPostJSON(timeout, s.gatewayURL+"/v1/chat/completions", s.apiKey, rid, payload)
}

// controlRequest issues a healthy control request through the same
// credentials, route and provider and asserts the full round trip: client
// response, exactly one whole-ledger provider contact (arrival, dispatch
// and receipt), retained evidence, and a durable billed row matching the
// independently known usage and rates. It is the harness-validity oracle
// used around every injected fault — and it doubles as the standing proof
// that both detectors (fixture ledger, database oracle) see real traffic,
// so a later absence cannot be excused as a blind harness.
func (s *stand) controlRequest(t *testing.T, label string) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := s.reqPrefix + "ctl-" + label
	status, body, err := s.chat(t, rid, 30*time.Second)
	if err != nil || status != httpOK {
		t.Fatalf("harness: control request %s failed (status=%d err=%v body=%s): stand or fault restoration is broken, product assertions below would be meaningless", label, status, err, body)
	}
	if !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("harness: control request %s: unexpected body %q", label, body)
	}
	s.fixture.VerifyEvidence()
	delta := s.fixture.Since(before)
	if delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		a, d, r := s.fixture.Counts(rid)
		t.Fatalf("harness: control %s: whole-ledger delta arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1 (id-matched %d/%d/%d); the provider-contact detector itself must be proven by a passing control before any fault window",
			label, delta.arrivals, delta.dispatches, delta.receipts, a, d, r)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid) == 1
	}, "harness: control request %s never became durable in request_logs", label)
	s.requireBilledRow(t, rid, "harness: control "+label)
	t.Logf("harness: control %s ok (request id %s)", label, rid)
}

// requireEventually polls cond until deadline, failing with format/args on
// timeout.
func requireEventually(t *testing.T, d time.Duration, interval time.Duration, cond func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf(msg, args...)
}

// cmdProcessAlive reports whether the child has not exited yet.
func cmdProcessAlive(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return fmt.Errorf("no process")
	}
	return cmd.Process.Signal(syscall.Signal(0))
}
