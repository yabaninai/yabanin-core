//go:build integration

package accounting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestWalletAdmissionFloorWire is the wire-level §8 admission contract: the
// per-org grace floor a ROOT ADMIN types into the real admin HTTP API (real
// admin process, real adminstore persistence, journalled mutation) must
// reach the real charged gateway admission path for the same org without
// any restart or in-process invalidation, and the release must restore
// paid service on the very next request.
//
// Scenario, in full production topology (gateway, loggerd AND admin are
// distinct product processes over one database):
//
//  1. Read-back baseline through the admin API: the seeded org has no
//     explicit floor and sits on the platform default (−$1.00).
//  2. Harness arrangement: the wallet sits at −50 cents (the seed itself
//     arranges opening balances with owner-login SQL, and so does this
//     step; verified by read-back). Rates stay the operator-installed
//     2.0/6.0 per M, so every real charge is the known 32 µUSD residue.
//  3. Prime: one real paid chat request arrives once at the provider and
//     really charges the negative wallet (still above the platform floor).
//  4. Typed PUT {grace_floor_cents: 0, reason} → 200: production
//     persistence (adminstore, audit journal), read-back confirms 0.
//  5. The immediate next paid request is refused 402 insufficient_credits
//     with the fresh wallet echoed, the provider is contacted zero times,
//     and nothing is recorded or charged for the refused request.
//  6. Typed PUT null (the documented reset to the platform default) → 200.
//  7. The next paid request on the same credentials/route arrives exactly
//     once, really charges, and becomes durable.
//
// Nothing here inspects product memory or calls product test hooks: the
// only product surfaces are the gateway chat API and the admin console API
// of three separately started processes, plus the owner-login SQL oracle
// for independent evidence.
func TestWalletAdmissionFloorWire(t *testing.T) {
	s := startStand(t)
	adminURL := s.startAdminService(t)
	sess := adminLogin(t, s, adminURL)
	orgID := s.oracleDB.orgID

	// Baseline read-back through the real admin API: no explicit floor,
	// platform default −$1.00 in effect.
	base := sess.getBudgetSettings(t, orgID)
	if base.GraceFloorCents != nil {
		t.Fatalf("product: seeded org must start without an explicit floor, got %d", *base.GraceFloorCents)
	}
	if base.EffectiveGraceFloorCents != -100 {
		t.Fatalf("product: seeded org effective floor %d, want the platform default -100", base.EffectiveGraceFloorCents)
	}

	// Harness arrangement (owner-login SQL, seed-style): wallet at −50c so
	// the typed zero floor can tighten past it. Verified by read-back.
	s.oracleExec(t, "arrange wallet at -50 cents",
		`UPDATE org_credits SET balance_cents = -50, remainder_micro_usd = 0 WHERE org_id = $1`, orgID)
	w := s.oracleWallet(t, orgID)
	if w.balance != -50 || w.remainder != 0 || w.floor != nil {
		t.Fatalf("harness: wallet arrangement read-back balance/remainder/floor = %d/%d/%v, want -50/0/<nil>", w.balance, w.remainder, w.floor)
	}

	// Prime: one real paid request is served and really charges the wallet.
	// At the known rates the 32 µUSD cost is pure sub-cent residue, so the
	// raw balance must stay −50 while the remainder accrues to exactly 32.
	before := s.fixture.Snapshot()
	rid := s.reqPrefix + "prime"
	status, body, err := s.chat(t, rid, 45*time.Second)
	if err != nil || status != httpOK {
		t.Fatalf("product: prime request failed (status=%d err=%v body=%s) — the negative wallet above the platform floor must admit", status, err, body)
	}
	if delta := s.fixture.Since(before); delta != (fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}) {
		t.Fatalf("product: prime request provider contact arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, orgID) == 1
	}, "product: prime request never became durable in request_logs")
	s.requireBilledRow(t, rid, orgID, "product: prime")
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		w := s.oracleWallet(t, orgID)
		return w.balance == -50 && w.remainder == 32
	}, "product: prime charge never settled into the wallet (want balance −50, remainder 32 µUSD)")

	// Typed floor mutation through the real admin API: explicit zero,
	// production persistence, mandatory reason, echoed effective floor.
	put := sess.putGraceFloor(t, orgID, int64Ptr(0), "wire: forbid overdraft for this org")
	if put.GraceFloorCents == nil || *put.GraceFloorCents != 0 || put.EffectiveGraceFloorCents != 0 {
		t.Fatalf("product: floor PUT echoed saved/effective %v/%d, want 0/0",
			put.GraceFloorCents, put.EffectiveGraceFloorCents)
	}
	after := sess.getBudgetSettings(t, orgID)
	if after.GraceFloorCents == nil || *after.GraceFloorCents != 0 || after.EffectiveGraceFloorCents != 0 {
		t.Fatalf("product: floor read-back saved/effective %v/%d, want 0/0",
			after.GraceFloorCents, after.EffectiveGraceFloorCents)
	}
	if w := s.oracleWallet(t, orgID); w.floor == nil || *w.floor != 0 {
		t.Fatalf("product: persisted grace_floor_cents after PUT = %v, want 0 (production persistence)", w.floor)
	}

	// The immediate next paid request must be refused on the authoritative
	// path: 402 insufficient_credits echoing the fresh wallet (−50 − ceil
	// residue → −51 effective cents), zero provider contact, and nothing
	// recorded or charged for the refused request.
	before = s.fixture.Snapshot()
	ridDenied := s.reqPrefix + "denied"
	status, body, err = s.chat(t, ridDenied, 45*time.Second)
	if err != nil {
		t.Fatalf("product: refused request: client transport error %v — the denial must be the documented 402 contract, not a drop", err)
	}
	if status != http.StatusPaymentRequired {
		t.Fatalf("product: request under the tightened floor: client status %d, want 402 (body %s)", status, clip(body))
	}
	var denied struct {
		Error        string `json:"error"`
		BalanceCents int64  `json:"balance_cents"`
	}
	if err := json.Unmarshal([]byte(body), &denied); err != nil || denied.Error != "insufficient_credits" {
		t.Fatalf("product: 402 body is not the documented insufficient_credits contract (body %s, err %v)", clip(body), err)
	}
	if denied.BalanceCents != -51 {
		t.Fatalf("product: 402 balance echo %d, want -51 — the denial must decide on the fresh wallet row, not a warm snapshot", denied.BalanceCents)
	}
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta != (fixtureTotals{}) {
		t.Fatalf("product: provider contact during the floor denial arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	if n := s.oracleRequestLogCount(t, ridDenied, orgID); n != 0 {
		t.Fatalf("product: %d request_logs row(s) exist for the floor-denied request", n)
	}
	if c := s.oracleCreditTotals(t, ridDenied, orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: credit transactions exist for the floor-denied request (%+v)", c)
	}
	if n := s.oracleSettlementJobs(t, ridDenied, orgID); n != 0 {
		t.Fatalf("product: %d settlement job(s) exist for the floor-denied request", n)
	}
	if n := s.oracleAdmissionRowCount(t, ridDenied, orgID); n != 0 {
		t.Fatalf("product: %d admission row(s) exist for the floor-denied request", n)
	}
	if w := s.oracleWallet(t, orgID); w.balance != -50 || w.remainder != 32 {
		t.Fatalf("product: wallet moved during the denial (balance/remainder %d/%d), want untouched -50/32", w.balance, w.remainder)
	}

	// Typed reset: null restores the platform default through the same
	// production surface.
	put = sess.putGraceFloor(t, orgID, nil, "wire: restore platform default overdraft")
	if put.GraceFloorCents != nil || put.EffectiveGraceFloorCents != -100 {
		t.Fatalf("product: floor reset echoed saved/effective %v/%d, want null/-100",
			put.GraceFloorCents, put.EffectiveGraceFloorCents)
	}
	if w := s.oracleWallet(t, orgID); w.floor != nil {
		t.Fatalf("product: persisted grace_floor_cents after reset = %v, want NULL", w.floor)
	}

	// The very next paid request on the same credentials and route is
	// served again: arrives exactly once, really charges, becomes durable.
	before = s.fixture.Snapshot()
	ridRestored := s.reqPrefix + "restored"
	status, body, err = s.chat(t, ridRestored, 45*time.Second)
	if err != nil || status != httpOK {
		t.Fatalf("product: post-reset request failed (status=%d err=%v body=%s) — restoring the floor must restore paid service immediately", status, err, body)
	}
	if delta := s.fixture.Since(before); delta != (fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}) {
		t.Fatalf("product: post-reset request provider contact arrivals/dispatches/receipts = %d/%d/%d, want exactly 1/1/1 for the same tenant/route",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, ridRestored, orgID) == 1
	}, "product: post-reset request never became durable in request_logs")
	s.requireBilledRow(t, ridRestored, orgID, "product: post-reset")
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		w := s.oracleWallet(t, orgID)
		return w.balance == -50 && w.remainder == 64
	}, "product: post-reset charge never settled into the wallet (want balance −50, remainder 64 µUSD)")

	t.Logf("product: wallet admission floor wire contract passed (prime %s, denied %s, restored %s)", rid, ridDenied, ridRestored)
}

// startAdminService launches the real admin console process (third product
// process, yabanin_app posture like gateway and loggerd) and waits for its
// public health endpoint. The URL is returned; cleanup is registered here.
func (s *stand) startAdminService(t *testing.T) string {
	t.Helper()
	port := freePort(t)
	adminURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	env := []string{
		"YABANIN_ADMIN_LISTEN=127.0.0.1:" + strconv.Itoa(port),
		"YABANIN_PG_URI=" + s.appDSN,
		"YABANIN_REDIS_ADDR=" + s.redisAddr,
		"YABANIN_ENCRYPTION_KEY=" + s.encKey,
		"YABANIN_REGION=test",
		"YABANIN_LOG_LEVEL=info",
		"YABANIN_LOG_FORMAT=text",
	}
	s.procSeq++
	logFile := filepath.Join(s.tempDir, fmt.Sprintf("admin-%d.log", s.procSeq))
	cmd := s.spawn("admin", env, logFile)
	t.Cleanup(func() { s.stopProc("admin", cmd) })
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := cmdProcessAlive(cmd); err != nil {
			s.dumpLog(logFile)
			t.Fatalf("harness: admin exited during startup: %v", err)
		}
		resp, err := http.Get(adminURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("harness: admin service ready at %s", adminURL)
				return adminURL
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	s.dumpLog(logFile)
	t.Fatalf("harness: admin service never became healthy at %s", adminURL)
	return adminURL
}

// adminSession is one authenticated root-admin console session against the
// stand's real admin API: cookie jar plus the CSRF token the console
// protocol requires on every unsafe method.
type adminSession struct {
	t       *testing.T
	baseURL string
	csrf    string
	client  *http.Client
}

// adminLogin authenticates the seeded root admin through the real console
// login protocol: GET /auth/login renders the page and mints the pre-login
// CSRF cookie, the form POST must echo it as _csrf, and only after the
// session cookie exists does the session-gated /auth/csrf issue the token
// the protected API expects as X-CSRF-Token.
func adminLogin(t *testing.T, s *stand, adminURL string) *adminSession {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("harness: cookie jar: %v", err)
	}
	sess := &adminSession{
		t:       t,
		baseURL: adminURL,
		client:  &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("harness: admin url parse: %v", err)
	}

	// Login page: mints the yabanin_csrf_token cookie into the jar.
	pageResp, err := sess.client.Get(adminURL + "/auth/login")
	if err != nil {
		t.Fatalf("harness: admin login page fetch: %v", err)
	}
	_ = pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK {
		t.Fatalf("harness: admin login page status %d", pageResp.StatusCode)
	}
	csrfToken := ""
	for _, c := range jar.Cookies(u) {
		if c.Name == "yabanin_csrf_token" {
			csrfToken = c.Value
		}
	}
	if csrfToken == "" {
		t.Fatalf("harness: login page did not mint the CSRF cookie — the documented login protocol is broken")
	}

	// Form login as the seeded root admin, echoing the CSRF cookie value.
	form := url.Values{}
	form.Set("email", "admin@"+s.runID+".test")
	form.Set("password", "acc-admin-password-"+s.runID)
	form.Set("_csrf", csrfToken)
	loginResp, err := sess.client.PostForm(adminURL+"/auth/login", form)
	if err != nil {
		t.Fatalf("harness: admin login post: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode >= 400 {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(loginResp.Body)
		t.Fatalf("harness: admin login refused (status %d, body %s)", loginResp.StatusCode, clip(body.String()))
	}
	sessionEstablished := false
	for _, c := range jar.Cookies(u) {
		if c.Name == "yabanin_admin_session" {
			sessionEstablished = true
		}
	}
	if !sessionEstablished {
		t.Fatalf("harness: admin login did not establish a session cookie")
	}

	// The session-gated CSRF endpoint issues the canonical token for the
	// protected API calls.
	csrfResp, err := sess.client.Get(adminURL + "/auth/csrf")
	if err != nil {
		t.Fatalf("harness: admin csrf fetch: %v", err)
	}
	defer csrfResp.Body.Close()
	if csrfResp.StatusCode != http.StatusOK {
		t.Fatalf("harness: admin csrf fetch status %d", csrfResp.StatusCode)
	}
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	if err := json.NewDecoder(csrfResp.Body).Decode(&csrf); err != nil || csrf.Token == "" {
		t.Fatalf("harness: admin csrf body decode: %v", err)
	}
	sess.csrf = csrf.Token
	t.Logf("harness: root admin session established")
	return sess
}

// budgetSettings is the read projection of GET/PUT /api/orgs/{id}/credits/grace.
type budgetSettings struct {
	GraceFloorCents          *int64 `json:"grace_floor_cents"`
	EffectiveGraceFloorCents int64  `json:"effective_grace_floor_cents"`
	BalanceCents             *int64 `json:"balance_cents"`
}

// doJSON issues one authenticated admin API call with the CSRF header.
func (a *adminSession) doJSON(t *testing.T, method, path string, payload []byte) *budgetSettings {
	t.Helper()
	req, err := http.NewRequest(method, a.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("harness: admin %s %s build: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatalf("harness: admin %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("harness: admin %s %s status %d (body %s)", method, path, resp.StatusCode, clip(body.String()))
	}
	var out budgetSettings
	if err := json.Unmarshal(body.Bytes(), &out); err != nil {
		t.Fatalf("harness: admin %s %s body decode: %v (body %s)", method, path, err, clip(body.String()))
	}
	return &out
}

func (a *adminSession) getBudgetSettings(t *testing.T, orgID string) *budgetSettings {
	t.Helper()
	return a.doJSON(t, http.MethodGet, "/api/orgs/"+orgID+"/credits/grace", nil)
}

// putGraceFloor performs the typed floor mutation (floor nil = reset to the
// platform default) and returns the echoed settings block.
func (a *adminSession) putGraceFloor(t *testing.T, orgID string, floor *int64, reason string) *budgetSettings {
	t.Helper()
	payload, err := json.Marshal(struct {
		GraceFloorCents *int64 `json:"grace_floor_cents"`
		Reason          string `json:"reason"`
	}{GraceFloorCents: floor, Reason: reason})
	if err != nil {
		t.Fatalf("harness: floor PUT encode: %v", err)
	}
	return a.doJSON(t, http.MethodPut, "/api/orgs/"+orgID+"/credits/grace", payload)
}

// oracleWallet is the independent raw wallet row: balance cents, sub-cent
// remainder and the persisted floor (nil = platform default).
func (s *stand) oracleWallet(t *testing.T, orgID string) (w struct {
	balance   int64
	remainder int64
	floor     *int64
}) {
	t.Helper()
	err := s.oracleDB.db.QueryRow(
		`SELECT balance_cents, remainder_micro_usd, grace_floor_cents FROM org_credits WHERE org_id = $1`, orgID).
		Scan(&w.balance, &w.remainder, &w.floor)
	if err != nil {
		t.Fatalf("harness: oracle wallet read %s: %v", orgID, err)
	}
	return w
}

// int64Ptr is the typed-floor helper for PUT bodies.
func int64Ptr(v int64) *int64 { return &v }
