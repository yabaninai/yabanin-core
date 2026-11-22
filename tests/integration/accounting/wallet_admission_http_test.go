//go:build integration

package accounting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Bounded admin-side timing: every admin console HTTP call carries a request
// context at or below these bounds, and the client carries an overall
// timeout as the second bound. A stand that stops answering fails the test;
// it never hangs the lease.
const (
	adminRequestTimeout = 15 * time.Second
	adminStartupTimeout = 30 * time.Second
	adminHealthTimeout  = 2 * time.Second
)

// TestWalletAdmissionFloorWire is the wire-level §8 admission contract: the
// per-org grace floor a ROOT ADMIN types into the real admin HTTP API (real
// admin process, real adminstore persistence, journalled mutation) must
// reach the real charged gateway admission path for the same org without
// any restart or in-process invalidation, and the release must restore
// paid service on the very next request.
//
// In full production topology (gateway, loggerd AND admin are distinct
// product processes over one database) the contract phases are:
//
//  1. Baseline read-back: the seeded org has no explicit floor and sits on
//     the platform default (−$1.00).
//  2. Harness arrangement: the wallet sits at −50 cents (the seed itself
//     arranges opening balances with owner-login SQL, and so does this
//     step; verified by read-back). Rates stay the operator-installed
//     2.0/6.0 per M, so every real charge is the known 32 µUSD residue.
//  3. Prime (positive phase): one real paid request arrives once at the
//     provider and really charges the negative wallet — above the platform
//     floor it must admit.
//  4. Typed PUT {grace_floor_cents: 0, reason} → 200: production
//     persistence (adminstore, audit journal), read-back confirms 0.
//  5. Deny phase: the immediate next paid request is refused 402
//     insufficient_credits with the fresh wallet echoed, the provider is
//     contacted zero times, and nothing is recorded or charged.
//  6. Typed PUT null (the documented reset to the platform default) → 200.
//  7. Restore (positive phase): the next paid request on the same
//     credentials/route arrives exactly once, really charges, becomes
//     durable.
//
// Nothing here inspects product memory or calls product test hooks: the
// only product surfaces are the gateway chat API and the admin console API
// of three separately started processes, plus the owner-login SQL oracle
// for independent evidence.
func TestWalletAdmissionFloorWire(t *testing.T) {
	s := startStand(t)
	sess := adminLogin(t, s, s.startAdminService(t))
	orgID := s.oracleDB.orgID

	// Baseline: platform default floor in effect, nothing persisted.
	requireBudgetSettings(t, sess, orgID, nil, -100)

	// Harness arrangement (owner-login SQL, seed-style): wallet at −50c so
	// the typed zero floor can tighten past it.
	arrangeWalletAt(t, s, orgID, -50)

	// Prime: one real paid request is served and really charges the wallet.
	runPositivePaidPhase(t, s, orgID, "product: prime", s.reqPrefix+"prime", 32)

	// Typed floor mutation: explicit zero through the real admin API.
	requireTypedFloorMutation(t, s, sess, orgID, int64Ptr(0), "wire: forbid overdraft for this org", 0)

	// The immediate next paid request is refused on the authoritative path.
	requireTypedFloorDenial(t, s, orgID, s.reqPrefix+"denied")

	// Typed reset: null restores the platform default on the same surface.
	requireTypedFloorMutation(t, s, sess, orgID, nil, "wire: restore platform default overdraft", -100)

	// The very next paid request on the same credentials and route returns.
	runPositivePaidPhase(t, s, orgID, "product: post-reset", s.reqPrefix+"restored", 64)

	t.Logf("product: wallet admission floor wire contract passed (prime %s, denied %s, restored %s)",
		s.reqPrefix+"prime", s.reqPrefix+"denied", s.reqPrefix+"restored")
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
	health := &http.Client{Timeout: adminHealthTimeout}
	deadline := time.Now().Add(adminStartupTimeout)
	for time.Now().Before(deadline) {
		if err := cmdProcessAlive(cmd); err != nil {
			s.dumpLog(logFile)
			t.Fatalf("harness: admin exited during startup: %v", err)
		}
		if adminHealthOK(health, adminURL) {
			t.Logf("harness: admin service ready at %s", adminURL)
			return adminURL
		}
		time.Sleep(300 * time.Millisecond)
	}
	s.dumpLog(logFile)
	t.Fatalf("harness: admin service never became healthy at %s", adminURL)
	return adminURL
}

// adminHealthOK polls the admin public health endpoint once.
func adminHealthOK(client *http.Client, adminURL string) bool {
	resp, err := client.Get(adminURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	return resp.StatusCode == http.StatusOK
}

// adminSession is one authenticated root-admin console session against the
// stand's real admin API: cookie jar plus the CSRF token the console
// protocol requires on every unsafe method.
type adminSession struct {
	baseURL string
	csrf    string
	client  *http.Client
}

// adminLogin authenticates the seeded root admin through the real console
// login protocol as three coherent stages: the login page mints the
// pre-login CSRF cookie, the form POST establishes the session cookie, and
// the session-gated CSRF endpoint issues the token the protected API
// expects as X-CSRF-Token.
func adminLogin(t *testing.T, s *stand, adminURL string) *adminSession {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("harness: cookie jar: %v", err)
	}
	sess := &adminSession{
		baseURL: adminURL,
		client:  &http.Client{Jar: jar, Timeout: adminRequestTimeout},
	}
	csrfCookie := adminLoginStageCSRFCookie(t, sess)
	adminLoginStagePostForm(t, sess, "admin@"+s.runID+".test", "acc-admin-password-"+s.runID, csrfCookie)
	sess.csrf = adminLoginStageSessionToken(t, sess)
	t.Logf("harness: root admin session established")
	return sess
}

// adminLoginStageCSRFCookie fetches the real login page (which mints the
// yabanin_csrf_token cookie into the jar) and returns the cookie value the
// form POST must echo.
func adminLoginStageCSRFCookie(t *testing.T, sess *adminSession) string {
	t.Helper()
	status, _ := adminSessionGet(t, sess, "/auth/login")
	if status != http.StatusOK {
		t.Fatalf("harness: admin login page status %d", status)
	}
	csrfToken := sessionCookieValue(t, sess, "yabanin_csrf_token")
	if csrfToken == "" {
		t.Fatalf("harness: login page did not mint the CSRF cookie — the documented login protocol is broken")
	}
	return csrfToken
}

// adminLoginStagePostForm submits the real form login as the seeded root
// admin, echoing the CSRF cookie value, and demands the session cookie.
func adminLoginStagePostForm(t *testing.T, sess *adminSession, email, password, csrfToken string) {
	t.Helper()
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	form.Set("_csrf", csrfToken)
	status, body := adminSessionPostForm(t, sess, "/auth/login", form)
	if status >= 400 {
		t.Fatalf("harness: admin login refused (status %d, body %s)", status, clip(body))
	}
	if sessionCookieValue(t, sess, "yabanin_admin_session") == "" {
		t.Fatalf("harness: admin login did not establish a session cookie")
	}
}

// adminLoginStageSessionToken asks the session-gated CSRF endpoint for the
// canonical token used on protected admin API calls.
func adminLoginStageSessionToken(t *testing.T, sess *adminSession) string {
	t.Helper()
	status, body := adminSessionGet(t, sess, "/auth/csrf")
	if status != http.StatusOK {
		t.Fatalf("harness: admin csrf fetch status %d", status)
	}
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal([]byte(body), &csrf); err != nil || csrf.Token == "" {
		t.Fatalf("harness: admin csrf body decode: %v", err)
	}
	return csrf.Token
}

// adminSessionGet issues one bounded GET against the admin console and
// returns the status plus the fully drained body.
func adminSessionGet(t *testing.T, sess *adminSession, path string) (int, string) {
	t.Helper()
	return adminSessionDo(t, sess, http.MethodGet, path, "", nil)
}

// adminSessionPostForm issues one bounded form POST against the admin
// console with the browser content type and returns status plus body.
func adminSessionPostForm(t *testing.T, sess *adminSession, path string, form url.Values) (int, string) {
	t.Helper()
	return adminSessionDo(t, sess, http.MethodPost, path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
}

// adminSessionDo is the one common admin request helper: bounded request
// context, bounded client, and the response body fully read and closed
// BEFORE the context cancels. It returns (status, body); no live response
// body is ever handed back tied to an already-cancelled context, so a slow
// body can be late but never truncated or failed by the deferred cancel.
func adminSessionDo(t *testing.T, sess *adminSession, method, path, contentType string, payload io.Reader) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), adminRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, sess.baseURL+path, payload)
	if err != nil {
		t.Fatalf("harness: admin %s %s build: %v", method, path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := sess.client.Do(req)
	if err != nil {
		t.Fatalf("harness: admin %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body := readAllBody(t, resp)
	return resp.StatusCode, body
}

// TestAdminSessionDelayedBodyRead pins the request-helper contract the
// login stages depend on: a response whose body arrives LATE must be read
// completely by the shipped common helper (body drained and closed before
// the bounded context cancels), while the abandoned shape this replaces —
// handing back a live *http.Response from a helper whose deferred cancel
// fires on return — deterministically fails or truncates that same body.
func TestAdminSessionDelayedBodyRead(t *testing.T) {
	const payload = "yabanin-delayed-body-payload"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // headers are on the wire; client Do returns here
		}
		time.Sleep(300 * time.Millisecond) // body arrives only later
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	// Negative control: the abandoned helper shape. The context is
	// cancelled the moment Do returns, before the delayed body exists —
	// exactly what the previous deferred-cancel-and-return-response
	// helpers did to every caller that then read the body.
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("harness: control request build: %v", err)
	}
	controlResp, err := (&http.Client{Timeout: adminRequestTimeout}).Do(req)
	if err != nil {
		t.Fatalf("harness: control request: %v", err)
	}
	cancel()
	if _, readErr := io.ReadAll(controlResp.Body); readErr == nil {
		t.Fatalf("harness: negative control read the delayed body cleanly — the demonstration no longer reproduces the abandoned shape and must be rebuilt")
	}
	_ = controlResp.Body.Close()

	// Shipped shape: GET and form POST through the common helper return
	// status plus the fully drained body, late arrival notwithstanding.
	sess := &adminSession{baseURL: srv.URL, client: &http.Client{Timeout: adminRequestTimeout}}
	status, body := adminSessionGet(t, sess, "/")
	if status != http.StatusOK || body != payload {
		t.Fatalf("harness: helper GET of a delayed body truncated or failed (status %d, body %q), want 200/%q", status, body, payload)
	}
	status, body = adminSessionPostForm(t, sess, "/", url.Values{"k": {"v"}})
	if status != http.StatusOK || body != payload {
		t.Fatalf("harness: helper form POST of a delayed body truncated or failed (status %d, body %q), want 200/%q", status, body, payload)
	}
}

// TestBudgetSettingsAbsentEffectiveKeyRejected pins the decode oracle for
// the grace-floor JSON contract at both layers. Decode layer: an ABSENT
// effective_grace_floor_cents decodes as a nil pointer — structurally
// unable to equal an expected zero — while an explicit zero decodes as a
// pointer to 0. Oracle layer: doJSON rejects the nil-pointer shape (its
// guard fails the test on an absent key; the failure mode is a t.Fatalf,
// demonstrated against a live server during review, where the run logged
// "response omits effective_grace_floor_cents … must never satisfy an
// expected zero") and accepts the explicit-zero shape, so a real zero
// effective floor keeps passing.
func TestBudgetSettingsAbsentEffectiveKeyRejected(t *testing.T) {
	// Decode layer: absence is nil, never zero.
	var absent budgetSettings
	if err := json.Unmarshal([]byte(`{"grace_floor_cents":0,"balance_cents":100}`), &absent); err != nil {
		t.Fatalf("oracle: absent-key body must decode (err %v)", err)
	}
	if absent.EffectiveGraceFloorCents != nil {
		t.Fatalf("oracle: absent effective_grace_floor_cents decoded as %d — absence must stay nil so it can never equal an expected zero", *absent.EffectiveGraceFloorCents)
	}

	var explicit budgetSettings
	if err := json.Unmarshal([]byte(`{"grace_floor_cents":0,"effective_grace_floor_cents":0,"balance_cents":100}`), &explicit); err != nil {
		t.Fatalf("oracle: explicit-zero body must decode (err %v)", err)
	}
	if explicit.EffectiveGraceFloorCents == nil || *explicit.EffectiveGraceFloorCents != 0 {
		t.Fatalf("oracle: explicit zero effective_grace_floor_cents decoded as %v, want a pointer to 0", explicit.EffectiveGraceFloorCents)
	}

	// Oracle layer: the explicit-zero shape passes the live doJSON path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"grace_floor_cents":0,"effective_grace_floor_cents":0,"balance_cents":100}`)
	}))
	defer srv.Close()
	sess := &adminSession{baseURL: srv.URL, client: &http.Client{Timeout: adminRequestTimeout}, csrf: "test"}
	got := sess.doJSON(t, http.MethodGet, "/api/orgs/x/credits/grace", nil)
	if got.EffectiveGraceFloorCents == nil || *got.EffectiveGraceFloorCents != 0 {
		t.Fatalf("oracle: explicit zero effective_grace_floor_cents did not pass the oracle cleanly (got %v)", got.EffectiveGraceFloorCents)
	}
}

// sessionCookieValue reads one named cookie from the session jar.
func sessionCookieValue(t *testing.T, sess *adminSession, name string) string {
	t.Helper()
	u, err := url.Parse(sess.baseURL)
	if err != nil {
		t.Fatalf("harness: admin url parse: %v", err)
	}
	for _, c := range sess.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// readAllBody drains a response body with explicit read-failure handling: a
// truncated body is a harness failure, never silently empty input.
func readAllBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("harness: response body read failed (status %d): %v", resp.StatusCode, err)
	}
	return string(raw)
}

// budgetSettings is the read projection of GET/PUT /api/orgs/{id}/credits/grace.
// Both floor fields are pointers on purpose: an ABSENT key must never be
// conflated with an explicit value — in particular an absent
// effective_grace_floor_cents would decode as the zero value 0 and could
// otherwise satisfy an expected zero floor assertion.
type budgetSettings struct {
	GraceFloorCents          *int64 `json:"grace_floor_cents"`
	EffectiveGraceFloorCents *int64 `json:"effective_grace_floor_cents"`
	BalanceCents             *int64 `json:"balance_cents"`
}

// doJSON issues one authenticated admin API call with the CSRF header and a
// bounded request context.
func (a *adminSession) doJSON(t *testing.T, method, path string, payload []byte) *budgetSettings {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), adminRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, bytes.NewReader(payload))
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
	body := readAllBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("harness: admin %s %s status %d (body %s)", method, path, resp.StatusCode, clip(body))
	}
	var out budgetSettings
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("harness: admin %s %s body decode: %v (body %s)", method, path, err, clip(body))
	}
	if out.EffectiveGraceFloorCents == nil {
		t.Fatalf("harness: admin %s %s response omits effective_grace_floor_cents (body %s) — an absent key must never satisfy an expected zero", method, path, clip(body))
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

// requireBudgetSettings reads the real admin API projection and demands the
// exact saved/effective floor pair (saved nil = platform default). The
// effective field is presence-checked in the decode oracle, so an absent
// key can never stand in for an expected value.
func requireBudgetSettings(t *testing.T, sess *adminSession, orgID string, wantSaved *int64, wantEffective int64) {
	t.Helper()
	got := sess.getBudgetSettings(t, orgID)
	if (wantSaved == nil) != (got.GraceFloorCents == nil) ||
		(wantSaved != nil && *got.GraceFloorCents != *wantSaved) ||
		*got.EffectiveGraceFloorCents != wantEffective {
		t.Fatalf("product: grace floor read-back saved/effective %v/%d, want %v/%d",
			got.GraceFloorCents, *got.EffectiveGraceFloorCents, wantSaved, wantEffective)
	}
}

// arrangeWalletAt arranges the wallet row owner-SQL style (the seed itself
// inserts opening balances this way) and verifies the arrangement by
// read-back: balance cents, zero sub-cent remainder, no explicit floor.
func arrangeWalletAt(t *testing.T, s *stand, orgID string, balance int64) {
	t.Helper()
	s.oracleExec(t, fmt.Sprintf("arrange wallet at %d cents", balance),
		`UPDATE org_credits SET balance_cents = $2, remainder_micro_usd = 0 WHERE org_id = $1`, orgID, balance)
	w := s.oracleWallet(t, orgID)
	if w.balance != balance || w.remainder != 0 || w.floor != nil {
		t.Fatalf("harness: wallet arrangement read-back balance/remainder/floor = %d/%d/%v, want %d/0/<nil>",
			w.balance, w.remainder, w.floor, balance)
	}
}

// requireTypedFloorMutation performs the typed floor mutation through the
// real admin API and verifies the full production chain of one exact
// effect: the echoed settings, a fresh API read-back, and the persisted
// org_credits row (floor nil = documented reset to the platform default).
func requireTypedFloorMutation(t *testing.T, s *stand, sess *adminSession, orgID string, floor *int64, reason string, wantEffective int64) {
	t.Helper()
	put := sess.putGraceFloor(t, orgID, floor, reason)
	if (floor == nil) != (put.GraceFloorCents == nil) ||
		(floor != nil && *put.GraceFloorCents != *floor) ||
		*put.EffectiveGraceFloorCents != wantEffective {
		t.Fatalf("product: floor PUT echoed saved/effective %v/%d, want %v/%d",
			put.GraceFloorCents, *put.EffectiveGraceFloorCents, floor, wantEffective)
	}
	requireBudgetSettings(t, sess, orgID, floor, wantEffective)
	w := s.oracleWallet(t, orgID)
	if (floor == nil) != (w.floor == nil) || (floor != nil && *w.floor != *floor) {
		t.Fatalf("product: persisted grace_floor_cents after PUT = %v, want %v (production persistence)", w.floor, floor)
	}
}

// requireTypedFloorDenial is the client-facing deny phase on the real
// charged entrypoint, pinned to the exact post-prime ledger state (wallet
// −50, remainder 32 so the fresh effective view is −51): the immediate
// next paid request under the tightened floor must be refused 402
// insufficient_credits echoing the fresh wallet.
func requireTypedFloorDenial(t *testing.T, s *stand, orgID, rid string) {
	t.Helper()
	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 45*time.Second)
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
	requireFloorDenialZeroSideEffects(t, s, orgID, rid, before)
}

// requireFloorDenialZeroSideEffects is the deny-phase ledger half, spanning
// the refused request from its pre-chat fixture snapshot: the provider
// fixture must show zero contact and no request, transaction, settlement
// job or admission row may exist for the refused request, and the wallet
// must be untouched.
func requireFloorDenialZeroSideEffects(t *testing.T, s *stand, orgID, rid string, before fixtureTotals) {
	t.Helper()
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta != (fixtureTotals{}) {
		t.Fatalf("product: provider contact during the floor denial arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	if n := s.oracleRequestLogCount(t, rid, orgID); n != 0 {
		t.Fatalf("product: %d request_logs row(s) exist for the floor-denied request", n)
	}
	if c := s.oracleCreditTotals(t, rid, orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: credit transactions exist for the floor-denied request (%+v)", c)
	}
	if n := s.oracleSettlementJobs(t, rid, orgID); n != 0 {
		t.Fatalf("product: %d settlement job(s) exist for the floor-denied request", n)
	}
	if n := s.oracleAdmissionRowCount(t, rid, orgID); n != 0 {
		t.Fatalf("product: %d admission row(s) exist for the floor-denied request", n)
	}
	if w := s.oracleWallet(t, orgID); w.balance != -50 || w.remainder != 32 {
		t.Fatalf("product: wallet moved during the denial (balance/remainder %d/%d), want untouched -50/32", w.balance, w.remainder)
	}
}

// runPositivePaidPhase is the shared positive phase (prime and post-reset):
// one real paid request must arrive exactly once at the provider, become
// durable, bill exactly, and settle its known residue-only charge into the
// wallet — the exact effect set of the original inline phases. At the
// installed 2.0/6.0 per M rates the 32 µUSD request cost is pure sub-cent
// residue, so the raw balance stays −50 while the remainder accrues by 32.
func runPositivePaidPhase(t *testing.T, s *stand, orgID string, label, rid string, wantRemainder int64) {
	t.Helper()
	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 45*time.Second)
	if err != nil || status != httpOK {
		t.Fatalf("%s failed (status=%d err=%v body=%s) — the wallet above the floor must admit", label, status, err, body)
	}
	if delta := s.fixture.Since(before); delta != (fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}) {
		t.Fatalf("%s provider contact arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1",
			label, delta.arrivals, delta.dispatches, delta.receipts)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, orgID) == 1
	}, "%s never became durable in request_logs", label)
	s.requireBilledRow(t, rid, orgID, label)
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		w := s.oracleWallet(t, orgID)
		return w.balance == -50 && w.remainder == wantRemainder
	}, "%s charge never settled into the wallet (want balance −50, remainder %d µUSD)", label, wantRemainder)
}

// walletRow is the independent raw wallet row: balance cents, sub-cent
// remainder and the persisted floor (nil = platform default).
type walletRow struct {
	balance   int64
	remainder int64
	floor     *int64
}

// oracleWallet reads the raw wallet row as independent evidence.
func (s *stand) oracleWallet(t *testing.T, orgID string) walletRow {
	t.Helper()
	var w walletRow
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
