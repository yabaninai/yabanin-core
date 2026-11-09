package handlers

// N04-P02-T08 [recovery] mock corpus: interruption / retry / resume of the
// SAML admin-SSO flow must recover its results without duplicates and
// without losses. Four invariants, each paired with a live cell in
// pkg/adminauth/keycloak_live_saml_recovery_test.go:
//
//  1. a replay storm (N racing attempts on one captured exchange) yields
//     exactly ONE session and exactly ONE audit login entry — the
//     per-process assertion replay guard is the duplicate breaker;
//  2. a failed ACS (signature from an unpublished key) leaves no session,
//     no audit entry and nothing sticky; a fresh login recovers instantly;
//  3. a flow interrupted before the ACS post never wedges the browser: a
//     fresh login supersedes it, the abandoned (response, flow cookie)
//     pair stays redeemable EXACTLY once, and every login mints a distinct
//     session identity;
//  4. metadata refresh churn concurrent with full logins never tears the
//     trust state: every refresh succeeds and every login succeeds (race
//     pin for the atomic currentSP swap).

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// ---- recovery helpers --------------------------------------------------------

// samlAuditLoginCount counts durable login entries in the mock journal
// (recovery means "no duplicate audit rows and no lost successes").
func samlAuditLoginCount(h *testAdminHandlers) int {
	h.store.auditMu.Lock()
	defer h.store.auditMu.Unlock()
	n := 0
	for _, e := range h.store.auditRecords {
		if e.Action == "login" {
			n++
		}
	}
	return n
}

// samlSessionCookieValue returns the minted session cookie value, "" when
// the response carries none (no duplicate session may ever hide here).
func samlSessionCookieValue(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// samlRecorderClearedFlow reports whether the recorder expires the one-time
// flow cookie (MaxAge < 0) — the interrupt/retry hygiene of every ACS exit.
func samlRecorderClearedFlow(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == adminauth.SAMLFlowCookieName {
			return c.MaxAge < 0
		}
	}
	return false
}

// samlTryStartLogin is the non-fatal startSAMLFlow variant for goroutines
// (t.Fatal from a non-test goroutine is forbidden).
func samlTryStartLogin(h *testAdminHandlers) (redirect, flowCookie string, code int, err error) {
	w := httptest.NewRecorder()
	h.SAMLLogin()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/login", nil))
	if w.Code != http.StatusFound {
		return "", "", w.Code, fmt.Errorf("login start: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == adminauth.SAMLFlowCookieName {
			return w.Header().Get("Location"), c.Value, w.Code, nil
		}
	}
	return "", "", w.Code, errors.New("login start: no flow cookie")
}

// samlTryIDPOffer is the non-fatal idpRespond variant for goroutines.
func samlTryIDPOffer(p *fakeSAMLIdP, loginRedirect string) (string, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginRedirect, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp %d", resp.StatusCode)
	}
	m := samlResponseRe.FindStringSubmatch(string(body))
	if m == nil {
		return "", errors.New("idp: no SAMLResponse form")
	}
	return html.UnescapeString(m[1]), nil
}

// samlTryFullLogin is the non-fatal happySAMLFlow variant for goroutines.
func samlTryFullLogin(h *testAdminHandlers, p *fakeSAMLIdP) (int, error) {
	redirect, flowCookie, _, err := samlTryStartLogin(h)
	if err != nil {
		return 0, err
	}
	offer, err := samlTryIDPOffer(p, redirect)
	if err != nil {
		return 0, err
	}
	form := url.Values{"SAMLResponse": {offer}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:1234"
	// Production flow-cookie attributes (the handler plants HttpOnly/Secure/
	// Strict); the planted copy mirrors them so the transport shape under
	// test matches what a real browser would send.
	req.AddCookie(&http.Cookie{
		Name:     adminauth.SAMLFlowCookieName,
		Value:    flowCookie,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	w := httptest.NewRecorder()
	h.SAMLACS()(w, req)
	return w.Code, nil
}

// ---- tests -------------------------------------------------------------------

// TestSAMLRecovery_ReplayStorm_SingleSessionAndAudit races N attempts at one
// captured (response, flow cookie) exchange with no prior redemption: the
// replay guard must hand out exactly one session and exactly one audit row,
// no matter how the attempts interleave (run under -race by the gates).
func TestSAMLRecovery_ReplayStorm_SingleSessionAndAudit(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	redirect, flowCookie := startSAMLFlow(t, h)
	resp := p.idpRespond(t, redirect)

	const attempts = 8
	recs := make([]*httptest.ResponseRecorder, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// runACS touches t only through the concurrency-safe Helper.
			recs[i] = runACS(t, h, resp, flowCookie)
		}(i)
	}
	wg.Wait()

	wins := 0
	var sessionValue string
	for i, w := range recs {
		if w == nil {
			t.Fatalf("storm attempt %d produced no recorder", i)
		}
		if v := samlSessionCookieValue(t, w); v != "" {
			wins++
			sessionValue = v
		}
	}
	if wins != 1 {
		t.Fatalf("replay storm of %d attempts minted %d sessions, want exactly 1", attempts, wins)
	}
	sess, err := adminauth.ParseAdminSessionCookie(sessionValue, "test-secret")
	if err != nil {
		t.Fatalf("the single winning session does not verify: %v", err)
	}
	if sess.Email != "root@test.io" {
		t.Fatalf("winning session identity: got %+v", sess)
	}
	if n := samlAuditLoginCount(h); n != 1 {
		t.Fatalf("audit login entries after the storm: got %d, want 1", n)
	}

	// The retry axis stays closed too: later replays of the dead exchange
	// are refused without duplicate sessions or audit rows.
	for i := 0; i < 2; i++ {
		w := runACS(t, h, resp, flowCookie)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("replay retry %d: got %d, want 401", i+1, w.Code)
		}
		if v := samlSessionCookieValue(t, w); v != "" {
			t.Fatalf("replay retry %d minted a duplicate session", i+1)
		}
	}
	if n := samlAuditLoginCount(h); n != 1 {
		t.Fatalf("audit login entries after retries: got %d, want 1", n)
	}
}

// TestSAMLRecovery_FailedACSThenFreshLoginRecovers verifies that a failed
// ACS (the IdP signs with a key its metadata never published) fails closed
// with no session, no audit row and only the one-time cookie burned — and
// that a fresh login immediately recovers, writing exactly one audit row.
func TestSAMLRecovery_FailedACSThenFreshLoginRecovers(t *testing.T) {
	// The IdP signs with a key its metadata never published (the knob must
	// engage before SP construction, mirroring TestSAML_BadSignature_Rejected):
	// the ACS fails closed (401), leaves no session, no audit entry, and
	// burns only the one-time flow cookie.
	p := newFakeSAMLIdP(t)
	p.signKeyMismatch = true
	h, _ := newSAMLTestHandlers(t, p)

	w, _ := happySAMLFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched-signature acs: got %d, want 401; body %s", w.Code, w.Body.String())
	}
	if v := samlSessionCookieValue(t, w); v != "" {
		t.Fatal("failed acs minted a session")
	}
	if !samlRecorderClearedFlow(t, w) {
		t.Fatal("failed acs did not clear the one-time flow cookie")
	}
	if n := samlAuditLoginCount(h); n != 0 {
		t.Fatalf("failed acs wrote %d audit login entries, want 0", n)
	}

	// Recovery: the operator restores the IdP signing identity — the failure
	// created nothing sticky, and the very next login succeeds.
	p.restoreOriginalSigningIdentity(t)
	w2, _ := happySAMLFlow(t, h, p)
	if w2.Code != http.StatusFound {
		t.Fatalf("recovery login: got %d, want 302; body %s", w2.Code, w2.Body.String())
	}
	sessionValue := samlSessionCookieValue(t, w2)
	if sessionValue == "" {
		t.Fatal("recovery login issued no session")
	}
	sess, err := adminauth.ParseAdminSessionCookie(sessionValue, "test-secret")
	if err != nil {
		t.Fatalf("recovery session does not verify: %v", err)
	}
	if sess.Email != "root@test.io" {
		t.Fatalf("recovery session identity: got %+v", sess)
	}
	if n := samlAuditLoginCount(h); n != 1 {
		t.Fatalf("audit entries after recovery: got %d, want exactly 1 (none from the failed attempt)", n)
	}
}

// TestSAMLRecovery_AbandonedFlow_SupersededAndSingleRedemption pins the
// interrupted-flow contract: the SP keeps no server-side registry of issued
// requests (the flow cookie IS the state), so a browser that died before the
// ACS post is not locked out — a fresh login works, and the abandoned pair
// remains redeemable exactly once within the assertion's validity window.
func TestSAMLRecovery_AbandonedFlow_SupersededAndSingleRedemption(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	// Flow A is interrupted after the IdP leg: the browser holds the
	// captured pair but never reaches the ACS.
	redirectA, flowA := startSAMLFlow(t, h)
	offerA := p.idpRespond(t, redirectA)

	// A fresh login supersedes the abandoned flow — nothing about flow A
	// blocks flow B (no lockout, no lost access).
	wB, _ := happySAMLFlow(t, h, p)
	if wB.Code != http.StatusFound {
		t.Fatalf("flow B after abandonment: got %d, want 302; body %s", wB.Code, wB.Body.String())
	}
	valueB := samlSessionCookieValue(t, wB)
	if valueB == "" {
		t.Fatal("flow B issued no session")
	}

	// Resume: the abandoned pair itself is still redeemable — once.
	wA := runACS(t, h, offerA, flowA)
	if wA.Code != http.StatusFound {
		t.Fatalf("late redemption of the abandoned flow: got %d, want 302; body %s", wA.Code, wA.Body.String())
	}
	valueA := samlSessionCookieValue(t, wA)
	if valueA == "" {
		t.Fatal("late redemption issued no session")
	}
	sessA, err := adminauth.ParseAdminSessionCookie(valueA, "test-secret")
	if err != nil {
		t.Fatalf("late-redemption session does not verify: %v", err)
	}
	sessB, err := adminauth.ParseAdminSessionCookie(valueB, "test-secret")
	if err != nil {
		t.Fatalf("flow B session does not verify: %v", err)
	}
	if sessA.SessionID == sessB.SessionID {
		t.Fatal("two logins produced a duplicated session identity")
	}

	// The redeemed pair is dead: a second redemption yields no duplicate
	// session and no duplicate audit row.
	wA2 := runACS(t, h, offerA, flowA)
	if wA2.Code != http.StatusUnauthorized {
		t.Fatalf("second redemption of the abandoned pair: got %d, want 401", wA2.Code)
	}
	if v := samlSessionCookieValue(t, wA2); v != "" {
		t.Fatal("second redemption minted a duplicate session")
	}
	if n := samlAuditLoginCount(h); n != 2 {
		t.Fatalf("audit login entries: got %d, want exactly 2", n)
	}
}

// TestSAMLRecovery_MetadataSwapUnderConcurrentLogins races metadata
// refreshes against full logins while the IdP itself is stable: the atomic
// currentSP swap must make every refresh succeed and every login mint a
// session (run under -race this pins the no-torn-read recovery property).
func TestSAMLRecovery_MetadataSwapUnderConcurrentLogins(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)

	const rounds = 4
	results := make(chan error, rounds*2)
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			results <- sp.RefreshMetadata(context.Background())
		}()
		go func() {
			defer wg.Done()
			code, err := samlTryFullLogin(h, p)
			if err != nil {
				results <- fmt.Errorf("login (status %d): %w", code, err)
				return
			}
			if code != http.StatusFound {
				results <- fmt.Errorf("login status %d, want 302", code)
				return
			}
			results <- nil
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
}
