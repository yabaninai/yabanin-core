package handlers

// N04-P02-T10 independent verification corpus (test-only): SAML resource
// bounds at the HTTP boundary.
//
// ROTATION UNDER LOAD — the mock rotation arc (dual-trust publish → promote
// → retire) is driven repeatedly while concurrent full logins hammer the SP;
// the corpus ends only when the process holds no goroutine or descriptor
// growth beyond warmup slack and every audit row matches exactly one success.
// BODY CEILING — the production router's 1 MiB request-body cap refuses an
// oversized ACS POST before the handler, while a junk-but-small POST still
// reaches the handler and a real login still succeeds. Unit-level replay-cap
// and refresh-concurrency cells live in pkg/adminauth.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// samlRotateDual toggles the fake IdP's dual-certificate metadata publishing
// (the mock stand-in for the IdP admin's key-rollover API).
func samlRotateDual(t *testing.T, p *fakeSAMLIdP, on bool) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dualCerts = on
}

// samlLoginWave runs G concurrent full logins through the SP and returns the
// number of 302 successes (callers require every wave to be all-success).
func samlLoginWave(t *testing.T, h *testAdminHandlers, p *fakeSAMLIdP, workers int) int {
	t.Helper()
	var mu sync.Mutex
	successes := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, err := samlTryFullLogin(h, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("wave login: %v", err)
				return
			}
			if code == http.StatusFound {
				successes++
			} else {
				t.Errorf("wave login: got %d, want 302", code)
			}
		}()
	}
	wg.Wait()
	return successes
}

// samlProcFDCount counts the process's open descriptors (linux /proc).
func samlProcFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestSAMLResources_RotationUnderLoadStable drives eight full rotation cycles
// (dual-trust publish → sign with the alternate identity → promote via
// refresh → retire back to the original identity) while four concurrent
// workers log in during every trusted phase. Afterwards the process must show
// no goroutine or descriptor growth beyond slack, and every audit row must
// correspond to exactly one successful login.
func TestSAMLResources_RotationUnderLoadStable(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, sp := newSAMLTestHandlers(t, p)
	ctx := context.Background()

	const workers = 4
	const cycles = 8

	// Warmup: settle the HTTP client pools the workers will reuse before
	// taking the leak baselines.
	samlRotateDual(t, p, true)
	require.NoError(t, sp.RefreshMetadata(ctx))
	require.Equal(t, workers, samlLoginWave(t, h, p, workers), "warmup wave")
	require.NoError(t, sp.RefreshMetadata(ctx), "warmup refresh")
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	goroutinesBase := runtime.NumGoroutine()
	fdBase := 0
	if runtime.GOOS == "linux" {
		fdBase = samlProcFDCount(t)
	}

	successes := workers // the warmup wave already wrote its audit rows
	for cycle := 0; cycle < cycles; cycle++ {
		// Phase A: dual-trust window, original identity signing.
		samlRotateDual(t, p, true)
		require.NoError(t, sp.RefreshMetadata(ctx), "cycle %d: dual publish", cycle)
		successes += samlLoginWave(t, h, p, workers)

		// Phase B: IdP switches signing to the alternate key it published.
		p.useAlternatePublishedIdentity(t)
		successes += samlLoginWave(t, h, p, workers)

		// Phase C: the IdP retires the original key from metadata; refresh
		// promotes the alternate certificate to the only trusted identity.
		samlRotateDual(t, p, false)
		require.NoError(t, sp.RefreshMetadata(ctx), "cycle %d: promote alternate", cycle)
		successes += samlLoginWave(t, h, p, workers)

		// Phase D: retire back to the original identity and refresh so the
		// next cycle starts from the steady state.
		p.restoreOriginalSigningIdentity(t)
		require.NoError(t, sp.RefreshMetadata(ctx), "cycle %d: retire alternate", cycle)
		successes += samlLoginWave(t, h, p, workers)
	}

	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	goroutinesEnd := runtime.NumGoroutine()
	require.LessOrEqual(t, goroutinesEnd, goroutinesBase+16,
		"goroutine growth across %d rotation cycles: %d → %d", cycles, goroutinesBase, goroutinesEnd)
	if runtime.GOOS == "linux" {
		fdEnd := samlProcFDCount(t)
		require.LessOrEqual(t, fdEnd, fdBase+24,
			"descriptor growth across %d rotation cycles: %d → %d", cycles, fdBase, fdEnd)
	}

	require.Equal(t, successes, samlAuditLoginCount(h),
		"every successful rotation-window login must carry exactly one audit row")
}

// TestSAMLResources_ACSBodyCeilingThroughRouter proves the production router
// enforces its 1 MiB request-body ceiling on the ACS: an oversized POST is
// refused before the handler (no session, no echo), a small junk POST still
// reaches the handler and gets the verification refusal, and a real login
// through the same router still succeeds.
func TestSAMLResources_ACSBodyCeilingThroughRouter(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)
	router := h.SetupRouter()

	redirect, flowCookie := startSAMLFlow(t, h)
	realResponse := p.idpRespond(t, redirect)

	samlACSPost := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/saml/acs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:1234"
		req.AddCookie(&http.Cookie{
			Name: adminauth.SAMLFlowCookieName, Value: flowCookie,
			Path: "/auth/saml", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	requireNoSession := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		for _, c := range rec.Result().Cookies() {
			require.NotEqual(t, "yabanin_admin_session", c.Name,
				"refused acs must not mint a session cookie")
		}
	}

	// Oversized (beyond the router's 1 MiB ceiling): refused before the
	// handler reads the form.
	oversized := "SAMLResponse=x&pad=" + strings.Repeat("A", 1_100_000)
	wBig := samlACSPost(t, oversized)
	require.Contains(t, []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge}, wBig.Code,
		"oversized acs body: got %d", wBig.Code)
	requireNoSession(t, wBig)
	require.NotContains(t, wBig.Body.String(), "AAAAAAA", "refusal must not echo the payload")

	// Small junk: reaches the handler, verification refuses generically.
	smallJunk := "SAMLResponse=" + strings.Repeat("A", 4096)
	wJunk := samlACSPost(t, smallJunk)
	require.Equal(t, http.StatusUnauthorized, wJunk.Code, "small junk must reach the handler")
	require.Equal(t, "sso login failed", strings.TrimSpace(wJunk.Body.String()))
	requireNoSession(t, wJunk)

	// Real response through the same router: full success.
	realForm := url.Values{"SAMLResponse": {realResponse}}
	wReal := samlACSPost(t, realForm.Encode())
	require.Equal(t, http.StatusFound, wReal.Code, "real acs through the router must succeed")
	var sessionMinted bool
	for _, c := range wReal.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && c.Value != "" {
			sessionMinted = true
		}
	}
	require.True(t, sessionMinted, "real acs must mint a session cookie")
}
