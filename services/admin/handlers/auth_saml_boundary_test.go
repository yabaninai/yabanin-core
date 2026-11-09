package handlers

// Boundary corpus for the SAML surface, sharpening the coarse negatives in
// auth_saml_test.go to the exact edges the crewjam v0.5.1 validation contract
// draws (verified against the module source):
//
//   - staleness budget 90s (MaxIssueDelay), enforced TWICE with no skew
//     leeway: by the IdP against the AuthnRequest IssueInstant (a drifted
//     IdP refuses the login before minting anything) and by the SP against
//     the response/assertion IssueInstant;
//   - Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData bounds:
//     ±180s leeway (MaxClockSkew) on the SP side;
//   - InResponseTo must equal the request ID inside the flow cookie (the SP
//     is strictly SP-initiated: AllowIDPInitiated=false) — a response minted
//     for a different flow is refused even though it is fully signed, fresh
//     and otherwise valid.
//
// Clock cells sit 5–10s off the exact edge: assertions are minted with
// second granularity, so exact-edge cells would be scheduling-flaky (same
// reasoning as the OIDC boundary corpus).

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// TestSAMLBoundary_AssertionClockEdges pins the clock-drift boundary on
// both sides. The IdP clock shift applies while the IdP answers; the SP
// validates with the real clock (the fake's contract), so each cell
// observes what a drifted IdP produces against an honest SP. Past drift is
// refused by the SP's envelope budget; future drift within the same budget
// completes (the SP's NotBefore leeway absorbs it); future drift beyond the
// budget never reaches minting — the IdP refuses the request itself.
func TestSAMLBoundary_AssertionClockEdges(t *testing.T) {
	for _, tc := range []struct {
		name       string
		idpShift   time.Duration
		wantStatus int
	}{
		// Past drift: 85s stays inside the 90s envelope budget (the
		// Conditions window with its 180s leeway is far from binding);
		// 95s crosses the envelope budget and is refused even though
		// Conditions still have ~175s of leeway left — the envelope
		// check fires first and carries no skew.
		{"past_inside_envelope_budget_accepted", 85 * time.Second, http.StatusFound},
		{"past_beyond_envelope_budget_refused", 95 * time.Second, http.StatusUnauthorized},
		// Future drift inside the IdP's own request budget: the request
		// looks at most 85s stale to the IdP, the assertion is minted
		// with a NotBefore up to 85s ahead of the SP clock and the 180s
		// NotBefore leeway absorbs it end to end.
		{"future_inside_idp_request_budget_accepted", -85 * time.Second, http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeSAMLIdP(t)
			p.clockShift = tc.idpShift
			h, _ := newSAMLTestHandlers(t, p)

			w, _ := happySAMLFlow(t, h, p)
			if w.Code != tc.wantStatus {
				t.Fatalf("acs: got %d, want %d; body %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus != http.StatusFound {
				for _, c := range w.Result().Cookies() {
					if c.Name == "yabanin_admin_session" && c.Value != "" {
						t.Fatal("refused assertion produced a session cookie")
					}
				}
			}
		})
	}

	// Future drift beyond the budget: the IdP refuses the AuthnRequest
	// (its IssueInstant looks more than 90s stale) BEFORE minting any
	// assertion — the login fails at the IdP with an HTTP 400, never at
	// our ACS. The 90s future boundary is thus IdP-owned; the SP's 180s
	// NotBefore leeway is unreachable past it.
	t.Run("future_beyond_idp_request_budget_refused_at_idp", func(t *testing.T) {
		p := newFakeSAMLIdP(t)
		p.clockShift = -95 * time.Second
		h, _ := newSAMLTestHandlers(t, p)

		redirect, _ := startSAMLFlow(t, h)
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, redirect, nil)
		if err != nil {
			t.Fatalf("idp request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("idp respond: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("stale-request IdP answer: got %d, want 400; body %s", resp.StatusCode, readAll(t, resp.Body))
		}
	})
}

// TestSAMLBoundary_InResponseTo_CrossFlowRefused pins the flow-pairing
// boundary: the assertion must answer the request named by THIS browser's
// flow cookie. Both cross pairings are refused despite cryptographically
// valid, fresh, correctly signed assertions — and the refusals burn neither
// flow: the honest pairing still completes afterwards.
func TestSAMLBoundary_InResponseTo_CrossFlowRefused(t *testing.T) {
	p := newFakeSAMLIdP(t)
	h, _ := newSAMLTestHandlers(t, p)

	redirectA, cookieA := startSAMLFlow(t, h)
	redirectB, cookieB := startSAMLFlow(t, h)
	respA := p.idpRespond(t, redirectA)
	respB := p.idpRespond(t, redirectB)

	crossPairs := []struct {
		name         string
		resp, cookie string
	}{
		{"response_of_flow_b_with_cookie_a", respB, cookieA},
		{"response_of_flow_a_with_cookie_b", respA, cookieB},
	}
	for _, cp := range crossPairs {
		w := runACS(t, h, cp.resp, cp.cookie)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: got %d, want 401; body %s", cp.name, w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "yabanin_admin_session" && c.Value != "" {
				t.Fatalf("%s produced a session cookie", cp.name)
			}
		}
	}

	// Positive control: each refusal left its own flow intact — A's
	// response under A's cookie completes with a session.
	w := runACS(t, h, respA, cookieA)
	if w.Code != http.StatusFound {
		t.Fatalf("honest pairing after refusals: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("honest pairing issued no session cookie")
	}
	if _, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret"); err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
}
