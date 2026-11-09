package provider

// Negative battery for the Vertex adapter: upstream quota/permission
// refusals surfaced verbatim, credential-chain failures that never fall
// back to a foreign or weaker source, malformed token/stream inputs that
// fail closed, and capability-lookup rejects that leak no partial answer.
// Everything here is hermetic (httptest doubles, no live Google endpoint)
// and deterministic; the pinning/refusal guarantees hold under -race.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// vertexRawTokenServer is a token-endpoint double whose response body and
// status are switched per test phase, so malformed/refused/healthy exchange
// responses can follow one another against a single binding.
type vertexRawTokenServer struct {
	srv    *httptest.Server
	hits   atomic.Int64
	status atomic.Int64 // 0 → 200
	body   atomic.Value // string
}

func newVertexRawTokenServer(t *testing.T) *vertexRawTokenServer {
	t.Helper()
	raw := &vertexRawTokenServer{}
	raw.body.Store("")
	raw.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		raw.hits.Add(1)
		if status := raw.status.Load(); status != 0 {
			w.WriteHeader(int(status))
		}
		_, _ = w.Write([]byte(raw.body.Load().(string)))
	}))
	t.Cleanup(raw.srv.Close)
	return raw
}

// TestVertexNegative_NonStreamUpstreamErrorSurfaced pins the quota/permission
// refusal contract for non-streaming responses: a 200 body carrying a Google
// error object surfaces the provider's own status and message — it is never
// translated into a successful chat completion and never misreported as the
// vaguer "no candidates" (the error must not be hidden).
func TestVertexNegative_NonStreamUpstreamErrorSurfaced(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, body, wantErr string
	}{
		{
			name:    "quota exhausted",
			body:    `{"error":{"code":429,"message":"quota exceeded for the current request budget","status":"RESOURCE_EXHAUSTED"}}`,
			wantErr: "RESOURCE_EXHAUSTED",
		},
		{
			name:    "permission refused",
			body:    `{"error":{"code":403,"message":"caller lacks the aiplatform.endpoints.predict permission","status":"PERMISSION_DENIED"}}`,
			wantErr: "PERMISSION_DENIED",
		},
		{
			// The error object dominates: candidates alongside it are never
			// translated into a half-successful response.
			name:    "error object wins over candidates",
			body:    `{"error":{"code":500,"message":"internal failure","status":"INTERNAL"},"candidates":[{"content":{"parts":[{"text":"partial"}]},"finishReason":"STOP"}]}`,
			wantErr: "internal failure",
		},
	}
	for _, tc := range cases {
		out, err := (*Vertex)(nil).TranslateResponse([]byte(tc.body))
		if err == nil {
			t.Errorf("%s: TranslateResponse succeeded with %q, want the upstream error surfaced", tc.name, out)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
		if strings.Contains(err.Error(), "no candidates") {
			t.Errorf("%s: error = %q hides the upstream refusal behind the no-candidates fallback", tc.name, err)
		}
	}

	// Control: a refusal-free body still translates (the surfacing check
	// must not swallow well-formed completions).
	if _, err := (*Vertex)(nil).TranslateResponse([]byte(
		`{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`)); err != nil {
		t.Errorf("refusal-free body rejected: %v", err)
	}
}

// TestVertexNegative_ProjectMismatch_NoForeignToken pins the packet's core
// negative end-to-end: one shared adapter, one ambient ADC credential, many
// org bindings. A binding whose token exchange is refused never receives —
// or is never served — another binding's token, for project mismatches and
// location mismatches alike, under concurrency; and each binding heals on
// its own without disturbing the others' cached tokens.
func TestVertexNegative_ProjectMismatch_NoForeignToken(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()

	const openaiBody = `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`
	envelope := mustTranslate(t, v, openaiBody)
	projA := rig.credsJSON                                           // api-proj-0001 / us-central1
	projB := `{"project":"api-proj-0002","location":"us-central1"}`  // refused org: different project
	projC := `{"project":"api-proj-0001","location":"europe-west4"}` // mismatched location, same project

	// Warm binding A so its token lives in the cache before the refusal
	// phase: any later A request must be served from that cache only.
	req, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projA, false)
	if err != nil {
		t.Fatalf("warm projA: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer VT-1" {
		t.Fatalf("warm projA authorization = %q", got)
	}
	baseline := rig.tokenSrv.hits.Load()
	if baseline != 1 {
		t.Fatalf("warm exchange hits = %d, want 1", baseline)
	}

	// The token endpoint now refuses every exchange (invalid/revoked
	// credential class): B and C must attempt their OWN exchange and fail
	// closed — never ride A's cached token.
	rig.tokenSrv.status.Store(http.StatusForbidden)

	const callers = 12
	var wg sync.WaitGroup
	auths := make([]string, callers)
	errsB := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			r, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projA, false)
			if err == nil {
				auths[i] = r.Header.Get("Authorization")
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			_, errsB[i] = v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projB, false)
		}(i)
	}
	wg.Wait()

	for i, auth := range auths {
		if auth != "Bearer VT-1" {
			t.Fatalf("concurrent projA caller %d authorization = %q, want the binding's own cached token", i, auth)
		}
	}
	for i, err := range errsB {
		if err == nil {
			t.Fatalf("concurrent projB caller %d succeeded; a refused binding must never reuse a foreign token", i)
		}
		if !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("concurrent projB caller %d error = %v, want the refused exchange surfaced", i, err)
		}
		if strings.Contains(err.Error(), "VT-1") {
			t.Fatalf("concurrent projB caller %d error leaks the foreign token: %v", i, err)
		}
	}
	// B's exchange was genuinely attempted at the token endpoint (at least
	// one own wave) — the failure is the real refusal, not a cache serving.
	if afterB := rig.tokenSrv.hits.Load(); afterB <= baseline {
		t.Fatalf("token endpoint hits after refused projB = %d, want > %d (own exchange attempted)", afterB, baseline)
	}

	// Location mismatch: same project, different region — still its own
	// binding, its own refused exchange, exactly one more attempt.
	if _, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projC, false); err == nil ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("projC (location mismatch) error = %v, want the refused own exchange", err)
	}
	afterC := rig.tokenSrv.hits.Load()

	// The refusal heals: B's next exchange succeeds with the NEW token,
	// while A still rides ITS OWN cached VT-1 — tokens never cross the
	// binding boundary in either direction.
	rig.tokenSrv.status.Store(0)
	rig.tokenSrv.bodyToken.Store("VT-2")
	reqB, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projB, false)
	if err != nil {
		t.Fatalf("projB recovery: %v", err)
	}
	if got := reqB.Header.Get("Authorization"); got != "Bearer VT-2" {
		t.Fatalf("projB recovery authorization = %q, want the freshly exchanged token", got)
	}
	reqA, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projA, false)
	if err != nil {
		t.Fatalf("projA after recovery: %v", err)
	}
	if got := reqA.Header.Get("Authorization"); got != "Bearer VT-1" {
		t.Fatalf("projA authorization after projB recovery = %q, want projA's own cached token", got)
	}
	if hits := rig.tokenSrv.hits.Load(); hits != afterC+1 {
		t.Fatalf("token endpoint hits = %d, want %d (one recovery exchange for projB; projA stays cached)", hits, afterC+1)
	}
}

// TestVertexNegative_TokenCooldownIsolatedPerBinding pins the quota
// containment: a rate-limited token exchange parks ONLY its own binding
// behind the cooldown — sibling bindings keep exchanging normally and a
// healthy binding keeps riding its cache.
func TestVertexNegative_TokenCooldownIsolatedPerBinding(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)

	bindA := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}
	bindB := VertexCredentials{Project: "api-proj-0002", Location: "us-central1"}
	bindC := VertexCredentials{Project: "api-proj-0003", Location: "europe-west4"}

	if tok, err := adc.token(bindA); err != nil || tok != "VT-1" {
		t.Fatalf("warm bindA: token %q err %v", tok, err)
	}

	tokenSrv.status.Store(http.StatusTooManyRequests)
	tokenSrv.retryAft.Store("60")
	if _, err := adc.token(bindB); err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("bindB error = %v, want the 429 surfaced", err)
	}
	if _, err := adc.token(bindB); err == nil || !strings.Contains(err.Error(), "retry allowed in") {
		t.Fatalf("bindB retry error = %v, want the fail-fast cooldown", err)
	}

	// Other bindings are untouched by B's cooldown: C exchanges normally.
	tokenSrv.status.Store(0)
	tok, err := adc.token(bindC)
	if err != nil || tok != "VT-1" {
		t.Fatalf("bindC during bindB cooldown: token %q err %v", tok, err)
	}
	// B's own cooldown persists (bounded), A's cache is unaffected.
	if _, err := adc.token(bindB); err == nil || !strings.Contains(err.Error(), "retry allowed in") {
		t.Fatalf("bindB after heal error = %v, want the still-active own cooldown", err)
	}
	if tok, err := adc.token(bindA); err != nil || tok != "VT-1" {
		t.Fatalf("bindA cache: token %q err %v", tok, err)
	}
	if hits := tokenSrv.hits.Load(); hits != 3 {
		t.Fatalf("token endpoint hits = %d, want 3 (A warm, B refused, C exchange; fail-fasts add none)", hits)
	}
}

// TestVertexNegative_InvalidSAKey_NoFallback pins the exchange-time
// credential failure: a structurally valid key file whose private_key is
// not PEM material fails closed at signing — no token is posted anywhere,
// and neither the weaker well-known user credential nor the metadata
// server is consulted (the resolved source is never silently swapped).
func TestVertexNegative_InvalidSAKey_NoFallback(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t) // would serve the SA exchange
	userSrv := newVertexTokenRecorder(t)  // would serve the user grant
	metadataSrv := newVertexTokenRecorder(t)

	file := map[string]string{
		"type":         "service_account",
		"client_email": "vertex-test-sa@api-proj-0001.iam.gserviceaccount.com",
		"private_key":  "definitely not a PEM block",
		"token_uri":    tokenSrv.srv.URL,
	}
	path := filepath.Join(t.TempDir(), "broken-key.json")
	if err := os.WriteFile(path, marshalVertexJSON(t, file), 0o600); err != nil {
		t.Fatalf("write broken key: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	home := t.TempDir()
	writeVertexUserKeyFile(t, home) // the weaker source sits RIGHT THERE
	vertexSwapHome(t, home, nil)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL
	adc.metadataURL = metadataSrv.srv.URL
	adc.metadataClient = metadataSrv.srv.Client()

	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}
	for i := 1; i <= 2; i++ {
		_, err := adc.token(creds)
		if err == nil || !strings.Contains(err.Error(), "ADC service-account key unusable") ||
			!strings.Contains(err.Error(), "not PEM-encoded") {
			t.Fatalf("call %d error = %v, want the precise signing failure", i, err)
		}
		if tokenSrv.hits.Load() != 0 || userSrv.hits.Load() != 0 || metadataSrv.hits.Load() != 0 {
			t.Fatalf("call %d endpoint hits SA=%d user=%d meta=%d; an unusable key must not post anywhere",
				i, tokenSrv.hits.Load(), userSrv.hits.Load(), metadataSrv.hits.Load())
		}
	}
}

// TestVertexNegative_UserTokenRefused_NoKeylessFallback pins the refused
// authorized_user grant: the token endpoint rejects the refresh token
// (revoked/expired credential class) with 400 — the failure surfaces with
// its status code and never degrades into the keyless metadata server.
func TestVertexNegative_UserTokenRefused_NoKeylessFallback(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.status.Store(http.StatusBadRequest) // invalid_grant class
	metadataSrv := newVertexTokenRecorder(t)

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = tokenSrv.srv.URL
	adc.metadataURL = metadataSrv.srv.URL
	adc.metadataClient = metadataSrv.srv.Client()

	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}
	for i := 1; i <= 2; i++ {
		_, err := adc.token(creds)
		if err == nil || !strings.Contains(err.Error(), "token exchange HTTP 400") {
			t.Fatalf("call %d error = %v, want the refused grant surfaced with its status", i, err)
		}
		if metadataSrv.hits.Load() != 0 {
			t.Fatalf("call %d metadata hits = %d; a refused user grant must not go keyless", i, metadataSrv.hits.Load())
		}
	}
	if hits := tokenSrv.hits.Load(); hits != 2 {
		t.Fatalf("token endpoint hits = %d, want 2 (each request re-attempts its own grant)", hits)
	}
}

// TestVertexNegative_MalformedTokenResponse_Recoverable pins malformed
// token-endpoint payloads: garbage JSON and an empty access_token fail
// closed with the precise decode error, are never cached, and the binding
// recovers on the next healthy exchange without an adapter restart.
func TestVertexNegative_MalformedTokenResponse_Recoverable(t *testing.T) {
	raw := newVertexRawTokenServer(t)
	keyPath, _, _ := writeVertexSAKeyFile(t, raw.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(raw.srv)

	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	raw.body.Store("not-json at all")
	if _, err := adc.token(creds); err == nil || !strings.Contains(err.Error(), "decode token response") {
		t.Fatalf("garbage body error = %v, want the decode failure", err)
	}
	raw.body.Store("{}")
	if _, err := adc.token(creds); err == nil || !strings.Contains(err.Error(), "empty access_token") {
		t.Fatalf("empty-token body error = %v, want the empty access_token failure", err)
	}
	if hits := raw.hits.Load(); hits != 2 {
		t.Fatalf("token endpoint hits = %d, want 2 failed exchanges", hits)
	}

	// The malformed responses left nothing in the cache: the healthy
	// exchange happens, and the second request rides it.
	raw.body.Store(`{"access_token":"VT-OK","expires_in":3600}`)
	for i := 1; i <= 2; i++ {
		tok, err := adc.token(creds)
		if err != nil || tok != "VT-OK" {
			t.Fatalf("call %d: token %q err %v, want the healthy VT-OK", i, tok, err)
		}
	}
	if hits := raw.hits.Load(); hits != 3 {
		t.Fatalf("token endpoint hits = %d, want 3 (failures never cached)", hits)
	}
}

// TestVertexNegative_EnvCredentialsDirectory_NoFallback pins the unreadable
// explicit source: GOOGLE_APPLICATION_CREDENTIALS pointing at a directory
// is a hard failure — the well-known user credential sitting next to it is
// never consulted.
func TestVertexNegative_EnvCredentialsDirectory_NoFallback(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	userSrv := newVertexTokenRecorder(t)

	dir := filepath.Join(t.TempDir(), "creds-directory")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", dir)

	home := t.TempDir()
	writeVertexUserKeyFile(t, home)
	vertexSwapHome(t, home, nil)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL

	_, err := adc.token(VertexCredentials{Project: "api-proj-0001", Location: "us-central1"})
	if err == nil || !strings.Contains(err.Error(), "key file unreadable") ||
		!strings.Contains(err.Error(), "no fallback") {
		t.Fatalf("error = %v, want the unreadable-source hard failure", err)
	}
	if userSrv.hits.Load() != 0 {
		t.Fatalf("user token endpoint hit %d times; an unreadable explicit source must not fall through", userSrv.hits.Load())
	}
}

// marshalVertexJSON is a tiny helper keeping the negative battery's fixture
// writes noise-free (map → JSON bytes).
func marshalVertexJSON(t *testing.T, file map[string]string) []byte {
	t.Helper()
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

// TestVertexNegative_StreamOversizedLineFailsClosed pins the hostile-stream
// bound: a single SSE line beyond maxStreamLineBytes fails the handler with
// the read error — the oversized frame is not decoded, nothing is written
// to the client, and no unbounded buffering happens.
func TestVertexNegative_StreamOversizedLineFailsClosed(t *testing.T) {
	t.Parallel()

	oversized := "data: " + strings.Repeat("x", 2<<20) + "\n\n"
	resp := newSSEResponse(oversized)
	defer resp.Body.Close()
	w, buf := newRecorder()

	_, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
	if err == nil {
		t.Fatal("oversized SSE line must fail the stream handler")
	}
	if !strings.Contains(err.Error(), "stream read failed") || !strings.Contains(err.Error(), "token too long") {
		t.Fatalf("error = %v, want the bounded-reader failure", err)
	}
	if out := buf.String(); out != "" {
		t.Fatalf("client received %q before the failure; an undecodable frame must not be translated", out)
	}
}

// TestVertexNegative_LookupRejectYieldsZeroCaps pins the capability-matrix
// reject shape: every refused (model, region) pair returns the ZERO
// capability set — a rejection never leaks a partial answer from another
// family's row or another region's acceptance.
func TestVertexNegative_LookupRejectYieldsZeroCaps(t *testing.T) {
	t.Parallel()

	rejects := []struct{ model, location string }{
		{"gemini-1.5-pro", "global"},               // right family, wrong region class
		{"imagen-3.0-generate-001", "us-central1"}, // family outside the matrix
		{"gemini-2.5-flash", "moon-base1"},         // right family, unverified region
		{"", "us-central1"},                        // missing model
		{"gemini-2.5-flash", ""},                   // missing region
	}
	for _, tc := range rejects {
		caps, err := VertexLookup(tc.model, tc.location)
		if err == nil {
			t.Errorf("VertexLookup(%q,%q) = %+v, want rejection", tc.model, tc.location, caps)
			continue
		}
		if caps != (VertexCapabilities{}) {
			t.Errorf("VertexLookup(%q,%q) caps = %+v, want the zero set on rejection", tc.model, tc.location, caps)
		}
	}
}
