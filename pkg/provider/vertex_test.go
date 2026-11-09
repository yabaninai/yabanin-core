package provider

// Adapter-level tests for the native Vertex AI provider: factory wiring,
// credential parsing, endpoint construction, the mocked ADC-authenticated
// request flow, the project/audience binding negative, capability gates,
// fail-closed boundaries and usage parsing.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVertexFactory(t *testing.T) {
	t.Parallel()

	p, err := New("vertex")
	if err != nil {
		t.Fatalf("New(vertex): %v", err)
	}
	v, ok := p.(*Vertex)
	if !ok {
		t.Fatalf("New(vertex) = %T, want *Vertex", p)
	}
	if v.Name() != "vertex" {
		t.Fatalf("Name = %q", v.Name())
	}
	path := v.Path(false)
	if !strings.Contains(path, "/v1/projects/{project}/") ||
		!strings.Contains(path, "/locations/{location}/") ||
		!strings.Contains(path, "models/{model}:") {
		t.Fatalf("Path = %q, want the project/location/model template", path)
	}
}

func TestParseVertexCredentials(t *testing.T) {
	t.Parallel()

	errCases := []struct{ name, in, wantErr string }{
		{"not json", `project=api-proj-0001`, "credentials must be JSON"},
		{"missing project", `{"location":"eu"}`, "missing project"},
		{"missing location", `{"project":"api-proj-0001"}`, "missing location"},
		{"uppercase project", `{"project":"Api-Proj-0001","location":"eu"}`, "not a valid Google project ID"},
		{"too short project", `{"project":"ab1","location":"eu"}`, "not a valid Google project ID"},
		{"leading digit project", `{"project":"1api-proj","location":"eu"}`, "not a valid Google project ID"},
		{"path traversal project", `{"project":"../../etc","location":"eu"}`, "not a valid Google project ID"},
		{"slash in project", `{"project":"a/b/c-xyz","location":"eu"}`, "not a valid Google project ID"},
		{"31 char project", `{"project":"` + strings.Repeat("a", 31) + `","location":"eu"}`, "not a valid Google project ID"},
		{"uppercase location", `{"project":"api-proj-0001","location":"US"}`, "not a valid Vertex location"},
		{"space in location", `{"project":"api-proj-0001","location":"us central1"}`, "not a valid Vertex location"},
		{"traversal location", `{"project":"api-proj-0001","location":"../eu"}`, "not a valid Vertex location"},
		{"empty everything", `{}`, "missing project"},
	}
	for _, tc := range errCases {
		_, err := ParseVertexCredentials(tc.in)
		if err == nil {
			t.Errorf("%s: ParseVertexCredentials(%q) = nil error", tc.name, tc.in)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
		// Values never appear in parse errors (tenant-identifying input).
		for _, forbidden := range []string{"api-proj-0001", "us-central1"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("%s: error leaks value %q: %v", tc.name, forbidden, err)
			}
		}
	}

	c, err := ParseVertexCredentials(`{"project":"api-proj-0001","location":"us-central1"}`)
	if err != nil {
		t.Fatalf("valid blob: %v", err)
	}
	if c.Project != "api-proj-0001" || c.Location != "us-central1" {
		t.Fatalf("creds = %+v", c)
	}
}

func TestVertexUpstreamURLConstruction(t *testing.T) {
	t.Parallel()

	// Empty baseURL → canonical location-derived host.
	got, err := vertexUpstreamURL("", "us-central1", VertexEndpoint("api-proj-0001", "us-central1", "gemini-2.0-flash", false))
	if err != nil {
		t.Fatalf("empty baseURL: %v", err)
	}
	want := "https://us-central1-aiplatform.googleapis.com" +
		"/v1/projects/api-proj-0001/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent"
	if got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
	got, _ = vertexUpstreamURL("", "global", VertexEndpoint("api-proj-0001", "global", "gemini-2.5-pro", false))
	if !strings.HasPrefix(got, "https://aiplatform.googleapis.com/v1/") {
		t.Fatalf("global url = %q", got)
	}

	// Configured baseURL (test rigs / private gateways) is used verbatim.
	got, err = vertexUpstreamURL("http://127.0.0.1:8443/", "us-central1", "/v1/x")
	if err != nil {
		t.Fatalf("baseURL override: %v", err)
	}
	if got != "http://127.0.0.1:8443/v1/x" {
		t.Fatalf("override url = %q", got)
	}

	errCases := []string{"us-central1-aiplatform.googleapis.com", "ftp://x.example", "://nope"}
	for _, in := range errCases {
		if _, err := vertexUpstreamURL(in, "us-central1", "/v1/x"); err == nil {
			t.Errorf("vertexUpstreamURL(%q) = nil error, want absolute-http(s) rejection", in)
		}
	}
}

// vertexChatRig is the full mocked environment: SA key file (token_uri →
// tokenSrv), chat server capturing the final Vertex request, and an adapter
// whose exchange client points at the test double (loopback, no SSRF guard).
type vertexChatRig struct {
	tokenSrv  *vertexTokenRecorder
	chatSrv   *httptest.Server
	chatHits  atomic.Int64
	chatPath  atomic.Value // string
	chatAuth  atomic.Value // string
	chatBody  atomic.Value // []byte
	keyPath   string
	credsJSON string
}

func newVertexChatRig(t *testing.T) *vertexChatRig {
	t.Helper()
	rig := &vertexChatRig{}
	rig.tokenSrv = newVertexTokenRecorder(t)
	rig.keyPath, _, _ = writeVertexSAKeyFile(t, rig.tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", rig.keyPath)

	rig.chatSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.chatHits.Add(1)
		rig.chatPath.Store(r.URL.Path)
		rig.chatAuth.Store(r.Header.Get("Authorization"))
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rig.chatBody.Store(body)
		// Gemini-shaped reply; ParseUsage exercises usageMetadata.
		_, _ = w.Write([]byte(`{"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":3,"totalTokenCount":15}}`))
	}))
	t.Cleanup(rig.chatSrv.Close)

	rig.credsJSON = `{"project":"api-proj-0001","location":"us-central1"}`
	return rig
}

func (r *vertexChatRig) adapter() *Vertex {
	adc := plainVertexADC(r.tokenSrv.srv)
	return NewVertexWithSource(adc)
}

func (r *vertexChatRig) chatSnapshot(t *testing.T) (path, auth string, body []byte) {
	t.Helper()
	p, ok := r.chatPath.Load().(string)
	if !ok {
		t.Fatal("no chat request captured")
	}
	return p, r.chatAuth.Load().(string), r.chatBody.Load().([]byte)
}

// mustTranslate converts an OpenAI chat body into the vertex envelope,
// failing the test on error.
func mustTranslate(t *testing.T, v *Vertex, openaiBody string) []byte {
	t.Helper()
	env, err := v.TranslateRequest([]byte(openaiBody))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	return env
}

// overrideEnvelopeModel mirrors the upstream client's overrideModel rewrite
// (map round-trip setting the top-level "model" key) without importing the
// upstream package (which would cycle in provider tests).
func overrideEnvelopeModel(t *testing.T, envelope []byte, model string) []byte {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(envelope, &raw); err != nil {
		t.Fatalf("overrideEnvelopeModel: %v", err)
	}
	raw["model"] = model
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("overrideEnvelopeModel marshal: %v", err)
	}
	return out
}

// TestVertexPrepareRequest_MockedAuth is the happy-path pin: translation →
// per-hop model override → capability lookup → ADC exchange → project/
// location URL → Bearer → inner generateContent body on the wire, with the
// token cached across requests.
func TestVertexPrepareRequest_MockedAuth(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()

	clientBody := `{"model":"whatever-client-said","messages":[{"role":"user","content":"hi"}],"max_tokens":64}`
	envelope := overrideEnvelopeModel(t, mustTranslate(t, v, clientBody), "gemini-2.0-flash")
	req, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, rig.credsJSON, false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	// PrepareRequest constructs; the upstream client sends. Exercise the
	// full mocked flow so the rig's captures reflect a real round-trip.
	resp, err := rig.chatSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(reply), "usageMetadata") {
		t.Fatalf("chat reply = %q, want the Gemini-shaped body passed through", reply)
	}

	wantPath := "/v1/projects/api-proj-0001/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent"
	gotPath, gotAuth, gotBody := rig.chatSnapshot(t)
	if req.URL.String() != rig.chatSrv.URL+wantPath {
		t.Fatalf("request URL = %q, want %q", req.URL.String(), rig.chatSrv.URL+wantPath)
	}
	if gotPath != wantPath {
		t.Fatalf("server saw path %q, want %q", gotPath, wantPath)
	}
	if gotAuth != "Bearer VT-1" {
		t.Fatalf("Authorization = %q, want the ADC Bearer token", gotAuth)
	}
	// The wire body must be the inner generateContent payload only: the
	// envelope (and the client's original model name) never reaches the
	// upstream, and the Gemini schema rejects unknown top-level fields.
	// The comparison is semantic (JSONEq): the gateway's model override
	// round-trips the envelope through a generic map, which re-serializes
	// object keys in sorted order — key order is not part of the JSON wire
	// contract.
	assert.JSONEq(t,
		`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":64}}`,
		string(gotBody))
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", req.Header.Get("Content-Type"))
	}

	// Token exchange form: JWT-bearer grant signed by the key file's SA.
	form := rig.tokenSrv.form(t)
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("grant_type = %q", form.Get("grant_type"))
	}
	claims := decodeVertexJWTPart(t, form.Get("assertion"), 1)
	if claims["iss"] != "vertex-test-sa@api-proj-0001.iam.gserviceaccount.com" {
		t.Fatalf("JWT iss = %v", claims["iss"])
	}
	if claims["scope"] != vertexCloudPlatformScope {
		t.Fatalf("JWT scope = %v", claims["scope"])
	}

	// Cache: a second request must not re-exchange.
	if _, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, rig.credsJSON, false); err != nil {
		t.Fatalf("second PrepareRequest: %v", err)
	}
	if rig.tokenSrv.hits.Load() != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cache)", rig.tokenSrv.hits.Load())
	}
}

// TestVertexTokenBindingPerProjectLocation is the packet negative: a token
// minted for one (project, location) is never handed to another binding,
// even though the ambient ADC credential is identical.
func TestVertexTokenBindingPerProjectLocation(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()

	projA := `{"project":"api-proj-0001","location":"us-central1"}`
	projB := `{"project":"api-proj-0002","location":"us-central1"}`
	envelope := mustTranslate(t, v, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`)

	if _, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projA, false); err != nil {
		t.Fatalf("projA first: %v", err)
	}

	// Now the token endpoint rejects everything; projB must attempt (and
	// fail) its own exchange instead of reusing projA's cached token.
	rig.tokenSrv.status.Store(http.StatusUnauthorized)
	if _, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projB, false); err == nil {
		t.Fatal("projB must not reuse projA's token")
	}
	if rig.tokenSrv.hits.Load() != 2 {
		t.Fatalf("token hits = %d, want 2 (separate exchanges per binding)", rig.tokenSrv.hits.Load())
	}

	// projA still rides its cache: no third exchange.
	if _, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, projA, false); err != nil {
		t.Fatalf("projA cache: %v", err)
	}
	if rig.tokenSrv.hits.Load() != 2 {
		t.Fatalf("token hits = %d, projA must be cache-hit", rig.tokenSrv.hits.Load())
	}
}

// TestVertexPrepareRequest_FailClosed pins precise rejections BEFORE any
// credential or network work (I51: no silent downgrades, no wasted auth).
func TestVertexPrepareRequest_FailClosed(t *testing.T) {
	rig := newVertexChatRig(t)
	v := rig.adapter()

	// rawRequest bodies skip TranslateRequest: PrepareRequest must refuse
	// them (foreign schema on the wire would be a silent downgrade).
	rawCases := []struct {
		name, creds, body string
		stream            bool
		wantErr           string
	}{
		// A JSON object with a model but no gemini payload is the
		// foreign-schema case; non-JSON input hits the envelope refusal.
		{"raw openai body", rig.credsJSON, `{"model":"gemini-2.0-flash","messages":[]}`, false, "envelope has no gemini payload"},
		{"raw body not json", rig.credsJSON, `nope`, false, "not a vertex envelope; TranslateRequest must run first"},
		{"raw body without model", rig.credsJSON, `{"messages":[{"role":"user","content":"hi"}]}`, false, "envelope has no model"},
	}
	for _, tc := range rawCases {
		_, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), []byte(tc.body), tc.creds, tc.stream)
		if err == nil {
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
	}

	cases := []struct {
		name, creds, openaiBody string
		stream                  bool
		wantErr                 string
	}{
		{"bad creds", `not-json`, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`, false, "credentials must be JSON"},
		{"unknown model", rig.credsJSON, `{"model":"imagen-3.0-generate-001","messages":[{"role":"user","content":"hi"}]}`, false, `model "imagen-3.0-generate-001" is not in the capability matrix`},
		{"1.5 on global", `{"project":"api-proj-0001","location":"global"}`, `{"model":"gemini-1.5-pro","messages":[{"role":"user","content":"hi"}]}`, false, `location "global" is not served for model family "gemini-1.5-"`},
		{"model with path separators", rig.credsJSON, `{"model":"../etc/passwd","messages":[{"role":"user","content":"hi"}]}`, false, "URL path separators"},
	}
	for _, tc := range cases {
		body := mustTranslate(t, v, tc.openaiBody)
		_, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), body, tc.creds, tc.stream)
		if err == nil {
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
	}
	if rig.tokenSrv.hits.Load() != 0 || rig.chatHits.Load() != 0 {
		t.Fatalf("fail-closed cases must not touch the network: token=%d chat=%d",
			rig.tokenSrv.hits.Load(), rig.chatHits.Load())
	}
}

// TestVertexCapabilityGate pins the matrix-driven per-family gates without
// mutating the shared matrix: a stream request against a non-streaming
// family and a tool-bearing request against a non-tool family reject.
func TestVertexCapabilityGate(t *testing.T) {
	t.Parallel()

	full := VertexCapabilities{Streaming: true, Tools: true}
	noStream := VertexCapabilities{Tools: true}
	noTools := VertexCapabilities{Streaming: true}

	if err := vertexCapabilityGate("m", full, true, true); err != nil {
		t.Fatalf("full-caps family: %v", err)
	}
	err := vertexCapabilityGate("m", noStream, true, false)
	if err == nil || !strings.Contains(err.Error(), "does not support streaming") {
		t.Fatalf("stream gate = %v, want streaming rejection", err)
	}
	err = vertexCapabilityGate("m", noTools, false, true)
	if err == nil || !strings.Contains(err.Error(), "does not support tool calling") {
		t.Fatalf("tools gate = %v, want tools rejection", err)
	}
	// Non-stream request against a streaming-capable family: fine.
	if err := vertexCapabilityGate("m", full, false, true); err != nil {
		t.Fatalf("non-stream full-caps: %v", err)
	}
}

// TestVertexPrepareRequest_AuthFailureNoLeak pins the secret discipline:
// exchange failures carry status codes only — never key material.
func TestVertexPrepareRequest_AuthFailureNoLeak(t *testing.T) {
	rig := newVertexChatRig(t)
	rig.tokenSrv.status.Store(http.StatusInternalServerError)
	v := rig.adapter()

	envelope := mustTranslate(t, v, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`)
	_, err := v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false), envelope, rig.credsJSON, false)
	if err == nil {
		t.Fatal("500 from token endpoint must fail closed")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "vertex-test-sa@", "VT-", "api-proj-0001"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaks %q: %v", forbidden, err)
		}
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("error = %v, want the status code only", err)
	}
}

// TestVertexTokenSingleflightConcurrent pins the shared-exchange behavior:
// N concurrent cold callers on one binding produce exactly one token
// exchange (azure precedent).
func TestVertexTokenSingleflightConcurrent(t *testing.T) {
	rig := newVertexChatRig(t)
	rig.tokenSrv.delay.Store(80) // widen the race window
	v := rig.adapter()

	envelope := mustTranslate(t, v, `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`)
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = v.PrepareRequest(context.Background(), rig.chatSrv.URL, v.Path(false),
				envelope, rig.credsJSON, false)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if hits := rig.tokenSrv.hits.Load(); hits != 1 {
		t.Fatalf("token endpoint hits = %d, want exactly 1 under concurrency", hits)
	}
}

func TestVertexParseUsage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want Usage
	}{
		{
			name: "native full usageMetadata",
			in:   `{"usageMetadata":{"promptTokenCount":120,"candidatesTokenCount":30,"totalTokenCount":150,"cachedContentTokenCount":8}}`,
			want: Usage{PromptTokens: 120, CompletionTokens: 30, TotalTokens: 150, CacheReadTokens: 8, Source: UsageSourceProvider},
		},
		{
			name: "native total falls back to prompt+completion",
			in:   `{"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":3}}`,
			want: Usage{PromptTokens: 12, CompletionTokens: 3, TotalTokens: 15, Source: UsageSourceProvider},
		},
		{
			// The gateway parses usage from the TRANSLATED chat.completion
			// body — the OpenAI-contract shape must parse identically.
			name: "translated openai shape",
			in:   `{"id":"chatcmpl-vertex-x","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150,"prompt_tokens_details":{"cached_tokens":8}}}`,
			want: Usage{PromptTokens: 120, CompletionTokens: 30, TotalTokens: 150, CacheReadTokens: 8, Source: UsageSourceProvider},
		},
		{
			name: "translated without details",
			in:   `{"usage":{"prompt_tokens":12,"completion_tokens":3}}`,
			want: Usage{PromptTokens: 12, CompletionTokens: 3, TotalTokens: 15, Source: UsageSourceProvider},
		},
		{
			name: "usage block without prompt_tokens is not metering",
			in:   `{"usage":{"completion_tokens":3}}`,
			want: Usage{Source: UsageSourceNone},
		},
		{
			name: "error body without usage",
			in:   `{"error":{"code":429,"message":"quota"}}`,
			want: Usage{Source: UsageSourceNone},
		},
		{
			name: "not json",
			in:   `nope`,
			want: Usage{Source: UsageSourceNone},
		},
	}
	for _, tc := range cases {
		if got := (*Vertex)(nil).ParseUsage([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: ParseUsage = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
