package callout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// testAllowHost is the allow-list entry matching httptest loopback servers.
const testAllowHost = "127.0.0.1"

// newTestRuntimeAt builds a Runtime whose allow-list admits httptest
// loopback endpoints. Loopback is a reserved address, so the production
// guarded dialer can never reach it; the tests swap the transport dialer
// for a plain one through the same newClient seam — the reserved-IP guard
// itself is exercised separately (TestGuard_BlocksReservedDial) with the
// real client.
func newTestRuntimeAt(t *testing.T) *Runtime {
	t.Helper()
	rt, err := New(Deps{
		AllowHosts: []string{testAllowHost},
		Timeout:    2 * time.Second,
		Breaker:    testBreakerConfig(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	plain := &net.Dialer{Timeout: 2 * time.Second}
	rt.client = newClient(Deps{Timeout: 2 * time.Second}, plain.DialContext)
	return rt
}

// testBreakerConfig is a deterministic breaker for tests: opens after 2
// failures and does not half-open during a test run.
func testBreakerConfig() *circuit.Config {
	return &circuit.Config{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}
}

// msgPayload builds a request payload with the given message contents.
func msgPayload(contents ...string) *pipeline.Payload {
	msgs := make([]pipeline.Message, len(contents))
	for i, c := range contents {
		msgs[i] = pipeline.Message{Role: "user", Content: c}
	}
	return &pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: "chat", Messages: msgs}
}

// bodyPayload builds a response payload with a raw JSON body.
func bodyPayload(body string) *pipeline.Payload {
	return &pipeline.Payload{Kind: pipeline.KindResponse, Endpoint: "chat", Body: []byte(body)}
}

// stepYAML renders one callout-kind step with the given extra params.
func stepYAML(id, url string, params string) string {
	return fmt.Sprintf("  - id: %s\n    callout: %q\n    params:\n      %s", id, url, params)
}

// policyYAML wraps steps into a full policy document.
func policyYAML(mode string, steps string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: %s
hooks: [pre_upstream]
steps:
%s
`, mode, steps))
}

// compileWith loads a policy into an engine wired with rt's factories.
func compileWith(t *testing.T, rt *Runtime, policy []byte) pipeline.Compiled {
	t.Helper()
	eng := pipeline.NewEngine()
	if err := rt.RegisterAll(eng.Steps()); err != nil {
		t.Fatalf("register factories: %v", err)
	}
	comp, err := eng.LoadPolicy(policy)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return comp
}

// runOne executes one compiled policy against the payload.
func runOne(t *testing.T, comp pipeline.Compiled, in *pipeline.Payload) *pipeline.Result {
	t.Helper()
	eng := pipeline.NewEngine()
	return eng.Run(context.Background(), []pipeline.Compiled{comp}, in)
}

// recorder is a test scanner server: it records every request and replies
// per call through respond.
type recorder struct {
	requests atomic.Int32
	respond  func(seq int, r *http.Request) (status int, ctype string, out string)

	mu     sync.Mutex
	body   []byte
	method string
	ua     string
}

// server starts the recorder on an httptest server (registered for cleanup).
func (rec *recorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(rec.requests.Add(1))
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.body, rec.method, rec.ua = body, r.Method, r.Header.Get("User-Agent")
		rec.mu.Unlock()
		status, ctype, out := rec.respond(n, r)
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// envelope is the decoded callout request.
type envelope struct {
	Expose  string          `json:"expose"`
	Content json.RawMessage `json:"content"`
}

func decodeEnvelope(t *testing.T, b []byte) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("decode callout request %q: %v", b, err)
	}
	return e
}

// findingsResponse renders a findings-mode scanner response; without
// arguments it is the empty findings array (not null — the parser is
// contract-strict about null).
func findingsResponse(fs ...map[string]any) string {
	list := fs
	if list == nil {
		list = []map[string]any{}
	}
	b, _ := json.Marshal(map[string]any{"findings": list})
	return string(b)
}

// echo finds the step id used across single-step tests.
const testStepID = "call"
