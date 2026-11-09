package callout

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// guardIdentity is the versioned pack/rule identity used across adapter tests.
var guardIdentity = guardhooks.RuleVersion{PackID: "user.pack", PackVersion: "1.0.0", RuleID: "remote", RuleVersion: "1"}

// guardRespond renders a protocol-valid findings response body.
func guardRespond(version string, findings ...map[string]any) string {
	list := findings
	if list == nil {
		list = []map[string]any{}
	}
	b, _ := json.Marshal(map[string]any{"version": version, "findings": list})
	return string(b)
}

// newGuardRuntime builds a loopback-testable Runtime with the given breaker
// config (nil → package test default).
func newGuardRuntime(t *testing.T, breaker *circuit.Config, timeout time.Duration) *Runtime {
	t.Helper()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deps := Deps{AllowHosts: []string{testAllowHost}, Timeout: timeout, Breaker: breaker}
	rt, err := New(deps)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	plain := &net.Dialer{Timeout: timeout}
	rt.client = newClient(Deps{Timeout: timeout}, plain.DialContext)
	return rt
}

// newGuardDetector builds an approved adapter for the loopback server.
func newGuardDetector(t *testing.T, rt *Runtime, url string) *GuardDetector {
	t.Helper()
	d, err := rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: url})
	if err != nil {
		t.Fatalf("new guard detector: %v", err)
	}
	return d
}

// guardInvocation builds a versioned text invocation.
func guardInvocation(ctx context.Context, text string) guardhooks.Invocation {
	return guardhooks.Invocation{Context: ctx, Version: guardhooks.RuntimeVersion, Phase: guardhooks.PhaseBefore, Kind: guardhooks.ContentText, Text: text}
}

// TestGuardDetector_ConstructionValidation: an adapter is only built for a
// complete versioned identity and an endpoint the operator allow-list
// explicitly approves (rights boundary, N02-P04-T04/T10).
func TestGuardDetector_ConstructionValidation(t *testing.T) {
	rt := newGuardRuntime(t, nil, 0)
	for name, tc := range map[string]struct {
		cfg     GuardDetectorConfig
		wantErr string
	}{
		"identity missing": {
			GuardDetectorConfig{Endpoint: "http://127.0.0.1/x"},
			"complete versioned identity",
		},
		"scheme ftp": {
			GuardDetectorConfig{Identity: guardIdentity, Endpoint: "ftp://127.0.0.1/x"},
			"scheme must be http or https",
		},
		"userinfo": {
			// G101 false positive: the credential-bearing URL is the fixture
			// itself — the test asserts construction REJECTS it, proving
			// credentials can never travel in detector URLs.
			GuardDetectorConfig{Identity: guardIdentity, Endpoint: "http://u:p@127.0.0.1/x"}, //nolint:gosec // G101: rejection fixture, not a real credential
			"userinfo",
		},
		"no host": {
			GuardDetectorConfig{Identity: guardIdentity, Endpoint: "http:///x"},
			"host is required",
		},
		"fragment": {
			GuardDetectorConfig{Identity: guardIdentity, Endpoint: "http://127.0.0.1/x#f"},
			"fragment",
		},
		"foreign host": {
			GuardDetectorConfig{Identity: guardIdentity, Endpoint: "http://evil.example/scan"},
			"not in the callout egress allow-list",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := rt.NewGuardDetector(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
	d := newGuardDetector(t, rt, "http://127.0.0.1:9/scan?q=secret")
	if d.Identity() != guardIdentity {
		t.Fatalf("identity = %+v", d.Identity())
	}
	if d.cfg.endpoint != "http://127.0.0.1:9/scan" {
		t.Fatalf("endpoint key = %q (query must be dropped)", d.cfg.endpoint)
	}
}

// TestGuardDetector_ForeignHostPayloadNeverSent is the packet's negative
// scenario (N02-P04-T05): a secret never reaches an unapproved host, with an
// observable error — at the construction boundary (foreign host refused
// before anything can be sent) and at the dial boundary (an approved hostname
// resolving to a reserved IP refuses the connection and never dials).
func TestGuardDetector_ForeignHostPayloadNeverSent(t *testing.T) {
	const secret = "sk-supersecret-000000000000000"

	t.Run("construction/foreign-host", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		srv := rec.server(t) // the "foreign" target the payload must never reach
		// The operator allow-list approves only a different host, so the
		// server's loopback endpoint is unapproved for this runtime.
		rt, err := New(Deps{AllowHosts: []string{"detector.internal"}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("new runtime: %v", err)
		}
		_, err = rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: srv.URL})
		if err == nil || !strings.Contains(err.Error(), "not in the callout egress allow-list") {
			t.Fatalf("err = %v, want allow-list rejection", err)
		}
		if n := rec.requests.Load(); n != 0 {
			t.Fatalf("foreign host received %d requests", n)
		}
	})

	t.Run("dial/reserved-ip-hijack", func(t *testing.T) {
		var dials int
		rt, err := New(Deps{
			AllowHosts: []string{"detector.test"},
			Timeout:    time.Second,
			Lookup: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("169.254.169.254")}, nil // hijacked resolver
			},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dials++
				return nil, errors.New("must not dial")
			},
		})
		if err != nil {
			t.Fatalf("new runtime: %v", err)
		}
		d, err := rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: "http://detector.test/v1/detect"})
		if err != nil {
			t.Fatalf("approved host refused: %v", err)
		}
		findings, err := d.Detect(guardInvocation(context.Background(), "token "+secret))
		if err == nil {
			t.Fatalf("Detect() = %#v, want reserved-target error", findings)
		}
		if !errors.Is(err, ssrf.ErrReservedTarget) && !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("err = %v, want reserved-target refusal", err)
		}
		if dials != 0 {
			t.Fatalf("hijacked address was dialed %d times", dials)
		}
	})
}

// TestGuardDetector_JointContract is the shared-contract scenario
// (N02-P04-T06): deny / allow / timeout / malformed / recovery all flow
// through ONE path — the real adapter (real HTTP server) for the network
// rows and an explicitly-labeled mock stub for the verdict rows — and every
// probe failure maps through the same FailureOutcome contract (enforce ⇒
// deny+blocked, shadow ⇒ audit-only+not blocked), never to a silent allow.
func TestGuardDetector_JointContract(t *testing.T) {
	ctx := context.Background()

	// verdictThroughHook runs the findings/error through the exact guardhook
	// verdict contract a gateway request observes.
	verdictThroughHook := func(t *testing.T, mode guardhooks.Mode, findings []guardhooks.Finding, err error) (guardhooks.Verdict, bool) {
		t.Helper()
		if err != nil {
			v, blocked := guardhooks.FailureOutcome(guardhooks.FailureModeEnforce, err)
			if !blocked || v != guardhooks.VerdictDeny {
				t.Fatalf("enforce outcome = (%s, %v), want (deny, true)", v, blocked)
			}
			sv, sblocked := guardhooks.FailureOutcome(guardhooks.FailureModeShadow, err)
			if sblocked || sv != guardhooks.VerdictAuditOnly {
				t.Fatalf("shadow outcome = (%s, %v), want (audit-only, false)", sv, sblocked)
			}
			return v, blocked
		}
		evaluator, evalErr := guardhooks.NewEvaluator(stubFromFindings(findings))
		if evalErr != nil {
			t.Fatalf("evaluator: %v", evalErr)
		}
		_, _, applyErr := guardhooks.NewWithEvaluator(mode, evaluator).Apply("text")
		if applyErr != nil {
			if errors.Is(applyErr, guardhooks.ErrDenied) {
				return guardhooks.VerdictDeny, true
			}
			t.Fatalf("apply: %v", applyErr)
		}
		return guardhooks.VerdictAllow, false
	}

	t.Run("real/allow", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		findings, err := d.Detect(guardInvocation(ctx, "clean text"))
		v, blocked := verdictThroughHook(t, guardhooks.ModeDeny, findings, err)
		if v != guardhooks.VerdictAllow || blocked {
			t.Fatalf("verdict = (%s, %v), want (allow, false)", v, blocked)
		}
	})

	t.Run("real/deny", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion,
				map[string]any{"category": "secret", "start": 0, "end": 4, "confidence": 1, "detector": "remote:secret"})
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		findings, err := d.Detect(guardInvocation(ctx, "leak"))
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		v, blocked := verdictThroughHook(t, guardhooks.ModeDeny, findings, err)
		if v != guardhooks.VerdictDeny || !blocked {
			t.Fatalf("verdict = (%s, %v), want (deny, true)", v, blocked)
		}
	})

	for name, handler := range map[string]http.HandlerFunc{
		"real/timeout": func(w http.ResponseWriter, _ *http.Request) { time.Sleep(2 * time.Second) },
		"real/malformed": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not json`))
		},
		"real/wrong-version": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(guardRespond("guardrails.http.v0")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newSingletonServer(t, handler)
			d := newGuardDetector(t, newGuardRuntime(t, nil, 100*time.Millisecond), srv.URL)
			_, err := d.Detect(guardInvocation(ctx, "x"))
			if err == nil {
				t.Fatal("expected probe error")
			}
			if v, blocked := verdictThroughHook(t, guardhooks.ModeDeny, nil, err); v != guardhooks.VerdictDeny || !blocked {
				t.Fatalf("verdict = (%s, %v), want (deny, true)", v, blocked)
			}
		})
	}

	t.Run("real/recovery-after-breaker", func(t *testing.T) {
		rec := &recorder{respond: func(seq int, _ *http.Request) (int, string, string) {
			if seq <= 2 {
				return http.StatusServiceUnavailable, "application/json", ""
			}
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		srv := rec.server(t)
		rt := newGuardRuntime(t, &circuit.Config{
			Enabled: true, FailureThreshold: 2, SuccessThreshold: 1,
			OpenTimeout: 80 * time.Millisecond, Window: time.Minute,
		}, 0)
		d := newGuardDetector(t, rt, srv.URL)

		for i := 1; i <= 3; i++ {
			_, err := d.Detect(guardInvocation(ctx, "x"))
			if err == nil {
				t.Fatalf("call %d: want error", i)
			}
			if got := int(rec.requests.Load()); got != min(i, 2) {
				t.Fatalf("call %d: upstream hits = %d, want %d", i, got, min(i, 2))
			}
		}
		if _, err := d.Detect(guardInvocation(ctx, "x")); !IsBreakerOpen(err) {
			t.Fatalf("shed call err = %v, want breaker-open classification", err)
		}
		time.Sleep(120 * time.Millisecond) // past OpenTimeout: the probe is allowed
		findings, err := d.Detect(guardInvocation(ctx, "x"))
		if err != nil {
			t.Fatalf("recovery call: %v", err)
		}
		if findings == nil {
			t.Fatal("recovery call returned no findings slice")
		}
		if got := int(rec.requests.Load()); got != 3 {
			t.Fatalf("post-recovery upstream hits = %d, want 3", got)
		}
	})

	t.Run("mock/stub-detector-same-contract", func(t *testing.T) {
		// MOCK check (explicitly not the network path): a stub
		// VersionedDetector placed in the same evaluator/hook contract must
		// produce the identical verdict mapping as the real adapter rows.
		evaluator, err := guardhooks.NewEvaluator(stubFromFindings([]guardhooks.Finding{
			{Category: guardhooks.CatSecret, Start: 0, End: 4, Confidence: 1, Detector: "stub"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, _, applyErr := guardhooks.NewWithEvaluator(guardhooks.ModeDeny, evaluator).Apply("leak")
		if !errors.Is(applyErr, guardhooks.ErrDenied) {
			t.Fatalf("mock deny err = %v, want ErrDenied", applyErr)
		}
		emptyEval, err := guardhooks.NewEvaluator(stubFromFindings(nil))
		if err != nil {
			t.Fatal(err)
		}
		mutated, _, err := guardhooks.NewWithEvaluator(guardhooks.ModeDeny, emptyEval).Apply("clean")
		if err != nil || mutated != nil {
			t.Fatalf("mock allow = (%#v, %v), want (nil, nil)", mutated, err)
		}
	})
}

// TestGuardDetector_BoundaryCorpus is the reusable boundary corpus
// (N02-P04-T07): malformed responses, oversized payloads and timeouts on the
// adapter path — every row ends in an observable error (or the documented
// prior behavior), and nothing is forwarded on failure.
func TestGuardDetector_BoundaryCorpus(t *testing.T) {
	ctx := context.Background()

	t.Run("oversized-response", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", strings.Repeat("x", 64)
		}}
		rt := newGuardRuntime(t, nil, 0)
		d, err := rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: rec.server(t).URL, MaxResponseBytes: 8})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Detect(guardInvocation(ctx, "x")); err == nil || !strings.Contains(err.Error(), "response exceeds") {
			t.Fatalf("err = %v, want response cap error", err)
		}
	})

	t.Run("oversized-request-never-sent", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		rt := newGuardRuntime(t, nil, 0)
		d, err := rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: rec.server(t).URL, MaxRequestBytes: 4})
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Detect(guardInvocation(ctx, "too long"))
		if err == nil || !strings.Contains(err.Error(), "input exceeds") {
			t.Fatalf("err = %v, want input cap error", err)
		}
		if n := rec.requests.Load(); n != 0 {
			t.Fatalf("oversized payload was sent %d times", n)
		}
	})

	t.Run("wrong-content-type", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "text/plain", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		if _, err := d.Detect(guardInvocation(ctx, "x")); err == nil || !strings.Contains(err.Error(), "content-type") {
			t.Fatalf("err = %v, want content-type contract error", err)
		}
	})

	t.Run("non-2xx", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusInternalServerError, "application/json", ""
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		if _, err := d.Detect(guardInvocation(ctx, "x")); err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Fatalf("err = %v, want status error", err)
		}
	})

	t.Run("span-beyond-projection", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion,
				map[string]any{"category": "secret", "start": 0, "end": 99, "detector": "remote"})
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		if _, err := d.Detect(guardInvocation(ctx, "abc")); err == nil || !strings.Contains(err.Error(), "invalid finding span") {
			t.Fatalf("err = %v, want span validation error", err)
		}
	})

	t.Run("expired-context", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			time.Sleep(300 * time.Millisecond)
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		if _, err := d.Detect(guardInvocation(cctx, "x")); err == nil {
			t.Fatal("expected deadline error")
		}
	})
}

// TestGuardDetector_NoRetryNoDuplicateEffects (N02-P04-T08): the adapter is
// one-shot — a failure is attempted exactly once (no transport or client
// retry), concurrent identical calls share ONE upstream send (singleflight),
// and an interrupted call is never re-driven by the adapter: the next call is
// a fresh flight, counted exactly once.
func TestGuardDetector_NoRetryNoDuplicateEffects(t *testing.T) {
	t.Run("no-retry-on-failure", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			return http.StatusInternalServerError, "application/json", ""
		}}
		// Threshold-2 breaker: calls 1-2 reach the endpoint once each, call 3
		// is shed — one attempt per call, never a retry.
		d := newGuardDetector(t, newGuardRuntime(t, testBreakerConfig(), 0), rec.server(t).URL)
		for i := 0; i < 3; i++ {
			if _, err := d.Detect(guardInvocation(context.Background(), "x")); err == nil {
				t.Fatal("want error")
			}
		}
		if got := rec.requests.Load(); got != 2 {
			t.Fatalf("upstream hits = %d, want 2 (one attempt per call, no retry)", got)
		}
	})

	t.Run("concurrent-identical-share-one-send", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			time.Sleep(150 * time.Millisecond)
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion,
				map[string]any{"category": "secret", "start": 0, "end": 1, "detector": "remote"})
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)

		const n = 8
		results := make([][]guardhooks.Finding, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				results[i], errs[i] = d.Detect(guardInvocation(context.Background(), "same"))
			})
		}
		wg.Wait()
		if got := rec.requests.Load(); got != 1 {
			t.Fatalf("upstream hits = %d, want 1 for %d identical calls", got, n)
		}
		for i := range n {
			if errs[i] != nil || len(results[i]) != 1 || results[i][0].Detector != "remote" {
				t.Fatalf("call %d = %#v, %v", i, results[i], errs[i])
			}
		}
	})

	t.Run("interrupted-call-not-retried", func(t *testing.T) {
		rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
			time.Sleep(400 * time.Millisecond)
			return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
		}}
		d := newGuardDetector(t, newGuardRuntime(t, nil, 0), rec.server(t).URL)
		cctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		_, err := d.Detect(guardInvocation(cctx, "same"))
		cancel()
		if err == nil {
			t.Fatal("expected interruption error")
		}
		findings, err := d.Detect(guardInvocation(context.Background(), "same"))
		if err != nil || findings == nil {
			t.Fatalf("fresh call after interruption = %#v, %v", findings, err)
		}
		if got := rec.requests.Load(); got != 2 {
			t.Fatalf("upstream hits = %d, want 2 (aborted attempt + fresh attempt, no hidden retry)", got)
		}
	})
}

// TestGuardDetector_RequestEnvelopeMinimal (N02-P04-T10 data negative): the
// outbound envelope carries exactly the versioned protocol fields plus the
// invocation projection — no org/key/model metadata can leak through the
// detector path, and the protocol version travels on every request.
func TestGuardDetector_RequestEnvelopeMinimal(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
	}}
	srv := rec.server(t)
	d := newGuardDetector(t, newGuardRuntime(t, nil, 0), srv.URL)
	if _, err := d.Detect(guardInvocation(context.Background(), "payload text")); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.body, &raw); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if len(raw) != 4 {
		t.Fatalf("envelope fields = %v, want exactly version/phase/kind/text", raw)
	}
	for _, key := range []string{"version", "phase", "kind", "text"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("envelope missing %q: %v", key, raw)
		}
	}
	if raw["version"] != guardhooks.HTTPDetectorRequestVersion || raw["text"] != "payload text" {
		t.Fatalf("envelope = %v", raw)
	}
}

// TestGuardDetector_UnsupportedSpecVersionsLoud (N02-P04-T09): old and new
// configuration alike ends in a loud, explicit refusal — an invocation
// carrying an unsupported runtime version never reaches the network, and a
// detector answering with an unsupported protocol version is an error.
func TestGuardDetector_UnsupportedSpecVersionsLoud(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", guardRespond(guardhooks.HTTPDetectorRequestVersion)
	}}
	srv := rec.server(t)
	d := newGuardDetector(t, newGuardRuntime(t, nil, 0), srv.URL)

	_, err := d.Detect(guardhooks.Invocation{Context: context.Background(), Version: "guardrails.v0", Phase: guardhooks.PhaseBefore, Kind: guardhooks.ContentText, Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "unsupported invocation version") {
		t.Fatalf("old invocation version err = %v, want loud refusal", err)
	}
	if n := rec.requests.Load(); n != 0 {
		t.Fatalf("unsupported invocation reached the network %d times", n)
	}

	reply := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", guardRespond("guardrails.http.v2")
	}}
	d2 := newGuardDetector(t, newGuardRuntime(t, nil, 0), reply.server(t).URL)
	if _, err := d2.Detect(guardInvocation(context.Background(), "x")); err == nil || !strings.Contains(err.Error(), "unsupported response version") {
		t.Fatalf("new response version err = %v, want loud refusal", err)
	}
}

// --- helpers -----------------------------------------------------------------

// stubFromFindings wraps a static finding list in a VersionedDetector (the
// explicitly-labeled MOCK path of the joint contract).
func stubFromFindings(fs []guardhooks.Finding) guardhooks.VersionedDetector {
	return stubDetector{findings: fs}
}

type stubDetector struct{ findings []guardhooks.Finding }

func (stubDetector) Identity() guardhooks.RuleVersion {
	return guardhooks.RuleVersion{PackID: "stub.pack", PackVersion: "1", RuleID: "stub", RuleVersion: "1"}
}

func (d stubDetector) Detect(guardhooks.Invocation) ([]guardhooks.Finding, error) {
	return d.findings, nil
}

// newSingletonServer serves one handler on a fresh httptest server.
func newSingletonServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}
