// Package callout implements the YPP pipeline's external HTTP callout steps
// (OP-2): builtin/callout-detect (a Detector that POSTs a payload projection
// to an external scanner and maps the verdict to Findings) and
// builtin/callout-mutate (a Mutator that sends content out and applies the
// mutated content back, with boundary checks so a mutator can never expand
// its reach).
//
// SECURITY POSTURE (plan §2 OP-2 — non-negotiable):
//
//   - Egress allow-list: a Runtime is built with an explicit operator
//     AllowHosts list. Every step URL is validated against it at policy
//     compile time — a policy (or credential) can never widen egress beyond
//     the allow-list, and a Runtime with an empty list refuses to build any
//     step. Matching is by hostname pattern (ssrf.ParseDomain semantics:
//     exact or *.suffix); ports and paths are not restricted by the list.
//   - Dial-time SSRF guard: every connection of every callout-URL goes
//     through ssrf.NewGuardedDialer — DNS answers are resolved and pinned at
//     dial time and every reserved address (loopback, RFC1918, link-local /
//     cloud metadata, ...) refuses the connection, closing the DNS-rebinding
//     TOCTOU window. Compile-time allow-listing narrows WHO may be called;
//     the dial guard guarantees the dialled IP is never a reserved address.
//   - No redirects: a 3xx response is an error. A redirect would silently
//     change the method (POST→GET) and re-target the request; both violate
//     the one-shot contract and the allow-list invariant.
//   - No retries: one upstream attempt per (url, content) pair. Degradation
//     is decided by the step's on_error mode, never by silent retries.
//   - Per-URL circuit breaker (pkg/circuit): after the failure threshold the
//     endpoint is shed for the open timeout instead of being hammered; a
//     breaker rejection is a step error and follows on_error.
//   - Per-step timeout: request work observes the caller's context — the
//     policy `timeout` field bounds it at the engine, Deps.Timeout bounds
//     the transport itself.
//   - Singleflight: N concurrent runs of the SAME (url, sha256(content))
//     share one upstream call within the in-flight window (no result cache —
//     two sequential identical calls each hit the endpoint).
//   - Minimal exposure: only the configured projection leaves the gateway —
//     message contents, selected JSON body fields, or (opt-in, documented
//     risk) the full body. Org/key/model metadata never leaves.
//
// RESPONSE CONTRACTS (stable, for detector/mutator operators):
//
//	Detect, response=findings (default), HTTP 200 + Content-Type
//	application/json:
//
//	    {"findings": [{"category": "pan", "severity": "high",
//	                   "action": "deny", "span": "10:16",
//	                   "evidence": "4111…"}]}
//
//	  category is required (a finding without one is a contract error →
//	  step error → on_error decides); severity empty → "medium"; action
//	  empty → the step's finding_action param; an unrecognized action is
//	  fail-closed (ranks as deny via pipeline.Action.Rank); span is a
//	  detector-defined locator — for the messages projection it is the
//	  byte offset range inside the UTF-8 document the messages were
//	  joined into with "\n" separators; evidence may quote user content
//	  (decision-log stores hashes only — see pipeline.Finding).
//
//	Detect, response=boolean: body must be JSON true or false. true → one
//	synthetic finding (category/ severity/action from the finding_*
//	params, no span/evidence); false → no findings. Anything else is a
//	contract error.
//
//	Mutate: request {"expose": "...", "content": ...}; response must be
//	HTTP 200 + application/json {"content": ...}. The content shape is
//	fixed by the projection (below) and the response may never extend it:
//	messages → string array with EXACTLY len(messages) elements (no
//	added/dropped messages); body → a string replacing Body wholesale;
//	fields → an object whose key set EQUALS the projected field set (no
//	added, no dropped fields — deletion is explicit null).
//
// PROJECTIONS (params.expose):
//
//	messages (default) — detect sends all message contents joined with
//	"\n" (continuous byte offsets for spans); mutate sends one array
//	element per message so replacements stay per-message.
//	body — the raw payload Body as a JSON string; the full content leaves
//	the perimeter: enable only for scanners contractually bound to the
//	same data domain (documented risk).
//	fields:a,b,c — only those top-level fields of a JSON-object Body;
//	spans locate inside the projected JSON document. A Body that is not a
//	JSON object is a step error.
//
// An empty projection (no messages / empty body / no field present) skips
// the upstream call entirely — the step traces as ran with no findings.
//
// on_error SEMANTICS (engine-applied; the step itself never swallows):
// a network failure, non-2xx status, wrong content-type, invalid/out-of-
// contract response, breaker rejection or projection error is returned as
// an ERROR → fail_closed denies, fail_open ignores, fail_open+flag adds the
// synthetic step_error flag finding. A scanner VERDICT (valid 2xx response)
// is never an error — findings found / not found is the normal path, and
// the two can never be confused. A scanner reporting findings still counts
// as breaker success: the endpoint is healthy.
//
// METRICS (pipeline_callout_* / label endpoint = allow-listed endpoint URL
// without query): requests_total counts actual upstream sends (singleflight
// winners), errors_total every step error including breaker rejections,
// duration_seconds the winners' round-trip latency.
//
// WIRING:
//
//	rt, err := callout.New(callout.Deps{AllowHosts: []string{"detector.internal"}})
//	rt.RegisterAll(engine.Steps()) // "callout", "builtin/callout-detect",
//	                               // "builtin/callout-mutate"
//
// YAML (both spellings compile to the same steps):
//
//   - id: pii-detect
//     callout: https://detector.internal/v1/detect   # reserved param "url"
//     params: {mode: detect, expose: messages, finding_action: deny}
//     timeout: 500ms
//     on_error: fail_closed
//   - id: anon
//     callout: https://detector.internal/v1/redact
//     params: {mode: mutate}
//   - id: alt-spelling
//     detector: builtin/callout-detect               # url travels in params
//     params: {url: https://detector.internal/v1/detect}
package callout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"golang.org/x/sync/singleflight"
)

// Default transport budgets used when the corresponding Deps fields are
// unset. The breaker defaults shed an endpoint after 5 failures within 30s
// for 30s.
const (
	DefaultTimeout          = 5 * time.Second
	DefaultMaxResponseBytes = 1 << 20 // 1 MiB
	defaultFailureThreshold = 5
	defaultOpenTimeout      = 30 * time.Second
	defaultWindow           = 30 * time.Second
)

// Deps is the operator-owned runtime configuration. One Runtime is built at
// gateway wiring time and shared by every callout step of every policy; Deps
// itself is only read at construction.
type Deps struct {
	// AllowHosts is the egress allow-list (ssrf.ParseDomain patterns:
	// "detector.internal" or "*.scanner.example"). Required non-empty:
	// callout egress can never be wider than this list, and policies are
	// structurally unable to expand it.
	AllowHosts []string

	// Timeout bounds one upstream attempt at the transport (default
	// DefaultTimeout). Policy-level step timeouts bound it independently.
	Timeout time.Duration

	// Breaker configures the per-URL circuit breakers. nil → enabled with
	// package defaults; an explicit config is used verbatim (Enabled=false
	// disables shedding). The per-URL Name is set by the Runtime.
	Breaker *circuit.Config

	// MaxResponseBytes caps a scanner response body (default
	// DefaultMaxResponseBytes). A larger response is a step error.
	MaxResponseBytes int64

	// Lookup and Dial are test seams forwarded to ssrf.NewGuardedDialer;
	// production wiring must leave them nil (the same contract as
	// ssrf.DialerOptions — a nil-failing seam must never silently disable
	// the reserved-IP checks in production).
	Lookup ssrf.LookupFunc
	Dial   func(ctx context.Context, network, address string) (net.Conn, error)
}

// Runtime is the shared, goroutine-safe state behind every callout step:
// the guarded HTTP client, the per-URL breakers and the singleflight group.
// Safe for concurrent Engine.Run invocations.
type Runtime struct {
	deps   Deps
	client *http.Client
	hosts  []ssrf.Domain
	// breakers caches the per-URL circuit breakers, keyed by endpoint
	// (scheme://host/path). The key set is bounded: only allow-listed,
	// compile-time-validated URLs ever reach it.
	breakers sync.Map
	flight   singleflight.Group

	inFlight atomic.Int64 // diagnostics: calls currently inside singleflight.Do
}

// New validates Deps and builds the shared runtime. An empty allow-list is a
// construction error: a callout deployment without an explicit egress list
// is a misconfiguration, not a default.
func New(deps Deps) (*Runtime, error) {
	if len(deps.AllowHosts) == 0 {
		return nil, fmt.Errorf("callout: AllowHosts is empty: callout egress requires an explicit operator allow-list")
	}
	hosts := make([]ssrf.Domain, 0, len(deps.AllowHosts))
	for _, entry := range deps.AllowHosts {
		d, err := ssrf.ParseDomain(entry)
		if err != nil {
			return nil, fmt.Errorf("callout: allow-list entry: %w", err)
		}
		hosts = append(hosts, d)
	}
	if deps.Timeout <= 0 {
		deps.Timeout = DefaultTimeout
	}
	if deps.MaxResponseBytes <= 0 {
		deps.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return &Runtime{
		deps:   deps,
		client: newGuardedClient(deps),
		hosts:  hosts,
	}, nil
}

// newGuardedClient builds the one shared HTTP client. Every dial of every
// callout-URL resolves through ssrf.NewGuardedDialer (pinned, reserved-IP
// checked), there is no proxy and redirects are refused. The step layer
// performs no retries of its own. One stdlib nuance is deliberate and keeps
// the contract intact: for a body with GetBody set (every callout body is a
// *bytes.Reader, so NewRequest sets it), the transport may replay a POST
// exactly once — and only when a REUSED keep-alive connection dies before
// the request bytes were written. The endpoint never observed attempt #1 in
// that window, so the one-upstream-effect invariant (at most one observed
// call per (url, content) pair) still holds; a failure after the request
// reached the wire is never replayed.
func newGuardedClient(deps Deps) *http.Client {
	return newClient(deps, ssrf.NewGuardedDialer(ssrf.DialerOptions{
		Timeout: deps.Timeout,
		Lookup:  deps.Lookup,
		Dial:    deps.Dial,
	}))
}

// newClient builds the shared HTTP client around the given dial function
// (production: the guarded dialer; tests may pass a plain dialer for
// loopback httptest endpoints — the reserved-IP guard itself is never
// bypassable through Deps).
func newClient(deps Deps, dialCtx func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil, // operator URLs must not ride an operator proxy
			DialContext:           dialCtx,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       time.Minute,
			TLSHandshakeTimeout:   deps.Timeout,
			ResponseHeaderTimeout: deps.Timeout,
			ExpectContinueTimeout: time.Second,
		},
		Timeout: deps.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("callout: redirect to %s refused (one-shot callout, no redirects)", req.URL.Host)
		},
	}
}

// hostAllowed reports whether hostname matches the operator allow-list.
func (r *Runtime) hostAllowed(hostname string) bool {
	for _, h := range r.hosts {
		if h.Matches(hostname) {
			return true
		}
	}
	return false
}

// breakerFor returns the per-URL breaker, creating it on first use. The key
// set is bounded: only allow-listed, compile-time-validated URLs ever reach
// this cache.
func (r *Runtime) breakerFor(endpoint string) *circuit.Breaker {
	if b, ok := r.breakers.Load(endpoint); ok {
		return b.(*circuit.Breaker)
	}
	cfg := circuit.Config{}
	if r.deps.Breaker != nil {
		cfg = *r.deps.Breaker
	} else {
		cfg.Enabled = true
		cfg.FailureThreshold = defaultFailureThreshold
		cfg.OpenTimeout = defaultOpenTimeout
		cfg.Window = defaultWindow
	}
	cfg.Name = "callout:" + endpoint
	b, _ := r.breakers.LoadOrStore(endpoint, circuit.NewBreaker(cfg))
	return b.(*circuit.Breaker)
}

// errCircuitOpen wraps the breaker sentinel so callers can classify a shed
// callout without string matching.
var errCircuitOpen = circuit.ErrCircuitOpen

// IsBreakerOpen reports whether err is a per-URL circuit-breaker rejection
// (as opposed to a network/protocol failure).
func IsBreakerOpen(err error) bool { return errors.Is(err, errCircuitOpen) }

// RegisterAll registers the three factories on the engine's step registry:
// "callout" (the callout-kind registry name reserved by pkg/pipeline; mode
// dispatched via the params.mode key), "builtin/callout-detect" and
// "builtin/callout-mutate".
func (r *Runtime) RegisterAll(reg *pipeline.Registry) error {
	for name, f := range map[string]pipeline.StepFactory{
		"callout":                r.CalloutFactory,
		"builtin/callout-detect": r.DetectFactory,
		"builtin/callout-mutate": r.MutateFactory,
	} {
		if err := reg.Register(name, f); err != nil {
			return fmt.Errorf("callout: register %s: %w", name, err)
		}
	}
	return nil
}

// DetectFactory builds a builtin/callout-detect step from step params.
func (r *Runtime) DetectFactory(params map[string]any) (pipeline.Step, error) {
	cfg, err := parseStepConfig(params, r, modeDetect)
	if err != nil {
		return nil, err
	}
	return &Detect{rt: r, cfg: cfg}, nil
}

// MutateFactory builds a builtin/callout-mutate step from step params.
func (r *Runtime) MutateFactory(params map[string]any) (pipeline.Step, error) {
	cfg, err := parseStepConfig(params, r, modeMutate)
	if err != nil {
		return nil, err
	}
	return &Mutate{rt: r, cfg: cfg}, nil
}

// CalloutFactory dispatches the core "callout" kind on params.mode
// ("detect" default | "mutate"); the URL comes in as the reserved "url"
// param merged by the core (pkg/pipeline StepSpec.Params contract).
func (r *Runtime) CalloutFactory(params map[string]any) (pipeline.Step, error) {
	switch paramMode(params) {
	case modeMutate:
		return r.MutateFactory(params)
	default: // detect is the safe default: read-only
		return r.DetectFactory(params)
	}
}

func paramMode(params map[string]any) stepMode {
	if v, ok := params[paramKeyMode].(string); ok && v == modeMutate.yamlName() {
		return modeMutate
	}
	return modeDetect
}

// InFlight returns the number of upstream calls currently executing (or
// joined) inside the singleflight window. Diagnostics only.
func (r *Runtime) InFlight() int64 { return r.inFlight.Load() }
