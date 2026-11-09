// OP-8 (OUTPLAY-PLAN-2026-10-06 §2.1/§3): the gateway policy-pipeline
// middleware — the SINGLE integration point that runs pkg/pipeline over
// gateway traffic.
//
// Shape:
//
//   - PolicyRuntime compiles an org's enabled policystore pipelines once per
//     version and executes the ones attached to the request's
//     (endpoint, model, key label) on the hook the caller asks for. The
//     per-org cache is keyed by the policystore version key
//     ("policystore:ver:<orgID>", adminstore.PolicyVersionKeyPrefix) with a
//     hard TTL fallback (policyCacheTTL) when Redis is unreachable — the same
//     mechanics as the org-credential probe (upstream.go).
//   - Global kill-switch (YABANIN_POLICY_MODE, resolved in services/run and
//     carried here as PolicyMode): off = the runtime is never built and every
//     hook is a nil-check no-op (bit-for-bit pre-OP-8 behavior); shadow =
//     every policy is downgraded to shadow at compile time (never mutates,
//     never raises the verdict); enforce = policies run in their stored mode.
//   - Internal judge payloads whose meta passes llmjudge.IsJudgeMeta are the
//     supported recursion signal. An inbound HTTP judge header — any value,
//     empty or duplicated included — is untrusted and rejected (400
//     judge_reentry_unsupported) at the shared pre-upstream boundary, with
//     the existing cold-enforce 503 precedence.
//   - Hook sites (minimal call sites, one per path): chat.go JSON path
//     (pre/post), messages_native.go, completions_endpoint.go,
//     responses_native.go (pre/post). The SSE path (stream.go) carries only
//     the OP-4 stubs — stream_prefix/stream_final wiring lands with the
//   - Decisions travel to the event stream in Event.Policy (the OP-9
//     contract — see the field comment in pkg/eventpublisher).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/gateway/internal/policydecide"
	"github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/builtins"
	"github.com/reireirei/yabanin/pkg/pipeline/callout"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	scriptexpr "github.com/reireirei/yabanin/pkg/pipeline/script/expr"
	scriptlua "github.com/reireirei/yabanin/pkg/pipeline/script/lua"
	scriptstarlark "github.com/reireirei/yabanin/pkg/pipeline/script/starlark"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// PolicyMode is the global policy kill-switch (YABANIN_POLICY_MODE).
type PolicyMode string

// AuthorizationVerdict is the result of a permission check. It must not be
// inferred from a content detector or route candidate outcome.
type AuthorizationVerdict string

// GuardrailVerdict is the content-policy outcome, distinct from permission
// and candidate selection semantics.
type GuardrailVerdict string

// RoutingDecision describes candidate selection/refusal, not authorization
// and not a detector finding.
type RoutingDecision string

const (
	// AuthorizationAllow permits the requested operation.
	AuthorizationAllow AuthorizationVerdict = "allow"
	// AuthorizationDeny rejects the requested operation.
	AuthorizationDeny AuthorizationVerdict = "deny"
	// AuthorizationError indicates that a mandatory authorization provider failed.
	AuthorizationError AuthorizationVerdict = "error"

	// GuardrailAllow indicates no action is required.
	GuardrailAllow GuardrailVerdict = "allow"
	// GuardrailDeny rejects content or operation under guardrail policy.
	GuardrailDeny GuardrailVerdict = "deny"
	// GuardrailRedact requests content mutation.
	GuardrailRedact GuardrailVerdict = "redact"
	// GuardrailAuditOnly records a finding without blocking or mutation.
	GuardrailAuditOnly GuardrailVerdict = "audit-only"

	// RoutingSelect selects a candidate route.
	RoutingSelect RoutingDecision = "select"
	// RoutingRefuse means no candidate satisfies routing requirements.
	RoutingRefuse RoutingDecision = "refuse"
	// RoutingNoChange means routing does not alter the current candidate.
	RoutingNoChange RoutingDecision = "no-change"
)

// PolicyColdFailureMode controls requests whose organization has no successful
// policy snapshot and whose first policy-store read is unavailable.
type PolicyColdFailureMode string

// Kill-switch modes. off is the default: the runtime is not built and the
// request paths keep their exact pre-OP-8 behavior.
const (
	PolicyModeOff     PolicyMode = "off"
	PolicyModeShadow  PolicyMode = "shadow"
	PolicyModeEnforce PolicyMode = "enforce"
)

const (
	// PolicyColdFailureFailClosed rejects requests when the initial policy-store
	// read is unavailable and no successful snapshot exists.
	PolicyColdFailureFailClosed PolicyColdFailureMode = "fail-closed"
	// PolicyColdFailureFailOpen permits cold requests to continue without a
	// policy snapshot when the policy store is unavailable.
	PolicyColdFailureFailOpen PolicyColdFailureMode = "fail-open"
)

// ResolvePolicyColdFailureMode parses the cold-load override. Unknown values
// fail closed and return a generic warning that never includes operator input.
func ResolvePolicyColdFailureMode(value string) (PolicyColdFailureMode, string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(PolicyColdFailureFailClosed):
		return PolicyColdFailureFailClosed, ""
	case string(PolicyColdFailureFailOpen):
		return PolicyColdFailureFailOpen, ""
	default:
		return PolicyColdFailureFailClosed, "YABANIN_POLICY_COLD_FAILURE_MODE is invalid; defaulting to fail-closed"
	}
}

// Valid reports whether m is a defined kill-switch mode.
func (m PolicyMode) Valid() bool {
	switch m {
	case PolicyModeOff, PolicyModeShadow, PolicyModeEnforce:
		return true
	default:
		return false
	}
}

// ResolvePolicyMode parses the YABANIN_POLICY_MODE env value. An empty value
// or an unknown value resolves to off (the second return is a non-empty note
// for unknown values only — an unset knob must not log). Startup wiring must
// treat that note as invalid input rather than accepting the fallback.
func ResolvePolicyMode(v string) (PolicyMode, string) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return PolicyModeOff, ""
	case "off":
		return PolicyModeOff, ""
	case "shadow":
		return PolicyModeShadow, ""
	case "enforce":
		return PolicyModeEnforce, ""
	default:
		return PolicyModeOff, fmt.Sprintf("YABANIN_POLICY_MODE %q is not off|shadow|enforce — policy pipeline disabled", v)
	}
}

// PolicyWiring carries the env-resolved policy knobs from services/run into
// the gateway composition root (pkg/config is deliberately untouched).
type PolicyWiring struct {
	// Mode is the global kill-switch (YABANIN_POLICY_MODE).
	Mode PolicyMode
	// ColdFailureMode applies only when an org has no successful snapshot.
	ColdFailureMode PolicyColdFailureMode
	// CalloutAllowHosts is the callout egress allow-list
	// (YABANIN_POLICY_CALLOUT_ALLOW_HOSTS, comma-separated ssrf.ParseDomain
	// patterns). Empty disables callout steps: policies referencing them
	// then fail to LOAD (and are skipped with a warning), callout egress can
	// never be wider than the operator's list.
	CalloutAllowHosts []string
}

// PolicySnapshotReader provides one complete, org-scoped policy input set.
// Implementations return either the complete database snapshot or an error.
type PolicySnapshotReader interface {
	LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error)
}

type policyPromptPinWriter interface {
	SavePolicyPromptPins(ctx context.Context, orgID, policyID string, version int, pins map[string]adminstore.PromptPin) error
}

// PolicyPipelineReader preserves the legacy store surface while requiring
// the aggregate snapshot operation. PolicyRuntime uses only the snapshot
// method; the split read methods remain for other callers and compatibility.
type PolicyPipelineReader interface {
	PolicySnapshotReader
	ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error)
	GetPolicyVersion(ctx context.Context, orgID, policyID string, version int) (adminstore.PolicyVersion, error)
	ListPolicyAttachments(ctx context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error)
}

// PolicyVersionReader is the version-key probe
// (adminstore.NewPolicyVersionCache over the shared Redis). nil = TTL-only
// cache invalidation.
type PolicyVersionReader interface {
	GetPolicyVersion(ctx context.Context, orgID string) (int64, error)
}

// policyCacheTTL bounds the per-org compiled-policy cache when the version
// key is unreachable (orgCredsProbeTTL parity — the documented TTL fallback).
const policyCacheTTL = 30 * time.Second

// policyMaxOrgs caps the org cache; eviction is oldest-loaded
// (orgCredsProbeMaxOrgs parity).
const policyMaxOrgs = 4096

// policyDenyErrorCode is the wire error code for both pre- and post-upstream
// denials (400, the existing error envelope).
const policyDenyErrorCode = "content_policy_violation"

// PolicyRuntime is the request-path policy service. Safe for concurrent use;
// the per-org cache holds compiled pipelines only (never payload content).
type PolicyRuntime struct {
	engine          *pipeline.Engine
	store           PolicyPipelineReader
	versions        PolicyVersionReader
	mode            PolicyMode
	coldFailureMode PolicyColdFailureMode
	coldUnavailable bool
	ttl             time.Duration
	now             func() time.Time
	log             *slog.Logger
	// calloutAllowHosts is carried so per-org engine rebuilds (below) match
	// the shared engine's registries exactly.
	calloutAllowHosts []string
	// unwired — org: refs fail policy load — and partials keep the
	// both fields after construction (buildPolicyRuntime); they are
	// read-only afterwards.
	sources      promptStudioSources
	orgJudgeDeps llmjudge.Deps

	mu   sync.Mutex
	orgs map[string]*orgPolicyEntry
}

// policyEntryOutcome is immutable request-scoped availability information.
// A load error is never installed as a successful org cache entry.
type policyEntryOutcome struct {
	entry   *orgPolicyEntry
	loadErr error
	stale   bool
}

type policyOutcomeContextKey struct{}

type policyOutcomeContextValue struct {
	runtime *PolicyRuntime
	orgID   string
	outcome policyEntryOutcome
}

func withPolicyEntryOutcome(ctx context.Context, runtime *PolicyRuntime, orgID string, outcome policyEntryOutcome) context.Context {
	return context.WithValue(ctx, policyOutcomeContextKey{}, policyOutcomeContextValue{runtime: runtime, orgID: orgID, outcome: outcome})
}

func policyEntryOutcomeFromContext(ctx context.Context, runtime *PolicyRuntime, orgID string) (policyEntryOutcome, bool) {
	value, ok := ctx.Value(policyOutcomeContextKey{}).(policyOutcomeContextValue)
	if !ok || value.runtime != runtime || value.orgID != orgID {
		return policyEntryOutcome{}, false
	}
	return value.outcome, true
}

func withRequestPolicyEntryOutcome(ctx context.Context, r *http.Request, runtime *PolicyRuntime, orgID string) context.Context {
	if r == nil || runtime == nil {
		return ctx
	}
	outcome, ok := policyEntryOutcomeFromContext(r.Context(), runtime, orgID)
	if !ok {
		return ctx
	}
	return withPolicyEntryOutcome(ctx, runtime, orgID, outcome)
}

// withRequestRouteHint copies a route hint stamped on the request by
// callers capture ctx before the hook mutates *r, so the hint must be moved
// explicitly for the downstream routing sites.
func withRequestRouteHint(ctx context.Context, r *http.Request) context.Context {
	if r == nil {
		return ctx
	}
	if hint := routehint.HintFrom(r.Context()); hint != "" {
		ctx = routehint.WithHint(ctx, hint)
	}
	return ctx
}

// executeFallback runs the fallback chain for a request, honoring a route
// candidates are attempted first, chain order otherwise unchanged. An absent
// hint is exactly gw.fallback.Execute. An enforce-mode hint no candidate can
// status 400, code route_hint_unsatisfiable, zero provider dials.
func (gw *gateway) executeFallback(ctx context.Context, primary resolver.ModelInfo, fn router.AttemptFunc) (resolver.ModelInfo, int, []router.AttemptOutcome, error) {
	return gw.fallback.ExecuteWithProviderHint(ctx, primary, routehint.HintFrom(ctx), fn)
}

// without a fallback chain (the native endpoints): there is nothing to
// reorder, so an enforce-mode route hint naming any provider other than the
// one serving the request is unsatisfiable and must fail explicitly — 400
// route_hint_unsatisfiable, written here — instead of being silently ignored
// off) and a hint matching the serving provider proceed. Call sites invoke
// this right after policyPreUpstream, before any reservation, so a refusal
// never creates or settles escrow.
func (gw *gateway) enforceSingularRouteHint(w http.ResponseWriter, r *http.Request, providerName string) bool {
	hint := routehint.HintFrom(r.Context())
	if hint == "" || hint == providerName {
		return true
	}
	logctx.From(r.Context(), gw.log).Warn("route hint refused: unsatisfiable on single-candidate pipeline",
		"hint", hint, "provider", providerName)
	writeGateDenial(w, gateResultFromPolicy(router.HintRefusal(hint,
		fmt.Sprintf("this pipeline runs on provider %q with no fallback chain to reorder", providerName))))
	return false
}

// orgPolicyEntry is one org's compiled policy set. Immutable after load;
// the entry is replaced (never mutated) on reload.
type orgPolicyEntry struct {
	plans    []policyPlan
	version  int64
	haveVer  bool
	loadedAt time.Time
	// judgeVersion is the first judge prompt/template version identifier
	// header; "" when the runtime is unwired or no judge template
	// resolved). Compile order is deterministic (plan priority), so the
	// "first" pick is stable across reloads of the same snapshot.
	judgeVersion string
}

// policyPlan is one compiled policy plus the identity and attachment set it
// was loaded under.
type policyPlan struct {
	policyID     string
	version      int
	priority     int
	compiled     pipeline.Compiled
	atts         []adminstore.PolicyAttachment
	promptPins   map[string]llmjudge.Prompt
	judgeVersion string
}

// NewPolicyRuntime builds the runtime with the full step/condition registry.
// A registration failure is a construction error — the caller logs it and
// leaves the runtime nil (feature off) rather than booting with a partial
// pipeline registry. The llmjudge default deps (judge client) must be
// installed with llmjudge.SetDefaultDeps BEFORE this call.
func NewPolicyRuntime(store PolicyPipelineReader, versions PolicyVersionReader, mode PolicyMode, calloutAllowHosts []string, l *slog.Logger) (*PolicyRuntime, error) {
	if store == nil {
		return nil, errors.New("policy runtime: policy store is required")
	}
	if !mode.Valid() {
		return nil, fmt.Errorf("policy runtime: mode %q is not off|shadow|enforce", mode)
	}
	if l == nil {
		l = slog.Default()
	}

	eng, err := newPolicyEngine(calloutAllowHosts, l)
	if err != nil {
		return nil, err
	}
	return &PolicyRuntime{
		engine:            eng,
		store:             store,
		versions:          versions,
		mode:              mode,
		coldFailureMode:   PolicyColdFailureFailClosed,
		ttl:               policyCacheTTL,
		now:               time.Now,
		log:               l,
		calloutAllowHosts: calloutAllowHosts,
		orgs:              make(map[string]*orgPolicyEntry),
	}, nil
}

func newUnavailablePolicyRuntime(mode PolicyMode, coldMode PolicyColdFailureMode, l *slog.Logger) *PolicyRuntime {
	if l == nil {
		l = slog.Default()
	}
	if coldMode != PolicyColdFailureFailOpen {
		coldMode = PolicyColdFailureFailClosed
	}
	return &PolicyRuntime{mode: mode, coldFailureMode: coldMode, coldUnavailable: true, log: l, orgs: make(map[string]*orgPolicyEntry)}
}

// builtins (OP-1), callout (OP-2, only when an allow-list is configured),
// llm_judge (OP-3), toolpolicy (OP-6), the decide/route_hint seam steps, and
// all three condition engines (OP-7: expr, lua, starlark).
//
// TODO(owner, OP-7 spike): expr is registered FIRST as the intended default
// when_engine. The pkg/pipeline core currently treats a single registered
// engine as the default and requires an explicit when_engine once several are
// registered — the owner decision must add a default-engine mechanism to the
// core (or policies must pin when_engine) before mixed-engine deployments
// rely on implicit defaults.
func newPolicyEngine(calloutAllowHosts []string, l *slog.Logger) (*pipeline.Engine, error) {
	return newPolicyEngineWithJudgeDeps(calloutAllowHosts, llmjudge.DefaultDeps(), l)
}

// newPolicyEngineWithJudgeDeps is newPolicyEngine with the judge deps made
// prompts) so org-scoped prompt resolution binds at step-compile time. The
// registries produced for the same inputs are identical otherwise.
func newPolicyEngineWithJudgeDeps(calloutAllowHosts []string, judgeDeps llmjudge.Deps, l *slog.Logger) (*pipeline.Engine, error) {
	eng := pipeline.NewEngine()

	// Condition engines (OP-7). expr first — see the TODO above.
	exprEng := scriptexpr.New()
	eng.Scripts().MustRegister(exprEng.Name(), exprEng.Compile)
	luaEng := scriptlua.New()
	eng.Scripts().MustRegister(luaEng.Name(), luaEng.Compile)
	starlarkEng := scriptstarlark.New()
	eng.Scripts().MustRegister(starlarkEng.Name(), starlarkEng.Compile)

	// Builtins (OP-1).
	for name, factory := range builtins.Registry() {
		if err := eng.Steps().Register(name, factory); err != nil {
			return nil, fmt.Errorf("policy engine: register %s: %w", name, err)
		}
	}

	// Callout (OP-2). Requires an explicit operator allow-list; without one
	// the factories stay unregistered and callout policies fail at LOAD
	// (never silent egress).
	if len(calloutAllowHosts) > 0 {
		rt, err := callout.New(callout.Deps{AllowHosts: calloutAllowHosts})
		if err != nil {
			return nil, fmt.Errorf("policy engine: callout runtime: %w", err)
		}
		if err := rt.RegisterAll(eng.Steps()); err != nil {
			return nil, fmt.Errorf("policy engine: %w", err)
		}
	}

	// llm_judge (OP-3). Deps are passed by the caller: the shared engine
	// gets the process-wide defaults installed by the wiring that owns the
	// judge client (buildGatewayCompliance); an org-scoped engine gets the
	// org's prompt source added on top of the same client.
	if err := llmjudge.Register(eng.Steps(), judgeDeps); err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}

	// Toolpolicy (OP-6).
	if err := toolpolicy.RegisterStepFactory(eng.Steps()); err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}

	// decide: the verdict step the sovereign-default pack uses. The registry
	// name is reserved by the core contract; the implementation is
	// registration glue owned here (see internal/policydecide).
	if err := eng.Steps().Register(policydecide.FactoryName, policydecide.Factory); err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}
	// the request-scoped sink policyPreUpstream installs; the routing call
	// sites then prefer hinted-provider candidates via the fallback executor
	// enforce-mode hint that cannot influence the route is an explicit
	// refusal — unmatched hints on chained pipelines (executeFallback) and
	// hints foreign to the serving provider on chainless native endpoints
	// (enforceSingularRouteHint) return 400 route_hint_unsatisfiable.
	if err := eng.Steps().Register(routehint.FactoryName, routehint.Factory); err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}

	l.Debug("policy engine registries built",
		"steps", eng.Steps().Names(), "condition_engines", eng.Scripts().Names())
	return eng, nil
}

// --- per-org cache -----------------------------------------------------------

// entry returns the org's cached plans, probing the version key on every
// call (a bump drops the cache immediately — that is the point of the
// version-key contract) and falling back to the hard TTL when the probe is
// unavailable (the policystore contract's "degrades to its own hard TTL").
// Loads read the store outside the mutex (orgCredsProbe shape); failures
// never evict a usable stale entry and are returned as an availability
// outcome for the gateway's cold-failure policy.
func (rt *PolicyRuntime) entry(ctx context.Context, orgID string) *orgPolicyEntry {
	return rt.entryWithOutcome(ctx, orgID).entry
}

func (rt *PolicyRuntime) hasSnapshot(orgID string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.orgs[orgID] != nil
}

func (rt *PolicyRuntime) entryWithOutcome(ctx context.Context, orgID string) policyEntryOutcome {
	if rt.coldUnavailable {
		return policyEntryOutcome{loadErr: errPolicyRuntimeUnavailable}
	}
	now := rt.now()

	rt.mu.Lock()
	e := rt.orgs[orgID]
	rt.mu.Unlock()

	if e == nil {
		return rt.refreshWithOutcome(ctx, orgID, nil, now)
	}

	if rt.versions != nil {
		v, err := rt.versions.GetPolicyVersion(ctx, orgID)
		switch {
		case err == nil && e.haveVer && v != e.version:
			// A known version change invalidates the cache immediately.
		case err == nil:
			// Equal and previously unknown versions share the hard load-age
			// bound. A healthy probe does not renew loadedAt.
			if now.Sub(e.loadedAt) < rt.ttl {
				return policyEntryOutcome{entry: e}
			}
		case err != nil:
			rt.log.Debug("policy version probe failed; TTL fallback governs", "org_id", orgID)
			if now.Sub(e.loadedAt) < rt.ttl {
				return policyEntryOutcome{entry: e}
			}
		}
	} else if now.Sub(e.loadedAt) < rt.ttl {
		return policyEntryOutcome{entry: e}
	}
	return rt.refreshWithOutcome(ctx, orgID, e, now)
}

var errPolicyRuntimeUnavailable = errors.New("policy runtime unavailable")

var errInvalidPolicyConfiguration = errors.New("invalid policy configuration")
var errPolicySnapshotChurn = errors.New("policy snapshot changed during refresh")

type policyConfigStage string

const (
	policyConfigStageActiveReference policyConfigStage = "active_version_reference"
	policyConfigStageYAMLDocument    policyConfigStage = "yaml_document"
	policyConfigStageSchemaMode      policyConfigStage = "schema_mode"
	policyConfigStageStepCompile     policyConfigStage = "step_compile"
)

type policyConfigError struct {
	stage policyConfigStage
	cause error
}

func (e *policyConfigError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", errInvalidPolicyConfiguration, e.cause)
	}
	return errInvalidPolicyConfiguration.Error()
}

func (e *policyConfigError) Unwrap() error {
	if e.cause != nil {
		return errors.Join(errInvalidPolicyConfiguration, e.cause)
	}
	return errInvalidPolicyConfiguration
}

func invalidPolicyConfig(stage policyConfigStage) error {
	return &policyConfigError{stage: stage}
}

func invalidPolicyConfigCause(stage policyConfigStage, cause error) error {
	return &policyConfigError{stage: stage, cause: cause}
}

func (rt *PolicyRuntime) refreshWithOutcome(ctx context.Context, orgID string, stale *orgPolicyEntry, now time.Time) policyEntryOutcome {
	for attempt := 0; attempt < 2; attempt++ {
		before, beforeErr := int64(0), error(nil)
		if rt.versions != nil {
			before, beforeErr = rt.versions.GetPolicyVersion(ctx, orgID)
		}
		plans, judgeVersion, loadErr := rt.load(ctx, orgID, stale)
		after, afterErr := int64(0), error(nil)
		if rt.versions != nil {
			after, afterErr = rt.versions.GetPolicyVersion(ctx, orgID)
		}
		if loadErr != nil {
			return policyEntryOutcome{entry: stale, loadErr: loadErr, stale: stale != nil}
		}
		if rt.versions != nil && beforeErr == nil && afterErr == nil && before != after {
			if attempt == 0 {
				continue
			}
			return policyEntryOutcome{entry: stale, loadErr: errPolicySnapshotChurn, stale: stale != nil}
		}
		fresh := &orgPolicyEntry{plans: plans, judgeVersion: judgeVersion, loadedAt: now}
		if rt.versions != nil && beforeErr == nil && afterErr == nil {
			fresh.version, fresh.haveVer = after, true
		}
		rt.mu.Lock()
		rt.orgs[orgID] = fresh
		rt.evictLocked(now)
		rt.mu.Unlock()
		rt.log.Info("policy store load succeeded", "org_id", orgID)
		return policyEntryOutcome{entry: fresh}
	}
	return policyEntryOutcome{entry: stale, loadErr: errPolicySnapshotChurn, stale: stale != nil}
}

// promptVersionRecorder wraps the org prompt source during one candidate
// compile and records the template version identifiers the judge steps
// pipeline.CompilePolicy — sequential per candidate load (no locking) and
// the recorder is created fresh per load, so it is never shared across
// goroutines. Distinct versions collapse order-stable; the FIRST resolved
// version is the one surfaced (single-valued header).
type promptVersionRecorder struct {
	inner        llmjudge.PromptSource
	pins         map[string]llmjudge.Prompt
	firstVersion string
}

type pinnedPromptSource struct {
	inner  llmjudge.PromptSource
	pinned map[string]llmjudge.Prompt
}

func (s *pinnedPromptSource) Load(ctx context.Context, ref string) (llmjudge.Prompt, error) {
	if p, ok := s.pinned[ref]; ok {
		return p, nil
	}
	return s.inner.Load(ctx, ref)
}

func (r *promptVersionRecorder) Load(ctx context.Context, ref string) (llmjudge.Prompt, error) {
	p, err := r.inner.Load(ctx, ref)
	if err != nil {
		return p, err
	}
	if r.pins == nil {
		r.pins = make(map[string]llmjudge.Prompt)
	}
	r.pins[ref] = p
	if r.firstVersion == "" {
		r.firstVersion = p.Version
	}
	return p, nil
}

// load compiles the org's enabled, attached, versioned pipelines as one
// candidate. An invalid active member rejects the entire candidate, so a
// partial set can never replace the last known-good snapshot.
//
// compiles against a fresh org-scoped registry — the judge factory is
// llmjudge.FactoryWith over the org's PromptSource and every
// builtin/partials-substitute step receives the org's PartialsSource.
// Engine construction is registry-only and cheap, and Engine.Run consults no
// registries (compiled steps are self-contained), so the plans still execute
// on the shared rt.engine. nil sources = feature-off: the shared engine and
// judge version is recorded — the D2 header stays absent when unwired).
//
// The second return is the judge prompt version identifier resolved for this
func (rt *PolicyRuntime) load(ctx context.Context, orgID string, previousEntries ...*orgPolicyEntry) ([]policyPlan, string, error) {
	var previous *orgPolicyEntry
	if len(previousEntries) > 0 {
		previous = previousEntries[0]
	}
	snapshot, err := rt.store.LoadPolicySnapshot(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("load policy snapshot: %w", err)
	}
	engine := rt.engine
	var partials builtins.PartialsSource
	var promptSource llmjudge.PromptSource
	if rt.sources != nil {
		promptSource = rt.sources.JudgePromptSource(orgID)
		judgeDeps := rt.orgJudgeDeps
		judgeDeps.Prompts = promptSource
		// Policy compilation is context-free by the pkg/pipeline contract
		// (CompilePolicy takes no ctx); the inner Background() lives in
		// llmjudge's compile-time prompt load, whose embedded source ignores its ctx.
		eng, err := newPolicyEngineWithJudgeDeps(rt.calloutAllowHosts, judgeDeps, rt.log) //nolint:contextcheck // policy compilation is context-free by the pkg/pipeline contract (CompilePolicy takes no ctx; the inner Background() lives in llmjudge's compile-time prompt load, whose embedded source ignores its ctx)
		if err != nil {
			return nil, "", fmt.Errorf("policy engine rebuild: %w", err)
		}
		engine = eng
		partials = builtins.PartialsSource(rt.sources.PartialsLookup(orgID))
	}
	plans := make([]policyPlan, 0, len(snapshot.Policies))
	for i := range snapshot.Policies {
		p := snapshot.Policies[i]
		if !p.Enabled {
			continue
		}
		atts := snapshot.Attachments[p.ID]
		if len(atts) == 0 {
			continue // no attachments = detached
		}
		if p.CurrentVersion <= 0 {
			return nil, "", invalidPolicyConfig(policyConfigStageActiveReference)
		}
		var rec *promptVersionRecorder
		if promptSource != nil {
			var pins map[string]llmjudge.Prompt
			stored := snapshot.PromptPins[fmt.Sprintf("%s@%d", p.ID, p.CurrentVersion)]
			if len(stored) > 0 {
				pins = make(map[string]llmjudge.Prompt, len(stored))
				for ref, pin := range stored {
					pins[ref] = llmjudge.Prompt{Ref: pin.Ref, Version: pin.Version, Body: pin.Body}
				}
			}
			if len(pins) == 0 && previous != nil {
				for _, prior := range previous.plans {
					if prior.policyID == p.ID && prior.version == p.CurrentVersion {
						pins = prior.promptPins
						break
					}
				}
			}
			rec = &promptVersionRecorder{inner: &pinnedPromptSource{inner: promptSource, pinned: pins}, pins: make(map[string]llmjudge.Prompt)}
			judgeDeps := rt.orgJudgeDeps
			judgeDeps.Prompts = rec
			eng, rebuildErr := newPolicyEngineWithJudgeDeps(rt.calloutAllowHosts, judgeDeps, rt.log) //nolint:contextcheck // policy compilation is context-free by the pkg/pipeline contract
			if rebuildErr != nil {
				return nil, "", fmt.Errorf("policy engine rebuild: %w", rebuildErr)
			}
			engine = eng
		}
		pv, ok := snapshot.Versions[p.ID]
		if !ok || pv.Version != p.CurrentVersion {
			return nil, "", invalidPolicyConfig(policyConfigStageActiveReference)
		}
		pp, err := pipeline.ParsePolicy([]byte(pv.YAML))
		if err != nil {
			return nil, "", invalidPolicyConfig(policyConfigStageYAMLDocument)
		}
		if err := pp.Validate(); err != nil {
			return nil, "", invalidPolicyConfig(policyConfigStageSchemaMode)
		}
		if partials != nil {
			injectPartialsSource(&pp, partials)
		}
		// Global kill-switch: shadow downgrades every policy at compile
		// time only after the stored policy has passed validation; the engine
		// then never mutates nor raises the verdict.
		if rt.mode == PolicyModeShadow {
			pp.Mode = pipeline.ModeShadow
		}
		compiled, err := engine.CompilePolicy(pp)
		if err != nil {
			return nil, "", invalidPolicyConfigCause(policyConfigStageStepCompile, err)
		}
		if rec != nil && len(rec.pins) > 0 {
			if writer, ok := rt.store.(policyPromptPinWriter); ok {
				persisted := make(map[string]adminstore.PromptPin, len(rec.pins))
				for ref, pin := range rec.pins {
					persisted[ref] = adminstore.PromptPin{Ref: pin.Ref, Version: pin.Version, Body: pin.Body}
				}
				if err := writer.SavePolicyPromptPins(ctx, orgID, p.ID, p.CurrentVersion, persisted); err != nil {
					return nil, "", fmt.Errorf("persist policy prompt pins: %w", err)
				}
			}
		}
		priority := atts[0].Priority
		for _, a := range atts[1:] {
			priority = min(priority, a.Priority)
		}
		plans = append(plans, policyPlan{
			policyID: p.ID,
			version:  p.CurrentVersion,
			priority: priority,
			compiled: compiled,
			atts:     atts,
			promptPins: func() map[string]llmjudge.Prompt {
				if rec == nil {
					return nil
				}
				return rec.pins
			}(),
			judgeVersion: func() string {
				if rec == nil {
					return ""
				}
				return rec.firstVersion
			}(),
		})
	}
	slices.SortStableFunc(plans, func(a, b policyPlan) int {
		if a.priority != b.priority {
			return a.priority - b.priority
		}
		return strings.Compare(a.policyID, b.policyID)
	})
	judgeVersion := ""
	for _, plan := range plans {
		if plan.judgeVersion != "" {
			judgeVersion = plan.judgeVersion
			break
		}
	}
	return plans, judgeVersion, nil
}

// injectPartialsSource binds the org partials source into every
// seam; the source rides step params at compile time — YAML cannot carry
// one). A step whose stored params already declare "source" is left alone:
// under strict YAML such a value can only be a non-source scalar, and
// NewPartialsSubstitute must keep rejecting it rather than being silently
// overwritten.
func injectPartialsSource(pp *pipeline.Policy, src builtins.PartialsSource) {
	for i := range pp.Steps {
		s := &pp.Steps[i]
		if s.Mutator != builtins.NamePartialsSubstitute {
			continue
		}
		if _, ok := s.Params["source"]; ok {
			continue
		}
		if s.Params == nil {
			s.Params = make(map[string]any, 1)
		}
		s.Params["source"] = src
	}
}

// evictLocked drops expired entries first, then oldest-loaded, while the map
// exceeds policyMaxOrgs. Caller holds rt.mu.
func (rt *PolicyRuntime) evictLocked(now time.Time) {
	if len(rt.orgs) <= policyMaxOrgs {
		return
	}
	for id, e := range rt.orgs {
		if now.Sub(e.loadedAt) >= rt.ttl {
			delete(rt.orgs, id)
		}
	}
	for len(rt.orgs) > policyMaxOrgs {
		oldestID := ""
		var oldest time.Time
		for id, e := range rt.orgs {
			if oldestID == "" || e.loadedAt.Before(oldest) {
				oldestID, oldest = id, e.loadedAt
			}
		}
		if oldestID == "" {
			return
		}
		delete(rt.orgs, oldestID)
	}
}

// --- matching ----------------------------------------------------------------

// policyQuery is the per-request attachment selector.
type policyQuery struct {
	endpoint  string
	hook      pipeline.Hook
	model     string
	keyLabels []string // key-source label keys+values from the request principal
}

// plansFor filters the org's plans to those attached to the query, in
// priority order. Matching: the policy declares the hook, and at least one
// attachment matches (endpoint equal, model pattern = '*' | trailing-star
// prefix | exact, key label empty = every key). Toolpolicy pattern semantics.
func (rt *PolicyRuntime) plansFor(e *orgPolicyEntry, q policyQuery) []policyPlan {
	if e == nil || len(e.plans) == 0 {
		return nil
	}
	var out []policyPlan
	for i := range e.plans {
		pl := &e.plans[i]
		if !slices.Contains(pl.compiled.Policy.Hooks, q.hook) {
			continue
		}
		for _, a := range pl.atts {
			if a.Endpoint != q.endpoint {
				continue
			}
			if !matchModelPattern(a.ModelPattern, q.model) {
				continue
			}
			if !matchKeyLabel(a.KeyLabel, q.keyLabels) {
				continue
			}
			out = append(out, *pl)
			break
		}
	}
	return out
}

// streamPlans is the streaming-hook selector (OP-4 seam, stream_policy.go):
// the org's plans attached to one streaming hook, in attachment-priority
// order. The hook is part of the query; the caller passes a query whose hook
// names the stream stage.
func (rt *PolicyRuntime) streamPlans(ctx context.Context, orgID string, q policyQuery) []policyPlan {
	return rt.plansFor(rt.requestOutcome(ctx, orgID).entry, q)
}

func (rt *PolicyRuntime) requestOutcome(ctx context.Context, orgID string) policyEntryOutcome {
	if outcome, ok := policyEntryOutcomeFromContext(ctx, rt, orgID); ok {
		return outcome
	}
	outcome := rt.entryWithOutcome(ctx, orgID)
	rt.recordLoadOutcome(outcome)
	return outcome
}

// judgeVersionHeaderKey is the chat response header carrying the resolved
// runtime is off/unwired, the org has no snapshot, or no judge template
// resolved for the org's compiled candidate.
const judgeVersionHeaderKey = "X-Policy-Judge-Version"

// judgePromptVersion reports the judge prompt/template version identifier
// observability; "" when none). Availability semantics follow the request-
// scoped outcome contract: on the chat path the outcome is stamped into the
// request before this runs, so this never triggers an extra store read
// there. Never gates — the value is diagnostic only.
func (rt *PolicyRuntime) judgePromptVersion(ctx context.Context, orgID string) string {
	if rt == nil || rt.coldUnavailable || orgID == "" {
		return ""
	}
	outcome := rt.requestOutcome(ctx, orgID)
	if outcome.entry == nil {
		return ""
	}
	return outcome.entry.judgeVersion
}

func (rt *PolicyRuntime) recordLoadOutcome(outcome policyEntryOutcome) {
	if outcome.loadErr == nil {
		return
	}
	cacheState := "cold"
	if outcome.stale {
		cacheState = "stale"
	}
	metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues(string(rt.mode), cacheState).Inc()
	failureClass := "store_read"
	var stage policyConfigStage
	var configErr *policyConfigError
	if errors.As(outcome.loadErr, &configErr) {
		failureClass = "invalid_config"
		stage = configErr.stage
	}
	if errors.Is(outcome.loadErr, context.Canceled) || errors.Is(outcome.loadErr, context.DeadlineExceeded) {
		failureClass = "context_canceled"
	} else if errors.Is(outcome.loadErr, errPolicyRuntimeUnavailable) {
		failureClass = "runtime_unavailable"
	}
	attrs := []any{"mode", string(rt.mode), "cache_state", cacheState, "failure_class", failureClass}
	if stage != "" {
		attrs = append(attrs, "stage", string(stage))
	}
	rt.log.Warn("policy load failed", attrs...)
}

// matchModelPattern mirrors pkg/toolpolicy's matcher: '*' alone matches all,
// a trailing '*' is a prefix wildcard, anything else is exact.
func matchModelPattern(pattern, model string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(model, pattern[:len(pattern)-1])
	}
	return pattern == model
}

// matchKeyLabel reports whether the attachment's key-label scope covers the
// request. Empty scope = every key. v1 semantics: a non-empty scope matches
// when any key-source label KEY or VALUE equals it (the attachment grammar
func matchKeyLabel(scope string, keyLabels []string) bool {
	if scope == "" {
		return true
	}
	return slices.Contains(keyLabels, scope)
}

// principalKeyLabels extracts the key-source label keys and values from the
// request context (the auth middleware's principal label sources).
func principalKeyLabels(ctx context.Context) []string {
	var out []string
	for _, src := range principalLabelSources(ctx) {
		if src.Name != "key" {
			continue
		}
		if src.Labels == nil {
			continue
		}
		for k, v := range src.Labels {
			out = append(out, k)
			if v != "" && v != k {
				out = append(out, v)
			}
		}
	}
	return out
}

// --- evaluation --------------------------------------------------------------

// policyFinding is one decision-record finding (category/severity only —
// never payload content; the OP-9 contract shape).
type policyFinding struct {
	Step     string `json:"step"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
}

// CORE-TRACE-05 decision-envelope vocabulary. Actions keep the pipeline
// strictness scale (deny > mask > flag > allow) for every action field;
// applied_action says what actually happened to the traffic, effective_action
// what the policy wanted (shadow policies report their would-have action and
// stay applied at allow). trace_completeness: full = complete bounded step
// list; partial = clipped, totals honest; absent = this decision type carries
// no step instrumentation (tool-policy) — never rendered as "no steps ran".
const (
	decisionEnvelopeVersion = 1

	ruleNamespacePolicy     = "policy"
	ruleNamespaceToolPolicy = "tool-policy"

	traceCompleteFull    = "full"
	traceCompletePartial = "partial"
	traceCompleteAbsent  = "absent"

	// policyMaxDecisionFindings / policyMaxTraceSteps bound one decision's
	// finding/step lists before the wire (the loggerd consumer enforces its
	// own identical caps and must only ever see an already-bounded list;
	// clipping is always stamped with explicit *_total/*_truncated markers).
	policyMaxDecisionFindings = 64
	policyMaxTraceSteps       = 64
	// policyMaxTraceFieldLen bounds skip reasons and step error strings —
	// engine-generated, value-free messages (never payload content).
	policyMaxTraceFieldLen = 512
)

// policyStepTrace is one step record of the decision envelope — the engine's
// StepTrace vocabulary, content-free. Error carries the failure message for
// error/timeout outcomes and the skip reason for skipped steps (engine
// semantics); bounded by policyMaxTraceFieldLen.
type policyStepTrace struct {
	Step     string `json:"step"`
	Outcome  string `json:"outcome"`
	Duration int64  `json:"duration_ms,omitempty"`
	Error    string `json:"error,omitempty"`
}

// policyDecision is one policy's decision record (Event.Policy element; the
// OP-9 contract — see pkg/eventpublisher.Event.Policy).
//
// CORE-TRACE-05 envelope (envelope_version 1): the pre-existing fields keep
// their exact semantics (Verdict stays the composed verdict — allow for
// shadow decisions, the degraded action for stream-final denials); the
// envelope fields add the explicit evaluation contract:
//
//	hook               which hook produced this record (pre_upstream, ...)
//	rule_namespace     policy | tool-policy (routing rules carry their own
//	                   TRACE-04 DecisionRuleRef on the routing decision)
//	matched            the policy actually triggered (findings or a
//	                   non-allow effective action) — absent means evaluated
//	                   but not triggered
//	effective_action   the action the policy determined (shadow: would-have)
//	applied_action     the action actually taken (shadow: allow, always)
//	steps[+totals]     bounded content-free engine step trace; an early deny
//	                   shows its tail as skipped, never as absent
//	trace_completeness full | partial | absent (see the constants above)
//
// All envelope fields are omitempty: absent means "producer predates the
// envelope / field not applicable", never a fabricated value.
type policyDecision struct {
	PolicyID      string          `json:"policy_id"`
	Name          string          `json:"name,omitempty"`
	Version       int             `json:"version"`
	EffectiveHash string          `json:"effective_hash"`
	Mode          string          `json:"mode"`
	Verdict       string          `json:"verdict"`
	Findings      []policyFinding `json:"findings,omitempty"`
	DurationMs    int64           `json:"duration_ms"`

	EnvelopeVersion   int               `json:"envelope_version,omitempty"`
	Hook              string            `json:"hook,omitempty"`
	RuleNamespace     string            `json:"rule_namespace,omitempty"`
	Matched           *bool             `json:"matched,omitempty"`
	EffectiveAction   string            `json:"effective_action,omitempty"`
	AppliedAction     string            `json:"applied_action,omitempty"`
	Steps             []policyStepTrace `json:"steps,omitempty"`
	StepsTotal        int               `json:"steps_total,omitempty"`
	StepsTruncated    bool              `json:"steps_truncated,omitempty"`
	FindingsTotal     int               `json:"findings_total,omitempty"`
	FindingsTruncated bool              `json:"findings_truncated,omitempty"`
	TraceCompleteness string            `json:"trace_completeness,omitempty"`
}

// evaluate runs the matching policies for one hook in attachment-priority
// order, propagating mutations across policies and stopping at the first
// deny (the engine composition law, applied per policy so each decision
// record keeps its own verdict and duration). Returns the decision records,
// the final payload when any policy changed it, and whether the composed
// outcome denies.
func (rt *PolicyRuntime) evaluate(ctx context.Context, orgID string, q policyQuery, in *pipeline.Payload) ([]policyDecision, *pipeline.Payload, bool) {
	return rt.evaluateFromOutcome(ctx, orgID, q, in, rt.requestOutcome(ctx, orgID))
}

func (rt *PolicyRuntime) evaluateWithOutcome(ctx context.Context, orgID string, q policyQuery, in *pipeline.Payload) ([]policyDecision, *pipeline.Payload, bool) {
	return rt.evaluateFromOutcome(ctx, orgID, q, in, rt.requestOutcome(ctx, orgID))
}

func (rt *PolicyRuntime) evaluateFromOutcome(ctx context.Context, orgID string, q policyQuery, in *pipeline.Payload, outcome policyEntryOutcome) ([]policyDecision, *pipeline.Payload, bool) {
	plans := rt.plansFor(outcome.entry, q)
	if len(plans) == 0 {
		return nil, nil, false
	}

	var decisions []policyDecision
	working := in
	changed := false
	denied := false
	for i := range plans {
		pl := &plans[i]
		start := time.Now()
		res := rt.engine.Run(ctx, []pipeline.Compiled{pl.compiled}, working)
		guardrailVerdict := policyGuardrailVerdict(res.Verdict)
		effectiveHash := effectivePolicyHash(pl)
		shadow := pl.compiled.Policy.Mode == pipeline.ModeShadow
		// CORE-TRACE-05: effective vs applied. Shadow policies report their
		// would-have action (engine ShadowVerdict) and stay applied at allow;
		// enforce applied is the action that actually took effect (a mask
		// verdict with no mutation degraded the traffic to flag-level
		// observation — recorded honestly, not as a mutation).
		effective := res.Verdict
		if shadow {
			effective = res.ShadowAction()
		}
		var applied pipeline.Action
		switch {
		case shadow:
			applied = pipeline.ActionAllow
		case guardrailVerdict == GuardrailDeny:
			applied = pipeline.ActionDeny
		case res.Mutated != nil:
			applied = pipeline.ActionMask
		case effective != pipeline.ActionAllow:
			applied = pipeline.ActionFlag
		default:
			applied = pipeline.ActionAllow
		}
		matched := len(res.Findings) > 0 || effective != pipeline.ActionAllow
		steps, stepsTotal, stepsTruncated := decisionStepsFromTrace(res.Trace)
		findings, findingsTotal, findingsTruncated := decisionFindings(res.Findings)
		dec := policyDecision{
			PolicyID:      pl.policyID,
			Name:          pl.compiled.Policy.Name,
			Version:       pl.version,
			EffectiveHash: effectiveHash,
			Mode:          string(pl.compiled.Policy.Mode),
			Verdict:       string(res.Verdict),
			DurationMs:    time.Since(start).Milliseconds(),

			EnvelopeVersion:   decisionEnvelopeVersion,
			Hook:              string(q.hook),
			RuleNamespace:     ruleNamespacePolicy,
			Matched:           &matched,
			EffectiveAction:   string(effective),
			AppliedAction:     string(applied),
			Steps:             steps,
			StepsTotal:        stepsTotal,
			StepsTruncated:    stepsTruncated,
			FindingsTotal:     findingsTotal,
			FindingsTruncated: findingsTruncated,
			TraceCompleteness: traceCompleteFull,
		}
		if stepsTruncated || findingsTruncated {
			dec.TraceCompleteness = traceCompletePartial
			// G4: the same truncation fact must surface on the request-row
			// stamp (owner arm 2: truncation ⇒ partial + reason), not only
			// inside the decision envelope.
			traceStampPolicyTruncation(ctx, stepsTruncated, findingsTruncated)
		}
		dec.Findings = findings
		decisions = append(decisions, dec)
		rt.recordMetrics(q, pl, res, time.Since(start), effectiveHash)

		if res.Mutated != nil {
			working = res.Mutated
			changed = true
		}
		if guardrailVerdict == GuardrailDeny {
			denied = true
			break
		}
	}
	var mutated *pipeline.Payload
	if changed {
		mutated = working
	}
	return decisions, mutated, denied
}

func effectivePolicyHash(pl *policyPlan) string {
	pins := make(map[string]string, len(pl.promptPins))
	for ref, prompt := range pl.promptPins {
		pins[ref] = prompt.Version
	}
	return pipeline.EffectivePolicyHash(pl.version, pl.compiled.Policy, pins)
}

// decisionStepsFromTrace renders the engine's step trace into the bounded,
// content-free envelope shape. The list is clipped at policyMaxTraceSteps
// with an honest total — an early deny keeps its tail as explicit skipped
// entries, never as silent absence (CORE-TRACE-05: skip/truncation must not
// read as "nothing ran").
func decisionStepsFromTrace(trace []pipeline.StepTrace) (steps []policyStepTrace, total int, truncated bool) {
	total = len(trace)
	clipped := trace
	if total > policyMaxTraceSteps {
		clipped = trace[:policyMaxTraceSteps]
		truncated = true
	}
	if total == 0 {
		return nil, 0, false
	}
	steps = make([]policyStepTrace, 0, len(clipped))
	for _, t := range clipped {
		steps = append(steps, policyStepTrace{
			Step:     boundTraceField(t.Step),
			Outcome:  string(t.Outcome),
			Duration: t.Duration.Milliseconds(),
			Error:    boundTraceField(t.Error),
		})
	}
	return steps, total, truncated
}

// decisionFindings clips the decision findings at the envelope bound with an
// honest total (the consumer re-enforces its identical cap and must never
// clip silently either).
func decisionFindings(findings []pipeline.Finding) (out []policyFinding, total int, truncated bool) {
	total = len(findings)
	clipped := findings
	if total > policyMaxDecisionFindings {
		clipped = findings[:policyMaxDecisionFindings]
		truncated = true
	}
	out = make([]policyFinding, 0, len(clipped))
	for _, f := range clipped {
		out = append(out, policyFinding{
			Step: boundTraceField(f.Step), Category: boundTraceField(f.Category),
			Severity: boundTraceField(f.Severity), Action: string(f.Action),
		})
	}
	return out, total, truncated
}

// boundTraceField clips one engine-generated trace string (skip reason, step
// error, step id, detector category) at the envelope bound. These strings are
// produced by the engine/detectors, not from payload content, but a
// pathological error message must still not inflate the event.
func boundTraceField(s string) string {
	if len(s) <= policyMaxTraceFieldLen {
		return s
	}
	return s[:policyMaxTraceFieldLen]
}

// policyGuardrailVerdict adapts the public pipeline result into the distinct
// gateway content-policy semantic. Authorization and route decisions never
// pass through this conversion.
func policyGuardrailVerdict(action pipeline.Action) GuardrailVerdict {
	switch action {
	case pipeline.ActionDeny:
		return GuardrailDeny
	case pipeline.ActionMask:
		return GuardrailRedact
	case pipeline.ActionFlag:
		return GuardrailAuditOnly
	case pipeline.ActionAllow:
		return GuardrailAllow
	default:
		return GuardrailDeny
	}
}

// recordMetrics emits the gateway_policy_* series for one policy run.
func (rt *PolicyRuntime) recordMetrics(q policyQuery, pl *policyPlan, res *pipeline.Result, dur time.Duration, effectiveHash string) {
	name := pl.compiled.Policy.Name
	metrics.GatewayPolicyRunsTotal.WithLabelValues(name, q.endpoint, string(res.Verdict)).Inc()
	if effectiveHash != "" {
		metrics.GatewayPolicyEffectiveInfo.WithLabelValues(name, effectiveHash).Set(1)
	}
	metrics.GatewayPolicyDurationMs.WithLabelValues(name, q.endpoint).Observe(float64(dur.Milliseconds()))
	switch res.Verdict {
	case pipeline.ActionDeny:
		metrics.GatewayPolicyDeniesTotal.WithLabelValues(name, q.endpoint).Inc()
	case pipeline.ActionMask:
		metrics.GatewayPolicyMasksTotal.WithLabelValues(name, q.endpoint).Inc()
	}
	if res.Mutated != nil && res.Verdict != pipeline.ActionMask {
		metrics.GatewayPolicyMasksTotal.WithLabelValues(name, q.endpoint).Inc()
	}
	if pl.compiled.Policy.Mode == pipeline.ModeShadow {
		metrics.GatewayPolicyShadowFlagsTotal.WithLabelValues(name, q.endpoint).Add(float64(len(res.Findings)))
	}
}

// marshalPolicyDecisions renders the Event.Policy payload (JSON array; empty
// string when nothing ran).
func marshalPolicyDecisions(decisions []policyDecision) string {
	if len(decisions) == 0 {
		return ""
	}
	b, err := json.Marshal(decisions)
	if err != nil {
		return ""
	}
	return string(b)
}

// appendPolicyEvents merges the post-upstream decision records into the
// pre-upstream ones (both are JSON arrays; parse failure degrades to the
// newer payload).
func appendPolicyEvents(base, add string) string {
	if base == "" {
		return add
	}
	if add == "" {
		return base
	}
	var merged []policyDecision
	if err := json.Unmarshal([]byte(base), &merged); err != nil {
		return add
	}
	var post []policyDecision
	if err := json.Unmarshal([]byte(add), &post); err != nil {
		return base
	}
	out, err := json.Marshal(append(merged, post...))
	if err != nil {
		return add
	}
	return string(out)
}

// --- gateway hooks -----------------------------------------------------------

type policyEventCtxKey struct{}

// withPolicyEvent stamps the decision-record JSON onto the request context so
// the finisher in the calling file can put it on the analytics event.
func withPolicyEvent(ctx context.Context, payload string) context.Context {
	if payload == "" {
		return ctx
	}
	return context.WithValue(ctx, policyEventCtxKey{}, payload)
}

// policyEventFrom reads the stamped decision-record JSON ("" when none).
func policyEventFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(policyEventCtxKey{}).(string)
	return s
}

// hasJudgeHeader reports whether the untrusted judge marker field is present.
// Values are deliberately ignored: even an empty or duplicate field is an
// unsupported attempt to re-enter through the public HTTP boundary.
func hasJudgeHeader(r *http.Request) bool {
	if r == nil {
		return false
	}
	for key := range r.Header {
		if strings.EqualFold(key, llmjudge.JudgeHeader) {
			return true
		}
	}
	return false
}

// policyMeta builds the payload routing identity.
func policyMeta(orgID, keyID, model, provider string) *pipeline.RequestMeta {
	return &pipeline.RequestMeta{Org: orgID, Key: keyID, Model: model, Provider: provider}
}

// metaLabelTeamScope is the meta-label key policyMetaWithTeam stamps with
// the auth-resolved team identity. The judge hop reads it back through
// hopTeamScope (agent_hop_budget.go): the hop context carries the request
// principal but never the team identity, so this label — carried onto the
// hop meta by llmjudge's judgeMeta (parent-label propagation landed in the
// T03 wave-17 addendum) — is the channel through which team-scoped judge
// hops attribute and budget.
const metaLabelTeamScope = "team"

// metaLabelWorkload is the meta-label key carrying the request's workload
// identity (N06-P07-T04). It has two writers: policyMetaWithTeam stamps the
// explicit X-Yabanin-Workload header onto payload meta labels, and
// admissionCore merges the resolved key (explicit or derived) into the
// request's label CONTEXT under the same name. The judge hop reads the
// context form through hopWorkloadScope (agent_hop_budget.go) for the
// workload cap and charges its settled actual against it; the settle events
// carry the label through the ctx-labels channel either way. Unlike the
// team scope this channel does not depend on judgeMeta propagation — the
// hop inherits the parent request's context.
const metaLabelWorkload = "workload"

// policyMetaWithTeam is policyMeta plus the team scope and the explicit
// workload identity. The gateway auth middleware deletes any client-sent
// X-Team-Id and re-sets it from the API key resolution (auth.go), so the
// header here is the trusted identity; the workload header is validated
// downstream by admissionCore (invalid → 400), so stamping it here only
// ever carries a well-formed value onto payloads the request still owns.
// Teamless, workloadless traffic keeps Labels nil — meta stays
// byte-identical to policyMeta's. The live stream-stage gate still uses
// policyMeta (out of this card's file scope) — that gap is a documented
// follow-up.
func policyMetaWithTeam(r *http.Request, orgID, model, provider string) *pipeline.RequestMeta {
	meta := policyMeta(orgID, r.Header.Get("X-API-Key-Id"), model, provider)
	metaLabels := map[string]string{}
	if team := r.Header.Get("X-Team-Id"); team != "" {
		metaLabels[metaLabelTeamScope] = team
	}
	if workload := r.Header.Get("X-Yabanin-Workload"); workload != "" {
		metaLabels[metaLabelWorkload] = workload
	}
	if len(metaLabels) > 0 {
		meta.Labels = metaLabels
	}
	return meta
}

// policyRequestPayload builds a request-kind payload; chat-shaped messages
// are projected alongside the raw body (detectors prefer Messages and fall
// back to Body).
func policyRequestPayload(endpoint string, body []byte, meta *pipeline.RequestMeta) *pipeline.Payload {
	p := &pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: endpoint, Body: body, Meta: meta}
	p.Messages = pipelineMessages(body)
	return p
}

// policyResponsePayload builds a response-kind payload (Body only — provider
// response bodies are not chat message arrays).
func policyResponsePayload(endpoint string, body []byte, meta *pipeline.RequestMeta) *pipeline.Payload {
	return &pipeline.Payload{Kind: pipeline.KindResponse, Endpoint: endpoint, Body: body, Meta: meta}
}

// pipelineMessages parses a chat.completions-shaped messages array; other
// shapes yield nil (detectors then scan the raw Body).
func pipelineMessages(body []byte) []pipeline.Message {
	if len(body) == 0 {
		return nil
	}
	var req struct {
		Messages []pipeline.Message `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	return req.Messages
}

// policyPreUpstream is the shared pre-upstream hook. It runs the pre_upstream
// hook of every matching policy, answers the deny with the error envelope
// (400 content_policy_violation) plus a request.invalid analytics event, and
// returns the (possibly masked) body and the decision-record JSON. ok=false
// means the request was answered terminally here.
func (gw *gateway) policyPreUpstream(w http.ResponseWriter, r *http.Request, endpoint, model, providerName string, body []byte) ([]byte, string, bool) {
	rt := gw.policyRuntime
	orgID := r.Header.Get("X-Org-Id")
	if hasJudgeHeader(r) {
		// is no successful snapshot for the authenticated org. Reuse any
		// request-scoped result so streams and retries cannot trigger a second
		// store read merely to choose this error.
		if rt != nil && rt.mode == PolicyModeEnforce && orgID != "" && !rt.hasSnapshot(orgID) {
			outcome, found := policyEntryOutcomeFromContext(r.Context(), rt, orgID)
			if !found {
				outcome = rt.entryWithOutcome(r.Context(), orgID)
				rt.recordLoadOutcome(outcome)
				*r = *r.WithContext(withPolicyEntryOutcome(r.Context(), rt, orgID, outcome))
			}
			var configErr *policyConfigError
			if errors.As(outcome.loadErr, &configErr) && outcome.entry == nil {
				apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
					"policy configuration unavailable", "policy_configuration_unavailable")
				return body, "", false
			}
			if outcome.loadErr != nil && outcome.entry == nil && rt.coldFailureMode == PolicyColdFailureFailClosed {
				apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
					"policy store temporarily unavailable", "policy_temporarily_unavailable")
				return body, "", false
			}
		}
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"unsupported judge re-entry", "judge_reentry_unsupported")
		return body, "", false
	}
	if rt == nil || rt.mode == PolicyModeOff {
		return body, "", true
	}
	if orgID == "" {
		return body, "", true
	}
	outcome, found := policyEntryOutcomeFromContext(r.Context(), rt, orgID)
	if !found {
		outcome = rt.entryWithOutcome(r.Context(), orgID)
		rt.recordLoadOutcome(outcome)
		*r = *r.WithContext(withPolicyEntryOutcome(r.Context(), rt, orgID, outcome))
	}
	var configErr *policyConfigError
	if errors.As(outcome.loadErr, &configErr) && outcome.entry == nil && rt.mode == PolicyModeEnforce {
		apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"policy configuration unavailable", "policy_configuration_unavailable")
		return body, "", false
	}
	if outcome.loadErr != nil && outcome.entry == nil && rt.mode == PolicyModeEnforce && rt.coldFailureMode == PolicyColdFailureFailClosed {
		apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"policy store temporarily unavailable", "policy_temporarily_unavailable")
		return body, "", false
	}
	meta := policyMetaWithTeam(r, orgID, model, providerName)
	q := policyQuery{endpoint: endpoint, hook: pipeline.HookPreUpstream, model: model, keyLabels: principalKeyLabels(r.Context())}
	// a recorded hint rides the request context to the routing call sites.
	sink := &routehint.Sink{}
	decisions, mutated, denied := rt.evaluateWithOutcome(routehint.WithSink(r.Context(), sink), orgID, q, policyRequestPayload(endpoint, body, meta))
	payloadJSON := marshalPolicyDecisions(decisions)

	if denied {
		l := logctx.From(r.Context(), gw.log)
		l.Warn("policy denied request",
			"org_id", orgID, "endpoint", endpoint, "model", model, "mode", string(rt.mode))
		gw.publishPolicyDenial(r, endpoint, model, payloadJSON, "request blocked by policy")
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"request blocked by organization policy", policyDenyErrorCode)
		return body, payloadJSON, false
	}
	if mutated != nil {
		body = mutated.Body
	}
	if hint := sink.Hint(); hint != "" {
		*r = *r.WithContext(routehint.WithHint(r.Context(), hint))
	}
	return body, payloadJSON, true
}

// policyPostUpstream is the shared post-upstream hook over a non-streaming
// upstream response body. It returns the (possibly masked) body, the merged
// decision-record JSON, and whether the composed verdict denies (the caller
// answers the denial instead of the upstream body).
func (gw *gateway) policyPostUpstream(r *http.Request, endpoint, model, providerName string, body []byte) ([]byte, string, bool) {
	rt := gw.policyRuntime
	if rt == nil {
		return body, "", false
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		return body, "", false
	}

	meta := policyMetaWithTeam(r, orgID, model, providerName)
	q := policyQuery{endpoint: endpoint, hook: pipeline.HookPostUpstream, model: model, keyLabels: principalKeyLabels(r.Context())}
	decisions, mutated, denied := rt.evaluate(r.Context(), orgID, q, policyResponsePayload(endpoint, body, meta))
	payloadJSON := marshalPolicyDecisions(decisions)

	if denied {
		logctx.From(r.Context(), gw.log).Warn("policy denied upstream response",
			"org_id", orgID, "endpoint", endpoint, "model", model)
		return body, payloadJSON, true
	}
	if mutated != nil {
		body = mutated.Body
	}
	return body, payloadJSON, false
}

// policyReplayStreamCheck re-governs a cached replay served to a STREAMING
// client with the CURRENT stream-stage policies: stream_prefix over the
// replayed content text and stream_final over the replay document — the same
// payload kinds, queries and meta a live stream would have fed them
// (newStreamPolicyWriter, stream.go). It closes the warm-cache bypass for
// stream-attached policies: policyPostUpstream only evaluates the
// post_upstream hook, so a deny attached to a stream stage and tightened
// after the response was cached would otherwise let the replay serve
// forbidden content (N03-P02-T02).
//
// Deny semantics: a replay has issued no bytes, so unlike a live stream —
// whose stream_final deny degrades to a flag after issuance
// (streamPolicyRunner.final) — the deny stays terminal here.
// stream_final mutations are recorded but not applied, matching live
// semantics; a stream_prefix mutation replaces the replayed
// choices[0].message.content (the live gate ingests delta.content,
// frameDeltaContent — content only). No-op when the runtime is off, the org
// is unset, or no plans are attached (rt.evaluate short-circuits on an empty
// plan set, so unconfigured orgs pay no extra work and no store reads — the
// request-scoped outcome is reused).
func (gw *gateway) policyReplayStreamCheck(r *http.Request, endpoint, model, providerName string, doc []byte) ([]byte, string, bool) {
	rt := gw.policyRuntime
	if rt == nil {
		return doc, "", false
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		return doc, "", false
	}

	meta := policyMetaWithTeam(r, orgID, model, providerName)
	ctx := r.Context()
	prefixQ := policyQuery{endpoint: endpoint, hook: pipeline.HookStreamPrefix, model: model, keyLabels: principalKeyLabels(ctx)}

	var decisions []policyDecision
	denied := false
	mutatedText := ""
	// A live gate with no content deltas ingests nothing; skip the prefix
	// stage for content-less documents — the final stage still audits the
	// whole document below.
	if text := replayContentText(doc); text != "" {
		pd, pm, pdenied := rt.evaluate(ctx, orgID, prefixQ, &pipeline.Payload{
			Kind: pipeline.KindStreamPrefix, Endpoint: endpoint, Body: []byte(text), Meta: meta,
		})
		decisions = append(decisions, pd...)
		denied = denied || pdenied
		if !pdenied && pm != nil {
			mutatedText = string(pm.Body)
		}
	}

	finalQ := prefixQ
	finalQ.hook = pipeline.HookStreamFinal
	fd, fm, fdenied := rt.evaluate(ctx, orgID, finalQ, &pipeline.Payload{
		Kind: pipeline.KindStreamFinal, Endpoint: endpoint, Body: doc, Meta: meta,
	})
	decisions = append(decisions, fd...)
	_ = fm // final-stage mutations are recorded, never applied (live parity)
	denied = denied || fdenied

	payloadJSON := marshalPolicyDecisions(decisions)
	if denied {
		logctx.From(ctx, gw.log).Warn("policy denied cached stream replay",
			"org_id", orgID, "endpoint", endpoint, "model", model)
		return doc, payloadJSON, true
	}
	if mutatedText != "" {
		if spliced, ok := spliceReplayContent(doc, mutatedText); ok {
			doc = spliced
		}
	}
	return doc, payloadJSON, false
}

// replayContentText extracts the choices[0].message.content text of a cached
// completion document — the same text a live stream's prefix gate ingests
// from delta.content (frameDeltaContent). "" when the shape does not match.
func replayContentText(doc []byte) string {
	var cc cachedCompletion
	if err := json.Unmarshal(doc, &cc); err != nil || len(cc.Choices) == 0 {
		return ""
	}
	return cc.Choices[0].Message.Content
}

// spliceReplayContent replaces choices[0].message.content in a cached
// completion document with the prefix-mutated text. Navigation through
// generic maps preserves every other document field; an unexpected shape
// returns the original document unchanged (the served replay stays
// consistent, the mutation stays recorded in the decision payload).
func spliceReplayContent(doc []byte, text string) ([]byte, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return doc, false
	}
	rawChoices, ok := m["choices"]
	if !ok {
		return doc, false
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil || len(choices) == 0 {
		return doc, false
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(choices[0]["message"], &msg); err != nil {
		return doc, false
	}
	content, err := json.Marshal(text)
	if err != nil {
		return doc, false
	}
	msg["content"] = content
	if choices[0]["message"], err = json.Marshal(msg); err != nil {
		return doc, false
	}
	if m["choices"], err = json.Marshal(choices); err != nil {
		return doc, false
	}
	out, err := json.Marshal(m)
	if err != nil {
		return doc, false
	}
	return out, true
}

// publishPolicyDenial emits the request.invalid event carrying the decision
// record (the OP-9 source of truth for pre-upstream denials — the normal
// completion event never fires on this path). Payload stays empty on this
// event: the denied content must not enter the log stream.
func (gw *gateway) publishPolicyDenial(r *http.Request, endpoint, model, policyJSON, message string) {
	publishEvent(gw.publisher, logctx.From(r.Context(), gw.log), eventBase{ //nolint:contextcheck // publishEvent creates its own timeout context internally — standard pattern in gateway
		EventType:      "request.invalid",
		RequestID:      logctx.RequestID(r.Context()),
		SessionID:      r.Header.Get("X-Session-Id"),
		Payload:        "",
		OrgID:          r.Header.Get("X-Org-Id"),
		TeamID:         r.Header.Get("X-Team-Id"),
		ModelRequested: model,
		Endpoint:       endpoint,
		Error:          message,
		Policy:         policyJSON,
		Labels:         labelsFrom(r.Context()),
	}.build())
}

// --- judge wiring (OP-3 deps over the gateway's own machinery) ---------------

// buildPolicyRuntime wires the OP-8 runtime into the gateway (called from the
// compliance facet builder). off-mode or no-DB deployments stay nil: every
// hook then short-circuits on the nil check and behavior is bit-for-bit
// pre-OP-8. A construction failure disables the pipeline loudly (Error log),
// never the boot: a broken registration must not take the whole gateway down
// (the pre-OP-8 fallback — traffic without pipeline — is the documented
// degradation, and the log names the exact cause).
func buildPolicyRuntime(ctx context.Context, w *gatewayWiring, gw *gateway) {
	if w.policy.Mode == "" || w.policy.Mode == PolicyModeOff {
		return
	}
	coldMode := w.policy.ColdFailureMode
	if coldMode != PolicyColdFailureFailOpen {
		coldMode = PolicyColdFailureFailClosed
	}
	if w.pool == nil {
		w.l.Info("policy pipeline unavailable: no database configured")
		gw.policyRuntime = newUnavailablePolicyRuntime(w.policy.Mode, coldMode, w.l.With("component", "policy-runtime"))
		return
	}
	reader, ok := policyPipelineReader(w.adminStore)
	if !ok {
		w.l.Error("policy pipeline unavailable: adminstore does not carry the policystore request surface")
		gw.policyRuntime = newUnavailablePolicyRuntime(w.policy.Mode, coldMode, w.l.With("component", "policy-runtime"))
		return
	}

	// policyPipelineReader pattern below). nil/unasserted = feature-off:
	// org judge prompts stay unwired (org: refs fail policy load) and
	promptStudio, hasPromptStudio := promptStudioSourcesFrom(w.adminStore)

	// OP-3: the judge client rides the gateway's own upstream pool with the
	// gateway's resolver + credential chain (org BYOK → per-model → global).
	// N06-P07-T03: the budgeted wrapper owns that same transport and adds
	// the loop cap, the G2 agent check, §5 admission/reservation and the
	// per-hop settlement event (agent_hop_budget.go) — judge hops ride the
	// SAME budget as interactive traffic.
	llmjudge.SetDefaultDeps(llmjudge.Deps{
		Client: gw.newBudgetedJudgeClient(gatewayJudgeModels{gw: gw}, gatewayJudgeKeys{gw: gw}),
	})

	var versions PolicyVersionReader
	if w.rdb != nil {
		versions = adminstore.NewPolicyVersionCache(w.rdb, w.l.With("component", "policy-versions"))
	}
	// Policy compilation is context-free by the pkg/pipeline contract
	// (LoadPolicy/CompilePolicy take no ctx); the inner Background() lives in
	// llmjudge's compile-time prompt load, whose embedded source ignores its ctx.
	rt, err := NewPolicyRuntime(reader, versions, w.policy.Mode, w.policy.CalloutAllowHosts, //nolint:contextcheck // policy compilation is context-free by the pkg/pipeline contract (LoadPolicy/CompilePolicy take no ctx; the inner Background() lives in llmjudge's compile-time prompt load, whose embedded source ignores its ctx)
		w.l.With("component", "policy-runtime"))
	if err != nil {
		w.l.Error("policy pipeline unavailable", "mode", string(w.policy.Mode))
		gw.policyRuntime = newUnavailablePolicyRuntime(w.policy.Mode, coldMode, w.l.With("component", "policy-runtime"))
		return
	}
	rt.coldFailureMode = coldMode
	rt.sources = promptStudio
	rt.orgJudgeDeps = llmjudge.DefaultDeps()
	gw.policyRuntime = rt
	w.l.InfoContext(ctx, "policy pipeline enabled", "mode", string(w.policy.Mode),
		"callout_allow_hosts", len(w.policy.CalloutAllowHosts),
		"version_key_invalidation", versions != nil,
		"prompt_studio_sources", hasPromptStudio)
}

// policyPipelineReader reports whether the concrete adminstore carries the
// frozen policystore request surface (structural assertion — the
// orgKeyResolver pattern; a nil store is feature-off).
func policyPipelineReader(s *adminstore.Store) (PolicyPipelineReader, bool) {
	if s == nil {
		return nil, false
	}
	if r, ok := interface{}(s).(PolicyPipelineReader); ok {
		return r, true
	}
	return nil, false
}

// promptStudioSources is the gateway-local structural seam over the
// pattern): org-scoped judge prompts and partial bodies consumed by the
// per-org policy compile in rt.load. The PartialsLookup return type is the
// adminstore-side twin interface — structurally identical to
// builtins.PartialsSource, so its values ride the step "source" param
// directly.
type promptStudioSources interface {
	JudgePromptSource(orgID string) llmjudge.PromptSource
	PartialsLookup(orgID string) adminstore.PartialsSource
}

// promptStudioSourcesFrom reports whether the concrete adminstore carries
// the prompt-studio request surface (structural assertion; nil = off).
func promptStudioSourcesFrom(s *adminstore.Store) (promptStudioSources, bool) {
	if s == nil {
		return nil, false
	}
	if srcs, ok := interface{}(s).(promptStudioSources); ok {
		return srcs, true
	}
	return nil, false
}

// gatewayJudgeModels resolves judge model references through the gateway's
// normal resolver path (registry, aliases, fallbacks) — llmjudge.ModelResolver.
type gatewayJudgeModels struct {
	gw *gateway
}

// ResolveJudgeModel implements llmjudge.ModelResolver.
func (r gatewayJudgeModels) ResolveJudgeModel(ctx context.Context, ref string) (llmjudge.Target, error) {
	info, err := r.gw.resolveModelInfo(ctx, ref)
	if err != nil {
		return llmjudge.Target{}, fmt.Errorf("judge model %q: %w", ref, err)
	}
	if info.ModelName == "" {
		return llmjudge.Target{}, fmt.Errorf("judge model %q: unknown", ref)
	}
	return llmjudge.Target{
		Model:       info.ModelName,
		Provider:    info.Provider,
		UpstreamURL: r.gw.upstreamURL(info),
		Timeout:     info.UpstreamTimeout,
	}, nil
}

// gatewayJudgeKeys resolves judge credentials through the same priority chain
// as client traffic (org BYOK → per-model key → global) — llmjudge.KeyResolver.
// The resolved plaintext rides only this one judge attempt (never cached).
type gatewayJudgeKeys struct {
	gw *gateway
}

// ResolveJudgeKey implements llmjudge.KeyResolver.
func (r gatewayJudgeKeys) ResolveJudgeKey(ctx context.Context, orgID string, target llmjudge.Target) (string, error) {
	mi := resolver.ModelInfo{ModelName: target.Model, Provider: target.Provider, UpstreamURL: target.UpstreamURL}
	key, _, err := r.gw.resolveUpstreamKey(ctx, orgID, mi)
	return key, err
}

// compile-time interface checks.
var (
	_ llmjudge.ModelResolver = gatewayJudgeModels{}
	_ llmjudge.KeyResolver   = gatewayJudgeKeys{}
	_ promptStudioSources    = (*adminstore.Store)(nil)
	_ PolicyPipelineReader   = (*adminstore.Store)(nil)
)
