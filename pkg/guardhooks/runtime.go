package guardhooks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// RuntimeVersion identifies the stable request/verdict and built-in rule
// contract implemented by this package.
const RuntimeVersion = "guardrails.v1"

// MaxFindingsPerDetection bounds retained findings across a single evaluator
// request. Further findings are dropped and counted in the
// gateway_guard_findings_truncated_total counter (pkg/metrics).
const MaxFindingsPerDetection = 10_000

// Phase identifies whether content is observed before or after an operation.
type Phase string

const (
	// PhaseBefore inspects content before an operation.
	PhaseBefore Phase = "before"
	// PhaseAfter inspects content after an operation.
	PhaseAfter Phase = "after"
)

// ContentKind describes which value in an invocation is being inspected.
type ContentKind string

const (
	// ContentText is plain text.
	ContentText ContentKind = "text"
	// ContentArguments is tool input.
	ContentArguments ContentKind = "arguments"
	// ContentResult is tool output.
	ContentResult ContentKind = "result"
)

// Invocation is the versioned detector input. Only one content field should
// be populated; the named fields allow adapters to retain structured inputs.
type Invocation struct {
	Context   context.Context
	Version   string
	Phase     Phase
	Kind      ContentKind
	Text      string
	Arguments []byte
	Result    []byte
}

// Content returns the selected invocation projection after validating the
// versioned envelope: an unsupported RuntimeVersion, phase or content kind is
// a loud error (never a silent empty projection). It is the shared input
// decoder for every detector, including external adapters.
func (i Invocation) Content() (string, error) {
	if i.Version != RuntimeVersion {
		return "", fmt.Errorf("guardrails: unsupported invocation version %q", i.Version)
	}
	if i.Phase != PhaseBefore && i.Phase != PhaseAfter {
		return "", fmt.Errorf("guardrails: invalid phase %q", i.Phase)
	}
	switch i.Kind {
	case ContentText:
		return i.Text, nil
	case ContentArguments:
		return string(i.Arguments), nil
	case ContentResult:
		return string(i.Result), nil
	default:
		return "", fmt.Errorf("guardrails: invalid content kind %q", i.Kind)
	}
}

// Verdict is the guardrail outcome; it is deliberately separate from
// authorization and routing decisions.
type Verdict string

const (
	// VerdictAllow observes no blocking action.
	VerdictAllow Verdict = "allow"
	// VerdictDeny rejects the operation.
	VerdictDeny Verdict = "deny"
	// VerdictRedact requests a mutation.
	VerdictRedact Verdict = "redact"
	// VerdictAuditOnly records without mutation.
	VerdictAuditOnly Verdict = "audit-only"
)

// FailureMode is the policy mode used when a guardrail detector cannot
// produce a verdict. It is independent of authorization and routing.
type FailureMode string

const (
	// FailureModeOff means optional guardrail evaluation is not required.
	FailureModeOff FailureMode = "off"
	// FailureModeShadow audits evaluation errors without changing the client operation.
	FailureModeShadow FailureMode = "shadow"
	// FailureModeEnforce fails closed when a required guardrail evaluation errors.
	FailureModeEnforce FailureMode = "enforce"
)

// FailureOutcome maps a guardrail evaluation error to its observable verdict
// and whether the operation must be blocked. The original error remains
// available to the caller for audit; shadow is never represented as allow.
func FailureOutcome(mode FailureMode, err error) (Verdict, bool) {
	if err == nil {
		return VerdictAllow, false
	}
	if mode == FailureModeShadow {
		return VerdictAuditOnly, false
	}
	return VerdictDeny, true
}

// RuleVersion identifies one rule within a versioned pack.
type RuleVersion struct {
	PackID      string
	PackVersion string
	RuleID      string
	RuleVersion string
}

// VersionedDetector is the extension SPI shared by built-in and user-provided
// detectors. Implementations must be safe for concurrent calls.
type VersionedDetector interface {
	Identity() RuleVersion
	Detect(Invocation) ([]Finding, error)
}

// Evaluation is an immutable detector result. Findings contain metadata and
// offsets only; content is never copied into this value.
type Evaluation struct {
	Version  string
	Verdict  Verdict
	Findings []Finding
}

// Evaluator runs built-in and extension detectors through the same SPI.
type Evaluator struct {
	detectors []VersionedDetector
}

var builtinEvaluator = BuiltinEvaluator()

// NewEvaluator validates and creates an evaluator over versioned detectors.
func NewEvaluator(detectors ...VersionedDetector) (*Evaluator, error) {
	seen := make(map[RuleVersion]struct{}, len(detectors))
	registered := make([]VersionedDetector, 0, len(detectors))
	for _, d := range detectors {
		if d == nil {
			return nil, errors.New("guardrails: nil detector")
		}
		id := d.Identity()
		if id.PackID == "" || id.PackVersion == "" || id.RuleID == "" || id.RuleVersion == "" {
			return nil, errors.New("guardrails: detector identity must include pack and rule versions")
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("guardrails: duplicate detector %s/%s", id.PackID, id.RuleID)
		}
		seen[id] = struct{}{}
		registered = append(registered, d)
	}
	slices.SortFunc(registered, func(a, b VersionedDetector) int {
		ai, bi := a.Identity(), b.Identity()
		if ai.PackID != bi.PackID {
			return cmpString(ai.PackID, bi.PackID)
		}
		if ai.RuleID != bi.RuleID {
			return cmpString(ai.RuleID, bi.RuleID)
		}
		return cmpString(ai.RuleVersion, bi.RuleVersion)
	})
	return &Evaluator{detectors: registered}, nil
}

// NewExtendedEvaluator combines the immutable built-in chain with additional
// pack detectors while applying the same identity and duplicate validation.
func NewExtendedEvaluator(detectors ...VersionedDetector) (*Evaluator, error) {
	all := append([]VersionedDetector(nil), builtinEvaluator.detectors...)
	all = append(all, detectors...)
	return NewEvaluator(all...)
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Evaluate performs detection without applying an action. A detector error
// is returned and never converted into an allow verdict.
func (e *Evaluator) Evaluate(in Invocation) (Evaluation, error) {
	if e == nil {
		return Evaluation{}, errors.New("guardrails: nil evaluator")
	}
	if in.Context == nil {
		return Evaluation{}, errors.New("guardrails: nil context")
	}
	content, err := in.Content()
	if err != nil {
		return Evaluation{}, err
	}
	result := Evaluation{Version: RuntimeVersion, Verdict: VerdictAllow}
	truncated := 0
	for _, d := range e.detectors {
		if err := in.Context.Err(); err != nil {
			return Evaluation{}, err
		}
		findings, err := detectSafely(d, in)
		if err != nil {
			return Evaluation{}, fmt.Errorf("guardrails detector %s/%s: %w", d.Identity().PackID, d.Identity().RuleID, err)
		}
		for _, f := range findings {
			if f.Start < 0 || f.End < f.Start || f.End > len(content) {
				return Evaluation{}, fmt.Errorf("guardrails detector %s/%s returned invalid span", d.Identity().PackID, d.Identity().RuleID)
			}
			if len(result.Findings) >= MaxFindingsPerDetection {
				truncated++
				continue
			}
			result.Findings = append(result.Findings, f)
		}
	}
	if truncated > 0 {
		metrics.GuardFindingsTruncatedTotal.Add(float64(truncated))
		slog.Warn("guard findings truncated", "limit", MaxFindingsPerDetection, "dropped_at_least", truncated)
	}
	return result, nil
}

// detectSafely keeps a faulty extension from panicking through a gateway
// request. The error remains explicit so the caller can apply its configured
// enforce/shadow failure posture rather than treating a panic as a clean scan.
func detectSafely(d VersionedDetector, in Invocation) (findings []Finding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			findings = nil
			err = fmt.Errorf("detector panic: %v", recovered)
		}
	}()
	return d.Detect(in)
}

// EvaluateBuiltins runs the versioned core pack through the public SPI.
func EvaluateBuiltins(in Invocation) (Evaluation, error) {
	return builtinEvaluator.Evaluate(in)
}

// Apply returns the actioned output for one evaluation. Redaction itself is
// deliberately delegated to the configured compatibility mutator because
// detector-specific replacements and structured mutations are pack-owned.
func Apply(e Evaluation, action Verdict, redact func() []byte) ([]byte, Verdict, error) {
	if e.Version != RuntimeVersion {
		return nil, "", fmt.Errorf("guardrails: unsupported evaluation version %q", e.Version)
	}
	if len(e.Findings) == 0 {
		return nil, VerdictAllow, nil
	}
	switch action {
	case VerdictAllow, VerdictAuditOnly:
		return nil, action, nil
	case VerdictDeny:
		return nil, VerdictDeny, nil
	case VerdictRedact:
		if redact == nil {
			return nil, "", errors.New("guardrails: redact action requires mutator")
		}
		return redact(), VerdictRedact, nil
	default:
		return nil, "", fmt.Errorf("guardrails: invalid action %q", action)
	}
}

type builtinAdapter struct{ Detector }

func (d builtinAdapter) Identity() RuleVersion {
	return RuleVersion{PackID: "core.guardrails", PackVersion: "1", RuleID: d.Name(), RuleVersion: "1"}
}

func (d builtinAdapter) Detect(in Invocation) ([]Finding, error) {
	if err := in.Context.Err(); err != nil {
		return nil, err
	}
	text, err := in.Content()
	if err != nil {
		return nil, err
	}
	return d.Detector.Detect(text), nil
}

// BuiltinEvaluator registers the shipped offline detectors using the same
// extension SPI and evaluator as customer detectors.
func BuiltinEvaluator() *Evaluator {
	detectors := DefaultDetectors()
	wrapped := make([]VersionedDetector, 0, len(detectors))
	for _, d := range detectors {
		wrapped = append(wrapped, builtinAdapter{Detector: d})
	}
	// credential-key detection is a built-in rule with the same contract.
	wrapped = append(wrapped, credentialKeyDetector{})
	e, _ := NewEvaluator(wrapped...)
	return e
}

type credentialKeyDetector struct{}

func (credentialKeyDetector) Identity() RuleVersion {
	return RuleVersion{PackID: "core.guardrails", PackVersion: "1", RuleID: "credential:key-value", RuleVersion: "1"}
}

func (credentialKeyDetector) Detect(in Invocation) ([]Finding, error) {
	if err := in.Context.Err(); err != nil {
		return nil, err
	}
	text, err := in.Content()
	if err != nil {
		return nil, err
	}
	spans := credentialKeyRe.FindAllStringIndex(text, -1)
	out := make([]Finding, 0, len(spans))
	for _, span := range spans {
		out = append(out, Finding{Category: CatCredential, Start: span[0], End: span[1], Confidence: 1, Detector: "credential:key-value"})
	}
	return out, nil
}
