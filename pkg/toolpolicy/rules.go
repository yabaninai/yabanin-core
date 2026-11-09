// OP-6 tool-call guardrails: compiled guard rules evaluated on tool
// arguments (pre-egress) and tool results (post-egress).
//
// Rule wire shape (the `tool_policies.rules` JSONB column AND the params of
// the builtin/toolpolicy pipeline step — one shape, two shells):
//
//	{
//	  "args":   {"schema": {...}, "max_bytes": 8192, "deny_regex": ["..."]},
//	  "result": {"mode": "flag|mask|deny", "secrets": true, "deny_regex": ["..."]},
//	  "fail":   "closed" | "open",
//	  "credential_mode": "auto" | "service" | "delegated"
//	}
//
// union + most-restrictive semantics, docs/plans/OUTPLAY-PLAN-2026-10-06 §2.2):
//
//   - Guard rules are PURELY RESTRICTIVE: a rule can only add restrictions,
//     never loosen one. Every matching enabled rule applies (union); the
//     composed outcome is the most restrictive action deny > mask > flag —
//     exactly the pipeline.Action.Rank order, so a rule verdict composes
//     with the OP-8 pipeline composition without translation.
//   - Specificity (org → server → tool → subject) selects only the
//     allow/deny WINNER (Engine.DecideTool); it never reduces which guard
//     rules apply. A less-specific rule cannot carve an exception out of a
//     more-specific one.
//   - Fail modes are per rule ("closed" default): fail_closed rules turn a
//     policy-loader outage into denies; fail_open rules (perf-sensitive
//     guards) keep traffic flowing. The org posture is the most protective
//     fail mode of its enabled rules (Engine.guardPosture).
//
// SECURITY INVARIANTS: findings carry ONLY the source, category and a span
// or JSON pointer — never the matched value, never the schema-rejected
// instance fragment. Error strings produced here are value-free by
// construction (guardhooks spans are offsets; jsonschema errors are reduced
// to instance location + schema keyword path because the library's
// LocalizedString can embed the instance value).
package toolpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Bounds on rule payloads. Enforced at compile time (the admin CRUD calls
// ValidateRulesJSON, the engine re-compiles on load) so a rule can never
// make the hot path unbounded.
const (
	// MaxRulesBytes bounds the whole rules JSON document.
	MaxRulesBytes = 64 << 10
	// maxSchemaBytes bounds one embedded JSON Schema document.
	maxSchemaBytes = 32 << 10
	// maxRegexes bounds each deny_regex list.
	maxRegexes = 16
	// maxRegexLen bounds one RE2 pattern.
	maxRegexLen = 512
	// maxArgBytesUpper bounds the max_bytes knob (an args cap above the
	// proxy's response cap is meaningless).
	maxArgBytesUpper = 16 << 20
	// maxFindingsPerCheck bounds the findings one check may report (a
	// pathological payload must not flood the decision log).
	maxFindingsPerCheck = 32
)

// ResultAction is the action for the result post-check (the args side is
// deny-shaped: a schema violation, an oversize payload or a forbidden
// pattern blocks the call outright).
type ResultAction string

// Result actions, most restrictive last.
const (
	ResultFlag ResultAction = "flag" // proceed, record the observation
	ResultMask ResultAction = "mask" // proceed with the redacted result
	ResultDeny ResultAction = "deny" // drop the result (the call already ran)
)

// Rank is the strictness of a on deny(3) > mask(2) > flag(1) > none(0) —
// mirrors pipeline.Action.Rank so verdicts compose across lanes.
func (a ResultAction) Rank() int {
	switch a {
	case ResultDeny:
		return 3
	case ResultMask:
		return 2
	case ResultFlag:
		return 1
	default:
		return 0
	}
}

// Fail modes.
const (
	FailClosed = "closed" // loader/eval failure ⇒ deny (security rules)
	FailOpen   = "open"   // failure ⇒ proceed (perf-sensitive rules)
)

// ArgsRule guards the tool-call arguments.
type ArgsRule struct {
	// Schema is a JSON Schema (draft 2020-12) the serialized args object
	// must validate. Compiled once at rule load; see the package comment
	// for the validator choice rationale.
	Schema json.RawMessage `json:"schema,omitempty"`
	// MaxBytes caps the serialized args size in bytes (0 = unlimited).
	MaxBytes int64 `json:"max_bytes,omitempty"`
	// DenyRegex lists RE2 patterns; any match in the serialized args
	// denies the call. Go regexp is RE2: linear time, no ReDoS.
	DenyRegex []string `json:"deny_regex,omitempty"`
}

// ResultRule post-checks the serialized upstream tool result.
type ResultRule struct {
	// Mode prescribes the outcome when the rule matches: flag (default
	// when a ResultRule is present), mask (proceed redacted) or deny.
	Mode ResultAction `json:"mode,omitempty"`
	// Secrets runs the pkg/guardhooks default detectors (secrets, PAN,
	// national PII, injection phrases) over the serialized result.
	Secrets bool `json:"secrets,omitempty"`
	// DenyRegex lists RE2 patterns; matches follow Mode.
	DenyRegex []string `json:"deny_regex,omitempty"`
}

// RuleSpec is the wire shape of one policy's guard rules.
type RuleSpec struct {
	Args   *ArgsRule   `json:"args,omitempty"`
	Result *ResultRule `json:"result,omitempty"`
	// Fail is the fail mode: "closed" (default) or "open".
	Fail string `json:"fail,omitempty"`
	// CredentialMode pins the credential mode for calls this policy matches
	// (N05-P02-T04): "service" = org service credential only, "delegated" =
	// the user's delegated credential only, "auto" = explicitly no
	// constraint. "" = the row carries no credential-mode constraint (the
	// server's connection-config mode governs). It is a DECISION input
	// (Engine.DecideCredMode follows the specificity winner), unlike the
	// guard rules above which compose union + most-restrictive — so an
	// unconstrained row never loosens a constrained one: rows without a
	// credential_mode simply do not participate in the mode ranking.
	// Vocabulary values are intentionally identical to pkg/mcpagg's
	// CredMode* constants (migration 0016); the equality is pinned by a
	// test in pkg/mcpagg (this package must not import it — cycle).
	CredentialMode string `json:"credential_mode,omitempty"`
}

// Finding is one guard observation. It NEVER carries the matched value:
// Span is either "start:end" byte offsets (regex/secret hits) or a JSON
// pointer into the args document (schema violations); Category is the
// detector category (guardhooks vocabulary) or the schema keyword path.
type Finding struct {
	Source   string `json:"source"`   // schema | max_size | deny_regex | secrets
	Category string `json:"category"` // guardhooks category or schema keyword
	Span     string `json:"span"`     // "start:end" or JSON pointer
	Action   string `json:"action"`   // deny | mask | flag
}

// ArgsReport is the pre-egress args verdict (deny-shaped).
type ArgsReport struct {
	Denied   bool
	Reason   string // value-free, names the rule source and policy
	Findings []Finding
	// Degraded reports a policy-loader outage answered fail-open (the org
	// posture is fail-open): the call proceeded UNGUARDED and the caller
	// should count it as an error, not an allow.
	Degraded bool
}

// ResultReport is the post-egress result verdict.
type ResultReport struct {
	Action   ResultAction // "" = the policy carries no result rules
	Reason   string       // value-free
	Masked   []byte       // set iff Action == mask
	Findings []Finding
	// Degraded: see ArgsReport.Degraded.
	Degraded bool
}

// Rules is one policy's compiled guard rules. Immutable after Compile; safe
// for concurrent use (only precompiled derived values are held).
type Rules struct {
	spec RuleSpec

	argsSchema   *jsonschema.Schema
	argsMaxBytes int64
	argsDeny     []*regexp.Regexp

	resultMode    ResultAction
	resultSecrets bool
	resultDeny    []*regexp.Regexp

	failClosed bool

	// credentialMode is the compiled credential-mode constraint (validated
	// vocabulary; "" = none). Decision input for Engine.DecideCredMode.
	credentialMode string
}

// CredentialMode returns the compiled credential-mode constraint for this
// rule document: "" (no constraint), CredentialModeAuto, CredentialModeService
// or CredentialModeDelegated.
func (r *Rules) CredentialMode() string { return r.credentialMode }

// ValidateRulesJSON bounds and compiles a rules document without keeping the
// compiled form (admin CRUD write path). A nil/empty doc is valid (no rules).
func ValidateRulesJSON(raw json.RawMessage) error {
	_, err := CompileRules(raw)
	return err
}

// CompileRules validates and compiles a rules document. Every failure names
// the offending part; nothing about the CALLER'S data can fail here (only
// the rule author's input).
func CompileRules(raw json.RawMessage) (*Rules, error) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return &Rules{failClosed: true}, nil
	}
	if len(raw) > MaxRulesBytes {
		return nil, fmt.Errorf("toolpolicy: rules too large (%d bytes, max %d)", len(raw), MaxRulesBytes)
	}
	var spec RuleSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("toolpolicy: rules: %w", err)
	}
	r := &Rules{spec: spec, failClosed: true}
	switch spec.Fail {
	case "", FailClosed:
		r.failClosed = true
	case FailOpen:
		r.failClosed = false
	default:
		return nil, fmt.Errorf("toolpolicy: rules.fail must be %q or %q", FailClosed, FailOpen)
	}
	// N05-P02-T04: the credential-mode constraint is a closed vocabulary —
	// an unknown value must be rejected at write time and at load time
	// (defense in depth for out-of-band rows), never silently ignored.
	switch spec.CredentialMode {
	case "":
		r.credentialMode = ""
	case CredentialModeAuto, CredentialModeService, CredentialModeDelegated:
		r.credentialMode = spec.CredentialMode
	default:
		return nil, fmt.Errorf("toolpolicy: rules.credential_mode must be %q, %q or %q",
			CredentialModeAuto, CredentialModeService, CredentialModeDelegated)
	}
	if spec.Args == nil && spec.Result == nil && spec.CredentialMode == "" {
		return nil, fmt.Errorf("toolpolicy: rules must define args or result checks")
	}
	if spec.Args != nil {
		if len(spec.Args.Schema) > maxSchemaBytes {
			return nil, fmt.Errorf("toolpolicy: rules.args.schema too large (%d bytes, max %d)", len(spec.Args.Schema), maxSchemaBytes)
		}
		if len(spec.Args.Schema) > 0 {
			sch, err := compileSchema(spec.Args.Schema)
			if err != nil {
				return nil, fmt.Errorf("toolpolicy: rules.args.schema: %w", err)
			}
			r.argsSchema = sch
		}
		if spec.Args.MaxBytes < 0 || spec.Args.MaxBytes > maxArgBytesUpper {
			return nil, fmt.Errorf("toolpolicy: rules.args.max_bytes must be 0..%d", maxArgBytesUpper)
		}
		r.argsMaxBytes = spec.Args.MaxBytes
		res, err := compileRegexes(spec.Args.DenyRegex)
		if err != nil {
			return nil, fmt.Errorf("toolpolicy: rules.args.deny_regex: %w", err)
		}
		r.argsDeny = res
		if r.argsSchema == nil && r.argsMaxBytes == 0 && len(r.argsDeny) == 0 {
			return nil, fmt.Errorf("toolpolicy: rules.args defines no checks")
		}
	}
	if spec.Result != nil {
		switch spec.Result.Mode {
		case "", ResultFlag:
			r.resultMode = ResultFlag
		case ResultMask, ResultDeny:
			r.resultMode = spec.Result.Mode
		default:
			return nil, fmt.Errorf("toolpolicy: rules.result.mode must be %q, %q or %q", ResultFlag, ResultMask, ResultDeny)
		}
		r.resultSecrets = spec.Result.Secrets
		res, err := compileRegexes(spec.Result.DenyRegex)
		if err != nil {
			return nil, fmt.Errorf("toolpolicy: rules.result.deny_regex: %w", err)
		}
		r.resultDeny = res
		if !r.resultSecrets && len(r.resultDeny) == 0 {
			return nil, fmt.Errorf("toolpolicy: rules.result defines no checks")
		}
	}
	return r, nil
}

// compileSchema compiles one JSON Schema document. Justification for the
// library (task item 1): github.com/santhosh-tekuri/jsonschema/v6 is ALREADY
// a direct dependency (pkg/agenteval) — no new supply-chain surface; it
// implements full draft 2020-12 ($ref/oneOf/allOf — real MCP/OpenAPI-style
// tool schemas use them, a hand-rolled light validator would silently
// under-enforce); its pattern keyword compiles through Go regexp (RE2,
// linear-time, ReDoS-safe). The doc size cap bounds compile cost; compiles
// happen at rule load / admin write, never on the invoke hot path.
func compileSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

func compileRegexes(list []string) ([]*regexp.Regexp, error) {
	if len(list) > maxRegexes {
		return nil, fmt.Errorf("%d patterns, max %d", len(list), maxRegexes)
	}
	out := make([]*regexp.Regexp, 0, len(list))
	for i, p := range list {
		if len(p) == 0 {
			return nil, fmt.Errorf("regex[%d]: empty pattern", i)
		}
		if len(p) > maxRegexLen {
			return nil, fmt.Errorf("regex[%d]: %d bytes, max %d", i, len(p), maxRegexLen)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("regex[%d]: %w", i, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// CheckArgs evaluates the args guards. All configured checks run (full
// diagnostics); any violation denies.
func (r *Rules) CheckArgs(args []byte) ArgsReport {
	var rep ArgsReport
	add := func(f Finding) {
		if len(rep.Findings) < maxFindingsPerCheck {
			rep.Findings = append(rep.Findings, f)
		}
	}
	deny := func(f Finding) {
		f.Action = "deny"
		rep.Denied = true
		add(f)
	}
	if r.argsMaxBytes > 0 && int64(len(args)) > r.argsMaxBytes {
		deny(Finding{Source: "max_size", Category: "args_size",
			Span: fmt.Sprintf("0:%d", len(args))})
	}
	if r.argsSchema != nil {
		var v any
		if err := json.Unmarshal(args, &v); err != nil {
			deny(Finding{Source: "schema", Category: "invalid_json", Span: "/"})
		} else if err := r.argsSchema.Validate(v); err != nil {
			for _, f := range schemaFindings(err) {
				deny(f)
			}
		}
	}
	for i, re := range r.argsDeny {
		for _, span := range re.FindAllStringIndex(string(args), -1) {
			deny(Finding{Source: "deny_regex", Category: fmt.Sprintf("regex[%d]", i),
				Span: fmt.Sprintf("%d:%d", span[0], span[1])})
			if len(rep.Findings) >= maxFindingsPerCheck {
				break
			}
		}
	}
	if rep.Denied && rep.Reason == "" {
		rep.Reason = reason(rep.Findings)
	}
	return rep
}

// schemaFindings reduces a jsonschema validation error to value-free
// findings: the JSON pointer of the offending instance location plus the
// SCHEMA keyword path. The library's LocalizedString may embed the instance
// value (e.g. kind.Pattern quotes k.Got) and is never used here.
func schemaFindings(err error) []Finding {
	verr, ok := err.(*jsonschema.ValidationError)
	if !ok || verr == nil {
		return []Finding{{Source: "schema", Category: "invalid_json", Span: "/"}}
	}
	var out []Finding
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if e == nil {
			return
		}
		if len(e.Causes) == 0 {
			out = append(out, Finding{Source: "schema",
				Category: strings.Join(e.ErrorKind.KeywordPath(), "/"),
				Span:     jsonPointer(e.InstanceLocation)})
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(verr)
	if len(out) == 0 {
		out = append(out, Finding{Source: "schema", Category: "schema", Span: "/"})
	}
	return out
}

func jsonPointer(tokens []string) string {
	if len(tokens) == 0 {
		return "/"
	}
	return "/" + strings.Join(tokens, "/")
}

// resultRedactedToken replaces custom-regex matches in mask mode. It is a
// fixed label: the matched value is never echoed anywhere.
const resultRedactedToken = "[REDACTED]"

// CheckResult evaluates the result post-check. Matching checks apply in a
// fixed order (secrets detectors, then deny_regex) and compose
// most-restrictively; in mask mode each check observes the previous check's
// output (the pipeline engine's "detectors see the latest mutated payload"
// discipline). A rules value with no result rules returns Action "".
func (r *Rules) CheckResult(result []byte) ResultReport {
	if r.spec.Result == nil {
		return ResultReport{}
	}
	var rep ResultReport
	text := string(result)

	if r.resultSecrets {
		// Detection reuses the shipped guardhooks Hook (Scan carries the
		// confidence threshold and checksum nuance of the chat-path guards;
		// duplicating it here would drift). Scan returns categories only —
		// no spans, and by construction no values — which is exactly the
		// finding contract. Masking reuses Hook.Redact (checksum-validated
		// replacement, credential-key handling).
		hits := guardhooks.New(guardhooks.ModeLog).Scan(text)
		for _, h := range hits {
			rep.Findings = append(rep.Findings, Finding{
				Source: "secrets", Category: string(h.Category), Span: "",
				Action: string(r.resultMode)})
		}
		if len(hits) > 0 && r.resultMode == ResultMask {
			text = guardhooks.New(guardhooks.ModeRedact).Redact(text)
		}
	}
	for i, re := range r.resultDeny {
		spans := re.FindAllStringIndex(text, -1)
		if len(spans) == 0 {
			continue
		}
		for _, span := range spans {
			if len(rep.Findings) < maxFindingsPerCheck {
				rep.Findings = append(rep.Findings, Finding{
					Source: "deny_regex", Category: fmt.Sprintf("regex[%d]", i),
					Span:   fmt.Sprintf("%d:%d", span[0], span[1]),
					Action: string(r.resultMode)})
			}
		}
		if r.resultMode == ResultMask {
			text = re.ReplaceAllString(text, resultRedactedToken)
		}
	}
	if len(rep.Findings) == 0 {
		return ResultReport{}
	}
	rep.Action = r.resultMode
	switch rep.Action {
	case ResultMask:
		rep.Masked = []byte(text)
		rep.Reason = reason(rep.Findings)
	case ResultDeny:
		rep.Reason = reason(rep.Findings)
	default: // flag: proceed unchanged
		rep.Masked = nil
	}
	return rep
}

func reason(fs []Finding) string {
	if len(fs) == 0 {
		return "tool call blocked by org policy"
	}
	f := fs[0]
	return fmt.Sprintf("tool call blocked: %s check failed (%s)", f.Source, f.Category)
}
