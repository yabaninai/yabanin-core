// OP-6 / OP-8 seam: the toolpolicy guard rules as a policy-pipeline step.
//
// The SAME RuleSpec that the tool_policies.rules column stores (rules.go)
// compiles into a pipeline.Step here, so a policy author can express the
// guard either DB-side (the MCP invoke path wires Engine.GuardArgs/
// GuardResult directly) or YAML-side (a pipeline attached to the
// mcp.invoke endpoint runs this step on tool_args / tool_result payloads).
//
// Import discipline (conflict map): pkg/toolpolicy imports pkg/pipeline —
// NEVER the reverse. pkg/pipeline stays a pure core; the gateway
// (OP-8) registers the factory on its Engine.Steps() registry via
// RegisterStepFactory.
package toolpolicy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// StepName is the builtin step name ("builtin/toolpolicy").
const StepName = "builtin/toolpolicy"

// Step param keys (the RuleSpec fields plus optional targeting).
const (
	paramArgs   = "args"
	paramResult = "result"
	paramFail   = "fail"
	paramServer = "server"
	paramTool   = "tool"
)

// Meta label keys the step consults for targeting (set by the gateway on
// tool payloads — the OP-8 contract for Endpoint "mcp.invoke").
const (
	LabelServer = "mcp.server"
	LabelTool   = "mcp.tool"
)

// stepRule is one compiled step instance. Immutable; Run may be invoked
// concurrently (pipeline contract).
type stepRule struct {
	compiled *Rules
	server   string // targeting pattern ('' = all)
	tool     string // targeting pattern ('' = all)
}

// StepFactory compiles one builtin/toolpolicy step from params. A compile
// error is a POLICY LOAD error (never a silent runtime skip) — the pipeline
// contract for unresolvable steps.
func StepFactory(params map[string]any) (pipeline.Step, error) {
	var spec RuleSpec
	if v, ok := params[paramArgs]; ok && v != nil {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramArgs, err)
		}
		var r *ArgsRule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramArgs, err)
		}
		spec.Args = r
	}
	if v, ok := params[paramResult]; ok && v != nil {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramResult, err)
		}
		var r *ResultRule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramResult, err)
		}
		spec.Result = r
	}
	if v, ok := params[paramFail]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("toolpolicy step: %s must be a string", paramFail)
		}
		spec.Fail = s
	}
	compiled, err := CompileRules(mustJSON(spec))
	if err != nil {
		return nil, err
	}
	st := &stepRule{compiled: compiled}
	if v, ok := params[paramServer].(string); ok {
		st.server = v
	}
	if v, ok := params[paramTool].(string); ok {
		st.tool = v
	}
	if st.server != "" {
		if err := ValidatePattern(st.server); err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramServer, err)
		}
	}
	if st.tool != "" {
		if err := ValidatePattern(st.tool); err != nil {
			return nil, fmt.Errorf("toolpolicy step: %s: %w", paramTool, err)
		}
	}
	return st, nil
}

// RegisterStepFactory registers StepFactory under StepName on a pipeline
// registry (the gateway calls this once at wiring time).
func RegisterStepFactory(r *pipeline.Registry) error {
	return r.Register(StepName, StepFactory)
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		// RuleSpec is plain JSON data; marshaling cannot fail.
		panic(fmt.Sprintf("toolpolicy: marshal RuleSpec: %v", err))
	}
	return raw
}

// Name returns the builtin step name.
func (s *stepRule) Name() string { return StepName }

// ImplementsDetector: the step only inspects tool payloads (mask mutates
// the tool_result Body, see Run).
func (s *stepRule) ImplementsDetector() {}

// ImplementsMutator: mask-mode result rules rewrite the payload Body.
func (s *stepRule) ImplementsMutator() {}

// Run evaluates the compiled rules against tool_args / tool_result
// payloads. Every finding is VALUE-FREE: Span carries the byte offsets or
// JSON pointer, Evidence the schema keyword / detector category — matched
// values never enter the pipeline result (decision-log persistence, OP-9,
// stays clean).
func (s *stepRule) Run(_ context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if in == nil || !in.Kind.Valid() {
		return nil
	}
	if !s.targeted(in) {
		return nil
	}
	switch in.Kind {
	case pipeline.KindToolArgs:
		rep := s.compiled.CheckArgs(in.Body)
		for _, f := range rep.Findings {
			out.Findings = append(out.Findings, pipeline.Finding{
				Step:     p.StepID(),
				Category: "toolpolicy." + f.Source,
				Severity: severity(f.Action),
				Span:     f.Span,
				Evidence: f.Category,
				Action:   pipeline.Action(f.Action),
			})
		}
		if rep.Denied {
			out.Verdict = out.Verdict.Max(pipeline.ActionDeny)
		}
	case pipeline.KindToolResult:
		rep := s.compiled.CheckResult(in.Body)
		for _, f := range rep.Findings {
			out.Findings = append(out.Findings, pipeline.Finding{
				Step:     p.StepID(),
				Category: "toolpolicy." + f.Source,
				Severity: severity(f.Action),
				Span:     f.Span,
				Evidence: f.Category,
				Action:   pipeline.Action(f.Action),
			})
		}
		switch rep.Action {
		case ResultDeny:
			out.Verdict = out.Verdict.Max(pipeline.ActionDeny)
		case ResultMask:
			if len(rep.Masked) > 0 {
				// Mutator contract: edit the payload in place (this Run
				// owns a private clone).
				in.Body = rep.Masked
			}
			out.Verdict = out.Verdict.Max(pipeline.ActionMask)
		case ResultFlag:
			out.Verdict = out.Verdict.Max(pipeline.ActionFlag)
		}
	}
	return nil
}

// targeted applies the optional server/tool params against the payload
// labels. When the step declares targeting and the payload carries no
// labels, the step does NOT match — a misscoped policy must never deny
// calls it was not written for (the attachment endpoint scopes the rest).
func (s *stepRule) targeted(in *pipeline.Payload) bool {
	if s.server == "" && s.tool == "" {
		return true
	}
	if in.Meta == nil {
		return false
	}
	if s.server != "" && !matches(s.server, in.Meta.Labels[LabelServer]) {
		return false
	}
	if s.tool != "" && !matches(s.tool, in.Meta.Labels[LabelTool]) {
		return false
	}
	return true
}

// severity maps the strictness action to the builtin severity scale.
func severity(action string) string {
	switch action {
	case "deny":
		return "high"
	case "mask":
		return "medium"
	default:
		return "low"
	}
}
