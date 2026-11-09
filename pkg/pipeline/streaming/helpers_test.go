package streaming

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Trigger strings of the test steps (mirroring what builtins/injection and
// mutator steps do in production, without importing sibling packages).
const (
	testInjectionTrigger = "ignore previous instructions"
	testSecretTrigger    = "super-secret-value"
	testSecretMask       = "[REDACTED]"
)

// injectionStep is a read-only detector that denies when the payload text
// contains the injection trigger.
type injectionStep struct {
	pipeline.DetectorBase
	action pipeline.Action
}

// Name returns the test step name.
func (s *injectionStep) Name() string { return "test/injection" }

// Run scans the payload text and reports the trigger as a finding.
func (s *injectionStep) Run(_ context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if in == nil || !strings.Contains(payloadText(in), testInjectionTrigger) {
		return nil
	}
	out.Findings = append(out.Findings, pipeline.Finding{
		Step:     p.StepID(),
		Category: "injection",
		Severity: "high",
		Action:   s.action,
	})
	return nil
}

// maskStep is a mutator that replaces the secret trigger in the payload
// body (stream payloads carry the text in Body).
type maskStep struct {
	pipeline.MutatorBase
}

// Name returns the test step name.
func (maskStep) Name() string { return "test/mask-secret" }

// Run rewrites the payload body, replacing the trigger.
func (s maskStep) Run(_ context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if in == nil || len(in.Body) == 0 {
		return nil
	}
	repl := bytes.ReplaceAll(in.Body, []byte(testSecretTrigger), []byte(testSecretMask))
	if !bytes.Equal(repl, in.Body) {
		in.Body = repl
		out.Findings = append(out.Findings, pipeline.Finding{
			Step:     p.StepID(),
			Category: "secret",
			Severity: "high",
			Action:   pipeline.ActionMask,
		})
	}
	return nil
}

// newTestEngine builds an engine with the test steps registered.
func newTestEngine(t *testing.T) *pipeline.Engine {
	t.Helper()
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("test/injection", func(params map[string]any) (pipeline.Step, error) {
		act := pipeline.ActionDeny
		if raw, ok := params["action"].(string); ok && raw != "" {
			act = pipeline.Action(raw)
		}
		return &injectionStep{action: act}, nil
	})
	eng.Steps().MustRegister("test/mask-secret", func(map[string]any) (pipeline.Step, error) {
		return maskStep{}, nil
	})
	return eng
}

// mustCompile compiles one YAML policy against the test engine.
func mustCompile(t *testing.T, eng *pipeline.Engine, yamlDoc string) pipeline.Compiled {
	t.Helper()
	c, err := eng.LoadPolicy([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return c
}

// prefixDenyPolicy enforces a deny on the stream_prefix hook.
const prefixDenyPolicy = `
apiVersion: ypp/v1
kind: Policy
name: prefix-deny-injection
mode: enforce
hooks: [stream_prefix]
steps:
  - id: inj
    detector: test/injection
    params:
      action: deny
`

// prefixFlagPolicy only flags on the stream_prefix hook.
const prefixFlagPolicy = `
apiVersion: ypp/v1
kind: Policy
name: prefix-flag-injection
mode: enforce
hooks: [stream_prefix]
steps:
  - id: inj
    detector: test/injection
    params:
      action: flag
`

// prefixMaskPolicy mutates on the stream_prefix hook.
const prefixMaskPolicy = `
apiVersion: ypp/v1
kind: Policy
name: prefix-mask-secret
mode: enforce
hooks: [stream_prefix]
steps:
  - id: mask
    mutator: test/mask-secret
`

// finalDenyPolicy enforces a deny on the stream_final hook.
const finalDenyPolicy = `
apiVersion: ypp/v1
kind: Policy
name: final-deny-injection
mode: enforce
hooks: [stream_final]
steps:
  - id: inj
    detector: test/injection
    params:
      action: deny
`

// finalMaskPolicy mutates the stream_final aggregate.
const finalMaskPolicy = `
apiVersion: ypp/v1
kind: Policy
name: final-mask-secret
mode: enforce
hooks: [stream_final]
steps:
  - id: mask
    mutator: test/mask-secret
`
