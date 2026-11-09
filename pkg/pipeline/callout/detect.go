package callout

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Detect is the builtin/callout-detect step: a read-only Detector that
// POSTs the configured payload projection to an external scanner and maps
// the verdict to pipeline.Findings. Run is goroutine-safe: instances hold
// only the shared Runtime and the immutable step config.
type Detect struct {
	pipeline.DetectorBase
	rt  *Runtime
	cfg stepConfig
}

// Name returns the registry name of the step implementation.
func (d *Detect) Name() string { return "builtin/callout-detect" }

// Run projects the payload, performs the one-shot deduplicated callout and
// appends the scanner's findings. Network/protocol/contract failures are
// returned as errors — the engine's on_error semantics decide their effect
// (a scanner verdict can never be confused with a probe failure).
func (d *Detect) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	content, ok, err := projectContent(in, d.cfg, false)
	if err != nil || !ok {
		return err // empty projection: nothing to inspect, no call
	}
	env, err := json.Marshal(requestEnvelope{Expose: string(d.cfg.expose), Content: content})
	if err != nil {
		return fmt.Errorf("callout %s: marshal request: %w", d.cfg.endpoint, err)
	}
	resp, err := d.rt.call(ctx, d.cfg, env)
	if err != nil {
		return err
	}
	findings, err := d.parseResponse(resp.body)
	if err != nil {
		return err
	}
	for i := range findings {
		findings[i].Step = p.StepID()
	}
	out.Findings = append(out.Findings, findings...)
	return nil
}

// scannerFinding is one entry of the findings response contract. category
// is required; severity/action/span/evidence are optional with documented
// defaults.
type scannerFinding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Span     string `json:"span"`
	Evidence string `json:"evidence"`
}

// parseResponse decodes the detect response per the configured contract
// (findings array or boolean) and maps it to pipeline findings with the
// step id attached. Lenient JSON decoding: scanners may enrich entries with
// extra fields, but the documented required keys must be present.
func (d *Detect) parseResponse(body []byte) ([]pipeline.Finding, error) {
	if d.cfg.response == responseBoolean {
		var verdict bool
		if err := json.Unmarshal(body, &verdict); err != nil {
			return nil, fmt.Errorf("callout %s: boolean response: %w", d.cfg.endpoint, err)
		}
		if !verdict {
			return nil, nil
		}
		return []pipeline.Finding{{
			Category: d.cfg.category,
			Severity: d.cfg.severity,
			Action:   d.cfg.action,
		}}, nil
	}

	var wire struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("callout %s: decode findings response: %w", d.cfg.endpoint, err)
	}
	if len(wire.Findings) == 0 || string(wire.Findings) == "null" {
		return nil, fmt.Errorf("callout %s: response contract: findings array is required", d.cfg.endpoint)
	}
	var raw []scannerFinding
	if err := json.Unmarshal(wire.Findings, &raw); err != nil {
		return nil, fmt.Errorf("callout %s: decode findings: %w", d.cfg.endpoint, err)
	}
	findings := make([]pipeline.Finding, 0, len(raw))
	for i, f := range raw {
		if f.Category == "" {
			return nil, fmt.Errorf("callout %s: finding %d: category is required", d.cfg.endpoint, i)
		}
		severity := f.Severity
		if severity == "" {
			severity = defaultFindingsSeverity
		}
		action := pipeline.Action(f.Action)
		if f.Action == "" {
			action = d.cfg.action
		}
		// An unrecognized action is left as-is: pipeline.Action.Rank
		// normalizes unknown actions to deny (fail closed).
		findings = append(findings, pipeline.Finding{
			Category: f.Category,
			Severity: severity,
			Action:   action,
			Span:     f.Span,
			Evidence: f.Evidence,
		})
	}
	return findings, nil
}
