package llmjudge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Tuning defaults for the judge step. Temperature is pinned to 0: verdicts
// must be deterministic for the same input (consistency test in
// fixtures_test.go), which is what makes threshold tuning meaningful.
const (
	DefaultMode      = ModeInput
	judgeTemperature = 0
	judgeMaxTokens   = 512
	maxEvidenceRunes = 256
)

// Message roles used by the mode extraction.
const (
	ModeInputRole  = "user"
	ModeOutputRole = "assistant"
)

// Mode selects which conversation turn the judge inspects.
type Mode string

// Judge modes.
const (
	// ModeInput inspects the last user turn (pre_upstream hook).
	ModeInput Mode = "input"
	// ModeOutput inspects the last assistant turn (post_upstream /
	// stream_final hooks).
	ModeOutput Mode = "output"
)

// Valid reports whether m is a defined mode.
func (m Mode) Valid() bool {
	return m == ModeInput || m == ModeOutput
}

// Judge is the llm_judge pipeline step (OP-3). It is a read-only Detector:
// it never mutates the payload, only appends findings and (through them)
// raises the verdict — so it may join parallel groups like any builtin
// detector (plan §2.2 shows judge + secret_scan in one group).
//
// The step value is immutable after construction (factory-built from policy
// params) and safe for concurrent Runs.
type Judge struct {
	pipeline.DetectorBase

	client     JudgeClient
	tpl        *template.Template
	promptRef  string
	modelRef   string
	mode       Mode
	categories []string
	threshold  float64
}

// Name returns the implementation name for diagnostics.
func (j *Judge) Name() string { return "llmjudge/judge" }

// Run executes one judge call: extract the inspected turn, render the
// versioned prompt, call the judge model, parse the verdict and append
// findings. Errors — transport, timeout, malformed verdict — return as step
// errors so the policy's on_error mode applies (fail_open+flag is the
// recommended default; the engine default fail_closed denies).
func (j *Judge) Run(ctx context.Context, pv *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	start := time.Now()
	modelLabel := j.modelRef

	content := judgeContent(in, j.mode)
	if strings.TrimSpace(content) == "" {
		recordJudgeOutcome(modelLabel, outcomeAllow, time.Since(start))
		return nil // nothing to judge: an empty turn cannot violate
	}

	rendered, err := renderPrompt(j.tpl, promptData{
		Input:      content,
		Categories: strings.Join(j.categories, ", "),
	})
	if err != nil {
		recordJudgeOutcome(modelLabel, outcomeError, time.Since(start))
		return err
	}

	resp, err := j.client.JudgeChat(ctx, ChatRequest{
		ModelRef:     j.modelRef,
		Messages:     []pipeline.Message{{Role: "system", Content: rendered}, {Role: "user", Content: content}},
		Temperature:  judgeTemperature,
		MaxTokens:    judgeMaxTokens,
		ResponseJSON: true,
		Meta:         judgeMeta(in.Meta),
	})
	if err != nil {
		recordJudgeOutcome(modelLabel, outcomeError, time.Since(start))
		return fmt.Errorf("judge call: %w", err)
	}
	if resp.Model != "" {
		modelLabel = resp.Model
	}

	verdict, err := ParseVerdict(resp.Content, maxEvidenceRunes)
	if err != nil {
		recordJudgeOutcome(modelLabel, outcomeError, time.Since(start))
		return fmt.Errorf("judge %s: %w", j.promptRef, err)
	}

	composed := pipeline.ActionAllow
	for _, f := range verdict.Findings {
		action := findingAction(f.confidence(), j.threshold)
		composed = composed.Max(action)
		out.Findings = append(out.Findings, pipeline.Finding{
			Step:     pv.StepID(),
			Category: CategoryPrefix + f.Category,
			Severity: f.Severity,
			Span:     f.Span,
			Evidence: f.Evidence,
			Action:   action,
		})
	}
	recordJudgeOutcome(modelLabel, string(composed), time.Since(start))
	return nil
}

// judgeContent extracts the turn under inspection: the LAST message of the
// mode's role. When the payload carries no Messages (raw-body wiring, OP-8
// adapters), the chat.completions body is parsed as a fallback.
func judgeContent(in *pipeline.Payload, mode Mode) string {
	msgs := in.Messages
	if len(msgs) == 0 && len(in.Body) > 0 {
		msgs = bodyMessages(in.Body)
	}
	role := ModeInputRole
	if mode == ModeOutput {
		role = ModeOutputRole
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == role {
			return msgs[i].Content
		}
	}
	return ""
}

// bodyMessages parses a chat.completions request body for its messages;
// unparsable bodies yield none (the step then no-ops — an unparsable request
// is upstream validation's problem, not the judge's).
func bodyMessages(body []byte) []pipeline.Message {
	var req struct {
		Messages []pipeline.Message `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	return req.Messages
}

// judgeMeta builds the synthetic meta for the judge call: a deep clone of
// the request meta with the judge marker merged in. The parent labels —
// among them the gateway's team stamp — are copied into a fresh map, so the
// hop meta carries them without aliasing the request's own map. The
// original payload meta is never touched (RequestMeta is read-only by core
// contract). A nil incoming meta yields an org-less meta carrying only the
// marker.
func judgeMeta(m *pipeline.RequestMeta) *pipeline.RequestMeta {
	var c pipeline.RequestMeta
	if m != nil {
		c = *m
	}
	parent := c.Labels
	c.Labels = make(map[string]string, len(parent)+1)
	for k, v := range parent {
		c.Labels[k] = v
	}
	c.Labels[MetaLabelJudge] = JudgeLabelValue
	return &c
}
