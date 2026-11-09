package streaming

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// finalChunk mirrors the chat.completion.chunk fields the aggregate
// consumes (decode pattern: pkg/gateway stream.go streamCacheChunk /
// provider streamDeltaBytes). Only the primary choice (index 0) is
// aggregated — the same scope as the stream cache document.
type finalChunk struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int     `json:"index"`
		FinishReason *string `json:"finish_reason"`
		Delta        struct {
			Role             *string                 `json:"role"`
			Content          json.RawMessage         `json:"content"`
			ReasoningContent json.RawMessage         `json:"reasoning_content"`
			ToolCalls        []finalToolCallFragment `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
	Usage json.RawMessage `json:"usage"`
}

// finalToolCallFragment is one delta.tool_calls entry: the function name
// rides the first fragment of a call, the arguments JSON is split across
// the consecutive fragments that share the call's index.
type finalToolCallFragment struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// finalToolCallAcc accumulates one streamed tool call.
type finalToolCallAcc struct {
	id   string
	name string
	args strings.Builder
}

// merge folds one fragment into the call accumulator.
func (tc *finalToolCallAcc) merge(f finalToolCallFragment) {
	if tc.id == "" {
		tc.id = f.ID
	}
	if tc.name == "" {
		tc.name = f.Function.Name
	}
	tc.args.WriteString(f.Function.Arguments)
}

// FinalAggregate accumulates a streamed chat.completion response into the
// synthetic non-streaming document — the W-STCACHE accumulator pattern:
// content and reasoning concatenated from the deltas, tool calls merged by
// index, the last finish_reason seen, usage carried over from the final
// frame. Feed every frame the CLIENT received (post-FrameProcessor) so the
// stream_final policies audit delivered bytes. Not goroutine-safe: one
// aggregate per stream.
type FinalAggregate struct {
	sawChunk  bool
	id        string
	created   int64
	model     string
	role      string
	content   strings.Builder
	reasoning strings.Builder
	tools     []*finalToolCallAcc
	toolIndex map[int]*finalToolCallAcc
	finish    *string
	usage     json.RawMessage
}

// NewFinalAggregate returns an empty aggregate.
func NewFinalAggregate() *FinalAggregate { return &FinalAggregate{} }

// AddFrame consumes one raw SSE event. [DONE], blank lines, comments and
// unparseable frames are ignored (the aggregate tolerates provider frame
// noise; the middleware may simply feed every event it sees).
func (fa *FinalAggregate) AddFrame(frame []byte) {
	_, payload, _, ok, done := splitSSEData(frame)
	if !ok || done {
		return
	}
	fa.AddChunk(payload)
}

// AddChunk consumes one already-stripped data payload (a JSON chunk).
func (fa *FinalAggregate) AddChunk(raw []byte) {
	if len(raw) == 0 || raw[0] != '{' {
		return
	}
	var ch finalChunk
	if err := json.Unmarshal(raw, &ch); err != nil {
		return
	}
	fa.add(ch)
}

// add folds one decoded chunk into the aggregate (W-STCACHE pattern).
func (fa *FinalAggregate) add(ch finalChunk) {
	fa.sawChunk = true
	if fa.id == "" {
		fa.id = ch.ID
	}
	if fa.created == 0 {
		fa.created = ch.Created
	}
	if fa.model == "" {
		fa.model = ch.Model
	}
	for _, choice := range ch.Choices {
		if choice.Index != 0 {
			continue // the synthetic document covers the primary choice only
		}
		if choice.Delta.Role != nil && *choice.Delta.Role != "" && fa.role == "" {
			fa.role = *choice.Delta.Role
		}
		appendStreamText(&fa.content, choice.Delta.Content)
		appendStreamText(&fa.reasoning, choice.Delta.ReasoningContent)
		for _, frag := range choice.Delta.ToolCalls {
			fa.toolCall(frag.Index).merge(frag)
		}
		if choice.FinishReason != nil {
			fa.finish = choice.FinishReason
		}
	}
	if len(ch.Usage) != 0 {
		fa.usage = append(fa.usage[:0], ch.Usage...)
	}
}

// toolCall returns the accumulator for the call at the given delta index,
// creating it on first sight (fragments arrive in index order).
func (fa *FinalAggregate) toolCall(index int) *finalToolCallAcc {
	if fa.toolIndex == nil {
		fa.toolIndex = make(map[int]*finalToolCallAcc)
	}
	if tc, ok := fa.toolIndex[index]; ok {
		return tc
	}
	tc := &finalToolCallAcc{}
	fa.toolIndex[index] = tc
	fa.tools = append(fa.tools, tc)
	return tc
}

// Document renders the accumulated stream as the synthetic chat.completion
// document, nil when nothing replayable was streamed: without a parseable
// chunk, or with no content/reasoning/tool-call payload at all — a
// role-only document would serve the post-check policies an empty answer.
func (fa *FinalAggregate) Document() []byte {
	if !fa.sawChunk || (fa.content.Len() == 0 && fa.reasoning.Len() == 0 && len(fa.tools) == 0) {
		return nil
	}
	message := map[string]any{"role": fa.role}
	if fa.role == "" {
		message["role"] = "assistant"
	}
	message["content"] = fa.content.String()
	if fa.reasoning.Len() > 0 {
		message["reasoning_content"] = fa.reasoning.String()
	}
	if len(fa.tools) > 0 {
		calls := make([]any, 0, len(fa.tools))
		for _, tc := range fa.tools {
			fn := map[string]any{"arguments": tc.args.String()}
			if tc.name != "" {
				fn["name"] = tc.name
			}
			call := map[string]any{"type": "function", "function": fn}
			if tc.id != "" {
				call["id"] = tc.id
			}
			calls = append(calls, call)
		}
		message["tool_calls"] = calls
	}
	choice := map[string]any{"index": 0, "message": message}
	if fa.finish != nil {
		choice["finish_reason"] = *fa.finish
	}
	doc := map[string]any{
		"object":  "chat.completion",
		"choices": []any{choice},
	}
	if fa.id != "" {
		doc["id"] = fa.id
	}
	if fa.created != 0 {
		doc["created"] = fa.created
	}
	if fa.model != "" {
		doc["model"] = fa.model
	}
	if len(fa.usage) != 0 && !bytes.Equal(fa.usage, []byte("null")) {
		var u map[string]any
		if err := json.Unmarshal(fa.usage, &u); err == nil && len(u) > 0 {
			doc["usage"] = u
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return b
}

// appendStreamText appends a delta text field that OpenAI-compatible
// streams encode as a JSON string or null.
func appendStreamText(b *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return
	}
	b.WriteString(s)
}

// FinalOutcome is the post-issuance result of the stream_final policies.
type FinalOutcome struct {
	// Result is the full engine result (findings, trace, verdict) for the
	// decision-log (OP-9); nil when the policies did not run (empty
	// aggregate or infrastructure failure — see Err).
	Result *pipeline.Result
	// Effective is the action the middleware must record: the composed
	// verdict, EXCEPT that a deny after issuance degrades to flag — the
	// client already received the bytes, so the only correct post-issuance
	// enforcement is a flag event + decision-log entry + metric (abort
	// before delivery happens only at the prefix stage).
	Effective pipeline.Action
	// Document is the synthetic document the policies saw (nil when the
	// aggregate had nothing replayable).
	Document []byte
	// Err carries an infrastructure failure (dead ctx, missing runner,
	// Runner contract violation). The outcome still degrades to
	// Effective == flag so the middleware's observability sees the gap.
	Err error
}

// FinalCheck runs the stream_final policies over the aggregate document.
// An empty aggregate (no replayable content) skips the policy run: there is
// nothing to post-check. A cancelled context degrades to a flagged infra
// failure — delivered bytes can no longer be recalled, only observed.
func FinalCheck(ctx context.Context, r Runner, agg *FinalAggregate, meta *pipeline.RequestMeta, endpoint string) FinalOutcome {
	if agg == nil {
		return FinalOutcome{Effective: pipeline.ActionAllow}
	}
	doc := agg.Document()
	if doc == nil {
		return FinalOutcome{Effective: pipeline.ActionAllow}
	}
	out := FinalOutcome{Document: doc, Effective: pipeline.ActionFlag}
	if err := ctx.Err(); err != nil {
		out.Err = err
		return out
	}
	if r == nil {
		out.Err = errNilRunner
		return out
	}
	res := r.Run(ctx, &pipeline.Payload{
		Kind:     pipeline.KindStreamFinal,
		Endpoint: endpoint,
		Body:     doc,
		Meta:     meta,
	})
	if res == nil {
		out.Err = errNilResult
		return out
	}
	out.Result = res
	out.Effective = res.Verdict
	if out.Effective == pipeline.ActionDeny {
		out.Effective = pipeline.ActionFlag // deny after issuance: observe, do not recall
	}
	return out
}

// Runner contract errors: infrastructure failures of the streaming
// primitives (distinct from policy verdicts).
var (
	errNilRunner = errors.New("streaming: no policy runner configured")
	errNilResult = errors.New("streaming: policy run returned no result")
)
