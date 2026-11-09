package builtins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// MINIMAL shape (owner decisions D2/D3, 2026-10-16): NO local compression or
// trimming ever happens. The step only marks stable prompt regions with the
// provider's NATIVE prompt-caching hint — Anthropic `cache_control` blocks —
// so the provider caches them itself. OpenAI-style implicit prompt caching
// needs no marker: providers outside the configured set are passed through
// untouched (D2), and disabling the policy step restores byte-identical
// behaviour (no marker, no re-serialization).
//
// Targets (params.targets, default ["system","last"]):
//
//   - "system": the top-level "system" field of an Anthropic-native body
//     (the /v1/messages surface, forwarded verbatim). A string system is
//     promoted to a single marked text block; a block array gets the marker
//     on its last block.
//   - "last": the last message carrying content gets the marker on its last
//     content part (a string content is promoted to a one-part array — the
//     OpenAI→Anthropic translate preserves per-part cache_control).
//
// On an OpenAI chat-shaped body (system inside role=system messages) the
// "system" target is a deliberate no-op: the translate path renders system as
// a joined plain string, so a parts-array system (the only shape that can
// carry cache_control) would be corrupted into literal JSON text — the card's
// negative scenario. The system prompt is never touched there.
//
// Idempotency: a target that already carries any cache_control marker is
// skipped, so stacked policies or re-runs never double-mark (Anthropic
// allows at most four cache_control blocks per request).
//
// TRACE NOTE (mandatory, mirroring model-rewrite): every applied hint is
// recorded as a FLAG finding (Category "prompt_cache_hint", Severity low,
// content-free evidence "targets → provider") — a mutation without its note
// is a contract violation; the decision record (OP-9) and X-Yabanin-Decision
// surface the injection.
//
// Kinds: request only, non-negotiable (responses are the upstream's).
type compressStep struct {
	pipeline.MutatorBase
	providers map[string]bool
	targets   map[string]bool
	cacheRaw  json.RawMessage
}

// Name returns the step implementation name.
func (*compressStep) Name() string { return NameCompress }

// Category of the mandatory hint-note finding.
const compressCategory = "prompt_cache_hint"

// Run injects the configured cache_control hints into the request body in
// place. Text content is never altered; only cache_control markers are
// added. ctx is honored before each target.
func (c *compressStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || in.Kind != pipeline.KindRequest {
		return nil
	}
	if in.Meta == nil || !c.providers[in.Meta.Provider] {
		return nil // D2: implicit-caching (and unknown) providers pass through untouched
	}
	if len(in.Body) == 0 {
		return nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(in.Body, &root); err != nil {
		return fmt.Errorf("request body is not a JSON object: %w", err)
	}
	var msgs []map[string]json.RawMessage
	usableMsgs := false
	if raw, ok := root["messages"]; ok {
		usableMsgs = json.Unmarshal(raw, &msgs) == nil && len(msgs) > 0
	}
	if !usableMsgs {
		return nil
	}

	var applied []string
	if c.targets["system"] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if markSystemBlock(root, c.cacheRaw) {
			applied = append(applied, "system")
		}
	}
	if c.targets["last"] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if markLastMessage(msgs, c.cacheRaw) {
			applied = append(applied, "last")
		}
	}
	if len(applied) == 0 {
		return nil
	}

	msgsRaw, err := json.Marshal(msgs)
	if err != nil {
		return fmt.Errorf("re-encode messages: %w", err)
	}
	root["messages"] = msgsRaw
	body, err := json.Marshal(root)
	if err != nil {
		return fmt.Errorf("re-encode request body: %w", err)
	}
	in.Body = body
	out.Findings = append(out.Findings, finding(
		p.StepID(), compressCategory, sevLow, "",
		clipEvidence("prompt-cache hints "+strings.Join(applied, "+")+" -> "+in.Meta.Provider, maxEvidence),
		pipeline.ActionFlag,
	))
	return nil
}

// markSystemBlock marks the top-level "system" of an Anthropic-native body:
// a string is promoted to one marked text block; a block array gets the
// marker on its last block. It reports whether a marker was added; a system
// that is absent, of another shape, or already marked anywhere is skipped.
func markSystemBlock(root map[string]json.RawMessage, cc json.RawMessage) bool {
	raw, ok := root["system"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return false
	}
	if s, err := decodeJSONString(raw); err == nil {
		block := map[string]any{"type": "text", "text": s, "cache_control": cc}
		enc, err := json.Marshal([]any{block})
		if err != nil {
			return false
		}
		root["system"] = enc
		return true
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil || len(blocks) == 0 {
		return false
	}
	if !markLastBlock(blocks, cc) {
		return false
	}
	enc, err := json.Marshal(blocks)
	if err != nil {
		return false
	}
	root["system"] = enc
	return true
}

// markLastMessage marks the last message that carries string or block-array
// content: a string is promoted to a one-part array with the marker; an
// array gets the marker on its last part. Messages without usable content
// (or with content of another shape) are skipped in reverse order. It
// reports whether a marker was added.
func markLastMessage(msgs []map[string]json.RawMessage, cc json.RawMessage) bool {
	for i := len(msgs) - 1; i >= 0; i-- {
		raw, ok := msgs[i]["content"]
		if !ok || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		if s, err := decodeJSONString(raw); err == nil {
			if s == "" {
				continue
			}
			part := map[string]any{"type": "text", "text": s, "cache_control": cc}
			enc, err := json.Marshal([]any{part})
			if err != nil {
				return false
			}
			msgs[i]["content"] = enc
			return true
		}
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &parts); err != nil || len(parts) == 0 {
			continue
		}
		if !markLastBlock(parts, cc) {
			return false
		}
		enc, err := json.Marshal(parts)
		if err != nil {
			return false
		}
		msgs[i]["content"] = enc
		return true
	}
	return false
}

// markLastBlock sets the cache_control marker on the last block of a
// block/parts array, unless any block already carries one (idempotency).
func markLastBlock(blocks []map[string]json.RawMessage, cc json.RawMessage) bool {
	for _, b := range blocks {
		if _, marked := b["cache_control"]; marked {
			return false
		}
	}
	last := blocks[len(blocks)-1]
	last["cache_control"] = cc
	return true
}

// decodeJSONString decodes raw as a JSON string.
func decodeJSONString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// NewCompress builds builtin/compress.
//
// Params: "providers" (optional list of provider names eligible for hints;
// default ["anthropic"] — D2 keeps the provider matrix open, OpenAI-style
// caching is implicit and never hinted), "targets" (optional list from
// {"system","last"}; default both), "ttl" (optional cache_control TTL, one
// of "5m"|"1h"; absent = plain ephemeral). The "kinds" param is rejected —
// the step is request-only by contract.
func NewCompress(params map[string]any) (pipeline.Step, error) {
	if _, ok := params["kinds"]; ok {
		return nil, fmt.Errorf("params.kinds: compress is request-only; the kinds param is not supported")
	}
	providers := map[string]bool{"anthropic": true}
	if raw, ok := params["providers"]; ok && raw != nil {
		items, err := anyToStrings(raw)
		if err != nil {
			return nil, fmt.Errorf("params.providers: %w", err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("params.providers: at least one provider name is required")
		}
		providers = make(map[string]bool, len(items))
		for _, it := range items {
			if it == "" {
				return nil, fmt.Errorf("params.providers: empty entries are not allowed")
			}
			providers[it] = true
		}
	}
	targets := map[string]bool{"system": true, "last": true}
	if raw, ok := params["targets"]; ok && raw != nil {
		items, err := anyToStrings(raw)
		if err != nil {
			return nil, fmt.Errorf("params.targets: %w", err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("params.targets: at least one of \"system\", \"last\" is required")
		}
		targets = make(map[string]bool, len(items))
		for _, it := range items {
			switch it {
			case "system", "last":
				targets[it] = true
			default:
				return nil, fmt.Errorf("params.targets: %q: want \"system\" or \"last\"", it)
			}
		}
	}
	ttl := ""
	if raw, ok := params["ttl"]; ok && raw != nil {
		var err error
		if ttl, err = paramString(params, "ttl"); err != nil {
			return nil, err
		}
		switch ttl {
		case "5m", "1h":
		default:
			return nil, fmt.Errorf("params.ttl: %q: want \"5m\" or \"1h\"", ttl)
		}
	}
	cc := json.RawMessage(`{"type":"ephemeral"}`)
	if ttl != "" {
		cc = json.RawMessage(`{"type":"ephemeral","ttl":"` + ttl + `"}`)
	}
	return &compressStep{providers: providers, targets: targets, cacheRaw: cc}, nil
}

// compile-time guard: compress is a Mutator.
var _ pipeline.Mutator = (*compressStep)(nil)
