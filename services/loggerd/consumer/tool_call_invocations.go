package consumer

import (
	"encoding/json"
	"strings"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// maxInvocationArgsChars caps the stored per-occurrence arguments. Tool
// arguments can legitimately be long (file edits), but rows must stay
// bounded; the cut uses the same marker as the response sample so the UI can
// tell a capped blob from a complete one.
const maxInvocationArgsChars = 2000

// toolCallInvocation is one tool-call occurrence with its reassembled
// arguments, as extracted from the pre-truncation sample.
type toolCallInvocation struct {
	Seq    int
	CallID string
	Name   string
	Args   string
}

// extractToolCallInvocations parses the full per-occurrence tool calls from a
// captured sample: a complete chat.completion document (non-streaming) or an
// SSE capture (streaming). SSE delta fragments are grouped by their `index`
// field; the name/call id arrive on the first fragment, later fragments only
// extend the arguments string. Occurrences are ordered by first appearance.
//
// Truncated samples may yield a partial set with partial arguments — that is
// honest: whatever survived the capture is stored, nothing is fabricated.
func extractToolCallInvocations(sample string) []toolCallInvocation {
	if strings.TrimSpace(sample) == "" {
		return nil
	}
	var doc interface{}
	if err := json.Unmarshal([]byte(sample), &doc); err == nil {
		return invocationsFromDoc(doc)
	}
	// Not one JSON document — a streamed SSE capture: scan data: frames and
	// merge fragments across frames.
	var out []toolCallInvocation
	byIndex := map[int]*toolCallInvocation{}
	for _, line := range strings.Split(sample, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			continue
		}
		var frame interface{}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			metrics.SilentFailure("audit_ingest_decode", "tool_frame")
			continue
		}
		out = appendInvocationsFromFrame(out, byIndex, frame)
	}
	return out
}

// invocationsFromDoc reads per-occurrence calls from a completion document.
func invocationsFromDoc(doc interface{}) []toolCallInvocation {
	root, ok := doc.(map[string]interface{})
	if !ok {
		return nil
	}
	choices, ok := root["choices"].([]interface{})
	if !ok {
		return nil
	}
	var out []toolCallInvocation
	for _, ch := range choices {
		choice, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}
		for _, holderKey := range []string{"message", "delta"} {
			holder, ok := choice[holderKey].(map[string]interface{})
			if !ok || holder["tool_calls"] == nil {
				continue
			}
			calls, ok := holder["tool_calls"].([]interface{})
			if !ok {
				continue
			}
			for _, c := range calls {
				call, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				fn, _ := call["function"].(map[string]interface{})
				if fn == nil {
					continue
				}
				name, _ := fn["name"].(string)
				if name == "" {
					continue
				}
				args, _ := fn["arguments"].(string)
				out = append(out, toolCallInvocation{
					Seq:    len(out),
					CallID: jsonStr(call["id"]),
					Name:   name,
					Args:   args,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// appendInvocationsFromFrame merges one SSE frame's delta fragments into the
// running occurrence list. Fragments carrying the same provider `index`
// extend the same invocation; fragments without an index are treated as
// index 0 (single-call responses commonly omit it on the first fragment).
func appendInvocationsFromFrame(out []toolCallInvocation, byIndex map[int]*toolCallInvocation, frame interface{}) []toolCallInvocation {
	root, ok := frame.(map[string]interface{})
	if !ok {
		return out
	}
	choices, ok := root["choices"].([]interface{})
	if !ok {
		return out
	}
	for _, ch := range choices {
		choice, ok := ch.(map[string]interface{})
		if !ok {
			continue
		}
		delta, ok := choice["delta"].(map[string]interface{})
		if !ok || delta["tool_calls"] == nil {
			continue
		}
		fragments, ok := delta["tool_calls"].([]interface{})
		if !ok {
			continue
		}
		for _, f := range fragments {
			frag, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			fn, _ := frag["function"].(map[string]interface{})
			if fn == nil {
				continue
			}
			idx := 0
			if v, ok := frag["index"].(float64); ok {
				idx = int(v)
			}
			name, _ := fn["name"].(string)
			args, _ := fn["arguments"].(string)
			inv, seen := byIndex[idx]
			if !seen {
				if name == "" {
					// Fragment with neither index-known call nor a name —
					// nothing to anchor it to; skip honestly.
					continue
				}
				inv = &toolCallInvocation{Seq: len(out), CallID: jsonStr(frag["id"]), Name: name}
				byIndex[idx] = inv
				out = append(out, *inv)
			}
			// The call id can arrive on a later fragment than the name.
			if inv.CallID == "" {
				inv.CallID = jsonStr(frag["id"])
			}
			inv.Args += args
			// Keep the slice copy in sync (out holds values, not pointers).
			out[inv.Seq] = *inv
		}
	}
	return out
}

func jsonStr(v interface{}) string {
	s, _ := v.(string)
	return s
}
