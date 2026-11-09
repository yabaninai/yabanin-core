package streaming

import "encoding/json"

// DocumentMutator applies the streaming replacement map to the assistant
// text of a whole chat.completion cache document (N03-P03-T03).
//
// The gateway's streaming mutation (FrameProcessor) rewrites the SSE deltas
// before the client sees them, and the recording that builds the cache
// document runs downstream of the mutation point — so in today's streaming
// path the stored document already equals the client bytes, and the honest
// default for the write seam is to abstain. DocumentMutator exists for the
// write-path enforcement seam (cache.Writer.SetResponseMutator): it applies
// the same fixed map to a completion document as ONE batch replacement,
// which is byte-for-byte (at the text level) the result the frame-by-frame
// application produces over the concatenated stream — the ChunkProcessor
// whole-stream invariant:
//
//	DocumentMutator(concat(original deltas))
//		== concat(FrameProcessor-mutated deltas)
//
// for every chunk split of the original text (proven over the adversarial
// corpus in cachewrite_test.go, the same splits the client path is proven
// against in adversarial_test.go). A document mutated here therefore leaks
// exactly as few forbidden spans as the client stream — none.
//
// Emitted-bytes boundary (N03-P03-T04): the mutator's authority ends at the
// bytes it is given. Bytes already emitted to the client are outside its
// reach — the streaming transform rewrites a delta before the client sees
// it, and nothing can revise a delta after emission — and entries already
// sealed into a cache store are equally final: the writer captures the
// mutator per job at Submit time and never re-runs it over stored entries
// (see cache.Writer.SetResponseMutator). The seam vouches for exactly one
// region: the not-yet-sealed document of the current job. A forbidden span
// that straddles the streaming prefix-release boundary keeps its emitted
// half verbatim — the prefix snapshot saw it incomplete and nothing is
// re-inspected after release — while the same value occurring wholly inside
// this document is replaced in full (boundary_test.go pins both shapes).
//
// Scope limits (mirroring FrameProcessor, by design):
//   - Only choices[0].message.content is rewritten. Reasoning content,
//     tool-call arguments and every other field are never touched: the
//     replacement map is defined over the assistant text stream.
//   - A document that is not a parseable chat.completion shape, or whose
//     choices[0].message.content is absent, null or not a JSON string, is
//     passed through unchanged (abstain, changed=false). The primitive never
//     fabricates a mutation for a shape it does not understand; refusal
//     policy belongs to the wiring that installs the mutator.
//   - changed=false returns the original slice untouched, so the writer's
//     seal binds exactly the bytes the client received.
//   - When the content changed, the document is re-encoded from the decoded
//     value: semantic JSON is preserved (every field round-trips), but
//     object key order and non-semantic escapes inside the rewritten object
//     may differ from the input bytes. This mirrors FrameProcessor, which
//     likewise re-encodes every mutated frame.
//
// Apply-once contract: the map is defined over ORIGINAL model text.
// Re-applying the same map to an already-mutated document is a caller error
// and double-applies self-referential pairs (e.g. {"a":"ab"}) — enforced by
// test so the limitation is visible, not hidden. Production wiring must
// install the mutator only where the document is known not to have been
// map-mutated yet, or abstain when the streaming path already guarantees
// parity (today's recording topology).
//
// DocumentMutator is immutable and safe for concurrent use: every Mutate
// call builds a fresh ChunkProcessor, so no match state ever crosses calls
// and the mutator promises nothing about bytes outside the document passed
// in (the card's negative — no checking of "future tokens" — encoded by
// test: NoCrossCallState in cachewrite_test.go).
type DocumentMutator struct {
	replacements map[string]string
}

// NewDocumentMutator validates the replacement map with the same rules as
// the streaming path (non-empty map, no empty keys) and returns a mutator
// that applies it to completion documents.
func NewDocumentMutator(replacements map[string]string) (*DocumentMutator, error) {
	if _, err := NewChunkProcessor(replacements); err != nil {
		return nil, err
	}
	return &DocumentMutator{replacements: replacements}, nil
}

// Mutate applies the replacement map to choices[0].message.content of the
// chat.completion document. It returns the mutated document and changed=true,
// or (doc, false) when the document is left untouched — because no pattern
// matched, or because the document shape is not one this mutator rewrites.
// The input slice is never modified.
func (m *DocumentMutator) Mutate(doc []byte) ([]byte, bool) {
	if m == nil || len(doc) == 0 {
		return doc, false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return doc, false
	}
	rawChoices, ok := top["choices"]
	if !ok || len(rawChoices) == 0 {
		return doc, false
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil || len(choices) == 0 {
		return doc, false
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &choice); err != nil {
		return doc, false
	}
	rawMessage, ok := choice["message"]
	if !ok || len(rawMessage) == 0 {
		return doc, false
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(rawMessage, &message); err != nil {
		return doc, false
	}
	rawContent, ok := message["content"]
	if !ok || len(rawContent) == 0 {
		return doc, false
	}
	var content string
	if err := json.Unmarshal(rawContent, &content); err != nil {
		return doc, false // null content or a non-string shape: abstain
	}

	// Fresh processor per call: a batch replacement over the whole text is
	// exactly the result the chunked stream application produces (the
	// ChunkProcessor invariant), and no match state crosses calls.
	proc, err := NewChunkProcessor(m.replacements)
	if err != nil { // unreachable: validated at construction
		return doc, false
	}
	full := proc.Process(content) + proc.Flush()
	if full == content {
		return doc, false
	}

	mutContent, err := json.Marshal(full)
	if err != nil {
		return doc, false
	}
	message["content"] = mutContent
	mutMessage, err := json.Marshal(message)
	if err != nil {
		return doc, false
	}
	choice["message"] = mutMessage
	mutChoice, err := json.Marshal(choice)
	if err != nil {
		return doc, false
	}
	choices[0] = mutChoice
	mutChoices, err := json.Marshal(choices)
	if err != nil {
		return doc, false
	}
	top["choices"] = mutChoices
	out, err := json.Marshal(top)
	if err != nil {
		return doc, false
	}
	return out, true
}

// MutateResponse adapts Mutate to the cache writer's response-mutator seam
// (cache.Writer.SetResponseMutator): (nil, nil) abstains — the writer keeps
// the original bytes — and orgID is accepted for seam compatibility
// (per-org map selection happens in the wiring that constructs the
// mutator). The writer seals exactly the returned bytes, so a returned
// document is what the writer vouches for.
func (m *DocumentMutator) MutateResponse(_ string, response json.RawMessage) (json.RawMessage, error) {
	out, changed := m.Mutate(response)
	if !changed {
		return nil, nil
	}
	return json.RawMessage(out), nil
}
