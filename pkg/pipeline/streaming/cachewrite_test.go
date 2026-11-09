package streaming

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// cwDoc builds a minimal chat.completion document carrying content as the
// choices[0].message.content of an assistant message.
func cwDoc(t *testing.T, content string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"id":     "chatcmpl-doc",
		"object": "chat.completion",
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": "stop",
			"message":       map[string]any{"role": "assistant", "content": content},
		}},
	})
	if err != nil {
		t.Fatalf("build doc: %v", err)
	}
	return doc
}

// cwDocContent extracts choices[0].message.content from a chat.completion
// document (decoded string).
func cwDocContent(t *testing.T, doc []byte) string {
	t.Helper()
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("parse doc %s: %v", doc, err)
	}
	if len(parsed.Choices) == 0 {
		t.Fatalf("doc has no choices: %s", doc)
	}
	return parsed.Choices[0].Message.Content
}

// mustDocMutator builds a DocumentMutator or fails the test.
func mustDocMutator(t *testing.T, pairs map[string]string) *DocumentMutator {
	t.Helper()
	dm, err := NewDocumentMutator(pairs)
	if err != nil {
		t.Fatalf("NewDocumentMutator: %v", err)
	}
	return dm
}

// TestDocumentMutator_AdversarialSplitsMatchClientStream is the card's
// acceptance, carried to the cache document: for every adversarial chunk
// split of the T02 corpus, the document produced by the write-seam
// composition (DocumentMutator over the concatenated ORIGINAL text) equals
// — at the text level and at the no-forbidden-span level — the bytes the
// client received from the frame-by-frame application (FrameProcessor).
// A cache entry built from either composition can therefore never leak a
// forbidden span the client stream did not.
func TestDocumentMutator_AdversarialSplitsMatchClientStream(t *testing.T) {
	secret := [2]string{testSecretTrigger, testSecretMask}
	rows := []struct {
		name  string
		pairs [][2]string
		head  string
		rest  string
		extra []string
	}{
		{
			name:  "secret at boundary",
			pairs: [][2]string{secret},
			head:  "value is " + testSecretTrigger,
			rest:  " and done",
			extra: []string{"filler " + testSecretTrigger + " again"},
		},
		{
			name:  "secret twice",
			pairs: [][2]string{secret},
			head:  testSecretTrigger,
			rest:  " then " + testSecretTrigger + " end",
		},
		{
			name:  "adjacent matches",
			pairs: [][2]string{secret, {"abc", "X"}},
			head:  "start " + testSecretTrigger + " abc",
			rest:  "abcabcabc",
		},
		{
			name:  "cyrillic alias at boundary",
			pairs: [][2]string{{"Иванов Иван", "ORG_1"}, secret},
			head:  "Дорогой Иванов Иван, код " + testSecretTrigger,
			rest:  ", привет! А это Иванов Иван снова",
		},
		{
			name:  "utf8 around the split",
			pairs: [][2]string{secret},
			head:  "итог: " + testSecretTrigger,
			rest:  "ЙЙЙ и ещё " + testSecretTrigger,
		},
		{
			name:  "whole stream is the prefix",
			pairs: [][2]string{secret},
			head:  testSecretTrigger,
			rest:  "",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			full := row.head + row.rest
			for _, ex := range row.extra {
				full += ex
			}
			repl := advReplMap(row.pairs)
			want := refReplace(full, repl)
			dm := mustDocMutator(t, repl)

			runes := []rune(row.rest)
			for i := 0; i <= len(runes); i++ {
				chunks := []string{string(runes[:i]), string(runes[i:])}
				chunks = append(chunks, row.extra...)
				st := advRunStream(t, row.pairs, []string{row.head}, chunks)
				if st.aborted || !st.mutated {
					t.Fatalf("split %d: chain state aborted=%v mutated=%v", i, st.aborted, st.mutated)
				}
				client := advDecodedStream(t, st.wire)
				if client != want {
					t.Fatalf("split %d: client stream %q, want %q", i, client, want)
				}

				// Composition (a) — the write seam over the original text.
				doc := cwDoc(t, full)
				out, changed := dm.Mutate(doc)
				if !changed {
					t.Fatalf("split %d: mutator abstained on a document containing forbidden spans", i)
				}
				if got := cwDocContent(t, out); got != want {
					t.Fatalf("split %d: mutated doc content %q, want %q (client %q)", i, got, want, client)
				}
				for pat := range repl {
					if strings.Contains(cwDocContent(t, out), pat) {
						t.Fatalf("split %d: forbidden span %q leaked into the cache document", i, pat)
					}
					if bytes.Contains(out, []byte(pat)) {
						t.Fatalf("split %d: forbidden span %q present in raw document bytes", i, pat)
					}
				}

				// Composition (b) — today's recording topology: the document
				// is built from already-mutated deltas, so the map no longer
				// matches and the mutator must abstain, keeping the bytes
				// (which already equal the client stream).
				mutatedDoc := cwDoc(t, want)
				out2, changed2 := dm.Mutate(mutatedDoc)
				if changed2 {
					t.Fatalf("split %d: mutator re-applied to an already-mutated document", i)
				}
				if !bytes.Equal(out2, mutatedDoc) {
					t.Fatalf("split %d: abstain altered the document bytes", i)
				}
			}
		})
	}
}

// TestDocumentMutator_JSONEscapeBoundaryParity: the doc-level twin of
// TestAdversarial_SecretAcrossJSONEscapeBoundary — a decoded text whose
// content carries a JSON escape right before the forbidden span mutates to
// exactly the batch-replaced text, and the re-encoded document stays valid
// JSON whose decoded content equals the client-mutated stream.
func TestDocumentMutator_JSONEscapeBoundaryParity(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	repl := advReplMap(pairs)
	full := "start " + testSecretTrigger + " mid " + `q\" ` + testSecretTrigger + " tail"
	want := refReplace(full, repl)
	dm := mustDocMutator(t, repl)

	out, changed := dm.Mutate(cwDoc(t, full))
	if !changed {
		t.Fatal("mutator abstained on a document containing the forbidden span")
	}
	got := cwDocContent(t, out)
	if got != want {
		t.Fatalf("mutated doc content %q, want %q", got, want)
	}
	if strings.Contains(got, testSecretTrigger) {
		t.Fatal("forbidden span leaked across the escape boundary")
	}
	// `got` is already the once-decoded form of the mutated document; the
	// equality above is the round-trip proof (re-encoding did not corrupt
	// the escape that surrounded the masked span).
}

// TestDocumentMutator_AbstainsOnForeignShapes: the primitive never fabricates
// a mutation for a shape it does not understand — unparseable documents,
// missing choices/message/content, null or non-string content, and documents
// where nothing matches all pass through with the original bytes and
// changed=false.
func TestDocumentMutator_AbstainsOnForeignShapes(t *testing.T) {
	dm := mustDocMutator(t, map[string]string{testSecretTrigger: testSecretMask})
	docs := [][]byte{
		[]byte(`not json{`),
		[]byte(`{"object":"chat.completion"}`),
		[]byte(`{"choices":[]}`),
		[]byte(`{"choices":null}`),
		[]byte(`{"choices":"two"}`),
		[]byte(`{"choices":[{"index":0}]}`),
		[]byte(`{"choices":[{"message":{}}]}`),
		[]byte(`{"choices":[{"message":{"content":null}}]}`),
		[]byte(`{"choices":[{"message":{"content":42}}]}`),
		[]byte(`{"choices":[{"message":{"content":"nothing to replace here"}}]}`),
	}
	for i, doc := range docs {
		out, changed := dm.Mutate(doc)
		if changed {
			t.Fatalf("doc %d: unexpected mutation: %s", i, out)
		}
		if !bytes.Equal(out, doc) {
			t.Fatalf("doc %d: abstain altered the bytes: %s", i, out)
		}
	}
}

// TestDocumentMutator_UnknownFieldsPreserved: rewriting choices[0] must keep
// every other field of the document — top-level (usage, system_fingerprint),
// choice-level (logprobs, finish_reason) and message-level (refusal) — with
// identical values, so a mutated document stays a faithful chat.completion.
func TestDocumentMutator_UnknownFieldsPreserved(t *testing.T) {
	dm := mustDocMutator(t, map[string]string{testSecretTrigger: testSecretMask})
	doc := []byte(`{
		"id": "chatcmpl-x",
		"object": "chat.completion",
		"system_fingerprint": "fp_1",
		"usage": {"prompt_tokens": 3, "completion_tokens": 5},
		"choices": [{
			"index": 0,
			"finish_reason": "stop",
			"logprobs": null,
			"message": {"role": "assistant", "content": "value is ` + testSecretTrigger + ` end", "refusal": null}
		}]
	}`)
	out, changed := dm.Mutate(doc)
	if !changed {
		t.Fatal("mutator abstained on a document containing the forbidden span")
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("mutated doc is not valid JSON: %v\n%s", err, out)
	}
	if parsed["system_fingerprint"] != "fp_1" {
		t.Errorf("system_fingerprint lost: %v", parsed["system_fingerprint"])
	}
	usage, ok := parsed["usage"].(map[string]any)
	if !ok || usage["prompt_tokens"] != float64(3) || usage["completion_tokens"] != float64(5) {
		t.Errorf("usage lost or changed: %v", parsed["usage"])
	}
	choices, ok := parsed["choices"].([]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("choices lost: %v", parsed["choices"])
	}
	choice := choices[0].(map[string]any)
	if choice["finish_reason"] != "stop" || choice["index"] != float64(0) {
		t.Errorf("choice fields changed: %v", choice)
	}
	if _, has := choice["logprobs"]; !has {
		t.Error("choice logprobs key dropped (must stay present even when null)")
	}
	message := choice["message"].(map[string]any)
	if message["role"] != "assistant" {
		t.Errorf("message role changed: %v", message["role"])
	}
	if _, has := message["refusal"]; !has {
		t.Error("message refusal key dropped (must stay present even when null)")
	}
	if content, _ := message["content"].(string); strings.Contains(content, testSecretTrigger) || !strings.Contains(content, testSecretMask) {
		t.Errorf("content not mutated as expected: %q", content)
	}
}

// TestDocumentMutator_SecondChoiceUntouched: the replacement map is defined
// over the assistant text stream, which has exactly one choice — only
// choices[0].message.content is rewritten, mirroring FrameProcessor's
// delta-only scope. Any other choice passes through verbatim, even when its
// text contains a pattern.
func TestDocumentMutator_SecondChoiceUntouched(t *testing.T) {
	dm := mustDocMutator(t, map[string]string{testSecretTrigger: testSecretMask})
	doc := []byte(`{"choices":[
		{"index":0,"message":{"role":"assistant","content":"keep ` + testSecretTrigger + ` hidden"}},
		{"index":1,"message":{"role":"assistant","content":"other ` + testSecretTrigger + ` branch"}}
	]}`)
	out, changed := dm.Mutate(doc)
	if !changed {
		t.Fatal("mutator abstained on a document containing the forbidden span")
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("mutated doc is not valid JSON: %v", err)
	}
	if strings.Contains(parsed.Choices[0].Message.Content, testSecretTrigger) {
		t.Errorf("choices[0] not mutated: %q", parsed.Choices[0].Message.Content)
	}
	if !strings.Contains(parsed.Choices[1].Message.Content, testSecretTrigger) {
		t.Errorf("choices[1] must pass through verbatim, got %q", parsed.Choices[1].Message.Content)
	}
}

// TestDocumentMutator_NoCrossCallState encodes the card's negative: the
// mutator checks exactly the document it is given and keeps no state across
// calls — there is no "future token" it has seen, held or promised to
// inspect. A fresh processor per call also means the apply-once hazard is
// visible instead of hidden: re-feeding an already-mutated document through
// a self-referential map double-applies it, which is why production wiring
// must abstain on already-mutated payloads (see the type contract).
func TestDocumentMutator_NoCrossCallState(t *testing.T) {
	dm := mustDocMutator(t, map[string]string{"a": "ab"})

	// A first call mutating "a" → "ab" must not contaminate the next call:
	// the second document mutates as a fresh batch replacement.
	out1, changed1 := dm.Mutate(cwDoc(t, "a"))
	if !changed1 || cwDocContent(t, out1) != "ab" {
		t.Fatalf("first call: changed=%v content=%q, want ab", changed1, cwDocContent(t, out1))
	}
	out2, changed2 := dm.Mutate(cwDoc(t, "xax"))
	got := cwDocContent(t, out2)
	if !changed2 || got != "xabx" {
		t.Fatalf("second call: changed=%v content=%q, want xabx (no cross-call state)", changed2, got)
	}

	// The apply-once hazard is real and demonstrated, not hidden: the
	// replacement contains its own pattern, so re-applying to already-mutated
	// bytes mutates again ("ab" → "abb").
	out3, changed3 := dm.Mutate(cwDoc(t, "ab"))
	if !changed3 || cwDocContent(t, out3) != "abb" {
		t.Fatalf("apply-once hazard changed: changed=%v content=%q, want abb", changed3, cwDocContent(t, out3))
	}

	// Concurrent use stays independent: parallel mutations of different
	// documents produce the same results as sequential ones.
	const workers = 8
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				out, changed := dm.Mutate(cwDoc(t, "xax"))
				if !changed || cwDocContent(t, out) != "xabx" {
					errs <- errors.New("concurrent mutation diverged from the batch result")
					return
				}
			}
			errs <- nil
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// TestDocumentMutator_ConstructorValidation mirrors the streaming map rules:
// an empty map or an empty pattern is a wiring error, not a passthrough.
// (An empty replacement value is a deliberate deletion and stays valid.)
func TestDocumentMutator_ConstructorValidation(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"nil map":    nil,
		"empty map":  {},
		"empty poly": {"": "x"},
	} {
		if _, err := NewDocumentMutator(m); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := NewDocumentMutator(map[string]string{"a": "b"}); err != nil {
		t.Errorf("valid map rejected: %v", err)
	}
	if _, err := NewDocumentMutator(map[string]string{"secret": ""}); err != nil {
		t.Errorf("empty replacement (deletion) must stay valid: %v", err)
	}
}

// TestDocumentMutator_MutateResponseSeam: the adapter used by the cache
// writer wiring abstains (nil, nil) exactly when Mutate reports no change
// and returns the mutated bytes otherwise, so the writer seals exactly what
// the primitive vouched for.
func TestDocumentMutator_MutateResponseSeam(t *testing.T) {
	dm := mustDocMutator(t, map[string]string{testSecretTrigger: testSecretMask})

	mutated, err := dm.MutateResponse("org-1", json.RawMessage(cwDoc(t, "value is "+testSecretTrigger)))
	if err != nil || mutated == nil {
		t.Fatalf("expected a mutation, got err=%v mutated=%s", err, mutated)
	}
	if strings.Contains(string(mutated), testSecretTrigger) {
		t.Fatal("forbidden span leaked through the seam adapter")
	}

	abstain, err := dm.MutateResponse("org-1", json.RawMessage(cwDoc(t, "nothing to replace")))
	if err != nil || abstain != nil {
		t.Fatalf("expected an abstain, got err=%v abstain=%s", err, abstain)
	}
}
