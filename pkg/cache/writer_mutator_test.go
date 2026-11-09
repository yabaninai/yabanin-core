package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// The response-mutator seam (N03-P03-T03): a mutator installed via
// SetResponseMutator rewrites the response document before it is sealed and
// persisted, so the stored bytes are exactly what the writer vouches the
// client received. These tests exercise the full write path — mutator, seal,
// entry construction, store — against a capturing in-memory store.

const mutSecret = "super-secret-value"

// captureStore records every entry the writer persists; an optional putErr
// turns persistence into a failure outcome.
type captureStore struct {
	mu      sync.Mutex
	entries []*Entry
	putErr  error
}

func (s *captureStore) Put(_ context.Context, e *Entry) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return "", s.putErr
	}
	s.entries = append(s.entries, e)
	return "stored-" + e.PromptHash, nil
}

func (s *captureStore) all() []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Entry(nil), s.entries...)
}

// newMutatorTestWriter builds a writer whose persistence is the capturing
// store. The store is swapped immediately after construction, before any
// Submit: workers only touch w.store after dequeuing a job, and dequeues
// happen after (happens-before) the swap, so there is no concurrent access.
func newMutatorTestWriter(t *testing.T, store *captureStore) *Writer {
	t.Helper()
	w := NewWriter(context.Background(), nil, nil, slog.New(slog.DiscardHandler))
	w.store = store
	return w
}

// mutChatDoc builds a chat.completion document with the given assistant
// content.
func mutChatDoc(t *testing.T, content string) json.RawMessage {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"id":     "chatcmpl-mut",
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

// mutStored unseals a stored entry's response; a stored entry that does not
// carry a verifiable provenance fails the test (an entry without one must
// never exist, RT-05).
func mutStored(t *testing.T, e *Entry) json.RawMessage {
	t.Helper()
	_, data, ok := OpenEntry(e.Response)
	if !ok {
		t.Fatalf("stored entry does not unseal: %.80s", e.Response)
	}
	return data
}

// mutMaskMutator is the streaming DocumentMutator over the canonical test
// map, wrapped so the seam input is captured for assertions.
func mutMaskMutator(t *testing.T, seen *[]json.RawMessage) func(string, json.RawMessage) (json.RawMessage, error) {
	t.Helper()
	dm, err := streaming.NewDocumentMutator(map[string]string{mutSecret: "[REDACTED]"})
	if err != nil {
		t.Fatalf("build document mutator: %v", err)
	}
	return func(org string, resp json.RawMessage) (json.RawMessage, error) {
		if seen != nil {
			*seen = append(*seen, append(json.RawMessage(nil), resp...))
		}
		return dm.MutateResponse(org, resp)
	}
}

// TestWriter_ResponseMutator_NilKeepsLegacyBytes: without a mutator the
// write path behaves exactly as before — the job's response bytes are sealed
// and stored as given.
func TestWriter_ResponseMutator_NilKeepsLegacyBytes(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)

	resp := mutChatDoc(t, "value is "+mutSecret+" end")
	if !w.Submit(writerJob{orgID: "org-legacy", modelTier: "m-1", response: resp}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	entries := cs.all()
	if len(entries) != 1 {
		t.Fatalf("entries stored = %d, want 1", len(entries))
	}
	if data := mutStored(t, entries[0]); !json.Valid(data) || !bytes.Contains(data, []byte(mutSecret)) {
		t.Errorf("stored response changed without a mutator: %s", data)
	}
	if _, _, written := w.Stats(); written != 1 {
		t.Errorf("written = %d, want 1", written)
	}
}

// TestWriter_ResponseMutator_MutatesBeforeSealing: the mutator runs on the
// pristine job bytes and the entry stores the MUTATED document, sealed with
// the job's route identity — the provenance envelope binds the mutated bytes
// (which is what makes them vouchable as "what the client received").
func TestWriter_ResponseMutator_MutatesBeforeSealing(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)

	var seen []json.RawMessage
	w.SetResponseMutator(mutMaskMutator(t, &seen))

	resp := mutChatDoc(t, "value is "+mutSecret+" end")
	ri := RouteIdentity{OrgID: "org-mut", Model: "m-1", GenParams: "high"}
	if !w.Submit(writerJob{orgID: ri.OrgID, modelTier: ri.Model, genParams: ri.GenParams, response: resp}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	if len(seen) != 1 {
		t.Fatalf("mutator invocations = %d, want 1", len(seen))
	}
	if !bytes.Contains(seen[0], []byte(mutSecret)) {
		t.Errorf("mutator did not receive the pristine job bytes: %s", seen[0])
	}

	entries := cs.all()
	if len(entries) != 1 {
		t.Fatalf("entries stored = %d, want 1", len(entries))
	}
	data := mutStored(t, entries[0])
	if bytes.Contains(data, []byte(mutSecret)) {
		t.Errorf("forbidden span stored in the cache entry: %s", data)
	}
	if !bytes.Contains(data, []byte("[REDACTED]")) {
		t.Errorf("mutated content not stored: %s", data)
	}
	prov, _, ok := OpenEntry(entries[0].Response)
	if !ok || !prov.Matches(ri) {
		t.Errorf("stored provenance does not match the job route: ok=%v prov=%+v", ok, prov)
	}
}

// TestWriter_ResponseMutator_RefusalSkipsWrite: a mutator that refuses the
// payload (error) must leave nothing behind — the RT-05 fail-closed shape:
// the job resolves to the skipped outcome, never to written or failed.
func TestWriter_ResponseMutator_RefusalSkipsWrite(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)
	w.SetResponseMutator(func(string, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("payload parity cannot be established")
	})

	if !w.Submit(writerJob{orgID: "org-refuse", response: mutChatDoc(t, "x")}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	if entries := cs.all(); len(entries) != 0 {
		t.Fatalf("a refused payload must not be stored, got %d entries", len(entries))
	}
	if _, _, written := w.Stats(); written != 0 {
		t.Errorf("written = %d, want 0", written)
	}
	if failed, skipped := w.OutcomeStats(); failed != 0 || skipped != 1 {
		t.Errorf("failed=%d skipped=%d, want 0/1 (refusal is a skip, not an error)", failed, skipped)
	}
}

// TestWriter_ResponseMutator_AbstainKeepsOriginal: (nil, nil) abstains — the
// original bytes are sealed and stored unchanged.
func TestWriter_ResponseMutator_AbstainKeepsOriginal(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)
	w.SetResponseMutator(func(string, json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	})

	resp := mutChatDoc(t, "value is "+mutSecret+" end")
	if !w.Submit(writerJob{orgID: "org-abstain", modelTier: "m-1", response: resp}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	entries := cs.all()
	if len(entries) != 1 {
		t.Fatalf("entries stored = %d, want 1", len(entries))
	}
	if data := mutStored(t, entries[0]); !bytes.Contains(data, []byte(mutSecret)) {
		t.Errorf("abstain did not keep the original bytes: %s", data)
	}
}

// TestWriter_ResponseMutator_ReceivesOrgID: the mutator is addressed per org
// (per-org map selection happens in the wiring that constructs it), so the
// writer must pass the job's org through.
func TestWriter_ResponseMutator_ReceivesOrgID(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)

	var mu sync.Mutex
	var gotOrg string
	w.SetResponseMutator(func(org string, resp json.RawMessage) (json.RawMessage, error) {
		mu.Lock()
		gotOrg = org
		mu.Unlock()
		return resp, nil
	})

	if !w.Submit(writerJob{orgID: "org-route", response: mutChatDoc(t, "x")}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	mu.Lock()
	defer mu.Unlock()
	if gotOrg != "org-route" {
		t.Errorf("mutator org = %q, want %q", gotOrg, "org-route")
	}
}

// TestWriter_SetResponseMutator_ToggleMidFlight: a job enqueued after
// SetResponseMutator always observes the new mutator, and a job enqueued
// after SetResponseMutator(nil) always observes the removal. Jobs enqueued
// BEFORE a toggle may observe either state (in-flight writes race the
// setter by design), so only the after-enqueue jobs are asserted.
func TestWriter_SetResponseMutator_ToggleMidFlight(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)
	w.SetResponseMutator(mutMaskMutator(t, nil))

	if !w.Submit(writerJob{orgID: "org-toggle", modelTier: "m-1", response: mutChatDoc(t, "job-a "+mutSecret)}) {
		t.Fatal("Submit job-a failed")
	}
	w.SetResponseMutator(nil)
	if !w.Submit(writerJob{orgID: "org-toggle", modelTier: "m-1", response: mutChatDoc(t, "job-b "+mutSecret)}) {
		t.Fatal("Submit job-b failed")
	}
	w.Stop()

	var sawMutated, sawOriginal int
	for _, e := range cs.all() {
		data := mutStored(t, e)
		switch {
		case bytes.Contains(data, []byte("[REDACTED]")):
			sawMutated++
			if bytes.Contains(data, []byte(mutSecret)) {
				t.Errorf("mutated entry still carries the forbidden span: %s", data)
			}
		case bytes.Contains(data, []byte(mutSecret)):
			sawOriginal++
		default:
			t.Errorf("entry matches neither toggle state: %s", data)
		}
	}
	if sawMutated != 1 || sawOriginal != 1 {
		t.Errorf("toggle results: mutated=%d original=%d, want 1/1 (job-a mutated, job-b original)", sawMutated, sawOriginal)
	}
}

// TestWriter_SetResponseMutator_ConcurrentWithWrites is the -race gate for
// the seam: a setter toggling the mutator while submitters enqueue jobs must
// not race the workers' reads, and every accepted job must still resolve to
// exactly one outcome — all written here, since this mutator never refuses
// and never abstains.
func TestWriter_SetResponseMutator_ConcurrentWithWrites(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)
	w.SetResponseMutator(func(_ string, resp json.RawMessage) (json.RawMessage, error) {
		return bytes.ReplaceAll(resp, []byte(mutSecret), []byte("[REDACTED]")), nil
	})

	const submitters, jobs = 4, 50
	stop := make(chan struct{})
	var toggler sync.WaitGroup
	toggler.Add(1)
	go func() {
		defer toggler.Done()
		for {
			select {
			case <-stop:
				return
			default:
				w.SetResponseMutator(nil)
				w.SetResponseMutator(func(_ string, resp json.RawMessage) (json.RawMessage, error) {
					return bytes.ReplaceAll(resp, []byte(mutSecret), []byte("[REDACTED]")), nil
				})
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < submitters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < jobs; j++ {
				w.Submit(writerJob{orgID: "org-race", response: mutChatDoc(t, "race "+mutSecret)})
			}
		}()
	}
	wg.Wait()
	close(stop)
	toggler.Wait()
	w.Stop()

	if _, _, written := w.Stats(); written != submitters*jobs {
		t.Errorf("written = %d, want %d", written, submitters*jobs)
	}
	if failed, skipped := w.OutcomeStats(); failed != 0 || skipped != 0 {
		t.Errorf("failed=%d skipped=%d, want 0/0", failed, skipped)
	}
	if entries := cs.all(); len(entries) != submitters*jobs {
		t.Errorf("entries stored = %d, want %d", len(entries), submitters*jobs)
	}
}

// TestWriter_ResponseMutator_ForeignDocumentAbstains: the real streaming
// DocumentMutator abstains on documents it does not understand, and the
// writer stores the original — the seam composes with the primitive's
// abstention contract instead of inventing a refusal policy.
func TestWriter_ResponseMutator_ForeignDocumentAbstains(t *testing.T) {
	cs := &captureStore{}
	w := newMutatorTestWriter(t, cs)
	w.SetResponseMutator(mutMaskMutator(t, nil))

	resp := json.RawMessage(`{"foo":"bar"}`)
	if !w.Submit(writerJob{orgID: "org-foreign", modelTier: "m-1", response: resp}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	entries := cs.all()
	if len(entries) != 1 {
		t.Fatalf("entries stored = %d, want 1", len(entries))
	}
	if data := mutStored(t, entries[0]); !bytes.Contains(data, []byte(`"bar"`)) {
		t.Errorf("foreign document not stored as given: %s", data)
	}
}
