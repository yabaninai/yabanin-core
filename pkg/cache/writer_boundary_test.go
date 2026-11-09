package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/pipeline/streaming"
)

// Emitted-bytes boundary of the cache write seam (N03-P03-T04): the
// response mutator's authority ends at the semantic-cache seal, and the
// synchronous exact layer sits OUTSIDE the seam — CacheService.Write seals
// the original response bytes for it before Submit. These tests pin that
// documented asymmetry (docs/pipeline.md §7 item 3, writer.go mutator
// window): a wiring that installs a mutator must keep the abstain default
// or explicitly unify both layers before claiming coverage.

// newBoundaryTestService builds a CacheService over real Redis (exact layer)
// with a LIVE writer whose persistence is a capturing store, so one Write
// can be observed on both layers at once. The store is swapped immediately
// after construction, before any Submit (same reasoning as
// newMutatorTestWriter: workers only touch w.store after a dequeue, which
// happens after the swap).
func newBoundaryTestService(t *testing.T, mut ResponseMutator) (*CacheService, *captureStore, *redis.Client) {
	t.Helper()
	rdb := redisContainer(t) // skips in -short like the rest of the Redis suite

	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
	}
	w := NewWriter(context.Background(), nil, nil, slog.New(slog.DiscardHandler))
	stored := &captureStore{}
	w.store = stored
	if mut != nil {
		w.SetResponseMutator(mut)
	}
	return &CacheService{
		exact:  NewRedisStore(rdb, 24*time.Hour),
		policy: pc,
		writer: w,
		log:    slog.New(slog.DiscardHandler),
	}, stored, rdb
}

// TestService_WriteBoundary_ExactLayerOutsideMutatorSeam: with a document
// mutator installed, one Write lands the ORIGINAL sealed bytes in the exact
// layer (sealed synchronously before the seam runs — the bytes the client
// observed in today's topology) and the MUTATED document in the semantic
// entry (the seam applies pre-seal). Both facts are the documented
// asymmetry, pinned against future wiring changes.
func TestService_WriteBoundary_ExactLayerOutsideMutatorSeam(t *testing.T) {
	dm, err := streaming.NewDocumentMutator(map[string]string{mutSecret: "[REDACTED]"})
	if err != nil {
		t.Fatalf("build document mutator: %v", err)
	}
	cs, stored, rdb := newBoundaryTestService(t, dm.MutateResponse)

	ri := RouteIdentity{OrgID: "org-bnd", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	resp := mutChatDoc(t, "value is "+mutSecret+" end")
	if err := cs.Write(context.Background(), ri, body, resp, 1, 2); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Exact layer: serves and stores the original bytes.
	hit, err := cs.LookupWithResult(context.Background(), ri, body)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if hit == nil {
		t.Fatal("exact layer must serve the entry (it was sealed before the seam ran)")
	}
	if !bytes.Equal([]byte(hit.Data), resp) {
		t.Errorf("exact layer does not carry the original bytes verbatim: %s", hit.Data)
	}
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(body)))
	raw, err := rdb.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("raw exact-layer get: %v", err)
	}
	if !bytes.Contains([]byte(raw), []byte(mutSecret)) {
		t.Errorf("exact-layer envelope does not carry the original response bytes")
	}

	// Semantic layer: the seam mutated the document before its seal.
	cs.writer.Stop()
	entries := stored.all()
	if len(entries) != 1 {
		t.Fatalf("semantic entries stored = %d, want 1", len(entries))
	}
	data := mutStored(t, entries[0])
	if bytes.Contains(data, []byte(mutSecret)) {
		t.Errorf("forbidden span stored in the semantic entry: %s", data)
	}
	if !bytes.Contains(data, []byte("[REDACTED]")) {
		t.Errorf("mutated content not stored in the semantic entry: %s", data)
	}
	if _, _, written := cs.writer.Stats(); written != 1 {
		t.Errorf("written = %d, want 1", written)
	}
}

// TestService_WriteBoundary_RefusalStillSealsExactLayer: a mutator refusal
// (RT-05 fail-closed) governs the semantic layer only — nothing is stored
// there — while the exact layer keeps the entry sealed from the original
// bytes before Submit. Pinned as the documented seam window: unifying this
// is a wiring decision, not a writer-side change.
func TestService_WriteBoundary_RefusalStillSealsExactLayer(t *testing.T) {
	mut := func(string, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("payload parity cannot be established")
	}
	cs, stored, rdb := newBoundaryTestService(t, mut)

	ri := RouteIdentity{OrgID: "org-refuse", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"refuse"}]}`)
	resp := mutChatDoc(t, "value is "+mutSecret+" end")
	if err := cs.Write(context.Background(), ri, body, resp, 1, 1); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Exact layer: the entry exists, sealed from the original bytes.
	hit, err := cs.LookupWithResult(context.Background(), ri, body)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if hit == nil {
		t.Fatal("exact layer must keep the entry (the seam's refusal cannot unseal it retroactively)")
	}
	if !bytes.Equal([]byte(hit.Data), resp) {
		t.Errorf("exact layer does not carry the original bytes verbatim: %s", hit.Data)
	}
	key := MakeKey(ri.OrgID, ri.Model, ComputePromptHash(normalizeForCache(body)))
	raw, err := rdb.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("raw exact-layer get: %v", err)
	}
	if !bytes.Contains([]byte(raw), []byte(mutSecret)) {
		t.Errorf("exact-layer envelope does not carry the original response bytes")
	}

	// Semantic layer: refusal skipped the write entirely.
	cs.writer.Stop()
	if entries := stored.all(); len(entries) != 0 {
		t.Fatalf("a refused payload must not reach the semantic store, got %d entries", len(entries))
	}
	if failed, skipped := cs.writer.OutcomeStats(); failed != 0 || skipped != 1 {
		t.Errorf("failed=%d skipped=%d, want 0/1 (refusal is a skip, not an error)", failed, skipped)
	}
}
