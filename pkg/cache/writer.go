// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/embeddings"
)

const (
	writerWorkers      = 4
	writerQueueSize    = 256
	writerWriteTimeout = 30 * time.Second
)

// writerJob is a cache write request queued for background processing.
// It carries values only — never a caller context — so cancelling the HTTP
// request that produced the job cannot affect an accepted job.
type writerJob struct {
	orgID, modelTier, modelVer string
	genParams                  string
	// upstream is the endpoint-revision fingerprint (audit H1) captured at
	// Submit time; the worker re-seals from the job's identity fields, so
	// the fingerprint must ride along or the pgvector copy loses the
	// endpoint binding the exact layer's seal carries.
	upstream            string
	promptJSON          json.RawMessage
	response            json.RawMessage
	sseChunks           json.RawMessage
	tokensIn, tokensOut int
	// mutator is the response mutator current at Submit time, captured
	// under the writer mutex (N03-P03-T03). Binding the mutator to the job
	// — instead of reading the writer field at processing time — makes the
	// stored bytes reflect the policy era the response was produced in, the
	// same way the seal binds provenance; an admin toggle mid-flight can
	// never flip a queued job's parity contract.
	mutator ResponseMutator
}

// entryStore is the persistence surface the writer needs (the subset of
// *Store). Kept as an interface so the write path — including the response
// mutator seam below — can be exercised with a capturing store in unit
// tests without a database. *Store satisfies it unchanged.
type entryStore interface {
	Put(ctx context.Context, e *Entry) (string, error)
}

// ResponseMutator rewrites a cache response document before the writer
// seals and persists it (N03-P03-T03). It receives the org that owns the
// write and the raw completion document exactly as the job carried them,
// and returns:
//   - (mutated, nil) — store the returned bytes. They are what the seal
//     envelope will bind: whatever the mutator returns is what the cache
//     will serve, so it must equal the client-visible response.
//   - (nil, nil) — abstain: the original bytes are stored unchanged.
//   - (any, err) — the mutator refuses the payload: the write is skipped
//     (RT-05 fail-closed — an entry whose parity with the client bytes
//     cannot be established must never be stored), counted in the skipped
//     outcome and logged at warn. It is not an error outcome: the writer
//     is healthy, the payload is unvouchable.
//
// The mutator is captured into each job at Submit time, under the writer
// mutex: a job enqueued after SetResponseMutator always observes the new
// mutator, a job enqueued before always observes the old one — no in-flight
// ambiguity. SetResponseMutator is safe to call concurrently with writes.
//
// Mutator window (N03-P03-T04): the seam's authority ends at the seal. The
// mutator decision is bound into the entry when the job is written; entries
// already sealed and stored are never revisited by a later
// SetResponseMutator, and bytes already emitted to the client were never
// this seam's input. The seam governs the pgvector document only:
// CacheService.Write seals the ORIGINAL response bytes for the synchronous
// exact layer before Submit, so with a mutator installed the exact layer and
// the semantic-cache document deliberately differ (exact = client-observed
// bytes, semantic = mutated) — writer_boundary_test.go pins this. A wiring
// that installs a mutator in production must either keep it abstaining
// (today's streaming topology already guarantees client/cache parity) or
// first route both layers through one mutator outcome.
type ResponseMutator func(orgID string, response json.RawMessage) (json.RawMessage, error)

// Writer manages asynchronous cache writes using a worker pool.
//
// Counters are typed atomics on two distinct axes: queued counts admission
// (jobs accepted into the queue); every accepted job then resolves to exactly
// one outcome — written, failed, skipped (RT-05) or dropped (Submit rejection
// or stop-timeout abandonment). No job is ever counted in two outcome
// categories.
//
// Lifecycle uses one synchronized boundary: mu serializes Submit's enqueue,
// close(queue) and Stop, so Submit never sends on a closed channel and never
// blocks on queue capacity.
type Writer struct {
	store    entryStore
	pool     *pgxpool.Pool
	embedder embeddings.Client
	queue    chan writerJob
	log      *slog.Logger
	ctx      context.Context

	// mutator is the response mutator new jobs capture at Submit (see
	// writerJob.mutator). Nil (the default) keeps the legacy behavior: the
	// job's response bytes are sealed and stored as given. Guarded by mu.
	mutator ResponseMutator

	// writeTimeout bounds each job's write (embedding + persistence) so a
	// hung embedder or DB cannot pin a worker forever. Zero means the
	// writerWriteTimeout default. The deadline is independent of the
	// lifecycle ctx: a cancelled lifecycle ctx must not abort in-flight
	// writes, but a write must still finish by its deadline.
	writeTimeout time.Duration

	mu     sync.Mutex // serializes Submit enqueue with close(queue) and Stop
	closed bool       // queue closed; Submit rejects
	// abandon stops workers from dequeuing further buffered jobs after a
	// stop timeout; already dequeued jobs still run to their deadline.
	abandoned bool
	abandon   chan struct{}
	stopDone  chan struct{} // closed once all workers terminated
	// drainResult remembers the outcome of the first completed stop so
	// repeated Stop calls return the same wait-result.
	drainResult *bool

	// Counters (atomic.Int64): queued = admission; dequeued = received by a
	// worker (every dequeued job resolves to written/failed/skipped);
	// dropped = Submit rejections + jobs abandoned by a stop timeout.
	queued   atomic.Int64
	dequeued atomic.Int64
	written  atomic.Int64
	failed   atomic.Int64
	skipped  atomic.Int64
	dropped  atomic.Int64

	wg sync.WaitGroup
}

// NewWriter creates a new cache writer with the given worker pool size and embedding client.
// ctx bounds the writer's lifetime; it is not the caller's request context —
// Submit copies job values only, so cancelling an HTTP request never reaches
// queued or in-flight jobs.
func NewWriter(ctx context.Context, pool *pgxpool.Pool, embedder embeddings.Client, log *slog.Logger) *Writer {
	w := &Writer{
		store:        NewStore(pool),
		pool:         pool,
		embedder:     embedder,
		queue:        make(chan writerJob, writerQueueSize),
		log:          log,
		ctx:          ctx,
		writeTimeout: writerWriteTimeout,
		abandon:      make(chan struct{}),
	}
	for i := 0; i < writerWorkers; i++ {
		w.wg.Add(1)
		go w.worker() //nolint:contextcheck // worker pool outlives request contexts; jobs run on a detached, deadline-bounded context
	}
	return w
}

// Submit queues a write job non-blocking. Returns false if the queue is full
// or the writer has been stopped. Safe against a concurrent Stop: the closed
// flag and the channel send are serialized by the same mutex, so Submit never
// sends on a closed channel.
func (w *Writer) Submit(job writerJob) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.dropped.Add(1)
		if w.log != nil {
			w.log.Warn("cache writer stopped, dropping job", "org", job.orgID)
		}
		return false
	}
	// N03-P03-T03: pin the response mutator current at admission, so the
	// job's parity contract is fixed at enqueue, not at whichever moment a
	// worker later picks it up (we already hold mu).
	job.mutator = w.mutator
	select {
	case w.queue <- job:
		w.queued.Add(1)
		return true
	default:
		w.dropped.Add(1)
		if w.log != nil {
			w.log.Warn("cache write queue full, dropping", "org", job.orgID)
		}
		return false
	}
}

// SetResponseMutator installs (or replaces) the response mutator captured
// into jobs submitted from now on; nil removes it and restores the legacy
// behavior (response bytes sealed and stored exactly as the job carried
// them). Already-queued jobs keep the mutator they were submitted with.
// Safe to call at any time, including after Stop and concurrently with
// in-flight writes.
func (w *Writer) SetResponseMutator(m ResponseMutator) {
	w.mu.Lock()
	w.mutator = m
	w.mu.Unlock()
}

// StopWithTimeout closes the queue and waits for worker termination before
// returning: after any Stop* call returns, workers no longer touch the store
// pool. With timeout > 0 it first waits up to that long for workers to drain
// every accepted job; if the timeout elapses first, the still-buffered jobs
// are abandoned — never dequeued, counted as dropped exactly once — while
// jobs already dequeued run to their per-write deadline. timeout <= 0 waits
// unbounded and always drains fully.
//
// The returned bool is the wait-result: true means the drain completed (every
// accepted job reached an outcome); false means the timeout path abandoned
// buffered jobs. Repeated Stop/StopWithTimeout calls are safe: they return
// the remembered result of the first completed stop (termination is already
// complete by then).
func (w *Writer) StopWithTimeout(timeout time.Duration) bool {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	if w.abandon == nil { // zero-value Writer (no workers): keep the signal usable
		w.abandon = make(chan struct{})
	}
	if w.stopDone == nil {
		w.stopDone = make(chan struct{})
		go func() {
			w.wg.Wait()
			close(w.stopDone)
		}()
	}
	stopDone := w.stopDone
	w.mu.Unlock()

	drained := true
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-stopDone:
		case <-timer.C:
			drained = false
			w.abandonRemaining()
		}
	}
	<-stopDone // bounded even on the timeout path: per-write deadlines end in-flight jobs

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.drainResult == nil {
		res := drained
		w.drainResult = &res
		if !drained {
			// Workers have terminated, so the counters are stable:
			// accepted minus dequeued is exactly the set of buffered jobs
			// abandoned by the timeout — counted dropped once, never as
			// written/failed/skipped.
			if undrained := w.queued.Load() - w.dequeued.Load(); undrained > 0 {
				w.dropped.Add(undrained)
				if w.log != nil {
					w.log.Warn("cache writer stop timeout, abandoned jobs counted as dropped", "count", undrained)
				}
			}
		}
	}
	return *w.drainResult
}

// Stop closes the queue and waits unbounded for all workers to finish
// draining. Repeated calls are safe and return the same result.
func (w *Writer) Stop() bool {
	return w.StopWithTimeout(0)
}

func (w *Writer) abandonRemaining() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.abandoned {
		w.abandoned = true
		close(w.abandon)
	}
}

func (w *Writer) worker() {
	defer w.wg.Done()
	// Exit on queue close (full drain) or on the abandon signal fired by a
	// stop timeout — never on the lifecycle ctx, so a shutdown cancellation
	// cannot silently drop queued jobs.
	for {
		select {
		case job, ok := <-w.queue:
			if !ok {
				return
			}
			w.dequeued.Add(1)
			w.process(job)
		case <-w.abandon:
			return
		}
	}
}

// process resolves one dequeued job to exactly one outcome:
// written | failed | skipped (RT-05). The per-write context is detached from
// the lifecycle ctx (a shutdown cancellation must not abort in-flight writes)
// but bounded by the write deadline, so a hung embedder or DB cannot pin a
// worker forever.
func (w *Writer) process(job writerJob) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), w.writeDeadline())
	defer cancel()

	written, err := w.write(ctx, job)
	switch {
	case err != nil:
		w.failed.Add(1)
		if w.log != nil {
			w.log.Error("cache write failed", "org", job.orgID, "error", err)
		}
	case written:
		// N2: the authoritative "written" counter — a job actually persisted.
		w.written.Add(1)
		RecordWrite("written")
	default:
		// RT-05: skipped — the response could not carry a verifiable
		// provenance, so no entry was stored. Counted as skipped, never
		// as written or dropped.
		w.skipped.Add(1)
		RecordWrite("skipped")
	}
}

func (w *Writer) writeDeadline() time.Duration {
	if w.writeTimeout > 0 {
		return w.writeTimeout
	}
	return writerWriteTimeout
}

// write persists one queued job. written=false reports a deliberate skip
// (nothing stored) with no error; err reports a real persistence failure.
func (w *Writer) write(ctx context.Context, job writerJob) (bool, error) {
	// N03-P03-T03: apply the response mutator captured at Submit BEFORE the
	// seal, so the provenance envelope binds exactly the bytes that will be
	// stored — which must be the bytes the client received. A refusal skips
	// the write (same RT-05 shape as an unsealable response below); an
	// abstain keeps the original bytes.
	if job.mutator != nil {
		mutated, mErr := job.mutator(job.orgID, job.response)
		switch {
		case mErr != nil:
			if w.log != nil {
				w.log.Warn("cache write skipped, response mutator refused the payload", "org", job.orgID, "error", mErr)
			}
			return false, nil
		case len(mutated) > 0:
			job.response = mutated
		default:
			// (nil, nil): abstain — keep the original response bytes.
		}
	}

	// Normalize the prompt once: the stored prompt_hash and the embedding are
	// computed over the same canonical bytes, so a lookup that normalizes the
	// same prompt (normalizeForCache) reproduces both.
	normJSON, err := NormalizeMessagesJSON(job.promptJSON)
	if err != nil {
		normJSON = job.promptJSON // fallback to original
	}
	promptHash := ComputePromptHash(normJSON)

	// RT-05: the pgvector payload carries the same provenance envelope the
	// exact layer stores, so a lookup can verify model used, org, route
	// namespace and generation parameters no matter which layer served the
	// entry. An unsealable response is not written at all — an entry without
	// verifiable provenance must never exist.
	// N03-P04-T02: the envelope also carries this writer's embedding-space
	// identity (derived from the embedder configuration, so a model or
	// query-prefix change can never pass unnoticed) and the
	// similarity-admission rule version; the semantic lookup serves entries
	// only when both match its current configuration.
	// N03-P04-T03: the space identity additionally carries the per-input
	// multilingual/domain qualifier tag derived from THIS prompt's content,
	// and the embedded text carries the qualifier prefix. A near-duplicate
	// in another language (or a prompt written under another qualifier
	// configuration) is a different space, not a similar vector — see the
	// lookup-side mirror in LookupWithResult.
	qualTag := embedderInputTag(w.embedder, qualifierSourceText(normJSON))
	// N03-P04-T05: stamp a one-way fingerprint of the prompt's decisive
	// content (dates, numbers, entities, access markers) into the
	// provenance. The lookup-side admission guard (LookupWithResult) vetoes
	// semantic hits whose decisive content differs from the current prompt
	// even when the vectors score above the threshold — T04 measured 10/14
	// such false hits on the holdout. Hash only: the cache never stores
	// prompt text.
	decVer, decFP := DecisiveContentStamp(normJSON)
	sealed, sealErr := SealEntryVersionedContent(job.response, RouteIdentity{
		OrgID:     job.orgID,
		Model:     job.modelTier,
		Version:   job.modelVer,
		GenParams: job.genParams,
		Upstream:  job.upstream,
	}, embeddings.QualifiedSpaceVersion(embedderSpaceVersion(w.embedder), qualTag), SemanticAdmissionVersion(), decVer, decFP)
	if sealErr != nil {
		if w.log != nil {
			w.log.Warn("cache write skipped, response cannot carry provenance", "org", job.orgID, "error", sealErr)
		}
		return false, nil
	}

	entry := &Entry{
		OrgID:      job.orgID,
		ModelTier:  job.modelTier,
		PromptHash: promptHash,
		Response:   sealed,
		SSEChunks:  job.sseChunks,
		TokensIn:   job.tokensIn,
		TokensOut:  job.tokensOut,
		ModelVer:   job.modelVer,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	// Compute embedding for semantic search. The embedded text is the
	// canonical prompt bytes plus the qualifier prefix derived above — the
	// exact input the lookup path reconstructs for the same prompt
	// (N03-P04-T03).
	var vec []float32
	var embErr error
	if w.embedder != nil {
		vec, embErr = w.embedder.Embed(ctx, qualifiedEmbedInput(string(normJSON), qualTag))
	} else {
		embErr = nil // no embedder available — skip embedding
	}
	if embErr != nil {
		if w.log != nil {
			w.log.Warn("embedding failed for cache write, storing without vector", "error", embErr)
		}
	} else if len(vec) > 0 {
		entry.Embedding = vec
	}

	if _, err = w.store.Put(ctx, entry); err != nil {
		return false, err
	}
	return true, nil
}

// embedderSpaceVersion resolves an embedder's embedding-space identity
// (N03-P04-T02). Embedders implementing embeddings.SpaceVersioner identify
// their space; any other embedder (test stubs, legacy clients) is
// version-blind and yields "". Both the writer (at seal time) and the cache
// service (at lookup time) resolve versions through this one helper, so the
// two sides can never disagree about what "current" means.
func embedderSpaceVersion(emb embeddings.Client) string {
	if sv, ok := emb.(embeddings.SpaceVersioner); ok {
		return sv.SpaceVersion()
	}
	return ""
}

// embedderInputTag resolves an embedder's per-input multilingual/domain
// qualifier tag (N03-P04-T03). Embedders implementing
// embeddings.InputQualifier derive the tag from the prompt content;
// any other embedder is qualifier-blind and yields "". Both the writer and
// the cache service resolve tags through this one helper with the same
// extracted content, so the two sides derive the same qualifier for the
// same prompt by construction.
func embedderInputTag(emb embeddings.Client, text string) string {
	if iq, ok := emb.(embeddings.InputQualifier); ok {
		return iq.InputQualifierTag(text)
	}
	return ""
}

// qualifierSourceText extracts the natural-language content of a normalized
// prompt (the "messages" content strings) for qualifier detection
// (N03-P04-T03). Detection runs over content — not raw JSON — so structural
// keys ("messages", "content", uuid org ids) cannot outvote the user's
// script in short prompts. It is a pure function of the input bytes: the
// write path and the lookup path call it with the same normalized prompt
// and must get identical results. Unparsable or message-less bodies fall
// back to the raw bytes (detection then sees JSON structure too — still
// deterministic).
func qualifierSourceText(promptJSON []byte) string {
	var raw map[string]interface{}
	if err := json.Unmarshal(promptJSON, &raw); err != nil {
		return string(promptJSON)
	}
	messages, ok := raw["messages"].([]interface{})
	if !ok {
		return string(promptJSON)
	}
	var b strings.Builder
	for _, m := range messages {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if content, ok := msg["content"].(string); ok {
			b.WriteString(content)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return string(promptJSON)
	}
	return b.String()
}

// qualifiedEmbedInput builds the embedding input for a normalized prompt
// under a qualifier tag (N03-P04-T03): the qualifier prefix conditions the
// vector on the input's multilingual/domain qualifier; an empty tag leaves
// the input byte-identical to the pre-T03 behavior. Writer and lookup build
// the input through this one function.
func qualifiedEmbedInput(normPrompt string, tag string) string {
	return embeddings.QualifierInputPrefix(tag) + normPrompt
}

// Stats returns writer metrics for Prometheus exposure: queued counts jobs
// accepted into the queue, dropped counts Submit rejections plus jobs
// abandoned by a stop timeout, written counts jobs actually persisted.
func (w *Writer) Stats() (queued, dropped, written int64) {
	return w.queued.Load(), w.dropped.Load(), w.written.Load()
}

// OutcomeStats exposes the remaining outcome counters: every accepted job
// resolves to exactly one of written, failed, skipped — or is counted dropped
// by a stop timeout.
func (w *Writer) OutcomeStats() (failed, skipped int64) {
	return w.failed.Load(), w.skipped.Load()
}
