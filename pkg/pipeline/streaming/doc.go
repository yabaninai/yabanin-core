// Package streaming holds the three policy primitives that ride a gateway
// SSE stream (plan OUTPLAY-2026-10-06 §2.2 п.5, card OP-4). The gateway
// middleware (OP-8) is the only production caller: pkg/gateway/stream.go and
// chat.go stay untouched by this package — the primitives operate on decoded
// stream text and SSE frames, while the middleware owns the HTTP plumbing.
//
// LIFECYCLE (canonical wiring for one streaming request):
//
//  1. ATTACH — the caller (policystore → gateway) pre-filters compiled
//     policies by hook and attachment priority (org → key → model, plan
//     §2.2 п.0) and wraps them in a Runner via EngineRunner. Install the
//     PrefixGate only when at least one stream_prefix policy attached: the
//     hold-back buffer is the only source of TTFB regression and it is
//     bounded by the prefix delay (default 500ms).
//
//  2. PREFIX — PrefixGate ingests decoded text deltas and buffers up to
//     MaxTokens tokens or MaxDelay since the first delta (whichever fires
//     first), then Flush runs the prefix policies once over a
//     KindStreamPrefix payload. Deny aborts the stream BEFORE any buffered
//     byte reaches the client — AbortFrame renders the canonical error
//     frame plus the "data: [DONE]\n\n" terminator. Otherwise the (possibly
//     mutated — Result.Mutated) buffer is released and the stream switches
//     to passthrough. Flush is also required at end-of-stream: a short
//     stream may end while still buffering.
//
//  3. CARRY — ChunkProcessor rewrites chunk text with a fixed replacement
//     map carried across chunk boundaries: bytes that could still complete
//     a match are held back, so an original (pre-substitution) value is
//     never released to the client even when the match is split between
//     chunks (owner decision 2026-10-06: no reverse substitution, originals
//     never returned). FrameProcessor applies such a text transform to
//     OpenAI-compatible SSE frames: "data: [DONE]" and frames without a
//     content delta pass through byte-identical; a mutated delta re-encodes
//     the whole frame, so event boundaries are rebuilt around the new
//     length and never broken. Wire the FrameProcessor BEFORE the cache
//     RecordingWriter so the semantic cache and the client observe the same
//     mutated bytes (plan §8 risk note, RT-05 consistency).
//
//  4. FINAL — FinalAggregate accumulates the frames the client received
//     into the synthetic chat.completion document (the W-STCACHE
//     accumulator pattern: content and reasoning concatenated from deltas,
//     tool calls merged by index, usage carried from the final frame).
//     FinalCheck runs the stream_final policies over it. A deny AFTER
//     issuance cannot unsend delivered bytes: it degrades to a flagged
//     outcome (FinalOutcome.Effective == flag) that the middleware turns
//     into a flag event + decision-log entry + metric. Aborting mid-flight
//     is only possible at the prefix stage.
//
// Concurrency: one stream is served by one goroutine — the primitives
// carry per-stream state and are NOT goroutine-safe. Separate instances are
// safe for concurrent use (the Runner, typically *pipeline.Engine through
// EngineRunner, is goroutine-safe by its own contract). Every entry point
// honors ctx: a cancelled context fail-closes the prefix gate (abort —
// unverified content is never forwarded) and degrades the final check to a
// flagged infra failure.
package streaming
