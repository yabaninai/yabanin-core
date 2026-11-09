package streaming

import (
	"bytes"
	"errors"
	"slices"
)

// ChunkProcessor rewrites stream text with a fixed replacement map (alias →
// pseudonym), carrying match state across chunk boundaries (plan §2.2 п.5).
// Matches are found on the CONCATENATED stream: a value split between two
// chunks is still replaced in full, and the original bytes are never
// released to the client — they are either replaced or held back until they
// provably cannot start (or complete) a match (owner decision 2026-10-06:
// the pseudonym map dies with the request, no reverse substitution,
// originals never returned).
//
// Match semantics are the streaming equivalent of a whole-text
// leftmost-longest replace: at each byte position the longest pattern wins;
// a match that is a proper prefix of a longer pattern is deferred until the
// next bytes decide (a shorter match is never released early); replacements
// are emitted verbatim and never rescanned (a replacement cannot
// recursively match); a match overlapping an already-chosen one is skipped.
// Process(chunk1)+…+Process(chunkN)+Flush == the whole-text replace of the
// concatenated input, byte for byte.
//
// Not goroutine-safe: one processor per stream. After Flush the pending
// tail is empty, so the processor can be reused for a new stream with the
// same replacement map.
type ChunkProcessor struct {
	pats     []string // pattern k, parallel to patBytes/repls
	patBytes [][]byte // the same patterns as bytes (scan without conversions)
	repls    []string
	maxLen   int    // longest pattern, bounds the hold-back
	pending  []byte // hold-back tail: could still complete a match
	out      []byte // reusable output scratch
}

// NewChunkProcessor builds a processor for the replacement map. The map is
// copied; mutating the argument afterwards has no effect. An empty map or
// an empty key is an error: an empty key would match everywhere, and an
// empty map is more likely a wiring bug than an intended passthrough.
func NewChunkProcessor(replacements map[string]string) (*ChunkProcessor, error) {
	if len(replacements) == 0 {
		return nil, errors.New("streaming: chunk replacements map is empty")
	}
	cp := &ChunkProcessor{
		pats:  make([]string, 0, len(replacements)),
		repls: make([]string, 0, len(replacements)),
	}
	for k, v := range replacements {
		if k == "" {
			return nil, errors.New("streaming: chunk replacements: empty pattern")
		}
		cp.pats = append(cp.pats, k)
		cp.repls = append(cp.repls, v)
		if len(k) > cp.maxLen {
			cp.maxLen = len(k)
		}
	}
	// Deterministic scan order (longest first): at any position the first
	// hit is then the longest match; equal-length patterns cannot both
	// match, so order never changes the result.
	order := make([]int, len(cp.pats))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		if len(cp.pats[a]) != len(cp.pats[b]) {
			return len(cp.pats[b]) - len(cp.pats[a])
		}
		return bytes.Compare([]byte(cp.pats[a]), []byte(cp.pats[b]))
	})
	pats := make([]string, len(cp.pats))
	patBytes := make([][]byte, len(cp.pats))
	repls := make([]string, len(cp.repls))
	for i, k := range order {
		pats[i] = cp.pats[k]
		patBytes[i] = []byte(pats[i])
		repls[i] = cp.repls[k]
	}
	cp.pats, cp.patBytes, cp.repls = pats, patBytes, repls
	return cp, nil
}

// Process consumes one chunk of stream text and returns the text that is
// safe to emit now ("" when everything is held back). Bytes that could
// still complete a match are carried into the next call; call Flush at
// end-of-stream to release the final tail. The result is a fresh string;
// the processor reuses its internal scratch, so callers must not retain
// references to previous results.
func (cp *ChunkProcessor) Process(chunk string) string {
	if chunk == "" {
		return ""
	}
	cp.pending = append(cp.pending, chunk...)
	cp.drain(false)
	if len(cp.out) == 0 {
		return ""
	}
	return string(cp.out)
}

// Flush ends the stream: applies replacements to the held tail (no further
// input can complete a match) and emits it. Returns "" when nothing is
// held. After Flush the processor holds no bytes and may be reused.
func (cp *ChunkProcessor) Flush() string {
	cp.drain(true)
	if len(cp.out) == 0 {
		return ""
	}
	return string(cp.out)
}

// Held reports how many bytes are currently held back (telemetry support;
// bounds the delivery delay a client can observe at a chunk boundary: at
// most maxLen-1 bytes — what a learned pattern could still complete).
func (cp *ChunkProcessor) Held() int { return len(cp.pending) }

// drain scans pending, appending emit-ready bytes to out. With final=false
// two hold mechanisms protect the boundary: a committed match that could
// still extend into a longer pattern is deferred, and the longest literal
// suffix that is a proper prefix of some pattern is held back (it may
// complete with the next chunk). With final=true everything is emitted.
func (cp *ChunkProcessor) drain(final bool) {
	cp.out = cp.out[:0]
	n := len(cp.pending)
	i := 0
	emitFrom := 0 // start of the unprocessed literal run
	holdFrom := -1
	for i < n {
		mlen, pk := 0, -1
		for k, pat := range cp.patBytes {
			if len(pat) > mlen && i+len(pat) <= n && bytes.HasPrefix(cp.pending[i:], pat) {
				mlen, pk = len(pat), k
			}
		}
		if pk < 0 {
			i++
			continue
		}
		if !final && cp.extendableBeyond(i, mlen, n) {
			// The matched text is a proper prefix of a longer pattern whose
			// verdict needs future bytes: defer the whole decision.
			holdFrom = i
			break
		}
		cp.out = append(cp.out, cp.pending[emitFrom:i]...)
		cp.out = append(cp.out, cp.repls[pk]...)
		i += mlen
		emitFrom = i
	}
	switch {
	case holdFrom >= 0:
		// Emit the literal run before the deferred match, but keep its
		// possible-match-prefix tail held: it may extend into a match with
		// future bytes. The hold-back measures the tail THROUGH the
		// deferred region (holdback sees pending[litEnd-k:n]) — measured
		// on the literal run alone it could stack with the region and let
		// Held() exceed maxLen-1.
		litEnd := holdFrom
		hold := 0
		if !final {
			hold = cp.holdback(emitFrom, litEnd, n)
		}
		cp.out = append(cp.out, cp.pending[emitFrom:litEnd-hold]...)
		cp.pending = append(cp.pending[:0], cp.pending[litEnd-hold:]...)
	default:
		hold := 0
		if !final {
			hold = cp.holdback(emitFrom, n, n) // only the literal run may be held
		}
		cp.out = append(cp.out, cp.pending[emitFrom:n-hold]...)
		if hold > 0 {
			cp.pending = append(cp.pending[:0], cp.pending[n-hold:]...)
		} else {
			cp.pending = cp.pending[:0]
		}
	}
}

// extendableBeyond reports whether the match of mlen bytes at position i
// is a proper prefix of a longer pattern whose verdict needs bytes beyond
// the current pending (n) — in that case committing now could be wrong
// (the shorter match would leak before the longer one could win, as with
// "ab" of "abc").
func (cp *ChunkProcessor) extendableBeyond(i, mlen, n int) bool {
	head := cp.pending[i : i+mlen]
	avail := n - i
	for _, pat := range cp.patBytes {
		if len(pat) > mlen && len(pat) > avail && bytes.HasPrefix(pat, head) {
			return true
		}
	}
	return false
}

// holdback returns the largest k ≤ min(maxLen-1, litEnd-from) such that
// pending[litEnd-k:n] — the last k bytes of the literal run PLUS whatever
// is already deferred beyond it — is a proper prefix of some pattern: a
// match could still START at litEnd-k and complete with future bytes, so
// those bytes must not be emitted yet. In the deferred-match branch the
// window spans literal tail + held region, so the total in flight stays
// within the bound below; in the end-of-pending branch litEnd == n and the
// window is the plain tail (the pre-2026-10 shape, which measured the
// literal run alone and could stack hold + region past maxLen-1). Since a
// match fully contained in pending would already have been found by the
// scan, only proper heads (len(pat) > len(head)) are live. Holding the
// LARGEST such k is the leak-safety invariant: a shorter suffix released
// early could turn out to be the head of a match spanning the boundary,
// and the loop's first hit from the top proves the emitted gap
// [litEnd-hold, litEnd) starts no live match head. Bytes inside an
// already-replaced span are never reconsidered — leftmost-longest choice
// is final, exactly like a batch replace. With hold > 0 the kept head is a
// proper prefix of some pattern, so Held() ≤ maxLen-1 at every step; with
// hold == 0 the deferred region (extendable only while shorter than the
// longest pattern) respects the same bound.
func (cp *ChunkProcessor) holdback(from, litEnd, n int) int {
	limit := min(cp.maxLen-1, litEnd-from)
	for k := limit; k > 0; k-- {
		head := cp.pending[litEnd-k : n]
		for _, pat := range cp.patBytes {
			if len(pat) > len(head) && bytes.HasPrefix(pat, head) {
				return k
			}
		}
	}
	return 0
}
