package streaming

import (
	"bytes"
	"strings"
	"testing"
)

// Emitted-bytes boundary tests (N03-P03-T04): the region a streaming
// transform can govern ends at the bytes already released to the client.
// These tests pin the DOCUMENTED boundary — pipeline.md §7 item 3 and the
// card's negative (no promise of checking future tokens) — including the
// assembling shape that is correct-by-design, so a future change cannot
// silently claim more than the primitives deliver.

// TestBoundary_Straddle_LearnedValue_ReheldThroughCarry: the released
// prefix ends with a PARTIAL head of the value the carry map learned (the
// snapshot contained the value complete elsewhere). The held prefix frames
// re-flow through the FrameProcessor on release, the processor re-holds the
// match head (holdback), and the tail completes the replacement — the
// straddled occurrence is masked end-to-end and the decoded stream equals
// the batch replace of the whole text. The emitted prefix bytes themselves
// are never revised: only the not-yet-released head was still in flight.
func TestBoundary_Straddle_LearnedValue_ReheldThroughCarry(t *testing.T) {
	pairs := [][2]string{{testSecretTrigger, testSecretMask}}
	// Snapshot: the value complete early (learned by the map) plus a
	// partial head at the very end of the released buffer.
	head := "start " + testSecretTrigger + " mid " + testSecretTrigger[:14]
	prefix := []string{head}
	rest := []string{testSecretTrigger[14:] + " tail"}
	full := head + testSecretTrigger[14:] + " tail"

	st := advRunStream(t, pairs, prefix, rest)
	if st.aborted {
		t.Fatal("unexpected prefix abort")
	}
	if !st.mutated {
		t.Fatal("prefix mutation missing (carry map would not be derived)")
	}
	got := advDecodedStream(t, st.wire)
	want := refReplace(full, advReplMap(pairs))
	if got != want {
		t.Fatalf("decoded stream = %q, want %q (straddled occurrence must be masked end-to-end)", got, want)
	}
	// Pin the emitted volume explicitly (T04 review): the decoded stream is
	// exactly the batch replace — its length, and a held delta equal to the
	// two masked occurrences' shrinkage, so an edit that made the mask the
	// same length as the secret fails here instead of silently loosening
	// every leak assertion below.
	wantPlain := "start " + testSecretMask + " mid " + testSecretMask + " tail"
	if len(got) != len(wantPlain) {
		t.Fatalf("emitted %d bytes, want %d (exact volume of the batch replace)", len(got), len(wantPlain))
	}
	if delta := len(full) - len(got); delta != 2*(len(testSecretTrigger)-len(testSecretMask)) {
		t.Fatalf("held-back delta = %d bytes, want %d (two masked occurrences)", delta, 2*(len(testSecretTrigger)-len(testSecretMask)))
	}
	if bytes.Contains(st.wire, []byte(testSecretTrigger)) {
		t.Fatal("forbidden span present in raw wire bytes")
	}
	if bytes.Contains(st.wire, []byte(testSecretTrigger[:14])) {
		t.Fatal("the held head fragment rode the wire")
	}
}

// TestBoundary_Straddle_UnlearnedValue_AssemblesByDesign: the snapshot saw
// another value complete (the map learned it) but ends mid-VALUE-B, which
// the snapshot never saw complete — so the map has no entry for it. The
// emitted partial head is not a prefix of any learned pattern, passes
// verbatim, and the tail completes the value in the CLIENT's assembled
// view — while the full span never rides a single wire frame. This is the
// documented boundary (no retroactive hiding of emitted bytes, no
// inspection of future tokens): pinned as current behavior, not a defect.
func TestBoundary_Straddle_UnlearnedValue_AssemblesByDesign(t *testing.T) {
	alias := [2]string{"alias-one", "ONE"}
	pairs := [][2]string{alias}
	// Snapshot: alias complete (learned), a different value cut in half at
	// the release boundary.
	prefix := []string{"x alias-one y " + testSecretTrigger[:14]}
	rest := []string{testSecretTrigger[14:] + " tail"}

	st := advRunStream(t, pairs, prefix, rest)
	if st.aborted {
		t.Fatal("unexpected prefix abort")
	}
	if !st.mutated {
		t.Fatal("prefix mutation missing (carry map would not be derived)")
	}
	got := advDecodedStream(t, st.wire)

	// The learned value was transformed before release; the emitted region
	// (mutated snapshot text with the verbatim partial head) is final.
	if !strings.HasPrefix(got, "x ONE y "+testSecretTrigger[:14]) {
		t.Fatalf("emitted region was revised after release: %q", got)
	}
	if bytes.Contains(st.wire, []byte(alias[0])) {
		t.Fatal("learned value leaked to the wire")
	}

	// The boundary: the unlearned tail assembles across the release — the
	// full span exists in the client view but never on one wire frame.
	if !strings.Contains(got, testSecretTrigger) {
		t.Fatalf("expected the documented boundary (unlearned value assembles client-side), got %q", got)
	}
	if bytes.Contains(st.wire, []byte(testSecretTrigger)) {
		t.Fatal("the full forbidden span must never ride a single wire frame")
	}
}
