package secevents

// Derived-EventID law tests (E01-P05-W02-C03): the v2 derivation
// (adapter.go derivedEventID) folds the policy-payload digest into the
// dedup anchor, closing the W05 preemption gap while preserving the replay
// contract and the v1 namespace. Pins, in order:
//
//  1. replay stability: byte-identical redeliveries (independent adapter
//     invocations, fresh structs) re-derive the SAME core2-* id — the
//     legitimate replay contract is intact;
//  2. v1 golden + namespace separation: a FROZEN REPLICA of the v1
//     derivation (test-only, below) is pinned against the golden hex
//     captured from the real v1 code before the v2 edit (scratch run,
//     never committed) — proving the replica faithful and the historical
//     namespace exactly reproducible; the real v2 derivation of the same
//     fixtures lands in core2-* and NEVER in the v1 namespace, so v1-era
//     stored rows (core-*) can be neither re-derived nor preempted by v2
//     events;
//  3. length framing: the v1 NUL-separator concatenation alias (a NUL
//     inside a wire field aliasing adjacent parts) is gone — the v2
//     "len:bytes" framing makes every input split unambiguous;
//  4. REAL redelivery leg (Docker, via testdb.Postgres): two independent
//     adaptations of the same wire bytes → same id → Inserted then
//     AlreadyPresent. The full attack matrix (forged-first no longer
//     pre-empts, cross-org arm, empty-upstream arm, baseline dedup) lives
//     in adapter_preemption_int_test.go — inverted with the fix there.
//
// Variants: allowed = redelivery dedup (1,4); replay/delay = independent
// invocations and the golden pin (2); rollback = N/A — v1 rows keep their
// stored ids by the namespace-separation pin; rights/cross-org = pinned in
// the preemption file (org is in the tuple).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenV1EventID is the id the REAL v1 derivation produced for BOTH
// collision fixtures (identity tuple org-victim/req-77/pol-1/v3/scan/
// exfiltration/high/block at anchorOcc, decision 0 finding 0) — captured
// live from the pre-v2 code (scratch run, 2026-11-07) before the E01-P05
// W02-C03 edit. The two content variants shared this id: that equality WAS
// the W05 collision. It is frozen here as the v1 namespace witness.
const goldenV1EventID = "core-8a5c30f55c763ff2fd39047df2eaadec5cc00a8e917973aa59a08e8fa689e2ce"

// v1DerivedEventIDReplica is a byte-faithful, test-only copy of the v1
// derivation (NUL-separated tuple hash, "core-" prefix) as it stood in
// adapter.go before E01-P05-W02-C03. It exists ONLY to pin the historical
// namespace against the golden: stored v1-era rows were produced by this
// function, and its reproducibility is what "v1 rows keep their ids
// forever" rests on. It must never be used by product code.
func v1DerivedEventIDReplica(ev eventpublisher.Event, di, fi int, d opDecision, f opFinding) string {
	h := sha256.New()
	for _, part := range []string{
		ev.OrgID, ev.RequestID, strconv.FormatInt(ev.TS, 10),
		strconv.Itoa(di), d.PolicyID, strconv.Itoa(d.Version),
		strconv.Itoa(fi), f.Step, f.Category, f.Severity, f.Action,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return "core-" + hex.EncodeToString(sum)
}

// derivationFixture builds the identity tuple of the golden collision
// pair: one decision, one finding, the exact field values w05PreemptPolicy
// encodes for (pol-1, v3, scan, exfiltration, high, block).
func derivationFixture() (eventpublisher.Event, opDecision, opFinding) {
	ev := eventpublisher.Event{
		OrgID: "org-victim", RequestID: "req-77",
		TS: anchorOcc.UnixMilli(),
	}
	d := opDecision{PolicyID: "pol-1", Version: 3}
	f := opFinding{Step: "scan", Category: "exfiltration", Severity: "high", Action: "block"}
	return ev, d, f
}

// TestDerivedEventIDV2ReplayStability: byte-identical redeliveries
// re-derive the same id through the FULL adapter (independent invocations,
// fresh structs — no shared state), and the id lives in the v2 namespace.
func TestDerivedEventIDV2ReplayStability(t *testing.T) {
	wire := w05PreemptPolicy("data-exfil", "enforce", "pol-3", 2, "scan", "exfiltration", "high", "block")
	mk := func() eventpublisher.Event {
		return eventpublisher.Event{OrgID: "org-victim", RequestID: "req-79", TS: anchorOcc.UnixMilli(),
			Policy: wire, CostStatus: "priced", EstimatedCostUSD: 0.25}
	}
	first, err := (CoreAdapter{}).AdaptPublisherEvent(mk(), anchorOcc)
	require.NoError(t, err)
	second, err := (CoreAdapter{}).AdaptPublisherEvent(mk(), anchorOcc)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Equal(t, first[0].EventID, second[0].EventID,
		"redelivered identical wire bytes must re-derive the same EventID (replay contract)")
	assert.True(t, len(first[0].EventID) > len("core2-") && first[0].EventID[:len("core2-")] == "core2-",
		"post-fix ids live in the core2- namespace, got %q", first[0].EventID)
}

// TestDerivedEventIDV1GoldenAndNamespaceSeparation pins the historical
// namespace: the frozen v1 replica reproduces the golden EXACTLY (both
// content variants — content-blind, that was the gap), while the real v2
// derivation of the same fixtures lands in core2-* and never equals the
// golden — so no v2 event can preempt or alias a v1-era stored row.
func TestDerivedEventIDV1GoldenAndNamespaceSeparation(t *testing.T) {
	ev, d, f := derivationFixture()

	// The replica is faithful: it reproduces the captured golden for the
	// identity tuple, independent of policy content.
	require.Equal(t, goldenV1EventID, v1DerivedEventIDReplica(ev, 0, 0, d, f),
		"the frozen v1 replica must reproduce the captured v1 golden")

	// The real derivation of both collision fixtures: same identity tuple,
	// divergent content → distinct core2-* ids, none equal to the golden.
	policies := []string{
		w05PreemptPolicy("data-exfil", "enforce", "pol-1", 3, "scan", "exfiltration", "high", "block"),
		w05PreemptPolicy("benign-rewrite", "audit", "pol-1", 3, "scan", "exfiltration", "high", "block"),
	}
	seen := map[string]bool{}
	for _, p := range policies {
		src := ev
		src.Policy = p
		evts, err := (CoreAdapter{}).AdaptPublisherEvent(src, anchorOcc)
		require.NoError(t, err)
		require.Len(t, evts, 1)
		id := evts[0].EventID
		assert.NotEqual(t, goldenV1EventID, id,
			"a v2 id must never equal the v1 golden: v1-era rows are outside the v2 derivation's range")
		assert.True(t, len(id) > len("core2-") && id[:len("core2-")] == "core2-",
			"v2 namespace, got %q", id)
		assert.False(t, seen[id], "the two content variants must derive DISTINCT ids")
		seen[id] = true
	}
}

// TestDerivedEventIDLengthFraming pins the framing property: two field
// splits with the SAME v1 NUL-concatenation (step="a\x00b",category="c" vs
// step="a",category="b\x00c") collided in v1's unframed hash; the v2
// "len:bytes" framing derives distinct ids for them, and identical inputs
// stay identical.
func TestDerivedEventIDLengthFraming(t *testing.T) {
	ev, d, f := derivationFixture()
	digest := sha256.Sum256([]byte("policy-bytes"))
	left := f
	left.Step = "a\x00b"
	left.Category = "c"
	right := f
	right.Step = "a"
	right.Category = "b\x00c"

	// v1 alias witness: the replica cannot tell the two splits apart.
	assert.Equal(t, v1DerivedEventIDReplica(ev, 0, 0, d, left), v1DerivedEventIDReplica(ev, 0, 0, d, right),
		"v1 NUL-separator alias reproduced by the replica (the framing gap)")
	// v2 separates them, and is deterministic for identical inputs.
	idL := derivedEventID(ev, 0, 0, d, left, digest[:])
	idR := derivedEventID(ev, 0, 0, d, right, digest[:])
	assert.NotEqual(t, idL, idR, "length-framed parts must not alias across field splits")
	assert.Equal(t, idL, derivedEventID(ev, 0, 0, d, left, digest[:]),
		"identical input re-derives the identical id")
}

// TestDerivedEventIDRealRedeliveryLeg is the compact REAL leg (Docker):
// two independent adaptations of the same wire bytes derive the same id
// end-to-end, and the durable sink dedups the second write under the
// first-write-wins law. The attack matrix around it lives in
// adapter_preemption_int_test.go.
func TestDerivedEventIDRealRedeliveryLeg(t *testing.T) {
	pool := testdb.Postgres(t)
	sink := NewDurableSink(pool)
	require.NoError(t, sink.EnsureSchema(context.Background()))
	ctx := context.Background()

	wire := w05PreemptPolicy("data-exfil", "enforce", "pol-4", 1, "scan", "exfiltration", "high", "block")
	mk := func() eventpublisher.Event {
		return eventpublisher.Event{OrgID: "org-replay", RequestID: "req-80", TS: anchorOcc.UnixMilli(),
			Policy: wire, CostStatus: "priced", EstimatedCostUSD: 2.5}
	}
	first, err := (CoreAdapter{}).AdaptPublisherEvent(mk(), anchorOcc)
	require.NoError(t, err)
	second, err := (CoreAdapter{}).AdaptPublisherEvent(mk(), anchorOcc)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, first[0].EventID, second[0].EventID)

	status, err := sink.RecordContext(ctx, first[0])
	require.NoError(t, err)
	assert.Equal(t, DurableInserted, status)
	status, err = sink.RecordContext(ctx, second[0]) // the redelivery, independently re-derived
	require.NoError(t, err)
	assert.Equal(t, DurableAlreadyPresent, status,
		"the redelivery is absorbed — the replay contract holds under v2")

	docs := aud01Docs(t, pool, "org-replay", first[0].EventID)
	require.Len(t, docs, 1, "exactly one durable row for the redelivered event")
	assert.Contains(t, docs[0], "data-exfil")
}
