package secevents

// Regression pin for the W05 preemption attack — gap CLOSED by
// E01-P05-W02-C03 (derivedEventID v2, adapter.go):
//
//	«XF-2+EV-6 pre-emption — forged core-* id under a victim org pre-empts
//	 the genuine event (first-write-wins); cheap, no reader needed.»
//
// History: the v1 derivation hashed only the identity tuple
//
//	(org, request_id, ts, di, policy_id, version, fi, step, category,
//	 severity, action)
//
// — deliberately NOT the decision Name, Mode, Verdict, the summary text or
// the policy-payload bytes, so a producer-position adversary (W03 catalog
// A2: compromised or rogue producer; X7 transport) could deliver a forged
// core event under the VICTIM's org with the same identity tuple but
// divergent content and pre-empt the genuine document. W05-C02 recorded
// the verdict REAL-GAP at the adapter×durable seam with the remediation
// direction: fold the policy-record digest into the derivation. This file
// pinned that gap open (W05); E01-P05-W02-C03 implements the remediation
// and this file is INVERTED to pin it closed:
//
//   - the derivation-tuple collision is GONE: same identity tuple,
//     divergent content → DIFFERENT core2-* ids (the policy-payload digest
//     is folded in; the replay contract survives — a redelivered core
//     event carries byte-identical policy bytes);
//   - forged-first no longer substitutes evidence: the genuine event gets
//     its own row (own id), the forgery keeps its own row, and the victim
//     org's audit trail contains the genuine finding text;
//   - the v1 namespace stays intact and disjoint: v1-era rows keep their
//     historical core-* ids, and no v2 event can derive into the v1
//     namespace (different domain tag — pinned in adapter_derivation_test.go
//     against the frozen v1 golden).
//
// REAL legs: CoreAdapter.AdaptPublisherEvent and DurableSink over
// testdb.Postgres are the real production classes; the eventpublisher.Event
// payloads are MODELED wire fixtures (as in adapter_test.go). Docker-backed
// legs skip under -short like every testdb stand.
//
// Mandatory variants for this arm: allowed = the genuine event alone
// records once and its redelivery dedups (the legitimate replay contract);
// empty/unavailable upstream = a policy-less core event adapts to zero
// events (explicit no-signal — nothing to forge from); rights-denial +
// cross-org = the same forged tuple under the ATTACKER's org derives a
// different id (org-scoped identity holds); replay/delay = the attack arm
// (forged-first, genuine-delayed) now ends with BOTH documents durable and
// the genuine text intact; rollback = N/A — first-write-wins immutability
// stays the durability law, and pre-v2 "core-*" rows are never rewritten
// (v1 namespace preserved, see above).

import (
	"context"
	"strconv"
	"testing"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// w05PreemptPolicy builds a policy decision record for the derivation
// tuple (policy_id, version, step, category, severity, action) with the
// CONTENT fields (name, mode) as given — the fields OUTSIDE the identity
// tuple but INSIDE the folded policy-payload digest (v2).
func w05PreemptPolicy(name, mode, policyID string, version int, step, category, severity, action string) string {
	return ` [{"policy_id":"` + policyID + `","name":"` + name + `","version":` +
		strconv.Itoa(version) + `,"mode":"` + mode + `","verdict":"` + mode +
		`","findings":[{"step":"` + step + `","category":"` + category +
		`","severity":"` + severity + `","action":"` + action + `"}]}]`
}

// TestW05DerivedIDSeparation (inverted from the pre-v2 collision pin):
// two core events with the SAME identity tuple but divergent content now
// derive DIFFERENT EventIDs — the folded policy-payload digest makes the
// id a function of the policy content, so the pre-emption collision
// cannot be constructed anymore (no DB).
func TestW05DerivedIDSeparation(t *testing.T) {
	genuine := w05PreemptPolicy("data-exfil", "enforce", "pol-1", 3, "scan", "exfiltration", "high", "block")
	forged := w05PreemptPolicy("benign-rewrite", "audit", "pol-1", 3, "scan", "exfiltration", "high", "block")
	require.NotEqual(t, genuine, forged, "the two policy records must be different bytes")

	ts := anchorOcc.UnixMilli()
	g := eventpublisher.Event{OrgID: "org-victim", RequestID: "req-77", TS: ts, Policy: genuine, CostStatus: "priced", EstimatedCostUSD: 0.5}
	f := eventpublisher.Event{OrgID: "org-victim", RequestID: "req-77", TS: ts, Policy: forged, CostStatus: "unknown_price"}

	gEvts, err := (CoreAdapter{}).AdaptPublisherEvent(g, anchorOcc)
	require.NoError(t, err)
	fEvts, err := (CoreAdapter{}).AdaptPublisherEvent(f, anchorOcc)
	require.NoError(t, err)
	require.Len(t, gEvts, 1)
	require.Len(t, fEvts, 1)

	assert.NotEqual(t, gEvts[0].EventID, fEvts[0].EventID,
		"same identity tuple, divergent content must derive DIFFERENT ids (pre-emption collision closed)")
	for _, e := range []struct{ id, from string }{{gEvts[0].EventID, "genuine"}, {fEvts[0].EventID, "forged"}} {
		assert.True(t, len(e.id) > len("core2-") && e.id[:len("core2-")] == "core2-",
			"the %s id %q must live in the v2 namespace", e.from, e.id)
	}
	assert.NotEqual(t, string(mustEncode(t, gEvts[0])), string(mustEncode(t, fEvts[0])),
		"…and the documents diverge: Name/Mode/verdict/cost/evidence differ")
	assert.Contains(t, gEvts[0].Summary, "data-exfil")
	assert.Contains(t, fEvts[0].Summary, "benign-rewrite")
}

// TestW05PreemptionEndToEnd is the REAL durable leg, inverted with the
// fix: forged-first inserts, genuine-delayed ALSO inserts (its own id),
// and the victim org's durable trail contains BOTH documents — the
// genuine finding text is never substituted away.
func TestW05PreemptionEndToEnd(t *testing.T) {
	pool := testdb.Postgres(t)
	sink := NewDurableSink(pool)
	require.NoError(t, sink.EnsureSchema(context.Background()))
	ctx := context.Background()

	ts := anchorOcc.UnixMilli()
	genuine := eventpublisher.Event{OrgID: "org-victim", RequestID: "req-78", TS: ts,
		Policy:     w05PreemptPolicy("data-exfil", "enforce", "pol-2", 1, "scan", "exfiltration", "high", "block"),
		CostStatus: "priced", EstimatedCostUSD: 1.25}
	forged := eventpublisher.Event{OrgID: "org-victim", RequestID: "req-78", TS: ts,
		Policy:     w05PreemptPolicy("benign-rewrite", "audit", "pol-2", 1, "scan", "exfiltration", "high", "block"),
		CostStatus: "unknown_price"}

	fEvts, err := (CoreAdapter{}).AdaptPublisherEvent(forged, anchorOcc)
	require.NoError(t, err)
	gEvts, err := (CoreAdapter{}).AdaptPublisherEvent(genuine, anchorOcc)
	require.NoError(t, err)
	require.NotEqual(t, fEvts[0].EventID, gEvts[0].EventID,
		"the fix must give the forgery and the genuine event different ids before any write")

	t.Run("allowed baseline: genuine alone records exactly once", func(t *testing.T) {
		// (Uses a second request id so the baseline cannot disturb the
		// attack leg below.)
		g2 := genuine
		g2.RequestID = "req-78-baseline"
		evts, err := (CoreAdapter{}).AdaptPublisherEvent(g2, anchorOcc)
		require.NoError(t, err)
		status, err := sink.RecordContext(ctx, evts[0])
		require.NoError(t, err)
		assert.Equal(t, DurableInserted, status)
		status, err = sink.RecordContext(ctx, evts[0]) // the legitimate redelivery
		require.NoError(t, err)
		assert.Equal(t, DurableAlreadyPresent, status)
	})

	t.Run("forged-first no longer pre-empts (replay/delay arm, inverted)", func(t *testing.T) {
		status, err := sink.RecordContext(ctx, fEvts[0]) // the forge arrives first
		require.NoError(t, err)
		require.Equal(t, DurableInserted, status)

		status, err = sink.RecordContext(ctx, gEvts[0]) // the genuine event, delayed
		require.NoError(t, err, "an insert is success, never an error")
		assert.Equal(t, DurableInserted, status,
			"the genuine delivery gets its OWN row — no absorption into the forgery's id")

		gDocs := aud01Docs(t, pool, "org-victim", gEvts[0].EventID) //nolint:contextcheck // shared in-package fixture reader: signature is (testing.TB)
		require.Len(t, gDocs, 1, "exactly one row per (org, event_id) — the genuine id's row")
		assert.Contains(t, gDocs[0], "data-exfil",
			"the genuine finding text IS the durable document under its own id")
		fDocs := aud01Docs(t, pool, "org-victim", fEvts[0].EventID) //nolint:contextcheck // shared in-package fixture reader: signature is (testing.TB)
		require.Len(t, fDocs, 1, "the forgery also keeps its own row — first-write-wins immutability unchanged")
		assert.Contains(t, fDocs[0], "benign-rewrite")
		assert.NotContains(t, gDocs[0], "benign-rewrite",
			"no cross-contamination between the two documents")
	})

	t.Run("cross-org forge cannot collide (rights-denial + cross-org arm)", func(t *testing.T) {
		// Same tuple under the ATTACKER's org: org is in the derivation,
		// so the id differs and both orgs keep their own rows.
		attacker := forged
		attacker.OrgID = "org-attacker"
		aEvts, err := (CoreAdapter{}).AdaptPublisherEvent(attacker, anchorOcc)
		require.NoError(t, err)
		require.Len(t, aEvts, 1)
		assert.NotEqual(t, gEvts[0].EventID, aEvts[0].EventID,
			"org-scoped identity: a foreign-org forge derives a different id")

		status, err := sink.RecordContext(ctx, aEvts[0])
		require.NoError(t, err)
		assert.Equal(t, DurableInserted, status, "the attacker's own-org row records normally")

		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE org_id = 'org-attacker'`).Scan(&n))
		assert.Equal(t, 1, n, "exactly one attacker-org row — no shadowing of the victim rows")
	})

	t.Run("policy-less core event adapts to zero events (empty-upstream arm)", func(t *testing.T) {
		none := genuine
		none.Policy = ""
		none.RequestID = "req-78-nosignal"
		evts, err := (CoreAdapter{}).AdaptPublisherEvent(none, anchorOcc)
		require.NoError(t, err)
		assert.Empty(t, evts, "explicit no-signal: nothing to forge from")
	})
}
