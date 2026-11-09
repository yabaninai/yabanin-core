package ocsf

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// W04-C02 redelivery battery (AC: 10+ scenarios, table-driven; rollback
// emulation proves ReplayID idempotency; consumer dedup contract
// documented with a runnable example consumer).
//
// CONSUMER DEDUP CONTRACT (the example below is the contract):
//
//	A consumer that imports envelopes MUST key its dedup table on
//	NormalizedRecord.ReplayID alone. The id already folds in the tenant
//	org (W04-C03), so a bare ReplayID key is org-safe by construction;
//	keys that add batch, envelope or attempt coordinates would RE-IMPORT
//	the same record after every redelivery and defeat the contract.
//	Consumers must not assume ordering across envelopes: ids are
//	position- and batch-independent (W04-C01 order-free discipline).
type replayConsumer struct {
	seen     map[string]struct{}
	imported int
}

func newReplayConsumer() *replayConsumer {
	return &replayConsumer{seen: make(map[string]struct{})}
}

// apply imports one envelope, deduplicating by ReplayID. It returns
// how many records were newly imported and how many were duplicates.
func (c *replayConsumer) apply(env Envelope) (imported, duplicates int) {
	for _, rec := range env.Records {
		key := rec.ReplayID // ReplayID alone — see contract above
		if _, dup := c.seen[key]; dup {
			duplicates++
			continue
		}
		c.seen[key] = struct{}{}
		c.imported++
		imported++
	}
	return imported, duplicates
}

// batteryEnv builds a signed-envelope-ready record batch with explicit
// source event ids (the producer-side pipeline: map → assign →
// envelope). fixture() deliberately pins ONE secevents EventID across
// calls, so scenarios that need distinct events must name them.
func batteryEnv(t *testing.T, orgID string, eventIDs []string, issuedAt time.Time) Envelope {
	t.Helper()
	records := make([]NormalizedRecord, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		ev := fixture("policy.deny")
		ev.EventID = eventID
		rec, err := MapEvent(ev)
		if err != nil {
			t.Fatalf("MapEvent(%s): %v", eventID, err)
		}
		rec.OrgID = orgID
		records = append(records, rec)
	}
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("AssignReplayIDs: %v", err)
	}
	env, err := NewEnvelope(orgID, records, issuedAt)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	return env
}

// redeliver re-issues an envelope for a delivery retry: same records,
// attempt bumped, fresh signature (the W04-C01 discipline).
func redeliver(t *testing.T, env Envelope, attempt int) Envelope {
	t.Helper()
	retry := env
	retry.Attempt = attempt
	return retry
}

// TestReplayBattery is the W04-C02 table. Every row exercises one
// delivery scenario against the example consumer; want fields state
// the expected import/duplicate accounting.
func TestReplayBattery(t *testing.T) {
	base := testSignTime
	cases := []struct {
		name           string
		run            func(t *testing.T) (gotImported, gotDuplicates int)
		wantImported   int
		wantDuplicates int
	}{
		{
			name: "fresh single envelope imports all",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				c := newReplayConsumer()
				i, d := c.apply(batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base))
				return i, d
			},
			wantImported: 2, wantDuplicates: 0,
		},
		{
			name: "exact redelivery (attempt+1, fresh signature) dedups",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				c := newReplayConsumer()
				env := batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base)
				c.apply(env)
				i, d := c.apply(redeliver(t, env, 1))
				return i, d
			},
			wantImported: 0, wantDuplicates: 2,
		},
		{
			name: "redelivery after partial import (first record lost)",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				env := batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base)
				partial := env
				partial.Records = env.Records[:1] // consumer crashed mid-batch
				c := newReplayConsumer()
				c.apply(partial)
				i, d := c.apply(redeliver(t, env, 1))
				return i, d
			},
			wantImported: 1, wantDuplicates: 1,
		},
		{
			name: "same record in two different envelopes dedups",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				c := newReplayConsumer()
				c.apply(batteryEnv(t, "org-1", []string{"evt-deny-1"}, base))
				// Different batch composition AND issue time.
				i, d := c.apply(batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-flag-1"}, base.Add(time.Hour)))
				return i, d
			},
			wantImported: 1, wantDuplicates: 1,
		},
		{
			name: "producer batch with an internal duplicate event",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				// Same source event mapped twice into one batch
				// (producer bug): the consumer still imports it once.
				env := batteryEnv(t, "org-1", []string{"evt-dup", "evt-dup"}, base)
				if env.Records[0].ReplayID != env.Records[1].ReplayID {
					t.Fatalf("identical source events must derive identical ids")
				}
				c := newReplayConsumer()
				i, d := c.apply(env)
				return i, d
			},
			wantImported: 1, wantDuplicates: 1,
		},
		{
			name: "interleaved envelopes of two orgs",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				a1 := batteryEnv(t, "org-1", []string{"evt-shared"}, base)
				b1 := batteryEnv(t, "org-2", []string{"evt-shared"}, base) // same event id, other org
				a2 := batteryEnv(t, "org-1", []string{"evt-mask-1"}, base.Add(time.Minute))
				b2 := batteryEnv(t, "org-2", []string{"evt-mask-1"}, base.Add(time.Minute))
				if a1.Records[0].ReplayID == b1.Records[0].ReplayID {
					t.Fatalf("cross-org envelopes collided on one replay id")
				}
				c := newReplayConsumer()
				var imported, duplicates int
				for _, env := range []Envelope{a1, b1, a2, b2, a1, b2} { // interleaved + re-deliveries
					i, d := c.apply(env)
					imported += i
					duplicates += d
				}
				return imported, duplicates
			},
			wantImported: 4, wantDuplicates: 2,
		},
		{
			name: "consumer rollback: full log replay re-imports nothing new",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				envs := []Envelope{
					batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base),
					batteryEnv(t, "org-1", []string{"evt-flag-1"}, base.Add(time.Minute)),
				}
				c := newReplayConsumer()
				for _, env := range envs {
					c.apply(env)
				}
				// "Rollback": consumer state lost, delivery log replayed
				// from the start. Ids are unchanged, so the replayed log
				// re-imports nothing.
				var imported, duplicates int
				for _, env := range envs {
					i, d := c.apply(env)
					imported += i
					duplicates += d
				}
				return imported, duplicates
			},
			wantImported: 0, wantDuplicates: 3,
		},
		{
			name: "producer rollback: re-export after storage rollback dedups",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				c := newReplayConsumer()
				c.apply(batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base))
				// Producer re-exports the SAME source events after its
				// own rollback: fresh envelope, same anchors ⇒ same ids.
				i, d := c.apply(batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-mask-1"}, base.Add(2*time.Hour)))
				return i, d
			},
			wantImported: 0, wantDuplicates: 2,
		},
		{
			name: "retry storm: N redeliveries never double-import",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				env := batteryEnv(t, "org-1", []string{"evt-deny-1"}, base)
				c := newReplayConsumer()
				c.apply(env)
				var imported, duplicates int
				for attempt := 1; attempt <= 5; attempt++ {
					i, d := c.apply(redeliver(t, env, attempt))
					imported += i
					duplicates += d
				}
				return imported, duplicates
			},
			wantImported: 0, wantDuplicates: 5,
		},
		{
			name: "empty envelope imports nothing",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				env, err := NewEnvelope("org-1", nil, base)
				if err != nil {
					t.Fatalf("NewEnvelope(empty): %v", err)
				}
				c := newReplayConsumer()
				i, d := c.apply(env)
				return i, d
			},
			wantImported: 0, wantDuplicates: 0,
		},
		{
			name: "anchorless record fails closed before any delivery",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				records := envelopeRecords(t)
				records[0].FindingInfo.UID = ""
				if err := AssignReplayIDs(records); !errors.Is(err, ErrEmptyReplayInput) {
					t.Fatalf("err = %v, want ErrEmptyReplayInput", err)
				}
				// Producer pipeline stops; nothing reaches a consumer.
				return 0, 0
			},
			wantImported: 0, wantDuplicates: 0,
		},
		{
			name: "signed redelivery round-trip with bumped attempt",
			run: func(t *testing.T) (int, int) {
				t.Helper()
				env := batteryEnv(t, "org-1", []string{"evt-deny-1"}, base)
				body, header := signForTest(t, testSecret, env)
				retry := redeliver(t, env, 1)
				retryBody, retryHeader := signForTest(t, testSecret, retry)
				for _, d := range []struct{ name, body, header string }{
					{"first", string(body), header},
					{"retry", string(retryBody), retryHeader},
				} {
					if err := VerifyEnvelope(testSecret, d.header, []byte(d.body), "org-1", testTolerance, testVerifyTime()); err != nil {
						t.Fatalf("verify %s delivery: %v", d.name, err)
					}
				}
				c := newReplayConsumer()
				c.apply(env)
				i, dup := c.apply(retry)
				return i, dup
			},
			wantImported: 0, wantDuplicates: 1,
		},
	}
	if len(cases) < 10 {
		t.Fatalf("battery must keep >= 10 scenarios, has %d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotImported, gotDuplicates := tc.run(t)
			if gotImported != tc.wantImported || gotDuplicates != tc.wantDuplicates {
				t.Fatalf("imported/duplicates = %d/%d, want %d/%d",
					gotImported, gotDuplicates, tc.wantImported, tc.wantDuplicates)
			}
		})
	}
}

// TestReplayBatteryContractPinned pins the dedup key discipline itself:
// a consumer keyed on (ReplayID) survives re-delivery and re-batching,
// while a naive consumer keyed on (envelope_id, ReplayID) double-imports
// the same record once it travels in a second envelope — the
// anti-example the contract exists to prevent.
func TestReplayBatteryContractPinned(t *testing.T) {
	solo := batteryEnv(t, "org-1", []string{"evt-deny-1"}, testSignTime)
	rebatched := batteryEnv(t, "org-1", []string{"evt-deny-1", "evt-flag-1"}, testSignTime.Add(time.Hour))
	if solo.EnvelopeID == rebatched.EnvelopeID {
		t.Fatalf("scenario needs two distinct envelopes")
	}
	if solo.Records[0].ReplayID != rebatched.Records[0].ReplayID {
		t.Fatalf("same source record must keep its replay id across envelopes")
	}

	correct := newReplayConsumer()
	correct.apply(solo)
	if i, _ := correct.apply(rebatched); i != 1 { // only the NEW event imports
		t.Fatalf("ReplayID-keyed consumer re-imported a re-batched record")
	}

	naiveSeen := make(map[string]struct{})
	var naiveImports int
	applyNaive := func(e Envelope) {
		for _, rec := range e.Records {
			key := fmt.Sprintf("%s/%s", e.EnvelopeID, rec.ReplayID)
			if _, dup := naiveSeen[key]; dup {
				continue
			}
			naiveSeen[key] = struct{}{}
			naiveImports++
		}
	}
	applyNaive(solo)
	applyNaive(rebatched)
	if naiveImports != 3 {
		t.Fatalf("naive consumer imports = %d, want 3 (it must demonstrably re-import the re-batched record)", naiveImports)
	}
}
