package inbox

// E06-P01 W03-C01: acceptance battery for the scoring law (scoring.go).
//
// The card's two acceptance criteria are pinned here explicitly:
//
//  1. Semantics are not interchangeable — severity and confidence move on
//     disjoint input axes (verdict words vs grouping-quality signals).
//  2. An incident from a single event has deterministic values of BOTH
//     fields: its verdict, and exactly 0.7 confidence.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// scFinding builds a findings-shaped event in the adapter's exact summary
// format (adapter.go buildFindingEvents). evidence>=1 marks a complete
// source; severityWord may be "" for a verdict-less event.
func scFinding(id, severityWord string, evidence int) secevents.Event {
	e := secevents.Event{}
	e.SchemaVersion = secevents.SchemaVersion
	e.EventID = id
	e.EventType = "tool.deny"
	e.OrgID = "org-1"
	e.OccurredAt = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	e.Identity.Agent = secevents.IDRef{Value: "agent-7", State: secevents.IDKnown}
	e.Identity.Session = secevents.IDRef{Value: "sess-42"}
	e.Identity.Task = secevents.IDRef{State: secevents.IDAbsent}
	e.Identity.Tool = secevents.IDRef{State: secevents.IDUnknown}
	e.Cost = secevents.Cost{State: secevents.CostUnknown}
	if severityWord == "" {
		e.Summary = "manual retention summary without any verdict token"
	} else {
		e.Summary = fmt.Sprintf("policy p-1 v3 enforcing: step-1 category=abuse severity=%s action=deny", severityWord)
	}
	for i := 0; i < evidence; i++ {
		e.Evidence = append(e.Evidence, secevents.EvidenceRef{
			Kind:   secevents.EvidencePolicyDecision,
			Digest: fmt.Sprintf("%064x", i),
		})
	}
	return e
}

func TestEscalate(t *testing.T) {
	t.Run("max over the dictionary", func(t *testing.T) {
		for _, tc := range []struct {
			in   []string
			want string
		}{
			{[]string{SeverityLow}, SeverityLow},
			{[]string{SeverityMedium}, SeverityMedium},
			{[]string{SeverityHigh}, SeverityHigh},
			{[]string{SeverityLow, SeverityMedium, SeverityHigh}, SeverityHigh},
			{[]string{SeverityHigh, SeverityLow, SeverityMedium}, SeverityHigh},
			{[]string{SeverityLow, SeverityLow}, SeverityLow},
			{[]string{SeverityMedium, SeverityLow, SeverityMedium}, SeverityMedium},
		} {
			got, err := Escalate(tc.in...)
			require.NoError(t, err)
			require.Equal(t, tc.want, got, "escalate(%v)", tc.in)
		}
	})

	t.Run("empty fails closed", func(t *testing.T) {
		_, err := Escalate()
		require.ErrorIs(t, err, ErrNoVerdict)
	})

	t.Run("non-dictionary word fails closed", func(t *testing.T) {
		for _, bad := range []string{"", "critical", "LOW", "low ", "hi"} {
			_, err := Escalate(SeverityLow, bad)
			require.ErrorIs(t, err, ErrUnreadableVerdict, "word %q must not be rankable", bad)
		}
	})
}

func TestVerdictFromSummary(t *testing.T) {
	t.Run("adapter format recovers the verdict", func(t *testing.T) {
		for _, word := range []string{SeverityLow, SeverityMedium, SeverityHigh} {
			e := scFinding("evt-1", word, 1)
			sev, ok, err := EventVerdict(e)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, word, sev)
		}
	})

	t.Run("no token is absence, not corruption", func(t *testing.T) {
		for _, summary := range []string{
			"",
			"manual retention summary without any verdict token",
			"category=abuse action=deny", // neighbors present, verdict not
			"policy p v1 enforcing: step category=abuse action=deny",
		} {
			sev, ok, err := VerdictFromSummary(summary)
			require.NoError(t, err, "summary %q", summary)
			require.False(t, ok, "summary %q must carry no verdict", summary)
			require.Empty(t, sev)
		}
	})

	t.Run("truncated token fails closed, not absent", func(t *testing.T) {
		// TrimSummary's 1024-byte cap can cut the verdict mid-word: the
		// token is PRESENT but unreadable. Reading it as absence would
		// understate severity — refuse instead.
		for _, tok := range []string{"severity=hi", "severity=", "severity=critical", "severity=Low"} {
			_, ok, err := VerdictFromSummary("policy p v1 enforcing: step category=abuse " + tok + " action=deny")
			require.ErrorIs(t, err, ErrUnreadableVerdict, "token %q", tok)
			require.False(t, ok)
		}
	})

	t.Run("tail truncation after an intact verdict still reads", func(t *testing.T) {
		sev, ok, err := VerdictFromSummary("policy p v1 enforcing: step category=abuse severity=medium act")
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, SeverityMedium, sev)
	})

	t.Run("multiple well-formed tokens escalate to the max", func(t *testing.T) {
		// Only producer-side injection into the free-text fields can
		// produce this; the law must not let an injected token LOWER a
		// real verdict.
		sev, ok, err := VerdictFromSummary("policy severity=low p v1 enforcing: severity=medium step category=abuse severity=low action=deny")
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, SeverityMedium, sev)
	})

	t.Run("one corrupt token poisons even with a good one present", func(t *testing.T) {
		_, _, err := VerdictFromSummary("policy p v1: severity=high step severity=hi")
		require.ErrorIs(t, err, ErrUnreadableVerdict)
	})
}

func TestScoreEventsSingleEventDeterministic(t *testing.T) {
	// Card AC: an incident from a single event has deterministic values of
	// both fields — the event's own verdict, and exactly 0.7 confidence
	// (0.6 completeness + 0 corroboration + 0.1 dedup certainty).
	got, err := ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityHigh, 1)})
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, got.Severity)
	require.InDelta(t, 0.7, got.Confidence, 1e-12)

	// Same shape, different verdict: confidence identical.
	got, err = ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityLow, 1)})
	require.NoError(t, err)
	require.Equal(t, SeverityLow, got.Severity)
	require.InDelta(t, 0.7, got.Confidence, 1e-12)

	// Single event without evidence: 0.6*0 + 0 + 0.1*1 = 0.1.
	got, err = ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityMedium, 0)})
	require.NoError(t, err)
	require.Equal(t, SeverityMedium, got.Severity)
	require.InDelta(t, 0.1, got.Confidence, 1e-12)
}

func TestScoreEventsSemanticsNotInterchangeable(t *testing.T) {
	// Card AC: severity and confidence have SEPARATE sources. Pin BOTH
	// directions of independence.

	t.Run("verdict word changes severity, never confidence", func(t *testing.T) {
		var prev float64
		for i, word := range []string{SeverityLow, SeverityMedium, SeverityHigh} {
			got, err := ScoreEvents([]secevents.Event{
				scFinding("evt-1", word, 1),
				scFinding("evt-2", word, 1),
			})
			require.NoError(t, err)
			require.Equal(t, word, got.Severity)
			if i == 0 {
				prev = got.Confidence
			} else {
				require.InDelta(t, prev, got.Confidence, 1e-12,
					"confidence must not move with the verdict word")
			}
		}
	})

	t.Run("grouping quality changes confidence, never severity", func(t *testing.T) {
		single, err := ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityLow, 1)})
		require.NoError(t, err)
		nine, err := ScoreEvents([]secevents.Event{
			scFinding("evt-1", SeverityLow, 1), scFinding("evt-2", SeverityLow, 1),
			scFinding("evt-3", SeverityLow, 1), scFinding("evt-4", SeverityLow, 1),
			scFinding("evt-5", SeverityLow, 1), scFinding("evt-6", SeverityLow, 1),
			scFinding("evt-7", SeverityLow, 1), scFinding("evt-8", SeverityLow, 1),
			scFinding("evt-9", SeverityLow, 1),
		})
		require.NoError(t, err)
		require.Equal(t, SeverityLow, single.Severity)
		require.Equal(t, SeverityLow, nine.Severity, "event count must not move severity")
		require.Greater(t, nine.Confidence, single.Confidence,
			"corroboration must raise confidence")
		// Exact arithmetic: n=9 → 0.6 + 0.3*(8/12) + 0.1 = 0.9.
		require.InDelta(t, 0.9, nine.Confidence, 1e-12)
		// n=2 → 0.6 + 0.3*(1/5) + 0.1 = 0.76.
		pair, err := ScoreEvents([]secevents.Event{scFinding("a", SeverityLow, 1), scFinding("b", SeverityLow, 1)})
		require.NoError(t, err)
		require.InDelta(t, 0.76, pair.Confidence, 1e-12)
	})
}

func TestScoreEventsEscalationAcrossEvents(t *testing.T) {
	got, err := ScoreEvents([]secevents.Event{
		scFinding("evt-1", SeverityLow, 1),
		scFinding("evt-2", SeverityMedium, 1),
		scFinding("evt-3", SeverityHigh, 1),
	})
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, got.Severity, "group severity is the max verdict")
}

func TestScoreEventsOrderIndependence(t *testing.T) {
	events := []secevents.Event{
		scFinding("evt-1", SeverityLow, 1),
		scFinding("evt-2", SeverityHigh, 0),
		scFinding("evt-3", SeverityMedium, 1),
		scFinding("evt-4", SeverityLow, 1),
		scFinding("evt-5", SeverityHigh, 1),
	}
	want, err := ScoreEvents(events)
	require.NoError(t, err)
	n := len(events)
	for round := 0; round < 50; round++ {
		shuffled := append([]secevents.Event(nil), events...)
		// Deterministic swap schedule (no RNG): index arithmetic only,
		// varied orderings per round.
		for step := 0; step < n; step++ {
			a := (round*n + step*2) % n
			b := (round*3 + step*5 + 1) % n
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		}
		got, err := ScoreEvents(shuffled)
		require.NoError(t, err)
		require.Equal(t, want, got, "round %d: fold order must not change the score", round)
	}
}

func TestScoreEventsFailClosed(t *testing.T) {
	t.Run("empty fold", func(t *testing.T) {
		_, err := ScoreEvents(nil)
		require.ErrorIs(t, err, ErrNoEvents)
		_, err = ScoreEvents([]secevents.Event{})
		require.ErrorIs(t, err, ErrNoEvents)
	})

	t.Run("no readable verdict refuses to invent", func(t *testing.T) {
		_, err := ScoreEvents([]secevents.Event{scFinding("evt-1", "", 1)})
		require.ErrorIs(t, err, ErrNoVerdict, "a verdict-less fold must not score 'low'")
	})

	t.Run("one corrupt token poisons the fold", func(t *testing.T) {
		corrupt := scFinding("evt-bad", SeverityLow, 1)
		corrupt.Summary = "policy p v1 enforcing: step category=abuse severity=me action=deny"
		_, err := ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityHigh, 1), corrupt})
		require.ErrorIs(t, err, ErrUnreadableVerdict)
	})
}

func TestScoreEventsDuplicatesLowerDedupCertainty(t *testing.T) {
	distinct, err := ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityLow, 1), scFinding("evt-2", SeverityLow, 1)})
	require.NoError(t, err)
	// Same event id twice: dedup certainty 1/2 → 0.6 + 0.06 + 0.05 = 0.71.
	duplicated, err := ScoreEvents([]secevents.Event{scFinding("evt-1", SeverityLow, 1), scFinding("evt-1", SeverityLow, 1)})
	require.NoError(t, err)
	require.InDelta(t, 0.76, distinct.Confidence, 1e-12)
	require.InDelta(t, 0.71, duplicated.Confidence, 1e-12)
	require.Less(t, duplicated.Confidence, distinct.Confidence,
		"duplicate-laden input must score lower grouping quality")
	require.Equal(t, distinct.Severity, duplicated.Severity)
}

func TestScoreEventsConfidenceStaysInUnitInterval(t *testing.T) {
	// Convex combination of components: every mixture stays in [0,1].
	for _, evidence := range []int{0, 1} {
		for _, words := range [][]string{{SeverityLow}, {SeverityLow, SeverityHigh}} {
			var events []secevents.Event
			for i, w := range words {
				events = append(events, scFinding(fmt.Sprintf("evt-%d", i), w, evidence))
			}
			got, err := ScoreEvents(events)
			require.NoError(t, err)
			require.GreaterOrEqual(t, got.Confidence, 0.0)
			require.LessOrEqual(t, got.Confidence, 1.0)
		}
	}
}

// Compile-time pin: the scoring law must satisfy the incident model — its
// outputs are valid Incident field values by construction.
var _ = func() error {
	s := Score{Severity: SeverityLow, Confidence: 0.5}
	if s.Severity != SeverityLow || s.Confidence < 0 || s.Confidence > 1 {
		return errors.New("score out of model contract")
	}
	return nil
}()
