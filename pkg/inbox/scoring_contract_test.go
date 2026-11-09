package inbox

// E06-P01 W03-C03: contract/drift guard for the W03-C01 scoring law.
//
// Three guards, deliberately beyond the unit battery (scoring_test.go):
//
//  1. Adapter realism: a REAL CoreAdapter feed must score — the summary
//     token is the only v1 carrier of the finding verdict, so an adapter
//     format change must turn this file red, not silently downgrade every
//     fold to "no verdict".
//  2. Law anchors: the reviewed numeric anchors re-pinned here, so a
//     semantic change that ships with an "updated" unit battery still
//     trips the contract file.
//  3. Artifact presence: the W03-C03 deliverable document must exist and
//     carry the law's markers.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/secevents"
)

// Compile-time exported-surface pin: the law's names are part of the
// package contract (the future wiring card consumes them).
var (
	_ func(...string) (string, error)             = Escalate
	_ func(secevents.Event) (string, bool, error) = EventVerdict
	_ func([]secevents.Event) (Score, error)      = ScoreEvents
	_                                             = ErrNoEvents
	_                                             = ErrNoVerdict
	_                                             = ErrUnreadableVerdict
)

// TestScoringContractAdapterFeedIsScoreable pins the carrier end-to-end:
// a genuine policy-decision record adapted by the production adapter must
// yield events the scoring law can verdict and score.
func TestScoringContractAdapterFeedIsScoreable(t *testing.T) {
	record := `[{"policy_id":"p-1","name":"Data exfil guard","version":3,"mode":"enforcing","verdict":"block","findings":[` +
		`{"step":"tool-call","category":"exfiltration","severity":"high","action":"deny"},` +
		`{"step":"tool-call","category":"prompt-injection","severity":"medium","action":"flag"}]}]`
	ev := eventpublisher.Event{
		EventType:  "policy.decision",
		Source:     "gateway",
		TS:         1762602000000,
		RequestID:  "req-1",
		SessionID:  "sess-1",
		Payload:    "redacted",
		OrgID:      "11111111-1111-1111-1111-111111111111",
		CostStatus: "no_usage",
		PromptHash: strings.Repeat("a", 64),
		Policy:     record,
		StatusCode: 200,
		DurationMs: 12,
	}
	events, err := secevents.CoreAdapter{}.AdaptPublisherEvent(ev, time.UnixMilli(ev.TS).UTC())
	require.NoError(t, err)
	require.Len(t, events, 2, "one finding event per finding")

	// Per-event verdict recovery: exactly the record's words.
	words := map[string]bool{}
	for _, e := range events {
		sev, ok, err := EventVerdict(e)
		require.NoError(t, err, "adapter summary must stay verdict-readable")
		require.True(t, ok)
		words[sev] = true
	}
	require.True(t, words[SeverityHigh] && words[SeverityMedium], "verdicts = %v", words)

	// Whole-fold scoring: escalation max(high, medium) and the n=2 anchor.
	score, err := ScoreEvents(events)
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, score.Severity, "escalation = max")
	require.InDelta(t, 0.76, score.Confidence, 1e-12,
		"2 distinct complete events: 0.6 + 0.3*(1/5) + 0.1")
}

// TestScoringContractLawAnchors re-pins the REVIEWED anchor values. These
// intentionally duplicate scoring_test.go: the contract file is the
// reviewed artifact, so changing the law means changing this file in the
// open, not just the unit battery.
func TestScoringContractLawAnchors(t *testing.T) {
	one, err := ScoreEvents([]secevents.Event{scFinding("c-1", SeverityLow, 1)})
	require.NoError(t, err)
	require.Equal(t, SeverityLow, one.Severity)
	require.InDelta(t, 0.7, one.Confidence, 1e-12, "single complete event anchor")

	nine := make([]secevents.Event, 0, 9)
	for i := 0; i < 9; i++ {
		nine = append(nine, scFinding(strings.Repeat("c", 63)+string(rune('0'+i)), SeverityMedium, 1))
	}
	got, err := ScoreEvents(nine)
	require.NoError(t, err)
	require.Equal(t, SeverityMedium, got.Severity)
	require.InDelta(t, 0.9, got.Confidence, 1e-12, "nine distinct complete events anchor")

	dup, err := ScoreEvents([]secevents.Event{scFinding("c-dup", SeverityHigh, 1), scFinding("c-dup", SeverityHigh, 1)})
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, dup.Severity)
	require.InDelta(t, 0.71, dup.Confidence, 1e-12, "duplicate-laden fold anchor")

	esc, err := Escalate(SeverityLow, SeverityMedium, SeverityHigh)
	require.NoError(t, err)
	require.Equal(t, SeverityHigh, esc, "escalation = max anchor")

	_, err = ScoreEvents([]secevents.Event{scFinding("c-none", "", 1)})
	require.ErrorIs(t, err, ErrNoVerdict, "the law never invents a severity")
}

// TestScoringContractArtifactDocumentsTheLaw guards the W03-C03 deliverable
// document: it must exist in the tree and carry the law's markers (loose
// markers — content churn is fine, losing the law's statement is not).
func TestScoringContractArtifactDocumentsTheLaw(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "artifacts", "enterprise-beta", "E06-P01",
		"W03-SEVERITY-CONFIDENCE-2026-11-07.md"))
	require.NoError(t, err, "the W03-C03 artifact must exist in the tree")
	doc := string(b)
	for _, marker := range []string{
		"escalation = max",
		"low|medium|high",
		"0.6",
		"0.3",
		"0.1",
		"completeness",
		"corroboration",
		"dedup certainty",
		"independence",
		"0.7",
		"0.76",
		"ErrNoVerdict",
	} {
		require.Contains(t, doc, marker, "artifact must state the law marker %q", marker)
	}
}
