package inbox

// E06-P01 W01-C02: unit battery for the Incident model contract — the Go
// mirror of migration 0027's CHECK dictionaries plus the fold invariants.
// No Docker: every arm is decided in-process.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
)

func validIncident() Incident {
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	return Incident{
		OrgID:        uuid.New(),
		GroupKey:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Summary:      "tool invocation denied by policy",
		Severity:     SeverityLow,
		Confidence:   1.0,
		Status:       StatusNew,
		FirstSeen:    base,
		LastSeen:     base.Add(time.Minute),
		EventCount:   2,
		FirstEventID: "evt-first",
		LastEventID:  "evt-last",
		Evidence:     []secevents.EvidenceRef{{Kind: secevents.EvidencePayloadDigest, Digest: digest64()}},
	}
}

func digest64() string {
	var d [64]byte
	for i := range d {
		d[i] = 'a'
	}
	return string(d[:])
}

func TestStoreModelValidateAcceptsValidAndBoundaries(t *testing.T) {
	inc := validIncident()
	require.NoError(t, inc.Validate())

	inc = validIncident()
	inc.Confidence = 0.0 // closed lower bound: "no confidence at all" is legal
	require.NoError(t, inc.Validate(), "confidence [0,1] is a closed range")

	inc = validIncident()
	inc.GroupKey = strings.Repeat("k", MaxGroupKeyLen)
	require.NoError(t, inc.Validate(), "group key at the 128-char bound is legal")

	inc = validIncident()
	inc.Assignee = uuidPtr(uuid.New()) // an assigned incident validates like an unassigned one
	require.NoError(t, inc.Validate())

	inc = validIncident()
	inc.FirstSeen = inc.LastSeen // a single-moment group is legal
	require.NoError(t, inc.Validate())
}

func TestStoreModelValidateRefusesEveryInvalidShape(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Incident)
	}{
		{"nil org", func(i *Incident) { i.OrgID = uuid.Nil }},
		{"empty group key", func(i *Incident) { i.GroupKey = "" }},
		{"oversized group key", func(i *Incident) { i.GroupKey = strings.Repeat("k", MaxGroupKeyLen+1) }},
		{"severity outside dictionary", func(i *Incident) { i.Severity = "critical" }},
		{"empty severity", func(i *Incident) { i.Severity = "" }},
		{"confidence below range", func(i *Incident) { i.Confidence = -0.01 }},
		{"confidence above range", func(i *Incident) { i.Confidence = 1.01 }},
		{"status outside state machine", func(i *Incident) { i.Status = "closed" }},
		{"empty first event id", func(i *Incident) { i.FirstEventID = "" }},
		{"oversized last event id", func(i *Incident) { i.LastEventID = strings.Repeat("e", MaxEventIDLen+1) }},
		{"zero event count", func(i *Incident) { i.EventCount = 0 }},
		{"first seen after last seen", func(i *Incident) { i.FirstSeen = i.LastSeen.Add(time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inc := validIncident()
			tc.mut(&inc)
			assert.ErrorIs(t, inc.Validate(), ErrInvalidIncident)
		})
	}
}

func TestStoreModelDictionariesMatchTheMigrationContract(t *testing.T) {
	// The Go dictionaries must cover exactly the 0027 CHECK arrays: any
	// drift (a state or severity level added here but not in the
	// migration, or vice versa) breaks at this pin, not at runtime.
	assert.ElementsMatch(t,
		[]string{SeverityLow, SeverityMedium, SeverityHigh},
		[]string{"low", "medium", "high"})
	assert.ElementsMatch(t,
		[]string{StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusDismissed},
		[]string{"new", "acknowledged", "in_progress", "resolved", "dismissed"})
}

func uuidPtr(u uuid.UUID) *uuid.UUID { return &u }
