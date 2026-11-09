package inbox

// E06-P01 W04-C01: acceptance battery for the operator state machine
// (status.go).
//
//   - the FULL transition matrix: every legal edge exactly once (forward
//     walk + both reopens + all self-loops), every illegal edge refused
//     with ErrInvalidTransition;
//   - ApplyOperatorPatch on the real stand under the real yabanin_app
//     role: lifecycle walk, reopen history preservation, no-op law
//     (updated_at does not move), assignee set/clear, operator state
//     surviving later folds, org scoping (foreign org = not found), and
//     the bypass probe's both branches (app pin / superuser no-pin).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
)

var allStates = []string{StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusDismissed}

// legalEdges is the reviewed edge SET (self-loops implicit — they are the
// idempotency law, asserted separately).
var legalEdges = map[[2]string]bool{
	{StatusNew, StatusAcknowledged}:        true,
	{StatusAcknowledged, StatusInProgress}: true,
	{StatusInProgress, StatusResolved}:     true,
	{StatusInProgress, StatusDismissed}:    true,
	{StatusResolved, StatusAcknowledged}:   true, // reopen
	{StatusDismissed, StatusAcknowledged}:  true, // reopen
}

func TestValidateTransitionFullMatrix(t *testing.T) {
	legalCount := 0
	for _, from := range allStates {
		for _, to := range allStates {
			err := ValidateTransition(from, to)
			if from == to {
				require.NoError(t, err, "self-loop %s→%s: the idempotency law", from, to)
				legalCount++
				continue
			}
			if legalEdges[[2]string{from, to}] {
				require.NoError(t, err, "legal edge %s→%s", from, to)
				legalCount++
				continue
			}
			require.ErrorIs(t, err, ErrInvalidTransition, "illegal edge %s→%s must be refused", from, to)
		}
	}
	// 5 self-loops + 6 legal edges (in_progress has two targets).
	require.Equal(t, 11, legalCount, "exactly 11 legal cells of the 25")

	t.Run("in_progress also reaches dismissed", func(t *testing.T) {
		require.NoError(t, ValidateTransition(StatusInProgress, StatusDismissed))
	})

	t.Run("unknown states are refused", func(t *testing.T) {
		for _, pair := range [][2]string{{"open", StatusNew}, {StatusNew, "closed"}, {"", ""}, {"resolved", "RESOLVED"}} {
			require.ErrorIs(t, ValidateTransition(pair[0], pair[1]), ErrInvalidTransition, "%s→%s", pair[0], pair[1])
		}
	})
}

func TestOperatorPatchValidationBeforeAnyStatement(t *testing.T) {
	t.Run("nil org is refused before any SQL", func(t *testing.T) {
		st := NewStore(&refusingDB{t: t})
		status := StatusAcknowledged
		_, found, err := st.ApplyOperatorPatch(t.Context(), uuid.Nil, uuid.New(), OperatorPatch{Status: &status})
		require.ErrorIs(t, err, ErrStoreOrgRequired)
		require.False(t, found)
	})

	t.Run("unknown status word is refused before any SQL", func(t *testing.T) {
		st := NewStore(&refusingDB{t: t})
		bad := "teleported"
		_, found, err := st.ApplyOperatorPatch(t.Context(), uuid.New(), uuid.New(), OperatorPatch{Status: &bad})
		require.ErrorIs(t, err, ErrInvalidTransition)
		require.False(t, found)
	})
}

// stSeed folds one real event into a fresh incident (through the
// production upsert) and returns it.
func stSeed(t *testing.T, ctx context.Context, store *Store, org uuid.UUID, occurred time.Time) Incident {
	t.Helper()
	e := siEvent(org.String(), "st-evt-"+org.String()[:8], "status battery", occurred,
		secevents.EvidenceRef{Kind: secevents.EvidencePayloadDigest, Digest: validDigest(org.String())})
	inc, err := store.Upsert(ctx, org, IncidentDraft{
		GroupKey:   "st-key-" + org.String()[:8],
		Summary:    "status battery",
		Severity:   SeverityMedium,
		Confidence: 0.7,
		OccurredAt: occurred,
		EventID:    e.EventID,
		Evidence:   e.Evidence,
	})
	require.NoError(t, err)
	return inc
}

func TestApplyOperatorPatchLifecycle(t *testing.T) {
	su, app, orgA, orgB := siFixture(t)
	ctx := context.Background()
	occurred := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	store := NewStore(app) // real yabanin_app role: GUC pin path
	inc := stSeed(t, ctx, store, orgA, occurred)

	setStatus := func(s string) OperatorPatch { return OperatorPatch{Status: &s} }

	patch := func(patch OperatorPatch) (Incident, bool, error) {
		return store.ApplyOperatorPatch(ctx, orgA, inc.ID, patch)
	}

	t.Run("full legal walk with reopens", func(t *testing.T) {
		for _, to := range []string{StatusAcknowledged, StatusInProgress, StatusResolved,
			StatusAcknowledged /*reopen*/, StatusInProgress, StatusDismissed,
			StatusAcknowledged /*reopen again*/} {
			got, found, err := patch(setStatus(to))
			require.NoError(t, err, "transition to %s", to)
			require.True(t, found)
			require.Equal(t, to, got.Status)
		}
	})

	t.Run("reopen never loses history", func(t *testing.T) {
		got, found, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, int64(1), got.EventCount, "operator transitions never touch counts")
		assert.Equal(t, inc.FirstEventID, got.FirstEventID)
		assert.Equal(t, inc.LastEventID, got.LastEventID)
		assert.True(t, got.FirstSeen.Equal(inc.FirstSeen))
		assert.True(t, got.LastSeen.Equal(inc.LastSeen))
		assert.Equal(t, inc.GroupKey, got.GroupKey)
		assert.Equal(t, inc.Summary, got.Summary)
	})

	t.Run("illegal transition is refused and changes nothing", func(t *testing.T) {
		before, found, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, StatusAcknowledged, before.Status)

		_, _, err = patch(setStatus(StatusResolved)) // acknowledged → resolved: illegal
		require.ErrorIs(t, err, ErrInvalidTransition)

		after, found, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, before.Status, after.Status)
		assert.True(t, after.UpdatedAt.Equal(before.UpdatedAt), "a refused patch must not bump updated_at")
	})

	t.Run("same-state self-loop is a no-op that does not move updated_at", func(t *testing.T) {
		before, found, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		require.True(t, found)

		got, found, err := patch(setStatus(before.Status))
		require.NoError(t, err, "self-loop is legal (idempotent PATCH)")
		require.True(t, found)
		assert.Equal(t, before.Status, got.Status)
		assert.True(t, got.UpdatedAt.Equal(before.UpdatedAt), "no-op must not move updated_at")
		assert.True(t, got.CreatedAt.Equal(before.CreatedAt))
		assert.Equal(t, before.EventCount, got.EventCount)
	})

	t.Run("assignee set and clear", func(t *testing.T) {
		member := uuid.New()
		got, found, err := patch(OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		require.NotNil(t, got.Assignee)
		assert.Equal(t, member, *got.Assignee)

		got, found, err = patch(OperatorPatch{Assignee: uuid.Nil, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		assert.Nil(t, got.Assignee, "uuid.Nil in a set patch clears the assignee")
	})

	t.Run("assignee re-set is a no-op", func(t *testing.T) {
		member := uuid.New()
		_, found, err := patch(OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		before, _, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)

		got, found, err := patch(OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		assert.True(t, got.UpdatedAt.Equal(before.UpdatedAt), "equal-value assignee patch is a no-op")
	})

	t.Run("operator state survives a later fold", func(t *testing.T) {
		member := uuid.New()
		_, found, err := patch(OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		_, found, err = patch(setStatus(StatusInProgress))
		require.NoError(t, err)
		require.True(t, found)

		e := siEvent(orgA.String(), "st-evt-later-"+orgA.String()[:8], "later fold", occurred.Add(time.Hour),
			secevents.EvidenceRef{Kind: secevents.EvidencePayloadDigest, Digest: validDigest("later")})
		_, err = store.Upsert(ctx, orgA, IncidentDraft{
			GroupKey:   inc.GroupKey,
			Summary:    "later fold",
			Severity:   SeverityMedium,
			Confidence: 0.7,
			OccurredAt: occurred.Add(time.Hour),
			EventID:    e.EventID,
			Evidence:   e.Evidence,
		})
		require.NoError(t, err)

		got, found, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, StatusInProgress, got.Status, "fold never rewrites operator status")
		require.NotNil(t, got.Assignee)
		assert.Equal(t, member, *got.Assignee, "fold never rewrites the assignee")
		assert.Equal(t, int64(2), got.EventCount, "fold still advances counts")
	})

	t.Run("empty patch is a no-op", func(t *testing.T) {
		before, _, err := store.Get(ctx, orgA, inc.ID)
		require.NoError(t, err)
		got, found, err := patch(OperatorPatch{})
		require.NoError(t, err)
		require.True(t, found)
		assert.True(t, got.UpdatedAt.Equal(before.UpdatedAt))
	})

	t.Run("unknown incident and foreign org are not found", func(t *testing.T) {
		_, found, err := store.ApplyOperatorPatch(ctx, orgA, uuid.New(), setStatus(StatusAcknowledged))
		require.NoError(t, err)
		assert.False(t, found)

		// orgB owns a real incident; patching it under orgA's scope must
		// not find it (RLS org isolation + explicit predicate).
		other := stSeed(t, ctx, store, orgB, occurred)
		_, found, err = store.ApplyOperatorPatch(ctx, orgA, other.ID, setStatus(StatusAcknowledged))
		require.NoError(t, err)
		assert.False(t, found, "cross-org patch must be invisible, not an error")
		unchanged, found, err := store.Get(ctx, orgB, other.ID)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, StatusNew, unchanged.Status)
	})

	t.Run("bypass sessions work without the pin (superuser store)", func(t *testing.T) {
		suStore := NewStore(su) // superuser: the probe skips the GUC pin
		member := uuid.New()
		got, found, err := suStore.ApplyOperatorPatch(ctx, orgA, inc.ID,
			OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)
		require.True(t, found)
		require.NotNil(t, got.Assignee)
	})
}
