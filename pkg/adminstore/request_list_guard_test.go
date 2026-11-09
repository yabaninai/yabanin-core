package adminstore

// N04-P05.listguard (RV-n04p5t7 F2) — the verdict gate decides through the
// SHARED requestListWhere predicate, not through a handler-side clamp: the
// list/stats handlers pass the verdict-derived filters to the store and the
// store alone must guarantee that a verdict-denied caller yields nothing.
// These pins hold the exact filter shapes authorizeRequestList builds, so a
// refactor that drops one of the predicates fails here before a leak can
// ship. The handler-level and real-SQL shape pins live in
// services/admin/handlers/request_list_guard_test.go and
// request_list_guard_int_test.go.

import (
	"strings"
	"testing"
)

func TestRequestListWhereVerdictDeniedShapesYieldNothing(t *testing.T) {
	t.Run("verdict-denied agent is FALSE with and without the metadata allowance", func(t *testing.T) {
		// The handler leaves PayloadUserID and DelegateAgentID empty for a
		// denied non-human subject; OrgWideMetadata only ever interacts with
		// OwnerUserID (also empty here), so the FALSE branch must dominate
		// in both cases — the metadata allowance can never resurrect rows.
		for _, orgWide := range []bool{false, true} {
			where, _ := requestListWhere(RequestListFilters{
				OrgID:                   "org-a",
				PayloadDenied:           true,
				PayloadAuthorizationSet: true,
				OrgWideMetadata:         orgWide,
			})
			if !strings.Contains(where, "FALSE") {
				t.Fatalf("orgWideMetadata=%v: verdict-denied subject predicate = %q, want FALSE", orgWide, where)
			}
		}
	})

	t.Run("explicit deny overrides a delegation scope too", func(t *testing.T) {
		// Delegation scope is applied before the deny branch precisely so a
		// deny still yields nothing (store comment on the DelegateAgentID
		// branch); pin it — the handler never builds this shape, but a store
		// seam that re-orders the branches must stay safe.
		where, _ := requestListWhere(RequestListFilters{
			OrgID:                   "org-a",
			PayloadDenied:           true,
			PayloadAuthorizationSet: true,
			DelegateAgentID:         "agent-1",
		})
		if !strings.Contains(where, "FALSE") {
			t.Fatalf("deny+delegation predicate = %q, want FALSE", where)
		}
	})

	t.Run("denied human without the metadata allowance keeps owner scoping", func(t *testing.T) {
		// OwnerUserID mirrors PayloadUserID (set by authorizeRequestList for
		// every human), so without the org-wide metadata allowance the
		// own-history exclusion AND the owner scope are both present; their
		// conjunction is unsatisfiable and the page is empty. Drop the
		// owner-scope branch and a denied human would see every OTHER
		// user's org rows — this pin guards that.
		where, args := requestListWhere(RequestListFilters{
			OrgID:                   "org-a",
			PayloadDenied:           true,
			PayloadUserID:           "subject-a",
			OwnerUserID:             "subject-a",
			PayloadAuthorizationSet: true,
		})
		if !strings.Contains(where, "user_id::text <> $2") {
			t.Fatalf("denied human predicate = %q, want own-history exclusion", where)
		}
		if !strings.Contains(where, "user_id::text = $3 AND agent_id IS NULL AND api_key_id IS NULL") {
			t.Fatalf("denied human predicate = %q, want owner scope", where)
		}
		if len(args) < 3 || args[1] != "subject-a" || args[2] != "subject-a" {
			t.Fatalf("denied human bind args = %#v", args)
		}
	})
}
