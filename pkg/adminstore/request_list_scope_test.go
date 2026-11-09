package adminstore

import (
	"strings"
	"testing"
)

func TestRequestListWherePayloadSearchScopesOrSuppressesMatches(t *testing.T) {
	t.Run("unknown authorization has no matches", func(t *testing.T) {
		where, _ := requestListWhere(RequestListFilters{OrgID: "org-a", ContentSearch: "secret", PayloadAuthorizationSet: true})
		if !strings.Contains(where, "FALSE") {
			t.Fatalf("unauthorized content search predicate = %q, want FALSE", where)
		}
	})
	t.Run("own history is scoped to subject", func(t *testing.T) {
		where, args := requestListWhere(RequestListFilters{OrgID: "org-a", PayloadUserID: "subject-a", ContentSearch: "secret", PayloadSearchAllowed: true, PayloadAuthorizationSet: true})
		if !strings.Contains(where, "rl.user_id::text = $2") || !strings.Contains(where, "rl.agent_id IS NULL AND rl.api_key_id IS NULL") {
			t.Fatalf("own-history predicate = %q, want subject scope", where)
		}
		if len(args) < 3 || args[1] != "subject-a" {
			t.Fatalf("subject bind args = %#v", args)
		}
	})
	t.Run("explicit deny overrides grant", func(t *testing.T) {
		where, _ := requestListWhere(RequestListFilters{
			OrgID: "org-a", ContentSearch: "secret", PayloadGrant: true,
			PayloadSearchAllowed: true, PayloadAuthorizationSet: true, PayloadDenied: true,
		})
		if !strings.Contains(where, "FALSE") {
			t.Fatalf("deny policy predicate = %q, want FALSE despite grant", where)
		}
	})
	t.Run("deny own history removes rows before aggregates", func(t *testing.T) {
		where, args := requestListWhere(RequestListFilters{OrgID: "org-a", PayloadUserID: "subject-a", PayloadDenied: true})
		if !strings.Contains(where, "user_id::text <> $2") {
			t.Fatalf("own-history deny predicate = %q, want subject exclusion", where)
		}
		if len(args) < 2 || args[1] != "subject-a" {
			t.Fatalf("own-history deny bind args = %#v", args)
		}
	})
	t.Run("YQL body search shares q payload scope", func(t *testing.T) {
		query, err := ParseYQL(`text ~ "secret"`)
		if err != nil {
			t.Fatal(err)
		}
		where, _ := requestListWhere(RequestListFilters{
			OrgID: "org-a", Query: query, PayloadAuthorizationSet: true,
		})
		if !strings.Contains(where, "FALSE") {
			t.Fatalf("unauthorized YQL content search predicate = %q, want FALSE", where)
		}
	})
	t.Run("YQL body search scopes content to owner", func(t *testing.T) {
		query, err := ParseYQL(`text ~ "secret"`)
		if err != nil {
			t.Fatal(err)
		}
		where, args := requestListWhere(RequestListFilters{
			OrgID: "org-a", Query: query, PayloadUserID: "subject-a",
			PayloadSearchAllowed: true, PayloadAuthorizationSet: true,
		})
		if !strings.Contains(where, "rl.user_id::text = $2") || !strings.Contains(where, "rl.agent_id IS NULL") {
			t.Fatalf("YQL body scope = %q, want owner-only predicate", where)
		}
		if len(args) != 3 || args[1] != "subject-a" {
			t.Fatalf("YQL body args = %#v, want owner bind", args)
		}
	})
}
