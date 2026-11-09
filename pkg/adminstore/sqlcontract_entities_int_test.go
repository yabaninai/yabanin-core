package adminstore

// exported method that executes SQL in orgs.go, keys.go (API keys),
// agentkeys.go, session_keys.go, models.go, model_aliases.go, whitelist.go,
// teams.go, admin.go and roles.go (members = org memberships), run against
// combinations (org set/empty/unknown, allowlisted sort column in both
// directions, default order, empty pages, missing ids, nil optionals) are
// matrix-generated; business answers (not-found, unique conflicts, empty
// lists) are asserted where they pin the contract, SQL rejections fail via
// contract(). permissions.go holds no SQL and is excluded by design.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// entitiesUnknownID is a well-formed uuid that no seeded row ever carries —
// the contract-legal empty answer for id-scoped entity reads.
const entitiesUnknownID = "00000000-0000-0000-0000-0000000000bb"

// entitiesSortMatrix drives one list method over the full optional-sort
// surface: every allowlisted column in both directions, the endpoint default
// order and an over-run page (empty result).
func entitiesSortMatrix(t *testing.T, columns SortColumns, run func(name string, f PageFilter)) {
	t.Helper()
	names := make([]string, 0, len(columns))
	for c := range columns {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		for _, desc := range []bool{false, true} {
			dir := "asc"
			if desc {
				dir = "desc"
			}
			run(c+"/"+dir, PageFilter{Page: 1, PageSize: 100, Sort: &Sort{Column: c, Desc: desc, Set: true}})
		}
	}
	run("default", NewPageFilter(1, 100))
	run("empty-page", NewPageFilter(9999, 100))
}

// TestSQLContractEntities_Orgs covers CreateOrganization (wallet CTE),
// GetOrganizationByID/BySlug (found + missing), ListOrganizations over every
// OrganizationSortColumns column in both directions plus default and empty
// page, UpdateOrganization in both issue-url branches, the residency-region
// read/clear pair and DeleteOrganization (existing, then missing).
func TestSQLContractEntities_Orgs(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	// Throwaway org for the mutation surface; fixture cleanup only knows the
	// seeded orgs, so this one is removed here (wallet first, mirroring the
	// FK direction).
	var created *Organization
	contract(t, "CreateOrganization", func(ctx context.Context) error {
		org, err := store.CreateOrganization(ctx, fx.Token+"-org-c", fx.Token+"-org-c")
		if err != nil {
			return err
		}
		if org.ID == "" || org.Currency != "USD" || org.Slug != fx.Token+"-org-c" {
			t.Errorf("CreateOrganization: unexpected row %+v", org)
		}
		created = org
		return nil
	})
	require.NotNil(t, created, "CreateOrganization must produce the row before the read contract")
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = $1`, created.ID); err != nil {
			t.Errorf("org cleanup (credits): %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id::text = $1`, created.ID); err != nil {
			t.Errorf("org cleanup: %v", err)
		}
	})

	contract(t, "GetOrganizationByID/found", func(ctx context.Context) error {
		org, err := store.GetOrganizationByID(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if org.Slug != fx.Token+"-org-a" {
			t.Errorf("GetOrganizationByID: got slug %q", org.Slug)
		}
		return nil
	})
	contract(t, "GetOrganizationByID/missing", func(ctx context.Context) error {
		_, err := store.GetOrganizationByID(ctx, entitiesUnknownID)
		if !IsNotFound(err) {
			t.Errorf("GetOrganizationByID/missing: want not-found, got %v", err)
		}
		return nil
	})
	contract(t, "GetOrganizationBySlug/found", func(ctx context.Context) error {
		org, err := store.GetOrganizationBySlug(ctx, fx.Token+"-org-b")
		if err != nil {
			return err
		}
		if org.ID != fx.OrgB {
			t.Errorf("GetOrganizationBySlug: got %s, want %s", org.ID, fx.OrgB)
		}
		return nil
	})
	contract(t, "GetOrganizationBySlug/missing", func(ctx context.Context) error {
		_, err := store.GetOrganizationBySlug(ctx, fx.Token+"-no-such-slug")
		if !IsNotFound(err) {
			t.Errorf("GetOrganizationBySlug/missing: want not-found, got %v", err)
		}
		return nil
	})

	orgs := map[string]bool{}
	entitiesSortMatrix(t, OrganizationSortColumns, func(name string, f PageFilter) {
		contract(t, "ListOrganizations/"+name, func(ctx context.Context) error {
			rows, total, err := store.ListOrganizations(ctx, f)
			if err != nil {
				return err
			}
			if name == "default" {
				if total < 2 {
					t.Errorf("ListOrganizations/default: total %d, want >= 2", total)
				}
				for _, o := range rows {
					orgs[o.ID] = true
				}
			}
			if name == "empty-page" && len(rows) != 0 {
				t.Errorf("ListOrganizations/empty-page: got %d rows", len(rows))
			}
			return nil
		})
	})
	if !orgs[fx.OrgA] || !orgs[fx.OrgB] {
		t.Errorf("ListOrganizations/default: seeded orgs missing from the page: %v", orgs)
	}

	contract(t, "UpdateOrganization/no-issue-url", func(ctx context.Context) error {
		return store.UpdateOrganization(ctx, created.ID, fx.Token+"-org-c2", fx.Token+"-org-c2", "EUR", "Europe/Berlin", nil)
	})
	contract(t, "UpdateOrganization/issue-url", func(ctx context.Context) error {
		url := "https://issues.example.com/{issue}"
		return store.UpdateOrganization(ctx, created.ID, fx.Token+"-org-c2", fx.Token+"-org-c2", "EUR", "Europe/Berlin", &url)
	})
	contract(t, "UpdateOrganization/roundtrip", func(ctx context.Context) error {
		org, err := store.GetOrganizationByID(ctx, created.ID)
		if err != nil {
			return err
		}
		if org.Currency != "EUR" || org.Timezone != "Europe/Berlin" ||
			org.IssueURLTemplate != "https://issues.example.com/{issue}" {
			t.Errorf("UpdateOrganization: fields not persisted: %+v", org)
		}
		return nil
	})

	contract(t, "GetOrgResidencyRegion/unset", func(ctx context.Context) error {
		region, err := store.GetOrgResidencyRegion(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if region != "" {
			t.Errorf("GetOrgResidencyRegion: got %q, want empty", region)
		}
		return nil
	})
	contract(t, "GetOrgResidencyRegion/missing-org", func(ctx context.Context) error {
		region, err := store.GetOrgResidencyRegion(ctx, entitiesUnknownID)
		if err != nil {
			return err
		}
		if region != "" {
			t.Errorf("GetOrgResidencyRegion/missing: got %q, want empty", region)
		}
		return nil
	})
	contract(t, "UpdateOrgResidencyRegion/set-and-clear", func(ctx context.Context) error {
		if err := store.UpdateOrgResidencyRegion(ctx, fx.OrgB, "EU"); err != nil {
			return err
		}
		region, err := store.GetOrgResidencyRegion(ctx, fx.OrgB)
		if err != nil {
			return err
		}
		if region != "EU" {
			t.Errorf("UpdateOrgResidencyRegion: region %q, want EU", region)
		}
		return store.UpdateOrgResidencyRegion(ctx, fx.OrgB, "")
	})

	contract(t, "DeleteOrganization/existing", func(ctx context.Context) error {
		return store.DeleteOrganization(ctx, created.ID)
	})
	contract(t, "DeleteOrganization/missing", func(ctx context.Context) error {
		err := store.DeleteOrganization(ctx, created.ID)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteOrganization/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_APIKeys covers CreateAPIKey (org+team and nil-org
// variants), GetAPIKeyByID, ListAPIKeys over org set/nil × every
// APIKeySortColumns column in both directions + default + empty page and
// cross-tenant isolation, the labels/flags update (existing + missing),
// active toggle, rotate and delete (existing, then missing).
func TestSQLContractEntities_APIKeys(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	var withOrg, withoutOrg *APIKey
	contract(t, "CreateAPIKey/org+team", func(ctx context.Context) error {
		org, team := fx.OrgA, fx.TeamA1
		k, err := store.CreateAPIKey(ctx, fx.Token+"-ak-c1", fx.Token+"-key-c1", &org, &team)
		if err != nil {
			return err
		}
		if k.ID == "" || k.OrgID == nil || *k.OrgID != fx.OrgA || !k.Active {
			t.Errorf("CreateAPIKey/org+team: unexpected row %+v", k)
		}
		withOrg = k
		return nil
	})
	contract(t, "CreateAPIKey/nil-org", func(ctx context.Context) error {
		team := fx.TeamA1
		k, err := store.CreateAPIKey(ctx, fx.Token+"-ak-c2", fx.Token+"-key-c2", nil, &team)
		if err != nil {
			return err
		}
		if k.OrgID != nil {
			t.Errorf("CreateAPIKey/nil-org: org %q, want null", *k.OrgID)
		}
		withoutOrg = k
		return nil
	})
	require.NotNil(t, withOrg, "org+team key must exist before the read contract")
	require.NotNil(t, withoutOrg, "nil-org key must exist before the read contract")

	contract(t, "GetAPIKeyByID/found", func(ctx context.Context) error {
		k, err := store.GetAPIKeyByID(ctx, withOrg.ID)
		if err != nil {
			return err
		}
		if k.KeyHash != fx.Token+"-ak-c1" || k.Labels == nil {
			t.Errorf("GetAPIKeyByID: unexpected row %+v", k)
		}
		return nil
	})
	contract(t, "GetAPIKeyByID/missing", func(ctx context.Context) error {
		_, err := store.GetAPIKeyByID(ctx, entitiesUnknownID)
		if !IsNotFound(err) {
			t.Errorf("GetAPIKeyByID/missing: want not-found, got %v", err)
		}
		return nil
	})

	for _, orgName := range []string{"org-scoped", "global"} {
		orgScoped := orgName == "org-scoped"
		var org *string
		if orgScoped {
			o := fx.OrgA
			org = &o
		}
		entitiesSortMatrix(t, APIKeySortColumns, func(name string, f PageFilter) {
			contract(t, fmt.Sprintf("ListAPIKeys/%s/%s", orgName, name), func(ctx context.Context) error {
				rows, total, err := store.ListAPIKeys(ctx, org, f)
				if err != nil {
					return err
				}
				if orgScoped {
					for _, k := range rows {
						if k.OrgID == nil || *k.OrgID != fx.OrgA {
							t.Errorf("ListAPIKeys/org-scoped/%s: org B key leaked: %+v", name, k)
						}
					}
					if name == "default" {
						seen := map[string]bool{}
						for _, k := range rows {
							seen[k.ID] = true
						}
						if !seen[fx.APIKeyA] || !seen[withOrg.ID] {
							t.Errorf("ListAPIKeys/org-scoped/default: org A keys missing (total %d)", total)
						}
					}
				}
				if name == "empty-page" && len(rows) != 0 {
					t.Errorf("ListAPIKeys/%s/empty-page: got %d rows", orgName, len(rows))
				}
				return nil
			})
		})
	}
	contract(t, "ListAPIKeys/unknown-org", func(ctx context.Context) error {
		unknown := entitiesUnknownID
		rows, total, err := store.ListAPIKeys(ctx, &unknown, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("ListAPIKeys/unknown-org: total %d rows %d, want 0/0", total, len(rows))
		}
		return nil
	})

	contract(t, "UpdateAPIKeyLabels/found", func(ctx context.Context) error {
		return store.UpdateAPIKeyLabels(ctx, withOrg.ID, map[string]string{"env": "contract"}, true, true, false)
	})
	contract(t, "UpdateAPIKeyLabels/roundtrip", func(ctx context.Context) error {
		k, err := store.GetAPIKeyByID(ctx, withOrg.ID)
		if err != nil {
			return err
		}
		if !k.LabelsLocked || !k.CanMintSessions || k.CanReadUsage || k.Labels["env"] != "contract" {
			t.Errorf("UpdateAPIKeyLabels: flags not persisted: %+v", k)
		}
		return nil
	})
	contract(t, "UpdateAPIKeyLabels/missing", func(ctx context.Context) error {
		err := store.UpdateAPIKeyLabels(ctx, entitiesUnknownID, nil, false, false, false)
		if err != ErrNotFound {
			t.Errorf("UpdateAPIKeyLabels/missing: want ErrNotFound, got %v", err)
		}
		return nil
	})

	contract(t, "UpdateAPIKeyActive/toggle", func(ctx context.Context) error {
		if err := store.UpdateAPIKeyActive(ctx, withoutOrg.ID, false); err != nil {
			return err
		}
		k, err := store.GetAPIKeyByID(ctx, withoutOrg.ID)
		if err != nil {
			return err
		}
		if k.Active {
			t.Errorf("UpdateAPIKeyActive: key still active")
		}
		return store.UpdateAPIKeyActive(ctx, withoutOrg.ID, true)
	})
	contract(t, "RotateAPIKey", func(ctx context.Context) error {
		return store.RotateAPIKey(ctx, withOrg.ID, fx.Token+"-ak-c1-rotated")
	})
	contract(t, "RotateAPIKey/missing-id", func(ctx context.Context) error {
		return store.RotateAPIKey(ctx, entitiesUnknownID, fx.Token+"-ak-none")
	})

	contract(t, "DeleteAPIKey/existing", func(ctx context.Context) error {
		return store.DeleteAPIKey(ctx, withoutOrg.ID)
	})
	contract(t, "DeleteAPIKey/missing", func(ctx context.Context) error {
		err := store.DeleteAPIKey(ctx, withoutOrg.ID)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteAPIKey/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_AgentSessionKeys covers CreateAgentKey (root
// wrapper), CreateAgentKeyDelegated (root and child with delegation TTL and
// budget cap), GetAgentKeyByID (found + missing), ListAgentKeys (org with
// keys + empty org), RevokeAgentKey (existing + missing) and
// RevokeSessionKeysByParent (live sessions, already-revoked re-run, unknown
// parent).
func TestSQLContractEntities_AgentSessionKeys(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	var child *AgentKey
	contract(t, "CreateAgentKey/root-wrapper", func(ctx context.Context) error {
		k, err := store.CreateAgentKey(ctx, fx.Token+"-ag-c1", fx.Token+"-agent-c1", fx.OrgA)
		if err != nil {
			return err
		}
		if !k.Active || k.ParentID != nil || k.ExpiresAt != nil || k.DailyLimitCents != nil {
			t.Errorf("CreateAgentKey/root: unexpected row %+v", k)
		}
		return nil
	})
	contract(t, "CreateAgentKeyDelegated/child", func(ctx context.Context) error {
		parent := fx.AgentKeyA
		expires := time.Now().Add(24 * time.Hour)
		limit := int64(500)
		k, err := store.CreateAgentKeyDelegated(ctx, AgentKeyCreateParams{
			KeyHash: fx.Token + "-ag-c2", Name: fx.Token + "-agent-c2", OrgID: fx.OrgA,
			ParentID: &parent, ExpiresAt: &expires, DailyLimitCents: &limit,
		})
		if err != nil {
			return err
		}
		if k.ParentID == nil || *k.ParentID != fx.AgentKeyA || k.DailyLimitCents == nil || *k.DailyLimitCents != 500 {
			t.Errorf("CreateAgentKeyDelegated/child: delegation fields lost: %+v", k)
		}
		child = k
		return nil
	})
	require.NotNil(t, child, "child agent key must exist before the read contract")

	contract(t, "GetAgentKeyByID/found", func(ctx context.Context) error {
		k, err := store.GetAgentKeyByID(ctx, fx.AgentKeyA)
		if err != nil {
			return err
		}
		if k.ID != fx.AgentKeyA || !k.Active {
			t.Errorf("GetAgentKeyByID: unexpected row %+v", k)
		}
		return nil
	})
	contract(t, "GetAgentKeyByID/missing", func(ctx context.Context) error {
		_, err := store.GetAgentKeyByID(ctx, entitiesUnknownID)
		if !IsNotFound(err) {
			t.Errorf("GetAgentKeyByID/missing: want not-found, got %v", err)
		}
		return nil
	})

	contract(t, "ListAgentKeys/orgA", func(ctx context.Context) error {
		keys, err := store.ListAgentKeys(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, k := range keys {
			seen[k.ID] = true
		}
		if !seen[fx.AgentKeyA] || !seen[child.ID] {
			t.Errorf("ListAgentKeys/orgA: seeded agent keys missing: %v", seen)
		}
		return nil
	})
	contract(t, "ListAgentKeys/empty-org", func(ctx context.Context) error {
		keys, err := store.ListAgentKeys(ctx, entitiesUnknownID)
		if err != nil {
			return err
		}
		if len(keys) != 0 {
			t.Errorf("ListAgentKeys/empty-org: got %d keys", len(keys))
		}
		return nil
	})

	contract(t, "RevokeAgentKey/existing", func(ctx context.Context) error {
		return store.RevokeAgentKey(ctx, child.ID)
	})
	// Revoking an already-revoked key is idempotent (the row still matches).
	contract(t, "RevokeAgentKey/already-revoked", func(ctx context.Context) error {
		if err := store.RevokeAgentKey(ctx, child.ID); err != nil {
			t.Errorf("RevokeAgentKey/already-revoked: want idempotent nil, got %v", err)
		}
		return nil
	})
	contract(t, "RevokeAgentKey/missing", func(ctx context.Context) error {
		err := store.RevokeAgentKey(ctx, entitiesUnknownID)
		if err != ErrNotFound {
			t.Errorf("RevokeAgentKey/missing: want ErrNotFound, got %v", err)
		}
		return nil
	})

	// Two live session keys minted from the seeded API key; hashes carry the
	// run token so the fixture teardown removes them.
	for _, suffix := range []string{"-sk-c1", "-sk-c2"} {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO session_keys (key_hash, org_id, parent_api_key_id, name, labels, expires_at)
			VALUES ($1, $2::uuid, $3::uuid, $4, '{}'::jsonb, now() + interval '24 hours')`,
			fx.Token+suffix, fx.OrgA, fx.APIKeyA, fx.Token+"-session"+suffix)
		require.NoError(t, err, "seed session key %s", suffix)
	}
	contract(t, "RevokeSessionKeysByParent/live", func(ctx context.Context) error {
		hashes, err := store.RevokeSessionKeysByParent(ctx, fx.APIKeyA)
		if err != nil {
			return err
		}
		// fx.SessionKeyA plus the two seeded above were live.
		if len(hashes) < 3 {
			t.Errorf("RevokeSessionKeysByParent/live: got %d hashes, want >= 3", len(hashes))
		}
		return nil
	})
	contract(t, "RevokeSessionKeysByParent/already-revoked", func(ctx context.Context) error {
		hashes, err := store.RevokeSessionKeysByParent(ctx, fx.APIKeyA)
		if err != nil {
			return err
		}
		if len(hashes) != 0 {
			t.Errorf("RevokeSessionKeysByParent/re-run: got %d hashes, want 0", len(hashes))
		}
		return nil
	})
	contract(t, "RevokeSessionKeysByParent/unknown-parent", func(ctx context.Context) error {
		hashes, err := store.RevokeSessionKeysByParent(ctx, entitiesUnknownID)
		if err != nil {
			return err
		}
		if len(hashes) != 0 {
			t.Errorf("RevokeSessionKeysByParent/unknown: got %d hashes, want 0", len(hashes))
		}
		return nil
	})
}

// TestSQLContractEntities_Models covers CreateModel (legacy wrapper without
// optionals), CreateModelWithParams (full P3.3 set and the defaults path),
// GetModelByName (found + missing), ListModels over every ModelSortColumns
// column in both directions + default + empty page, UpdateModelEnabled,
// UpdateModel (minimal and full pointer sets), UpdateModelWithParams
// (partial, full, empty-set existence probe on existing and missing models),
// BumpModelVersion (existing + missing) and DeleteModel (existing + missing).
func TestSQLContractEntities_Models(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	contract(t, "CreateModel/legacy", func(ctx context.Context) error {
		m, err := store.CreateModel(ctx, fx.Token+"-m-c1", fx.Token+"-m-c1", "fast", nil, nil)
		if err != nil {
			return err
		}
		if m.Tier != "fast" || m.UpstreamURL != nil || !m.Enabled {
			t.Errorf("CreateModel/legacy: unexpected row %+v", m)
		}
		return nil
	})
	contract(t, "CreateModelWithParams/full", func(ctx context.Context) error {
		url := "https://upstream.example.com/v1"
		key := "sk-contract"
		fallback := fx.Token + "-m-fast"
		timeout := 1500
		m, err := store.CreateModelWithParams(ctx, CreateModelParams{
			ModelName: fx.Token + "-m-c2", DisplayName: fx.Token + "-m-c2", Tier: "smart",
			UpstreamURL: &url, UpstreamAPIKey: &key, Provider: "openai-compat",
			FallbackModel: &fallback, FailoverModels: []string{fx.Token + "-m-fast"},
			TierPool: []string{fx.Token + "-m-mini"}, UpstreamTimeoutMs: &timeout,
		})
		if err != nil {
			return err
		}
		if m.Provider != "openai-compat" || m.FallbackModel == nil || len(m.FailoverModels) != 1 ||
			len(m.TierPool) != 1 || m.UpstreamTimeoutMs == nil || *m.UpstreamTimeoutMs != 1500 {
			t.Errorf("CreateModelWithParams/full: P3.3 fields lost: %+v", m)
		}
		return nil
	})
	contract(t, "CreateModelWithParams/defaults", func(ctx context.Context) error {
		m, err := store.CreateModelWithParams(ctx, CreateModelParams{
			ModelName: fx.Token + "-m-c3", DisplayName: fx.Token + "-m-c3", Tier: "smart",
		})
		if err != nil {
			return err
		}
		if m.Provider != "openai-compat" || m.FailoverModels == nil || m.TierPool == nil {
			t.Errorf("CreateModelWithParams/defaults: provider %q failover %v pool %v", m.Provider, m.FailoverModels, m.TierPool)
		}
		return nil
	})

	contract(t, "GetModelByName/found", func(ctx context.Context) error {
		m, err := store.GetModelByName(ctx, fx.Token+"-m-smart")
		if err != nil {
			return err
		}
		if len(m.FailoverModels) != 1 || m.FailoverModels[0] != fx.Token+"-m-fast" {
			t.Errorf("GetModelByName: failover chain not round-tripped: %+v", m)
		}
		return nil
	})
	contract(t, "GetModelByName/missing", func(ctx context.Context) error {
		_, err := store.GetModelByName(ctx, fx.Token+"-no-such-model")
		if !IsNotFound(err) {
			t.Errorf("GetModelByName/missing: want not-found, got %v", err)
		}
		return nil
	})

	models := 0
	entitiesSortMatrix(t, ModelSortColumns, func(name string, f PageFilter) {
		contract(t, "ListModels/"+name, func(ctx context.Context) error {
			rows, total, err := store.ListModels(ctx, f)
			if err != nil {
				return err
			}
			if name == "default" {
				models = len(rows)
				if total < 5 {
					t.Errorf("ListModels/default: total %d, want >= 5 seeded models", total)
				}
			}
			if name == "empty-page" && len(rows) != 0 {
				t.Errorf("ListModels/empty-page: got %d rows", len(rows))
			}
			return nil
		})
	})
	if models == 0 {
		t.Errorf("ListModels/default: expected the seeded models, got %d", models)
	}

	contract(t, "UpdateModelEnabled", func(ctx context.Context) error {
		if err := store.UpdateModelEnabled(ctx, fx.Token+"-m-c1", false); err != nil {
			return err
		}
		m, err := store.GetModelByName(ctx, fx.Token+"-m-c1")
		if err != nil {
			return err
		}
		if m.Enabled {
			t.Errorf("UpdateModelEnabled: model still enabled")
		}
		return store.UpdateModelEnabled(ctx, fx.Token+"-m-c1", true)
	})
	// Missing model answers nil by design (no RowsAffected check) — the
	// contract pins the SQL, not the policy.
	contract(t, "UpdateModelEnabled/missing-model", func(ctx context.Context) error {
		return store.UpdateModelEnabled(ctx, fx.Token+"-no-such-model", false)
	})

	tier := "fast"
	url := "https://upstream.example.com/v2"
	key := "sk-contract-2"
	enabled := false
	contract(t, "UpdateModel/minimal", func(ctx context.Context) error {
		return store.UpdateModel(ctx, fx.Token+"-m-c1", fx.Token+"-m-c1-display", nil, nil, nil, nil)
	})
	contract(t, "UpdateModel/full", func(ctx context.Context) error {
		return store.UpdateModel(ctx, fx.Token+"-m-c1", fx.Token+"-m-c1-display", &tier, &url, &key, &enabled)
	})
	contract(t, "UpdateModel/roundtrip", func(ctx context.Context) error {
		m, err := store.GetModelByName(ctx, fx.Token+"-m-c1")
		if err != nil {
			return err
		}
		if m.DisplayName != fx.Token+"-m-c1-display" || m.Tier != "fast" || m.Enabled ||
			m.UpstreamURL == nil || *m.UpstreamURL != url {
			t.Errorf("UpdateModel/full: fields not persisted: %+v", m)
		}
		return nil
	})

	newTier := "mini"
	empty := []string{}
	timeout := 2500
	contract(t, "UpdateModelWithParams/partial", func(ctx context.Context) error {
		return store.UpdateModelWithParams(ctx, UpdateModelParams{
			ModelName: fx.Token + "-m-c2", Tier: &newTier, Enabled: &enabled,
		})
	})
	contract(t, "UpdateModelWithParams/full", func(ctx context.Context) error {
		fallback := fx.Token + "-m-mini"
		return store.UpdateModelWithParams(ctx, UpdateModelParams{
			ModelName: fx.Token + "-m-c2", DisplayName: &fx.Token, Tier: &newTier,
			UpstreamURL: &url, UpstreamAPIKey: &key, Provider: &[]string{"openai-compat"}[0],
			FallbackModel: &fallback, FailoverModels: empty, TierPool: empty,
			UpstreamTimeoutMs: &timeout, Enabled: &enabled,
		})
	})
	contract(t, "UpdateModelWithParams/roundtrip", func(ctx context.Context) error {
		m, err := store.GetModelByName(ctx, fx.Token+"-m-c2")
		if err != nil {
			return err
		}
		if m.Tier != "mini" || m.Enabled || len(m.FailoverModels) != 0 || len(m.TierPool) != 0 {
			t.Errorf("UpdateModelWithParams: fields not persisted: %+v", m)
		}
		return nil
	})
	contract(t, "UpdateModelWithParams/empty-set-existing", func(ctx context.Context) error {
		return store.UpdateModelWithParams(ctx, UpdateModelParams{ModelName: fx.Token + "-m-c2"})
	})
	// the empty-set existence probe in UpdateModelWithParams is dead code —
	// "updated_at" is appended to the SET list before the len(set)==0 check,
	// so a no-field update on a missing model silently succeeds. This case
	// stays red until the orchestrator applies the patch.
	contract(t, "UpdateModelWithParams/empty-set-missing", func(ctx context.Context) error {
		err := store.UpdateModelWithParams(ctx, UpdateModelParams{ModelName: fx.Token + "-no-such-model"})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("UpdateModelWithParams/empty-set-missing: want not-found, got %v", err)
		}
		return nil
	})

	contract(t, "BumpModelVersion/existing", func(ctx context.Context) error {
		return store.BumpModelVersion(ctx, fx.Token+"-m-c2")
	})
	contract(t, "BumpModelVersion/missing", func(ctx context.Context) error {
		err := store.BumpModelVersion(ctx, fx.Token+"-no-such-model")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("BumpModelVersion/missing: want not-found, got %v", err)
		}
		return nil
	})

	contract(t, "DeleteModel/existing", func(ctx context.Context) error {
		return store.DeleteModel(ctx, fx.Token+"-m-c3")
	})
	contract(t, "DeleteModel/missing", func(ctx context.Context) error {
		err := store.DeleteModel(ctx, fx.Token+"-m-c3")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteModel/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_AliasesWhitelist covers ListModelAliases,
// CreateModelAlias (valid + the validation-only rejection), DeleteModelAlias
// (existing + missing) and the full key/team whitelist surface: add (allowed
// and denied), list (with entries, empty key, empty page), point lookup
// (found + missing) and delete (existing + missing).
func TestSQLContractEntities_AliasesWhitelist(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	// Whitelist rows are not covered by the fixture teardown; drop them by
	// target id before the fixture cascade removes the targets.
	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("whitelist cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM api_key_model_whitelist WHERE api_key_id::text = $1`, fx.APIKeyA)
		cleanup(`DELETE FROM team_model_whitelist WHERE team_id::text = $1`, fx.TeamA1)
	})

	contract(t, "ListModelAliases", func(ctx context.Context) error {
		aliases, err := store.ListModelAliases(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, a := range aliases {
			if a.Alias == fx.Token+"-alias" {
				found = a.TargetModel == fx.Token+"-m-smart"
			}
		}
		if !found {
			t.Errorf("ListModelAliases: seeded alias missing or retargeted (%v)", aliases)
		}
		return nil
	})
	contract(t, "CreateModelAlias/valid", func(ctx context.Context) error {
		a, err := store.CreateModelAlias(ctx, fx.Token+"-alias-c1", fx.Token+"-m-smart")
		if err != nil {
			return err
		}
		if a.TargetModel != fx.Token+"-m-smart" {
			t.Errorf("CreateModelAlias: target %q", a.TargetModel)
		}
		return nil
	})
	contract(t, "CreateModelAlias/invalid-alias", func(ctx context.Context) error {
		_, err := store.CreateModelAlias(ctx, "bad alias!", fx.Token+"-m-smart")
		if err == nil {
			t.Errorf("CreateModelAlias/invalid: want validation error")
		}
		return nil
	})
	contract(t, "DeleteModelAlias/existing", func(ctx context.Context) error {
		return store.DeleteModelAlias(ctx, fx.Token+"-alias-c1")
	})
	contract(t, "DeleteModelAlias/missing", func(ctx context.Context) error {
		err := store.DeleteModelAlias(ctx, fx.Token+"-alias-c1")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteModelAlias/missing: want not-found error, got %v", err)
		}
		return nil
	})

	contract(t, "AddKeyWhitelist/allowed", func(ctx context.Context) error {
		w, err := store.AddKeyWhitelist(ctx, fx.APIKeyA, fx.Token+"-wl-m1", true)
		if err != nil {
			return err
		}
		if w.ID == 0 || w.TargetID != fx.APIKeyA || !w.Allowed {
			t.Errorf("AddKeyWhitelist/allowed: unexpected row %+v", w)
		}
		return nil
	})
	contract(t, "AddKeyWhitelist/denied", func(ctx context.Context) error {
		w, err := store.AddKeyWhitelist(ctx, fx.APIKeyA, fx.Token+"-wl-m2", false)
		if err != nil {
			return err
		}
		if w.Allowed {
			t.Errorf("AddKeyWhitelist/denied: allowed=true")
		}
		return nil
	})
	contract(t, "ListKeyWhitelist/page1", func(ctx context.Context) error {
		rows, total, err := store.ListKeyWhitelist(ctx, fx.APIKeyA, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total < 2 || len(rows) < 2 {
			t.Errorf("ListKeyWhitelist/page1: total %d rows %d, want >= 2", total, len(rows))
		}
		return nil
	})
	contract(t, "ListKeyWhitelist/empty-page", func(ctx context.Context) error {
		rows, total, err := store.ListKeyWhitelist(ctx, fx.APIKeyA, NewPageFilter(2, 100))
		if err != nil {
			return err
		}
		if len(rows) != 0 || total < 2 {
			t.Errorf("ListKeyWhitelist/empty-page: rows %d total %d", len(rows), total)
		}
		return nil
	})
	contract(t, "ListKeyWhitelist/empty-key", func(ctx context.Context) error {
		rows, total, err := store.ListKeyWhitelist(ctx, entitiesUnknownID, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("ListKeyWhitelist/empty-key: total %d rows %d, want 0/0", total, len(rows))
		}
		return nil
	})
	contract(t, "GetKeyWhitelistEntry/found", func(ctx context.Context) error {
		w, ok, err := store.GetKeyWhitelistEntry(ctx, fx.APIKeyA, fx.Token+"-wl-m1")
		if err != nil {
			return err
		}
		if !ok || w == nil || !w.Allowed {
			t.Errorf("GetKeyWhitelistEntry/found: ok=%v row=%+v", ok, w)
		}
		return nil
	})
	contract(t, "GetKeyWhitelistEntry/missing", func(ctx context.Context) error {
		w, ok, err := store.GetKeyWhitelistEntry(ctx, fx.APIKeyA, fx.Token+"-wl-none")
		if err != nil {
			return err
		}
		if ok || w != nil {
			t.Errorf("GetKeyWhitelistEntry/missing: ok=%v row=%+v", ok, w)
		}
		return nil
	})
	contract(t, "DeleteKeyWhitelist/existing", func(ctx context.Context) error {
		return store.DeleteKeyWhitelist(ctx, fx.APIKeyA, fx.Token+"-wl-m1")
	})
	contract(t, "DeleteKeyWhitelist/missing", func(ctx context.Context) error {
		err := store.DeleteKeyWhitelist(ctx, fx.APIKeyA, fx.Token+"-wl-m1")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteKeyWhitelist/missing: want not-found error, got %v", err)
		}
		return nil
	})

	contract(t, "AddTeamWhitelist/allowed", func(ctx context.Context) error {
		w, err := store.AddTeamWhitelist(ctx, fx.TeamA1, fx.Token+"-wl-m3", true)
		if err != nil {
			return err
		}
		if w.TargetID != fx.TeamA1 || !w.Allowed {
			t.Errorf("AddTeamWhitelist/allowed: unexpected row %+v", w)
		}
		return nil
	})
	contract(t, "AddTeamWhitelist/denied", func(ctx context.Context) error {
		_, err := store.AddTeamWhitelist(ctx, fx.TeamA1, fx.Token+"-wl-m4", false)
		return err
	})
	contract(t, "ListTeamWhitelist/page1", func(ctx context.Context) error {
		rows, total, err := store.ListTeamWhitelist(ctx, fx.TeamA1, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total < 2 || len(rows) < 2 {
			t.Errorf("ListTeamWhitelist/page1: total %d rows %d, want >= 2", total, len(rows))
		}
		return nil
	})
	contract(t, "ListTeamWhitelist/empty-page", func(ctx context.Context) error {
		rows, total, err := store.ListTeamWhitelist(ctx, fx.TeamA1, NewPageFilter(2, 100))
		if err != nil {
			return err
		}
		if len(rows) != 0 || total < 2 {
			t.Errorf("ListTeamWhitelist/empty-page: rows %d total %d", len(rows), total)
		}
		return nil
	})
	contract(t, "ListTeamWhitelist/empty-team", func(ctx context.Context) error {
		rows, total, err := store.ListTeamWhitelist(ctx, entitiesUnknownID, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("ListTeamWhitelist/empty-team: total %d rows %d, want 0/0", total, len(rows))
		}
		return nil
	})
	contract(t, "GetTeamWhitelistEntry/found", func(ctx context.Context) error {
		w, ok, err := store.GetTeamWhitelistEntry(ctx, fx.TeamA1, fx.Token+"-wl-m3")
		if err != nil {
			return err
		}
		if !ok || w == nil || !w.Allowed {
			t.Errorf("GetTeamWhitelistEntry/found: ok=%v row=%+v", ok, w)
		}
		return nil
	})
	contract(t, "GetTeamWhitelistEntry/missing", func(ctx context.Context) error {
		w, ok, err := store.GetTeamWhitelistEntry(ctx, fx.TeamA1, fx.Token+"-wl-none")
		if err != nil {
			return err
		}
		if ok || w != nil {
			t.Errorf("GetTeamWhitelistEntry/missing: ok=%v row=%+v", ok, w)
		}
		return nil
	})
	contract(t, "DeleteTeamWhitelist/existing", func(ctx context.Context) error {
		return store.DeleteTeamWhitelist(ctx, fx.TeamA1, fx.Token+"-wl-m3")
	})
	contract(t, "DeleteTeamWhitelist/missing", func(ctx context.Context) error {
		err := store.DeleteTeamWhitelist(ctx, fx.TeamA1, fx.Token+"-wl-m3")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteTeamWhitelist/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_Teams covers CreateTeam (root and nested),
// GetTeamByID (found + missing), ListTeamsByOrg (org with teams, empty org,
// empty page), UpdateTeam (name+slug, reparent, empty-string skip),
// GetDefaultTeam (create-on-absent then read-back) and DeleteTeam (existing,
// then missing).
func TestSQLContractEntities_Teams(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	var root, nested *Team
	contract(t, "CreateTeam/root", func(ctx context.Context) error {
		tm, err := store.CreateTeam(ctx, fx.OrgA, fx.Token+"-team-c1", "gamma", nil)
		if err != nil {
			return err
		}
		if tm.ParentTeam != nil || tm.OrgID != fx.OrgA {
			t.Errorf("CreateTeam/root: unexpected row %+v", tm)
		}
		root = tm
		return nil
	})
	contract(t, "CreateTeam/nested", func(ctx context.Context) error {
		parent := fx.TeamA1
		tm, err := store.CreateTeam(ctx, fx.OrgA, fx.Token+"-team-c2", "delta", &parent)
		if err != nil {
			return err
		}
		if tm.ParentTeam == nil || *tm.ParentTeam != fx.TeamA1 {
			t.Errorf("CreateTeam/nested: parent lost: %+v", tm)
		}
		nested = tm
		return nil
	})
	require.NotNil(t, root, "root team must exist before the read contract")
	require.NotNil(t, nested, "nested team must exist before the read contract")

	contract(t, "GetTeamByID/found", func(ctx context.Context) error {
		tm, err := store.GetTeamByID(ctx, nested.ID)
		if err != nil {
			return err
		}
		if tm.ParentTeam == nil || *tm.ParentTeam != fx.TeamA1 {
			t.Errorf("GetTeamByID: parent lost: %+v", tm)
		}
		return nil
	})
	contract(t, "GetTeamByID/missing", func(ctx context.Context) error {
		_, err := store.GetTeamByID(ctx, entitiesUnknownID)
		if !IsNotFound(err) {
			t.Errorf("GetTeamByID/missing: want not-found, got %v", err)
		}
		return nil
	})

	contract(t, "ListTeamsByOrg/orgA", func(ctx context.Context) error {
		rows, total, err := store.ListTeamsByOrg(ctx, fx.OrgA, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total < 4 || len(rows) < 4 {
			t.Errorf("ListTeamsByOrg/orgA: total %d rows %d, want >= 4", total, len(rows))
		}
		return nil
	})
	contract(t, "ListTeamsByOrg/empty-page", func(ctx context.Context) error {
		rows, total, err := store.ListTeamsByOrg(ctx, fx.OrgA, NewPageFilter(9999, 100))
		if err != nil {
			return err
		}
		if len(rows) != 0 || total < 4 {
			t.Errorf("ListTeamsByOrg/empty-page: rows %d total %d", len(rows), total)
		}
		return nil
	})
	contract(t, "ListTeamsByOrg/empty-org", func(ctx context.Context) error {
		rows, total, err := store.ListTeamsByOrg(ctx, entitiesUnknownID, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("ListTeamsByOrg/empty-org: total %d rows %d, want 0/0", total, len(rows))
		}
		return nil
	})

	contract(t, "UpdateTeam/name-slug", func(ctx context.Context) error {
		return store.UpdateTeam(ctx, root.ID, fx.Token+"-team-c1b", "gamma-b", nil)
	})
	contract(t, "UpdateTeam/reparent", func(ctx context.Context) error {
		parent := fx.TeamA2
		return store.UpdateTeam(ctx, root.ID, "", "", &parent)
	})
	contract(t, "UpdateTeam/empty-skip", func(ctx context.Context) error {
		return store.UpdateTeam(ctx, root.ID, "", "", nil)
	})
	contract(t, "UpdateTeam/roundtrip", func(ctx context.Context) error {
		tm, err := store.GetTeamByID(ctx, root.ID)
		if err != nil {
			return err
		}
		if tm.Name != fx.Token+"-team-c1b" || tm.Slug != "gamma-b" ||
			tm.ParentTeam == nil || *tm.ParentTeam != fx.TeamA2 {
			t.Errorf("UpdateTeam: fields not persisted: %+v", tm)
		}
		return nil
	})

	contract(t, "GetDefaultTeam/create-on-absent", func(ctx context.Context) error {
		tm, err := store.GetDefaultTeam(ctx, fx.OrgB)
		if err != nil {
			return err
		}
		if tm.Slug != "default" || tm.OrgID != fx.OrgB {
			t.Errorf("GetDefaultTeam/create: unexpected row %+v", tm)
		}
		return nil
	})
	contract(t, "GetDefaultTeam/read-back", func(ctx context.Context) error {
		tm, err := store.GetDefaultTeam(ctx, fx.OrgB)
		if err != nil {
			return err
		}
		if tm.Slug != "default" {
			t.Errorf("GetDefaultTeam/read-back: slug %q", tm.Slug)
		}
		return nil
	})

	contract(t, "DeleteTeam/existing", func(ctx context.Context) error {
		return store.DeleteTeam(ctx, nested.ID)
	})
	contract(t, "DeleteTeam/missing", func(ctx context.Context) error {
		err := store.DeleteTeam(ctx, nested.ID)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteTeam/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_AdminUsers covers CreateAdminUser (root and
// non-root), the three lookups (by id / email / email-with-hash, each found
// + missing), ListAdminUsers over onlyActive × every AdminUserSortColumns
// column in both directions + default + empty page, the active toggle, the
// password-hash update, UpdateAdminUser (name only, root flag only, both,
// no-op) and DeleteAdminUser (existing, then missing).
func TestSQLContractEntities_AdminUsers(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	rootEmail, opEmail, offEmail := fx.Token+"-root@example.com", fx.Token+"-op@example.com", fx.Token+"-off@example.com"
	var root, op, off *AdminUser
	contract(t, "CreateAdminUser/root", func(ctx context.Context) error {
		u, err := store.CreateAdminUser(ctx, rootEmail, fx.Token+"-root", "hash-root", true)
		if err != nil {
			return err
		}
		if !u.IsRoot || !u.Active {
			t.Errorf("CreateAdminUser/root: unexpected row %+v", u)
		}
		root = u
		return nil
	})
	contract(t, "CreateAdminUser/non-root", func(ctx context.Context) error {
		u, err := store.CreateAdminUser(ctx, opEmail, fx.Token+"-op", "hash-op", false)
		if err != nil {
			return err
		}
		if u.IsRoot {
			t.Errorf("CreateAdminUser/non-root: is_root=true")
		}
		op = u
		return nil
	})
	contract(t, "CreateAdminUser/deactivated-later", func(ctx context.Context) error {
		u, err := store.CreateAdminUser(ctx, offEmail, fx.Token+"-off", "hash-off", false)
		if err != nil {
			return err
		}
		off = u
		return nil
	})
	require.NotNil(t, root, "root admin must exist before the read contract")
	require.NotNil(t, op, "op admin must exist before the read contract")
	require.NotNil(t, off, "third admin must exist before the read contract")
	// admin_users and admin_org_memberships are outside the fixture teardown;
	// memberships cascade from the user delete.
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE $1`, fx.Token+"%"); err != nil {
			t.Errorf("admin users cleanup: %v", err)
		}
	})

	contract(t, "GetAdminUserByID/found", func(ctx context.Context) error {
		u, err := store.GetAdminUserByID(ctx, root.ID)
		if err != nil {
			return err
		}
		if u.Email != rootEmail {
			t.Errorf("GetAdminUserByID: email %q", u.Email)
		}
		return nil
	})
	contract(t, "GetAdminUserByID/missing", func(ctx context.Context) error {
		_, err := store.GetAdminUserByID(ctx, entitiesUnknownID)
		if !IsNotFound(err) {
			t.Errorf("GetAdminUserByID/missing: want not-found, got %v", err)
		}
		return nil
	})
	contract(t, "GetAdminUserByEmail/found", func(ctx context.Context) error {
		u, err := store.GetAdminUserByEmail(ctx, opEmail)
		if err != nil {
			return err
		}
		if u.ID != op.ID {
			t.Errorf("GetAdminUserByEmail: id %s, want %s", u.ID, op.ID)
		}
		return nil
	})
	contract(t, "GetAdminUserByEmail/missing", func(ctx context.Context) error {
		_, err := store.GetAdminUserByEmail(ctx, fx.Token+"-none@example.com")
		if !IsNotFound(err) {
			t.Errorf("GetAdminUserByEmail/missing: want not-found, got %v", err)
		}
		return nil
	})
	contract(t, "GetAdminUserByEmailWithHash/found", func(ctx context.Context) error {
		u, err := store.GetAdminUserByEmailWithHash(ctx, opEmail)
		if err != nil {
			return err
		}
		if u.PasswordHash != "hash-op" {
			t.Errorf("GetAdminUserByEmailWithHash: hash %q", u.PasswordHash)
		}
		return nil
	})
	contract(t, "GetAdminUserByEmailWithHash/missing", func(ctx context.Context) error {
		_, err := store.GetAdminUserByEmailWithHash(ctx, fx.Token+"-none@example.com")
		if !IsNotFound(err) {
			t.Errorf("GetAdminUserByEmailWithHash/missing: want not-found, got %v", err)
		}
		return nil
	})

	// Deactivate the third user so the onlyActive filter has a negative case.
	contract(t, "UpdateAdminUserActive/deactivate", func(ctx context.Context) error {
		return store.UpdateAdminUserActive(ctx, off.ID, false)
	})
	for _, onlyActive := range []bool{false, true} {
		flag := "all"
		if onlyActive {
			flag = "active"
		}
		entitiesSortMatrix(t, AdminUserSortColumns, func(name string, f PageFilter) {
			contract(t, fmt.Sprintf("ListAdminUsers/%s/%s", flag, name), func(ctx context.Context) error {
				rows, total, err := store.ListAdminUsers(ctx, onlyActive, f)
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, u := range rows {
					seen[u.ID] = true
					if onlyActive && !u.Active {
						t.Errorf("ListAdminUsers/%s/%s: inactive user leaked: %+v", flag, name, u)
					}
				}
				if name == "default" && onlyActive {
					if !seen[op.ID] || !seen[root.ID] {
						t.Errorf("ListAdminUsers/active/default: seeded active admins missing (total %d)", total)
					}
					if seen[off.ID] {
						t.Errorf("ListAdminUsers/active/default: deactivated admin visible")
					}
				}
				if name == "default" && !onlyActive && !seen[off.ID] {
					t.Errorf("ListAdminUsers/all/default: deactivated admin must stay listed (total %d)", total)
				}
				if name == "empty-page" && len(rows) != 0 {
					t.Errorf("ListAdminUsers/%s/empty-page: got %d rows", flag, len(rows))
				}
				return nil
			})
		})
	}

	contract(t, "UpdateAdminUserPasswordHash", func(ctx context.Context) error {
		if err := store.UpdateAdminUserPasswordHash(ctx, op.ID, "hash-op-2"); err != nil {
			return err
		}
		u, err := store.GetAdminUserByEmailWithHash(ctx, opEmail)
		if err != nil {
			return err
		}
		if u.PasswordHash != "hash-op-2" {
			t.Errorf("UpdateAdminUserPasswordHash: hash %q", u.PasswordHash)
		}
		return nil
	})

	newName := fx.Token + "-op-renamed"
	falsy := false
	contract(t, "UpdateAdminUser/name-only", func(ctx context.Context) error {
		return store.UpdateAdminUser(ctx, op.ID, &newName, nil)
	})
	contract(t, "UpdateAdminUser/root-only", func(ctx context.Context) error {
		return store.UpdateAdminUser(ctx, op.ID, nil, &falsy)
	})
	contract(t, "UpdateAdminUser/both", func(ctx context.Context) error {
		return store.UpdateAdminUser(ctx, op.ID, &newName, &falsy)
	})
	contract(t, "UpdateAdminUser/roundtrip", func(ctx context.Context) error {
		u, err := store.GetAdminUserByID(ctx, op.ID)
		if err != nil {
			return err
		}
		if u.DisplayName != newName || u.IsRoot {
			t.Errorf("UpdateAdminUser: fields not persisted: %+v", u)
		}
		return nil
	})
	contract(t, "UpdateAdminUser/no-op", func(ctx context.Context) error {
		return store.UpdateAdminUser(ctx, op.ID, nil, nil)
	})

	contract(t, "DeleteAdminUser/existing", func(ctx context.Context) error {
		return store.DeleteAdminUser(ctx, off.ID)
	})
	contract(t, "DeleteAdminUser/missing", func(ctx context.Context) error {
		err := store.DeleteAdminUser(ctx, off.ID)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("DeleteAdminUser/missing: want not-found error, got %v", err)
		}
		return nil
	})
}

// TestSQLContractEntities_Memberships covers CreateOrgMembership (grant,
// unique-conflict business answer, invalid-role validation path),
// SetOrgMembership (insert and upsert-change), GetUserOrgRoles (multi-org and
// unknown user), ListOrgMembers (org with members + empty org) and
// DeleteOrgMembership (existing, then missing). Role ranking and the
// permission matrix (permissions.go) carry no SQL and stay outside the
// contract.
func TestSQLContractEntities_Memberships(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	u1Email, u2Email := fx.Token+"-u1@example.com", fx.Token+"-u2@example.com"
	var u1, u2 *AdminUser
	contract(t, "fixture.CreateAdminUser/u1", func(ctx context.Context) error {
		u, err := store.CreateAdminUser(ctx, u1Email, fx.Token+"-u1", "hash-u1", false)
		if err != nil {
			return err
		}
		u1 = u
		return nil
	})
	contract(t, "fixture.CreateAdminUser/u2", func(ctx context.Context) error {
		u, err := store.CreateAdminUser(ctx, u2Email, fx.Token+"-u2", "hash-u2", false)
		if err != nil {
			return err
		}
		u2 = u
		return nil
	})
	require.NotNil(t, u1, "u1 must exist before the membership contract")
	require.NotNil(t, u2, "u2 must exist before the membership contract")
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE $1`, fx.Token+"%"); err != nil {
			t.Errorf("membership users cleanup: %v", err)
		}
	})

	contract(t, "CreateOrgMembership/grant", func(ctx context.Context) error {
		m, err := store.CreateOrgMembership(ctx, OrgMembership{UserID: u1.ID, OrgID: fx.OrgA, Role: RoleReader})
		if err != nil {
			return err
		}
		if m.ID == "" || m.Role != RoleReader {
			t.Errorf("CreateOrgMembership/grant: unexpected row %+v", m)
		}
		return nil
	})
	contract(t, "CreateOrgMembership/second-org", func(ctx context.Context) error {
		_, err := store.CreateOrgMembership(ctx, OrgMembership{UserID: u1.ID, OrgID: fx.OrgB, Role: RoleOrgAdmin})
		return err
	})
	contract(t, "CreateOrgMembership/second-user", func(ctx context.Context) error {
		_, err := store.CreateOrgMembership(ctx, OrgMembership{UserID: u2.ID, OrgID: fx.OrgA, Role: RoleOperator})
		return err
	})
	contract(t, "CreateOrgMembership/duplicate", func(ctx context.Context) error {
		_, err := store.CreateOrgMembership(ctx, OrgMembership{UserID: u1.ID, OrgID: fx.OrgA, Role: RoleReader})
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("CreateOrgMembership/duplicate: want unique-conflict answer, got %v", err)
		}
		return nil
	})
	contract(t, "CreateOrgMembership/invalid-role", func(ctx context.Context) error {
		_, err := store.CreateOrgMembership(ctx, OrgMembership{UserID: u2.ID, OrgID: fx.OrgB, Role: OrgRole("superuser")})
		if err == nil || !strings.Contains(err.Error(), "invalid role") {
			t.Errorf("CreateOrgMembership/invalid-role: want validation error, got %v", err)
		}
		return nil
	})

	contract(t, "SetOrgMembership/insert", func(ctx context.Context) error {
		m, err := store.SetOrgMembership(ctx, u2.ID, fx.OrgB, RolePartner)
		if err != nil {
			return err
		}
		if m.Role != RolePartner {
			t.Errorf("SetOrgMembership/insert: role %q", m.Role)
		}
		return nil
	})
	contract(t, "SetOrgMembership/upsert-change", func(ctx context.Context) error {
		m, err := store.SetOrgMembership(ctx, u2.ID, fx.OrgA, RoleOrgAdmin)
		if err != nil {
			return err
		}
		if m.Role != RoleOrgAdmin {
			t.Errorf("SetOrgMembership/upsert: role %q, want org-admin", m.Role)
		}
		return nil
	})

	contract(t, "GetUserOrgRoles/multi-org", func(ctx context.Context) error {
		roles, err := store.GetUserOrgRoles(ctx, u1.ID)
		if err != nil {
			return err
		}
		if roles[fx.OrgA] != RoleReader || roles[fx.OrgB] != RoleOrgAdmin || len(roles) != 2 {
			t.Errorf("GetUserOrgRoles/u1: %v", roles)
		}
		return nil
	})
	contract(t, "GetUserOrgRoles/no-memberships", func(ctx context.Context) error {
		roles, err := store.GetUserOrgRoles(ctx, entitiesUnknownID)
		if err != nil {
			return err
		}
		if len(roles) != 0 {
			t.Errorf("GetUserOrgRoles/none: %v", roles)
		}
		return nil
	})

	contract(t, "ListOrgMembers/orgA", func(ctx context.Context) error {
		members, err := store.ListOrgMembers(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		if len(members) < 2 {
			t.Errorf("ListOrgMembers/orgA: got %d members, want >= 2", len(members))
		}
		return nil
	})
	contract(t, "ListOrgMembers/empty-org", func(ctx context.Context) error {
		members, err := store.ListOrgMembers(ctx, entitiesUnknownID)
		if err != nil {
			return err
		}
		if len(members) != 0 {
			t.Errorf("ListOrgMembers/empty-org: got %d members", len(members))
		}
		return nil
	})

	contract(t, "DeleteOrgMembership/existing", func(ctx context.Context) error {
		return store.DeleteOrgMembership(ctx, u1.ID, fx.OrgB)
	})
	contract(t, "DeleteOrgMembership/missing", func(ctx context.Context) error {
		err := store.DeleteOrgMembership(ctx, u1.ID, fx.OrgB)
		if err != ErrNotFound {
			t.Errorf("DeleteOrgMembership/missing: want ErrNotFound, got %v", err)
		}
		return nil
	})
}
