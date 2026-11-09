package adminstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
)

// ---- pure helpers ----

func TestIsDelegatablePermissionBoundedSubset(t *testing.T) {
	delegatable := []Permission{PermAnalyticsRead, PermRequestsRead, PermRequestsPayloads, PermLineageRead, PermAuditRead}
	for _, p := range delegatable {
		if !IsDelegatablePermission(p) {
			t.Fatalf("permission %s must be delegatable", p)
		}
	}
	// Originals are never delegatable: they stay a separately assigned
	// capability (N04-P04 posture). Neither is any manage permission.
	notDelegatable := []Permission{PermRequestsReadOriginals, PermKeysManage, PermAgentKeysManage, PermMembersManage, PermBudgetsManage, PermRoutingManage, PermPoliciesManage, PermOrgUpdate, Permission("requests.admin")}
	for _, p := range notDelegatable {
		if IsDelegatablePermission(p) {
			t.Fatalf("permission %s must NOT be delegatable", p)
		}
	}
}

func TestNormalizePrincipalDelegationPermissions(t *testing.T) {
	if _, err := normalizePrincipalDelegationPermissions(nil); !errors.Is(err, ErrInvalidPrincipalDelegation) {
		t.Fatalf("empty subset must be invalid, got %v", err)
	}
	if _, err := normalizePrincipalDelegationPermissions([]string{"requests.read", "requests.read_originals"}); !errors.Is(err, ErrInvalidPrincipalDelegation) {
		t.Fatalf("originals in a subset must be rejected, got %v", err)
	}
	got, err := normalizePrincipalDelegationPermissions([]string{"requests.read", "requests.read", "audit.read"})
	if err != nil {
		t.Fatalf("valid subset rejected: %v", err)
	}
	if len(got) != 2 || got[0] != "requests.read" || got[1] != "audit.read" {
		t.Fatalf("dedup/sort mismatch: %v", got)
	}
}

func TestResolveDelegatedRowAccessMatrix(t *testing.T) {
	agent := RequestPayloadSubject{Type: RequestPayloadAgent, AgentID: "agent-1"}
	cases := []struct {
		name          string
		access        RequestPayloadAccess
		wantDelegated bool
		wantPayload   bool
	}{
		{
			name:          "human is never delegated",
			access:        RequestPayloadAccess{UserID: "u1", Grant: true, SubjectType: RequestPayloadHuman},
			wantDelegated: false, wantPayload: true, // payload falls back to Grant
		},
		{
			name:          "delegated agent with payload scope",
			access:        RequestPayloadAccess{Delegated: true, Grant: true, SubjectType: agent.Type, AgentID: agent.AgentID},
			wantDelegated: true, wantPayload: true,
		},
		{
			name:          "delegated agent read-only stays metadata-only",
			access:        RequestPayloadAccess{Delegated: true, SubjectType: agent.Type, AgentID: agent.AgentID},
			wantDelegated: true, wantPayload: false,
		},
		{
			name:          "explicit deny overrides the delegation payload",
			access:        RequestPayloadAccess{Delegated: true, Grant: true, DenyOwnHistory: true, SubjectType: agent.Type, AgentID: agent.AgentID},
			wantDelegated: true, wantPayload: false,
		},
		{
			name:          "empty agent id fails closed",
			access:        RequestPayloadAccess{Delegated: true, Grant: true, SubjectType: agent.Type},
			wantDelegated: false, wantPayload: true, // Grant still applies on the legacy path
		},
		{
			name:          "unmarked subject type fails closed",
			access:        RequestPayloadAccess{Delegated: true, SubjectType: "", AgentID: agent.AgentID},
			wantDelegated: false, wantPayload: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			delegated, payload := resolveDelegatedRowAccess(tc.access)
			if delegated != tc.wantDelegated || payload != tc.wantPayload {
				t.Fatalf("resolveDelegatedRowAccess(%+v) = (%v, %v), want (%v, %v)",
					tc.access, delegated, payload, tc.wantDelegated, tc.wantPayload)
			}
		})
	}
}

// ---- fake DB for the delegation store methods ----

type delegationFakeDB struct {
	mu          sync.Mutex
	delegations []PrincipalDelegation
	// activeAgentKeys mirrors agent_keys.active for the evaluation join.
	activeAgentKeys map[string]bool
	// memberRoles mirrors admin_org_memberships (grantor → org → role).
	memberRoles map[string]map[string]string
	// rootAccounts mirrors admin_users (id → is_root && active).
	rootAccounts map[string]bool
	// evalErr fails the evaluation query (fail-closed check).
	evalErr  error
	lastExec string
}

func newDelegationFakeDB() *delegationFakeDB {
	return &delegationFakeDB{
		activeAgentKeys: map[string]bool{},
		memberRoles:     map[string]map[string]string{},
		rootAccounts:    map[string]bool{},
	}
}

func (db *delegationFakeDB) BeginAuditTx(context.Context) (auditTx, error) {
	return nil, errors.New("no tx in this fake")
}

func (db *delegationFakeDB) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	if strings.Contains(query, "INSERT INTO principal_delegations") {
		// args: org, grantor_type, grantor, subject_type, subject, permissions, expires_at, created_at
		d := PrincipalDelegation{
			ID:          "d-" + args[4].(string),
			OrgID:       args[0].(string),
			GrantorType: args[1].(string),
			GrantorID:   args[2].(string),
			SubjectType: args[3].(string),
			SubjectID:   args[4].(string),
			Permissions: args[5].([]string),
			ExpiresAt:   args[6].(time.Time),
			CreatedAt:   args[7].(time.Time),
		}
		db.delegations = append(db.delegations, d)
		return &mockPGXRow{data: [][]interface{}{{d.ID}}}
	}
	return &mockPGXRow{err: errors.New("unexpected query row: " + query)}
}

func (db *delegationFakeDB) Query(_ context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.evalErr != nil {
		return nil, db.evalErr
	}
	if strings.Contains(query, "FROM principal_delegations d") {
		return db.queryEvaluation(args), nil
	}
	if strings.Contains(query, "FROM principal_delegations WHERE org_id") {
		return db.queryList(args), nil
	}
	return nil, errors.New("unexpected query: " + query)
}

// queryEvaluation mirrors the evaluation SQL: org + subject + permission +
// live row + active agent key, with the grantor authority columns joined in.
func (db *delegationFakeDB) queryEvaluation(args []interface{}) pgx.Rows {
	orgID, subjectType, subjectID := args[0].(string), args[1].(string), args[2].(string)
	perm, now := args[3].(string), args[4].(time.Time)
	rows := &mockPGXRows{}
	for _, d := range db.delegations {
		if d.OrgID != orgID || d.SubjectType != subjectType || d.SubjectID != subjectID {
			continue
		}
		if !containsString(d.Permissions, perm) {
			continue
		}
		if d.RevokedAt != nil || !now.Before(d.ExpiresAt) {
			continue
		}
		if !db.activeAgentKeys[d.SubjectID] {
			continue // JOIN agent_keys k.active = true fails
		}
		role := db.memberRoles[d.GrantorID][d.OrgID]
		rootActive := db.rootAccounts[d.GrantorID]
		rows.data = append(rows.data, []interface{}{d.ID, d.GrantorType, role, rootActive, rootActive})
	}
	return rows
}

func (db *delegationFakeDB) queryList(args []interface{}) pgx.Rows {
	orgID := args[0].(string)
	rows := &mockPGXRows{}
	for _, d := range db.delegations {
		if d.OrgID != orgID {
			continue
		}
		if len(args) > 1 && d.SubjectID != args[1].(string) {
			continue
		}
		var revoked *time.Time
		if d.RevokedAt != nil {
			t := *d.RevokedAt
			revoked = &t
		}
		rows.data = append(rows.data, []interface{}{d.ID, d.OrgID, d.GrantorType, d.GrantorID, d.SubjectType, d.SubjectID, d.Permissions, d.ExpiresAt, d.CreatedAt, revoked})
	}
	return rows
}

func (db *delegationFakeDB) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.lastExec = query
	if strings.Contains(query, "UPDATE principal_delegations SET revoked_at") {
		id, orgID := args[0].(string), args[1].(string)
		now := args[2].(time.Time)
		for i := range db.delegations {
			d := &db.delegations[i]
			if d.ID == id && d.OrgID == orgID && d.RevokedAt == nil {
				d.RevokedAt = &now
				return pgconn.NewCommandTag("UPDATE 1"), nil
			}
		}
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	return pgconn.NewCommandTag("OK"), nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func newDelegationTestStore(db *delegationFakeDB) *Store {
	if db == nil {
		// A typed-nil pointer must become a nil pgxdb interface so the
		// fail-closed path is actually exercised.
		return newForTest(nil, nil, nil)
	}
	return newForTest(db, nil, nil)
}

// ---- CreatePrincipalDelegation ----

func TestCreatePrincipalDelegationFailClosedWithoutStore(t *testing.T) {
	if _, err := newDelegationTestStore(nil).CreatePrincipalDelegation(context.Background(), PrincipalDelegationCreateParams{OrgID: "org", GrantorID: "g", SubjectID: "s", GrantorType: PrincipalDelegationGrantorAdmin, SubjectType: PrincipalDelegationSubjectAgent, Permissions: []string{"requests.read"}, TTL: time.Minute}, time.Now()); !errors.Is(err, ErrPrincipalDelegationUnavailable) {
		t.Fatalf("nil db must be unavailable, got %v", err)
	}
}

func TestCreatePrincipalDelegationValidation(t *testing.T) {
	db := newDelegationFakeDB()
	now := time.Now().UTC()
	base := PrincipalDelegationCreateParams{
		OrgID: "org-1", GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: "admin-1",
		SubjectType: PrincipalDelegationSubjectAgent, SubjectID: "agent-1",
		Permissions: []string{"requests.read"}, TTL: time.Hour,
	}
	if _, err := newDelegationTestStore(db).CreatePrincipalDelegation(context.Background(), base, now); err != nil {
		t.Fatalf("valid create rejected: %v", err)
	}
	if len(db.delegations) != 1 || db.delegations[0].ID != "d-agent-1" {
		t.Fatalf("valid create must persist one row, got %+v", db.delegations)
	}
	bad := []struct {
		name   string
		mutate func(*PrincipalDelegationCreateParams)
	}{
		{"empty org", func(p *PrincipalDelegationCreateParams) { p.OrgID = "" }},
		{"empty subject", func(p *PrincipalDelegationCreateParams) { p.SubjectID = "" }},
		{"bad grantor type", func(p *PrincipalDelegationCreateParams) { p.GrantorType = "agent" }},
		{"bad subject type", func(p *PrincipalDelegationCreateParams) { p.SubjectType = "human" }},
		{"non-delegatable permission", func(p *PrincipalDelegationCreateParams) { p.Permissions = []string{"requests.read_originals"} }},
		{"empty permissions", func(p *PrincipalDelegationCreateParams) { p.Permissions = nil }},
		{"zero ttl", func(p *PrincipalDelegationCreateParams) { p.TTL = 0 }},
		{"ttl beyond bound", func(p *PrincipalDelegationCreateParams) { p.TTL = MaxPrincipalDelegationTTL + time.Second }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if _, err := newDelegationTestStore(db).CreatePrincipalDelegation(context.Background(), p, now); !errors.Is(err, ErrInvalidPrincipalDelegation) {
				t.Fatalf("expected invalid, got %v", err)
			}
		})
	}
	if len(db.delegations) != 1 {
		t.Fatalf("invalid creates must not persist rows, got %d", len(db.delegations))
	}
}

// ---- EvaluatePrincipalDelegation ----

func TestEvaluatePrincipalDelegationChainAndCascade(t *testing.T) {
	db := newDelegationFakeDB()
	store := newDelegationTestStore(db)
	now := time.Now().UTC()
	live := PrincipalDelegation{
		ID: "d-live", OrgID: "org-1", GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: "admin-1",
		SubjectType: PrincipalDelegationSubjectAgent, SubjectID: "agent-1",
		Permissions: []string{"requests.read", "requests.read_payloads"},
		ExpiresAt:   now.Add(time.Hour),
	}
	revokedAt := now.Add(-time.Minute)
	revoked := live
	revoked.ID, revoked.RevokedAt = "d-revoked", &revokedAt
	expired := live
	expired.ID, expired.ExpiresAt = "d-expired", now.Add(-time.Second)
	wrongOrg := live
	wrongOrg.ID, wrongOrg.OrgID = "d-org2", "org-2"
	wrongSubject := live
	wrongSubject.ID, wrongSubject.SubjectID = "d-other", "agent-2"
	ciSubject := live
	ciSubject.ID, ciSubject.SubjectID, ciSubject.SubjectType = "d-ci", "agent-2", PrincipalDelegationSubjectCI
	db.delegations = []PrincipalDelegation{live, revoked, expired, wrongOrg, wrongSubject, ciSubject}
	db.activeAgentKeys["agent-1"] = true
	db.memberRoles["admin-1"] = map[string]string{"org-1": string(RoleOrgAdmin)}

	t.Run("admin grantor holding the role grants", func(t *testing.T) {
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || !ok {
			t.Fatalf("expected grant, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("permission must be inside the delegated subset", func(t *testing.T) {
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermAuditRead, now)
		if err != nil || ok {
			t.Fatalf("permission outside the subset must deny, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("revocation cascades at the next evaluation", func(t *testing.T) {
		if err := store.RevokePrincipalDelegation(context.Background(), "d-live", "org-1", now); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || ok {
			t.Fatalf("revoked delegation must deny, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("expired delegation denies", func(t *testing.T) {
		db.delegations[0].RevokedAt = nil // restore the live row for clarity
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now.Add(2*time.Hour))
		if err != nil || ok {
			t.Fatalf("expired delegation must deny, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("delegator losing the role cascades immediately", func(t *testing.T) {
		// reader still holds requests.read — that grant legitimately survives.
		db.memberRoles["admin-1"] = map[string]string{"org-1": string(RoleReader)}
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || !ok {
			t.Fatalf("a role still holding the permission must keep granting, got ok=%v err=%v", ok, err)
		}
		// ...but requests.read_payloads is gone with the demotion.
		ok, err = store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsPayloads, now)
		if err != nil || ok {
			t.Fatalf("demoted grantor must cascade to denial, got ok=%v err=%v", ok, err)
		}
		delete(db.memberRoles, "admin-1") // membership removed entirely
		ok, err = store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || ok {
			t.Fatalf("removed grantor membership must cascade to denial, got ok=%v err=%v", ok, err)
		}
		db.memberRoles["admin-1"] = map[string]string{"org-1": string(RoleOrgAdmin)}
	})
	t.Run("subject type mismatch denies", func(t *testing.T) {
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "ci", "agent-1", PermRequestsRead, now)
		if err != nil || ok {
			t.Fatalf("ci subject must not consume an agent delegation, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("revoked agent key cascades", func(t *testing.T) {
		db.activeAgentKeys["agent-1"] = false
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || ok {
			t.Fatalf("revoked delegate key must deny, got ok=%v err=%v", ok, err)
		}
		db.activeAgentKeys["agent-1"] = true
	})
	t.Run("root grantor holds while root+active and cascades on demotion", func(t *testing.T) {
		db.delegations[0].GrantorType = PrincipalDelegationGrantorRoot
		db.rootAccounts["admin-1"] = true
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || !ok {
			t.Fatalf("active root grantor must grant, got ok=%v err=%v", ok, err)
		}
		db.rootAccounts["admin-1"] = false // demoted from root
		ok, err = store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err != nil || ok {
			t.Fatalf("demoted root grantor must cascade to denial, got ok=%v err=%v", ok, err)
		}
		db.delegations[0].GrantorType = PrincipalDelegationGrantorAdmin
	})
	t.Run("store error fails closed", func(t *testing.T) {
		db.evalErr = errors.New("db down")
		ok, err := store.EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err == nil || ok {
			t.Fatalf("store error must fail closed, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("unavailable store fails closed", func(t *testing.T) {
		ok, err := newDelegationTestStore(nil).EvaluatePrincipalDelegation(context.Background(), "org-1", "agent", "agent-1", PermRequestsRead, now)
		if err == nil || ok {
			t.Fatalf("nil db must fail closed, got ok=%v err=%v", ok, err)
		}
	})
}

func TestRevokePrincipalDelegationNotFoundAndUnknown(t *testing.T) {
	db := newDelegationFakeDB()
	store := newDelegationTestStore(db)
	now := time.Now().UTC()
	if err := store.RevokePrincipalDelegation(context.Background(), "missing", "org-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown delegation must be ErrNotFound, got %v", err)
	}
	db.delegations = append(db.delegations, PrincipalDelegation{ID: "d-1", OrgID: "org-1", ExpiresAt: now.Add(time.Hour)})
	if err := store.RevokePrincipalDelegation(context.Background(), "d-1", "org-2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign-org revoke must be ErrNotFound, got %v", err)
	}
	if err := store.RevokePrincipalDelegation(context.Background(), "d-1", "org-1", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := store.RevokePrincipalDelegation(context.Background(), "d-1", "org-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke must be ErrNotFound, got %v", err)
	}
	if err := store.RevokePrincipalDelegation(context.Background(), "", "org-1", now); !errors.Is(err, ErrInvalidPrincipalDelegation) {
		t.Fatalf("empty id must be invalid, got %v", err)
	}
}

// ---- list WHERE scoping (pure) ----

func TestRequestListWhereDelegatedScoping(t *testing.T) {
	f := RequestListFilters{OrgID: "org-1", DelegateAgentID: "agent-1", PayloadAuthorizationSet: true, PayloadSearchAllowed: true, ContentSearch: "secret"}
	w, args := requestListWhere(f)
	if !strings.Contains(w, "agent_id::text = $") {
		t.Fatalf("delegated subject rows must be pinned to their own attribution: %s", w)
	}
	if !strings.Contains(w, "rl.agent_id::text = $") {
		t.Fatalf("content search under a delegation must stay agent-scoped: %s", w)
	}
	if !containsArg(args, "agent-1") {
		t.Fatalf("the trusted attribution value must be bound as a parameter: %v", args)
	}

	// The client-controlled ?agent_id filter can never substitute for the
	// trusted delegation scope: without DelegateAgentID there is no pin.
	f2 := RequestListFilters{OrgID: "org-1", AgentID: "agent-1", PayloadAuthorizationSet: true}
	w2, _ := requestListWhere(f2)
	if strings.Count(w2, "agent_id::text = $") != 1 {
		t.Fatalf("a client filter alone must not create a delegation scope: %s", w2)
	}
}

func containsArg(args []interface{}, want string) bool {
	for _, a := range args {
		if s, ok := a.(string); ok && s == want {
			return true
		}
	}
	return false
}
