package adminstore

// N04-P05-T07 (RV-n04p5c must-track): the delegation SQL runs for real here.
// delegations_test.go mirrors the queries in fakes, so row shapes, NULL
// semantics (LEFT JOIN membership, COALESCE(is_root)), FK enforcement, CHECK
// constraints and real timestamp comparison were never exercised. This suite
// drives the production store against the fully migrated disposable Postgres
// (testdb.Postgres): create → evaluate (allow / outside-subset deny / expired
// / revoked) → grantor cascades (demotion, membership removal, root flag,
// deactivation) → subject-key cascade → revoke → the 0015 TTL schema bound →
// concurrent issuance/evaluation.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// delegationIntWorld is one isolated slice of the shared stand: an org, an
// org-admin grantor, a root grantor and two subject keys. Every name carries
// a per-run token; cleanup removes exactly the seeded rows (delegations
// first — their FKs are NO ACTION — then users, then the org, which cascades
// memberships and agent keys).
type delegationIntWorld struct {
	pool  *pgxpool.Pool
	store *Store
	org   *Organization
	// org2 exists so foreign-org scoping (revoke/evaluate) is exercised on
	// real rows, not just empty results.
	org2        *Organization
	admin       *AdminUser // org-admin grantor on org
	adminNoRole *AdminUser // admin account with NO membership anywhere
	root        *AdminUser // root grantor
	key         *AgentKey  // "agent" subject
	ciKey       *AgentKey  // "ci" subject
}

func seedDelegationIntWorld(t *testing.T) *delegationIntWorld {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	token := fmt.Sprintf("dli07%x", time.Now().UnixNano())

	org, err := store.CreateOrganization(ctx, "dli07 org "+token, "dli07-"+token)
	require.NoError(t, err)
	org2, err := store.CreateOrganization(ctx, "dli07 org2 "+token, "dli07b-"+token)
	require.NoError(t, err)
	admin, err := store.CreateAdminUser(ctx, token+"-admin@example.com", "dli07 admin", "hash", false)
	require.NoError(t, err)
	adminNoRole, err := store.CreateAdminUser(ctx, token+"-norole@example.com", "dli07 norole", "hash", false)
	require.NoError(t, err)
	root, err := store.CreateAdminUser(ctx, token+"-root@example.com", "dli07 root", "hash", true)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, OrgMembership{UserID: admin.ID, OrgID: org.ID, Role: RoleOrgAdmin})
	require.NoError(t, err)
	key, err := store.CreateAgentKey(ctx, "hash-"+token+"-key", "dli07 worker", org.ID)
	require.NoError(t, err)
	ciKey, err := store.CreateAgentKey(ctx, "hash-"+token+"-ci", "dli07 ci", org.ID)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for orgID := range map[string]bool{org.ID: true, org2.ID: true} {
			_, _ = pool.Exec(cleanupCtx, `DELETE FROM principal_delegations WHERE org_id = $1`, orgID)
			_, _ = pool.Exec(cleanupCtx, `DELETE FROM request_logs WHERE org_id = $1`, orgID)
		}
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM admin_users WHERE id::text = ANY($1)`,
			[]string{admin.ID, adminNoRole.ID, root.ID})
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM organizations WHERE id::text = ANY($1)`,
			[]string{org.ID, org2.ID})
	})
	return &delegationIntWorld{
		pool: pool, store: store, org: org, org2: org2,
		admin: admin, adminNoRole: adminNoRole, root: root, key: key, ciKey: ciKey,
	}
}

// delegationIntCreate is the common valid create: admin grantor, agent
// subject, the given subset, one hour.
func delegationIntCreate(ctx context.Context, t *testing.T, w *delegationIntWorld, perms []string) *PrincipalDelegation {
	t.Helper()
	d, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
		OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
		SubjectType: PrincipalDelegationSubjectAgent, SubjectID: w.key.ID,
		Permissions: perms, TTL: time.Hour,
	}, time.Now().UTC())
	require.NoError(t, err)
	return d
}

// delegationIntSubject mints a fresh subject key: evaluation is an OR over a
// subject's candidate rows, so every denial-semantics subtest needs its own
// subject to stay unambiguous.
func delegationIntSubject(ctx context.Context, t *testing.T, w *delegationIntWorld, name string) *AgentKey {
	t.Helper()
	key, err := w.store.CreateAgentKey(ctx,
		"hash-"+name+"-"+fmt.Sprintf("%x", time.Now().UnixNano()), "dli07 "+name, w.org.ID)
	require.NoError(t, err)
	return key
}

// delegationIntCreateFor is delegationIntCreate with an explicit subject key.
func delegationIntCreateFor(ctx context.Context, t *testing.T, w *delegationIntWorld, subject *AgentKey, perms []string) *PrincipalDelegation {
	t.Helper()
	d, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
		OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
		SubjectType: PrincipalDelegationSubjectAgent, SubjectID: subject.ID,
		Permissions: perms, TTL: time.Hour,
	}, time.Now().UTC())
	require.NoError(t, err)
	return d
}

func TestPrincipalDelegationsRealSQLLifecycle_Int(t *testing.T) {
	w := seedDelegationIntWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("insert lands a real row with the exact delegated subset", func(t *testing.T) {
		issued := now
		d, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
			OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
			SubjectType: PrincipalDelegationSubjectAgent, SubjectID: w.key.ID,
			Permissions: []string{string(PermRequestsRead), string(PermAuditRead)}, TTL: time.Hour,
		}, issued)
		require.NoError(t, err)
		require.NotEmpty(t, d.ID)

		// Raw row shape: the fake asserted a mirrored struct, never the
		// persisted columns. Read them back straight from the table.
		var (
			grantorType, subjectType, grantorID, subjectID string
			perms                                          []string
			expiresAt, createdAt                           time.Time
			revokedAt                                      *time.Time
		)
		err = w.pool.QueryRow(ctx, `
			SELECT grantor_type, subject_type, grantor_id::text, subject_id::text,
			       permissions, expires_at, created_at, revoked_at
			FROM principal_delegations WHERE id = $1::uuid`, d.ID).
			Scan(&grantorType, &subjectType, &grantorID, &subjectID, &perms, &expiresAt, &createdAt, &revokedAt)
		require.NoError(t, err)
		require.Equal(t, "admin", grantorType)
		require.Equal(t, "agent", subjectType)
		require.Equal(t, w.admin.ID, grantorID)
		require.Equal(t, w.key.ID, subjectID)
		require.ElementsMatch(t, []string{"requests.read", "audit.read"}, perms,
			"the text[] column must persist exactly the normalized subset")
		require.Nil(t, revokedAt, "a live delegation must have revoked_at IS NULL (real NULL semantics)")
		require.WithinDuration(t, issued.Add(time.Hour), expiresAt, time.Second)
		require.WithinDuration(t, issued, createdAt, time.Second)
	})

	t.Run("evaluation re-derives grantor authority from the joined rows", func(t *testing.T) {
		delegationIntCreate(ctx, t, w, []string{string(PermRequestsRead), string(PermAuditRead)})
		for _, perm := range []Permission{PermRequestsRead, PermAuditRead} {
			ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.key.ID, perm, now)
			require.NoError(t, err, "org-admin holds %s; the JOIN must see it", perm)
			require.True(t, ok, "org-admin grantor + delegated %s must grant", perm)
		}
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.key.ID, PermRequestsPayloads, now)
		require.NoError(t, err)
		require.False(t, ok, "requests.read_payloads is outside the subset AND outside the org-admin role")
	})

	t.Run("foreign keys the fakes never enforced", func(t *testing.T) {
		unknown := "11111111-1111-1111-1111-111111111111"
		for _, tc := range []struct {
			name                  string
			org, grantor, subject string
		}{
			{"unknown grantor", w.org.ID, unknown, w.key.ID},
			{"unknown subject key", w.org.ID, w.admin.ID, unknown},
			{"unknown org", unknown, w.admin.ID, w.key.ID},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
					OrgID: tc.org, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: tc.grantor,
					SubjectType: PrincipalDelegationSubjectAgent, SubjectID: tc.subject,
					Permissions: []string{string(PermRequestsRead)}, TTL: time.Hour,
				}, now)
				require.Error(t, err, "the INSERT must actually run and hit the FK")
				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr)
				require.Equal(t, "23503", pgErr.Code, "foreign_key_violation expected, got %s (%s)", pgErr.Code, pgErr.Message)
			})
		}
	})

	t.Run("left-join NULL semantics deny a grantor without authority", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "norole")
		// No membership at all: m.role joins NULL → COALESCE '' → RoleHas denies.
		_, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
			OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.adminNoRole.ID,
			SubjectType: PrincipalDelegationSubjectAgent, SubjectID: subject.ID,
			Permissions: []string{string(PermRequestsRead)}, TTL: time.Hour,
		}, now)
		require.NoError(t, err)
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "a membership-less grantor must cascade to denial")
		// Positive control on the SAME subject: the denial above is the
		// grantor's missing authority, not a row-shape artifact.
		delegationIntCreateFor(ctx, t, w, subject, []string{string(PermRequestsRead)})
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok, "a grantor holding the role must grant on the same subject")
	})

	t.Run("expiry is a real timestamp comparison with a strict boundary", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "expiry")
		d := delegationIntCreateFor(ctx, t, w, subject, []string{string(PermRequestsRead)})
		// The 0014 CHECK pins expires_at > created_at, so expiry is staged by
		// moving the whole lifetime window (both columns in one statement).
		backdate := func(expiresAt time.Time) {
			t.Helper()
			_, err := w.pool.Exec(ctx,
				`UPDATE principal_delegations SET created_at = $2, expires_at = $3 WHERE id = $1::uuid`,
				d.ID, now.Add(-2*time.Hour), expiresAt)
			require.NoError(t, err)
		}
		// Past the horizon.
		backdate(now.Add(-time.Second))
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "expired delegation must deny")
		// Exactly-at-expiry denies: the SQL predicate is expires_at > $5 (strict).
		backdate(now)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "expires_at == now must deny (strict >)")
		// Live again — proves the denial above was the timestamp, not the row.
		backdate(now.Add(time.Hour))
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.key.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("root grantor needs the is_root flag AND an active row", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "rootgrantor")
		_, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
			OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorRoot, GrantorID: w.root.ID,
			SubjectType: PrincipalDelegationSubjectAgent, SubjectID: subject.ID,
			Permissions: []string{string(PermRequestsRead)}, TTL: time.Hour,
		}, now)
		require.NoError(t, err)
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok, "root + active grantor must grant")

		// Demote from root: the is_root column flips false while the row
		// stays active — the mirror fake could not tell these columns apart.
		_, err = w.pool.Exec(ctx, `UPDATE admin_users SET is_root = false WHERE id = $1`, w.root.ID)
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "root flag removal must cascade")
		_, err = w.pool.Exec(ctx, `UPDATE admin_users SET is_root = true WHERE id = $1`, w.root.ID)
		require.NoError(t, err)

		// Deactivate the account: the row still exists, is_root still true.
		_, err = w.pool.Exec(ctx, `UPDATE admin_users SET active = false WHERE id = $1`, w.root.ID)
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "an existing-but-inactive root account must cascade")
		_, err = w.pool.Exec(ctx, `UPDATE admin_users SET active = true WHERE id = $1`, w.root.ID)
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("demotion and membership removal cascade through the role matrix", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "demote")
		delegationIntCreateFor(ctx, t, w, subject, []string{string(PermRequestsRead), string(PermAuditRead)})
		// Demote to reader: requests.read survives (reader holds it),
		// audit.read dies with the role — exactly the RoleHas matrix.
		_, err := w.store.SetOrgMembership(ctx, w.admin.ID, w.org.ID, RoleReader)
		require.NoError(t, err)
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok, "a role still holding the permission keeps granting")
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermAuditRead, now)
		require.NoError(t, err)
		require.False(t, ok, "reader does not hold audit.read; the demotion cascades")
		// Remove the membership entirely: the LEFT JOIN loses the row.
		require.NoError(t, w.store.DeleteOrgMembership(ctx, w.admin.ID, w.org.ID))
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "removed membership must cascade to denial")
		// Restore the org-admin role for the later subtests.
		_, err = w.store.SetOrgMembership(ctx, w.admin.ID, w.org.ID, RoleOrgAdmin)
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("subject type is part of the row identity", func(t *testing.T) {
		_, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
			OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
			SubjectType: PrincipalDelegationSubjectCI, SubjectID: w.ciKey.ID,
			Permissions: []string{string(PermRequestsRead)}, TTL: time.Hour,
		}, now)
		require.NoError(t, err)
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "ci", w.ciKey.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok, "the ci subject consumes its own delegation")
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.ciKey.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "an agent-typed evaluation must not consume a ci delegation")
	})

	t.Run("deactivated subject key cascades", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "deactivated")
		delegationIntCreateFor(ctx, t, w, subject, []string{string(PermRequestsRead)})
		_, err := w.pool.Exec(ctx, `UPDATE agent_keys SET active = false WHERE id = $1`, subject.ID)
		require.NoError(t, err)
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "the JOIN agent_keys k.active = true must drop the candidate")
		_, err = w.pool.Exec(ctx, `UPDATE agent_keys SET active = true WHERE id = $1`, subject.ID)
		require.NoError(t, err)
		ok, err = w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("revocation stamps the real row and cascades", func(t *testing.T) {
		subject := delegationIntSubject(ctx, t, w, "revoked")
		d := delegationIntCreateFor(ctx, t, w, subject, []string{string(PermRequestsRead)})
		// Foreign-org revoke is ErrNotFound even for a valid id.
		require.ErrorIs(t, w.store.RevokePrincipalDelegation(ctx, d.ID, w.org2.ID, now), ErrNotFound)
		require.NoError(t, w.store.RevokePrincipalDelegation(ctx, d.ID, w.org.ID, now))
		var revokedAt *time.Time
		require.NoError(t, w.pool.QueryRow(ctx,
			`SELECT revoked_at FROM principal_delegations WHERE id = $1::uuid`, d.ID).Scan(&revokedAt))
		require.NotNil(t, revokedAt, "revoke must stamp revoked_at on the real row")
		ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", subject.ID, PermRequestsRead, now)
		require.NoError(t, err)
		require.False(t, ok, "revoked delegation must deny at the next evaluation")
		require.ErrorIs(t, w.store.RevokePrincipalDelegation(ctx, d.ID, w.org.ID, now), ErrNotFound,
			"double revoke must be ErrNotFound (revoked_at IS NULL guard)")
	})

	t.Run("list returns persisted provenance newest first", func(t *testing.T) {
		old := delegationIntCreate(ctx, t, w, []string{string(PermRequestsRead)})
		newer := delegationIntCreate(ctx, t, w, []string{string(PermAuditRead)})
		// Pin distinct created_at values so the order is deterministic
		// regardless of statement timing (newer lands in the future, past
		// every other row's real clock stamp).
		_, err := w.pool.Exec(ctx, `UPDATE principal_delegations SET created_at = $2 WHERE id = $1::uuid`, old.ID, now.Add(-2*time.Hour))
		require.NoError(t, err)
		_, err = w.pool.Exec(ctx, `UPDATE principal_delegations SET created_at = $2 WHERE id = $1::uuid`, newer.ID, now.Add(time.Hour))
		require.NoError(t, err)
		all, err := w.store.ListPrincipalDelegations(ctx, w.org.ID, "")
		require.NoError(t, err)
		require.NotEmpty(t, all)
		require.Equal(t, newer.ID, all[0].ID, "newest first")
		require.Len(t, all[0].Permissions, 1)
		require.Equal(t, w.org.ID, all[0].OrgID)

		narrowed, err := w.store.ListPrincipalDelegations(ctx, w.org.ID, w.ciKey.ID)
		require.NoError(t, err)
		require.NotEmpty(t, narrowed)
		for _, d := range narrowed {
			require.Equal(t, w.ciKey.ID, d.SubjectID, "subject narrowing must hold")
		}
	})
}

// TestPrincipalDelegationsRealDBTTLSchemaBound_Int pins the two schema-side
// lifetime constraints on the migrated stand: 0014's (expires_at >
// created_at) and 0015's TTL ceiling (expires_at <= created_at + 30 days).
// The Go-side bound (MaxPrincipalDelegationTTL) is the primary gate; the
// CHECK makes the bound durable against writers that bypass the store.
func TestPrincipalDelegationsRealDBTTLSchemaBound_Int(t *testing.T) {
	w := seedDelegationIntWorld(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// The 0015 constraint must exist under its explicit name.
	var conname string
	require.NoError(t, w.pool.QueryRow(ctx, `
		SELECT conname FROM pg_constraint
		WHERE conrelid = 'principal_delegations'::regclass
		  AND contype = 'c' AND conname = 'principal_delegations_ttl_bound_check'`).
		Scan(&conname), "0015 must add the named TTL bound CHECK")

	insertRaw := func(expiresAt time.Time) error {
		_, err := w.pool.Exec(ctx, `
			INSERT INTO principal_delegations
				(id, org_id, grantor_type, grantor_id, subject_type, subject_id, permissions, expires_at, created_at)
			VALUES (gen_random_uuid(), $1::uuid, 'admin', $2::uuid, 'agent', $3::uuid,
			        ARRAY['requests.read']::text[], $4, $5)`,
			w.org.ID, w.admin.ID, w.key.ID, expiresAt, now)
		return err
	}

	// The boundary is computed BY the database ($1 + interval '30 days') so
	// the test cannot drift from the CHECK by a timezone or DST mismatch.
	var boundary time.Time
	require.NoError(t, w.pool.QueryRow(ctx,
		`SELECT $1::timestamptz + interval '30 days'`, now).Scan(&boundary))

	// 30 days exactly: allowed (the bound is inclusive).
	require.NoError(t, insertRaw(boundary), "a 30-day TTL is inside the schema bound")
	// One microsecond past the boundary: the 0015 CHECK must reject the row.
	err := insertRaw(boundary.Add(time.Microsecond))
	require.Error(t, err, "the TTL CHECK must reject a >30d row written behind the store's back")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code, "check_violation expected, got %s (%s)", pgErr.Code, pgErr.Message)
	// Zero lifetime: 0014's (expires_at > created_at) rejects it.
	err = insertRaw(now)
	require.Error(t, err, "a zero-lifetime delegation must violate expires_at > created_at")
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code)

	// The Go-side bound stays the primary gate and writes nothing.
	for _, ttl := range []time.Duration{0, -time.Hour, MaxPrincipalDelegationTTL + time.Second} {
		_, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
			OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
			SubjectType: PrincipalDelegationSubjectAgent, SubjectID: w.key.ID,
			Permissions: []string{string(PermRequestsRead)}, TTL: ttl,
		}, now)
		require.ErrorIs(t, err, ErrInvalidPrincipalDelegation, "TTL %s must be rejected in Go", ttl)
	}
	// 30 days exactly is accepted by the store too (inclusive bound).
	_, err = w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
		OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
		SubjectType: PrincipalDelegationSubjectAgent, SubjectID: w.key.ID,
		Permissions: []string{string(PermRequestsRead)}, TTL: MaxPrincipalDelegationTTL,
	}, now)
	require.NoError(t, err)
}

// TestPrincipalDelegationsRealDBConcurrentIssueEvaluate_Int drives concurrent
// issuance and evaluation against the real store: no lost updates, no torn
// rows, evaluation answers stay consistent while writers run (run under
// -race by the task gate).
func TestPrincipalDelegationsRealDBConcurrentIssueEvaluate_Int(t *testing.T) {
	w := seedDelegationIntWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const writers, perWriter = 8, 5
	delegatable := DelegatablePermissions()

	errs := make(chan error, writers*perWriter+64)
	var wg sync.WaitGroup
	ids := make(chan string, writers*perWriter)

	// Writers: each issues perWriter single-permission delegations rotated
	// across the delegatable subset.
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				perm := delegatable[(g+i)%len(delegatable)]
				d, err := w.store.CreatePrincipalDelegation(ctx, PrincipalDelegationCreateParams{
					OrgID: w.org.ID, GrantorType: PrincipalDelegationGrantorAdmin, GrantorID: w.admin.ID,
					SubjectType: PrincipalDelegationSubjectAgent, SubjectID: w.key.ID,
					Permissions: []string{string(perm)}, TTL: time.Hour,
				}, now)
				if err != nil {
					errs <- fmt.Errorf("writer %d/%d: %w", g, i, err)
					continue
				}
				ids <- d.ID
			}
		}(g)
	}
	// Readers evaluate concurrently; the store must never return an error
	// just because rows are being written (fail-closed applies to failures,
	// not to concurrency).
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.key.ID, PermRequestsRead, now); err != nil {
					errs <- fmt.Errorf("reader: %w", err)
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatalf("concurrent suite must be error-free: %v", err)
	}
	issued := map[string]bool{}
	for id := range ids {
		require.False(t, issued[id], "the store must return distinct uuids")
		issued[id] = true
	}
	require.Len(t, issued, writers*perWriter)

	// Every issued row is persisted exactly once.
	all, err := w.store.ListPrincipalDelegations(ctx, w.org.ID, w.key.ID)
	require.NoError(t, err)
	count := 0
	for _, d := range all {
		if issued[d.ID] {
			count++
		}
	}
	require.Equal(t, writers*perWriter, count, "every concurrent create must land exactly one row")

	// Concurrent revocation: every id revokes exactly once; after the wave,
	// the delegated permission is fully denied.
	var rwg sync.WaitGroup
	revErrs := make(chan error, len(issued))
	for id := range issued {
		rwg.Add(1)
		go func(id string) {
			defer rwg.Done()
			if err := w.store.RevokePrincipalDelegation(ctx, id, w.org.ID, now); err != nil {
				revErrs <- fmt.Errorf("revoke %s: %w", id, err)
			}
		}(id)
	}
	rwg.Wait()
	close(revErrs)
	for err := range revErrs {
		t.Fatalf("concurrent revoke must be error-free: %v", err)
	}
	ok, err := w.store.EvaluatePrincipalDelegation(ctx, w.org.ID, "agent", w.key.ID, PermRequestsRead, now)
	require.NoError(t, err)
	require.False(t, ok, "after revoking every live delegation the subject must be denied")
}
