package trcli

// disposable testcontainers Postgres (pkg/testdb stand, fully migrated).
// Covers the store-side half the fake cannot prove: the byte-exact YAML
// round-trip through Postgres (idempotency), the version/attachment store
// semantics reconcile relies on, drift convergence on real rows and prune.
// Skips in -short mode and without Docker (repo convention).

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func newReconcileIntStore(t *testing.T) (*adminstore.Store, string) {
	t.Helper()
	pool := testdb.Postgres(t)
	// The shared stand: other packages may have dropped the wallet table the
	// orgs LEFT JOIN reads (repo-wide shared-DB caveat, QG2-B3).
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id text PRIMARY KEY,
			balance_cents bigint DEFAULT 0 NOT NULL,
			updated_at timestamptz DEFAULT now() NOT NULL
		)`)
	if err != nil {
		t.Fatalf("ensure org_credits: %v", err)
	}
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	slug := fmt.Sprintf("op10-%d", time.Now().UnixNano())
	org, err := store.CreateOrganization(context.Background(), "OP-10 Reconcile", slug)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM organizations WHERE id::text = ANY($1)", []string{org.ID})
	})
	return store, slug
}

func writeIntDecl(t *testing.T, dir, slug, content string) {
	t.Helper()
	if err := os.MkdirAll(dir+"/"+slug, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dir+"/"+slug+"/pii-guard.yaml", []byte(content), 0o600); err != nil {
		t.Fatalf("write decl: %v", err)
	}
}

// TestPoliciesReconcile_Integration: apply → verify → reconcile ×2 = 0 diff
// on the real store, then drift convergence, then prune.
func TestPoliciesReconcile_Integration(t *testing.T) {
	store, slug := newReconcileIntStore(t)
	dir := t.TempDir()
	writeIntDecl(t, dir, slug, declPIIGuard)
	ctx := context.Background()

	apply := func(mutate func(*policiesReconcileOptions)) string {
		t.Helper()
		opts := reconcileOpts(dir, func(o *policiesReconcileOptions) {
			o.Apply = true
			o.Org = slug
			if mutate != nil {
				mutate(o)
			}
		})
		var sb strings.Builder
		if err := runPoliciesReconcile(ctx, store, opts, &sb); err != nil {
			t.Fatalf("reconcile: %v\n%s", err, sb.String())
		}
		return sb.String()
	}

	// Apply: policy stored VERBATIM (first document), v1 active, attached.
	apply(nil)
	policies, err := store.ListPolicies(ctx, orgIDBySlug(t, store, slug))
	if err != nil || len(policies) != 1 {
		t.Fatalf("list after apply: %v (%d policies)", err, len(policies))
	}
	p := policies[0]
	if p.CurrentVersion != 1 {
		t.Fatalf("v1 must be active, current=%d", p.CurrentVersion)
	}
	versions, err := store.ListPolicyVersions(ctx, orgIDBySlug(t, store, slug), p.ID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions after apply: %v", err)
	}
	if versions[0].YAML != declPIIPolicy {
		t.Fatalf("stored YAML is not the verbatim first document:\n%q", versions[0].YAML)
	}
	atts, err := store.ListPolicyAttachments(ctx, orgIDBySlug(t, store, slug), p.ID)
	if err != nil || len(atts) != 1 || atts[0].Endpoint != "chat" {
		t.Fatalf("attachments after apply: %v (%+v)", err, atts)
	}

	// Reconcile ×2 = 0 diff on the real store (byte-exact round-trip).
	out := apply(nil)
	if !strings.Contains(out, "unchanged=1") || strings.Contains(out, "update pii-guard") {
		t.Fatalf("second apply is not a no-op:\n%s", out)
	}

	// Drift: a manual DB edit past git (UI-authored version) is reported and
	// converged by a new git version; the diverged version stays in history.
	if _, err := store.CreatePolicyVersion(ctx, orgIDBySlug(t, store, slug), p.ID, declPIIGuardV2, "", "admin@ui"); err != nil {
		t.Fatalf("seed ui edit: %v", err)
	}
	opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Org = slug })
	var sb strings.Builder
	if err := runPoliciesReconcile(ctx, store, opts, &sb); err != nil {
		t.Fatalf("dry-run after ui edit: %v\n%s", err, sb.String())
	}
	if !strings.Contains(sb.String(), "DRIFT") {
		t.Fatalf("drift not reported on the real store:\n%s", sb.String())
	}
	apply(nil)
	versions, err = store.ListPolicyVersions(ctx, orgIDBySlug(t, store, slug), p.ID)
	if err != nil || len(versions) != 3 {
		t.Fatalf("want 3 versions after convergence: %v (%d)", err, len(versions))
	}
	if versions[0].GitSHA == "" || versions[0].YAML != declPIIPolicy {
		t.Fatalf("latest version must be git-authored with the declaration content: %+v", versions[0])
	}
	if versions[1].CreatedBy != "admin@ui" {
		t.Fatalf("the UI edit must survive in history: %+v", versions[1])
	}

	// Prune: removing the declaration makes the policy a prune candidate;
	// --prune --apply deletes it.
	if err := os.Remove(dir + "/" + slug + "/pii-guard.yaml"); err != nil {
		t.Fatalf("remove decl: %v", err)
	}
	apply(func(o *policiesReconcileOptions) { o.Prune = true })
	policies, err = store.ListPolicies(ctx, orgIDBySlug(t, store, slug))
	if err != nil || len(policies) != 0 {
		t.Fatalf("prune did not delete: %v (%d policies)", err, len(policies))
	}
}

func orgIDBySlug(t *testing.T, store *adminstore.Store, slug string) string {
	t.Helper()
	org, err := store.GetOrganizationBySlug(context.Background(), slug)
	if err != nil {
		t.Fatalf("org by slug: %v", err)
	}
	return org.ID
}
