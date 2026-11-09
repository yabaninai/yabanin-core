package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// mode "RLS seed bootstrap несовместимы с чистой БД" — a baseline that
// region- or org-locks the seeded tables breaks every fresh install, because
// the seed pool (services/run.openSeedPool) intentionally sets no app.region /
// app.current_org GUC and the seeded-table inserts run as a non-bypassrls
// role. The unified baseline (0001_init) must therefore keep every table the
// seed writes outside ROW LEVEL SECURITY. This structural audit pins that
// invariant against the embedded SQL itself (no database needed) so a future
// re-squash cannot silently violate it.
//
// mis-baselined baseline (a seeded table RLS-locked by a future re-squash)
// and PASS on the shipped one — the check distinguishes broken from fixed.

// baselineSeedTables lists every table the seed path writes on a fresh
// install: services/run/seed.go ApplySeed (org, team, budget, model, credits,
// API key, admin) plus the beta starter grant (credits.EnsureStarterGrant).
var baselineSeedTables = []string{
	"organizations",
	"organizations_teams",
	"team_budgets",
	"models_registry",
	"org_credits",
	"credit_transactions",
	"api_keys",
	"admin_users",
}

var (
	// Matches "ALTER TABLE [ONLY] public.<name> ... ROW LEVEL SECURITY;"
	// (both the ENABLE and FORCE forms in the pg_dump baseline).
	baselineRLSRe = regexp.MustCompile(`(?m)^ALTER TABLE (?:ONLY )?public\.(\w+) \w+ ROW LEVEL SECURITY;`)
	// Matches "CREATE POLICY <name> ON public.<name> ...".
	baselinePolicyRe = regexp.MustCompile(`(?m)^CREATE POLICY \S+ ON (?:ONLY )?public\.(\w+)`)
)

// auditBaselineSeedRLS scans every .sql file under "migrations" in fsys and
// returns nil only when the baseline keeps a non-empty RLS posture AND none
// of the seed-path tables is RLS-enabled/forced or carries a row-level
// policy. It is the single decision core shared by the shipped-baseline
// guard and the mis-baseline mutation test below.
func auditBaselineSeedRLS(fsys fs.ReadFileFS) error {
	seedSet := map[string]bool{}
	for _, tbl := range baselineSeedTables {
		seedSet[tbl] = true
	}

	var rlsTables, policyTables []string
	err := fs.WalkDir(fsys, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(d.Name(), ".sql") {
			return nil
		}
		body, err := fsys.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		for _, m := range baselineRLSRe.FindAllStringSubmatch(text, -1) {
			rlsTables = append(rlsTables, m[1])
		}
		for _, m := range baselinePolicyRe.FindAllStringSubmatch(text, -1) {
			policyTables = append(policyTables, m[1])
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk migrations: %w", err)
	}

	sort.Strings(rlsTables)
	if len(rlsTables) == 0 {
		return fmt.Errorf("baseline lost its RLS posture: no ENABLE/FORCE ROW LEVEL SECURITY statement found")
	}

	var violations []string
	for _, tbl := range rlsTables {
		if seedSet[tbl] {
			violations = append(violations, "seeded table has RLS enabled/forced: "+tbl)
		}
	}
	for _, tbl := range policyTables {
		if seedSet[tbl] {
			violations = append(violations, "seeded table has a row-level policy: "+tbl)
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("baseline would break clean-DB seed (RLS seed bootstrap failure mode): %s",
			strings.Join(violations, "; "))
	}
	return nil
}

// TestBaseline_SeedTablesNotRLSLocked asserts the seed-compatibility
// invariant on the embedded baseline SQL: no ENABLE/FORCE ROW LEVEL SECURITY
// and no CREATE POLICY may reference a seeded table. It also asserts the RLS
// posture itself is present (non-empty), so the invariant cannot be satisfied
// by accidentally dropping all RLS from the baseline.
func TestBaseline_SeedTablesNotRLSLocked(t *testing.T) {
	if err := auditBaselineSeedRLS(migrationsFS); err != nil {
		t.Fatal(err.Error())
	}
}

// negative evidence for the audit itself: the same decision core must accept
// a correct baseline (regional RLS only) and reject every mis-baseline
// shape a future re-squash could produce — ENABLE or FORCE RLS on a seeded
// table, a policy on a seeded table — plus a baseline that lost its RLS
// posture entirely. Without this self-test a broken refactor of the audit
// (e.g. an over-broad regex) could go green while the invariant no longer
// holds.
func TestBaselineSeedRLSCheck_DistinguishesBrokenFromFixed(t *testing.T) {
	fixedBaseline := `
CREATE TABLE public.request_logs (id bigint);
CREATE TABLE public.organizations (id uuid);
CREATE TABLE public.api_keys (id uuid);
ALTER TABLE public.request_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.request_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY region_isolation ON public.request_logs
  USING (home_region = current_setting('app.region', true))
  WITH CHECK (home_region = current_setting('app.region', true));
`
	if err := auditBaselineSeedRLS(mapFS("migrations/0001_init.up.sql", fixedBaseline)); err != nil {
		t.Fatalf("correct baseline (regional RLS only) must pass the audit: %v", err)
	}

	cases := []struct {
		name        string
		misBaseline string
		wantTable   string
	}{
		{
			name: "enable RLS on a seeded table",
			misBaseline: fixedBaseline +
				"ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;\n",
			wantTable: "organizations",
		},
		{
			name: "force RLS on a seeded table",
			misBaseline: fixedBaseline +
				"ALTER TABLE ONLY public.api_keys FORCE ROW LEVEL SECURITY;\n",
			wantTable: "api_keys",
		},
		{
			name: "policy on a seeded table",
			misBaseline: fixedBaseline +
				"CREATE POLICY org_isolation ON public.organizations USING (true);\n",
			wantTable: "organizations",
		},
	}
	for _, tc := range cases {
		err := auditBaselineSeedRLS(mapFS("migrations/0001_init.up.sql", tc.misBaseline))
		if err == nil {
			t.Fatalf("%s: audit must flag the mis-baselined baseline", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantTable) {
			t.Fatalf("%s: audit must name the violated table %q, got: %v", tc.name, tc.wantTable, err)
		}
		if !strings.Contains(err.Error(), "RLS seed bootstrap failure mode") {
			t.Fatalf("%s: audit must carry the failure-mode diagnosis, got: %v", tc.name, err)
		}
	}

	// A baseline that lost RLS entirely must not satisfy the audit by
	// trivially having no conflicts.
	empty := auditBaselineSeedRLS(mapFS("migrations/0001_init.up.sql",
		"CREATE TABLE public.organizations (id uuid);\nCREATE TABLE public.request_logs (id bigint);\n"))
	if empty == nil || !strings.Contains(empty.Error(), "RLS posture") {
		t.Fatalf("audit must reject an RLS-free baseline, got: %v", empty)
	}
}

// mapFS builds the minimal embedded-migrations lookalike for the audit.
func mapFS(name, body string) fstest.MapFS {
	return fstest.MapFS{name: &fstest.MapFile{Data: []byte(body)}}
}
