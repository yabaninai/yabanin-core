package trcli

// in-memory policystore fake — idempotency (reconcile ×2 = 0 diff),
// create/update/version-bump, attachments/enabled convergence, prune,
// drift detection (a manual DB edit past git is reported and git wins),
// strict declaration validation (file:line errors) and the pack namespace.
// The store-side round-trip (byte-exact YAML through real Postgres) is
// covered by policies_int_test.go on testcontainers.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// fakePolicyStore implements policiesReconcileStore over maps, mimicking the
// store contract the planner relies on: versions newest first, attachments
// by priority, create → v1 draft + CurrentVersion 0 + Enabled false.
type fakePolicyStore struct {
	orgs  map[string]string // slug → org id
	pols  map[string]adminstore.PolicyPipeline
	vers  map[string][]adminstore.PolicyVersion // policyID, stored ASC
	atts  map[string][]adminstore.PolicyAttachment
	seq   int
	names map[string]string // orgID|name → policyID (org-unique names)
	// failVersionCreate injects a CreatePolicyVersion failure (tests).
	failVersionCreate error
}

func newFakePolicyStore(slugs ...string) *fakePolicyStore {
	s := &fakePolicyStore{
		orgs:  map[string]string{},
		pols:  map[string]adminstore.PolicyPipeline{},
		vers:  map[string][]adminstore.PolicyVersion{},
		atts:  map[string][]adminstore.PolicyAttachment{},
		names: map[string]string{},
	}
	for i, slug := range slugs {
		s.orgs[slug] = fmt.Sprintf("org-%d", i+1)
	}
	return s
}

func (s *fakePolicyStore) GetOrganizationBySlug(_ context.Context, slug string) (*adminstore.Organization, error) {
	id, ok := s.orgs[slug]
	if !ok {
		return nil, fmt.Errorf("get organization by slug: %w", adminstore.ErrNotFound)
	}
	return &adminstore.Organization{ID: id, Slug: slug}, nil
}

func (s *fakePolicyStore) CreatePolicy(_ context.Context, orgID, name, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error) {
	if orgID == "" || yamlDoc == "" {
		return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, errors.New("invalid create")
	}
	key := orgID + "|" + name
	if _, taken := s.names[key]; taken {
		return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, fmt.Errorf("policy name %q already exists in this org", name)
	}
	s.seq++
	id := fmt.Sprintf("pol-%d", s.seq)
	p := adminstore.PolicyPipeline{ID: id, OrgID: orgID, Name: name, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.pols[id] = p
	v := adminstore.PolicyVersion{ID: id + "-v1", PolicyID: id, OrgID: orgID, Version: 1, YAML: yamlDoc, GitSHA: gitSHA, Label: adminstore.PolicyLabelDraft, CreatedBy: createdBy, CreatedAt: time.Now()}
	s.vers[id] = []adminstore.PolicyVersion{v}
	s.names[key] = id
	return p, v, nil
}

func (s *fakePolicyStore) GetPolicy(_ context.Context, orgID, policyID string) (adminstore.PolicyPipeline, error) {
	p, ok := s.pols[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	return p, nil
}

func (s *fakePolicyStore) ListPolicies(_ context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	var out []adminstore.PolicyPipeline
	for _, p := range s.pols {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *fakePolicyStore) UpdatePolicy(_ context.Context, orgID, policyID string, enabled bool) (adminstore.PolicyPipeline, error) {
	p, ok := s.pols[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	p.Enabled = enabled
	p.UpdatedAt = time.Now()
	s.pols[policyID] = p
	return p, nil
}

func (s *fakePolicyStore) CreatePolicyVersion(_ context.Context, orgID, policyID, yamlDoc, gitSHA, createdBy string) (adminstore.PolicyVersion, error) {
	if _, ok := s.pols[policyID]; !ok {
		return adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	if s.failVersionCreate != nil {
		return adminstore.PolicyVersion{}, s.failVersionCreate
	}
	list := s.vers[policyID]
	v := adminstore.PolicyVersion{
		ID: fmt.Sprintf("%s-v%d", policyID, len(list)+1), PolicyID: policyID, OrgID: orgID,
		Version: len(list) + 1, YAML: yamlDoc, GitSHA: gitSHA, Label: adminstore.PolicyLabelDraft,
		CreatedBy: createdBy, CreatedAt: time.Now(),
	}
	s.vers[policyID] = append(list, v)
	return v, nil
}

func (s *fakePolicyStore) GetPolicyVersion(_ context.Context, orgID, policyID string, version int) (adminstore.PolicyVersion, error) {
	if _, ok := s.pols[policyID]; !ok {
		return adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	for _, v := range s.vers[policyID] {
		if v.Version == version {
			return v, nil
		}
	}
	return adminstore.PolicyVersion{}, adminstore.ErrNotFound
}

func (s *fakePolicyStore) ListPolicyVersions(_ context.Context, orgID, policyID string) ([]adminstore.PolicyVersion, error) {
	if _, ok := s.pols[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	out := append([]adminstore.PolicyVersion{}, s.vers[policyID]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { // newest first
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *fakePolicyStore) SetActivePolicyVersion(_ context.Context, orgID, policyID string, version int) (adminstore.PolicyPipeline, error) {
	p, ok := s.pols[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	list := s.vers[policyID]
	found := false
	for i := range list {
		switch {
		case list[i].Version == version:
			list[i].Label = adminstore.PolicyLabelActive
			found = true
		case list[i].Label == adminstore.PolicyLabelActive:
			list[i].Label = adminstore.PolicyLabelDraft
		}
	}
	if !found {
		return adminstore.PolicyPipeline{}, adminstore.ErrNotFound
	}
	p.CurrentVersion = version
	s.pols[policyID] = p
	return p, nil
}

func (s *fakePolicyStore) SetPolicyAttachments(_ context.Context, orgID, policyID string, atts []adminstore.PolicyAttachment) ([]adminstore.PolicyAttachment, error) {
	if _, ok := s.pols[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	for _, a := range atts {
		if a.ModelPattern == "" || a.Endpoint == "" || a.Priority < 0 {
			return nil, errors.New("invalid attachment")
		}
	}
	s.atts[policyID] = atts
	return atts, nil
}

func (s *fakePolicyStore) ListPolicyAttachments(_ context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error) {
	if _, ok := s.pols[policyID]; !ok {
		return nil, adminstore.ErrNotFound
	}
	return s.atts[policyID], nil
}

func (s *fakePolicyStore) DeletePolicy(_ context.Context, orgID, policyID string) error {
	p, ok := s.pols[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.ErrNotFound
	}
	delete(s.pols, policyID)
	delete(s.vers, policyID)
	delete(s.atts, policyID)
	return nil
}

// UpdatePolicyCAS mirrors the store's preconditioned PUT over the maps
// on the plain methods — the fake exists to satisfy the same contract).
func (s *fakePolicyStore) UpdatePolicyCAS(ctx context.Context, orgID, policyID string, upd adminstore.PolicyUpdate, expectVersion *int, createdBy string) (adminstore.PolicyPipeline, adminstore.PolicyVersion, error) {
	p, ok := s.pols[policyID]
	if !ok || p.OrgID != orgID {
		return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	if expectVersion != nil && p.CurrentVersion != *expectVersion {
		return p, adminstore.PolicyVersion{}, adminstore.ErrPreconditionFailed
	}
	var appended adminstore.PolicyVersion
	if upd.YAML != nil {
		v, err := s.CreatePolicyVersion(ctx, orgID, policyID, *upd.YAML, "", createdBy)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		appended = v
	}
	if upd.Enabled != nil && *upd.Enabled != p.Enabled {
		updated, err := s.UpdatePolicy(ctx, orgID, policyID, *upd.Enabled)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		p = updated
	}
	if upd.ActiveVersion != nil {
		updated, err := s.SetActivePolicyVersion(ctx, orgID, policyID, *upd.ActiveVersion)
		if err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
		p = updated
	}
	if upd.Attachments != nil {
		if _, err := s.SetPolicyAttachments(ctx, orgID, policyID, *upd.Attachments); err != nil {
			return adminstore.PolicyPipeline{}, adminstore.PolicyVersion{}, err
		}
	}
	return p, appended, nil
}

// --- fixtures -----------------------------------------------------------------

// declPIIPolicy is the policy document only (no reconcile block). Fixtures
// carry no surrounding whitespace: the stored YAML is the trimmed first
// document (byte-exact idempotency compares against exactly this).
const declPIIPolicy = `apiVersion: ypp/v1
kind: Policy
name: pii-guard
mode: shadow
hooks: [pre_upstream]
steps:
  - id: scan
    detector: builtin/pii`

const declPIIGuard = declPIIPolicy + `
---
enabled: false
attachments:
  - key_label: ""
    model_pattern: "*"
    endpoint: chat
    priority: 100
`

const declPIIGuardV2 = declPIIPolicy + `
    params:
      jurisdictions: [ru]`

// writeDecl writes one declaration file under dir/org.
func writeDecl(t *testing.T, dir, org, name, content string) string {
	t.Helper()
	path := dir + "/" + org
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	path += "/" + name
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func reconcileOpts(dir string, mutate func(*policiesReconcileOptions)) policiesReconcileOptions {
	opts := policiesReconcileOptions{Dir: dir, GitSHA: "testsha1", CreatedBy: "op10-test"}
	if mutate != nil {
		mutate(&opts)
	}
	return opts
}

// runReconcile executes runPoliciesReconcile returning combined output.
func runReconcile(t *testing.T, store *fakePolicyStore, opts policiesReconcileOptions) string {
	t.Helper()
	var sb strings.Builder
	if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err != nil {
		t.Fatalf("runPoliciesReconcile: %v\noutput:\n%s", err, sb.String())
	}
	return sb.String()
}

// --- core lifecycle -----------------------------------------------------------

func TestPoliciesReconcile_CreateThenIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")

	// Dry-run: plans add, writes nothing.
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "add    pii-guard") || !strings.Contains(out, "mode=dry-run") {
		t.Fatalf("dry-run plan missing add:\n%s", out)
	}
	if len(store.pols) != 0 {
		t.Fatalf("dry-run wrote %d policies", len(store.pols))
	}

	// Apply: policy + v1 (git_sha recorded) + activated + attachments.
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	p, ok := store.pols["pol-1"]
	if !ok || p.Name != "pii-guard" {
		t.Fatalf("apply state wrong: %+v", store.pols)
	}
	if p.Enabled {
		t.Fatalf("new policy must stay detached (enabled=false): %+v", p)
	}
	versions := store.vers["pol-1"]
	if len(versions) != 1 || versions[0].GitSHA != "testsha1" || versions[0].CreatedBy != "op10-test" {
		t.Fatalf("v1 not recorded with git metadata: %+v", versions)
	}
	if p.CurrentVersion != 1 {
		t.Fatalf("v1 must be activated, current=%d", p.CurrentVersion)
	}
	if atts := store.atts["pol-1"]; len(atts) != 1 || atts[0].Endpoint != "chat" || atts[0].Priority != 100 {
		t.Fatalf("attachments not applied: %+v", store.atts["pol-1"])
	}

	// Reconcile ×2 = 0 diff: second apply/dry-run plans nothing.
	for _, apply := range []bool{false, true} {
		out := runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = apply }))
		if !strings.Contains(out, "pii-guard (in sync)") || !strings.Contains(out, "unchanged=1") {
			t.Fatalf("second run (apply=%t) is not a no-op:\n%s", apply, out)
		}
		if strings.Contains(out, "add ") || strings.Contains(out, "update ") {
			t.Fatalf("second run plans changes:\n%s", out)
		}
	}
	if got := len(store.vers["pol-1"]); got != 1 {
		t.Fatalf("second run appended versions: %d", got)
	}
}

func TestPoliciesReconcile_UpdateBumpsVersion(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))

	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuardV2)
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "update+activate pii-guard") {
		t.Fatalf("plan missing update:\n%s", out)
	}
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))

	versions := store.vers["pol-1"]
	if len(versions) != 2 {
		t.Fatalf("want 2 versions, got %d", len(versions))
	}
	if versions[1].YAML != declPIIGuardV2 || versions[1].GitSHA != "testsha1" {
		t.Fatalf("v2 content/sha wrong: %+v", versions[1])
	}
	if store.pols["pol-1"].CurrentVersion != 2 {
		t.Fatalf("v2 must be active, current=%d", store.pols["pol-1"].CurrentVersion)
	}
	out = runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if !strings.Contains(out, "unchanged=1") {
		t.Fatalf("post-update run is not a no-op:\n%s", out)
	}
}

// --- drift (git wins + drift report) ------------------------------------------

// TestPoliciesReconcile_DriftGitWins: a manual DB edit past git (a version
// authored outside git) is reported as DRIFT and converged by a NEW version
// — the UI edit survives in immutable history, never merged silently.
func TestPoliciesReconcile_DriftGitWins(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))

	// Manual UI-style edit: v2 authored outside git, activated.
	uiEdit := declPIIGuard + "\n# ui tweak\n"
	if _, err := store.CreatePolicyVersion(context.Background(), "org-1", "pol-1", uiEdit, "", "admin@ui"); err != nil {
		t.Fatalf("seed ui edit: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(context.Background(), "org-1", "pol-1", 2); err != nil {
		t.Fatalf("activate ui edit: %v", err)
	}

	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "DRIFT  pii-guard") ||
		!strings.Contains(out, "edited outside git after a reconcile") ||
		!strings.Contains(out, `created_by="admin@ui"`) ||
		!strings.Contains(out, "git wins on apply") {
		t.Fatalf("drift not reported:\n%s", out)
	}
	if !strings.Contains(out, "drift=1") {
		t.Fatalf("drift summary missing:\n%s", out)
	}

	// Apply: git wins via a new version; the diverged v2 stays in history.
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	versions := store.vers["pol-1"]
	if len(versions) != 3 {
		t.Fatalf("want 3 versions (v1 git, v2 ui, v3 git), got %d", len(versions))
	}
	if versions[2].YAML != declPIIPolicy || versions[2].GitSHA != "testsha1" {
		t.Fatalf("v3 must carry git content+sha: %+v", versions[2])
	}
	if versions[1].YAML != uiEdit || versions[1].CreatedBy != "admin@ui" {
		t.Fatalf("the UI edit must survive in history: %+v", versions[1])
	}
	if store.pols["pol-1"].CurrentVersion != 3 {
		t.Fatalf("v3 must be active, current=%d", store.pols["pol-1"].CurrentVersion)
	}
	out = runReconcile(t, store, reconcileOpts(dir, nil))
	if strings.Contains(out, "DRIFT") || !strings.Contains(out, "unchanged=1") {
		t.Fatalf("post-convergence run must be clean:\n%s", out)
	}
}

// TestPoliciesReconcile_DriftNeverReconciled: a UI-native policy (no git
// versions at all) diverging from a new declaration is drift too.
func TestPoliciesReconcile_DriftNeverReconciled(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	if _, _, err := store.CreatePolicy(context.Background(), "org-1", "pii-guard", "apiVersion: ypp/v1\nkind: Policy\nname: pii-guard\nmode: enforce\nsteps: []\n", "", "admin@ui"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "DRIFT") || !strings.Contains(out, "never reconciled from git") {
		t.Fatalf("never-reconciled drift not reported:\n%s", out)
	}
}

// TestPoliciesReconcile_StaleReconcileNoDrift: git moved forward since the
// last reconcile (latest version IS git-authored) — a normal update, not drift.
func TestPoliciesReconcile_StaleReconcileNoDrift(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.GitSHA = "oldsha"; o.Apply = true }))

	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuardV2)
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if strings.Contains(out, "DRIFT") {
		t.Fatalf("a stale git sha is a normal update, not drift:\n%s", out)
	}
	if !strings.Contains(out, "update+activate pii-guard") {
		t.Fatalf("plan missing update:\n%s", out)
	}
}

// --- enabled / attachments convergence -----------------------------------------

func TestPoliciesReconcile_EnabledAndAttachments(t *testing.T) {
	dir := t.TempDir()
	decl := `apiVersion: ypp/v1
kind: Policy
name: pii-guard
mode: shadow
hooks: [pre_upstream]
steps:
  - id: scan
    detector: builtin/pii
---
enabled: true
attachments:
  - key_label: prod
    model_pattern: "gpt*"
    endpoint: chat
    priority: 5
`
	writeDecl(t, dir, "acme", "pii-guard.yaml", decl)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if !store.pols["pol-1"].Enabled {
		t.Fatalf("declared enabled=true not applied")
	}
	if atts := store.atts["pol-1"]; len(atts) != 1 || atts[0].KeyLabel != "prod" || atts[0].ModelPattern != "gpt*" {
		t.Fatalf("attachments wrong: %+v", store.atts["pol-1"])
	}

	// Omitted enabled/attachments keep the DB value (no accidental flip).
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuardV2+"\n")
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if strings.Contains(out, "disable pii-guard") || strings.Contains(out, "attachments pii-guard") {
		t.Fatalf("omitted fields must keep DB values:\n%s", out)
	}

	// Attachment diff plans a replace-all; idempotent after.
	declPrio := strings.Replace(decl, "priority: 5", "priority: 7", 1)
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPrio)
	out = runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "attachments pii-guard") {
		t.Fatalf("attachment diff not planned:\n%s", out)
	}
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if atts := store.atts["pol-1"]; len(atts) != 1 || atts[0].Priority != 7 {
		t.Fatalf("priority not applied: %+v", store.atts["pol-1"])
	}
	out = runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if !strings.Contains(out, "unchanged=1") {
		t.Fatalf("not idempotent after attachments:\n%s", out)
	}

	// Disable flips back; explicit empty attachments clears.
	declOff := strings.Replace(declPrio, "enabled: true", "enabled: false", 1)
	declOff = strings.Replace(declOff, "    endpoint: chat\n    priority: 7", "", 1)
	declOff = strings.Replace(declOff, "attachments:\n  - key_label: prod\n    model_pattern: \"gpt*\"\n", "attachments: []\n", 1)
	writeDecl(t, dir, "acme", "pii-guard.yaml", declOff)
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if store.pols["pol-1"].Enabled {
		t.Fatalf("disable not applied")
	}
	if atts := store.atts["pol-1"]; len(atts) != 0 {
		t.Fatalf("attachments: [] must clear, got %+v", atts)
	}
}

// --- prune ---------------------------------------------------------------------

func TestPoliciesReconcile_Prune(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	if _, _, err := store.CreatePolicy(context.Background(), "org-1", "legacy", "apiVersion: ypp/v1\nkind: Policy\nname: legacy\nmode: shadow\nhooks: [pre_upstream]\nsteps:\n  - id: s\n    detector: builtin/pii\n", "", "ui"); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	// Without --prune: reported as a candidate, never deleted.
	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "legacy (not covered by git; pass --prune to delete)") {
		t.Fatalf("prune candidate not reported:\n%s", out)
	}
	if _, ok := store.pols["pol-1"]; !ok {
		t.Fatalf("legacy deleted without --prune")
	}

	// Dry-run with --prune plans the delete; apply executes it.
	out = runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Prune = true }))
	if !strings.Contains(out, "delete legacy") {
		t.Fatalf("prune plan missing delete:\n%s", out)
	}
	if _, ok := store.pols["pol-1"]; !ok {
		t.Fatalf("dry-run with --prune deleted")
	}
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Prune = true; o.Apply = true }))
	if _, ok := store.pols["pol-1"]; ok {
		t.Fatalf("legacy not deleted with --prune --apply")
	}
	if err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Prune = true; o.Apply = true }), &strings.Builder{}); err != nil {
		t.Fatalf("prune of a converged org failed: %v", err)
	}
}

// --- validation ----------------------------------------------------------------

func TestPoliciesReconcile_YAMLValidation(t *testing.T) {
	t.Run("broken yaml fails with file and line", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", "apiVersion: ypp/v1\nkind: Policy\n  bad: [unclosed\n")
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "pii-guard.yaml") || !strings.Contains(err.Error(), "line") {
			t.Fatalf("want file:line validation error, got: %v", err)
		}
	})
	t.Run("unknown field fails (strict schema)", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard+"\nwat: 1\n")
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "pii-guard.yaml") || !strings.Contains(err.Error(), "field wat") {
			t.Fatalf("want strict unknown-field error with file, got: %v", err)
		}
	})
	t.Run("name must match file stem", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "other-name.yaml", declPIIGuard)
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "must match the file stem") {
			t.Fatalf("want stem mismatch error, got: %v", err)
		}
	})
	t.Run("three documents rejected", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard+"\n---\nenabled: true\n")
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "at most two documents") {
			t.Fatalf("want doc-count error, got: %v", err)
		}
	})
	t.Run("reconcile block rejects unknown keys", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIPolicy+"\n---\nenabled: false\nwat: 1\n")
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "reconcile block") {
			t.Fatalf("want reconcile block error, got: %v", err)
		}
	})
	t.Run("attachment validation", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIPolicy+"\n---\nattachments:\n  - model_pattern: \"\"\n    endpoint: chat\n")
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "model_pattern is required") {
			t.Fatalf("want attachment validation error, got: %v", err)
		}
	})
	t.Run("stray root-level yaml is an error", func(t *testing.T) {
		dir := t.TempDir()
		writeDecl(t, dir, "", "stray.yaml", declPIIGuard)
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(dir, nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "organization directory") {
			t.Fatalf("want org-directory error, got: %v", err)
		}
	})
	t.Run("missing dir is an error", func(t *testing.T) {
		store := newFakePolicyStore("acme")
		err := runPoliciesReconcile(context.Background(), store, reconcileOpts(t.TempDir()+"/nope", nil), &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "read directory") {
			t.Fatalf("want missing dir error, got: %v", err)
		}
	})
}

// --- org resolution ------------------------------------------------------------

func TestPoliciesReconcile_OrgResolution(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	writeDecl(t, dir, "ghost", "secrets-guard.yaml", strings.Replace(declPIIGuard, "pii-guard", "secrets-guard", 1))
	store := newFakePolicyStore("acme")

	opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
	err := runPoliciesReconcile(context.Background(), store, opts, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want unknown-slug error, got: %v", err)
	}
	// acme still reconciled despite ghost failing.
	if len(store.pols) != 1 {
		t.Fatalf("resolvable org must still reconcile, got %+v", store.pols)
	}

	// Explicit --org restricts scope and hard-fails on a missing dir.
	store2 := newFakePolicyStore("acme")
	opts.Org = "nope"
	if err := runPoliciesReconcile(context.Background(), store2, opts, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "--org") {
		t.Fatalf("want explicit --org error, got: %v", err)
	}
	opts.Org = "acme"
	out := runReconcile(t, store2, opts)
	if !strings.Contains(out, "org acme") || strings.Contains(out, "ghost") {
		t.Fatalf("--org scope wrong:\n%s", out)
	}
}

// --- pack ----------------------------------------------------------------------

// TestPoliciesReconcile_PackShipsOff: the _pack namespace is ignored unless
// --include-pack is set; with it, pack policies reconcile into every org in
// scope and stay idempotent.
func TestPoliciesReconcile_PackShipsOff(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	packDir := dir + "/" + policiesPackDir
	writeDecl(t, dir, policiesPackDir, "sovereign-default.yaml", strings.Replace(declPIIGuard, "pii-guard", "sovereign-default", 1))
	_ = packDir
	store := newFakePolicyStore("acme")

	out := runReconcile(t, store, reconcileOpts(dir, nil))
	if strings.Contains(out, "sovereign-default") {
		t.Fatalf("pack must be ignored without --include-pack:\n%s", out)
	}
	out = runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.IncludePack = true }))
	if !strings.Contains(out, "add    sovereign-default") {
		t.Fatalf("pack not planned with --include-pack:\n%s", out)
	}
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.IncludePack = true; o.Apply = true }))
	out = runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.IncludePack = true; o.Apply = true }))
	if !strings.Contains(out, "unchanged=2") {
		t.Fatalf("pack reconcile not idempotent:\n%s", out)
	}

	// Without --include-pack again, the pack policy becomes an unmanaged
	// prune candidate (documented semantics).
	out = runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "sovereign-default (not covered by git; pass --prune to delete)") {
		t.Fatalf("pack policy must become a prune candidate:\n%s", out)
	}
}

// TestPoliciesReconcile_ShippedPackParsesAndIsDisabled: the repo's
// sovereign-default pack parses with the strict pipeline schema and ships
// OFF (shadow mode, enabled=false) — owner decision 2026-10-06.
func TestPoliciesReconcile_ShippedPackParsesAndIsDisabled(t *testing.T) {
	raw, err := readFileLimited("../../deploy/policies/_pack/sovereign-default.yaml")
	if err != nil {
		t.Skipf("pack file not available from this checkout: %v", err)
	}
	decl, err := parsePolicyDeclaration("deploy/policies/_pack/sovereign-default.yaml", raw, "", true)
	if err != nil {
		t.Fatalf("shipped pack must parse: %v", err)
	}
	if decl.Policy.Name != "sovereign-default" || decl.Policy.Mode != pipeline.ModeShadow {
		t.Fatalf("pack identity/mode wrong: %+v", decl.Policy)
	}
	if decl.Meta.Enabled == nil || *decl.Meta.Enabled {
		t.Fatalf("pack must ship enabled=false, got %+v", decl.Meta.Enabled)
	}
	if decl.Meta.Attachments == nil || len(*decl.Meta.Attachments) == 0 {
		t.Fatalf("pack must carry org-wide attachments")
	}
	if !decl.Pack {
		t.Fatalf("pack flag not set")
	}
}

// --- misc ----------------------------------------------------------------------

func TestPoliciesReconcile_ResolveGitSHA(t *testing.T) {
	sha, err := resolveGitSHA(context.Background(), ".")
	if err != nil || sha == "" {
		t.Fatalf("resolveGitSHA in repo: sha=%q err=%v", sha, err)
	}
	if _, err := resolveGitSHA(context.Background(), t.TempDir()); err == nil {
		t.Fatalf("resolveGitSHA outside a repo must fail")
	}
}

func TestPoliciesReconcile_EmptyDirIsNoop(t *testing.T) {
	store := newFakePolicyStore()
	out := runReconcile(t, store, reconcileOpts(t.TempDir(), nil))
	if !strings.Contains(out, "no organization declarations") {
		t.Fatalf("empty dir must be a clean no-op:\n%s", out)
	}
}

func TestPoliciesCmd_Wired(t *testing.T) {
	root := RootCommand()
	pol, _, err := root.Find([]string{"policies"})
	if err != nil || pol.Name() != "policies" {
		t.Fatalf("policies command not wired: %v", err)
	}
	rec, _, err := pol.Find([]string{"reconcile"})
	if err != nil || rec.Name() != "reconcile" {
		t.Fatalf("reconcile subcommand not wired: %v", err)
	}
	for _, flag := range []string{"pg-uri", "dir", "org", "apply", "prune", "include-pack", "git-sha", "created-by"} {
		if rec.Flags().Lookup(flag) == nil {
			t.Errorf("reconcile flag --%s missing", flag)
		}
	}
}

// --- N16-P01-T02: validate (CI gate) / diff / rollback / mixed-state apply -----

func TestPoliciesValidate_StrictGate(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)

	var sb strings.Builder
	if err := runPoliciesValidate(&sb, policiesValidateOptions{Dir: dir}); err != nil {
		t.Fatalf("valid tree must pass: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "ok   "+dir+"/acme/pii-guard.yaml") || !strings.Contains(out, "files=1 orgs=1") {
		t.Fatalf("validate output missing the per-file ok / summary:\n%s", out)
	}

	// Negative: an unknown field must fail with the file path (CI gate teeth).
	broken := declPIIPolicy + "\nunknown_field: true"
	writeDecl(t, dir, "acme", "broken.yaml", broken)
	if err := runPoliciesValidate(io.Discard, policiesValidateOptions{Dir: dir}); err == nil {
		t.Fatalf("unknown field must fail the validate gate")
	} else if !strings.Contains(err.Error(), "broken.yaml") {
		t.Fatalf("error must carry the file path: %v", err)
	}

	// Negative: a broken reconcile block (second document) fails too.
	writeDecl(t, dir, "acme", "badmeta.yaml", declPIIPolicy+"\n---\nbogus_meta: true")
	if err := runPoliciesValidate(io.Discard, policiesValidateOptions{Dir: dir}); err == nil {
		t.Fatalf("unknown reconcile field must fail the validate gate")
	}

	// Org filter: only that org's files load; an unknown org is an error.
	if err := runPoliciesValidate(io.Discard, policiesValidateOptions{Dir: dir, Org: "nosuchorg"}); err == nil {
		t.Fatalf("unknown --org must fail")
	}
}

func TestPoliciesValidate_PackOptIn(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "_pack", "pii-guard.yaml", declPIIPolicy)

	// Default: _pack is a namespace, not an org — nothing to validate.
	var sb strings.Builder
	if err := runPoliciesValidate(&sb, policiesValidateOptions{Dir: dir}); err != nil {
		t.Fatalf("namespace-only tree must pass: %v", err)
	}
	if !strings.Contains(sb.String(), "files=0") {
		t.Fatalf("pack must be skipped by default:\n%s", sb.String())
	}

	// --include-pack validates it.
	sb.Reset()
	if err := runPoliciesValidate(&sb, policiesValidateOptions{Dir: dir, IncludePack: true}); err != nil {
		t.Fatalf("--include-pack must pass on a valid pack decl: %v", err)
	}
	if !strings.Contains(sb.String(), "(pack, policy pii-guard") {
		t.Fatalf("pack decl not reported:\n%s", sb.String())
	}
}

func TestPoliciesDiff_IsTheDryRunPlan(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")

	var sb strings.Builder
	opts := reconcileOpts(dir, nil)
	opts.Diff = true
	if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err != nil {
		t.Fatalf("diff: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "mode=diff (dry-run") {
		t.Fatalf("diff mode line missing:\n%s", out)
	}
	if !strings.Contains(out, "add    pii-guard") {
		t.Fatalf("diff must print the same plan as the dry-run reconcile:\n%s", out)
	}
	if len(store.pols) != 0 {
		t.Fatalf("diff wrote %d policies — diff is dry-run only", len(store.pols))
	}
}

func TestPoliciesRollback_PreviousThenExplicit(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuardV2)
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if p := store.pols["pol-1"]; p.CurrentVersion != 2 {
		t.Fatalf("setup: active version must be 2, got %d", p.CurrentVersion)
	}

	// Default target: the previous version (2 → 1).
	var sb strings.Builder
	if err := runPoliciesRollback(context.Background(), store, policiesRollbackOptions{Org: "acme", Policy: "pii-guard"}, &sb); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !strings.Contains(sb.String(), "version 2 → 1") {
		t.Fatalf("rollback output missing the from → to line:\n%s", sb.String())
	}
	if p := store.pols["pol-1"]; p.CurrentVersion != 1 {
		t.Fatalf("rollback did not move current_version: %d", p.CurrentVersion)
	}
	// Immutable-version model: both versions still exist, nothing rewritten.
	if got := len(store.vers["pol-1"]); got != 2 {
		t.Fatalf("rollback must not touch version history, have %d", got)
	}

	// Explicit --to: back to 2 (older than the new active 1? no — 2 > 1 must
	// be REFUSED; first roll back is impossible, so prove the refusal).
	sb.Reset()
	err := runPoliciesRollback(context.Background(), store, policiesRollbackOptions{Org: "acme", Policy: "pii-guard", To: 2}, &sb)
	if err == nil || !strings.Contains(err.Error(), "never rolls forward") {
		t.Fatalf("--to newer than active must be refused, got: %v", err)
	}

	// Reset the pointer through a fresh reconcile-update path, then --to 1.
	v3, err := store.CreatePolicyVersion(context.Background(), "org-1", "pol-1", declPIIPolicy+"\nparams:\n  x: 1", "sha", "op")
	if err != nil {
		t.Fatalf("seed v3: %v", err)
	}
	if _, err := store.SetActivePolicyVersion(context.Background(), "org-1", "pol-1", v3.Version); err != nil {
		t.Fatalf("activate v3: %v", err)
	}
	sb.Reset()
	if err := runPoliciesRollback(context.Background(), store, policiesRollbackOptions{Org: "acme", Policy: "pii-guard", To: 1}, &sb); err != nil {
		t.Fatalf("explicit --to 1: %v", err)
	}
	if p := store.pols["pol-1"]; p.CurrentVersion != 1 {
		t.Fatalf("explicit rollback landed on %d", p.CurrentVersion)
	}
}

func TestPoliciesRollback_Failures(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	store := newFakePolicyStore("acme")
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))

	cases := []struct {
		name string
		opts policiesRollbackOptions
		want string
	}{
		{"unknown org", policiesRollbackOptions{Org: "ghost", Policy: "pii-guard"}, `org "ghost"`},
		{"unknown policy", policiesRollbackOptions{Org: "acme", Policy: "ghost"}, `policy "ghost" not found`},
		{"nonexistent target", policiesRollbackOptions{Org: "acme", Policy: "pii-guard", To: 9}, "does not exist"},
		{"target == active", policiesRollbackOptions{Org: "acme", Policy: "pii-guard", To: 1}, "not older than the active version"},
	}
	for _, tc := range cases {
		err := runPoliciesRollback(context.Background(), store, tc.opts, io.Discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error %q, got %v", tc.name, tc.want, err)
		}
	}

	// No older version: single-version policy cannot roll back further.
	err := runPoliciesRollback(context.Background(), store, policiesRollbackOptions{Org: "acme", Policy: "pii-guard"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no version older") {
		t.Fatalf("single-version rollback must refuse: %v", err)
	}

	// No active version: a never-activated policy (current_version 0).
	if _, _, err := store.CreatePolicy(context.Background(), "org-1", "draft-only", declPIIPolicy, "", "ui"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err = runPoliciesRollback(context.Background(), store, policiesRollbackOptions{Org: "acme", Policy: "draft-only"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no active version") {
		t.Fatalf("policy without an active version must refuse: %v", err)
	}
}

// TestPoliciesReconcile_MixedStateReported pins the negative acceptance: a
// partially failed apply NEVER leaves an unreported mixed state — the output
// names the applied policies, the failed (possibly partially applied) one,
// and everything the run never attempted, plus the idempotent resume path.
func TestPoliciesReconcile_MixedStateReported(t *testing.T) {
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "a-guard.yaml", declPIIPolicyWith("a-guard"))
	writeDecl(t, dir, "acme", "b-guard.yaml", declPIIPolicyWith("b-guard"))
	writeDecl(t, dir, "acme", "c-guard.yaml", declPIIPolicyWith("c-guard"))
	store := newFakePolicyStore("acme")

	// Pre-seed b-guard as a UI-native policy whose content differs from the
	// declaration → the apply of b goes through CreatePolicyVersion, where
	// the injected store failure fires (mid-apply, after a already landed).
	if _, _, err := store.CreatePolicy(context.Background(), "org-1", "b-guard", declPIIPolicyWith("b-guard-old"), "", "ui-op"); err != nil {
		t.Fatalf("seed b: %v", err)
	}
	store.failVersionCreate = errors.New("boom: injected store failure")

	opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
	var sb strings.Builder
	err := runPoliciesReconcile(context.Background(), store, opts, &sb)
	if err == nil || !strings.Contains(err.Error(), "b-guard") {
		t.Fatalf("apply must fail on b-guard: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		`applied (live now): a-guard`,
		`PARTIALLY APPLIED: "b-guard"`,
		`NOT APPLIED: c-guard`,
		`resume: fix the error and re-run reconcile`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed-state disclosure missing %q:\n%s", want, out)
		}
	}
	// Forensic state: a landed, b kept its single pre-seed version (the
	// failed append appended nothing), c was never attempted.
	if _, ok := store.pols[store.names["org-1|a-guard"]]; !ok {
		t.Fatalf("a-guard must be applied: %+v", store.pols)
	}
	if got := len(store.vers[store.names["org-1|b-guard"]]); got != 1 {
		t.Fatalf("b-guard versions after failed append: %d", got)
	}
	if _, ok := store.names["org-1|c-guard"]; ok {
		t.Fatalf("c-guard must not exist (never attempted)")
	}

	// Idempotent resume: clear the failure and re-run — b converges, c adds,
	// a reports in sync. No duplicates, no lingering mixed state.
	store.failVersionCreate = nil
	runReconcile(t, store, reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true }))
	if got := len(store.vers[store.names["org-1|b-guard"]]); got != 2 {
		t.Fatalf("resume must append b's git version: %d", got)
	}
	out = runReconcile(t, store, reconcileOpts(dir, nil))
	if !strings.Contains(out, "unchanged=3") || strings.Contains(out, "add ") || strings.Contains(out, "update ") {
		t.Fatalf("resume must converge to a clean plan:\n%s", out)
	}
}

// declPIIPolicyWith builds a single-document policy declaration named name.
func declPIIPolicyWith(name string) string {
	return strings.ReplaceAll(declPIIPolicy, "pii-guard", name)
}

func TestPoliciesCmd_ValidateDiffRollbackWired(t *testing.T) {
	root := RootCommand()
	pol, _, err := root.Find([]string{"policies"})
	if err != nil || pol.Name() != "policies" {
		t.Fatalf("policies command not wired: %v", err)
	}
	val, _, err := pol.Find([]string{"validate"})
	if err != nil || val.Name() != "validate" {
		t.Fatalf("validate subcommand not wired: %v", err)
	}
	for _, flag := range []string{"dir", "org", "include-pack"} {
		if val.Flags().Lookup(flag) == nil {
			t.Errorf("validate flag --%s missing", flag)
		}
	}
	if val.Flags().Lookup("pg-uri") != nil {
		t.Errorf("validate must not require a database flag")
	}
	diff, _, err := pol.Find([]string{"diff"})
	if err != nil || diff.Name() != "diff" {
		t.Fatalf("diff subcommand not wired: %v", err)
	}
	if diff.Flags().Lookup("apply") != nil {
		t.Errorf("diff must not carry --apply (it is dry-run by definition)")
	}
	rb, _, err := pol.Find([]string{"rollback"})
	if err != nil || rb.Name() != "rollback" {
		t.Fatalf("rollback subcommand not wired: %v", err)
	}
	for _, flag := range []string{"pg-uri", "org", "policy", "to", "redis-addr"} {
		if rb.Flags().Lookup(flag) == nil {
			t.Errorf("rollback flag --%s missing", flag)
		}
	}
}
