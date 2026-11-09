package adminstore

// stand (testcontainers). Covers: the 0010 up/down pair, prompt CRUD
// round-trip (versions, draft-follows-latest, label promotion, resolution by
// name+label), per-org name uniqueness, partials (create/update/upsert/
// delete), org RLS isolation across ALL FOUR tables under the yabanin_app
// posture, and the two provider seams (PartialsLookup for the OP-5
// builtins.PartialsSource, JudgePromptSource for the OP-3
// llmjudge.PromptSource).

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline/builtins"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// structurally (no production import of the pipeline packages in adminstore;
// these pins live in the test binary only).
var (
	_ builtins.PartialsSource = PartialsSource(nil)
	_ PartialsSource          = builtins.NoopPartials{}
	_ builtins.PartialsSource = builtins.PartialsSourceFunc(nil)
	_ llmjudge.PromptSource   = orgJudgePrompts{}
)

const promptTestTemplate = `You are {{role}}.
{{partials.rules}}
Judge: {{input}}`

// newPromptFixture reuses the policystore fixture shape: two orgs on the
// shared stand; prompts/partials cascade with their orgs.
func newPromptFixture(t *testing.T) policyFixture {
	t.Helper()
	return newPolicyFixture(t)
}

// TestPromptStudio_CRUD_Integration: create appends version 1 + draft,
// updates append monotonically and draft follows, labels promote (upsert),
// resolution by name+label, versions list newest first, delete cascades.
func TestPromptStudio_CRUD_Integration(t *testing.T) {
	fx := newPromptFixture(t)
	ctx := context.Background()

	params := json.RawMessage(`{"model":"gpt-4o-mini","temperature":0.2}`)
	p, v1, err := fx.store.CreatePrompt(ctx, fx.orgA, "toxicity-ru", "RU toxicity judge", promptTestTemplate, params, "admin@x.test")
	require.NoError(t, err)
	require.NotEmpty(t, p.ID)
	assert.Equal(t, fx.orgA, p.OrgID)
	assert.Equal(t, 1, v1.Version)
	assert.JSONEq(t, `{"model":"gpt-4o-mini","temperature":0.2}`, string(v1.Params))
	assert.Equal(t, "admin@x.test", v1.CreatedBy)

	// A nil params document stores as {}.
	_, vEmpty, err := fx.store.CreatePrompt(ctx, fx.orgA, "no-params", "", "t", nil, "")
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(vEmpty.Params))

	// Labels after create: draft → 1.
	labels, err := fx.store.ListPromptLabels(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, labels, 1)
	assert.Equal(t, PromptLabelDraft, labels[0].Label)
	assert.Equal(t, 1, labels[0].Version)

	// Update appends v2 and draft follows.
	v2, err := fx.store.UpdatePrompt(ctx, fx.orgA, p.ID, promptTestTemplate+"\n# v2", nil, "admin@x.test", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, v2.Version)
	_, err = fx.store.UpdatePrompt(ctx, fx.orgA, p.ID, "stale write", nil, "admin@x.test", 1)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	labels, err = fx.store.ListPromptLabels(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, labels, 1)
	assert.Equal(t, 2, labels[0].Version, "draft follows the latest saved version")

	// Promote active → 1, canary → 2; draft stays at 2.
	l, err := fx.store.PromoteLabel(ctx, fx.orgA, p.ID, PromptLabelActive, 1)
	require.NoError(t, err)
	assert.Equal(t, PromptLabelActive, l.Label)
	assert.Equal(t, 1, l.Version)
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, p.ID, PromptLabelCanary, 2)
	require.NoError(t, err)

	// Re-promoting the same label moves the pointer (upsert).
	l, err = fx.store.PromoteLabel(ctx, fx.orgA, p.ID, PromptLabelActive, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, l.Version)
	labels, err = fx.store.ListPromptLabels(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	assert.Len(t, labels, 3, "labels are pointers, not history: at most one row per label")

	// Promoting a version that does not exist is ErrNotFound.
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, p.ID, PromptLabelActive, 99)
	require.True(t, IsNotFound(err))
	// Unknown labels and versions are rejected.
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, p.ID, "latest", 1)
	require.Error(t, err)
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, p.ID, PromptLabelActive, 0)
	require.Error(t, err)

	// Resolution by name + label (the gateway render seam).
	v, err := fx.store.GetActiveByLabel(ctx, fx.orgA, "toxicity-ru", PromptLabelCanary)
	require.NoError(t, err)
	assert.Equal(t, 2, v.Version)
	v, err = fx.store.GetActiveByLabel(ctx, fx.orgA, "toxicity-ru", PromptLabelDraft)
	require.NoError(t, err)
	assert.Equal(t, 2, v.Version)
	_, err = fx.store.GetActiveByLabel(ctx, fx.orgA, "missing", PromptLabelActive)
	require.True(t, IsNotFound(err))
	_, err = fx.store.GetActiveByLabel(ctx, fx.orgA, "toxicity-ru", "bogus")
	require.Error(t, err, "unknown labels are rejected, not silently unresolved")

	// Versions list: newest first; GetPromptVersion fetches one.
	versions, err := fx.store.ListPromptVersions(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].Version)
	got, err := fx.store.GetPromptVersion(ctx, fx.orgA, p.ID, 1)
	require.NoError(t, err)
	assert.Equal(t, promptTestTemplate, got.Template)
	_, err = fx.store.JudgePromptSource(fx.orgA).Load(ctx, "org:toxicity-ru@99")
	require.ErrorContains(t, err, "immutable version 99")
	_, err = fx.store.GetPromptVersion(ctx, fx.orgA, p.ID, 3)
	require.True(t, IsNotFound(err))

	// Duplicate name inside the org is rejected; a different org is fine.
	_, _, err = fx.store.CreatePrompt(ctx, fx.orgA, "toxicity-ru", "", "t", nil, "")
	require.ErrorContains(t, err, "already exists")
	_, _, err = fx.store.CreatePrompt(ctx, fx.orgB, "toxicity-ru", "", "t", nil, "")
	require.NoError(t, err)

	// Delete cascades: versions and labels are gone with the prompt.
	require.NoError(t, fx.store.DeletePrompt(ctx, fx.orgA, p.ID))
	_, err = fx.store.GetPrompt(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err))
	_, err = fx.store.GetPromptVersion(ctx, fx.orgA, p.ID, 2)
	require.True(t, IsNotFound(err))
	labels, err = fx.store.ListPromptLabels(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err), "a deleted prompt's labels list is ErrNotFound")
	assert.Empty(t, labels)
	err = fx.store.DeletePrompt(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err))
}

// TestPromptStudio_Partials_Integration: create (unique per org), update
// bumps the version, the upsert convenience, list, delete, and the OP-5
// PartialsLookup provider (found / missing / isolation).
func TestPromptStudio_Partials_Integration(t *testing.T) {
	fx := newPromptFixture(t)
	ctx := context.Background()

	p, err := fx.store.CreatePartial(ctx, fx.orgA, "safety-rules", "RULE-1")
	require.NoError(t, err)
	assert.Equal(t, 1, p.Version)

	_, err = fx.store.CreatePartial(ctx, fx.orgA, "safety-rules", "dup")
	require.ErrorContains(t, err, "already exists")

	p, err = fx.store.UpdatePartial(ctx, fx.orgA, "safety-rules", "RULE-1\nRULE-2", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Version)
	oldBody, found, err := fx.store.PartialsLookup(fx.orgA).Get(ctx, "safety-rules@1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "RULE-1", oldBody, "partial version 1 is immutable after update")
	_, err = fx.store.UpdatePartial(ctx, fx.orgA, "safety-rules", "stale", 1)
	require.ErrorIs(t, err, ErrPreconditionFailed)
	_, err = fx.store.UpdatePartial(ctx, fx.orgA, "missing-partial", "x", 1)
	require.True(t, IsNotFound(err))

	// Upsert: creates missing, bumps existing.
	p, err = fx.store.SetPartial(ctx, fx.orgA, "greeting", "hello")
	require.NoError(t, err)
	assert.Equal(t, 1, p.Version)
	p, err = fx.store.SetPartial(ctx, fx.orgA, "greeting", "hello v2")
	require.NoError(t, err)
	assert.Equal(t, 2, p.Version)

	list, err := fx.store.ListPartials(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "greeting", list[0].Name, "list is name-ordered")

	// The OP-5 provider resolves through the table.
	src := fx.store.PartialsLookup(fx.orgA)
	body, found, err := src.Get(ctx, "safety-rules")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "RULE-1\nRULE-2", body)
	_, found, err = src.Get(ctx, "nope")
	require.NoError(t, err)
	assert.False(t, found)

	// Same name in another org stays isolated.
	_, err = fx.store.CreatePartial(ctx, fx.orgB, "safety-rules", "ORG-B")
	require.NoError(t, err)
	body, _, err = fx.store.PartialsLookup(fx.orgB).Get(ctx, "safety-rules")
	require.NoError(t, err)
	assert.Equal(t, "ORG-B", body)

	// Delete is by name; missing is ErrNotFound.
	require.NoError(t, fx.store.DeletePartial(ctx, fx.orgA, "greeting"))
	err = fx.store.DeletePartial(ctx, fx.orgA, "greeting")
	require.True(t, IsNotFound(err))
}

// TestPromptStudio_JudgePromptSource_Integration: org refs resolve through
// the label bindings, judges/* refs delegate to the embedded source, and
// malformed/missing refs error.
func TestPromptStudio_JudgePromptSource_Integration(t *testing.T) {
	fx := newPromptFixture(t)
	ctx := context.Background()

	p1, _, err := fx.store.CreatePrompt(ctx, fx.orgA, "judge-org", "org judge prompt",
		"Verdict for: {{.Input}}", nil, "")
	require.NoError(t, err)
	v2, err := fx.store.UpdatePrompt(ctx, fx.orgA, p1.ID, "v2 {{.Input}}", nil, "", 1)
	require.NoError(t, err)
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, p1.ID, PromptLabelActive, 2)
	require.NoError(t, err)

	src := fx.store.JudgePromptSource(fx.orgA)

	// org:<name>@<label> resolves the bound version's raw template.
	prompt, err := src.Load(ctx, "org:judge-org@active")
	require.NoError(t, err)
	assert.Equal(t, "org:judge-org@active", prompt.Ref)
	assert.Equal(t, v2.Template, prompt.Body)
	// X-Policy-Judge-Version header input).
	assert.Equal(t, strconv.Itoa(v2.Version), prompt.Version)

	// The label is a movable pointer: re-promote, the next load follows.
	_, err = fx.store.PromoteLabel(ctx, fx.orgA, v2.PromptID, PromptLabelActive, 1)
	require.NoError(t, err)
	prompt, err = src.Load(ctx, "org:judge-org@active")
	require.NoError(t, err)
	assert.Equal(t, "Verdict for: {{.Input}}", prompt.Body)
	assert.Equal(t, "1", prompt.Version)

	// judges/* refs delegate to the embedded source (OP-3 behavior intact).
	prompt, err = src.Load(ctx, "judges/toxicity@2")
	require.NoError(t, err)
	assert.Equal(t, "judges/toxicity@2", prompt.Ref)
	assert.NotEmpty(t, prompt.Body)
	assert.Equal(t, "2", prompt.Version)

	// Missing prompt/label and malformed refs error (policy LOAD errors).
	_, err = src.Load(ctx, "org:missing@active")
	require.Error(t, err)
	_, err = src.Load(ctx, "org:judge-org@canary")
	require.Error(t, err)
	_, err = src.Load(ctx, "org:nolabel")
	require.Error(t, err)
	_, err = src.Load(ctx, "judges/nope@1")
	require.Error(t, err)
}

// TestPromptStudio_RLS_OrgIsolation_Integration: under the application
// posture (SET ROLE yabanin_app + app.current_org GUC) a foreign org's
// prompts/versions/labels/partials are invisible and unwritable across ALL
// FOUR tables, and an unbound session sees nothing at all (fail closed).
func TestPromptStudio_RLS_OrgIsolation_Integration(t *testing.T) {
	fx := newPromptFixture(t)
	ctx := context.Background()

	polA, _, err := fx.store.CreatePrompt(ctx, fx.orgA, "rls-a", "", "template a", nil, "")
	require.NoError(t, err)
	polB, _, err := fx.store.CreatePrompt(ctx, fx.orgB, "rls-b", "", "template b", nil, "")
	require.NoError(t, err)
	_, err = fx.store.PromoteLabel(ctx, fx.orgB, polB.ID, PromptLabelActive, 1)
	require.NoError(t, err)
	_, err = fx.store.CreatePartial(ctx, fx.orgB, "rls-partial", "org-b body")
	require.NoError(t, err)

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()

	// Downgrade to the NOBYPASSRLS application role and pin the production
	// row_security posture (the shared stand's migration session leaks
	// row_security=off; see orgcredentials_int_test.go).
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	bindOrg := func(orgID string) {
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
		require.NoError(t, err)
	}

	rlsAdapter := rlsConnAdapter{conn.Conn()}
	rls := newForTest(rlsAdapter, slog.New(slog.DiscardHandler), nil)

	// Org A sees only its own prompt and resolves only its own labels.
	bindOrg(fx.orgA)
	seen, err := rls.ListPrompts(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.Equal(t, polA.ID, seen[0].ID)

	_, err = rls.GetActiveByLabel(ctx, fx.orgA, "rls-b", PromptLabelActive)
	require.True(t, IsNotFound(err), "a foreign org's label resolution must be invisible")
	body, found, err := rls.PartialsLookup(fx.orgA).Get(ctx, "rls-partial")
	require.NoError(t, err)
	assert.False(t, found, "a foreign org's partial must be invisible")
	assert.Empty(t, body)
	_, err = rls.JudgePromptSource(fx.orgA).Load(ctx, "org:rls-b@active")
	require.Error(t, err, "a foreign org's judge prompt must not resolve")

	// Cross-org writes through the store are ErrNotFound: the WHERE clause
	// pins (id, org) and the org_isolation policy denies the foreign row.
	_, err = rls.UpdatePrompt(ctx, fx.orgA, polB.ID, "evil", nil, "", 1)
	require.True(t, IsNotFound(err), "cross-org version append must not touch the foreign row")
	_, err = rls.PromoteLabel(ctx, fx.orgA, polB.ID, PromptLabelActive, 1)
	require.True(t, IsNotFound(err), "cross-org label promote must not touch the foreign row")
	err = rls.DeletePrompt(ctx, fx.orgA, polB.ID)
	require.True(t, IsNotFound(err), "cross-org delete must not touch the foreign row")
	_, err = rls.UpdatePartial(ctx, fx.orgA, "rls-partial", "evil", 1)
	require.True(t, IsNotFound(err), "cross-org partial update must not touch the foreign row")

	// Raw SQL WITHOUT the org GUC (only role downgrade): nothing is visible
	// and nothing resolves — the FORCE policy is the isolation boundary.
	for _, q := range []struct {
		sql  string
		what string
	}{
		{`SELECT id FROM prompts WHERE org_id = $1::uuid`, "prompts"},
		{`SELECT id FROM prompt_versions WHERE org_id = $1::uuid`, "prompt_versions"},
		{`SELECT id FROM prompt_labels WHERE org_id = $1::uuid`, "prompt_labels"},
		{`SELECT id FROM partials WHERE org_id = $1::uuid`, "partials"},
	} {
		rows, err := rlsAdapter.Query(ctx, q.sql, fx.orgB)
		require.NoError(t, err)
		assert.False(t, rows.Next(), "an unbound raw session must not see any org's rows (%s)", q.what)
		rows.Close()
	}

	// Direct cross-org INSERT violates the WITH CHECK arm on every table.
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO prompts (org_id, name) VALUES ($1::uuid, 'evil')`, fx.orgB)
	require.Error(t, err, "cross-org prompt insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO prompt_versions (prompt_id, org_id, version, template) VALUES (gen_random_uuid(), $1::uuid, 1, 'x')`, fx.orgB)
	require.Error(t, err, "cross-org version insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO prompt_labels (prompt_id, org_id, label, version) VALUES (gen_random_uuid(), $1::uuid, 'active', 1)`, fx.orgB)
	require.Error(t, err, "cross-org label insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO partials (org_id, name, body) VALUES ($1::uuid, 'evil', 'x')`, fx.orgB)
	require.Error(t, err, "cross-org partial insert must be rejected by the org_isolation policy")

	// Unbound raw session (empty GUC): nothing is visible — fail closed.
	bindOrg("")
	for _, tbl := range []string{"prompts", "prompt_versions", "prompt_labels", "partials"} {
		rows, err := rlsAdapter.Query(ctx,
			`SELECT id FROM `+tbl+` WHERE org_id = $1::uuid`, fx.orgA)
		require.NoError(t, err)
		assert.False(t, rows.Next(), "an unbound session must see no %s at all", tbl)
		rows.Close()
	}
}
