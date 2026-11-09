package handlers

// E04-P01 W02-C03 tests — unmounted SPI handlers, direct invocation (no
// router), the union inventory_handlers_test.go pattern adapted to the
// base tree: root via rootRequest, org scope pinned INLINE via
// ctxKeyOrgScope{} (the base-native pattern; the union-only withOrgScope
// helper is deliberately not redefined here), membership seeded via the
// ctxKeyOrgRole{} request cache. Audit entries surface through
// lastAuditEntry (nil store → the in-memory buffer, the New(nil, "", "",
// []string{}) posture).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/dataclass"
)

// fakeTaxonomyStore fakes the ClassificationTaxonomyStore seam.
type fakeTaxonomyStore struct {
	getTax  dataclass.Taxonomy
	getFnd  bool
	getErr  error
	getN    int
	lastGet string

	putTax    dataclass.Taxonomy // what PutTaxonomy returns
	putChg    bool
	putErr    error
	putN      int
	lastPut   dataclass.Taxonomy
	lastOrg   string
	lastActor string
}

func (f *fakeTaxonomyStore) GetTaxonomy(_ context.Context, orgID string) (dataclass.Taxonomy, bool, error) {
	f.getN++
	f.lastGet = orgID
	return f.getTax, f.getFnd, f.getErr
}

func (f *fakeTaxonomyStore) PutTaxonomy(_ context.Context, orgID string, t dataclass.Taxonomy, updatedBy string) (dataclass.Taxonomy, bool, error) {
	f.putN++
	f.lastPut = t
	f.lastOrg = orgID
	f.lastActor = updatedBy
	return f.putTax, f.putChg, f.putErr
}

// taxScopedRequest builds a NON-root request with the middleware org
// scope pinned (the inline base-native pattern).
func taxScopedRequest(method, target, body, org string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, org)
	return r.WithContext(ctx)
}

// taxMemberRequest pins the scope AND seeds the per-request role cache
// (ctxKeyOrgRole{}) so requireOrgScope's membership check passes without
// a store — the member posture the middleware guarantees in production.
func taxMemberRequest(method, target, body, org string, role adminstore.OrgRole) *http.Request {
	r := taxScopedRequest(method, target, body, org)
	ctx := context.WithValue(r.Context(), ctxKeyOrgRole{}, map[string]adminstore.OrgRole{org: role})
	return r.WithContext(ctx)
}

func sampleTaxonomyBody() string {
	return `{"labels":[
		{"key":"billing","synonyms":{"ru":["оплата","счёт"]}},
		{"key":"billing.invoice","parent":"billing"},
		{"key":"support"}
	]}`
}

func TestTaxonomy_NoStore_503(t *testing.T) {
	h := New(nil, "", "", []string{})

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(nil)(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "GET without a wired store is 503")

	req = rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", sampleTaxonomyBody())
	w = httptest.NewRecorder()
	h.PutClassificationTaxonomy(nil)(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "PUT without a wired store is 503")
}

func TestTaxonomy_GetRootReadsOrg(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{
		getTax: dataclass.Taxonomy{OrgID: "org-1", Labels: []dataclass.Label{
			{Key: "billing", Synonyms: map[string][]string{"ru": {"оплата"}}},
			{Key: "support"},
		}, Version: 4},
		getFnd: true,
	}

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got dataclass.Taxonomy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "org-1", got.OrgID)
	assert.Equal(t, int64(4), got.Version)
	assert.Len(t, got.Labels, 2)
	assert.Equal(t, 1, fake.getN, "exactly one store read")
	assert.Equal(t, "org-1", fake.lastGet)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_read", entry.Action)
	assert.Equal(t, "organization:org-1", entry.Resource)
	assert.JSONEq(t, `{"org_id":"org-1","outcome":"ok","labels":2}`, entry.Details)
}

func TestTaxonomy_GetMissingOrgIsEmpty200(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{} // found=false

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "a never-written org is the empty taxonomy, not 404")
	assert.JSONEq(t, `{"org_id":"org-1","labels":[],"version":0}`, w.Body.String(),
		"labels marshal as [], never null")

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_read", entry.Action, "an empty read is still an allowed read")
	assert.JSONEq(t, `{"org_id":"org-1","outcome":"ok","labels":0}`, entry.Details)
}

func TestTaxonomy_GetForeignOrg403WithDeniedAudit(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{getFnd: true}

	// Scoped to org-1, targeting org-2: the mismatch refusal fires before
	// the membership lookup — no store needed.
	req := taxScopedRequest(http.MethodGet, "/api/organizations/org-2/classification/taxonomy?org_id=org-2", "", "org-1")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, fake.getN, "a denied request never reaches the store")

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_read.denied", entry.Action)
	assert.Equal(t, "organization:org-2", entry.Resource)
	assert.JSONEq(t, `{"org_id":"org-2","scope":"org-1","outcome":"forbidden","labels":0}`, entry.Details)
}

func TestTaxonomy_GetNonMember403(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{getFnd: true}

	// Scoped to org-1, targeting org-1, but no membership in the request
	// (and no store to resolve one): ENT-02's membership-only refusal.
	req := taxScopedRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "", "org-1")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "you do not have a role")
	assert.Zero(t, fake.getN)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_read.denied", entry.Action)
}

func TestTaxonomy_GetOrgMemberAllowed(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{getFnd: true, getTax: dataclass.Taxonomy{
		OrgID: "org-1", Labels: []dataclass.Label{{Key: "support"}}, Version: 2}}

	// Membership-only gate: any role on the org reads (the future wiring
	// card registers org:taxonomy.manage for WRITES; reads stay
	// membership-wide until then).
	req := taxMemberRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "", "org-1", adminstore.RoleReader)
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, fake.getN, "an org member's own-org read reaches the store")
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_read", entry.Action)
}

func TestTaxonomy_GetRootWithoutOrg400(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{}

	req := rootRequest(http.MethodGet, "/api/organizations/x/classification/taxonomy", "")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "root must name the target org")
	assert.Zero(t, fake.getN)
}

func TestTaxonomy_GetPathValueOrg(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{getFnd: true}

	req := rootRequest(http.MethodGet, "/api/organizations/org-9/classification/taxonomy", "")
	req.SetPathValue("id", "org-9")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "org-9", fake.lastGet, "the {id} path value feeds the org when the query is absent")
}

func TestTaxonomy_PutRootWrites(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{
		putTax: dataclass.Taxonomy{OrgID: "org-1", Labels: []dataclass.Label{
			{Key: "billing", Synonyms: map[string][]string{"ru": {"оплата", "счёт"}}},
			{Key: "billing.invoice", Parent: "billing"},
			{Key: "support"},
		}, Version: 1},
		putChg: true,
	}

	req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", sampleTaxonomyBody())
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		OrgID   string `json:"org_id"`
		Version int64  `json:"version"`
		Changed bool   `json:"changed"`
		Labels  []struct {
			Key string `json:"key"`
		} `json:"labels"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "org-1", resp.OrgID)
	assert.Equal(t, int64(1), resp.Version)
	assert.True(t, resp.Changed)
	assert.Len(t, resp.Labels, 3)

	// The store saw the decoded body: org from the scope, version never
	// client-supplied (Version 0 in), labels verbatim.
	assert.Equal(t, "org-1", fake.lastOrg)
	assert.Equal(t, int64(0), fake.lastPut.Version)
	assert.Len(t, fake.lastPut.Labels, 3)
	assert.Equal(t, "billing.invoice", fake.lastPut.Labels[1].Key)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_write", entry.Action)
	assert.Equal(t, "organization:org-1", entry.Resource)
	assert.JSONEq(t, `{"org_id":"org-1","outcome":"ok","labels":3,"version":1,"changed":true}`, entry.Details)
}

func TestTaxonomy_PutIdempotentResponse(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{
		putTax: dataclass.Taxonomy{OrgID: "org-1", Labels: []dataclass.Label{{Key: "support"}}, Version: 7},
		putChg: false,
	}

	req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1",
		`{"labels":[{"key":"support"}]}`)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"changed":false`, "an unchanged set surfaces the idempotence signal")
	assert.Contains(t, w.Body.String(), `"version":7`)
}

func TestTaxonomy_PutBadBody400(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{}

	for name, body := range map[string]string{
		"malformed": `{"labels":[`,
		"empty":     ``,
	} {
		req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", body)
		w := httptest.NewRecorder()
		h.PutClassificationTaxonomy(fake)(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, name)
		assert.Contains(t, w.Body.String(), "invalid request body", name)
	}
	assert.Zero(t, fake.putN, "parameter noise never reaches the store")
	h.auditMu.RLock()
	buffered := len(h.auditLogBuffer)
	h.auditMu.RUnlock()
	assert.Zero(t, buffered, "and it is not an authorization decision — nothing is journaled")
}

func TestTaxonomy_PutValidationErrorListVerbatim(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{}

	// Self-parent + unknown locale: MULTIPLE problems, the W01-C01
	// contract wants the full list, not the first error.
	body := `{"labels":[
		{"key":"cycle","parent":"cycle"},
		{"key":"loc","synonyms":{"fr":["oui"]}}
	]}`
	req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", body)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp taxonomyValidationError
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid taxonomy", resp.Error)

	// Lock-step with the C01 model: the handler renders the model's own
	// refusal verbatim.
	var want *dataclass.ValidationError
	wantErr := (&dataclass.Taxonomy{OrgID: "org-1", Labels: []dataclass.Label{
		{Key: "cycle", Parent: "cycle"},
		{Key: "loc", Synonyms: map[string][]string{"fr": {"oui"}}},
	}}).Validate()
	require.ErrorAs(t, wantErr, &want)
	assert.Equal(t, want.Errors, resp.Errors, "the API surfaces the ValidationError list verbatim")
	require.GreaterOrEqual(t, len(resp.Errors), 2, "every problem is listed")
	assert.Zero(t, fake.putN, "an invalid taxonomy never reaches the store")
}

func TestTaxonomy_PutStoreValidationRefusal400(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{putErr: &dataclass.ValidationError{Errors: []string{"label key must not exceed 63 bytes"}}}

	req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1",
		`{"labels":[{"key":"ok"}]}`)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "a store-side validation refusal is still a client error")
	assert.Contains(t, w.Body.String(), "errors")
}

func TestTaxonomy_PutStoreInternalError500(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{putErr: errors.New("db down")}

	req := rootRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1",
		`{"labels":[{"key":"ok"}]}`)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "taxonomy write failed")
}

func TestTaxonomy_GetStoreErrors(t *testing.T) {
	h := New(nil, "", "", []string{})

	fake := &fakeTaxonomyStore{getErr: errors.New("db down")}
	req := rootRequest(http.MethodGet, "/api/organizations/org-1/classification/taxonomy?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "taxonomy read failed")

	fake = &fakeTaxonomyStore{getErr: dataclass.ErrInvalidOrgID}
	req = rootRequest(http.MethodGet, "/api/organizations/x/classification/taxonomy?org_id=x", "")
	w = httptest.NewRecorder()
	h.GetClassificationTaxonomy(fake)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "the store's typed org refusal maps to 400")
}

func TestTaxonomy_PutForeignOrg403WithDeniedAudit(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{}

	req := taxMemberRequest(http.MethodPut, "/api/organizations/org-2/classification/taxonomy?org_id=org-2",
		sampleTaxonomyBody(), "org-1", adminstore.RoleOrgAdmin)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, fake.putN)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_write.denied", entry.Action)
	assert.Equal(t, "organization:org-2", entry.Resource)
	assert.JSONEq(t, `{"org_id":"org-2","scope":"org-1","outcome":"forbidden","labels":0,"changed":false}`, entry.Details)
}

func TestTaxonomy_PutOrgMemberAllowed(t *testing.T) {
	h := New(nil, "", "", []string{})
	fake := &fakeTaxonomyStore{
		putTax: dataclass.Taxonomy{OrgID: "org-1", Labels: []dataclass.Label{{Key: "support"}}, Version: 2},
		putChg: true,
	}

	// Membership-only until the wiring card registers
	// org:taxonomy.manage (documented in the handler doc comment).
	req := taxMemberRequest(http.MethodPut, "/api/organizations/org-1/classification/taxonomy?org_id=org-1",
		`{"labels":[{"key":"support"}]}`, "org-1", adminstore.RoleOrgAdmin)
	w := httptest.NewRecorder()
	h.PutClassificationTaxonomy(fake)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "org-1", fake.lastOrg)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "taxonomy_write", entry.Action)
	assert.JSONEq(t, `{"org_id":"org-1","scope":"org-1","outcome":"ok","labels":1,"version":2,"changed":true}`, entry.Details)
}
