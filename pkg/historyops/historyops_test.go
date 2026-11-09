package historyops

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// testNow pins a quiet closed period: everything before 2026-03-02T11:00Z is
// closed when now = 2026-03-02T11:30Z (the open hour is 11:00–12:00).
var testNow = time.Date(2026, 3, 2, 11, 30, 0, 0, time.UTC)

func closedPeriod() Period {
	return Period{
		From: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestParseSelectionAcceptsMetadataFilters(t *testing.T) {
	params := url.Values{
		"from":     {"2026-02-01T00:00:00Z"},
		"to":       {"2026-03-01T00:00:00Z"},
		"families": {"tool_calls,request_logs"},
		"model":    {"glm-5"},
		"errors":   {"true"},
		"team_id":  {"team-7"},
	}
	sel, err := ParseSelection("org-1", params, testNow)
	require.NoError(t, err)
	assert.Equal(t, "org-1", sel.OrgID)
	assert.Equal(t, "team-7", sel.TeamID)
	assert.Equal(t, []Family{FamilyRequestLogs, FamilyToolCalls}, sel.Families,
		"families are normalized to canonical sorted order")
	assert.True(t, sel.Filters.ErrorOnly)
	assert.Equal(t, "glm-5", sel.Filters.Model)
	assert.Equal(t, closedPeriod().From.UTC(), sel.Period.From)
	assert.Equal(t, closedPeriod().To.UTC(), sel.Period.To)
}

func TestParseSelectionRejectsContentSelectors(t *testing.T) {
	for _, key := range []string{"q", "query"} {
		params := url.Values{
			"from":     {"2026-02-01T00:00:00Z"},
			"to":       {"2026-03-01T00:00:00Z"},
			"families": {"request_logs"},
			key:        {"secret needle"},
		}
		_, err := ParseSelection("org-1", params, testNow)
		require.Error(t, err, "content selector %q must be refused", key)
		refusal, ok := RefusalOf(err)
		require.True(t, ok, "content selector refusal must be typed, got %v", err)
		assert.Equal(t, RefusalSelectorRejected, refusal.Code)
	}
}

func TestParseSelectionProtectedFamily(t *testing.T) {
	params := url.Values{
		"from":     {"2026-02-01T00:00:00Z"},
		"to":       {"2026-03-01T00:00:00Z"},
		"families": {"request_logs,request_lineage"},
	}
	_, err := ParseSelection("org-1", params, testNow)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "protected family must be a typed refusal, got %v", err)
	assert.Equal(t, RefusalProtectedFamily, refusal.Code)
}

func TestParseSelectionUnknownParam(t *testing.T) {
	params := url.Values{
		"from":     {"2026-02-01T00:00:00Z"},
		"to":       {"2026-03-01T00:00:00Z"},
		"families": {"request_logs"},
		"oops":     {"1"},
	}
	_, err := ParseSelection("org-1", params, testNow)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestParseSelectionRequiredFields(t *testing.T) {
	base := url.Values{
		"from":     {"2026-02-01T00:00:00Z"},
		"to":       {"2026-03-01T00:00:00Z"},
		"families": {"request_logs"},
	}
	t.Run("no families", func(t *testing.T) {
		p := url.Values{"from": {base.Get("from")}, "to": {base.Get("to")}}
		_, err := ParseSelection("org-1", p, testNow)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})
	t.Run("bad from", func(t *testing.T) {
		p := cloneValues(base)
		p.Set("from", "yesterday")
		_, err := ParseSelection("org-1", p, testNow)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})
	t.Run("unknown family", func(t *testing.T) {
		p := cloneValues(base)
		p.Set("families", "email_outbox")
		_, err := ParseSelection("org-1", p, testNow)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})
}

func TestPeriodOpenBoundaryRefusal(t *testing.T) {
	// now = 11:30Z: the open hour starts at 11:00Z.
	open := Period{
		From: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 2, 11, 45, 0, 0, time.UTC),
	}
	err := open.Validate(testNow)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "open period must be a typed refusal, got %v", err)
	assert.Equal(t, RefusalOpenPeriod, refusal.Code)

	closed := Period{
		From: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 3, 2, 10, 59, 59, 999999999, time.UTC),
	}
	require.NoError(t, closed.Validate(testNow),
		"ending just before the open-period boundary is closed")

	atBoundary := Period{From: closed.From,
		To: time.Date(2026, 3, 2, 11, 0, 0, 0, time.UTC)}
	refusal, ok = RefusalOf(atBoundary.Validate(testNow))
	require.True(t, ok, "To == boundary must refuse: the inclusive predicate "+
		"(created_at <= to) would include the boundary instant inside the open hour")
	assert.Equal(t, RefusalOpenPeriod, refusal.Code)

	reversed := Period{From: closed.To, To: closed.From}
	require.ErrorIs(t, reversed.Validate(testNow), ErrInvalidRequest)
	empty := Period{}
	require.ErrorIs(t, empty.Validate(testNow), ErrInvalidRequest)
}

func TestSelectionDigestStability(t *testing.T) {
	stamp := SchemaStamp{MigrationHead: 16, FamiliesSchemaVersion: FamiliesSchemaVersion}
	sel, err := NewSelection("org-1", "team-7", closedPeriod(),
		[]Family{FamilyToolCalls, FamilyRequestLogs}, SelectionFilters{Model: "glm-5"}, testNow)
	require.NoError(t, err)

	d1, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	d2, err := SelectionDigest(OpArchiveCopy, sel, stamp)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "identical selection+stamp digest identically")

	// Family order must not matter (normalized before digesting).
	selSwapped, err := NewSelection("org-1", "team-7", closedPeriod(),
		[]Family{FamilyRequestLogs, FamilyToolCalls}, SelectionFilters{Model: "glm-5"}, testNow)
	require.NoError(t, err)
	d3, err := SelectionDigest(OpArchiveCopy, selSwapped, stamp)
	require.NoError(t, err)
	assert.Equal(t, d1, d3, "family order is normalized")

	// Any scope change must change the digest.
	for name, mutate := range map[string]func(*Selection){
		"other org":     func(s *Selection) { s.OrgID = "org-2" },
		"other team":    func(s *Selection) { s.TeamID = "" },
		"other period":  func(s *Selection) { s.To = "2026-02-15T00:00:00Z" },
		"other filters": func(s *Selection) { s.Filters.Model = "glm-5.3" },
	} {
		mutated := sel
		mutate(&mutated)
		dm, err := SelectionDigest(OpArchiveCopy, mutated, stamp)
		require.NoError(t, err)
		assert.NotEqual(t, d1, dm, "%s must change the digest", name)
	}

	dOp, err := SelectionDigest(OpPurge, sel, stamp)
	require.NoError(t, err)
	assert.NotEqual(t, d1, dOp, "the operation is part of the digest")

	dStamp, err := SelectionDigest(OpArchiveCopy, sel, SchemaStamp{MigrationHead: 17, FamiliesSchemaVersion: FamiliesSchemaVersion})
	require.NoError(t, err)
	assert.NotEqual(t, d1, dStamp, "a new migration head changes the digest")

	_, err = SelectionDigest(Operation("explode"), sel, stamp)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestSelectionFiltersValidate(t *testing.T) {
	bad := SelectionFilters{MinTokens: -1}
	sel, err := NewSelection("org-1", "", closedPeriod(), []Family{FamilyRequestLogs}, bad, testNow)
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, _ = sel, err

	badCache := SelectionFilters{CacheHit: "sometimes"}
	_, err = NewSelection("org-1", "", closedPeriod(), []Family{FamilyRequestLogs}, badCache, testNow)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

// TestSelectionValidateCrossChecksPeriodWire pins F2 (review 0203): the
// digest signs the From/To wire strings while counts and plans use the
// Period instants — a hand-assembled desynced selection must fail closed
// instead of signing window B and executing window A.
func TestSelectionValidateCrossChecksPeriodWire(t *testing.T) {
	sel, err := NewSelection("org-1", "", closedPeriod(), []Family{FamilyRequestLogs},
		SelectionFilters{}, testNow)
	require.NoError(t, err)
	require.NoError(t, sel.Validate(testNow), "a constructor-built selection validates")

	desyncedWire := sel
	desyncedWire.To = "2026-02-15T00:00:00Z" // digest-string window B
	require.ErrorIs(t, desyncedWire.Validate(testNow), ErrInvalidRequest,
		"wire string vs Period desync must fail closed")

	desyncedPeriod := sel
	desyncedPeriod.Period.To = time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)
	require.ErrorIs(t, desyncedPeriod.Validate(testNow), ErrInvalidRequest,
		"mutated Period vs wire strings must fail closed too")

	emptyWire := sel
	emptyWire.From = "" // e.g. a JSON round-trip: Period is not serialized
	require.ErrorIs(t, emptyWire.Validate(testNow), ErrInvalidRequest)

	malformedWire := sel
	malformedWire.To = "not-a-time"
	require.ErrorIs(t, malformedWire.Validate(testNow), ErrInvalidRequest)

	// Ordering: the typed open-period refusal still fires before the wire
	// cross-check (period rules are the primary semantic gate).
	open := sel
	open.Period.To = testNow.Add(time.Hour)
	err = open.Validate(testNow)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "open period must stay a typed refusal, got %v", err)
	assert.Equal(t, RefusalOpenPeriod, refusal.Code)
}

// TestParseSelectionNumericFiltersFailClosed pins P3 (review 0203): a
// malformed or negative numeric filter is a malformed request — silently
// clamping it to 0 would drop the caller's filter and let the signed scope
// disagree with what was asked.
func TestParseSelectionNumericFiltersFailClosed(t *testing.T) {
	base := url.Values{
		"from":     {"2026-02-01T00:00:00Z"},
		"to":       {"2026-03-01T00:00:00Z"},
		"families": {"request_logs"},
	}
	for name, tc := range map[string]struct {
		param, value string
	}{
		"malformed tokens": {"min_tokens", "abc"},
		"negative tokens":  {"min_tokens", "-5"},
		"exponent latency": {"min_latency_ms", "1e3"},
		"negative latency": {"max_latency_ms", "-1"},
		"malformed cost":   {"min_cost_usd", "oops"},
		"NaN cost":         {"min_cost_usd", "NaN"},
		"Inf cost":         {"max_cost_usd", "Inf"},
		"negative cost":    {"min_cost_usd", "-0.5"},
	} {
		t.Run(name, func(t *testing.T) {
			p := cloneValues(base)
			p.Set(tc.param, tc.value)
			_, err := ParseSelection("org-1", p, testNow)
			require.ErrorIs(t, err, ErrInvalidRequest,
				"%s=%s must be a malformed request, not a silently clamped filter", tc.param, tc.value)
		})
	}
	t.Run("absent, zero and valid values keep their semantics", func(t *testing.T) {
		sel, err := ParseSelection("org-1", base, testNow)
		require.NoError(t, err, "absent numeric filters stay unset")
		assert.Zero(t, sel.Filters.MinTokens)
		assert.Zero(t, sel.Filters.MinCostUSD)

		p := cloneValues(base)
		p.Set("min_tokens", "0")
		p.Set("max_tokens", "42")
		p.Set("min_cost_usd", "1.5")
		sel, err = ParseSelection("org-1", p, testNow)
		require.NoError(t, err, "explicit zero is a legitimate bound")
		assert.Zero(t, sel.Filters.MinTokens)
		assert.EqualValues(t, 42, sel.Filters.MaxTokens)
		assert.InDelta(t, 1.5, sel.Filters.MinCostUSD, 0)
	})
}

func TestSelectionRequestListFiltersMapsOrg(t *testing.T) {
	sel, err := NewSelection("org-1", "", closedPeriod(), []Family{FamilyRequestLogs},
		SelectionFilters{Model: "glm-5"}, testNow)
	require.NoError(t, err)
	rl := sel.RequestListFilters()
	assert.Equal(t, "org-1", rl.OrgID)
	assert.Equal(t, "glm-5", rl.Model)
	assert.Equal(t, sel.Period.From, rl.From)
	assert.Equal(t, sel.Period.To, rl.To)
	assert.Zero(t, rl.Page, "history operations are never paginated")
}

func TestParseFamilyValues(t *testing.T) {
	for _, f := range SelectableFamilies {
		got, err := ParseFamily(string(f))
		require.NoError(t, err)
		assert.Equal(t, f, got)
	}
	for _, protected := range []string{"request_lineage", "policy_decisions"} {
		_, err := ParseFamily(protected)
		refusal, ok := RefusalOf(err)
		require.True(t, ok)
		assert.Equal(t, RefusalProtectedFamily, refusal.Code)
	}
}

func TestCallerRights(t *testing.T) {
	perms := func(ps ...adminstore.Permission) map[adminstore.Permission]bool {
		m := make(map[adminstore.Permission]bool, len(ps))
		for _, p := range ps {
			m[p] = true
		}
		return m
	}
	viewer := Caller{UserID: "u-viewer", Role: adminstore.RoleReader, Perms: perms(adminstore.PermRequestsRead)}
	operator := Caller{UserID: "u-op", Role: adminstore.RoleOperator, Perms: perms(adminstore.PermRequestsRead)}
	auditor := Caller{UserID: "u-audit", Role: adminstore.RoleSecurityAuditor, Perms: perms(adminstore.PermRequestsRead, adminstore.PermAuditRead)}
	admin := Caller{UserID: "u-admin", Role: adminstore.RoleOrgAdmin, Perms: perms(adminstore.PermRequestsRead)}
	agent := Caller{UserID: "u-bot", Role: adminstore.RoleOrgAdmin, Subject: adminstore.RequestPayloadAgent,
		Perms: perms(adminstore.PermRequestsRead)}
	adminRedact := Caller{UserID: "u-admin", Role: adminstore.RoleOrgAdmin,
		Perms: perms(adminstore.PermRequestsPayloads, adminstore.PermRequestsReadOriginals)}
	adminPayloadOnly := Caller{UserID: "u-admin", Role: adminstore.RoleOrgAdmin,
		Perms: perms(adminstore.PermRequestsPayloads)}

	require.NoError(t, AuthorizePreview(viewer), "viewer may preview")
	require.NoError(t, AuthorizeJobRead(viewer), "viewer may read job status")
	require.NoError(t, AuthorizeEnqueue(OpArchiveCopy, admin), "org-admin may archive")
	require.NoError(t, AuthorizeEnqueue(OpRedactContent, adminRedact), "explicit grants unlock redaction")

	for name, c := range map[string]Caller{
		"viewer": viewer, "operator": operator, "auditor": auditor,
		"delegated agent": agent,
	} {
		err := AuthorizeEnqueue(OpArchiveCopy, c)
		refusal, ok := RefusalOf(err)
		require.True(t, ok, "%s enqueue must be a typed refusal, got %v", name, err)
		assert.Equal(t, RefusalInsufficientRights, refusal.Code, "%s cannot enqueue cleanup", name)
	}

	err := AuthorizeEnqueue(OpRedactContent, admin)
	require.Error(t, err, "org-admin without explicit originals grant cannot redact")
	refusal, ok := RefusalOf(err)
	require.True(t, ok)
	assert.Equal(t, RefusalInsufficientRights, refusal.Code)
	err = AuthorizeEnqueue(OpRedactContent, adminPayloadOnly)
	require.Error(t, err, "payload grant alone is not enough for originals surfaces")

	// Every refusal for delegated subjects must name the rights code so the
	// caller sees a decision, not a generic error.
	err = AuthorizePreview(Caller{UserID: "ci", Role: adminstore.RoleOrgAdmin, Subject: adminstore.RequestPayloadCI})
	refusal, ok = RefusalOf(err)
	require.True(t, ok)
	assert.Equal(t, RefusalInsufficientRights, refusal.Code)
}

func TestJobActorValidation(t *testing.T) {
	require.NoError(t, (JobActor{Author: "u-1"}).Validate())
	require.NoError(t, (JobActor{Type: ActorUser, Author: "u-1"}).Validate())
	require.NoError(t, (JobActor{Type: ActorService, Author: "retention-svc", PolicyVersion: "ret-v3"}).Validate())

	err := (JobActor{}).Validate()
	require.ErrorIs(t, err, ErrInvalidRequest)
	err = (JobActor{Type: ActorService, Author: "svc"}).Validate()
	require.ErrorIs(t, err, ErrInvalidRequest,
		"service actor without policy version is a wiring bug, not a refusal")
	err = (JobActor{Type: ActorType("cron"), Author: "svc"}).Validate()
	require.ErrorIs(t, err, ErrInvalidRequest)

	a := (JobActor{Author: "u-1"}).Normalized()
	assert.Equal(t, ActorUser, a.Type, "empty actor type normalizes to user")
}

func TestRefusalExtraction(t *testing.T) {
	wrapped := errors.Join(nil, Refuse(RefusalActiveGrant, "grant g1 active"))
	refusal, ok := RefusalOf(wrapped)
	require.True(t, ok)
	assert.Equal(t, RefusalActiveGrant, refusal.Code)

	_, ok = RefusalOf(errors.New("plain"))
	assert.False(t, ok)
	_, ok = RefusalOf(nil)
	assert.False(t, ok)

	assert.Contains(t, Refuse(RefusalOpenPeriod, "ends %s", "late").Error(), "open_period")
}

// cloneValues copies url.Values for table-style subtests.
func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
