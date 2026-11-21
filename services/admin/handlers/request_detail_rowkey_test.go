package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// rowKeyFixture seeds one correlation with two physical rows (0028: two
// legitimate invocations bill and log independently) plus a cross-correlation
// key and a cross-org key, so every selector outcome has a distinct oracle.
func rowKeyFixture() *mockStore {
	m := newMockStore()
	m.requestRows = []mockRequestRow{
		{RowKey: 1, RequestID: "req-1", OrgID: "org-1", ModelUsed: "gpt-4o-mini", TokensIn: 100, TokensOut: 50, CreatedAt: time.Now()},
		{RowKey: 2, RequestID: "req-1", OrgID: "org-1", ModelUsed: "gpt-4o", TokensIn: 200, TokensOut: 60, CreatedAt: time.Now()},
		{RowKey: 3, RequestID: "req-2", OrgID: "org-1", ModelUsed: "gpt-4o-mini", TokensIn: 300, TokensOut: 70, CreatedAt: time.Now()},
		{RowKey: 4, RequestID: "req-1", OrgID: "org-2", ModelUsed: "gpt-4o-mini", TokensIn: 400, TokensOut: 80, CreatedAt: time.Now()},
	}
	return m
}

// Two rows share req-1; the row_key selector must answer with each row's own
// physical facts, and a key belonging to another correlation or org is the
// same 404 as an unknown key (no existence oracle).
func TestRequestDetailRowKeySelectsPhysicalRow(t *testing.T) {
	store := rowKeyFixture()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	row1 := runRootDetail(h, "/api/organizations/org-1/requests/req-1?row_key=1")
	require.Equal(t, http.StatusOK, row1.Code, row1.Body.String())
	require.Contains(t, row1.Body.String(), `"tokens_in":100`)

	row2 := runRootDetail(h, "/api/organizations/org-1/requests/req-1?row_key=2")
	require.Equal(t, http.StatusOK, row2.Code, row2.Body.String())
	require.Contains(t, row2.Body.String(), `"tokens_in":200`, "the selected sibling's facts, not the other row's")
	require.NotContains(t, row2.Body.String(), `"tokens_in":100`)

	for _, target := range []string{
		"/api/organizations/org-1/requests/req-1?row_key=3",  // key of another correlation
		"/api/organizations/org-1/requests/req-1?row_key=4",  // key of another org
		"/api/organizations/org-1/requests/req-1?row_key=99", // unknown key
	} {
		rec := runRootDetail(h, target)
		require.Equal(t, http.StatusNotFound, rec.Code, target)
		require.Contains(t, rec.Body.String(), "not found", target)
	}
}

// Presence is intent: a blank, repeated (even identically), non-decimal,
// non-positive or overflowing selector is an explicit 400 — never a silent
// fallback to the arbitrary-row correlation read.
func TestRequestDetailRowKeyStrictParamValidation(t *testing.T) {
	store := rowKeyFixture()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	for _, target := range []string{
		"/api/organizations/org-1/requests/req-1?row_key=",
		"/api/organizations/org-1/requests/req-1?row_key=1&row_key=2",
		"/api/organizations/org-1/requests/req-1?row_key=1&row_key=1",
		"/api/organizations/org-1/requests/req-1?row_key=abc",
		"/api/organizations/org-1/requests/req-1?row_key=1.5",
		"/api/organizations/org-1/requests/req-1?row_key=0",
		"/api/organizations/org-1/requests/req-1?row_key=-1",
		"/api/organizations/org-1/requests/req-1?row_key=9223372036854775808", // int64 overflow
	} {
		rec := runRootDetail(h, target)
		require.Equal(t, http.StatusBadRequest, rec.Code, target)
		require.Contains(t, rec.Body.String(), "row_key", target)
	}

	// Without the selector the legacy correlation read is unchanged.
	legacy := runRootDetail(h, "/api/organizations/org-1/requests/req-1")
	require.Equal(t, http.StatusOK, legacy.Code, legacy.Body.String())
}

// A row-selected redemption naming exactly the peeked target row is the
// normal one-time redemption: read, consume, disclose, journalled.
func TestDetailGrantRowKeyExactMatchRedeemsNormally(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token+"&row_key=1")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, []string{"read", "consume"}, store.callsSoFar(),
		"an exact row_key match changes nothing about the redemption order")
	require.Contains(t, rec.Body.String(), `"arguments"`)
	require.False(t, grantAlive(store.mockStore, token), "the matched redemption consumes the grant exactly once")
	require.NotNil(t, detailAuditRecord(store.mockStore, false, "completed"))
}

// A mismatched selector is rejected against the peeked target BEFORE the
// consume: 400, no payload bytes, no row read, token still redeemable.
func TestDetailGrantRowKeyMismatchDoesNotBurnGrant(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	mismatch := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token+"&row_key=2")

	require.Equal(t, http.StatusBadRequest, mismatch.Code, mismatch.Body.String())
	require.Contains(t, mismatch.Body.String(), "row_key does not match")
	require.NotContains(t, mismatch.Body.String(), "arguments", "a mismatch denial must not disclose payload bytes")
	require.Empty(t, store.callsSoFar(), "the mismatch check precedes the row read seam")
	require.True(t, grantAlive(store.mockStore, token), "a mismatched selector must not burn the one-time grant")
	require.NotNil(t, detailAuditRecord(store.mockStore, true, "row_key_mismatch"),
		"the post-peek denial must be journalled")

	// The very same token still redeems cleanly afterwards — proof the
	// mismatch path never consumed it.
	retry := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	require.False(t, grantAlive(store.mockStore, token))
}

// The list endpoint must expose row_key as an exact decimal STRING: the
// bigint passes 2^53, where a JSON number would round in every JS client and
// point the inspector at the wrong physical row. A number-typed row_key in
// this JSON must fail the string assertion (float64 parses 2^53+1 as 2^53).
func TestRequestListExposesRowKeyAsExactDecimalString(t *testing.T) {
	store := rowKeyFixture()
	store.requestRows = append(store.requestRows, mockRequestRow{
		RowKey: 9007199254740993, RequestID: "req-1", OrgID: "org-1", ModelUsed: "gpt-4o",
		TokensIn: 300, TokensOut: 90, CreatedAt: time.Now(),
	})
	h := newTestAdminH(store)

	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(
		rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/organizations/org-1/requests", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var page struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	keys := map[string]bool{}
	for _, row := range page.Data {
		v, ok := row["row_key"]
		require.True(t, ok, "every physical row carries row_key")
		s, isString := v.(string)
		require.True(t, isString, "row_key must be a JSON string, got %T", v)
		keys[s] = true
	}
	require.Equal(t, map[string]bool{"1": true, "2": true, "3": true, "9007199254740993": true}, keys,
		"org-1's rows as exact decimal keys including the beyond-2^53 value; a JSON number would have parsed as 9007199254740992")
}
